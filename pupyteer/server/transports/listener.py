"""Async TCP listener for Pupyteer agent callbacks.

Provides the core C2 server transport: accepts inbound TCP connections
from Pupyteer agents, performs session registration, dispatches queued
command on check-in, and collects command output.

Protocol: newline-delimited JSON messages over one TCP connection per session,
wrapped in TLS when the config supplies an ``ssl_context`` (server.tls).

Message types:
    Agent → Server:
        {"type": "register", "hostname": "...", "os": "...", "arch": "...",
         "username": "...", "agent_version": "...", "auth": "<enrollment secret>"}
        {"type": "checkin", "session_id": "...", "beacon": "<beacon token>"}
        {"type": "output", "session_id": "...", "command_id": "...",
         "output": "...", "beacon": "<beacon token>"}

    Server → Agent:
        {"type": "registered", "session_id": "...", "beacon_token": "..."}
        {"type": "commands", "commands": [{"command_id": "...", "command": "..."}]}
        {"type": "ack"}
        {"type": "error", "message": "..."}

``auth`` says a payload may become a session and is checked only at ``register``;
``beacon`` says a message speaks for the session it names, and is checked on every
one that does. A token is handed out once, in the ``registered`` reply.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from pupyteer.server.core.enrollment import beacon_accepts, new_beacon_token
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions.manager import SessionInfo

logger = logging.getLogger("pupyteer.transports.listener")

# asyncio's StreamReader defaults to 64 KiB per line, which a file-transfer
# chunk or a long command output blows straight through — readline() then raises
# and the session dies. Message framing is one JSON object per line, so the
# ceiling has to be above the largest payload an operator can ask for.
MAX_MESSAGE_BYTES = 32 * 1024 * 1024

# How long a peer may take to finish a TLS handshake before the connection is
# dropped. A host that cannot complete one is not going to start halfway through,
# and every second it holds this socket is a second of queue on the listener.
HANDSHAKE_TIMEOUT_SECONDS = 10.0

# One line per refusal is what an operator needs the first time a payload fails to
# call back; it is also an invitation to bury the entries that matter, because the
# audit log rotates at a fixed size and drops the oldest. So refusals of every kind
# are counted exactly and reported per key at most this often.
REFUSAL_REPORT_WINDOW_SECONDS = 60.0
_REFUSAL_REPORT_KEYS = 4096


class PendingCommand:
    """Tracks a command waiting for agent delivery / response."""

    __slots__ = ("command_id", "command", "queued_at", "delivered")

    def __init__(self, command_id: str, command: str, queued_at: float):
        self.command_id = command_id
        self.command = command
        self.queued_at = queued_at
        self.delivered = False


class ConnectionState:
    """Mutable state for one connected agent."""

    __slots__ = ("session_id", "writer", "addr", "connected_at", "last_activity")

    def __init__(
        self,
        session_id: str,
        writer: asyncio.StreamWriter,
        addr: str,
    ):
        self.session_id = session_id
        self.writer = writer
        self.addr = addr
        self.connected_at = time.time()
        self.last_activity = time.time()


class AgentListener:
    """Async TCP server that catches Pupyteer agent callbacks.

    Lifecycle:
        1. Instantiate with config dict, a SessionManager, and an AuditLogger.
        2. Call ``await listener.start()`` — blocks (via asyncio.start_server)
           until ``stop()`` is called.
        3. On agent connect → handle_client() drives the JSON-line protocol.
        4. Registration creates a ``SessionInfo`` via the session manager.
        5. Check-in returns any queued commands and updates last_checkin.
        6. Output resolves the pending command and acks through the manager.
    """

    def __init__(
        self,
        config: Dict[str, Any],
        session_manager: Any,
        audit_logger: AuditLogger,
    ):
        self._host: str = config.get("host", "0.0.0.0")
        self._port: int = int(config.get("port", 8443))
        # Supplied by TransportManager when server.tls is on. Absent means the
        # listener speaks plaintext JSON, which any tap on the wire can read.
        self._ssl_context = config.get("ssl_context")
        # Supplied by TransportManager: the enrollment file a register message has
        # to match a line of. Consulted per registration rather than resolved once
        # here, so an operator who deletes a secret stops it working without having
        # to restart the server and drop every session in the dashboard. None
        # disables the check, which is what server.agent_auth: false asks for.
        self._enrollment = config.get("enrollment")
        self._session_manager = session_manager
        self._audit = audit_logger

        self._server: Optional[asyncio.base_events.Server] = None
        self._connections: Dict[str, ConnectionState] = {}  # session_id → state
        self._lock = asyncio.Lock()
        self._stats: Dict[str, int] = {
            "connections": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "sessions_created": 0,
            "commands_dispatched": 0,
            # Counted separately from connections: "lots of connections, no
            # sessions" is what someone probing the listener looks like.
            "registrations_rejected": 0,
            # A message that named a session it cannot prove it owns. Distinct
            # from registrations_rejected because the shape it means is different:
            # that one is a stranger at the port, this one is someone who already
            # knows a session id and is trying to speak for it.
            "beacons_refused": 0,
            # Connections that never became a request line. On a TLS listener
            # this is what a payload built while server.tls was off looks like:
            # without it, a stranded implant and a powered-off host are the
            # same number — zero — and nothing points at the rebuild.
            "handshakes_refused": 0,
        }
        # Refusals leave a trace line at most once a window per key; see
        # _thin_report. Handshake refusals key on the peer, beacon refusals on
        # peer+session: someone poking at session ids is as loud as a port sweep,
        # and has the same power to push the entries an operator cares about out of
        # an audit file that rotates. Dict order is the order a key was last
        # reported in, which is what lets the cap drop the stalest key rather than
        # a random one.
        self._handshake_reports: Dict[str, List[float]] = {}
        self._beacon_reports: Dict[str, List[float]] = {}

    # ------------------------------------------------------------------
    #  Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Bind the TCP server and start accepting connections."""
        ssl_context = self._ssl_context
        # The upgrade happens per connection in _upgrade_tls rather than by
        # handing ssl= to start_server, so that a failed handshake is something
        # this listener can see. asyncio reports those to the event loop's
        # exception handler and closes the socket, which leaves the operator
        # with a port that is "not getting any sessions".
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
            limit=MAX_MESSAGE_BYTES,
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("Agent listener listening on %s (%s)",
                    addrs, "TLS" if ssl_context else "plaintext")
        self._audit.log_event("listener_started", {
            "host": self._host,
            "port": self._port,
            "tls": bool(ssl_context),
        })

    async def _upgrade_tls(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Wrap this connection in TLS, or say why it could not be wrapped.

        Returns False when the connection must be dropped: the peer did not
        speak TLS to a TLS listener, or the handshake went wrong. Never returns
        False on a listener that has no certificate — that one is plaintext by
        configuration, and the caller proceeds.
        """
        if self._ssl_context is None:
            return True
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        peer_key = f"{peer[0]}:{peer[1]}"
        try:
            await writer.start_tls(
                self._ssl_context, ssl_handshake_timeout=HANDSHAKE_TIMEOUT_SECONDS)
            return True
        except Exception as exc:
            self._stats["handshakes_refused"] += 1
            self._report_handshake_refusal(peer_key, f"{type(exc).__name__}: {exc}")
            return False

    def _thin_report(self, reports: Dict[str, List[float]], key: str) -> Optional[int]:
        """Decide whether this key earns a trace line now, or is folded into the next.

        Returns None when the last line for this key is still inside the window —
        the count has been incremented and nothing more is written — and the number
        of refusals suppressed since the line before otherwise. Counts stay exact
        either way; this only governs how much of them reaches the log and the
        rotating audit file, where a stranger's noise must not evict what an
        operator is looking for.
        """
        now = time.monotonic()
        record = reports.get(key)
        if record is None:
            if len(reports) >= _REFUSAL_REPORT_KEYS:
                reports.pop(next(iter(reports)))
            reports[key] = [now, 0.0]
            return 0
        if now - record[0] >= REFUSAL_REPORT_WINDOW_SECONDS:
            record[0] = now
            suppressed = int(record[1])
            record[1] = 0.0
            return suppressed
        record[1] += 1
        return None

    def _report_handshake_refusal(self, peer_key: str, reason: str) -> None:
        """Report a refused handshake, at most once a window per peer.

        ``handshakes_refused`` is the exact live total and ``transports list`` is
        where an operator reads it; this is the durable trace left beside it. It
        is thinned per peer so that a port sweep cannot use this event to push
        the entries that matter out of an audit file that rotates. Each line
        names the peer and the reason, ``count`` is the listener-wide total when
        it was written, and ``suppressed`` is what this peer did in between two
        lines, which would otherwise be invisible.
        """
        suppressed = self._thin_report(self._handshake_reports, peer_key)
        if suppressed is None:
            return

        logger.warning("TLS handshake failed from %s: %s (%d more from this peer "
                       "since the last line)", peer_key, reason[:200], suppressed)
        self._audit.log_event(
            "handshake_refused",
            {"peer": peer_key, "reason": reason[:200],
             "count": self._stats["handshakes_refused"],
             "suppressed": suppressed},
            result="error",
        )

    def _refuse_beacon(
        self,
        remote: str,
        session_id: str,
        presented: Any,
        verb: str,
    ) -> Dict[str, Any]:
        """Record a beacon that named a session it cannot prove it owns.

        Returns the reply the caller must send. An agent reads a refusal as a lost
        session and registers again, which is the right recovery for a server that
        restarted without it — and all an older payload can do, so what an operator
        sees is a session that reappears every beacon interval while
        ``beacons_refused`` climbs. The fix then is a rebuild, not a re-try: this
        is not a channel to be worked around, it is a proof the payload lacks.
        """
        self._stats["beacons_refused"] += 1
        suppressed = self._thin_report(
            self._beacon_reports, f"{remote}|{session_id}")
        if suppressed is None:
            return {"type": "error", "message": "beacon_auth_failed"}

        logger.warning(
            "Refused %s for session %s from %s: beacon token %s "
            "(%d more like it since the last line)",
            verb, session_id[:40], remote,
            "absent" if not presented else "wrong", suppressed)
        self._audit.log_event(
            "beacon_refused",
            {"peer": remote, "session_id": session_id, "verb": verb,
             "reason": "bad_beacon_token",
             "count": self._stats["beacons_refused"],
             "suppressed": suppressed},
            result="error",
        )
        return {"type": "error", "message": "beacon_auth_failed"}

    async def stop(self) -> None:
        """Gracefully close the server and all active connections."""
        # Close every active connection first
        async with self._lock:
            for sid, conn in list(self._connections.items()):
                try:
                    conn.writer.close()
                    await conn.writer.wait_closed()
                except Exception:
                    pass
            self._connections.clear()

        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        logger.info("Agent listener stopped on %s:%d", self._host, self._port)
        self._audit.log_event("listener_stopped", {
            "host": self._host,
            "port": self._port,
            "stats": dict(self._stats),
        })

    # ------------------------------------------------------------------
    #  Per-connection protocol handler
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Read newline-delimited JSON and dispatch each message.

        One TCP connection is expected to carry the lifetime of a single
        agent session (register → many checkin/output cycles).  If an
        agent re-connects it will register again and receive a new
        session_id.
        """
        addr = writer.get_extra_info("peername") or ("unknown", 0)
        remote_str = f"{addr[0]}:{addr[1]}"
        session_id: Optional[str] = None

        # Before anything is read, so a peer that cannot speak TLS to a TLS
        # listener is refused as a handshake and not as malformed JSON.
        if not await self._upgrade_tls(reader, writer):
            await self._drop(writer)
            return

        logger.debug("New agent connection from %s", remote_str)
        self._stats["connections"] += 1

        try:
            while True:
                try:
                    line = await reader.readline()
                except (ConnectionError, OSError):
                    break

                if not line:
                    # EOF — agent disconnected
                    break

                self._stats["bytes_received"] += len(line)

                # Strip whitespace / newline
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue

                # Parse JSON
                try:
                    msg: Dict[str, Any] = json.loads(line_str)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Malformed JSON from %s: %s", remote_str, exc
                    )
                    await self._send_json(
                        writer,
                        {"type": "error", "message": "invalid_json"},
                    )
                    continue

                # Dispatch
                try:
                    response = await self._process_message(
                        msg, remote_str, writer
                    )
                    # Capture session_id from registration for cleanup
                    if (
                        msg.get("type") == "register"
                        and response
                        and response.get("type") == "registered"
                    ):
                        session_id = response["session_id"]
                except Exception as exc:
                    logger.exception(
                        "Error processing %s from %s: %s",
                        msg.get("type"), remote_str, exc,
                    )
                    await self._send_json(
                        writer,
                        {"type": "error", "message": "internal_error"},
                    )
                    continue

                if response is not None:
                    sent = await self._send_json(writer, response)
                    if sent == -1:
                        break  # write failed, drop connection

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.exception("Unhandled error in handler for %s: %s", remote_str, exc)
        finally:
            # Clean up connection tracking
            if session_id:
                async with self._lock:
                    self._connections.pop(session_id, None)
                logger.debug("Session %s disconnected from %s", session_id, remote_str)

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _drop(writer: asyncio.StreamWriter) -> None:
        """Close a connection without ceremony; it is already going away."""
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    # ------------------------------------------------------------------
    #  Message dispatch
    # ------------------------------------------------------------------

    async def _process_message(
        self,
        msg: Dict[str, Any],
        remote: str,
        writer: asyncio.StreamWriter,
    ) -> Optional[Dict[str, Any]]:
        """Route a parsed JSON message to the appropriate handler."""
        msg_type = msg.get("type", "")

        if msg_type == "register":
            return await self._handle_register(msg, remote, writer)
        if msg_type == "checkin":
            return await self._handle_checkin(msg, remote, writer)
        if msg_type == "output":
            return await self._handle_output(msg, remote)

        logger.warning("Unknown message type '%s' from %s", msg_type, remote)
        return {"type": "error", "message": f"unknown_type: {msg_type}"}

    # ------------------------------------------------------------------
    #  Register
    # ------------------------------------------------------------------

    async def _handle_register(
        self,
        msg: Dict[str, Any],
        remote: str,
        writer: asyncio.StreamWriter,
    ) -> Dict[str, Any]:
        """Create a new session and register it."""
        ledger = self._enrollment
        if ledger is not None and not ledger.accepts(msg.get("auth")):
            # Deliberately before anything is created: a session is a handler an
            # operator can run commands through and push files to, so a stranger
            # must not be able to conjure one by reaching the port.
            self._stats["registrations_rejected"] += 1
            if not ledger.accepted():
                # Says something different from "wrong secret": here the server
                # is the one that cannot present a credential, and no payload
                # built against anything will get in until it is fixed.
                why = "accepting no enrollment secret at all"
            elif not msg.get("auth"):
                why = "absent"
            else:
                why = "wrong"
            logger.warning("Rejected registration from %s: enrollment secret %s",
                           remote, why)
            self._audit.log_event(
                "registration_rejected",
                {
                    "remote_address": remote,
                    "claimed_hostname": str(msg.get("hostname", ""))[:120],
                    "reason": "bad_enrollment_secret",
                },
                result="error",
            )
            return {"type": "error", "message": "auth_failed"}

        session_id = str(uuid.uuid4())[:12]

        info = SessionInfo(
            session_id=session_id,
            hostname=msg.get("hostname", "unknown"),
            os=msg.get("os", "unknown"),
            arch=msg.get("arch", "unknown"),
            username=msg.get("username", "unknown"),
            agent_version=msg.get("agent_version", "unknown"),
            remote_address=remote,
            # Handed out once, in the reply below, and never shown to an operator.
            # Everything after this line has to bring it back or it is a stranger
            # wearing a session id.
            beacon_token=new_beacon_token(),
        )

        registered_id = await self._session_manager.register(info)

        async with self._lock:
            self._connections[registered_id] = ConnectionState(
                session_id=registered_id,
                writer=writer,
                addr=remote,
            )

        self._stats["sessions_created"] += 1

        self._audit.log_event(
            "session_registered",
            {
                "session_id": registered_id,
                "hostname": info.hostname,
                "os": info.os,
                "arch": info.arch,
                "username": info.username,
                "remote_address": remote,
            },
            session=registered_id,
        )
        logger.info(
            "Agent registered: %s (%s@%s) from %s",
            registered_id, info.username, info.hostname, remote,
        )

        return {
            "type": "registered",
            "session_id": registered_id,
            "beacon_token": info.beacon_token,
        }

    # ------------------------------------------------------------------
    #  Check-in
    # ------------------------------------------------------------------

    async def _handle_checkin(
        self,
        msg: Dict[str, Any],
        remote: str,
        writer: asyncio.StreamWriter,
    ) -> Dict[str, Any]:
        """Return queued commands for the session and bump last_checkin."""
        session_id = msg.get("session_id", "")

        info = await self._session_manager.get(session_id)

        # An unknown session means the operator's side lost it — a team-server
        # restart, or a session killed while the agent kept beaconing. Answering
        # "no commands" forever leaves a live agent attached to a dead session
        # that no operator can address, so tell it to register again. Kept
        # distinct from a refused beacon because the two have different fixes: one
        # is a re-register, the other is a rebuild.
        if info is None:
            logger.info("Check-in for unknown session %s; telling agent to re-register", session_id)
            return {"type": "error", "message": "unknown_session"}

        # Before the heartbeat, before the queue is read. A beacon that cannot say
        # whose session it is gets nothing, and does not get to look alive either:
        # last_checkin is how an operator decides a host is still there.
        if not beacon_accepts(info.beacon_token, msg.get("beacon")):
            return self._refuse_beacon(remote, session_id, msg.get("beacon"), "checkin")

        # Update heartbeat
        await self._session_manager.update_checkin(session_id)

        # Refresh connection writer (agent may have reconnected)
        async with self._lock:
            conn = self._connections.get(session_id)
            if conn is not None:
                if conn.writer is not writer:
                    conn.writer = writer
                conn.last_activity = time.time()

        # Pull pending commands from session manager
        pending: list = await self._session_manager.get_pending_commands(session_id)

        commands = []
        for cmd in pending:
            commands.append({
                "command_id": cmd["command_id"],
                "command": cmd["command"],
            })
            # Mark as delivered so we don't re-send on next check-in
            # (session manager keeps them until ack)
            cmd["status"] = "delivered"

        if commands:
            self._stats["commands_dispatched"] += len(commands)
            logger.debug(
                "Dispatching %d command(s) to session %s",
                len(commands), session_id,
            )

        return {"type": "commands", "commands": commands}

    # ------------------------------------------------------------------
    #  Output
    # ------------------------------------------------------------------

    async def _handle_output(
        self, msg: Dict[str, Any], remote: str
    ) -> Dict[str, Any]:
        """Resolve a pending command with its output."""
        session_id = msg.get("session_id", "")
        command_id = msg.get("command_id", "")
        output = msg.get("output", "")

        info = await self._session_manager.get(session_id)
        if info is None:
            # ack_command would answer {"type":"ack"} for a session that has never
            # existed, and the audit line below would say a command was completed by
            # a session id the operator can name. That is a forged result with the
            # look of a real one, so it stops here.
            logger.info("Output for unknown session %s; dropped", session_id)
            return {"type": "error", "message": "unknown_session"}

        if not beacon_accepts(info.beacon_token, msg.get("beacon")):
            return self._refuse_beacon(remote, session_id, msg.get("beacon"), "output")

        await self._session_manager.ack_command(session_id, command_id, output)

        self._audit.log_event(
            "session_command_ack",
            {
                "session_id": session_id,
                "command_id": command_id,
                "output_length": len(output),
            },
            session=session_id,
        )
        logger.debug(
            "Received output for command %s (session %s, %d chars)",
            command_id, session_id, len(output),
        )

        return {"type": "ack"}

    # ------------------------------------------------------------------
    #  Helpers
    # ------------------------------------------------------------------

    async def _send_json(
        self,
        writer: asyncio.StreamWriter,
        payload: Dict[str, Any],
    ) -> int:
        """Serialize *payload* to JSON, write with trailing newline.

        Returns the number of bytes written, or -1 on failure.
        """
        try:
            data = (json.dumps(payload) + "\n").encode("utf-8")
            writer.write(data)
            await writer.drain()
            self._stats["bytes_sent"] += len(data)
            return len(data)
        except (ConnectionError, OSError) as exc:
            logger.warning("Failed to send to peer: %s", exc)
            return -1

    # ------------------------------------------------------------------
    #  Stats / introspection
    # ------------------------------------------------------------------

    @property
    def stats(self) -> Dict[str, Any]:
        """Return a snapshot of listener statistics."""
        return {
            **self._stats,
            "active_connections": len(self._connections),
            "host": self._host,
            "port": self._port,
        }

    @property
    def is_running(self) -> bool:
        return self._server is not None

    def get_connection_sessions(self) -> list:
        """Return list of active session IDs."""
        return list(self._connections.keys())
