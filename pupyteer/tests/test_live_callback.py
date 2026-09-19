"""Live callback integration tests — full agent-to-listener C2 loop.

These tests start the real engine (and its TCP listener), simulate an agent
connecting over TCP using raw sockets, and verify the full lifecycle:
register → session created → checkin → command dispatch → output → ack.

Uses port 0 (OS-assigned free port) to avoid conflicts with other tests.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

# Ensure pupyteer is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
import sys

sys.path.insert(0, str(PROJECT_ROOT))

from pupyteer.server.core.engine import PupyteerEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    """Ask the OS for a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    """Block until a TCP port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except (ConnectionError, OSError):
            time.sleep(0.05)
    raise TimeoutError(f"Port {host}:{port} not ready after {timeout}s")


class _EngineThread:
    """Run the PupyteerEngine in a background thread with its own event loop.

    Provides a simple ``submit(coro)`` helper to run coroutines on that loop
    from the test thread.
    """

    def __init__(self, port: int):
        self._port = port
        self.engine: Optional[PupyteerEngine] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._error: Optional[Exception] = None

    def start(self, timeout: float = 15.0) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            raise TimeoutError("Engine did not become ready")
        if self._error is not None:
            raise self._error

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self.engine = PupyteerEngine()
            # Patch config before start
            self.engine.config.set("server.host", "127.0.0.1")
            self.engine.config.set("server.port", self._port)
            self._loop.run_until_complete(self.engine.start())
            self._ready.set()
            self._loop.run_forever()
        except Exception as exc:
            self._error = exc
            self._ready.set()

    def stop(self, timeout: float = 15.0) -> None:
        if self.engine is not None and self._loop is not None:
            fut = asyncio.run_coroutine_threadsafe(
                self.engine.stop(), self._loop
            )
            try:
                fut.result(timeout=timeout)
            except Exception:
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def submit(self, coro, timeout: float = 5.0) -> Any:
        """Schedule a coroutine on the engine's event loop and return result."""
        assert self._loop is not None, "Loop not started"
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine_thread():
    """Start the engine once for all tests in this module."""
    port = _find_free_port()
    thread = _EngineThread(port)
    thread.start()
    _wait_for_port("127.0.0.1", port, timeout=5)
    yield thread, "127.0.0.1", port
    thread.stop()


def _tcp_connect(host: str, port: int) -> socket.socket:
    """Create a connected TCP socket with a 5-second timeout."""
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    return sock


def _send_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    """Serialize payload and send as a newline-terminated JSON line."""
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def _recv_json(sock: socket.socket) -> Optional[Dict[str, Any]]:
    """Read one newline-terminated JSON message."""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    return json.loads(buf.decode("utf-8").strip())


def _register_agent(
    host: str, port: int, hostname: str = "test-agent"
) -> tuple:
    """Register an agent and return (socket, session_id)."""
    sock = _tcp_connect(host, port)
    _send_json(sock, {
        "type": "register",
        "hostname": hostname,
        "os": "linux",
        "arch": "x86_64",
        "username": "testuser",
        "agent_version": "1.0.0-test",
    })
    response = _recv_json(sock)
    assert response is not None, "No registration response"
    assert response["type"] == "registered", f"Unexpected: {response}"
    session_id = response["session_id"]
    assert session_id, "No session_id in response"
    return sock, session_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLiveAgentRegistration:
    """Test agent registration and session creation."""

    def test_register_creates_session(self, engine_thread):
        """Registration creates a SessionInfo in the SessionManager."""
        thread, host, port = engine_thread

        sock, session_id = _register_agent(host, port, hostname="reg-test")

        try:
            session = thread.submit(thread.engine.sessions.get(session_id))
            assert session is not None
            assert session.hostname == "reg-test"
            assert session.os == "linux"
            assert session.arch == "x86_64"
            assert session.username == "testuser"
            assert session.state.value == "connected"
        finally:
            sock.close()

    def test_register_returns_unique_session_ids(self, engine_thread):
        """Each registration produces a distinct session ID."""
        thread, host, port = engine_thread

        sock1, sid1 = _register_agent(host, port, hostname="agent-1")
        sock2, sid2 = _register_agent(host, port, hostname="agent-2")

        try:
            assert sid1 != sid2
            s1 = thread.submit(thread.engine.sessions.get(sid1))
            s2 = thread.submit(thread.engine.sessions.get(sid2))
            assert s1 is not None and s2 is not None
            assert s1.hostname == "agent-1"
            assert s2.hostname == "agent-2"
        finally:
            sock1.close()
            sock2.close()


class TestLiveAgentCheckin:
    """Test agent checkin flow."""

    def test_checkin_updates_last_checkin(self, engine_thread):
        """Sending a checkin updates the session's last_checkin timestamp."""
        thread, host, port = engine_thread

        sock, session_id = _register_agent(host, port, hostname="checkin-test")

        try:
            before = thread.submit(thread.engine.sessions.get(session_id))
            assert before is not None
            initial_ts = before.last_checkin

            time.sleep(0.1)

            _send_json(sock, {"type": "checkin", "session_id": session_id})
            response = _recv_json(sock)

            assert response is not None
            assert response["type"] == "commands"

            after = thread.submit(thread.engine.sessions.get(session_id))
            assert after is not None
            assert after.last_checkin >= initial_ts
        finally:
            sock.close()

    def test_checkin_with_no_commands_returns_empty(self, engine_thread):
        """Checkin with no queued commands returns empty commands list."""
        thread, host, port = engine_thread

        sock, session_id = _register_agent(host, port, hostname="empty-checkin")

        try:
            _send_json(sock, {"type": "checkin", "session_id": session_id})
            response = _recv_json(sock)
            assert response is not None
            assert response["type"] == "commands"
            assert response["commands"] == []
        finally:
            sock.close()


class TestLiveCommandDispatch:
    """Test command queuing, delivery, and output capture."""

    def test_checkin_delivers_queued_command(self, engine_thread):
        """A queued command is returned on the next checkin."""
        thread, host, port = engine_thread

        sock, session_id = _register_agent(host, port, hostname="dispatch-test")

        try:
            # Queue a command
            cmd_id = thread.submit(
                thread.engine.sessions.interact(session_id, "echo hello")
            )
            assert cmd_id is not None

            # Checkin should deliver it
            _send_json(sock, {"type": "checkin", "session_id": session_id})
            response = _recv_json(sock)

            assert response is not None
            assert response["type"] == "commands"
            assert len(response["commands"]) == 1
            assert response["commands"][0]["command"] == "echo hello"
            assert response["commands"][0]["command_id"] == cmd_id
        finally:
            sock.close()

    def test_output_ack(self, engine_thread):
        """Sending command output returns ack and completes the command."""
        thread, host, port = engine_thread

        sock, session_id = _register_agent(host, port, hostname="output-test")

        try:
            # Queue a command
            cmd_id = thread.submit(
                thread.engine.sessions.interact(session_id, "whoami")
            )

            # Checkin to deliver
            _send_json(sock, {"type": "checkin", "session_id": session_id})
            resp = _recv_json(sock)
            assert resp is not None
            assert len(resp["commands"]) == 1

            # Send output
            _send_json(sock, {
                "type": "output",
                "session_id": session_id,
                "command_id": cmd_id,
                "output": "testuser\n",
            })
            ack = _recv_json(sock)
            assert ack is not None
            assert ack["type"] == "ack"

            # Verify command is completed
            history = thread.submit(
                thread.engine.sessions.get_command_history(session_id)
            )
            completed = [c for c in history if c["command_id"] == cmd_id]
            assert len(completed) == 1
            assert completed[0]["status"] == "completed"
            assert completed[0]["result"] == "testuser\n"
        finally:
            sock.close()

    def test_full_c2_loop(self, engine_thread):
        """Full end-to-end loop: register → queue → checkin → output → ack."""
        thread, host, port = engine_thread

        sock, session_id = _register_agent(host, port, hostname="full-loop")

        try:
            # Verify session exists
            session = thread.submit(thread.engine.sessions.get(session_id))
            assert session is not None

            # Queue command
            cmd_id = thread.submit(
                thread.engine.sessions.interact(session_id, "echo pupyteer_ok")
            )
            assert cmd_id

            # Checkin → get command
            _send_json(sock, {"type": "checkin", "session_id": session_id})
            checkin_resp = _recv_json(sock)
            assert checkin_resp is not None
            assert checkin_resp["type"] == "commands"
            assert len(checkin_resp["commands"]) == 1
            assert checkin_resp["commands"][0]["command_id"] == cmd_id

            # Output → ack
            _send_json(sock, {
                "type": "output",
                "session_id": session_id,
                "command_id": cmd_id,
                "output": "pupyteer_ok\n",
            })
            ack_resp = _recv_json(sock)
            assert ack_resp is not None
            assert ack_resp["type"] == "ack"

            # Verify history
            history = thread.submit(
                thread.engine.sessions.get_command_history(session_id)
            )
            entry = next(c for c in history if c["command_id"] == cmd_id)
            assert entry["status"] == "completed"
            assert "pupyteer_ok" in entry["result"]
        finally:
            sock.close()


class TestLiveErrorHandling:
    """Test error handling in the live protocol."""

    def test_malformed_json_returns_error(self, engine_thread):
        """Malformed JSON from the agent produces an error response."""
        thread, host, port = engine_thread

        sock = _tcp_connect(host, port)
        try:
            sock.sendall(b"not json at all\n")
            response = _recv_json(sock)
            assert response is not None
            assert response["type"] == "error"
            assert "invalid_json" in response.get("message", "")
        finally:
            sock.close()

    def test_unknown_type_returns_error(self, engine_thread):
        """An unknown message type produces an error response."""
        thread, host, port = engine_thread

        sock = _tcp_connect(host, port)
        try:
            _send_json(sock, {"type": "bogus_type", "data": 123})
            response = _recv_json(sock)
            assert response is not None
            assert response["type"] == "error"
            assert "unknown_type" in response.get("message", "")
        finally:
            sock.close()

    def test_checkin_unknown_session_returns_empty_commands(self, engine_thread):
        """Checkin for a non-existent session returns empty commands (not crash)."""
        thread, host, port = engine_thread

        sock = _tcp_connect(host, port)
        try:
            _send_json(sock, {
                "type": "checkin",
                "session_id": "nonexistent-session-id",
            })
            response = _recv_json(sock)
            assert response is not None
            assert response["type"] == "commands"
            assert response["commands"] == []
        finally:
            sock.close()


class TestLiveSessionCleanup:
    """Test session cleanup after agent disconnect."""

    def test_session_persists_after_disconnect(self, engine_thread):
        """After a socket disconnect, session is still tracked (until timeout)."""
        thread, host, port = engine_thread

        sock, session_id = _register_agent(host, port, hostname="persist-test")

        # Close connection
        sock.close()
        time.sleep(0.2)

        # Session should still exist
        session = thread.submit(thread.engine.sessions.get(session_id))
        assert session is not None
        assert session.hostname == "persist-test"
