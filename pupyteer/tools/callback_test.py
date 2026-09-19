"""Callback test — one-shot end-to-end test of the Pupyteer C2 callback loop.

Starts the engine in a background thread (which starts the TCP listener),
launches an agent simulator process, verifies the session appears in the
sessions list, sends a test command, verifies output is received, and
reports PASS/FAIL.

Usage:
    python -m pupyteer.tools.callback_test
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure project is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pupyteer.server.core.engine import PupyteerEngine

logger = logging.getLogger("pupyteer.callback_test")


def _find_free_port() -> int:
    """Ask the OS for a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EngineThread:
    """Runs the Pupyteer engine in a background thread with its own loop."""

    def __init__(self, port: int):
        self._port = port
        self._engine: Optional[PupyteerEngine] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._start_error: Optional[Exception] = None

    @property
    def engine(self) -> PupyteerEngine:
        assert self._engine is not None, "Engine not started"
        return self._engine

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        assert self._loop is not None, "Loop not started"
        return self._loop

    def start(self, timeout: float = 15.0) -> None:
        """Start the engine in a background thread and wait until RUNNING."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            raise TimeoutError(f"Engine did not become ready in {timeout}s")
        if self._start_error is not None:
            raise self._start_error

    def _run(self) -> None:
        """Thread target: create loop, start engine, run forever."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            # Write a temp config binding the listener to a free local port
            cfg = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            )
            cfg.write(f"server:\n  host: 127.0.0.1\n  port: {self._port}\n")
            cfg.close()

            self._engine = PupyteerEngine(cfg.name)
            self._loop.run_until_complete(self._engine.start())
            self._ready.set()
            self._loop.run_forever()
        except Exception as exc:  # pragma: no cover — surfaced via start()
            self._start_error = exc
            self._ready.set()

    def stop(self, timeout: float = 15.0) -> None:
        """Stop the engine and join the background thread."""
        if self._loop is not None and self._engine is not None:
            future = asyncio.run_coroutine_threadsafe(
                self._engine.stop(), self._loop
            )
            try:
                future.result(timeout=timeout)
            except Exception as exc:
                logger.warning("Engine stop error: %s", exc)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("Engine thread stopped")


class CallbackTestHarness:
    """End-to-end test harness for the C2 callback loop.

    Uses the real agent simulator subprocess (pupyteer.tools.agent_simulator)
    against a real engine, then verifies session, command, and output via the
    engine's SessionManager.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        test_command: str = "echo pupyteer_test_ok",
        expected_output: str = "pupyteer_test_ok",
    ):
        self._host = host
        self._port = _find_free_port()
        self._test_command = test_command
        self._expected_output = expected_output
        self._engine_thread: Optional[EngineThread] = None
        self._agent_proc: Optional[subprocess.Popen] = None
        self._result: Dict[str, Any] = {"passed": False, "errors": []}

    def run(self) -> bool:
        """Execute the full callback test. Returns True on PASS."""
        logger.info("=" * 60)
        logger.info("Pupyteer Callback Test — starting")
        logger.info("=" * 60)

        try:
            self._start_engine()
            self._launch_agent()
            session_id = self._wait_for_session()
            self._send_test_command(session_id)
            self._wait_for_output(session_id)
            self._result["passed"] = True
        except Exception as exc:
            self._result["errors"].append(str(exc))
            logger.error("TEST FAILED: %s", exc, exc_info=True)
        finally:
            self._teardown()

        self._report()
        return self._result["passed"]

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------

    def _start_engine(self) -> None:
        """Start the engine (and its TCP listener) in a background thread."""
        logger.info("Starting engine on %s:%d ...", self._host, self._port)
        self._engine_thread = EngineThread(self._port)
        self._engine_thread.start()
        assert self._engine_thread.engine.is_running, "Engine not RUNNING"
        self._wait_for_port(self._host, self._port, timeout=5)
        logger.info("Engine running, listener on %s:%d", self._host, self._port)

    def _launch_agent(self) -> None:
        """Launch the agent simulator as a subprocess."""
        logger.info("Launching agent simulator...")
        self._agent_proc = subprocess.Popen(
            [
                sys.executable, "-m", "pupyteer.tools.agent_simulator",
                "--host", str(self._host),
                "--port", str(self._port),
                "--hostname", "callback-test-agent",
                "--username", "cbtest",
                "--interval", "0.5",
                "--max-checkins", "20",
            ],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def _wait_for_session(self, timeout: float = 10.0) -> str:
        """Poll the sessions list until the agent's session appears."""
        engine = self._engine_thread.engine  # type: ignore[union-attr]
        deadline = time.time() + timeout
        while time.time() < deadline:
            sessions = asyncio.run_coroutine_threadsafe(
                engine.sessions.list_all(), self._engine_thread.loop  # type: ignore[union-attr]
            ).result(timeout=5)
            for s in sessions:
                if s.hostname == "callback-test-agent":
                    logger.info("Session appeared: %s", s.session_id)
                    return s.session_id
            time.sleep(0.2)
        raise TimeoutError("Agent session did not appear in sessions list")

    def _send_test_command(self, session_id: str) -> None:
        """Queue the test command for the session via SessionManager."""
        engine = self._engine_thread.engine  # type: ignore[union-attr]
        logger.info("Sending test command: %s", self._test_command)
        command_id = asyncio.run_coroutine_threadsafe(
            engine.sessions.interact(session_id, self._test_command),
            self._engine_thread.loop,  # type: ignore[union-attr]
        ).result(timeout=5)
        assert command_id, "Failed to queue command"
        logger.info("Command queued: %s", command_id)

    def _wait_for_output(self, session_id: str, timeout: float = 15.0) -> None:
        """Poll command history until the command completes with output."""
        engine = self._engine_thread.engine  # type: ignore[union-attr]
        deadline = time.time() + timeout
        while time.time() < deadline:
            history = asyncio.run_coroutine_threadsafe(
                engine.sessions.get_command_history(session_id),
                self._engine_thread.loop,  # type: ignore[union-attr]
            ).result(timeout=5)
            for cmd in history:
                if (
                    cmd.get("command") == self._test_command
                    and cmd.get("status") == "completed"
                ):
                    result = cmd.get("result") or ""
                    assert self._expected_output in result, (
                        f"Output mismatch: {result!r}"
                    )
                    logger.info("Output received: %r", result)
                    return
            time.sleep(0.2)
        raise TimeoutError("Command output was not received in time")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _teardown(self) -> None:
        """Stop agent process and engine thread."""
        if self._agent_proc is not None:
            self._agent_proc.terminate()
            try:
                self._agent_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._agent_proc.kill()
        if self._engine_thread is not None:
            self._engine_thread.stop()
        logger.info("Teardown complete")

    @staticmethod
    def _wait_for_port(host: str, port: int, timeout: float = 5) -> None:
        """Wait until a TCP port is accepting connections."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                with socket.create_connection((host, port), timeout=1):
                    return
            except (ConnectionError, OSError):
                time.sleep(0.1)
        raise TimeoutError(f"Port {host}:{port} not ready after {timeout}s")

    def _report(self) -> None:
        """Print test report."""
        logger.info("=" * 60)
        if self._result["passed"]:
            logger.info("RESULT: PASS")
        else:
            logger.info("RESULT: FAIL")
            for err in self._result["errors"]:
                logger.info("  ERROR: %s", err)
        logger.info("=" * 60)


def main() -> int:
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    harness = CallbackTestHarness()
    passed = harness.run()
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
