"""Callback test — prove the C2 loop works before a payload has to.

Starts an engine on a loopback port, generates an agent through the same
template the payload builder renders, runs it as a real subprocess, and checks
the operator-visible outcome: a session appears, a command runs on the host,
its output comes back.

This is deliberately not a hand-written client. A client written beside the
protocol can keep passing after the shipped payload stops working — which is
how this tool came to speak a dialect no agent uses: no enrollment secret, no
TLS, no beacon token, and so no chance of completing a registration against a
listener left on its defaults.

Usage:
    python -m pupyteer.tools.callback_test
    python -m pupyteer.tools.callback_test --config /path/to/pupyteer.yaml
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.core.enrollment import listener_secret
from pupyteer.server.core.tls import listener_tls

logger = logging.getLogger("pupyteer.callback_test")

#: Written into the sessions list; what the test command has to give back.
MARKER = "pupyteer_test_ok"
TEST_COMMAND = f"echo {MARKER}"


def _find_free_port() -> int:
    """Ask the OS for a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CallbackTestError(RuntimeError):
    """A step failed, with the explanation an operator needs to act on it."""


class EngineThread:
    """Runs the Pupyteer engine in a background thread with its own loop."""

    def __init__(self, config_path: str):
        self._config_path = config_path
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

    def start(self, timeout: float = 20.0) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            raise TimeoutError(f"Engine did not become ready in {timeout}s")
        if self._start_error is not None:
            raise self._start_error

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._engine = PupyteerEngine(self._config_path)
            self._loop.run_until_complete(self._engine.start())
            self._ready.set()
            self._loop.run_forever()
        except Exception as exc:  # pragma: no cover — surfaced via start()
            self._start_error = exc
            self._ready.set()

    def call(self, coro, timeout: float = 10.0):
        """Run a coroutine on the engine loop from this thread."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout=timeout)

    def stop(self, timeout: float = 15.0) -> None:
        if self._loop is not None and self._engine is not None:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._engine.stop(), self._loop).result(timeout=timeout)
            except Exception as exc:
                logger.warning("Engine stop error: %s", exc)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=timeout)


class CallbackTestHarness:
    """End-to-end check of the callback loop with a generated payload."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        host: str = "127.0.0.1",
        port: Optional[int] = None,
        tls: Optional[bool] = None,
        timeout: float = 30.0,
    ):
        #: A scratch directory for the listener's own material — the TLS pair,
        #: the enrollment secret, the audit trail, the operator store. The test
        #: is a server start like any other and those files are what a server
        #: start writes; pointing them here is what keeps a self-test run from
        #: dropping a real enrollment secret into a checkout.
        self._workdir = Path(tempfile.mkdtemp(prefix="pupyteer-callback-test-"))
        self._host = host
        self._port = port if port is not None else _find_free_port()
        self._tls = tls
        self._timeout = timeout
        self._config_path = config_path
        self._engine: Optional[EngineThread] = None
        self._agent_proc: Optional[subprocess.Popen] = None
        self._errors: List[str] = []
        self._steps: List[str] = []
        self._refusals: Dict[str, int] = {}

    @property
    def errors(self) -> List[str]:
        """Why a run failed, in the words the operator is shown."""
        return list(self._errors)

    @property
    def refusals(self) -> Dict[str, int]:
        """What the listener refused during the run, read before it stopped."""
        return dict(self._refusals)

    # ------------------------------------------------------------------
    #  Run
    # ------------------------------------------------------------------

    def run(self) -> bool:
        logger.info("=" * 66)
        logger.info("Pupyteer callback test - %s:%d", self._host, self._port)
        logger.info("=" * 66)
        passed = False
        try:
            cfg = self._write_config()
            self._start_engine(cfg)
            agent = self._generate_agent()
            self._launch_agent(agent)
            session_id = self._await_session()
            self._run_command(session_id)
            passed = not self._errors
        except CallbackTestError as exc:
            self._errors.append(str(exc))
            logger.error("FAIL: %s", exc)
        except Exception as exc:
            self._errors.append(f"{type(exc).__name__}: {exc}")
            logger.error("FAIL: %s", exc, exc_info=True)
        finally:
            # Read before the listeners are torn down: a refusal counter is a
            # fact about the run, and once the engine has stopped there is
            # nothing left to ask.
            self._refusals = self._refusal_stats()
            self._teardown()
        self._report(passed)
        return passed

    # ------------------------------------------------------------------
    #  Steps
    # ------------------------------------------------------------------

    def _write_config(self) -> str:
        """Materialise the config this run starts its listener from."""
        base: Dict[str, Any] = {}
        if self._config_path:
            src = Path(self._config_path)
            if not src.exists():
                raise CallbackTestError(f"config file not found: {src}")
            base = yaml.safe_load(src.read_text(encoding="utf-8")) or {}

        server = dict(base.get("server") or {})
        server.update({
            "host": self._host,
            "port": self._port,
            "tls_cert": str(self._workdir / "listener.crt"),
            "tls_key": str(self._workdir / "listener.key"),
            "tls_hostnames": ["127.0.0.1", "localhost"],
            "agent_auth_file": str(self._workdir / "enrollment.key"),
        })
        if self._tls is not None:
            server["tls"] = self._tls

        cfg = {
            **base,
            "server": server,
            "audit": {**(base.get("audit") or {}),
                      "log_file": str(self._workdir / "audit.json")},
            "security": {**(base.get("security") or {}),
                         "operators_file": str(self._workdir / "operators.json")},
            "paths": {**(base.get("paths") or {}),
                      "logs": str(self._workdir / "logs"),
                      "payload_artifacts": str(self._workdir / "artifacts")},
            "evasion": {**(base.get("evasion") or {}),
                        "history_path": str(self._workdir / "evasion_history.json")},
            "operator": {**(base.get("operator") or {}), "name": "callback-test"},
        }
        path = self._workdir / "callback-test.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        self._note(f"config: {path.name} (tls={server.get('tls', 'default')})")
        return str(path)

    def _start_engine(self, config_path: str) -> None:
        self._engine = EngineThread(config_path)
        self._engine.start()
        if not self._engine.engine.is_running:
            raise CallbackTestError("engine did not reach RUNNING")
        self._await_listener()
        self._note("listener: up")

    def _await_listener(self) -> None:
        """Wait for the agent listener to report itself listening.

        Deliberately not a TCP connect: probing the port from the outside makes a
        handshake refusal on a TLS listener, and a self-test that inflates the
        counter an operator reads to spot strangers is worse than no counter.
        """
        engine = self._engine  # type: ignore[union-attr]

        def peek():
            rows = engine.engine.transports.list()
            return any(r.get("name") == "agent_listener" and r.get("state") == "listening"
                       for r in rows)

        if not self._poll(peek, "the listener to report ready"):
            raise CallbackTestError(
                f"the engine started but no agent listener on {self._host}:{self._port}")

    def _generate_agent(self) -> Path:
        """Render a payload through the template the builder uses.

        TLS and the enrollment secret come from the running engine's own config,
        not from a guess in this file: that is the whole value of the test. If
        the pin and the secret the built agent carries are the ones the listener
        resolves, a real payload built from this server will connect.
        """
        engine = self._engine.engine  # type: ignore[union-attr]
        get = engine.config.get
        material = listener_tls(get)
        secret = listener_secret(get)
        if (get("server.tls", True) and material is None) or (
                get("server.agent_auth", True) and not secret):
            raise CallbackTestError(
                "listener is configured for TLS/enrollment but resolved neither a "
                "certificate nor a secret - nothing a payload could trust")

        cfg = StubConfig(
            name="callbacktest",
            transport="tcp",
            host=self._host,
            port=self._port,
            sleep=1,
            jitter=0,
            persistence=False,
            relay=False,
            tls=material is not None,
            tls_cert_pem=material.cert_pem if material else "",
            auth_secret=secret or "",
        )
        code = AgentStubGenerator().generate(cfg)
        if "install_persistence()" in code:
            raise CallbackTestError(
                "generated agent writes persistence; a self-test must not leave "
                "anything behind on the host it runs on")
        path = self._workdir / "callbacktest_agent.py"
        path.write_text(code, encoding="utf-8")
        self._note("payload: generated (%s%s)" % (
            "TLS, pinned" if material else "plaintext",
            ", enrolled" if secret else ", no enrollment secret"))
        return path

    def _launch_agent(self, agent_path: Path) -> None:
        self._agent_proc = subprocess.Popen(
            [sys.executable, str(agent_path)],
            cwd=str(self._workdir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._note("agent: started (pid %d)" % self._agent_proc.pid)

    def _await_session(self) -> str:
        engine = self._engine  # type: ignore[union-attr]

        def peek():
            ids = engine.engine.sessions.list_ids()
            return ids[0] if ids else None

        session_id = self._poll(peek, "a session to appear")
        if session_id is None:
            raise CallbackTestError(
                "%s - %s" % (
                    "the generated agent never registered",
                    self._agent_verdict() or "the agent produced no output"))
        self._note("session: %s" % session_id)
        return session_id

    def _run_command(self, session_id: str) -> None:
        engine = self._engine  # type: ignore[union-attr]
        command_id = engine.call(engine.engine.sessions.interact(session_id, TEST_COMMAND))
        if not command_id:
            raise CallbackTestError("the command was not queued")
        self._note("command: queued (%s)" % TEST_COMMAND)

        #: A command the listener has not finished with. Returning one of these
        #: would end the wait early and report the queue as a result.
        in_flight = ("queued", "executing", "pending")

        def peek():
            history = engine.call(
                engine.engine.sessions.get_command_history(session_id))
            for cmd in history:
                if cmd.get("command_id") == command_id and cmd.get("status") not in in_flight:
                    return cmd
            return None

        entry = self._poll(peek, "the command to complete")
        if entry is None:
            raise CallbackTestError(
                "no result came back for the queued command - %s"
                % (self._agent_verdict() or "and the agent gave no reason"))
        if entry.get("status") != "completed":
            raise CallbackTestError(
                f"command ended as {entry.get('status')!r}: {entry.get('result')!r}")
        if MARKER not in (entry.get("result") or ""):
            raise CallbackTestError(
                f"command returned {entry.get('result')!r}, which is not our output")
        self._note("output: received")

    # ------------------------------------------------------------------
    #  Diagnostics
    # ------------------------------------------------------------------

    def _poll(self, peek, what: str):
        """Return peek() once it is truthy, or None after the timeout."""
        deadline = time.time() + self._timeout
        while time.time() < deadline:
            value = peek()
            if value:
                return value
            if self._agent_proc is not None and self._agent_proc.poll() is not None:
                # The agent gave up; keep polling briefly in case its last
                # message is already in flight, then stop waiting on a process
                # that has exited.
                time.sleep(1.0)
                value = peek()
                if value:
                    return value
                return None
            time.sleep(0.25)
        return None

    def _agent_verdict(self) -> str:
        """What the agent itself said, which is the only diagnosis that helps."""
        if self._agent_proc is None:
            return ""
        try:
            out = self._agent_proc.stdout.read().decode("utf-8", "replace") if (
                self._agent_proc.poll() is not None) else ""
        except Exception:
            out = ""
        tail = [line.strip() for line in out.splitlines() if line.strip()]
        if self._agent_proc.poll() is not None:
            code = self._agent_proc.returncode
            reason = tail[-1] if tail else "no output"
            return f"agent exited with code {code}: {reason}"
        return ""

    def _refusal_stats(self) -> Dict[str, int]:
        try:
            rows = self._engine.engine.transports.list()  # type: ignore[union-attr]
        except Exception:
            return {}
        out: Dict[str, int] = {}
        for row in rows:
            stats = row.get("stats") or {}
            for key in ("registrations_rejected", "beacons_refused", "handshakes_refused"):
                value = stats.get(key)
                if isinstance(value, int) and value:
                    out[key] = out.get(key, 0) + value
        return out

    def _note(self, message: str) -> None:
        self._steps.append(message)
        logger.info("  %s", message)

    def _report(self, passed: bool) -> None:
        logger.info("-" * 66)
        for step in self._steps:
            logger.info("  %s%s", "ok  " if passed else "    ", step)
        if self._refusals:
            logger.info("  refusals counted by the listener: %s", self._refusals)
        logger.info("RESULT: %s", "PASS" if passed else "FAIL")
        for err in self._errors:
            logger.info("  why: %s", err)
        logger.info("=" * 66)

    def _teardown(self) -> None:
        if self._agent_proc is not None and self._agent_proc.poll() is None:
            self._agent_proc.terminate()
            try:
                self._agent_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._agent_proc.kill()
                self._agent_proc.wait(timeout=10)
        if self._engine is not None:
            self._engine.stop()
        shutil.rmtree(self._workdir, ignore_errors=True)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prove the C2 callback loop with a generated agent, before a real one has to.")
    parser.add_argument("--config", help="start the listener from this config file")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, help="default: a free loopback port")
    parser.add_argument("--tls", dest="tls", action="store_true", default=None,
                        help="force the test listener to speak TLS")
    parser.add_argument("--no-tls", dest="tls", action="store_false",
                        help="force plaintext - a deviation from the shipped default, "
                             "and the build log for a real payload says the same")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )
    # The engine is chatty and its lines are not the answer; this tool's own
    # step list is. Quieting the package would silence the report with it, so
    # the reporter keeps its own level.
    logging.getLogger("pupyteer").setLevel(
        logging.DEBUG if args.verbose else logging.WARNING)
    logging.getLogger("pupyteer.callback_test").setLevel(
        logging.DEBUG if args.verbose else logging.INFO)

    harness = CallbackTestHarness(
        config_path=args.config, host=args.host, port=args.port,
        tls=args.tls, timeout=args.timeout,
    )
    return 0 if harness.run() else 1


if __name__ == "__main__":
    sys.exit(main())
