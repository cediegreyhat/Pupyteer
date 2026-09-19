"""End-to-end C2 loop with the *generated* agent, run as a real subprocess.

test_live_callback.py speaks to the listener with a hand-written client whose
framing and message schema the shipped agent does not use, so it can pass while
no payload is able to check in. This module builds a stub through
AgentStubGenerator — the same template the payload builder renders — executes it
and asserts the operator-visible outcome: a session appears, a typed command
runs on the host, and its output comes back.
"""
from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
)

from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.engine import PupyteerEngine


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(predicate, timeout: float, interval: float = 0.2):
    """Poll until predicate() is truthy; return it, or None on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def _generate_agent(dir_path: Path, name: str, **overrides) -> Path:
    """Render the real stub template to a file and return its path."""
    settings = {"transport": "tcp", "host": "127.0.0.1"}
    settings.update(overrides)
    code = AgentStubGenerator().generate(StubConfig(name=name, **settings))
    path = dir_path / f"{name}_agent.py"
    path.write_text(code, encoding="utf-8")
    return path


def _load_agent_module(agent_path: Path):
    """Import a generated agent without running it (the __main__ guard holds)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(agent_path.stem, str(agent_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def listener_port():
    return _free_port()


@pytest.fixture
def agent_source(tmp_path, listener_port):
    """A real generated agent, beaconing fast, persistence and relay off."""
    path = _generate_agent(
        tmp_path, "labagent", port=listener_port, sleep=1, jitter=0,
    )
    code = path.read_text(encoding="utf-8")
    assert "install_persistence()" not in code, "persistence must be compiled out by default"
    return path


@pytest.mark.asyncio
async def test_generated_agent_checks_in_and_runs_a_command(tmp_path, listener_port, agent_source):
    """The one thing a C2 must do: payload runs, session appears, command returns."""
    engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
    assert engine._config.get("server.port") == listener_port

    proc = _start_agent(agent_source, tmp_path)
    try:
        await engine.start()

        session_id = await _await_session(engine)
        assert session_id, "generated agent never registered a session"

        info = await engine.sessions.get(session_id)
        assert info.hostname, "session has no hostname"
        assert info.os in ("windows", "linux", "macos", "android")

        output = await _run_on_agent(engine, session_id, "echo pupyteer-roundtrip")
        assert "pupyteer-roundtrip" in output

        named = await _run_on_agent(engine, session_id, "sysinfo")
        assert "hostname" in named

        # Marker file in the agent's cwd proves the callback really ran on that host.
        marker = tmp_path / "pupyteer-fs-marker"
        marker.write_text("listed", encoding="utf-8")
        listing = await _run_on_agent(engine, session_id, f"fs_list {tmp_path}")
        assert marker.name in listing, f"fs_list did not see the marker: {listing!r}"

        procs = await _run_on_agent(engine, session_id, "ps")
        assert "pid" in procs.lower(), f"process list unusable: {procs!r}"
    finally:
        _stop_agent(proc)
        await engine.stop()


async def _await_session(engine, timeout: float = 25.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ids = engine.sessions.list_ids()
        if ids:
            return ids[0]
        await asyncio.sleep(0.2)
    return None


async def _run_on_agent(engine, session_id: str, command: str, timeout: float = 25.0) -> str:
    command_id = await engine.sessions.interact(session_id, command)
    assert command_id, "command was not queued"
    deadline = time.time() + timeout
    while time.time() < deadline:
        queue = await engine.sessions.get_pending_commands(session_id)
        for entry in queue:
            if entry["command_id"] == command_id and entry["status"] == "completed":
                return entry.get("result") or ""
        await asyncio.sleep(0.2)
    pytest.fail(f"agent never returned output for {command!r}")


class TestHTTPTransport:
    """HTTP payloads must reach the same session protocol over a POST."""

    @pytest.mark.asyncio
    async def test_generated_http_agent_checks_in_and_runs_a_command(
        self, tmp_path, listener_port
    ):
        http_port = _free_port()
        config_path = tmp_path / "pupyteer.yaml"
        config_path.write_text(yaml.safe_dump({
            "server": {
                "host": "127.0.0.1", "port": listener_port,
                "http_port": http_port, "http_uri": "/index.html",
            },
            "operator": {"name": "lab-op"},
        }), encoding="utf-8")

        engine = PupyteerEngine(str(config_path))
        agent = _generate_agent(
            tmp_path, "httpagent", transport="http", port=http_port,
            http_uri="/index.html", sleep=1, jitter=0,
        )
        proc = _start_agent(agent, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id, "http agent never registered: %s" % _drain(proc)
            output = await _run_on_agent(engine, session_id, "echo http-roundtrip")
            assert "http-roundtrip" in output
        finally:
            _stop_agent(proc)
            await engine.stop()


def _drain(proc) -> str:
    """Best-effort agent stderr for a failure message; never blocks long."""
    try:
        proc.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        return "<still running>"
    try:
        return (proc.stderr.read() or b"").decode("utf-8", "replace")[-2000:]
    except Exception:
        return "<unreadable>"


class TestOperatorShell:
    """What the operator sees: `sessions interact` must print command output."""

    @pytest.mark.asyncio
    async def test_interact_prints_agent_output(self, tmp_path, listener_port, agent_source, capsys):
        from pupyteer.tui.commands.sessions import sessions_interact, sessions_results

        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        proc = _start_agent(agent_source, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id, "generated agent never registered a session"

            tui = _FakeTUI(engine)
            with _scripted_input(["echo tui-visible", "exit"]):
                await sessions_interact(tui, [session_id])

            printed = capsys.readouterr().out
            assert "tui-visible" in printed, (
                "sessions interact queued the command but never showed its output"
            )

            capsys.readouterr()
            await sessions_results(tui, [session_id])
            assert "tui-visible" in capsys.readouterr().out
        finally:
            _stop_agent(proc)
            await engine.stop()


def _write_server_config(tmp_path, port: int) -> str:
    config_path = tmp_path / "pupyteer.yaml"
    config_path.write_text(yaml.safe_dump({
        "server": {"host": "127.0.0.1", "port": port},
        "operator": {"name": "lab-op"},
    }), encoding="utf-8")
    return str(config_path)


def _start_agent(agent_path: Path, cwd: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, str(agent_path)],
        cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def _stop_agent(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


class _FakeTUI:
    """Minimal surface the session commands touch."""

    def __init__(self, engine):
        self._engine = engine
        self._theme = None
        self.messages = []

    def render_success(self, text): self.messages.append(("success", text))
    def render_error(self, text): self.messages.append(("error", text))
    def render_warning(self, text): self.messages.append(("warning", text))


class _scripted_input:
    """Replace blocking input() with a queue of operator keystrokes."""

    def __init__(self, lines):
        self._lines = list(lines)
        self._original = None

    def __enter__(self):
        import builtins
        self._original = builtins.input
        lines = self._lines

        def fake_input(_prompt=""):
            if not lines:
                raise EOFError
            return lines.pop(0)

        builtins.input = fake_input
        return self

    def __exit__(self, *_exc):
        import builtins
        builtins.input = self._original


class TestCommandVocabulary:
    """_parse_command decides what an operator's typed line actually does."""

    @pytest.fixture
    def agent(self, tmp_path):
        return _load_agent_module(_generate_agent(tmp_path, "vocab", port=1, sleep=1, jitter=0))

    def test_unknown_text_runs_as_shell(self, agent):
        assert agent._parse_command("whoami") == {"action": "exec", "command": "whoami"}

    def test_named_actions_bypass_the_shell(self, agent):
        assert agent._parse_command("sysinfo") == {"action": "sysinfo"}
        assert agent._parse_command("ps") == {"action": "processes"}

    def test_arguments_reach_module_actions(self, agent):
        assert agent._parse_command("fs_list /etc") == {"action": "fs_list", "path": "/etc"}

    def test_exit_maps_to_shutdown(self, agent):
        assert agent._parse_command("exit") == {"action": "shutdown"}

    def test_ping_is_answered_without_spawning_a_process(self, agent):
        assert agent._parse_command("ping") == {"action": "ping"}

    def test_command_with_arguments_splits_on_posix(self, agent):
        """shell=False plus a raw string means "no arguments" off Windows."""
        result = agent._run_command(f'{agent._sy.executable} -c "print(6*7)"')
        assert "42" in result, f"argumented command did not run: {result!r}"


class TestTransportFraming:
    """The agent must frame exactly the way AgentListener reads."""

    @pytest.fixture
    def transport_class(self, tmp_path):
        return _load_agent_module(
            _generate_agent(tmp_path, "frame", port=1, sleep=1, jitter=0)
        ).TCPTransport

    def test_request_is_newline_delimited_json(self, transport_class):
        """A length-prefixed frame is read by the listener as malformed JSON."""
        import json
        sent = {}

        class _FakeSocket:
            def settimeout(self, _t):
                pass

            def connect(self, _addr):
                pass

            def sendall(self, data):
                sent["data"] = data

            def recv(self, _n):
                return b'{"type": "registered", "session_id": "abc"}\n'

            def close(self):
                pass

        transport = transport_class("127.0.0.1", 9)
        transport._sock = _FakeSocket()
        reply = transport.request({"type": "register"})

        assert sent["data"].endswith(b"\n")
        assert not sent["data"].startswith(b"\x00"), "no binary length prefix may precede JSON"
        assert json.loads(sent["data"].decode().strip()) == {"type": "register"}
        assert reply == {"type": "registered", "session_id": "abc"}
