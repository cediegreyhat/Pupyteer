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
from pupyteer.server.core.enrollment import ensure_team_secret
from pupyteer.server.core.tls import certificate_fingerprint


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Written into tmp_path by every server config below, so a test run never
# generates a real enrollment secret into the working tree, and never depends on
# one left there by a previous run.
_TEST_SECRET = "0123456789abcdef" * 4
_ENROLLMENT_FILE = "enrollment.key"


def _put_secret(tmp_path: Path) -> str:
    """Place the enrollment secret where these tests point server.agent_auth_file."""
    (tmp_path / _ENROLLMENT_FILE).write_text(_TEST_SECRET + "\n", encoding="ascii")
    return _TEST_SECRET


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
    """Render the real stub template to a file and return its path.

    Carries the enrollment secret by default, because that is what the server in
    these tests checks: an agent built without one proves the *transport* under
    test and not a bug in enrollment.
    """
    settings = {"transport": "tcp", "host": "127.0.0.1", "auth_secret": _TEST_SECRET}
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
                "agent_auth_file": str(tmp_path / _ENROLLMENT_FILE),
            },
            "operator": {"name": "lab-op"},
        }), encoding="utf-8")
        _put_secret(tmp_path)

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


class TestEnrollment:
    """Encryption and admission are different questions.

    TLS can make the channel unreadable while the listener still hands a session
    — a command channel with file transfer — to anything that connects. These run
    real generated agents against a real listener, because the failure being
    guarded against is a payload and a server that disagree.
    """

    def test_the_generated_agent_presents_its_secret(self, tmp_path):
        """Not just a constant defined: the register message has to carry it."""
        agent = _load_agent_module(_generate_agent(tmp_path, "presents", port=1))
        assert agent.AUTH_SECRET == _TEST_SECRET

        captured = {}

        class _Recorder:
            def request(self, msg):
                captured.update(msg)
                return {"type": "registered", "session_id": "s-1"}

        assert agent._register(_Recorder()) == "s-1"
        assert captured["auth"] == _TEST_SECRET

    @pytest.mark.asyncio
    async def test_an_agent_without_the_secret_is_refused_and_gives_up(
        self, tmp_path, listener_port
    ):
        """Retrying a rejection forever looks like bad egress, not a wrong build."""
        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        await engine.start()
        try:
            agent = _generate_agent(tmp_path, "uninvited", port=listener_port,
                                    sleep=1, jitter=0, auth_secret="")
            # to_thread, because subprocess.run would block the loop the listener
            # needs in order to answer the registration.
            proc = await asyncio.to_thread(
                subprocess.run, [sys.executable, str(agent)], cwd=str(tmp_path),
                capture_output=True, timeout=60)
            joined = (proc.stderr + proc.stdout).decode("utf-8", "replace").lower()
            assert proc.returncode == 3, (
                f"a rejected agent kept beaconing (rc={proc.returncode}): {joined[-2000:]}"
            )
            assert "enrollment secret" in joined, joined[-2000:]
            assert not engine.sessions.list_ids(), "a refused registration opened a session"
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_a_wrong_secret_is_refused(self, tmp_path, listener_port):
        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        await engine.start()
        try:
            agent = _generate_agent(tmp_path, "wrongsecret", port=listener_port,
                                    sleep=1, jitter=0, auth_secret=_TEST_SECRET + "x")
            proc = await asyncio.to_thread(
                subprocess.run, [sys.executable, str(agent)], cwd=str(tmp_path),
                capture_output=True, timeout=60)
            assert proc.returncode == 3
            assert not engine.sessions.list_ids()
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_turning_agent_auth_off_admits_an_unauthenticated_agent(
        self, tmp_path, listener_port
    ):
        """The escape hatch has to work, or an operator cannot recover a listener

        that lost its secret file — and the warning that says so has to be the
        true one.
        """
        config_path = _write_server_config(tmp_path, listener_port, agent_auth=False)
        engine = PupyteerEngine(config_path)
        agent = _generate_agent(tmp_path, "open-door", port=listener_port,
                                sleep=1, jitter=0, auth_secret="")
        proc = _start_agent(agent, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id, "agent_auth off still refused: %s" % _drain(proc)
            assert engine.get_status()["config"]["agent_auth"] is False
        finally:
            _stop_agent(proc)
            await engine.stop()

    @pytest.mark.asyncio
    async def test_the_http_listener_applies_the_same_rule(self, tmp_path, listener_port):
        """Two listeners, one admission rule.

        The HTTP listener is a separate class with its own config dict, so the
        secret has to reach it too — otherwise a target that cannot reach the TCP
        port finds the door that was supposed to be closed.
        """
        http_port = _free_port()
        config_path = tmp_path / "http-auth.yaml"
        config_path.write_text(yaml.safe_dump({
            "server": {
                "host": "127.0.0.1", "port": listener_port,
                "http_port": http_port, "http_uri": "/index.html",
                "agent_auth_file": str(tmp_path / _ENROLLMENT_FILE),
            },
            "operator": {"name": "lab-op"},
        }), encoding="utf-8")
        _put_secret(tmp_path)

        engine = PupyteerEngine(str(config_path))
        agent = _generate_agent(tmp_path, "http-uninvited", transport="http",
                                port=http_port, http_uri="/index.html",
                                sleep=1, jitter=0, auth_secret="")
        proc = _start_agent(agent, tmp_path)
        try:
            await engine.start()
            # The agent stops on auth_failed and nowhere else, so its exit is the
            # proof the HTTP listener really saw the request and turned it down —
            # a missing session alone is also what a broken transport produces.
            deadline = time.time() + 30
            while time.time() < deadline and proc.poll() is None:
                await asyncio.sleep(0.25)
            assert proc.returncode == 3, (
                f"http agent was not refused (rc={proc.returncode}): {_drain(proc)}")
            assert not engine.sessions.list_ids()
        finally:
            _stop_agent(proc)
            await engine.stop()

    @pytest.mark.asyncio
    async def test_the_running_listener_reports_whether_it_checks(
        self, tmp_path, listener_port
    ):
        """A status line claiming a check that nothing performs is worse than none."""
        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        assert engine.get_status()["config"]["agent_auth"] is None, (
            "an unstarted listener must not report an admission rule")
        await engine.start()
        try:
            assert engine.get_status()["config"]["agent_auth"] is True
        finally:
            await engine.stop()


def _write_tls_server_config(tmp_path, port: int) -> str:
    """A server config that speaks TLS, with its material kept inside tmp_path.

    The certificate is deliberately absent: the listener has to produce it on
    first start, which is what an operator who flips server.tls will hit.
    """
    config_path = tmp_path / "pupyteer-tls.yaml"
    config_path.write_text(yaml.safe_dump({
        "server": {
            "host": "127.0.0.1", "port": port, "tls": True,
            "tls_cert": str(tmp_path / "listener.crt"),
            "tls_key": str(tmp_path / "listener.key"),
            "tls_hostnames": ["127.0.0.1"],
            "agent_auth_file": str(tmp_path / _ENROLLMENT_FILE),
        },
        "operator": {"name": "lab-op"},
    }), encoding="utf-8")
    _put_secret(tmp_path)
    return str(config_path)


class TestTLS:
    """The session channel carries every command result, so it has to be encrypted
    *and* authenticated: a payload that trusts any certificate tells the operator
    the channel is private while anyone on the path is reading it.
    """

    @pytest.mark.asyncio
    async def test_pinned_agent_works_over_tls(self, tmp_path, listener_port):
        engine = PupyteerEngine(_write_tls_server_config(tmp_path, listener_port))
        await engine.start()
        proc = None
        try:
            cert_file = tmp_path / "listener.crt"
            assert cert_file.exists(), "server.tls did not produce a listener certificate"
            assert (tmp_path / "listener.key").exists()

            agent = _generate_agent(
                tmp_path, "tlsagent", port=listener_port, sleep=1, jitter=0,
                tls=True, tls_cert_pem=cert_file.read_text(encoding="ascii"),
            )
            proc = _start_agent(agent, tmp_path)

            session_id = await _await_session(engine)
            assert session_id, "TLS agent never registered: %s" % _drain(proc)
            output = await _run_on_agent(engine, session_id, "echo tls-roundtrip")
            assert "tls-roundtrip" in output
            # What the console advertises has to be what the socket speaks.
            served = engine.get_status()["config"]["listener_tls"]
            assert served == certificate_fingerprint(str(cert_file))
        finally:
            if proc is not None:
                _stop_agent(proc)
            await engine.stop()

    @pytest.mark.asyncio
    async def test_the_port_refuses_plaintext(self, tmp_path, listener_port):
        """A TLS listener must not also answer plaintext.

        Dual-use ports are the usual way "encryption available" turns out to
        mean "encryption optional": a tap, or an agent built without the pin,
        still gets a session.
        """
        engine = PupyteerEngine(_write_tls_server_config(tmp_path, listener_port))
        await engine.start()
        try:
            def probe():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect(("127.0.0.1", listener_port))
                    s.sendall(b'{"type": "register", "hostname": "plaintext-probe"}\n')
                    return s.recv(4096)

            # The server fails the handshake instead of parsing the line, so the
            # probe gets an alert, an empty read, or a socket error. What it must
            # not get is a session_id.
            try:
                reply = await asyncio.to_thread(probe)
            except OSError:
                reply = b""
            assert b"session_id" not in reply, "listener answered a plaintext register"
            assert not engine.sessions.list_ids(), "plaintext probe created a session"
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_a_different_certificate_is_rejected(self, tmp_path, listener_port):
        """The wrong pin has to fail closed — this is the whole security property."""
        from pupyteer.server.core.tls import ensure_listener_cert

        other_cert, _, _ = ensure_listener_cert(
            str(tmp_path / "other.crt"), str(tmp_path / "other.key"),
            host_names=("127.0.0.1",),
        )
        engine = PupyteerEngine(_write_tls_server_config(tmp_path, listener_port))
        await engine.start()
        try:
            agent = _load_agent_module(_generate_agent(
                tmp_path, "wrongpin", port=listener_port, sleep=1, jitter=0,
                tls=True, tls_cert_pem=Path(other_cert).read_text(encoding="ascii"),
            ))
            transport = agent.TCPTransport("127.0.0.1", listener_port)
            try:
                with pytest.raises(Exception) as caught:
                    await asyncio.to_thread(transport._connect)
                assert "certificate verify failed" in str(caught.value)
            finally:
                transport.close()
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_https_agent_reaches_the_http_listener(self, tmp_path, listener_port):
        """The HTTP listener is the one a filtered target can reach, so TLS has to
        work there too — and an https:// URL with an unpinned trust store is
        exactly where a self-signed team server gets silently rejected.
        """
        http_port = _free_port()
        config_path = tmp_path / "pupyteer-tls-http.yaml"
        config_path.write_text(yaml.safe_dump({
            "server": {
                "host": "127.0.0.1", "port": listener_port,
                "http_port": http_port, "http_uri": "/index.html", "tls": True,
                "tls_cert": str(tmp_path / "hlistener.crt"),
                "tls_key": str(tmp_path / "hlistener.key"),
                "agent_auth_file": str(tmp_path / _ENROLLMENT_FILE),
            },
            "operator": {"name": "lab-op"},
        }), encoding="utf-8")
        _put_secret(tmp_path)

        engine = PupyteerEngine(str(config_path))
        await engine.start()
        proc = None
        try:
            cert = (tmp_path / "hlistener.crt").read_text(encoding="ascii")
            agent = _generate_agent(
                tmp_path, "httpsagent", transport="https", port=http_port,
                sleep=1, jitter=0, tls=True, tls_cert_pem=cert,
            )
            proc = _start_agent(agent, tmp_path)
            session_id = await _await_session(engine)
            assert session_id, "https agent never registered: %s" % _drain(proc)
            output = await _run_on_agent(engine, session_id, "echo https-roundtrip")
            assert "https-roundtrip" in output
        finally:
            if proc is not None:
                _stop_agent(proc)
            await engine.stop()

    @pytest.mark.asyncio
    async def test_a_payload_built_before_the_server_starts_connects(
        self, tmp_path, listener_port
    ):
        """The build side and the listen side each derive the pin from config.

        This is the test that catches them drifting: a payload the operator built
        yesterday, before the server was ever started, has to call home today.
        """
        from pupyteer.payloads.manager import PayloadConfig, PayloadManager, PayloadType
        from pupyteer.server.core.logging import AuditLogger

        config_path = _write_tls_server_config(tmp_path, listener_port)
        build_config = ConfigManager(config_path)
        build_config.set("paths.payload_artifacts", str(tmp_path / "artifacts"))
        manager = PayloadManager(build_config, AuditLogger(build_config))

        cert_file = tmp_path / "listener.crt"
        assert not cert_file.exists(), "TLS material must not pre-exist the build"
        meta = await manager.build(PayloadConfig(
            name="tls-chain", payload_type=PayloadType.SCRIPT,
            host="127.0.0.1", port=listener_port, sleep=1, jitter=0,
        ))
        assert cert_file.exists(), "building a TLS payload produced no listener certificate"

        engine = PupyteerEngine(config_path)
        proc = None
        try:
            await engine.start()
            proc = _start_agent(Path(meta.artifact_path), tmp_path)
            session_id = await _await_session(engine)
            assert session_id, "built payload never registered: %s" % _drain(proc)
            output = await _run_on_agent(engine, session_id, "echo built-over-tls")
            assert "built-over-tls" in output
        finally:
            if proc is not None:
                _stop_agent(proc)
            await engine.stop()

    def test_an_agent_built_without_the_pin_says_so(self, tmp_path):
        """TLS with no compiled certificate is a build mistake, not a downgrade."""
        agent = _load_agent_module(_generate_agent(
            tmp_path, "nopin", port=1, sleep=1, jitter=0, tls=True,
        ))
        assert agent.TLS_ON is True
        assert agent.TLS_CERT_PEM == ""
        with pytest.raises(Exception, match="no listener certificate"):
            agent.pinned_tls_context()

    def test_running_one_exits_instead_of_looping_silently(self, tmp_path):
        """Retrying a handshake it can never complete would look like a target
        with good egress filtering instead of a payload that was built wrong."""
        agent = _generate_agent(tmp_path, "nopin-run", port=1, sleep=1, jitter=0, tls=True)
        proc = subprocess.run([sys.executable, str(agent)], cwd=str(tmp_path),
                              capture_output=True, timeout=30)
        assert proc.returncode == 2
        joined = (proc.stderr + proc.stdout).decode("utf-8", "replace").lower()
        assert "no listener certificate" in joined

    def test_tls_is_off_unless_the_server_turns_it_on(self, tmp_path):
        agent = _load_agent_module(_generate_agent(tmp_path, "plaintext", port=1))
        assert agent.TLS_ON is False
        assert agent.TLS_CERT_PEM == ""


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


class TestSessionKillStopsTheImplant:
    """`sessions kill` must take the agent down, not just the server's record."""

    @pytest.mark.asyncio
    async def test_kill_terminates_the_running_agent(self, tmp_path, listener_port, agent_source):
        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        proc = _start_agent(agent_source, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id
            assert proc.poll() is None, "agent should still be running"

            assert await engine.sessions.kill(session_id, reason="test")
            # The agent beacons once a second here, so the order is picked up
            # within a couple of intervals.
            deadline = time.time() + 30
            while time.time() < deadline and proc.poll() is None:
                await asyncio.sleep(0.25)

            assert proc.returncode is not None, (
                "sessions kill left the implant running on the target"
            )
        finally:
            _stop_agent(proc)
            await engine.stop()


class TestFileTransfer:
    """Files have to move both ways for this to be worth running."""

    @pytest.mark.asyncio
    async def test_download_and_upload_round_trip(self, tmp_path, listener_port, agent_source):
        from pupyteer.tui.commands.sessions import sessions_download, sessions_upload

        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        proc = _start_agent(agent_source, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id, "generated agent never registered a session"

            # A file larger than one 512 KiB chunk, so the loop is really exercised.
            remote_file = tmp_path / "target" / "secret.bin"
            remote_file.parent.mkdir(parents=True, exist_ok=True)
            payload = bytes(range(256)) * 4096          # 1 MiB
            remote_file.write_bytes(payload)

            tui = _FakeTUI(engine)
            local_copy = tmp_path / "operator" / "secret.bin"
            result = await sessions_download(
                tui, [session_id, str(remote_file), str(local_copy)]
            )
            assert result["status"] == "ok", result
            assert local_copy.read_bytes() == payload, "downloaded file is not the original"

            back = tmp_path / "operator" / "upload.bin"
            back.write_bytes(payload)
            dest = tmp_path / "target" / "uploaded.bin"
            result = await sessions_upload(tui, [session_id, str(back), str(dest)])
            assert result["status"] == "ok", result
            assert dest.read_bytes() == payload, "uploaded file is not the original"
        finally:
            _stop_agent(proc)
            await engine.stop()

    @pytest.mark.asyncio
    async def test_download_reports_a_missing_remote_file(self, tmp_path, listener_port, agent_source):
        from pupyteer.tui.commands.sessions import sessions_download

        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        proc = _start_agent(agent_source, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id
            tui = _FakeTUI(engine)
            result = await sessions_download(
                tui, [session_id, str(tmp_path / "definitely-not-here"),
                      str(tmp_path / "out.bin")]
            )
            assert result["status"] == "error", "a missing file must not look like success"
        finally:
            _stop_agent(proc)
            await engine.stop()


def _has_desktop() -> bool:
    """Whether this host can actually produce a screen image.

    A headless runner has no display to capture, which is not the agent's
    failure — but the check is kept narrow so a broken Windows path cannot hide
    behind it.
    """
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


_SHOT_MODULES = {"recon": True, "exec": True, "fs": True, "privesc": True,
                 "screenshot": True}


class TestScreenshot:
    """A phantom config key is worse than an absent one: the operator asks for a
    capture, the build accepts the flag, and the agent answers `unknown action`
    mid-engagement. These pin the toggle to code that exists."""

    def test_toggle_compiles_the_module_in_and_out(self):
        gen = AgentStubGenerator()
        on = gen.generate(StubConfig(name="s1", transport="tcp", host="127.0.0.1",
                                     modules=_SHOT_MODULES))
        off = gen.generate(StubConfig(name="s2", transport="tcp", host="127.0.0.1"))

        assert "def mod_screenshot" in on, "--screenshot produced no capture code"
        assert 'action == "screenshot"' in on, "capture is compiled but not reachable"
        assert "def mod_screenshot" not in off, (
            "capture leaked into a default build; the toggle is not gating"
        )

    @pytest.mark.asyncio
    async def test_operator_captures_a_screen(self, tmp_path, listener_port):
        from pupyteer.tui.commands.sessions import sessions_screenshot

        if not _has_desktop():
            pytest.skip("headless runner: no display to capture")

        agent = _generate_agent(tmp_path, "shotagent", port=listener_port,
                               sleep=1, jitter=0, modules=_SHOT_MODULES)
        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        proc = _start_agent(agent, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id, "generated agent never registered a session"

            tui = _FakeTUI(engine)
            out = tmp_path / "operator" / "screen.png"
            result = await sessions_screenshot(tui, [session_id, str(out)])
            assert result["status"] == "ok", result

            raw = out.read_bytes()
            assert raw[:8] == b"\x89PNG\r\n\x1a\n", (
                f"saved file is not a PNG: {raw[:16]!r}"
            )
            # Nothing left on the target: the capture must not linger in temp.
            residue = list(tmp_path.glob(".pupyteer-shot-*"))
            assert not residue, f"screenshot left files behind: {residue}"
        finally:
            _stop_agent(proc)
            await engine.stop()

    @pytest.mark.asyncio
    async def test_agent_built_without_it_says_so(
        self, tmp_path, listener_port, agent_source
    ):
        """The default build has no capture — and must report that, not succeed."""
        from pupyteer.tui.commands.sessions import sessions_screenshot

        engine = PupyteerEngine(_write_server_config(tmp_path, listener_port))
        proc = _start_agent(agent_source, tmp_path)
        try:
            await engine.start()
            session_id = await _await_session(engine)
            assert session_id
            tui = _FakeTUI(engine)
            result = await sessions_screenshot(
                tui, [session_id, str(tmp_path / "never.png")]
            )
            assert result["status"] == "error", result
            assert not (tmp_path / "never.png").exists()
        finally:
            _stop_agent(proc)
            await engine.stop()


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


def _write_server_config(tmp_path, port: int, **server_overrides) -> str:
    config_path = tmp_path / "pupyteer.yaml"
    server = {
        "host": "127.0.0.1", "port": port,
        "agent_auth_file": str(tmp_path / _ENROLLMENT_FILE),
    }
    server.update(server_overrides)
    config_path.write_text(yaml.safe_dump({
        "server": server,
        "operator": {"name": "lab-op"},
    }), encoding="utf-8")
    _put_secret(tmp_path)
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

    def test_runaway_output_is_clipped(self, tmp_path):
        """An unbounded reply would outgrow the listener and take the session with it."""
        agent = _load_agent_module(_generate_agent(
            tmp_path, "clip", port=1, sleep=1, jitter=0, max_output=2000,
        ))
        result = agent._run_command(
            f'{agent._sy.executable} -c "print(\'x\' * 500000)"'
        )
        assert len(result) < 5000, f"output was not clipped: {len(result)} chars"
        assert "truncated" in result


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
