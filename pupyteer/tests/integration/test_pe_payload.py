"""The C payload, built by the shipped builder, against a TLS listener.

The Python agent covering TLS proves the listener works; it says nothing about
pe_template.c, which is a separate implementation of the same protocol in a
language with no test runner. This module compiles that template with the real
PEBuilder, runs the real .exe, and asks the two questions an operator would:
does it field a session and take a command, and does a payload that was built
for somebody else's certificate walk away instead of knocking forever.

Both are skipped anywhere the toolchain is not, because a cross-compiled .exe
cannot be executed on the build host.
"""
from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from pupyteer.agent.core.stub import StubConfig
from pupyteer.payloads.pe_builder import PEBuilder
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.core.tls import ensure_listener_cert, listener_tls

#: Where a MinGW that can produce a Windows .exe might be. The msys2 path is
#: first because that is the one on a Windows operator's box, where the shim on
#: PATH may be a different gcc entirely.
_MINGW_CANDIDATES = (
    "C:/msys64/ucrt64/bin/x86_64-w64-mingw32-gcc.exe",
    "x86_64-w64-mingw32-gcc",
    "/usr/bin/x86_64-w64-mingw32-gcc",
)


def _compiler() -> str | None:
    for candidate in _MINGW_CANDIDATES:
        found = shutil.which(candidate)
        if found:
            return found
        if "/" in candidate and Path(candidate).exists():
            return candidate
    return None


_TOOLCHAIN = _compiler()

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or _TOOLCHAIN is None,
    reason="needs a Windows host and a MinGW that can build a PE",
)


class _Config:
    """Just enough of ConfigManager for the builder."""

    def get(self, key, default=None):
        if key == "payloads.mingw_path":
            return _TOOLCHAIN
        return default


class _NoAudit:
    def log_event(self, *args, **kwargs):
        pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(tmp_path: Path, port: int):
    """Bring up the listener the way a config file does, and say what it serves.

    Returns (config_path, enrollment_secret, listener_material). The secret comes
    from ensure_team_secret rather than a fixed string because these payloads are
    built by the real builder, which reads the real enrollment file.
    """
    from pupyteer.server.core.enrollment import ensure_team_secret

    listener_cert, listener_key, _ = ensure_listener_cert(
        str(tmp_path / "listener.crt"), str(tmp_path / "listener.key"),
        host_names=("127.0.0.1", "localhost"))
    secret = ensure_team_secret(str(tmp_path / "enrollment.key"))
    config_path = tmp_path / "pupyteer.yaml"
    config_path.write_text(yaml.safe_dump({
        "server": {
            "host": "127.0.0.1", "port": port, "tls": True,
            "tls_cert": str(listener_cert), "tls_key": str(listener_key),
            "tls_hostnames": ["127.0.0.1", "localhost"],
            "agent_auth_file": str(tmp_path / "enrollment.key"),
        },
        "audit": {"log_file": str(tmp_path / "audit.json")},
        "security": {"operators_file": str(tmp_path / "operators.json")},
        "paths": {"logs": str(tmp_path / "logs"),
                  "payload_artifacts": str(tmp_path / "artifacts")},
        "evasion": {"history_path": str(tmp_path / "evasion_history.json")},
        "operator": {"name": "pe-lab"},
    }), encoding="utf-8")

    class _Getter:
        """The config the engine will read, before the engine reads it."""

        def __init__(self):
            self.values = {"server.tls": True,
                           "server.tls_cert": str(listener_cert),
                           "server.tls_key": str(listener_key),
                           "server.host": "127.0.0.1",
                           "server.tls_hostnames": ["127.0.0.1", "localhost"]}

        def get(self, name, default=None):
            return self.values.get(name, default)

    return str(config_path), secret, listener_tls(_Getter().get)


async def _build(tmp_path: Path, port: int, secret: str, cert_pem: str,
                 name: str = "peagent") -> Path:
    out = tmp_path / (name + ".exe")
    result = await PEBuilder(_Config(), _NoAudit()).build(
        StubConfig(name=name, transport="tcp", host="127.0.0.1", port=port,
                   sleep=1, jitter=0, persistence=False, auth_secret=secret,
                   tls=True, tls_cert_pem=cert_pem),
        out)
    assert result.status == "built", f"builder refused: {result.error_message}"
    assert out.exists()
    return out


async def _await_session(engine, timeout: float = 30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ids = engine.sessions.list_ids()
        if ids:
            return ids[0]
        await asyncio.sleep(0.25)
    return None


async def _await_exit(proc, timeout: float = 30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return proc.returncode
        await asyncio.sleep(0.25)
    return None


async def _await_result(engine, session_id: str, command_id: str,
                        timeout: float = 60.0) -> str | None:
    """The output of one command, or None if it never came back."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        history = await engine.sessions.get_command_history(session_id)
        for entry in history:
            if (entry.get("command_id") == command_id
                    and entry.get("status") == "completed"):
                return entry.get("result") or ""
        await asyncio.sleep(0.25)
    return None


async def _run(engine, session_id: str, command: str) -> str | None:
    command_id = await engine.sessions.interact(session_id, command)
    assert command_id, "command never queued"
    return await _await_result(engine, session_id, command_id)


@pytest.mark.asyncio
async def test_pe_payload_registers_and_runs_a_command_over_tls(tmp_path):
    """The claim the whole TLS section exists to support: a .exe that calls home."""
    port = _free_port()
    config_path, secret, material = _start_server(tmp_path, port)
    exe = await _build(tmp_path, port, secret, material.cert_pem)

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        session_id = await _await_session(engine)
        assert session_id, "PE payload never registered over TLS"

        info = await engine.sessions.get(session_id)
        assert info.os == "windows" and info.arch == "x64"
        assert info.hostname

        output = await _run(engine, session_id, "echo pe-tls-roundtrip")
        assert output is not None, "PE payload never returned command output"
        assert "pe-tls-roundtrip" in output
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()


#: A line and a count that together are well over one TLS record (Schannel caps
#: a record at 16384 bytes of plaintext) and do not divide evenly into one.
_BIG_LINES = 400
_BIG_LINE = "pupyteer-pe-tls-multi-record-line-0123456789abcdefghij"


@pytest.mark.asyncio
async def test_pe_payload_returns_a_result_bigger_than_one_record(tmp_path):
    """A command that prints more than one TLS record can hold.

    Splitting a line across records is the normal case rather than an edge case:
    a directory listing runs past 16 KB without anybody trying. The listener
    reassembles a byte stream and never tells either end a split happened, so
    the only thing provable from outside is that the whole text arrived — a
    result clipped at a record boundary would otherwise read as a target that
    simply had less to say.
    """
    port = _free_port()
    config_path, secret, material = _start_server(tmp_path, port)
    exe = await _build(tmp_path, port, secret, material.cert_pem, name="bigout")

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        session_id = await _await_session(engine)
        assert session_id, "PE payload never registered over TLS"

        output = await _run(
            engine, session_id,
            f"for /L %i in (1,1,{_BIG_LINES}) do @echo {_BIG_LINE}")
        expected = _BIG_LINES * (len(_BIG_LINE) + 1)      # + the newline
        assert output is not None, "PE payload never returned the big result"
        assert output.count(_BIG_LINE) == _BIG_LINES, (
            f"got {len(output)} bytes of a result that should be {expected}: "
            f"{output[:60]!r} … {output[-60:]!r}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()


@pytest.mark.asyncio
async def test_pe_payload_returns_output_that_is_not_clean_text(tmp_path):
    """A result carrying a byte that JSON has to escape.

    Command output is whatever a program wrote, and a coloured program writes
    0x1b. Passing such a byte through as itself does not print one odd
    character: the listener cannot decode the line, the result is dropped, and
    the operator is left waiting on a command that never finishes. The byte has
    to leave as an escape and come back as the byte it was.
    """
    port = _free_port()
    config_path, secret, material = _start_server(tmp_path, port)
    exe = await _build(tmp_path, port, secret, material.cert_pem, name="ctrlout")

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        session_id = await _await_session(engine)
        assert session_id, "PE payload never registered over TLS"

        output = await _run(engine, session_id, "echo a\x1bb\x07c")
        assert output is not None, "output with a control byte never came back"
        assert "\x1b" in output and "\x07" in output, repr(output)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()


@pytest.mark.asyncio
async def test_pe_payload_built_for_another_certificate_gives_up(tmp_path):
    """A pin that does not match is not a network problem.

    Retrying it is how an implant burns a host's process list for the rest of its
    life while the operator waits for a session that cannot arrive. Exit 3 is what
    the Python agent uses for the same refusal.
    """
    port = _free_port()
    config_path, secret, _ = _start_server(tmp_path, port)
    other = tmp_path / "foreign"
    other.mkdir()
    foreign_cert, _, _ = ensure_listener_cert(
        str(other / "listener.crt"), str(other / "listener.key"),
        host_names=("127.0.0.1",))
    exe = await _build(tmp_path, port, secret,
                       Path(foreign_cert).read_text(encoding="ascii"),
                       name="badpin")

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        code = await _await_exit(proc)
        assert code == 3, f"expected exit 3 (refused the listener), got {code}"
        assert not engine.sessions.list_ids(), "mispinned payload got a session"
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()
