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


#: A line and a count that together are several TLS records (Schannel caps a
#: record at 16384 bytes of plaintext) and do not divide evenly into one. Several
#: rather than two because the failure this guards is a copy that runs off the
#: end of the record buffer: overrun a neighbouring chunk by a few hundred bytes
#: and the process often survives to answer one more command anyway.
_BIG_LINES = 1200
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

        # And what did sending it cost? A record buffer overrun leaves the line
        # itself perfectly intact on the wire — the listener cannot tell that the
        # agent trashed its own heap building it. What it looks like from the
        # console is a target that answered once and then went quiet, so the
        # assertion belongs here rather than in some timeout test three commands
        # later.
        assert proc.poll() is None, "the implant died sending its own big result"
        after = await _run(engine, session_id, "echo still-here")
        assert after and "still-here" in after, (
            f"the implant stopped answering after a multi-record result "
            f"(exit {proc.poll()})")
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()


@pytest.mark.asyncio
async def test_pe_payload_runs_every_command_in_one_checkin(tmp_path):
    """Two tasks queued together, the first of them carrying an open brace.

    The payload walks the `commands` array by matching braces, and a brace is an
    ordinary character in the text of a command: `echo {` is a thing operators
    type and cmd.exe passes it through unchanged. Counting characters rather than
    tokens leaves the first object one brace short of closed, so the scanner runs
    on to the *next* command's brace, treats the pair as one task, and the second
    is never looked at. Nothing announces that — the operator just waits on a
    command the listener had already marked delivered.
    """
    port = _free_port()
    config_path, secret, material = _start_server(tmp_path, port)
    exe = await _build(tmp_path, port, secret, material.cert_pem, name="brace")

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        session_id = await _await_session(engine)
        assert session_id, "PE payload never registered over TLS"

        # The beacon is once a second, so a check-in can fall between the two
        # queue calls and split them across batches, which proves nothing. Three
        # tries makes an unbatched run of it a coin flip stacked three deep.
        for attempt in range(3):
            first = await engine.sessions.interact(session_id, "echo brace-{")
            second = await engine.sessions.interact(session_id, "echo two")
            assert first and second, "command never queued"
            await asyncio.sleep(2.5)
            one = await _await_result(engine, session_id, first, timeout=20.0)
            two = await _await_result(engine, session_id, second, timeout=20.0)
            assert one is not None and "brace-{" in one, (
                f"the brace-bearing command itself: got {one!r}")
            assert two is not None and "two" in two, (
                f"attempt {attempt}: the task queued behind an open brace never "
                f"ran — got {two!r}")
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


@pytest.mark.asyncio
async def test_pe_payload_declares_the_tasks_it_answers(tmp_path):
    """The registration line says what this .exe can be asked to do.

    Two halves, and the second is the one that matters: an action the payload
    never mentions is answered by the queue without ever going down the wire, so
    the operator reads a refusal that names the implant's own claim rather than
    whatever cmd.exe said about a word it had not seen.
    """
    import json

    port = _free_port()
    config_path, secret, material = _start_server(tmp_path, port)
    exe = await _build(tmp_path, port, secret, material.cert_pem, name="capa")

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        session_id = await _await_session(engine)
        assert session_id, "PE payload never registered over TLS"

        info = await engine.sessions.get(session_id)
        assert "fs_get" in info.capabilities and "fs_put" in info.capabilities
        assert "screenshot" not in info.capabilities
        assert info.max_line == 65536

        refused = await _run(engine, session_id, "screenshot")
        assert refused and "refused" in refused and "screenshot" in refused

        # Structured exec is how the modules task a host, and is the shape that
        # used to arrive at cmd.exe as a string of JSON.
        answered = await _run(
            engine, session_id, json.dumps({"action": "exec", "command": "echo pe-exec-task"}))
        assert answered and "pe-exec-task" in answered

        # The same words as typed text, which is the shape the queue carries them
        # in. A verb the payload announced but did not answer would go to
        # cmd.exe, and `is not recognized as an internal or external command`
        # reads to an operator as something the target said.
        ping = await _run(engine, session_id, "ping")
        assert ping and "pong" in ping, f"bare ping reached the shell: {ping!r}"
        procs = await _run(engine, session_id, "processes")
        assert procs and "not recognized" not in procs, (
            f"bare processes reached the shell: {procs[:80]!r}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()


@pytest.mark.asyncio
async def test_pe_payload_stops_when_the_operator_kills_it(tmp_path):
    """`sessions kill` orders `exit`, and the implant has to act on the order.

    The word used to fall through to cmd.exe, which exits its own child process
    and leaves the payload beaming. The server dropped the session after its
    grace period either way, so what was left behind was an implant calling home
    to a session nobody could address — invisible in the console, still on the
    host.
    """
    port = _free_port()
    config_path, secret, material = _start_server(tmp_path, port)
    exe = await _build(tmp_path, port, secret, material.cert_pem, name="killed")

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        session_id = await _await_session(engine)
        assert session_id, "PE payload never registered over TLS"

        assert await engine.sessions.kill(session_id, "test")
        code = await _await_exit(proc, timeout=30.0)
        assert code is not None, "the implant is still running after `sessions kill`"
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()


@pytest.mark.asyncio
async def test_pe_payload_round_trips_a_file_in_chunks(tmp_path):
    """`sessions upload` and `sessions download` against the C implant.

    The file is bigger than one chunk and carries every byte value, because the
    two ways this can fail are quiet: a chunk too long for the agent's read
    buffer is dropped at the socket and the transfer ends short, and a byte that
    survives base64 but not a text-mode file handle comes back as something
    nearby. Both produce a file and a check mark, so the only test worth having
    is the bytes on both ends.
    """
    from pupyteer.server.sessions import transfer

    port = _free_port()
    config_path, secret, material = _start_server(tmp_path, port)
    exe = await _build(tmp_path, port, secret, material.cert_pem, name="files")

    payload = bytes(range(256)) * 600          # 150 KB, no aligned chunk boundary
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    remote = tmp_path / "on_target.bin"
    pulled = tmp_path / "pulled.bin"

    engine = PupyteerEngine(config_path)
    await engine.start()
    proc = subprocess.Popen([str(exe)], cwd=str(tmp_path))
    try:
        session_id = await _await_session(engine)
        assert session_id, "PE payload never registered over TLS"

        uploaded = await transfer.push(
            engine.sessions, session_id, str(source), str(remote), timeout=60)
        assert uploaded["status"] == "ok", uploaded
        assert uploaded["bytes"] == len(payload)

        listing = await transfer.run_action(
            engine.sessions, session_id,
            {"action": "fs_list", "path": str(tmp_path)}, timeout=60)
        names = {e["name"] for e in listing.get("entries", [])}
        assert remote.name in names, listing
        entry = next(e for e in listing["entries"] if e["name"] == remote.name)
        assert entry["size"] == len(payload) and entry["is_file"]

        with open(pulled, "wb") as sink:
            down = await transfer.pull(
                engine.sessions, session_id, str(remote), sink, timeout=60)
        assert down["status"] == "ok", down
        assert pulled.read_bytes() == payload, (
            f"pulled {down['bytes']} of {len(payload)} bytes")
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        await engine.stop()
