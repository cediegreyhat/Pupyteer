"""Interop test: the RC4 transport the listener uses vs the compiled PE agent.

The compiled PE agent (pupyteer/agent/core/pe_template.c) RC4-frames every
message in BOTH directions using AGENT_RC4KEY:

    plaintext  = ASCII JSON object + '\\n'
    ciphertext = RC4(key, plaintext)      # same length, no framing bytes
    on-wire    = ciphertext + '\\n'        # the JSON's '\\n' is INSIDE the RC4

The listener must therefore decrypt inbound frames and encrypt outbound ones
with the same key. This test starts a real engine+listener with an ``rc4_key``
in config and drives the full register→challenge→session lifecycle exactly as
the C agent would (encrypt out, decrypt in), proving bidirectional interop.

Complements test_live_callback.py, which exercises the plaintext (no-key) path.
"""
from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import time
import warnings
from pathlib import Path

import pytest

# The listener internally uses rc4_crypt (deprecated) for RC4 transport.
# These tests exercise that path intentionally — suppress the noise.
warnings.filterwarnings("ignore", category=DeprecationWarning, module="pupyteer.*")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pupyteer.server.core.engine import PupyteerEngine

# 16-byte key as hex — exactly the shape pe_template.c's AGENT_RC4KEY takes.
RC4_KEY_HEX = "deadbeefdeadbeefdeadbeefdeadbeef"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except (ConnectionError, OSError):
            time.sleep(0.05)
    raise TimeoutError(f"Port {host}:{port} not ready after {timeout}s")


class _EngineThread:
    def __init__(self, port: int, rc4_key_hex: str):
        self._port = port
        self._rc4_key_hex = rc4_key_hex
        self.engine = None
        self._loop = None
        self._thread = None
        self._ready = threading.Event()
        self._error = None

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
            self.engine.config.set("server.host", "127.0.0.1")
            self.engine.config.set("server.port", self._port)
            # Enable the RC4 transport on the listener (matches AGENT_RC4KEY).
            self.engine.config.set("transports.rc4_key", self._rc4_key_hex)
            # Plaintext RC4 channel: the listener would otherwise serve TLS
            # (server.tls defaults on) and the handshake would fail on the
            # agent's non-TLS RC4 frame with WRONG_VERSION_NUMBER.
            self.engine.config.set("server.tls", False)
            self._loop.run_until_complete(self.engine.start())
            self._ready.set()
            self._loop.run_forever()
        except Exception as exc:  # noqa: BLE001
            self._error = exc
            self._ready.set()

    def stop(self, timeout: float = 15.0) -> None:
        if self.engine is not None and self._loop is not None:
            fut = asyncio.run_coroutine_threadsafe(self.engine.stop(), self._loop)
            try:
                fut.result(timeout=timeout)
            except Exception:
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def submit(self, coro, timeout: float = 5.0):
        """Run a coroutine on the engine's event loop and return its result."""
        assert self._loop is not None, "Loop not started"
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)


def _rc4(data: bytes, key: bytes) -> bytes:
    """Reference RC4 — mirrors pe_template.c rc4_crypt exactly."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


@pytest.fixture()
def rc4_engine():
    port = _find_free_port()
    thread = _EngineThread(port, RC4_KEY_HEX)
    thread.start()
    _wait_for_port("127.0.0.1", port, timeout=5)
    # Let run_forever() settle and drain the throwaway _wait_for_port
    # connection before the first real client connects.
    time.sleep(0.5)
    yield thread, "127.0.0.1", port, bytes.fromhex(RC4_KEY_HEX)
    thread.stop()


def _send_rc4(sock: socket.socket, payload: dict, key: bytes) -> None:
    """Encode exactly like pe_template.c sock_send: RC4(json+'\n') + '\n'."""
    msg = (json.dumps(payload) + "\n").encode("utf-8")
    sock.sendall(_rc4(msg, key) + b"\n")


def _send_rc4_frame(payload: dict, key: bytes) -> bytes:
    """The same frame _send_rc4 writes, returned as bytes for comparison."""
    msg = (json.dumps(payload) + "\n").encode("utf-8")
    return _rc4(msg, key) + b"\n"


def _recv_rc4(sock: socket.socket, key: bytes) -> dict:
    """Read one RC4-framed server reply and decode it.

    The server sends RC4(json+'\\n') + '\\n'. Control replies are small and
    arrive in a single TCP segment, so one recv() suffices; we strip the
    trailing framing newline, RC4-decrypt, and parse the JSON object.
    """
    sock.settimeout(5.0)
    buf = b""
    while not buf.endswith(b"\n"):
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            raise TimeoutError(f"no RC4 reply; partial raw={buf!r}")
        if not chunk:
            break
        buf += chunk
    dec = _rc4(buf.rstrip(b"\r\n"), key)
    text = dec.decode("utf-8", errors="ignore")
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError(f"no JSON object in decrypted reply: {text!r}")
    return json.loads(text[start:end + 1])


class TestRC4TransportInterop:
    def test_register_over_rc4_creates_session(self, rc4_engine):
        thread, host, port, key = rc4_engine
        from pupyteer.server.core.agent_keys import sign_payload

        # Mint a per-agent identity and pre-register it on the engine registry
        # so the listener can verify the signature — the authenticated path,
        # driven entirely over the RC4-framed wire exactly like a PE agent.
        pair = thread.engine.agent_keys.generate()
        base = {
            "type": "register", "agent_id": pair.agent_id,
            "hostname": "win-box", "os": "windows", "arch": "x64",
            "username": "analyst", "agent_version": "1.0.0",
        }

        sock = socket.create_connection((host, port), timeout=5)
        try:
            # Stage 1: register without signature -> challenge.
            _send_rc4(sock, base, key)
            challenge = _recv_rc4(sock, key)
            assert challenge["type"] == "challenge", f"got {challenge}"
            # Stage 2: sign the nonce, re-send.
            base["nonce"] = challenge["nonce"]
            base["signature"] = sign_payload(pair.priv_pem, challenge["nonce"])
            _send_rc4(sock, base, key)
            reply = _recv_rc4(sock, key)
        finally:
            sock.close()

        assert reply["type"] == "registered", f"got {reply}"
        session_id = reply["session_id"]
        assert session_id

        # The session must actually exist in the engine's session manager.
        sm = thread.engine.sessions
        assert thread.submit(sm.get(session_id)) is not None

    def test_rc4_reply_is_not_plaintext_json(self, rc4_engine):
        """Sanity: with RC4 on, the wire bytes must NOT be readable JSON."""
        _thread, host, port, key = rc4_engine
        sock = socket.create_connection((host, port), timeout=5)
        try:
            _send_rc4(sock, {"type": "checkin", "session_id": "nope"}, key)
            raw = sock.recv(4096)
        finally:
            sock.close()
        # Raw wire bytes must not contain the plaintext "type" token.
        assert b'"type"' not in raw
        # But decrypting it yields valid JSON with a type field.
        dec = _rc4(raw.rstrip(b"\r\n"), key)
        assert b'"type"' in dec


class TestRC4WireContract:
    """The exact on-wire framing, pinned byte-for-byte.

    The C agent (pe_template.c agent_send) and this test's _send_rc4 must agree
    on every byte, because the listener's _rc4_extract RC4-decrypts the whole
    buffer as one stream and pulls out balanced JSON. The subtle part an earlier
    merge got wrong: the JSON's own trailing '\\n' is INSIDE the ciphertext (it
    is the next byte of the RC4 stream, encrypted like any other), and only one
    further '\\n' is appended raw outside it. Writing that inner '\\n' unencrypted
    puts a literal 0x0a where the listener expects ciphertext.
    """

    KEY = bytes.fromhex(RC4_KEY_HEX)

    def _frame(self, payload: dict) -> bytes:
        # Exactly what pe_template.c agent_send must produce.
        plain = (json.dumps(payload) + "\n").encode("utf-8")
        return _rc4(plain, self.KEY) + b"\n"

    def test_inner_newline_is_inside_the_ciphertext(self):
        """The byte after the JSON (the '\\n') is encrypted, not a raw 0x0a."""
        frame = self._frame({"type": "checkin", "session_id": "abc"})
        # The last byte is the outer framing newline (raw).
        assert frame[-1] == 0x0A
        # The byte before it is the encrypted inner '\\n' — which is NOT 0x0A
        # for this key/plaintext (a raw unencrypted 0x0a here was the bug).
        inner_ct = frame[-2]
        assert inner_ct != 0x0A, (
            "the inner newline was appended unencrypted; the listener decrypts "
            "the whole buffer as one RC4 stream and would read a wrong byte")
        # Decrypting the whole frame (minus the outer framing newline) yields
        # the JSON followed by its own '\\n'.
        dec = _rc4(frame[:-1], self.KEY)
        assert dec.endswith(b"\n")
        assert json.loads(dec.decode("utf-8").strip())["type"] == "checkin"

    def test_send_rc4_matches_the_c_framing(self):
        """_send_rc4 (the test's stand-in for the C agent) == the pinned frame."""
        payload = {"type": "register", "hostname": "win-box"}
        assert _send_rc4_frame(payload, self.KEY) == self._frame(payload)


class _StubAudit:
    def log_event(self, *a, **k):
        pass


class _FakeWriter:
    """Just enough StreamWriter for _handle_client's RC4 branch: it never
    writes on a pure-garbage stream, but close()/wait_closed() run in finally."""

    def get_extra_info(self, name):
        return ("127.0.0.1", 44444) if name == "peername" else None

    def close(self):
        pass

    async def wait_closed(self):
        return None

    async def start_tls(self, *a, **k):
        raise AssertionError("plaintext listener must not upgrade TLS")


class TestRC4BufferBound:
    """The RC4 decrypt buffer must not grow without limit.

    The RC4 path cannot use readline() (any ciphertext byte can be '\\n'), so it
    accumulates raw ciphertext until a balanced JSON object forms. A peer that
    streams ciphertext which never decrypts to one object would otherwise grow
    the per-connection buffer without bound until the listener OOMs. Before the
    cap there was nothing stopping that: one frame is all a peer has to send to
    pin megabytes of RAM, and many such connections take the listener down.
    """

    def _listener(self, max_rc4_buffer):
        from pupyteer.server.transports.listener import AgentListener
        return AgentListener(
            config={
                "host": "127.0.0.1",
                "port": 0,
                "rc4_key": RC4_KEY_HEX,
                "max_rc4_buffer": max_rc4_buffer,
            },
            session_manager=None,
            audit_logger=_StubAudit(),
        )

    @pytest.mark.asyncio
    async def test_undecryptable_stream_is_bounded(self):
        """Streaming ciphertext that never forms a JSON object stops the
        connection at the cap instead of growing the buffer forever."""
        key = bytes.fromhex(RC4_KEY_HEX)
        listener = self._listener(max_rc4_buffer=4096)

        reader = asyncio.StreamReader()
        writer = _FakeWriter()

        # Feed well past the cap: bytes that, RC4-decrypted, never produce a
        # complete JSON object (raw non-JSON ciphertext). One frame would be
        # enough to overflow the tiny cap.
        for _ in range(64):
            reader.feed_data(_rc4(b"\x00" * 1024, key) + b"\n")

        await listener._handle_client(reader, writer)

        assert listener._stats["rc4_buffer_overflows"] == 1
        # The buffer was not allowed to grow past the cap + one chunk.
        assert len(listener._rc4_buf) <= 4096 + 4096

    @pytest.mark.asyncio
    async def test_a_complete_frame_under_the_cap_is_kept(self):
        """The cap does not fire on a legitimate small frame — the connection
        logic runs normally and no overflow is counted."""
        key = bytes.fromhex(RC4_KEY_HEX)
        listener = self._listener(max_rc4_buffer=1024 * 1024)

        reader = asyncio.StreamReader()
        writer = _FakeWriter()
        # A single well-formed RC4 frame (a checkin the listener will parse).
        frame = _send_rc4_frame({"type": "checkin", "session_id": "x"}, key)
        reader.feed_data(frame)
        reader.feed_eof()

        await listener._handle_client(reader, writer)

        assert listener._stats["rc4_buffer_overflows"] == 0

    def test_default_cap_matches_message_ceiling(self):
        """With no override the cap equals MAX_MESSAGE_BYTES, so a legit
        agent's largest single frame (its command output) always fits."""
        from pupyteer.server.transports.listener import (
            MAX_MESSAGE_BYTES,
            AgentListener,
        )
        listener = AgentListener(
            config={"host": "127.0.0.1", "port": 0, "rc4_key": RC4_KEY_HEX},
            session_manager=None,
            audit_logger=_StubAudit(),
        )
        assert listener._max_rc4_buffer == MAX_MESSAGE_BYTES

    def test_unset_cap_key_does_not_crash_startup(self):
        """A present-but-None max_rc4_buffer (manager forwards config.get)
        falls back to the default rather than int(None) crashing the listener."""
        from pupyteer.server.transports.listener import MAX_MESSAGE_BYTES, AgentListener
        listener = AgentListener(
            config={"host": "127.0.0.1", "port": 0, "rc4_key": RC4_KEY_HEX,
                    "max_rc4_buffer": None},
            session_manager=None,
            audit_logger=_StubAudit(),
        )
        assert listener._max_rc4_buffer == MAX_MESSAGE_BYTES
