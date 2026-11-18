"""A peer must not be able to grow the implant's memory without bound.

The listener's own ceiling is MAX_MESSAGE_BYTES (32 MiB), so a line past that is
not something this server sends. Before these bounds, a hostile or fake C2 — or
a relay peer off the internet — could hold a connection open and stream bytes
until the payload died, which an operator sees as a session that vanished.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig


def _load(tmp_path: Path, name: str = "agent_bounds", **overrides):
    settings = {"transport": "tcp", "host": "127.0.0.1", "port": 8443,
                "sleep": 1, "jitter": 0, "relay": True}
    settings.update(overrides)
    path = tmp_path / f"{name}.py"
    path.write_text(AgentStubGenerator().generate(StubConfig(name=name, **settings)),
                    encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Stream:
    """A socket that never produces the newline the reader is waiting for."""

    def __init__(self, chunk: bytes = b"x" * 4096):
        self._chunk = chunk
        self.read = 0

    def recv(self, n):
        self.read += n
        return self._chunk


def test_the_beacon_read_stops_instead_of_growing(tmp_path, monkeypatch):
    module = _load(tmp_path)
    monkeypatch.setattr(module, "MAX_INBOUND_LINE", 1024)
    transport = module.TCPTransport("127.0.0.1", 8443)
    peer = _Stream()
    with pytest.raises(module.TransportError, match="not a message this server sends"):
        transport._read_line(peer)
    # It stopped at the ceiling rather than reading without end.
    assert peer.read < 1024 + 8192


def test_the_signed_listener_read_stops_instead_of_growing(tmp_path, monkeypatch):
    module = _load(tmp_path, "agent_bounds_signed")
    monkeypatch.setattr(module, "MAX_INBOUND_LINE", 8)

    class _File:
        def readline(self, limit):
            return b"x" * (limit + 1)

    client = module.ListenerClient("127.0.0.1", 8443)
    client._fp = _File()
    with pytest.raises(module.TransportError, match="too long"):
        client._recv()


class _Conn:
    """A relay peer that announces a length and then sends nothing."""

    def __init__(self, announced: int):
        self._announced = announced
        self.sent = b""
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def recv(self, n):
        if n == 4 - len(b""):
            import struct
            return struct.pack(">I", self._announced)
        return b""

    def sendall(self, data):
        self.sent += data


def test_the_relay_refuses_a_peer_announcing_an_absurd_length(tmp_path):
    """A length prefix is a peer's claim about what it will send."""
    module = _load(tmp_path, "agent_bounds_relay")
    node = module.RelayNode.__new__(module.RelayNode)
    node._running = True
    node._forward = lambda data: b""

    conn = _Conn(4 * 1024 * 1024 * 1024)
    node._handle_peer(conn, ("203.0.113.9", 4000))
    assert conn.closed
    assert conn.sent == b"", "an oversized frame must not be forwarded upstream"


def test_the_relay_reads_a_frame_within_bounds(tmp_path):
    module = _load(tmp_path, "agent_bounds_relay_ok")
    node = module.RelayNode.__new__(module.RelayNode)
    node._running = True
    node._forward = lambda data: b"reply"

    import struct

    class _Small:
        def __init__(self):
            self._hdr = struct.pack(">I", 4)
            self._body = b"ping"
            self.sent = b""
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.closed = True

        def recv(self, n):
            if self._hdr:
                out, self._hdr = self._hdr[:n], self._hdr[n:]
                return out
            if self._body:
                out, self._body = self._body[:n], self._body[n:]
                return out
            return b""

        def sendall(self, data):
            self.sent += data

    conn = _Small()
    node._handle_peer(conn, ("203.0.113.9", 4000))
    assert conn.sent == struct.pack(">I", 5) + b"reply"
