"""Tests for EditModule."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.modules.registry import ModuleRegistry
from pupyteer.server.sessions import transfer


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


class FakeSession:
    session_id = "sess-r8"
    os = "linux"


class FakeSessionManager:
    pass


def test_requires_path(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("edit")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {}))
    assert r["status"] == "error"


def test_read_mode_pulls_and_returns_content(config, audit, monkeypatch, tmp_path):
    staged = tmp_path / "staged.txt"
    staged.write_text("hello world")

    async def _pull(session_manager, session_id, remote, sink, timeout=0, **kw):
        sink.write(b"hello world")
        return {"status": "ok", "bytes": 11}

    async def _push(*a, **kw):
        return {"status": "ok", "bytes": 0}

    monkeypatch.setattr(transfer, "pull", _pull)
    monkeypatch.setattr(transfer, "push", _push)

    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("edit")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"path": "/remote/file.txt", "mode": "read"}))
    assert r["status"] == "ok"
    assert r["mode"] == "read"
    assert r["content"] == "hello world"


def test_write_mode_pushes_content(config, audit, monkeypatch):
    async def _pull(*a, **kw):
        return {"status": "ok", "bytes": 0}

    async def _push(session_manager, session_id, local, remote, timeout=0, **kw):
        assert remote == "/remote/file.txt"
        return {"status": "ok", "bytes": 5}

    monkeypatch.setattr(transfer, "pull", _pull)
    monkeypatch.setattr(transfer, "push", _push)

    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("edit")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"path": "/remote/file.txt", "mode": "write", "content": "hello"}))
    assert r["status"] == "ok"
    assert r["mode"] == "write"


def test_read_failure_surfaces_error(config, audit, monkeypatch):
    async def _pull(session_manager, session_id, remote, sink, timeout=0, **kw):
        return {"status": "error", "error": "not found", "bytes": 0}

    async def _push(*a, **kw):
        return {"status": "ok", "bytes": 0}

    monkeypatch.setattr(transfer, "pull", _pull)
    monkeypatch.setattr(transfer, "push", _push)

    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("edit")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"path": "/remote/missing.txt", "mode": "read"}))
    assert r["status"] == "error"
    assert "not found" in r["error"]


def test_no_session_manager(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("edit")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {"path": "/x", "mode": "read"}))
    assert r["status"] == "error"
