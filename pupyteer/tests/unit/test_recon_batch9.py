"""Tests for mv, rm, write, reg modules."""
from __future__ import annotations

import asyncio
import os
import sys

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
    def __init__(self, os_name="linux"):
        self.session_id = "sess-r9"
        self.os = os_name


class FakeSessionManager:
    pass


def _install(monkeypatch, output="ok output"):
    calls = []

    async def _fake(session_manager, session_id, command, timeout=0):
        calls.append(command)
        return {"status": "ok", "output": output, "command_id": "c1"}

    async def _push(session_manager, session_id, local, remote, timeout=0, **kw):
        return {"status": "ok", "bytes": 5}

    import pupyteer.server.sessions.transfer as t
    monkeypatch.setattr(t, "run_command", _fake)
    monkeypatch.setattr(t, "push", _push)
    return calls


def test_mv_requires_src_dst(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("mv")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"


def test_mv_offline(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("mv")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"src": "/a", "dst": "/b"}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"
    assert "mv" in r["command"]


def test_mv_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("mv")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"src": "/a", "dst": "/b"}))
    assert r["status"] == "ok"
    assert calls


def test_rm_requires_path(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("rm")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"


def test_rm_offline(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("rm")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"path": "/tmp/x"}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"


def test_write_requires_path(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("write")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"


def test_write_pushes_content(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("write")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"path": "/tmp/x", "content": "hello"}))
    assert r["status"] == "ok"


def test_reg_requires_key_for_query(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("reg")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("windows"), {"action": "query"}))
    assert r["status"] == "error"


def test_reg_offline_query(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("reg")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("windows"), {"action": "query", "key": "HKLM\\Software"}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"
    assert "reg query" in r["command"]


def test_reg_unknown_action(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("reg")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("windows"), {"action": "frobnicate", "key": "HKLM\\Software"}))
    assert r["status"] == "error"
