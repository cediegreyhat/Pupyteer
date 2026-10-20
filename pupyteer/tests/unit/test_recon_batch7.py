"""Tests for http and cd modules."""
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
        self.session_id = "sess-r7"
        self.os = os_name


class FakeSessionManager:
    pass


def _install(monkeypatch, output="ok output"):
    calls = []

    async def _fake(session_manager, session_id, command, timeout=0):
        calls.append(command)
        return {"status": "ok", "output": output, "command_id": "c1"}

    import pupyteer.server.sessions.transfer as t
    monkeypatch.setattr(t, "run_command", _fake)
    return calls


def test_http_requires_url(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("http")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"


def test_http_offline_returns_curl(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("http")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"url": "example.com"}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"
    assert "curl" in r["command"]
    assert "example.com" in r["command"]


def test_http_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch, "resp body")
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("http")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"url": "http://example.com"}))
    assert r["status"] == "ok"
    assert r["output"] == "resp body"
    assert calls


def test_cd_offline_linux(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("cd")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"path": "/tmp"}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"
    assert "cd" in r["command"]
    assert "/tmp" in r["command"]


def test_cd_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch, "/tmp")
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("cd")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"path": "/tmp"}))
    assert r["status"] == "ok"
    assert r["output"] == "/tmp"
    assert calls
