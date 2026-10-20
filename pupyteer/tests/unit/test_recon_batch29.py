"""Tests for PortfwdModule."""
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
        self.session_id = "sess-r29"
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


def test_requires_ports_for_add(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("portfwd")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "add"}))
    assert r["status"] == "error"


def test_offline_add(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("portfwd")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "add", "local_port": 8080, "remote_port": 80}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"
    assert "socat" in r["command"]


def test_offline_list(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("portfwd")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "list"}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"


def test_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("portfwd")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "add", "local_port": 8080, "remote_port": 80}))
    assert r["status"] == "ok"
    assert calls
