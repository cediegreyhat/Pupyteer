"""Tests for last/logs/cloudinfo/dns modules."""
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
        self.session_id = "sess-r5"
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


@pytest.mark.parametrize("name,osname,needle", [
    ("last", "linux", "last -n"),
    ("last", "windows", "wevtutil"),
    ("logs", "linux", "journalctl"),
    ("logs", "windows", "wevtutil"),
    ("cloudinfo", "linux", "169.254.169.254"),
    ("dns", "linux", "getent hosts"),
    ("dns", "windows", "nslookup"),
])
def test_offline_mode_returns_the_command(name, osname, needle, config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create(name)
    mod._session_manager = None
    args = {"name": "example.com"} if name == "dns" else {}
    result = asyncio.run(mod.execute(FakeSession(osname), args))
    assert result["status"] == "ok"
    assert result["mode"] == "offline"
    assert needle in result["command"]


@pytest.mark.parametrize("name", ["last", "logs", "cloudinfo", "dns"])
def test_dispatches_and_surfaces_output(name, config, audit, monkeypatch):
    calls = _install(monkeypatch, "the output")
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create(name)
    mod._session_manager = FakeSessionManager()
    args = {"name": "example.com"} if name == "dns" else {}
    result = asyncio.run(mod.execute(FakeSession("linux"), args))
    assert result["status"] == "ok"
    assert result["output"] == "the output"
    assert calls, "no command was dispatched"


def test_dns_requires_name(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("dns")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"
