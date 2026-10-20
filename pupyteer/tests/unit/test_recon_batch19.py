"""Tests for ZipModule."""
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
        self.session_id = "sess-r19"
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


def test_requires_archive_for_create(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("zip")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "create"}))
    assert r["status"] == "error"


def test_offline_create(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("zip")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "create", "archive": "out.zip", "paths": ["a.txt"]}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"
    assert "zip" in r["command"] or "tar" in r["command"]


def test_offline_extract(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("zip")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "extract", "archive": "in.zip"}))
    assert r["status"] == "ok"
    assert r["mode"] == "offline"


def test_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("zip")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"action": "create", "archive": "out.zip"}))
    assert r["status"] == "ok"
    assert calls
