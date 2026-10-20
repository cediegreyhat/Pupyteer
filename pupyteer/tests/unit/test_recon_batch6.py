"""Tests for ExitModule (gated shutdown wrapper)."""
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
    session_id = "sess-r6"
    os = "linux"


class FakeSessionManager:
    pass


def _install(monkeypatch):
    calls = []

    async def _fake(session_manager, session_id, action, timeout=0):
        calls.append(action)
        return {"status": "ok", "output": "exit requested"}

    import pupyteer.server.sessions.transfer as t
    monkeypatch.setattr(t, "run_action", _fake)
    return calls


def test_refuses_without_confirmation(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("exit")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {}))
    assert r["status"] == "error"
    assert "confirmation" in r["error"] or "yes" in r["error"]


def test_dispatches_shutdown_when_confirmed(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("exit")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"yes": True}))
    assert r["status"] == "ok"
    assert calls == [{"action": "shutdown"}]


def test_offline_mode_with_confirmation(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("exit")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {"yes": True}))
    # no agent -> _no_agent
    assert r["status"] == "error"
