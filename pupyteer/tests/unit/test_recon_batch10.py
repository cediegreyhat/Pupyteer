"""Tests for PyexecModule."""
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
    session_id = "sess-r10"
    os = "linux"


class FakeSessionManager:
    pass


def _install(monkeypatch, output="hi"):
    calls = []

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return {"status": "ok", "ok": True, "output": output}

    import pupyteer.server.sessions.transfer as t
    monkeypatch.setattr(t, "run_action", _fake)
    return calls


def test_requires_code_or_file(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("pyexec")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {}))
    assert r["status"] == "error"


def test_reads_file(config, audit, monkeypatch, tmp_path):
    f = tmp_path / "code.py"
    f.write_text("print('hi')")
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("pyexec")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"file": str(f)}))
    assert r["status"] == "ok"
    assert calls[0]["code"] == "print('hi')"


def test_dispatches_code(config, audit, monkeypatch):
    calls = _install(monkeypatch, "result")
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("pyexec")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"code": "print(1)"}))
    assert r["status"] == "ok"
    assert r["output"] == "result"
    assert calls[0]["action"] == "pyexec"


def test_surfaces_agent_error(config, audit, monkeypatch):
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"status": "error", "ok": False, "error": "boom"}

    import pupyteer.server.sessions.transfer as t
    monkeypatch.setattr(t, "run_action", _fake)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("pyexec")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"code": "x"}))
    assert r["status"] == "error"
    assert "boom" in r["error"]


def test_no_session_manager(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("pyexec")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {"code": "x"}))
    assert r["status"] == "error"
