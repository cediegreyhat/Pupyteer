"""Tests for load_package module."""
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
    session_id = "sess-pkg"
    os = "linux"


class FakeSessionManager:
    pass


def _install(monkeypatch, push_ok=True, agent_reply=None):
    calls = {"push": [], "run_action": []}

    async def _push(session_manager, session_id, local, remote, timeout=0, **kw):
        calls["push"].append((local, remote))
        return {"status": "ok", "bytes": 42} if push_ok else {"status": "error", "error": "push failed"}

    async def _run_action(session_manager, session_id, task, timeout=0):
        calls["run_action"].append(task)
        if agent_reply is not None:
            return agent_reply
        return {"status": "ok", "ok": True}

    import pupyteer.server.sessions.transfer as t
    monkeypatch.setattr(t, "push", _push)
    monkeypatch.setattr(t, "run_action", _run_action)
    return calls


def test_requires_package(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("load_package")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {}))
    assert r["status"] == "error"


def test_missing_local_package(config, audit):
    config.set("packages.dir", "/nonexistent/dir")
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("load_package")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"package": "nope"}))
    assert r["status"] == "error"
    assert "not found" in r["error"]


def test_loads_existing_package(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    pkgdir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "..", "packages")
    # use the real packages dir
    real_pkgdir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "..", "packages"))
    config.set("packages.dir", real_pkgdir)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("load_package")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"package": "samplepkg"}))
    assert r["status"] == "ok", r
    assert calls["push"], "package was not pushed"
    assert calls["run_action"], "agent was not asked to import"
    assert calls["run_action"][0]["action"] == "load_package"
    assert calls["run_action"][0]["name"] == "samplepkg"


def test_push_failure_surfaces(config, audit, monkeypatch):
    _install(monkeypatch, push_ok=False)
    real_pkgdir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "..", "packages"))
    config.set("packages.dir", real_pkgdir)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("load_package")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"package": "samplepkg"}))
    assert r["status"] == "error"


def test_agent_import_failure_surfaces(config, audit, monkeypatch):
    _install(monkeypatch, agent_reply={"status": "error", "ok": False, "error": "import boom"})
    real_pkgdir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "..", "packages"))
    config.set("packages.dir", real_pkgdir)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("load_package")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"package": "samplepkg"}))
    assert r["status"] == "error"
    assert "boom" in r["error"]


def test_remove_mode(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("load_package")
    mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession(), {"package": "samplepkg", "remove": True}))
    assert r["status"] == "ok"
    assert calls["run_action"][0].get("remove") is True


def test_no_session_manager(config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create("load_package")
    mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession(), {"package": "samplepkg"}))
    assert r["status"] == "error"
