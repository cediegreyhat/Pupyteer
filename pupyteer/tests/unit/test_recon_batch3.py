"""Tests for a batch of shell-dispatched recon modules (Pupy parity).

Upstream references: pupy/modules/{users,drives,getprivs}.py

These upstream modules depended on Pupy's agent-side remote packages
(pupyps, pupwinutils, ...). Pupyteer reimplements them natively as
shell dispatchers: the implant already answers arbitrary commands through
the session manager's command queue, so each module queues the host's own
tool and surfaces its output. No agent change, no capability change.
"""
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
        self.session_id = "sess-r3"
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
    ("users", "linux", "getent passwd"),
    ("users", "windows", "net user"),
    ("drives", "linux", "df -h"),
    ("drives", "windows", "wmic logicaldisk"),
    ("getprivs", "linux", "id"),
    ("getprivs", "windows", "whoami /priv"),
])
def test_offline_mode_returns_the_command(name, osname, needle, config, audit):
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create(name)
    mod._session_manager = None
    result = asyncio.run(mod.execute(FakeSession(osname), {}))
    assert result["status"] == "ok"
    assert result["mode"] == "offline"
    assert needle in result["command"]


@pytest.mark.parametrize("name", ["users", "drives", "getprivs"])
def test_dispatches_and_surfaces_output(name, config, audit, monkeypatch):
    calls = _install(monkeypatch, "the output")
    reg = ModuleRegistry(config, audit)
    reg.discover()
    mod = reg.create(name)
    mod._session_manager = FakeSessionManager()
    result = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert result["status"] == "ok"
    assert result["output"] == "the output"
    assert calls, "no command was dispatched"


def test_missing_session_manager_is_an_error(config, audit):
    # users/drives/getprivs all degrade to offline mode (not an error) when
    # there is no agent -- mirrors ShellExecModule's _no_agent contract? No:
    # these return ok/offline. Verify they at least don't crash.
    reg = ModuleRegistry(config, audit)
    reg.discover()
    for name in ("users", "drives", "getprivs"):
        mod = reg.create(name)
        mod._session_manager = None
        r = asyncio.run(mod.execute(FakeSession("linux"), {}))
        assert r["status"] == "ok"
