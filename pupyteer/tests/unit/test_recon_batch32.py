"""Tests for remaining PY_DEP/AGENT_ACTION modules ported in the final integration batch."""
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
        self.session_id = "sess-r32"
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


def _mk(reg, name):
    mod = reg.create(name)
    return mod


# smb
def test_smb_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "smb"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_smb_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "smb"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and calls


# forward
def test_forward_requires_ports(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "forward"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"


def test_forward_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "forward"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"local_port": 8080, "remote_port": 80}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_forward_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "forward"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"local_port": 8080, "remote_port": 80}))
    assert r["status"] == "ok" and calls


# smbspider
def test_smbspider_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "smbspider"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_smbspider_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "smbspider"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and calls


# sshell
def test_sshell_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "sshell"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_sshell_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "sshell"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and calls


# psexec
def test_psexec_requires_target_and_command(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "psexec"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"


def test_psexec_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "psexec"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"target": "10.0.0.5", "command": "whoami"}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_psexec_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "psexec"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"target": "10.0.0.5", "command": "whoami"}))
    assert r["status"] == "ok" and calls


# ad
def test_ad_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "ad"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"domain": "example.com"}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_ad_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "ad"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"domain": "example.com"}))
    assert r["status"] == "ok" and calls


# become
def test_become_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "become"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_become_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "become"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and calls


# call
def test_call_requires_function(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "call"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "error"


def test_call_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "call"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {"function": "whoami"}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_call_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "call"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {"function": "whoami"}))
    assert r["status"] == "ok" and calls


# mimishell
def test_mimishell_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "mimishell"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_mimishell_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "mimishell"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and calls


# ttyrec
def test_ttyrec_offline(config, audit):
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "ttyrec"); mod._session_manager = None
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and r["mode"] == "offline"


def test_ttyrec_dispatches(config, audit, monkeypatch):
    calls = _install(monkeypatch)
    reg = ModuleRegistry(config, audit); reg.discover()
    mod = _mk(reg, "ttyrec"); mod._session_manager = FakeSessionManager()
    r = asyncio.run(mod.execute(FakeSession("linux"), {}))
    assert r["status"] == "ok" and calls
