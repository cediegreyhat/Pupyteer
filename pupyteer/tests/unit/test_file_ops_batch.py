"""Tests for the cp module (Pupy parity, STDLIB family).

Upstream reference: pupy/modules/cp.py

Server-side, like `stat`: the implant already declares fs_get and fs_put, so a
remote-to-remote copy is pull-to-temp then push. That is how upstream does it
too, and it means no agent action, no capability change, and nothing to keep in
sync across the two agents.

Using transfer.pull/push rather than raw fs_get/fs_put matters: those handle the
chunk budget and the line-framing allowance, so a file larger than the agent's
read buffer copies correctly instead of being silently truncated.
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions import transfer


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


class FakeSession:
    session_id = "sess-cp"


class FakeSessionManager:
    pass


def _install(monkeypatch, pull_reply=None, push_reply=None):
    """Patch transfer.pull/push and record the calls."""
    seen = {"pull": [], "push": [], "staged": []}

    async def _pull(session_manager, session_id, remote, sink, **kw):
        seen["pull"].append(remote)
        # Emulate a real pull: write bytes into the sink the module opened.
        sink.write(b"payload-bytes")
        sink.flush()
        seen["staged"].append(getattr(sink, "name", None))
        return pull_reply or {"status": "ok", "bytes": 13}

    async def _push(session_manager, session_id, local, remote, **kw):
        seen["push"].append((local, remote))
        return push_reply or {"status": "ok", "bytes": 13}

    monkeypatch.setattr(transfer, "pull", _pull)
    monkeypatch.setattr(transfer, "push", _push)
    return seen


def test_cp_pulls_the_source_then_pushes_to_the_destination(config, audit, monkeypatch):
    seen = _install(monkeypatch)

    from pupyteer.server.modules.builtin.file_ops import CpModule

    mod = CpModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"src": "/etc/a", "dst": "/tmp/b"}))

    assert result["status"] == "ok"
    assert seen["pull"] == ["/etc/a"]
    assert seen["push"][0][1] == "/tmp/b"
    assert result["src"] == "/etc/a" and result["dst"] == "/tmp/b"


def test_cp_stages_through_a_temp_file_and_cleans_it_up(config, audit, monkeypatch):
    """The staging file must not survive the copy."""
    seen = _install(monkeypatch)

    from pupyteer.server.modules.builtin.file_ops import CpModule

    mod = CpModule(config, audit)
    mod._session_manager = FakeSessionManager()

    asyncio.run(mod.execute(FakeSession(), {"src": "/etc/a", "dst": "/tmp/b"}))

    staged = seen["staged"][0]
    assert staged, "the module did not stage through a file"
    assert not os.path.exists(staged), f"staging file left behind: {staged}"


def test_cp_requires_both_paths(config, audit, monkeypatch):
    seen = _install(monkeypatch)

    from pupyteer.server.modules.builtin.file_ops import CpModule

    mod = CpModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"src": "/etc/a"}))

    assert result["status"] == "error"
    assert seen["pull"] == [] and seen["push"] == []


def test_cp_reports_a_failed_read_rather_than_pushing_a_partial_file(config, audit, monkeypatch):
    """If the read failed, nothing may be written to the destination."""
    seen = _install(monkeypatch, pull_reply={"status": "error", "error": "refused: no fs_get"})

    from pupyteer.server.modules.builtin.file_ops import CpModule

    mod = CpModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"src": "/etc/a", "dst": "/tmp/b"}))

    assert result["status"] == "error"
    assert seen["push"] == [], "pushed after a failed read"


def test_cp_reports_a_failed_write(config, audit, monkeypatch):
    _install(monkeypatch, push_reply={"status": "error", "error": "refused: no fs_put"})

    from pupyteer.server.modules.builtin.file_ops import CpModule

    mod = CpModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"src": "/etc/a", "dst": "/tmp/b"}))

    assert result["status"] == "error"
    assert "fs_put" in result["error"]
