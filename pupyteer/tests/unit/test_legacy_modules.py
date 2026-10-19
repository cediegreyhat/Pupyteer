"""Tests for the Pupy legacy-feature port.

Each test here pins one behaviour of a feature that exists in upstream Pupy
(https://github.com/n1nj4sec/pupy) and is being ported into Pupyteer.

Slice 1: `cat` — read a remote file and return its text.

Upstream reference: pupy/modules/cat.py
Pupyteer's agent already declares `fs_get`, so this is a server-side wrapper:
no agent change is needed, which is what makes it testable here.
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys
from typing import Any, Dict

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions import transfer


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


class FakeSession:
    session_id = "sess-0001"
    hostname = "testhost"


class FakeSessionManager:
    """Stands in for the live session manager.

    The agent is not reachable in a unit test, so this is the seam. Everything
    below it (argument handling, reply parsing, error shaping) is the real
    module code under test.
    """

    def __init__(self):
        self.calls = []


@pytest.fixture
def replies(monkeypatch):
    """Install a canned agent reply for transfer.run_action and record the task."""
    recorded: Dict[str, Any] = {"tasks": []}

    def _install(reply):
        async def _fake_run_action(session_manager, session_id, task, timeout=0):
            recorded["tasks"].append(task)
            recorded["session_id"] = session_id
            recorded["timeout"] = timeout
            return reply

        monkeypatch.setattr(transfer, "run_action", _fake_run_action)
        return recorded

    return _install


# ─── Slice 1: cat ────────────────────────────────────────────────────


def test_cat_returns_the_remote_file_as_text(config, audit, replies):
    """The agent returns base64 file bytes; cat decodes them and returns text."""
    body = b"hello from the target\nsecond line\n"
    rec = replies({"data": base64.b64encode(body).decode(), "bytes": len(body)})

    from pupyteer.server.modules.builtin.file_ops import CatModule

    mod = CatModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"path": "/etc/hostname"}))

    assert result["status"] == "ok"
    assert result["path"] == "/etc/hostname"
    assert result["content"] == body.decode()
    assert result["bytes"] == len(body)
    # It must ask the agent for exactly the path it was given, via fs_get.
    assert rec["tasks"] == [{"action": "fs_get", "path": "/etc/hostname"}]


def test_cat_requires_a_path(config, audit, replies):
    """No path is a usage error, and the agent must not be tasked."""
    rec = replies({"data": ""})

    from pupyteer.server.modules.builtin.file_ops import CatModule

    mod = CatModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
    assert "path" in result["error"].lower()
    assert rec["tasks"] == []


def test_cat_reports_an_agent_error_rather_than_empty_success(config, audit, replies):
    """A refusal from the agent is an error, never a zero-length file."""
    replies({"error": "refused: not declared 'fs_get'"})

    from pupyteer.server.modules.builtin.file_ops import CatModule

    mod = CatModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"path": "/etc/shadow"}))

    assert result["status"] == "error"
    assert "fs_get" in result["error"]


def test_cat_rejects_data_that_is_not_base64(config, audit, replies):
    """Garbage from the agent must not be silently written as content."""
    replies({"data": "not!valid!base64!"})

    from pupyteer.server.modules.builtin.file_ops import CatModule

    mod = CatModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"path": "/tmp/x"}))

    assert result["status"] == "error"
    assert "base64" in result["error"].lower()


# ─── Slice 2: search ─────────────────────────────────────────────────
# Upstream reference: pupy/modules/search.py + isearch.py
# Recursive file search over the agent's fs_list. The agent returns ONE
# directory per call, so descent is server-side orchestration.


class TreeSessionManager(FakeSessionManager):
    """Serves a fixed directory tree as the agent's fs_list would."""

    def __init__(self, tree):
        super().__init__()
        self.tree = tree

    def listing(self, path):
        entries = self.tree.get(path)
        if entries is None:
            return {"error": f"cannot list {path}"}
        return {"path": path, "entries": entries}


def _f(name, size=10):
    return {"name": name, "is_file": True, "is_dir": False, "size": size, "mtime": 1.0}


def _d(name):
    return {"name": name, "is_file": False, "is_dir": True, "size": 0, "mtime": 1.0}


TREE = {
    "/root": [_f("notes.txt"), _d("sub"), _f("report.log")],
    "/root/sub": [_f("deep_passwords.txt"), _d("deeper")],
    "/root/sub/deeper": [_f("buried_passwords.txt")],
}


def _search_manager(monkeypatch, tree=TREE):
    """Patch run_action so fs_list is answered from `tree`."""
    mgr = TreeSessionManager(tree)

    async def _fake_run_action(session_manager, session_id, task, timeout=0):
        mgr.calls.append(task)
        return mgr.listing(task.get("path", "."))

    monkeypatch.setattr(transfer, "run_action", _fake_run_action)
    return mgr


def test_search_descends_recursively_and_matches_by_substring(config, audit, monkeypatch):
    """A file two levels down must be found - that is the whole point."""
    mgr = _search_manager(monkeypatch)

    from pupyteer.server.modules.builtin.file_ops import SearchModule

    mod = SearchModule(config, audit)
    mod._session_manager = mgr

    result = asyncio.run(mod.execute(FakeSession(), {"path": "/root", "pattern": "passwords"}))

    assert result["status"] == "ok"
    found = sorted(m["path"] for m in result["matches"])
    assert found == ["/root/sub/deep_passwords.txt", "/root/sub/deeper/buried_passwords.txt"]
    assert result["dirs_visited"] == 3


def test_search_respects_max_depth(config, audit, monkeypatch):
    """max_depth=1 must not reach the level-2 file."""
    _search_manager(monkeypatch)

    from pupyteer.server.modules.builtin.file_ops import SearchModule

    mod = SearchModule(config, audit)
    mod._session_manager = TreeSessionManager(TREE)

    result = asyncio.run(mod.execute(FakeSession(),
                                     {"path": "/root", "pattern": "passwords", "max_depth": 1}))

    assert result["status"] == "ok"
    assert [m["path"] for m in result["matches"]] == ["/root/sub/deep_passwords.txt"]


def test_search_with_no_matches_is_ok_not_an_error(config, audit, monkeypatch):
    """Nothing found is a real answer, and must not read as a failure."""
    _search_manager(monkeypatch)

    from pupyteer.server.modules.builtin.file_ops import SearchModule

    mod = SearchModule(config, audit)
    mod._session_manager = TreeSessionManager(TREE)

    result = asyncio.run(mod.execute(FakeSession(), {"path": "/root", "pattern": "zzz-nope"}))

    assert result["status"] == "ok"
    assert result["matches"] == []


def test_search_requires_a_pattern(config, audit, monkeypatch):
    """No pattern is a usage error and must not task the agent."""
    mgr = _search_manager(monkeypatch)

    from pupyteer.server.modules.builtin.file_ops import SearchModule

    mod = SearchModule(config, audit)
    mod._session_manager = mgr

    result = asyncio.run(mod.execute(FakeSession(), {"path": "/root"}))

    assert result["status"] == "error"
    assert "pattern" in result["error"].lower()
    assert mgr.calls == []


def test_search_reports_an_unreadable_directory_instead_of_hiding_it(config, audit, monkeypatch):
    """A directory the agent could not read must surface, not vanish silently."""
    tree = {"/root": [_f("a.txt"), _d("locked")]}  # /root/locked is unlistable
    _search_manager(monkeypatch, tree)

    from pupyteer.server.modules.builtin.file_ops import SearchModule

    mod = SearchModule(config, audit)
    mod._session_manager = TreeSessionManager(tree)

    result = asyncio.run(mod.execute(FakeSession(), {"path": "/root", "pattern": "a"}))

    assert result["status"] == "ok"
    assert result["errors"] and "locked" in result["errors"][0]
