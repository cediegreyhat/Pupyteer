"""Contract tests for the `pwd` action (Pupy parity, tranche 1).

Upstream reference: pupy/modules/pwd.py

A bare verb with no argument, so it rides the same tuple in `_parse_command`
that `sysinfo`/`network` use. Included because it is the last of the cheap
AGENT_ACTION items, and because the agent's working directory is genuinely not
exposed by any existing action -- `fs_list` with no path defaults to "." but
never reports what that resolved to.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from typing import Any, Dict

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions import capabilities as caps
from pupyteer.server.sessions import transfer

AGENT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "agent", "core")
STUB = os.path.join(AGENT_DIR, "stub.py")
PE_TEMPLATE = os.path.join(AGENT_DIR, "pe_template.c")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_pwd_is_a_recognised_typed_verb():
    assert caps.TYPED_VERBS.get("pwd") == "pwd"


def test_pwd_gates_on_its_own_capability():
    assert caps.required_capability('{"action": "pwd"}') == "pwd"


def test_python_agent_declares_and_dispatches_pwd():
    src = _read(STUB)
    m = re.search(r"CAPABILITIES\s*=\s*\[(.*?)\]", src, re.S)
    assert m and '"pwd"' in m.group(1), "stub.py does not declare the pwd capability"
    assert re.search(r"def mod_pwd\b", src), "no mod_pwd handler"
    assert re.search(r'table\["pwd"\]', src), "no pwd dispatch entry"


def test_python_agent_parses_a_bare_pwd():
    src = _read(STUB)
    m = re.search(r"def _parse_command\(text: str\) -> dict:(.*?)\n    if v == \"fs_list\"", src, re.S)
    assert m, "could not isolate _parse_command's verb section"
    assert "pwd" in m.group(1), "_parse_command has no pwd verb"


def test_c_agent_declares_and_answers_pwd():
    src = _read(PE_TEMPLATE)
    m = re.search(r'\\"capabilities\\":\[(.*?)\]', src, re.S)
    assert m and "pwd" in m.group(1), "pe_template.c does not declare pwd"
    bv = re.search(r"static const char \*bare_verb_action\(const char \*line\)\s*\{(.*?)\n\}", src, re.S)
    assert bv and '"pwd"' in bv.group(1), "bare_verb_action() does not answer a bare pwd"


class FakeSession:
    session_id = "sess-pwd"


class FakeSessionManager:
    pass


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


def test_pwd_module_returns_the_working_directory(config, audit, monkeypatch):
    calls = []

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return {"cwd": "/home/operator", "platform": "linux"}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import PwdModule

    mod = PwdModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "ok"
    assert calls == [{"action": "pwd"}]
    assert result["cwd"] == "/home/operator"


def test_pwd_module_errors_when_the_agent_sends_no_directory(config, audit, monkeypatch):
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"ok": True}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import PwdModule

    mod = PwdModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
    assert "director" in result["error"].lower() or "cwd" in result["error"].lower()
