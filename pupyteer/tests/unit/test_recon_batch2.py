"""Contract tests for getdomain + check_vm (Pupy parity).

Upstream references: pupy/modules/getdomain.py, pupy/modules/check_vm.py

Both were classified PY_DEP and are stdlib-only upstream (the audit in
8134602f). Both are bare verbs, so they ride the same _parse_command tuple as
sysinfo/env/date.

check_vm is the evasion-relevant one: it reports whether the host looks
virtualised, which is what an operator needs before deciding whether a payload
is running in a sandbox or an analysis VM.
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

ACTIONS = ["getdomain", "check_vm"]
REPLY_KEY = {"getdomain": "domain", "check_vm": "is_vm"}
# Explicit, not derived: "checkvm".title() -> "Checkvm", but the class is
# CheckVmModule. String-mangling a class name is how this test broke twice.
CLASS = {"getdomain": "GetdomainModule", "check_vm": "CheckVmModule"}

AGENT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "agent", "core")
STUB = os.path.join(AGENT_DIR, "stub.py")
PE_TEMPLATE = os.path.join(AGENT_DIR, "pe_template.c")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("action", ACTIONS)
def test_action_is_a_recognised_typed_verb(action):
    assert caps.TYPED_VERBS.get(action) == action


@pytest.mark.parametrize("action", ACTIONS)
def test_python_agent_declares_dispatches_and_parses(action):
    src = _read(STUB)
    m = re.search(r"CAPABILITIES\s*=\s*\[(.*?)\]", src, re.S)
    assert m and f'"{action}"' in m.group(1), f"stub.py does not declare {action}"
    assert re.search(rf"def mod_{action}\b", src), f"no mod_{action} handler"
    assert re.search(rf'table\["{action}"\]', src), f"no {action} dispatch entry"
    pm = re.search(r"def _parse_command\(text: str\) -> dict:(.*?)\n    if v == \"fs_list\"", src, re.S)
    assert pm and action in pm.group(1), f"_parse_command has no {action} verb"


@pytest.mark.parametrize("action", ACTIONS)
def test_c_agent_declares_and_answers(action):
    src = _read(PE_TEMPLATE)
    m = re.search(r'\\"capabilities\\":\[(.*?)\]', src, re.S)
    assert m and action in m.group(1), f"pe_template.c does not declare {action}"
    bv = re.search(r"static const char \*bare_verb_action\(const char \*line\)\s*\{(.*?)\n\}", src, re.S)
    assert bv and f'"{action}"' in bv.group(1), f"bare_verb_action() does not answer {action}"


class FakeSession:
    session_id = "sess-b2"


class FakeSessionManager:
    pass


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.mark.parametrize("action", ACTIONS)
def test_module_dispatches_and_surfaces_the_reply(action, config, audit, monkeypatch):
    calls = []
    key = REPLY_KEY[action]
    payload = "corp.example" if action == "getdomain" else False

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return {key: payload}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin import recon

    cls = getattr(recon, CLASS[action])
    mod = cls(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "ok"
    assert calls == [{"action": action}]
    assert result[key] == payload


@pytest.mark.parametrize("action", ACTIONS)
def test_module_errors_when_the_agent_sends_no_answer(action, config, audit, monkeypatch):
    """A missing domain and a missing VM verdict are both 'no answer'.

    Note is_vm=False is a REAL answer, so the check must key on presence,
    not truthiness -- a false negative here would read as 'the agent said
    nothing' when it actually said 'not a VM'.
    """
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"ok": True}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin import recon

    cls = getattr(recon, CLASS[action])
    mod = cls(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"


def test_check_vm_false_is_reported_as_a_real_answer(config, audit, monkeypatch):
    """The boolean must survive: False is a verdict, not an absent value."""
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"is_vm": False, "indicators": []}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import CheckVmModule

    mod = CheckVmModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "ok"
    assert result["is_vm"] is False
