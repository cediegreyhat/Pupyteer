"""Contract tests for getpid / getuid / getppid (Pupy parity).

Upstream references: pupy/modules/{getpid,getuid,getppid}.py

These are the three that could NOT ride the shell_for() path: nothing in cmd
yields the agent's own pid (a `powershell -c $PID` returns PowerShell's), and
ppid needs a process snapshot. getuid is the exception -- `whoami` answers it,
so it does map through shell_for().

All three are stdlib-only upstream, so the native-reimplementation strategy
covers them with no third-party tree.
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

ACTIONS = ["getpid", "getuid", "getppid"]
REPLY_KEY = {"getpid": "pid", "getuid": "user", "getppid": "ppid"}
# getuid maps through shell_for(); the other two need explicit C handlers.
SHELL_MAPPED = {"getuid"}

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
    ha = re.search(r"static int handle_action\((.*?)\n\}", src, re.S)
    assert ha, "could not find handle_action"
    body = ha.group(1)
    if action in SHELL_MAPPED:
        # A fixed command answers it, so the mapping belongs in shell_for(),
        # which handle_action reaches through its as_shell lookup -- not in
        # handle_action's own body.
        sf = re.search(r"static const char \*shell_for\(const char \*action\)\s*\{(.*?)\n\}", src, re.S)
        assert sf, "could not find shell_for"
        assert f'action, "{action}"' in sf.group(1), f"shell_for() has no {action} mapping"
    else:
        # Needs a real handler: no fixed command can produce the answer.
        assert f'action, "{action}"' in body, f"handle_action() has no {action} branch"
        assert "GetCurrentProcessId" in body or "TH32CS_SNAPPROCESS" in body, \
            f"{action} has no Win32 implementation"


class FakeSession:
    session_id = "sess-pi"


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
    payload = 4242 if action != "getuid" else "NT AUTHORITY\\SYSTEM"

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return {key: payload}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin import recon

    cls = getattr(recon, f"{action.title().replace('_', '')}Module")
    mod = cls(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "ok"
    assert calls == [{"action": action}]
    assert result[key] == payload


@pytest.mark.parametrize("action", ACTIONS)
def test_module_errors_when_the_agent_sends_nothing(action, config, audit, monkeypatch):
    """pid 0 and an empty username are both "no answer", not a valid one."""
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"ok": True}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin import recon

    cls = getattr(recon, f"{action.title().replace('_', '')}Module")
    mod = cls(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
