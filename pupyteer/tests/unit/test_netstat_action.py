"""Contract tests for adding the `netstat` action (Pupy parity, tranche 1).

Upstream reference: pupy/modules/netstat.py

`netstat` is the first action added since Pupyteer's own contract was written,
so it exercises every place an action has to be declared. That is the documented
dominant failure mode in this repo: an action added to one agent and not the
other, or to the agent and not the capability gate, produces a task the server
sends and the implant silently cannot honour.

These tests pin all four surfaces at once so a partial addition fails loudly:

  1. the server's typed-verb table (`capabilities.TYPED_VERBS`)
  2. the Python agent (`stub.py`: CAPABILITIES + dispatch table + handler)
  3. the C agent (`pe_template.c`: capability string + shell mapping + bare verb)
  4. the operator-facing module
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


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# ─── 1. server-side verb table ───────────────────────────────────────


def test_netstat_is_a_recognised_typed_verb():
    assert caps.TYPED_VERBS.get("netstat") == "netstat"


def test_netstat_requires_the_netstat_capability():
    """A typed `netstat` must gate on the implant declaring it."""
    assert caps.required_capability("netstat") == "netstat"


def test_a_netstat_task_gates_on_the_netstat_capability():
    assert caps.required_capability('{"action": "netstat"}') == "netstat"


# ─── 2. Python agent ─────────────────────────────────────────────────


def test_python_agent_declares_netstat():
    src = _read(STUB)
    m = re.search(r"CAPABILITIES\s*=\s*\[(.*?)\]", src, re.S)
    assert m, "could not find CAPABILITIES in stub.py"
    assert '"netstat"' in m.group(1), "stub.py does not declare the netstat capability"


def test_python_agent_dispatches_netstat():
    src = _read(STUB)
    assert re.search(r'table\["netstat"\]', src), "stub.py has no netstat dispatch entry"
    assert re.search(r"def mod_netstat\b", src), "stub.py has no mod_netstat handler"


# ─── 3. C agent ──────────────────────────────────────────────────────


def test_c_agent_declares_netstat():
    src = _read(PE_TEMPLATE)
    m = re.search(r'\\"capabilities\\":\[(.*?)\]', src, re.S)
    assert m, "could not find the capability string in pe_template.c"
    assert "netstat" in m.group(1), "pe_template.c does not declare netstat"


def test_c_agent_maps_netstat_to_a_shell_command():
    src = _read(PE_TEMPLATE)
    assert re.search(r'shell_for[\s\S]{0,600}?"netstat"', src), \
        "pe_template.c shell_for() has no netstat mapping"


def test_c_agent_answers_a_bare_netstat_verb():
    src = _read(PE_TEMPLATE)
    m = re.search(r"static const char \*bare_verb_action\(const char \*line\)\s*\{(.*?)\n\}", src, re.S)
    assert m, "could not find bare_verb_action in pe_template.c"
    assert '"netstat"' in m.group(1), "bare_verb_action() does not answer a bare netstat"


# ─── 4. operator-facing module ───────────────────────────────────────


class FakeSession:
    session_id = "sess-ns"


class FakeSessionManager:
    def __init__(self):
        self.calls = []


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


def test_netstat_module_dispatches_the_netstat_action(config, audit, monkeypatch):
    calls = []

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return {"ok": True, "output": "TCP 0.0.0.0:445 LISTENING 4"}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import NetstatModule

    mod = NetstatModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "ok"
    assert calls == [{"action": "netstat"}]
    assert "445" in result["output"]


def test_netstat_module_reports_a_refusal_as_an_error(config, audit, monkeypatch):
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"error": "refused: this implant declared exec, and not 'netstat'"}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import NetstatModule

    mod = NetstatModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
    assert "netstat" in result["error"]
