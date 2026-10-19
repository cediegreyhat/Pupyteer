"""Contract tests for the `process_kill` action (Pupy parity, tranche 1).

Upstream reference: pupy/modules/process_kill.py

Unlike `netstat`, this action takes an argument (a PID), so it exercises the
JSON-task-with-args path rather than a bare verb. It is also the first
destructive action in the port, so the tests pin that a kill is never reported
as done when the agent did not confirm it.

Same six surfaces as any action (see test_netstat_action.py); pinned together so
a partial addition fails loudly.
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


# ─── server-side verb table ──────────────────────────────────────────


def test_process_kill_is_a_recognised_typed_verb():
    assert caps.TYPED_VERBS.get("process_kill") == "process_kill"


def test_a_process_kill_task_gates_on_its_own_capability():
    assert caps.required_capability('{"action": "process_kill", "pid": 4}') == "process_kill"


# ─── Python agent ────────────────────────────────────────────────────


def test_python_agent_declares_process_kill():
    src = _read(STUB)
    m = re.search(r"CAPABILITIES\s*=\s*\[(.*?)\]", src, re.S)
    assert m, "could not find CAPABILITIES in stub.py"
    assert '"process_kill"' in m.group(1), "stub.py does not declare process_kill"


def test_python_agent_has_a_process_kill_handler():
    src = _read(STUB)
    assert re.search(r"def mod_process_kill\b", src), "no mod_process_kill handler"
    assert re.search(r'table\["process_kill"\]', src), "no process_kill dispatch entry"


def test_python_agent_parses_a_kill_verb_with_a_pid():
    """`kill 1234` and `process_kill 1234` must become a task, not shell text."""
    src = _read(STUB)
    m = re.search(r"def _parse_command\(text: str\) -> dict:(.*?)\n    if v == \"fs_list\"", src, re.S)
    assert m, "could not isolate _parse_command's verb section"
    assert "process_kill" in m.group(1), "_parse_command has no process_kill verb"


# ─── C agent ─────────────────────────────────────────────────────────


def test_c_agent_declares_process_kill():
    src = _read(PE_TEMPLATE)
    m = re.search(r'\\"capabilities\\":\[(.*?)\]', src, re.S)
    assert m, "could not find the capability string in pe_template.c"
    assert "process_kill" in m.group(1), "pe_template.c does not declare process_kill"


def test_c_agent_handles_process_kill():
    """It takes an argument, so shell_for() cannot carry it -- handle_action must."""
    src = _read(PE_TEMPLATE)
    m = re.search(r"static int handle_action\((.*?)\n\}", src, re.S)
    assert m, "could not find handle_action in pe_template.c"
    assert "process_kill" in m.group(1), "handle_action() does not handle process_kill"


# ─── operator-facing module ──────────────────────────────────────────


class FakeSession:
    session_id = "sess-pk"


class FakeSessionManager:
    def __init__(self):
        self.calls = []


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


def _install(monkeypatch, reply):
    calls = []

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return reply

    monkeypatch.setattr(transfer, "run_action", _fake)
    return calls


def test_process_kill_module_sends_the_pid(config, audit, monkeypatch):
    calls = _install(monkeypatch, {"ok": True, "pid": 1234, "killed": True})

    from pupyteer.server.modules.builtin.recon import ProcessKillModule

    mod = ProcessKillModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"pid": 1234}))

    assert result["status"] == "ok"
    assert calls == [{"action": "process_kill", "pid": 1234}]
    assert result["killed"] is True


def test_process_kill_module_requires_a_target(config, audit, monkeypatch):
    """No pid and no name is a usage error, and must not task the agent."""
    calls = _install(monkeypatch, {"ok": True})

    from pupyteer.server.modules.builtin.recon import ProcessKillModule

    mod = ProcessKillModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
    assert calls == []


def test_process_kill_does_not_report_success_without_confirmation(config, audit, monkeypatch):
    """A destructive action must not read as done when the agent said nothing.

    This is the one that matters: an operator who believes a process is dead
    and is wrong will draw the wrong conclusion about the host.
    """
    _install(monkeypatch, {"ok": True})

    from pupyteer.server.modules.builtin.recon import ProcessKillModule

    mod = ProcessKillModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"pid": 1234}))

    assert result["status"] == "error"
    assert "confirm" in result["error"].lower() or "killed" in result["error"].lower()


def test_process_kill_surfaces_a_refusal(config, audit, monkeypatch):
    _install(monkeypatch, {"error": "refused: this implant declared exec, and not 'process_kill'"})

    from pupyteer.server.modules.builtin.recon import ProcessKillModule

    mod = ProcessKillModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {"pid": 4}))

    assert result["status"] == "error"
    assert "process_kill" in result["error"]
