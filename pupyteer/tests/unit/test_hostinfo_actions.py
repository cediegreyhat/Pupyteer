"""Contract tests for a batch of stdlib-only host-info actions (Pupy parity).

Upstream references: pupy/modules/{env,date,alive}.py

All six were classified PY_DEP in the manifest, which was wrong. Auditing their
upstream sources shows **zero third-party imports** -- only `sys`, `threading`,
`datetime`, `logging`. Pupy's per-module glue made them look dependency-bearing;
they are pure stdlib and portable now, with no package mechanism required.

They are also all the same shape: a bare verb, no argument, a small dict back.
Parametrised rather than six near-identical test bodies.
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

ACTIONS = ["env", "date", "alive"]

# Each action answers under its own key -- env is a mapping, date leads with
# utc, alive is a boolean. Pinning the real key keeps the module honest about
# the shape the agent actually sends.
# env answers {"variables": {...}, "redacted": [...]} -- the agent withholds
# credential-looking values by key name and names what it withheld, so the
# payload key is `variables`, not `env`.
REPLY_KEY = {"env": "variables", "date": "utc", "alive": "alive"}

# Deliberately NOT in this batch: getpid, getuid, getppid. They have no fixed
# shell command on Windows (nothing in cmd yields the agent's own pid, and
# uid/ppid are POSIX-shaped), so they need explicit C handlers -- a separate
# slice rather than a shell_for() entry.

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
    session_id = "sess-host"


class FakeSessionManager:
    pass


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.mark.parametrize("action", ACTIONS)
def test_module_dispatches_the_action_and_surfaces_the_reply(action, config, audit, monkeypatch):
    calls = []

    key = REPLY_KEY[action]
    payload = {"PATH": "/usr/bin"} if action == "env" else f"answer-from-{action}"

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
    assert result[REPLY_KEY[action]] == payload


@pytest.mark.parametrize("action", ACTIONS)
def test_module_errors_on_a_reply_with_nothing_in_it(action, config, audit, monkeypatch):
    """A well-formed reply carrying no answer is an error, not a blank success."""
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"ok": True}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin import recon

    cls = getattr(recon, f"{action.title().replace('_', '')}Module")
    mod = cls(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
