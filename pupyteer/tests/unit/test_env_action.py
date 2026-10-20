"""Contract tests for the `env` action (Pupy parity, native reimplementation).

Upstream reference: pupy/modules/env.py

Classified PY_DEP; under the revised strategy (reimplement natively rather than
vendor the third-party tree) it is a stdlib one-liner. It is the first module
landed under that strategy, so it doubles as the proof that the route works.

The agent's own environment is sensitive: it can hold proxy credentials, tokens
and cloud keys. So the module redacts by key name rather than dumping
everything, and says how many it redacted.
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


def test_env_is_a_recognised_typed_verb():
    assert caps.TYPED_VERBS.get("env") == "env"


def test_python_agent_declares_dispatches_and_parses_env():
    src = _read(STUB)
    m = re.search(r"CAPABILITIES\s*=\s*\[(.*?)\]", src, re.S)
    assert m and '"env"' in m.group(1), "stub.py does not declare env"
    assert re.search(r"def mod_env\b", src), "no mod_env handler"
    assert re.search(r'table\["env"\]', src), "no env dispatch entry"
    pm = re.search(r"def _parse_command\(text: str\) -> dict:(.*?)\n    if v == \"fs_list\"", src, re.S)
    assert pm and "env" in pm.group(1), "_parse_command has no env verb"


def test_c_agent_declares_and_answers_env():
    src = _read(PE_TEMPLATE)
    m = re.search(r'\\"capabilities\\":\[(.*?)\]', src, re.S)
    assert m and "env" in m.group(1), "pe_template.c does not declare env"
    bv = re.search(r"static const char \*bare_verb_action\(const char \*line\)\s*\{(.*?)\n\}", src, re.S)
    assert bv and '"env"' in bv.group(1), "bare_verb_action() does not answer env"


class FakeSession:
    session_id = "sess-env"


class FakeSessionManager:
    pass


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


def test_env_module_returns_the_environment(config, audit, monkeypatch):
    calls = []

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return {"variables": {"PATH": "/usr/bin", "LANG": "en_US.UTF-8"},
                "redacted": ["AWS_SECRET_ACCESS_KEY"]}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import EnvModule

    mod = EnvModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "ok"
    assert calls == [{"action": "env"}]
    assert result["variables"]["PATH"] == "/usr/bin"
    assert result["redacted"] == ["AWS_SECRET_ACCESS_KEY"]


def test_env_module_errors_when_the_agent_sends_nothing(config, audit, monkeypatch):
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"ok": True}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import EnvModule

    mod = EnvModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
    assert "environment" in result["error"].lower() or "variables" in result["error"].lower()


def test_env_module_never_reports_a_secret_as_a_plain_variable():
    """The redaction list is the point -- a dump of raw env is a credential leak."""
    src = _read(STUB)
    m = re.search(r"def mod_env\(\).*?(?=\ndef )", src, re.S)
    assert m, "could not isolate mod_env"
    body = m.group(0).lower()
    for needle in ("secret", "token", "password", "key"):
        assert needle in body, f"mod_env does not redact on '{needle}'"
