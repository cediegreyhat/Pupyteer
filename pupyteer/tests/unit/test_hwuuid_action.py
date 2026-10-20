"""Contract tests for the `get_hwuuid` action (Pupy parity).

Upstream reference: pupy/modules/get_hwuuid.py (+ pupy/packages/all/hwuuid.py)

Classified PY_DEP in the parity manifest, but it is NOT blocked: the lookup is
pure stdlib (Windows MachineGuid from the registry, /etc/machine-id or DMI on
Linux, IOPlatformUUID on macOS). Pupy's hwuuid.py glue exists to paper over
those three paths, not to pull in a dependency. So this is portable now and
does not wait on the load_package mechanism.
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


def test_get_hwuuid_is_a_recognised_typed_verb():
    assert caps.TYPED_VERBS.get("get_hwuuid") == "get_hwuuid"


def test_python_agent_declares_dispatches_and_parses_get_hwuuid():
    src = _read(STUB)
    m = re.search(r"CAPABILITIES\s*=\s*\[(.*?)\]", src, re.S)
    assert m and '"get_hwuuid"' in m.group(1), "stub.py does not declare get_hwuuid"
    assert re.search(r"def mod_hwuuid\b", src), "no mod_hwuuid handler"
    assert re.search(r'table\["get_hwuuid"\]', src), "no get_hwuuid dispatch entry"
    pm = re.search(r"def _parse_command\(text: str\) -> dict:(.*?)\n    if v == \"fs_list\"", src, re.S)
    assert pm and "get_hwuuid" in pm.group(1), "_parse_command has no get_hwuuid verb"


def test_c_agent_declares_and_answers_get_hwuuid():
    src = _read(PE_TEMPLATE)
    m = re.search(r'\\"capabilities\\":\[(.*?)\]', src, re.S)
    assert m and "get_hwuuid" in m.group(1), "pe_template.c does not declare get_hwuuid"
    bv = re.search(r"static const char \*bare_verb_action\(const char \*line\)\s*\{(.*?)\n\}", src, re.S)
    assert bv and '"get_hwuuid"' in bv.group(1), "bare_verb_action() does not answer get_hwuuid"


class FakeSession:
    session_id = "sess-hw"


class FakeSessionManager:
    pass


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


def test_hwuuid_module_returns_the_identifier(config, audit, monkeypatch):
    calls = []

    async def _fake(session_manager, session_id, task, timeout=0):
        calls.append(task)
        return {"hwuuid": "4c4c4544-0037-3110-8054-b7c04f4d4432", "source": "dmi"}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import HwUuidModule

    mod = HwUuidModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "ok"
    assert calls == [{"action": "get_hwuuid"}]
    assert result["hwuuid"].startswith("4c4c4544")


def test_hwuuid_module_errors_when_the_agent_has_no_identifier(config, audit, monkeypatch):
    """A host that will not give up a UUID is an error, not an empty string."""
    async def _fake(session_manager, session_id, task, timeout=0):
        return {"ok": True}

    monkeypatch.setattr(transfer, "run_action", _fake)

    from pupyteer.server.modules.builtin.recon import HwUuidModule

    mod = HwUuidModule(config, audit)
    mod._session_manager = FakeSessionManager()

    result = asyncio.run(mod.execute(FakeSession(), {}))

    assert result["status"] == "error"
    assert "uuid" in result["error"].lower() or "identifier" in result["error"].lower()
