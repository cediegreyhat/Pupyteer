"""The heavy obfuscated build must answer everything it declares.

The heavy build replaces the plaintext `if action == ...` chain with a dispatch
table. Two lists had to agree by hand — the encrypted key set and the table —
and they did not: twelve keys against a table of handlers, with `screenshot`,
`pyexec` and `load_package` missing from both. The build declared all of them in
`CAPABILITIES`, so the server sent those tasks and the payload answered
"unknown action", which the operator reads as the target's reply.

These tests import the generated agent and ask it every capability it claims.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig


def _generate(tmp_path: Path, name: str, **overrides) -> Path:
    settings = {
        "transport": "tcp", "host": "127.0.0.1", "port": 8443,
        "sleep": 1, "jitter": 0,
        "modules": {"recon": True, "exec": True, "fs": True,
                    "privesc": True, "screenshot": True},
    }
    settings.update(overrides)
    path = tmp_path / f"{name}.py"
    path.write_text(AgentStubGenerator().generate(StubConfig(name=name, **settings)),
                    encoding="utf-8")
    return path


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: Handlers that leave the process or touch hardware; "unknown action" is what
#: is under test, not whether the screenshot succeeded.
NON_DETERMINISTIC = {"shutdown", "migrate", "screenshot", "process_kill"}


@pytest.mark.parametrize("level", ["none", "light", "medium", "heavy"])
def test_every_declared_capability_has_a_handler(tmp_path, level):
    """Parity across obfuscation levels: a claim is a promise about the binary."""
    module = _load(_generate(tmp_path, f"agent_{level}", obfuscation=level))
    declared = module.CAPABILITIES
    assert declared, "the build declared nothing — the parse found no claim"

    unhandled = []
    for action in declared:
        if action in NON_DETERMINISTIC:
            continue
        result = module._dispatch({"action": action, "path": "."})
        if isinstance(result, dict) and result.get("error", "").startswith("unknown action"):
            unhandled.append(action)
    assert not unhandled, f"declared but no handler: {unhandled}"


def test_the_heavy_table_is_not_missing_the_file_dispatch(tmp_path):
    """`load_package` is a capability the server gates on and then sends."""
    module = _load(_generate(tmp_path, "agent_heavy_lp", obfuscation="heavy"))
    assert "load_package" in module.CAPABILITIES
    result = module._dispatch({"action": "load_package", "name": "nope",
                               "path": "", "force": False})
    assert not (isinstance(result, dict)
                and result.get("error", "").startswith("unknown action"))


def test_the_heavy_fs_get_reply_is_the_chunked_shape(tmp_path):
    """A bare {"data": ...} reads as a transfer that never reports eof."""
    module = _load(_generate(tmp_path, "agent_heavy_fs", obfuscation="heavy"))
    target = tmp_path / "blob.bin"
    target.write_bytes(b"x" * 64)

    reply = module._dispatch({"action": "fs_get", "path": str(target),
                              "offset": 0, "length": 16})
    assert set(reply) >= {"size", "offset", "length", "eof", "data"}
    assert reply["size"] == 64
    assert reply["length"] == 16
    assert reply["eof"] is False


def test_the_plaintext_and_heavy_builds_agree(tmp_path):
    """The obfuscator transforms how the source reads, not what it does."""
    plain = _load(_generate(tmp_path, "agent_plain", obfuscation="none"))
    heavy = _load(_generate(tmp_path, "agent_heavy_cmp", obfuscation="heavy"))
    target = tmp_path / "same.bin"
    target.write_bytes(b"y" * 48)

    a = plain._dispatch({"action": "fs_get", "path": str(target), "offset": 8,
                         "length": 16})
    b = heavy._dispatch({"action": "fs_get", "path": str(target), "offset": 8,
                         "length": 16})
    assert a == b


def test_a_build_without_the_screenshot_switch_does_not_claim_it(tmp_path):
    """The claim and the handler come from the same switch."""
    module = _load(_generate(tmp_path, "agent_noshot", obfuscation="heavy",
                             modules={"recon": True, "exec": True, "fs": True,
                                      "privesc": True, "screenshot": False}))
    assert "screenshot" not in module.CAPABILITIES
    result = module._dispatch({"action": "screenshot"})
    assert isinstance(result, dict)
    assert result["error"].startswith("unknown action")
