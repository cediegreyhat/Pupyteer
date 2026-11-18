"""Handlers the payload declares have to actually work.

Two of them did not: `mod_date` read two module aliases that were never
imported, so it always answered "cannot read the host clock", and the
anti-analysis sandbox probe read `USERNAME` before it was bound — an exception
its own probe loop swallows, so the probe silently never ran.
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
    settings = {"transport": "tcp", "host": "127.0.0.1", "port": 8443,
                "sleep": 1, "jitter": 0}
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


def test_mod_date_reports_the_clock(tmp_path):
    """It used to read `_dt` and `_tm`, neither of which existed."""
    module = _load(_generate(tmp_path, "agent_date"))
    out = module._dispatch({"action": "date"})
    assert "error" not in out, out
    for key in ("utc", "local", "tzname"):
        assert key in out, out


def test_the_recon_verbs_answer_with_real_data(tmp_path):
    """A handler that returns an error dict reads as the target's answer."""
    module = _load(_generate(tmp_path, "agent_recon"))
    for action in ("pwd", "getpid", "getppid", "getuid", "getdomain",
                   "alive", "date"):
        out = module._dispatch({"action": action})
        assert not (isinstance(out, dict) and out.get("error")), (action, out)


def test_the_anti_analysis_probes_can_read_the_operator_name(tmp_path):
    """`USERNAME` was defined below the probes that read it.

    The probe loop catches every exception and moves on, so the failure was
    invisible: on a build with anti-analysis on, the sandbox-environment probe
    never ran and the host was judged only by the probes after it.
    """
    try:
        module = _load(_generate(tmp_path, "agent_aa", anti_analysis=True))
    except SystemExit:
        pytest.skip("this host trips the anti-analysis gate")
    # Every probe must actually run. A name that is not bound yet raises, and
    # the loop in _anti_analysis() swallows it, so the probe is silently skipped.
    assert module._AA_PROBES, "no probes were emitted"
    for probe in module._AA_PROBES:
        assert probe() in (0, 2), probe.__name__
