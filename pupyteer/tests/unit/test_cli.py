"""Non-interactive subcommand surface.

These tests exercise pupyteer.cli without a TUI or a live listener. They are
the guard rail for the property that matters: scripted use must never start
the engine, bind a port, or report success for a build that failed.
"""
from __future__ import annotations

import json

import pytest

from pupyteer.cli import _redact, run_cli
from pupyteer.main import build_arg_parser


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    monkeypatch.delenv("PUPYTEER_ENV", raising=False)
    monkeypatch.chdir(tmp_path)
    yield


def _run(argv, capsys):
    rc = run_cli(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_no_subcommand_returns_none(capsys):
    """No subcommand means the caller starts the engine/TUI, not a CLI command."""
    assert run_cli([]) is None


def test_parser_exposes_subcommands():
    parser = build_arg_parser()
    # Import lazily to keep the registry import out of module scope.
    from pupyteer.cli import add_subcommands

    add_subcommands(parser)
    args = parser.parse_args(["list-modules"])
    assert args.command == "list-modules"
    assert hasattr(args, "func")


def test_list_modules_text(capsys):
    rc, out, _ = _run(["list-modules"], capsys)
    assert rc == 0
    assert "MODULE" in out
    # Registry discovery is exercised for real, so a known module must appear.
    assert "exec" in out


def test_list_modules_json(capsys):
    rc, out, _ = _run(["list-modules", "--json"], capsys)
    assert rc == 0
    rows = json.loads(out)
    assert isinstance(rows, list) and rows
    assert all("name" in m for m in rows)


def test_list_modules_category_filter(capsys):
    rc, out, _ = _run(["list-modules", "--category", "recon"], capsys)
    assert rc == 0
    assert "recon" in out
    # file_ops modules must be filtered out.
    assert "upload" not in out


def test_module_info(capsys):
    rc, out, _ = _run(["module-info", "exec"], capsys)
    assert rc == 0
    info = json.loads(out)
    assert info["name"] == "exec"
    assert info["category"] == "execution"


def test_module_info_unknown_is_nonzero(capsys):
    rc, _, err = _run(["module-info", "definitely_not_a_module"], capsys)
    assert rc == 2
    assert "Unknown module" in err
    assert "list-modules" in err


def test_module_health_reports_deliberate_failure(capsys):
    """antiforensics.py is deliberately unloadable (it destroys evidence and no
    test exercises it). The health command must surface it as failed rather
    than hide it, so 'everything registered' is not mistaken for 'all good'."""
    rc, out, _ = _run(["module-health", "--json"], capsys)
    assert rc == 0
    rows = json.loads(out)
    names = {r["name"] for r in rows}
    assert "file:antiforensics" in names
    failed = [r for r in rows if r["state"] == "failed"]
    assert failed


def test_server_info_redacts_secrets(capsys):
    rc, out, _ = _run(["server-info"], capsys)
    assert rc == 0
    cfg = json.loads(out)
    assert "***redacted***" in json.dumps(cfg)


def test_redact_recurses_and_conservative():
    obj = {"auth": {"api_token": "abc", "url": "http://x"},
           "list": [{"password": "p"}], "port": 8443}
    red = _redact(obj)
    assert red["auth"]["api_token"] == "***redacted***"
    assert red["auth"]["url"] == "http://x"
    assert red["list"][0]["password"] == "***redacted***"
    assert red["port"] == 8443


def test_build_payload_invalid_platform(capsys):
    rc, _, err = _run(["build-payload", "x", "--platform", "plan9"], capsys)
    assert rc == 2
    assert "not a valid PayloadPlatform" in err


def test_build_payload_invalid_port(capsys):
    rc, _, err = _run(["build-payload", "x", "--port", "99999"], capsys)
    assert rc == 2
    assert "Invalid port" in err


def test_build_payload_dry_run_validates_without_building(capsys, tmp_path, monkeypatch):
    """A dry-run must report buildability but leave the machine untouched: no
    artifact on disk, no audit entry. Otherwise a CI pre-check has side effects."""
    import pupyteer.server.core.logging as logging_mod

    calls = []
    monkeypatch.setattr(logging_mod.AuditLogger, "log_event",
                        lambda self, *a, **k: calls.append(a))

    rc, out, _ = _run(
        ["build-payload", "dryrun1", "--platform", "linux", "--arch", "x64",
         "--transport", "tcp", "--dry-run"], capsys)
    assert rc == 0
    cfg = json.loads(out.split("\nConfiguration is buildable")[0])
    assert cfg["platform"] == "linux"
    assert cfg["name"] == "dryrun1"
    assert "dry-run" in out
    # No compiler ran, so nothing was written into the artifact tree.
    assert not any(tmp_path.rglob("payloads/artifacts/*/dryrun1*"))
    assert calls == []


def test_build_payload_dry_run_invalid_still_nonzero(capsys):
    rc, _, err = _run(
        ["build-payload", "x", "--transport", "email", "--dry-run"], capsys)
    assert rc == 2
    assert "Invalid transport" in err


# ─── the subcommand path owns its logging ────────────────────────
#
# A subcommand's stdout/stderr are the contract for scripted use: list-modules
# --json and server-info are piped into other tools. Before run_cli configured
# logging itself, the engine's setup_logging() had not run yet, so the pupyteer
# logger had no handler and Python's "last resort" handler dumped every
# logger.warning straight to stderr — including the module registry's
# intentional antiforensics load failure — onto an otherwise clean rc=0 call.


def test_quiet_subcommand_does_not_leak_registry_warning_to_stderr(capsys):
    """The deliberate antiforensics load failure must not appear on a normal
    scripted call. It is a warning the registry emits by design; on a
    pipe-clean subcommand it belongs nowhere but --debug."""
    import logging

    # basicConfig is a no-op once the root logger has handlers, so reset the
    # handler state to exercise run_cli's own configuration in isolation.
    root = logging.getLogger()
    had = root.handlers[:]
    root.handlers.clear()
    try:
        rc, out, err = _run(["list-modules"], capsys)
    finally:
        root.handlers[:] = had
    assert rc == 0
    assert "exec" in out
    assert "Failed to load module" not in err
    assert "antiforensics" not in err


def test_debug_surfaces_the_intentional_registry_warning(capsys):
    """Under --debug the operator explicitly asked for detail, so the same
    warning is legitimate output. This is what keeps the quiet default honest
    rather than a silent swallow."""
    import logging

    root = logging.getLogger()
    had = root.handlers[:]
    root.handlers.clear()
    try:
        rc, _, err = _run(["--debug", "list-modules"], capsys)
    finally:
        root.handlers[:] = had
    assert rc == 0
    assert "Failed to load module" in err
    assert "antiforensics" in err
