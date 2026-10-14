#!/usr/bin/env python3
"""Non-interactive subcommand surface for Pupyteer.

The TUI is the primary interface, but an operator doing scripted or
repeatable work — enumerate modules in a CI gate, generate a lab payload for
a CTF, check server health — should not need a terminal TUI to do it. Every
subcommand here is read-only except `build-payload`, which writes an artifact
to the configured output directory and nothing else.

Deliberately NOT here: anything that talks to a live agent session. Tasking a
beacon is an interactive, auditable act; a one-shot CLI command that fires at
whatever host answered last is a foot-gun, and the TUI already does it with
confirmation and audit context.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger


def _make_registry(config: ConfigManager):
    """Build a module registry the same way the engine does.

    Imports are local so `pupyteer --help` and the lighter subcommands do not
    pay for importing the module/registry machinery.
    """
    from pupyteer.server.modules.registry import ModuleRegistry

    audit = AuditLogger(config)
    return ModuleRegistry(config, audit)


def _emit(rows: List[Dict[str, Any]], as_json: bool, text_fn) -> None:
    if as_json:
        print(json.dumps(rows, indent=2, sort_keys=True, default=str))
        return
    text_fn(rows)


def _cmd_list_modules(args: argparse.Namespace) -> int:
    config = ConfigManager(args.config, environment=args.environment)
    registry = _make_registry(config)
    registry.discover()
    rows = registry.list_all()
    if args.category:
        rows = [m for m in rows if m.get("category") == args.category]
    rows.sort(key=lambda m: m.get("name", ""))

    def text(data: List[Dict[str, Any]]) -> None:
        if not data:
            print("No modules registered.")
            return
        width = max(len(m.get("name", "")) for m in data)
        print(f"{'MODULE'.ljust(width)}  {'CATEGORY':<12}  DESCRIPTION")
        print(f"{'-' * width}  {'-' * 12}  {'-' * 11}")
        for m in data:
            name = m.get("name", "?").ljust(width)
            cat = str(m.get("category", "?")).ljust(12)
            print(f"{name}  {cat}  {m.get('description', '')}")

    _emit(rows, args.json, text)
    return 0


def _cmd_module_info(args: argparse.Namespace) -> int:
    config = ConfigManager(args.config, environment=args.environment)
    registry = _make_registry(config)
    registry.discover()
    rows = [m for m in registry.list_all() if m.get("name") == args.name]
    if not rows:
        print(f"Unknown module: {args.name}", file=sys.stderr)
        print(
            "Run `pupyteer list-modules` to see what is registered.",
            file=sys.stderr,
        )
        return 2

    info = rows[0]
    health = registry.get_health(args.name)
    if health is not None:
        info = dict(info)
        info["state"] = health.state.value
        info["last_error"] = health.last_error

    print(json.dumps(info, indent=2, sort_keys=True, default=str))
    return 0


def _cmd_module_health(args: argparse.Namespace) -> int:
    """Report registry load state — the antiforensics gate is meant to show
    up here as FAILED, so a clean run is not the same as 'nothing to report'."""
    config = ConfigManager(args.config, environment=args.environment)
    registry = _make_registry(config)
    registry.discover()
    rows = registry.list_health()

    _emit(
        rows,
        args.json,
        lambda data: (
            print("Module registry health:")
            or [print(f"  {r.get('name')}: {r.get('state')}" + (f" — {r.get('last_error')}" if r.get("last_error") else "")) for r in data]
            or print(f"  ({len(data)} entries)"),
        ),
    )
    return 0


def _cmd_build_payload(args: argparse.Namespace) -> int:
    """Generate one payload artifact. The only mutating subcommand."""
    from pupyteer.payloads.manager import (
        PayloadArch,
        PayloadBuilder,
        PayloadConfig,
        PayloadDelivery,
        PayloadPlatform,
        PayloadStatus,
        PayloadType,
    )

    config = ConfigManager(args.config, environment=args.environment)
    audit = AuditLogger(config)

    # --platform/--arch are strings on the command line, but every consumer
    # downstream (validate_config, to_dict, the stub renderer) expects the
    # enums. Coerce here and fail with a readable message rather than an
    # AttributeError from deep inside the builder.
    try:
        platform = PayloadPlatform(args.platform.lower())
        arch = PayloadArch(args.arch.lower())
    except ValueError as exc:
        print(f"Invalid platform/arch: {exc}", file=sys.stderr)
        print(f"  platforms: {[p.value for p in PayloadPlatform]}", file=sys.stderr)
        print(f"  archs:     {[a.value for a in PayloadArch]}", file=sys.stderr)
        return 2

    pcfg = PayloadConfig(
        name=args.name,
        platform=platform,
        arch=arch,
        payload_type=PayloadType.EXECUTABLE,
        delivery=PayloadDelivery.STAGELESS,
        transport=args.transport,
        host=args.host,
        port=args.port,
        profile=args.profile,
        sleep=args.sleep,
        jitter=args.jitter,
        persistence=args.persistence,
        screenshot=args.screenshot,
        migration=not args.no_migration,
        anti_analysis=args.anti_analysis,
        obfuscation=args.obfuscation,
        rc4_key=args.rc4_key,
    )

    builder = PayloadBuilder(config, audit)
    problems = builder.validate_config(pcfg)
    if problems:
        print("Payload configuration is not buildable:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2

    # Dry-run stops at the gate above: it reports buildability without writing
    # an artifact, invoking a compiler, or touching the audit trail.
    if args.dry_run:
        print(json.dumps(pcfg.to_dict(), indent=2, sort_keys=True, default=str))
        print("\nConfiguration is buildable (dry-run: nothing was compiled).")
        return 0

    metadata = asyncio.run(
        builder.build(pcfg, payload_id=builder.generate_payload_id(),
                      version=args.version, sign=args.sign)
    )
    print(json.dumps(metadata.to_dict(), indent=2, sort_keys=True, default=str))
    # build() records a failure in metadata (and the audit trail) instead of
    # raising, so the process would exit 0 on a payload that does not exist.
    # A CI gate or an operator script needs the non-zero status.
    if metadata.status == PayloadStatus.FAILED.value:
        print(
            "\nPayload build FAILED — see the generation log next to the "
            "artifact, and the audit trail.",
            file=sys.stderr,
        )
        return 1
    return 0


def _cmd_server_info(args: argparse.Namespace) -> int:
    """Dump the effective config (secrets redacted) — the fastest answer to
    'why is my listener on that port'."""
    config = ConfigManager(args.config, environment=args.environment)
    rows = config.as_dict() if hasattr(config, "as_dict") else config._config
    if not args.reveal:
        rows = _redact(rows)
    print(json.dumps(rows, indent=2, sort_keys=True, default=str))
    return 0


_SECRET_HINTS = ("secret", "password", "passwd", "token", "key", "auth")


def _redact(obj: Any) -> Any:
    """Redact values whose key name looks secret-bearing.

    Mirrors the audit logger's own redaction intent, and is intentionally
    conservative: when in doubt, redact. `--reveal` exists for the operator
    who genuinely wants the value on their own terminal.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(h in str(k).lower() for h in _SECRET_HINTS) and isinstance(v, (str, int)):
                out[k] = "***redacted***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def add_subcommands(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def _common(p: argparse.ArgumentParser) -> None:
        p.add_argument("-c", "--config", help="Path to configuration file", default=None)
        p.add_argument(
            "-e", "--environment",
            help="Environment overlay (dev/staging/prod/ctf)",
            default=None,
        )
        p.add_argument("--json", action="store_true", help="Emit JSON instead of text")

    p_list = sub.add_parser(
        "list-modules", help="List registered post-exploitation modules"
    )
    _common(p_list)
    p_list.add_argument("--category", help="Filter to one category", default=None)
    p_list.set_defaults(func=_cmd_list_modules)

    p_info = sub.add_parser("module-info", help="Show one module's metadata")
    _common(p_info)
    p_info.add_argument("name", help="Module name (see list-modules)")
    p_info.set_defaults(func=_cmd_module_info)

    p_health = sub.add_parser("module-health", help="Show registry load/health state")
    _common(p_health)
    p_health.set_defaults(func=_cmd_module_health)

    p_build = sub.add_parser(
        "build-payload", help="Generate one payload artifact"
    )
    _common(p_build)
    p_build.add_argument("name", help="Payload name")
    p_build.add_argument("--platform", default="windows", help="windows|linux|macos|android")
    p_build.add_argument("--arch", default="x64", help="x64|x86|arm|arm64")
    p_build.add_argument("--transport", default="tcp", help="tcp|http|https|dns|doh")
    p_build.add_argument("--host", default="127.0.0.1", help="Callback host")
    p_build.add_argument("--port", type=int, default=8443, help="Callback port")
    p_build.add_argument("--profile", default="HTTPS-Standard", help="Transport profile name")
    p_build.add_argument("--sleep", type=int, default=60, help="Beacon sleep seconds")
    p_build.add_argument("--jitter", type=int, default=20, help="Beacon jitter percent")
    p_build.add_argument("--version", default="1.0.0", help="Payload version string")
    p_build.add_argument("--persistence", action="store_true", help="Enable persistence (off by default)")
    p_build.add_argument("--screenshot", action="store_true", help="Compile in screen capture")
    p_build.add_argument("--no-migration", action="store_true", help="Omit process migration")
    p_build.add_argument("--anti-analysis", action="store_true", help="Compile in VM/sandbox detection (off by default)")
    p_build.add_argument("--obfuscation", choices=["none", "light", "medium", "heavy"], default=None,
                         help="Source-level obfuscation level (default: none)")
    p_build.add_argument("--rc4-key", default="", help="RC4 transport key (empty = plaintext wire)")
    p_build.add_argument("--sign", action="store_true", help="Sign the artifact if signing is configured")
    p_build.add_argument("--dry-run", action="store_true",
                         help="Validate the config and print it; compile nothing")
    p_build.set_defaults(func=_cmd_build_payload)

    p_srv = sub.add_parser(
        "server-info", help="Show effective config (secrets redacted)"
    )
    _common(p_srv)
    p_srv.add_argument("--reveal", action="store_true", help="Do not redact secret-bearing keys")
    p_srv.set_defaults(func=_cmd_server_info)


def run_cli(argv: Optional[List[str]] = None) -> Optional[int]:
    """Return the subcommand's exit code, or None when no subcommand was given
    (the caller should then start the normal engine/TUI flow)."""
    from pupyteer.main import build_arg_parser

    parser = build_arg_parser()
    add_subcommands(parser)
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        return None

    # A subcommand's stdout is the payload: list-modules --json and
    # server-info are meant to be piped into other tools. The engine's
    # setup_logging() never ran on this path, so the pupyteer logger had no
    # handler and Python's "last resort" handler dumped every logger.warning
    # straight to stderr — the module-registry's intentional antiforensics
    # load failure appeared on a clean rc=0 call, unusable in a pipe.
    # Configure logging here instead: quiet (ERROR and up only) on the normal
    # path so a scripted call is pipe-clean, full detail under --debug. The
    # intentional antiforensics warning is still reachable with --debug.
    level = logging.DEBUG if getattr(args, "debug", False) else logging.ERROR
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    return args.func(args)
