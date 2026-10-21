#!/usr/bin/env python3
"""Pupyteer — Red Team Operations Framework

Entry point for the Pupyteer C2 framework.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pupyteer import __version__, __codename__


def configure_stdio() -> None:
    """Force UTF-8 on stdout/stderr.

    The banner and tables use box-drawing glyphs, which the default Windows
    console codepage (cp1252) cannot encode and raises on.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def async_main(config_path: str | None = None, no_tui: bool = False,
                     environment: str | None = None) -> int:
    """Async main entry."""
    from pupyteer.server.core.config import ConfigManager
    from pupyteer.server.core.engine import PupyteerEngine
    from pupyteer.tui.app import PupyteerTUI

    configure_stdio()
    config = ConfigManager(config_path, environment=environment)
    setup_logging(config.get("logging.level", "INFO"))

    engine = PupyteerEngine(config_path)

    if no_tui:
        # Headless mode — just start engine and wait
        await engine.start()
        print("Pupyteer engine running (headless). Press Ctrl+C to stop.")
        try:
            await engine.wait_for_shutdown()
        except KeyboardInterrupt:
            pass
        await engine.stop()
    else:
        # TUI mode
        tui = PupyteerTUI(engine)
        await tui.run()

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the top-level parser.

    Exposed so pupyteer.cli can add its subcommands to the same parser rather
    than re-declaring the global flags — one place defines them.
    """
    parser = argparse.ArgumentParser(
        prog="pupyteer",
        description=f"Pupyteer — Red Team Operations Framework v{__version__}",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
        default=None,
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run engine without TUI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Pupyteer v{__version__} ({__codename__})",
    )
    parser.add_argument(
        "-e", "--environment",
        help="Environment overlay name (dev/staging/prod/ctf). Loads "
             "pupyteer.<name>.yaml/.json from cwd, ~/.config/pupyteer, or /etc/pupyteer. "
             "Overrides the PUPYTEER_ENV variable.",
        default=None,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    return parser


def main() -> int:
    """Synchronous entry point."""
    # A subcommand is non-interactive work (list modules, build a payload,
    # dump config) and must never fall through into starting the engine, so it
    # is checked before anything else touches config or binds a port.
    from pupyteer.cli import run_cli

    rc = run_cli()
    if rc is not None:
        return rc

    parser = build_arg_parser()
    args = parser.parse_args()

    if args.debug:
        os.environ["PUPYTEER_LOGGING__LEVEL"] = "DEBUG"

    try:
        return asyncio.run(async_main(args.config, args.headless, args.environment))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
