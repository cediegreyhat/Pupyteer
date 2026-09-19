"""Pupyteer Evasion Testing Commands — Phase 10.

Provides command-line and TUI-accessible commands for detection-resilience testing.

Wire to TUI via app.py: evasion [status|run|list|stats|profiles|runner]
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict, List, Optional


async def evasion_status(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show evasion testing system status."""
    engine = tui._engine
    return {
        "status": "ok",
        "test_mode": engine.evasion.test_mode,
        "litterbox_configured": engine.evasion.litterbox_configured,
        "stats": engine.evasion.get_stats(),
    }


async def evasion_run(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Run an evasion test.

    Usage: evasion run --name NAME --artifact PATH [--env ENV] [--controls C1,C2] [--profile PROFILE]
    """
    name = "unnamed"
    artifact_path = ""
    environment = "local"
    controls: List[str] = []
    profile_name = ""

    i = 0
    while i < len(args):
        if args[i] == "--name" and i + 1 < len(args):
            name = args[i + 1]
            i += 2
        elif args[i] == "--artifact" and i + 1 < len(args):
            artifact_path = args[i + 1]
            i += 2
        elif args[i] == "--env" and i + 1 < len(args):
            environment = args[i + 1]
            i += 2
        elif args[i] == "--controls" and i + 1 < len(args):
            controls = [c.strip() for c in args[i + 1].split(",")]
            i += 2
        elif args[i] == "--profile" and i + 1 < len(args):
            profile_name = args[i + 1]
            i += 2
        else:
            return {"status": "error", "error": f"Unknown argument: {args[i]}"}

    if not artifact_path and not profile_name:
        return {"status": "error", "error": "Missing --artifact PATH or --profile PROFILE"}

    from pupyteer.server.evasion.models import EvasionTestConfig
    from pupyteer.server.evasion.runner import EvasionTestRunner, RunnerConfig

    engine = tui._engine

    runner_config = RunnerConfig(auto_obfuscate=False)
    runner = EvasionTestRunner(engine.config, engine.audit, runner_config)
    await runner.initialize()

    try:
        if profile_name:
            result = await runner.run_with_profile(
                profile_name,
                artifact_path or os.devnull,
                environment=environment,
            )
        else:
            cfg = EvasionTestConfig(
                name=name,
                artifact_path=artifact_path,
                artifact_hash_sha256="",
                environment=environment,
                controls=controls,
                test_mode=True,
            )
            result = await engine.evasion.run_test(cfg)

        return {"status": "ok", "result": result.to_dict()}
    finally:
        await runner.shutdown()


async def evasion_list(tui: Any, args: List[str]) -> Dict[str, Any]:
    """List recent evasion test results."""
    history = tui._engine.evasion.get_history()
    results = [r.to_dict() for r in history[-20:]]
    return {"status": "ok", "count": len(results), "tests": results}


async def evasion_stats(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show evasion test statistics."""
    return {"status": "ok", "stats": tui._engine.evasion.get_stats()}


async def evasion_profiles(tui: Any, args: List[str]) -> Dict[str, Any]:
    """List available evasion test configuration profiles."""
    from pupyteer.server.evasion.profiles import list_profiles

    profiles = list_profiles()
    return {"status": "ok", "count": len(profiles), "profiles": profiles}


async def evasion_runner(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Run via EvasionTestRunner with full orchestration.

    Usage: evasion runner --profile PROFILE --artifact PATH [--env ENV]
    """
    profile_name = ""
    artifact_path = ""
    environment = "local"

    i = 0
    while i < len(args):
        if args[i] == "--profile" and i + 1 < len(args):
            profile_name = args[i + 1]
            i += 2
        elif args[i] == "--artifact" and i + 1 < len(args):
            artifact_path = args[i + 1]
            i += 2
        elif args[i] == "--env" and i + 1 < len(args):
            environment = args[i + 1]
            i += 2
        else:
            return {"status": "error", "error": f"Unknown argument: {args[i]}"}

    if not profile_name:
        return {"status": "error", "error": "--profile is required"}
    if not artifact_path:
        return {"status": "error", "error": "--artifact is required"}

    from pupyteer.server.evasion.runner import EvasionTestRunner, RunnerConfig

    engine = tui._engine

    runner_config = RunnerConfig(auto_obfuscate=False)
    runner = EvasionTestRunner(engine.config, engine.audit, runner_config)
    await runner.initialize()

    try:
        result = await runner.run_with_profile(
            profile_name, artifact_path, environment=environment
        )
        return {"status": "ok", "result": result.to_dict()}
    finally:
        await runner.shutdown()


COMMANDS = {
    "evasion_status": evasion_status,
    "evasion_run": evasion_run,
    "evasion_list": evasion_list,
    "evasion_stats": evasion_stats,
    "evasion_profiles": evasion_profiles,
    "evasion_runner": evasion_runner,
}
