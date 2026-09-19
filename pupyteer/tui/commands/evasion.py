"""Pupyteer Evasion Testing Commands — Phase 10.

Provides command-line and TUI-accessible commands for detection-resilience testing.

Wire to TUI via app.py: evasion [status|run|list|stats|profiles|runner]
"""
from __future__ import annotations

import asyncio
import sys
from typing import Any, Dict, List, Optional

from pupyteer.server.core.engine import PupyteerEngine


async def evasion_status(args: List[str]) -> Dict[str, Any]:
    """Show evasion testing system status."""
    engine = PupyteerEngine()
    await engine.evasion.initialize()

    stats = engine.evasion.get_stats()
    result = {
        "status": "ok",
        "test_mode": engine.evasion.test_mode,
        "litterbox_configured": engine.evasion._litterbox is not None,
        "stats": stats,
    }

    await engine.evasion.shutdown()
    return result


async def evasion_run(args: List[str]) -> Dict[str, Any]:
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
            i += 1

    if not artifact_path and not profile_name:
        return {"status": "error", "error": "Missing --artifact PATH or --profile PROFILE"}

    from pupyteer.server.evasion.models import EvasionTestConfig
    from pupyteer.server.evasion.runner import EvasionTestRunner, RunnerConfig

    engine = PupyteerEngine()
    await engine.evasion.initialize()

    runner_config = RunnerConfig(auto_obfuscate=False)
    runner = EvasionTestRunner(engine.config, engine.audit, runner_config)
    await runner.initialize()

    try:
        if profile_name:
            result = await runner.run_with_profile(
                profile_name,
                artifact_path or "/dev/null",
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
        await engine.evasion.shutdown()


async def evasion_list(args: List[str]) -> Dict[str, Any]:
    """List recent evasion test results."""
    engine = PupyteerEngine()
    await engine.evasion.initialize()

    history = engine.evasion.get_history()
    results = [r.to_dict() for r in history[-20:]]

    await engine.evasion.shutdown()
    return {"status": "ok", "count": len(results), "tests": results}


async def evasion_stats(args: List[str]) -> Dict[str, Any]:
    """Show evasion test statistics."""
    engine = PupyteerEngine()
    await engine.evasion.initialize()

    stats = engine.evasion.get_stats()
    await engine.evasion.shutdown()

    return {"status": "ok", "stats": stats}


async def evasion_profiles(args: List[str]) -> Dict[str, Any]:
    """List available evasion test configuration profiles."""
    from pupyteer.server.evasion.profiles import list_profiles

    profiles = list_profiles()
    return {"status": "ok", "count": len(profiles), "profiles": profiles}


async def evasion_runner(args: List[str]) -> Dict[str, Any]:
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
            i += 1

    if not profile_name:
        return {"status": "error", "error": "--profile is required"}
    if not artifact_path:
        return {"status": "error", "error": "--artifact is required"}

    from pupyteer.server.evasion.runner import EvasionTestRunner, RunnerConfig

    engine = PupyteerEngine()
    await engine.evasion.initialize()

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
        await engine.evasion.shutdown()


COMMANDS = {
    "evasion_status": evasion_status,
    "evasion_run": evasion_run,
    "evasion_list": evasion_list,
    "evasion_stats": evasion_stats,
    "evasion_profiles": evasion_profiles,
    "evasion_runner": evasion_runner,
}
