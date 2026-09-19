"""Pupyteer Payload Management Commands.

Provides TUI-accessible commands for payload lifecycle operations:
- Configuration → Validation → Build → Verification → Artifact Management → Controlled Deployment
"""
from __future__ import annotations

import asyncio
import sys
from typing import Any, Dict, List, Optional

from pupyteer.payloads.manager import (
    PayloadConfig,
    PayloadPlatform,
    PayloadArch,
    PayloadType,
)


async def payload_status(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show payload management system status and statistics."""
    engine = tui._engine

    stats = engine.payloads.get_stats()
    return {
        "status": "ok",
        "stats": stats,
    }


async def payload_list(tui: Any, args: List[str]) -> Dict[str, Any]:
    """List all payloads with optional filtering."""
    engine = tui._engine

    payloads = engine.payloads.list_all()
    result = []
    for p in payloads:
        result.append({
            "payload_id": p.payload_id,
            "name": p.name,
            "version": p.version,
            "platform": p.platform,
            "arch": p.arch,
            "status": p.status,
            "hash_sha256": p.hash_sha256[:16] + "..." if p.hash_sha256 else "",
            "created_at": p.created_at,
            "size_bytes": p.size_bytes,
            "operator": p.operator,
        })
    return {"status": "ok", "payloads": result, "total": len(result)}


async def payload_build(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Build a new payload.

    Args format: --name NAME --platform PLATFORM --arch ARCH --type TYPE
                 --transport TRANSPORT --host HOST --port PORT
                 [--profile PROFILE] [--expiration DAYS] [--sign] [--version VERSION]
                 [--sleep SECONDS] [--jitter PERCENT] [--persistence]
    """
    # Parse arguments
    name = ""
    platform = PayloadPlatform.WINDOWS
    arch = PayloadArch.X64
    payload_type = PayloadType.EXECUTABLE
    transport = "tcp"
    host = "127.0.0.1"
    port = 8443
    profile = "HTTPS-Standard"
    expiration_days = 0
    sign = False
    version = ""
    sleep = 60
    jitter = 20
    persistence = False

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
        elif args[i] == "--expiration" and i + 1 < len(args):
            try:
                expiration_days = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid expiration: {args[i + 1]}"}
            i += 2
        elif args[i] == "--sleep" and i + 1 < len(args):
            try:
                sleep = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid sleep: {args[i + 1]}"}
            i += 2
        elif args[i] == "--jitter" and i + 1 < len(args):
            try:
                jitter = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid jitter: {args[i + 1]}"}
            i += 2
        elif args[i] == "--persistence":
            persistence = True; i += 1
        elif args[i] == "--sign":
            sign = True; i += 1
        elif args[i] == "--version" and i + 1 < len(args):
            version = args[i + 1]; i += 2
        else:
            return {"status": "error", "error": f"Unknown argument: {args[i]}"}

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
        sleep=sleep,
        jitter=jitter,
        persistence=persistence,
    )

    engine = tui._engine

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


async def payload_info(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Get detailed info about a payload by ID.

    Args: payload_id
    """
    if not args:
        return {"status": "error", "error": "Missing payload_id argument"}

    payload_id = args[0]
    engine = tui._engine

    meta = engine.payloads.get(payload_id)
    if not meta:
        return {"status": "error", "error": f"Payload not found: {payload_id}"}

    # Get generation log
    log = engine.payloads.get_generation_log(payload_id)

    return {
        "status": "ok",
        "payload": meta.to_dict(),
        "generation_log": log,
    }


async def payload_verify(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Verify a payload's integrity.

    Args: payload_id
    """
    if not args:
        return {"status": "error", "error": "Missing payload_id argument"}

    payload_id = args[0]
    engine = tui._engine

    ok, msg = engine.payloads.verify(payload_id)
    return {
        "status": "ok" if ok else "error",
        "payload_id": payload_id,
        "verified": ok,
        "message": msg,
    }


async def payload_remove(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Remove a payload and its artifact.

    Args: payload_id
    """
    if not args:
        return {"status": "error", "error": "Missing payload_id argument"}

    payload_id = args[0]
    engine = tui._engine

    ok = engine.payloads.remove(payload_id)
    if not ok:
        return {"status": "error", "error": f"Payload not found: {payload_id}"}

    return {"status": "ok", "message": f"Payload {payload_id} removed"}


async def payload_cleanup(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Clean up old/expired payloads.

    Args: [--max-age DAYS] [--name NAME --keep N]
    """
    max_age_days = 30
    name = ""
    keep = 3

    i = 0
    while i < len(args):
        if args[i] == "--max-age" and i + 1 < len(args):
            try:
                max_age_days = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid max-age: {args[i + 1]}"}
            i += 2
        elif args[i] == "--name" and i + 1 < len(args):
            name = args[i + 1]; i += 2
        elif args[i] == "--keep" and i + 1 < len(args):
            try:
                keep = int(args[i + 1])
            except ValueError:
                return {"status": "error", "error": f"Invalid keep: {args[i + 1]}"}
            i += 2
        else:
            return {"status": "error", "error": f"Unknown argument: {args[i]}"}

    engine = tui._engine

    removed = 0
    if name:
        removed += engine.payloads.cleanup_old_versions(name, keep)
    else:
        removed += engine.payloads.cleanup(max_age_days)
    # Also mark expired
    expired = engine.payloads.mark_expired()

    return {
        "status": "ok",
        "removed": removed,
        "marked_expired": expired,
    }


async def payload_versions(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show version history for a named payload.

    Args: name
    """
    if not args:
        return {"status": "error", "error": "Missing name argument"}

    name = args[0]
    engine = tui._engine

    history = engine.payloads.get_version_history(name)
    return {"status": "ok", "name": name, "versions": history}
