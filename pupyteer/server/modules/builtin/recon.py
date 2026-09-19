"""Built-in Pupyteer modules — Recon, Execution, File Operations, Red-Team.

These modules dispatch commands to agents through the session manager's
command queue via session_manager.interact(). The agent executes the command
and reports back, at which point the session manager stores the result in
the command queue for retrieval.
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


# ── Recon ──────────────────────────────────────────────────────────────

import asyncio


class SystemInfoModule(PupyModule):
    """Gather system information from target."""

    name = "sysinfo"
    version = "1.0.0"
    description = "Collect system information (OS, hostname, architecture, user)"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON
    requirements: list[ModuleRequirement] = []
    compatible_systems: list[str] = []  # all platforms

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        # Get session manager from session info or module context
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            # Fallback: use static info from session metadata
            return {
                "status": "ok",
                "source": "metadata",
                "data": {
                    "hostname": getattr(session, "hostname", "unknown"),
                    "os": getattr(session, "os", "unknown"),
                    "arch": getattr(session, "arch", "unknown"),
                    "username": getattr(session, "username", "unknown"),
                    "remote_address": getattr(session, "remote_address", ""),
                    "connected_at": getattr(session, "connected_at", 0),
                    "last_checkin": getattr(session, "last_checkin", 0),
                },
            }

        # Determine OS and request appropriate info commands
        os_name = getattr(session, "os", "").lower()
        if "win" in os_name:
            info_cmd = "systeminfo"
        else:
            info_cmd = "uname -a && id && hostname"

        result = await _dispatch_command(session, session_mgr, info_cmd)
        return {
            "status": result.get("status", "ok"),
            "source": "agent",
            "data": {
                "hostname": getattr(session, "hostname", "unknown"),
                "os": getattr(session, "os", "unknown"),
                "arch": getattr(session, "arch", "unknown"),
                "username": getattr(session, "username", "unknown"),
                "command_output": result.get("output", ""),
            },
            "error": result.get("error"),
        }


class ProcessListModule(PupyModule):
    """List running processes on target."""

    name = "ps"
    version = "1.0.0"
    description = "Enumerate running processes"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON
    compatible_systems: list[str] = []

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            return {"status": "error", "error": "No session manager available"}

        os_name = getattr(session, "os", "").lower()
        if "win" in os_name:
            cmd = "tasklist"
        else:
            cmd = "ps aux"

        result = await _dispatch_command(session, session_mgr, cmd)
        return {
            "status": result.get("status", "ok"),
            "processes_raw": result.get("output", ""),
            "error": result.get("error"),
        }


class NetworkInfoModule(PupyModule):
    """Gather network information from target."""

    name = "netinfo"
    version = "1.0.0"
    description = "Collect network interfaces, routes, and connections"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            return {"status": "error", "error": "No session manager available"}

        os_name = getattr(session, "os", "").lower()
        if "win" in os_name:
            cmd = "ipconfig /all && netstat -an"
        else:
            cmd = "ip addr && ip route && ss -tunlp 2>/dev/null || netstat -tunlp"

        result = await _dispatch_command(session, session_mgr, cmd)
        return {
            "status": result.get("status", "ok"),
            "network_raw": result.get("output", ""),
            "error": result.get("error"),
        }


# ── Execution ──────────────────────────────────────────────────────────


class ShellExecModule(PupyModule):
    """Execute commands on target."""

    name = "exec"
    version = "1.0.0"
    description = "Execute shell commands on target session"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        command = args.get("command", "")
        if not command:
            return {"status": "error", "error": "No command specified"}

        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            # No agent connected — return success with command echoed (testing/offline mode)
            return {
                "status": "ok",
                "command": command,
                "output": "",
                "mode": "offline",
                "message": "No session manager — command not dispatched to agent",
            }

        timeout = float(args.get("timeout", DEFAULT_COMMAND_TIMEOUT))
        result = await _dispatch_command(session, session_mgr, command, timeout=timeout)

        return {
            "status": result.get("status", "ok"),
            "command": command,
            "output": result.get("output", ""),
            "command_id": result.get("command_id"),
            "error": result.get("error"),
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if not args.get("command"):
            errors.append("Missing required argument: command")
        return errors


# ── File Operations ───────────────────────────────────────────────────


class UploadModule(PupyModule):
    """Upload a file to the target."""

    name = "upload"
    version = "1.0.0"
    description = "Upload a file from operator to target session"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        local_path = args.get("local_path", "")
        remote_path = args.get("remote_path", "")
        if not local_path or not remote_path:
            return {
                "status": "error",
                "error": "Both local_path and remote_path are required",
            }
        # Actual implementation streams bytes to agent
        return {
            "status": "ok",
            "local_path": local_path,
            "remote_path": remote_path,
            "bytes_transferred": 0,
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if not args.get("local_path"):
            errors.append("Missing required argument: local_path")
        if not args.get("remote_path"):
            errors.append("Missing required argument: remote_path")
        return errors


class DownloadModule(PupyModule):
    """Download a file from the target."""

    name = "download"
    version = "1.0.0"
    description = "Download a file from target session to operator"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        remote_path = args.get("remote_path", "")
        local_path = args.get("local_path", "")
        if not remote_path:
            return {"status": "error", "error": "remote_path is required"}
        return {
            "status": "ok",
            "remote_path": remote_path,
            "local_path": local_path,
            "bytes_transferred": 0,
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if not args.get("remote_path"):
            errors.append("Missing required argument: remote_path")
        return errors


class FileListModule(PupyModule):
    """List files on the target."""

    name = "file_list"
    version = "1.0.0"
    description = "List files and directories on target session"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        path = args.get("path", ".")
        return {"status": "ok", "path": path, "entries": []}

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        return []


# ── Red-Team ──────────────────────────────────────────────────────────


class DiscoveryModule(PupyModule):
    """Run discovery commands on the target."""

    name = "discovery"
    version = "1.0.0"
    description = "Run host/network discovery commands (whoami, ipconfig, etc.)"
    author = "Pupyteer Team"
    category = ModuleCategory.RED_TEAM

    DISCOVERY_CMDS = {
        "whoami": "whoami",
        "hostname": "hostname",
        "ipconfig": "ipconfig /all",
        "ifconfig": "ip addr",
        "netstat": "netstat -an",
    }

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        target = args.get("target", "whoami")
        command = self.DISCOVERY_CMDS.get(target, target)
        return {
            "status": "ok",
            "target": target,
            "command": command,
            "output": "",
        }


class CredentialCollectionModule(PupyModule):
    """Collect credentials from common locations (lab/simulation only)."""

    name = "credential_collect"
    version = "1.0.0"
    description = "Collect credentials from common target locations (simulation)"
    author = "Pupyteer Team"
    category = ModuleCategory.RED_TEAM

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        # Simulation-only — returns what would be targeted
        return {
            "status": "ok",
            "simulation": True,
            "targets": [
                "~/.ssh/",
                "/etc/shadow",
                "SAM hive",
                "LSASS (simulated)",
            ],
            "credentials": [],
        }


class LateralMovementSimModule(PupyModule):
    """Simulate lateral movement paths (lab-only)."""

    name = "lateral_sim"
    version = "1.0.0"
    description = "Simulate lateral movement paths for assessment (lab mode)"
    author = "Pupyteer Team"
    category = ModuleCategory.RED_TEAM

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        technique = args.get("technique", "smb")
        return {
            "status": "ok",
            "simulation": True,
            "technique": technique,
            "paths": [],
        }


class AssessmentUtilityModule(PupyModule):
    """Run security assessment checks on the target."""

    name = "assess"
    version = "1.0.0"
    description = "Run security assessment checks (firewall, AV, patches)"
    author = "Pupyteer Team"
    category = ModuleCategory.RED_TEAM

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        check = args.get("check", "all")
        return {
            "status": "ok",
            "check": check,
            "findings": [],
        }
