"""Built-in Pupyteer modules — Recon, Execution, File Operations, Red-Team.

These modules dispatch commands to agents through the session manager's
command queue, and wait for the answer. The queue-and-wait loop, and the chunked
file transfer built on it, live in ``server.sessions.transfer`` — the same code
the operator console runs, so a module cannot report a transfer the console would
have discovered was incomplete.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict

from pupyteer.server.modules.registry import PupyModule, ModuleCategory, ModuleRequirement
from pupyteer.server.sessions import transfer


# Default timeout for waiting for agent command results
DEFAULT_COMMAND_TIMEOUT = transfer.DEFAULT_TIMEOUT


# How long a module will wait for one agent answer when the caller says nothing.
# An agent between beacons is normal, so this has to outlast the beacon interval.
def _command_timeout(args: Dict[str, Any]) -> float:
    try:
        value = float(args.get("timeout", DEFAULT_COMMAND_TIMEOUT))
    except (TypeError, ValueError):
        return DEFAULT_COMMAND_TIMEOUT
    return value if value > 0 else DEFAULT_COMMAND_TIMEOUT


def _no_agent(session: Any) -> Dict[str, Any]:
    """What a module says when it was never given a way to reach the agent.

    A module that cannot dispatch has not done the thing it is named after, so it
    fails. Returning a well-shaped empty result instead is how an operator ends up
    believing a file was uploaded.
    """
    return {
        "status": "error",
        "error": "no session manager: nothing was sent to the agent",
        "session_id": getattr(session, "session_id", ""),
    }


async def _dispatch_command(session: Any, session_mgr: Any, command: str, timeout: float = DEFAULT_COMMAND_TIMEOUT) -> Dict[str, Any]:
    """
    Send a command to an agent via session manager and wait for the result.

    Returns a dict with 'status', 'output', and 'command_id' keys.
    """
    if not session_mgr:
        return {"status": "error", "error": "No session manager available"}

    answered = await transfer.run_command(
        session_mgr, session.session_id, command, timeout=timeout)
    if answered.get("error"):
        return {"status": "error", "error": answered["error"]}
    if answered["output"] is None:
        return {
            "status": "error",
            "error": f"Command timed out after {timeout}s "
                     f"(is the agent beaconing?)",
            "command_id": answered["command_id"],
        }
    return {
        "status": "ok",
        "output": answered["output"],
        "command_id": answered["command_id"],
    }


# ── Recon ──────────────────────────────────────────────────────────────


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
            return _no_agent(session)

        timeout = _command_timeout(args)
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
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            return _no_agent(session)

        outcome = await transfer.push(
            session_mgr, session.session_id, local_path, remote_path,
            timeout=_command_timeout(args))
        if outcome["status"] != "ok":
            return {
                "status": "error",
                "error": outcome["error"],
                "local_path": local_path,
                "remote_path": remote_path,
                "bytes_transferred": outcome.get("bytes", 0),
            }
        return {
            "status": "ok",
            "local_path": local_path,
            "remote_path": remote_path,
            "bytes_transferred": outcome["bytes"],
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
        if not remote_path:
            return {"status": "error", "error": "remote_path is required"}
        local_path = args.get("local_path") or os.path.basename(
            remote_path.replace("\\", "/").rstrip("/")) or "downloaded_file"
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            return _no_agent(session)

        parent = os.path.dirname(os.path.abspath(local_path))
        os.makedirs(parent, exist_ok=True)
        # Chunked straight to disk, so a target-side file larger than the
        # operator's memory costs a file handle rather than a second copy of it.
        with open(local_path, "wb") as sink:
            outcome = await transfer.pull(
                session_mgr, session.session_id, remote_path, sink,
                timeout=_command_timeout(args))
        if outcome["status"] != "ok":
            return {
                "status": "error",
                "error": outcome["error"],
                "remote_path": remote_path,
                "local_path": local_path,
                "bytes_transferred": outcome.get("bytes", 0),
            }
        return {
            "status": "ok",
            "remote_path": remote_path,
            "local_path": local_path,
            "bytes_transferred": outcome["bytes"],
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
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "fs_list", "path": path},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"], "path": path}
        entries = reply.get("entries")
        if not isinstance(entries, list):
            return {
                "status": "error",
                "error": f"agent sent no listing for {path}: {str(reply)[:200]}",
                "path": path,
            }
        return {"status": "ok", "path": reply.get("path", path), "entries": entries}

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
        session_mgr = getattr(self, '_session_manager', None)
        if not session_mgr:
            return _no_agent(session)

        # Sent as a JSON task rather than typed text: "hostname" as a bare line is
        # the agent's own module action, and an operator asking for the shell
        # command would get the module's answer instead.
        result = await _dispatch_command(
            session, session_mgr, json.dumps({"action": "exec", "command": command,
                                              "timeout": int(_command_timeout(args))}),
            timeout=_command_timeout(args))
        return {
            "status": result.get("status", "ok"),
            "target": target,
            "command": command,
            "output": result.get("output", ""),
            "command_id": result.get("command_id"),
            "error": result.get("error"),
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
