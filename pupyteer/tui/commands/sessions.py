"""Session management commands for Pupyteer TUI.

Provides MSF-style session interaction:
- sessions list — List all active sessions
- sessions interact <id> — Interactive session shell
- sessions kill <id> — Kill session
- sessions info <id> — Session details
- sessions route <id> <module> — Run module on session
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from pupyteer.server.sessions.manager import SessionState

logger = logging.getLogger("pupyteer.tui.commands.sessions")


async def sessions_list(tui: Any, args: List[str]) -> Dict[str, Any]:
    """List all active sessions.

    Usage: sessions list
    """
    sessions = await tui._engine.sessions.list_all()

    if not sessions:
        tui.render_warning("No active sessions.")
        return {"status": "ok", "count": 0, "sessions": []}

    headers = ["ID", "Hostname", "OS", "Arch", "User", "Status", "Check-in", "Profile", "Tags"]
    rows = []
    for s in sessions:
        last_checkin = time.strftime("%H:%M:%S", time.localtime(s.last_checkin)) if s.last_checkin else "-"
        rows.append([
            s.session_id[:12],
            s.hostname[:18],
            s.os[:10],
            s.arch[:8],
            s.username[:12],
            s.state.value,
            last_checkin,
            s.profile[:12],
            ", ".join(s.tags[:3]),
        ])

    tui.render_table(headers, rows)
    print(f"\n  Total: {len(sessions)} sessions")
    return {"status": "ok", "count": len(sessions), "sessions": [s.to_dict() for s in sessions]}


async def sessions_interact(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Interactive session shell.

    Usage: sessions interact <id>
    """
    if not args:
        tui.render_error("Usage: sessions interact <id>")
        return {"status": "error", "error": "Usage: sessions interact <id>"}

    session_id = args[0]
    session = await tui._engine.sessions.get(session_id)

    if not session:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    if session.state.value != "connected":
        tui.render_warning(f"Session is {session.state.value} — cannot interact.")
        return {"status": "error", "error": f"Session is {session.state.value}"}

    theme = tui._theme
    print(f"\n  Interacting with session {session.session_id[:12]} ({session.hostname})")
    print(f"  Type 'exit' to end, 'help' for commands.\n")

    while True:
        try:
            prompt = f"  [{session.session_id[:4]}] > "
            cmd_line = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input(prompt)
            )
            cmd_line = cmd_line.strip()
            if not cmd_line:
                continue
            if cmd_line.lower() in ("exit", "quit"):
                break
            if cmd_line.lower() == "help":
                print("  Commands: help, exit, status, <command>")
                continue
            if cmd_line.lower() == "status":
                s = await tui._engine.sessions.get(session_id)
                if s:
                    print(f"    Status: {s.state.value} | Last check-in: {time.strftime('%H:%M:%S', time.localtime(s.last_checkin))}")
                continue

            cmd_id = await tui._engine.sessions.interact(session_id, cmd_line)
            if cmd_id:
                tui.render_success(f"Command queued (id: {cmd_id})")
            else:
                tui.render_error("Failed to queue command.")
        except (EOFError, KeyboardInterrupt):
            break

    print("  Interaction ended.")
    return {"status": "ok", "session_id": session_id}


async def sessions_kill(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Kill a session.

    Usage: sessions kill <id>
    """
    if not args:
        tui.render_error("Usage: sessions kill <id>")
        return {"status": "error", "error": "Usage: sessions kill <id>"}

    session_id = args[0]
    ok = await tui._engine.sessions.kill(session_id)

    if ok:
        tui.render_success(f"Session {session_id} killed.")
        return {"status": "ok", "session_id": session_id}
    else:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}


async def sessions_info(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show session details.

    Usage: sessions info <id>
    """
    if not args:
        tui.render_error("Usage: sessions info <id>")
        return {"status": "error", "error": "Usage: sessions info <id>"}

    session_id = args[0]
    session = await tui._engine.sessions.get(session_id)

    if not session:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    d = session.to_dict()
    theme = tui._theme
    print(f"\n  Session Details:")
    for key, val in d.items():
        print(f"    {key}: {val}")

    return {"status": "ok", "session": d}


async def sessions_route(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Run a module on a session.

    Usage: sessions route <id> <module>

    Dispatches the specified module against the given session.
    """
    if len(args) < 2:
        tui.render_error("Usage: sessions route <id> <module>")
        return {"status": "error", "error": "Usage: sessions route <id> <module>"}

    session_id = args[0]
    module_name = args[1]

    session = await tui._engine.sessions.get(session_id)
    if not session:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    # Get module registry from engine
    registry = getattr(tui._engine, '_modules_registry', None)
    if registry is None:
        from pupyteer.server.modules.registry import ModuleRegistry
        registry = ModuleRegistry(tui._engine.config, tui._engine.audit)
        registry.discover()
        tui._engine._modules_registry = registry

    # Build args from session context
    args_dict = {
        "SESSION": session_id,
        "SESSION_HOSTNAME": session.hostname,
        "SESSION_OS": session.os,
        "SESSION_ARCH": session.arch,
        "SESSION_USER": session.username,
    }

    result = await registry.execute(module_name, session, args_dict)

    if result.get("status") == "ok":
        tui.render_success(f"Module '{module_name}' executed on session {session_id}")
    else:
        tui.render_error(f"Module execution failed: {result.get('error', 'unknown')}")

    return {"status": result.get("status", "error"), "module": module_name, "session_id": session_id, "result": result}


# ─── Command Mapping ─────────────────────────────────────────────────

COMMANDS: Dict[str, Any] = {
    "sessions list": sessions_list,
    "sessions interact": sessions_interact,
    "sessions kill": sessions_kill,
    "sessions info": sessions_info,
    "sessions route": sessions_route,
}
