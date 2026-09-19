"""Session management commands for Pupyteer TUI.

Provides MSF-style session interaction:
- sessions list — List all active sessions
- sessions interact <id> — Interactive session shell
- sessions results <id> — Output of commands the agent already answered
- sessions download <id> <remote> [local] — Pull a file off the target
- sessions upload <id> <local> <remote> — Push a file to the target
- sessions kill <id> — Kill session
- sessions info <id> — Session details
- sessions rename <id> <name> — Relabel a session for operators
- sessions tag <id> <tag> — Tag a session
- sessions search <query> — Search sessions
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
            if not cmd_id:
                tui.render_error("Failed to queue command.")
                continue
            output = await _await_command_result(
                tui._engine, session_id, cmd_id, timeout=interaction_timeout(tui)
            )
            if output is None:
                tui.render_warning(
                    f"Command queued (id: {cmd_id}) — no reply yet. The agent "
                    f"picks commands up on its next check-in; "
                    f"'sessions results {session_id}' shows it later."
                )
            else:
                _print_result(output)
        except (EOFError, KeyboardInterrupt):
            break

    print("  Interaction ended.")
    return {"status": "ok", "session_id": session_id}


async def sessions_download(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Pull a file off the target, in chunks, and save it locally.

    Usage: sessions download <id> <remote-path> [local-path]

    fs_get on its own prints base64 into the terminal, which is useless for
    anything but a small text file; this reassembles the pieces to disk.
    """
    import base64
    import json
    import os

    if len(args) < 2:
        tui.render_error("Usage: sessions download <id> <remote> [local]")
        return {"status": "error", "error": "Usage: sessions download <id> <remote> [local]"}

    session_id, remote = args[0], args[1]
    local = args[2] if len(args) > 2 else os.path.join(
        ".", "downloads", os.path.basename(remote.replace("\\", "/").rstrip("/")) or "downloaded_file"
    )

    engine = tui._engine
    if await engine.sessions.get(session_id) is None:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    timeout = interaction_timeout(tui)
    chunk_size = 512 * 1024
    offset = 0
    total = -1
    parent = os.path.dirname(os.path.abspath(local))
    os.makedirs(parent, exist_ok=True)

    # Written incrementally: a target-side file can be larger than the
    # operator's memory, and each chunk is already on the wire.
    with open(local, "wb") as sink:
        while True:
            line = json.dumps({"action": "fs_get", "path": remote,
                               "offset": offset, "length": chunk_size})
            raw = await _run_agent_command(engine, session_id, line, timeout)
            if raw is None:
                tui.render_error("Agent did not answer the download request (still beacons?).")
                return {"status": "error", "error": "download timed out"}
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                tui.render_error(f"Agent returned an unreadable chunk: {raw[:200]}")
                return {"status": "error", "error": "unreadable chunk"}
            if "error" in payload:
                tui.render_error(f"Download failed: {payload['error']}")
                return {"status": "error", "error": payload["error"]}

            data = base64.b64decode(payload.get("data", ""))
            if not data:
                break
            sink.write(data)
            total = payload.get("size", -1)
            offset += len(data)
            if payload.get("eof") or (total >= 0 and offset >= total):
                break
            tui.render_success(f"  {offset}/{total} bytes")

    tui.render_success(f"Saved {offset} bytes to {local}")
    return {"status": "ok", "session_id": session_id, "local": local, "bytes": offset}


async def sessions_upload(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Push a local file to the target in offset chunks.

    Usage: sessions upload <id> <local-path> <remote-path>
    """
    import base64
    import json
    import os

    if len(args) < 3:
        tui.render_error("Usage: sessions upload <id> <local> <remote>")
        return {"status": "error", "error": "Usage: sessions upload <id> <local> <remote>"}

    session_id, local, remote = args[0], args[1], args[2]
    engine = tui._engine
    if await engine.sessions.get(session_id) is None:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}
    if not os.path.isfile(local):
        tui.render_error(f"Local file not found: {local}")
        return {"status": "error", "error": f"Local file not found: {local}"}

    timeout = interaction_timeout(tui)
    chunk_size = 512 * 1024
    size = os.path.getsize(local)
    offset = 0

    with open(local, "rb") as fh:
        while True:
            data = fh.read(chunk_size)
            if not data:
                break
            task = {
                "action": "fs_put",
                "path": remote,
                "offset": offset,
                "data": base64.b64encode(data).decode(),
            }
            raw = await _run_agent_command(
                engine, session_id, json.dumps(task), timeout
            )
            if raw is None:
                tui.render_error("Agent did not answer the upload request.")
                return {"status": "error", "error": "upload timed out"}
            try:
                reply = json.loads(raw)
            except json.JSONDecodeError:
                tui.render_error(f"Agent returned an unreadable reply: {raw[:200]}")
                return {"status": "error", "error": "unreadable reply"}
            if not reply.get("ok"):
                tui.render_error(f"Upload failed: {reply.get('error', 'unknown')}")
                return {"status": "error", "error": reply.get("error", "upload refused")}
            offset += len(data)
            tui.render_success(f"  {offset}/{size} bytes")

    tui.render_success(f"Uploaded {offset} bytes to {remote}")
    return {"status": "ok", "session_id": session_id, "remote": remote, "bytes": offset}


async def _run_agent_command(engine: Any, session_id: str, command: str, timeout: float) -> Optional[str]:
    """Queue one command and wait for the agent's answer."""
    command_id = await engine.sessions.interact(session_id, command)
    if not command_id:
        return None
    return await _await_command_result(engine, session_id, command_id, timeout)


def interaction_timeout(tui: Any) -> float:
    """How long to wait for a beacon that has not checked in yet."""
    try:
        configured = float(tui._engine.config.get("session.interact_timeout", 120))
    except Exception:
        configured = 120.0
    return configured if configured > 0 else 120.0


async def _await_command_result(
    engine: Any, session_id: str, command_id: str, timeout: float
) -> Optional[str]:
    """Poll the session queue until the agent reports this command back.

    Returns None if the deadline passes first — the agent may simply be
    between beacons, which is not an error.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        for entry in await engine.sessions.get_pending_commands(session_id):
            if entry.get("command_id") != command_id:
                continue
            if entry.get("status") == "completed":
                return entry.get("result") or ""
        await asyncio.sleep(0.25)
    return None


def _print_result(output: str) -> None:
    print()
    for line in (output or "").splitlines() or [""]:
        print(f"    {line}")
    print()


async def sessions_results(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show command output the agent has already reported for a session.

    Usage: sessions results <id> [--last N]
    """
    if not args:
        tui.render_error("Usage: sessions results <id> [--last N]")
        return {"status": "error", "error": "Usage: sessions results <id>"}

    session_id = args[0]
    last = 10
    if "--last" in args:
        try:
            last = int(args[args.index("--last") + 1])
        except (ValueError, IndexError):
            tui.render_error("Invalid --last value")
            return {"status": "error", "error": "Invalid --last"}

    session = await tui._engine.sessions.get(session_id)
    if not session:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    queue = await tui._engine.sessions.get_pending_commands(session_id)
    entries = queue[-last:] if last > 0 else queue
    if not entries:
        tui.render_warning(f"No commands recorded for session {session_id}.")
        return {"status": "ok", "session_id": session_id, "results": []}

    print(f"\n  Session {session_id} — {len(entries)} command(s):\n")
    for entry in entries:
        status = entry.get("status", "?")
        print(f"    [{entry.get('command_id', '?')}] ({status}) {entry.get('command', '')}")
        if status == "completed":
            for line in (entry.get("result") or "").splitlines():
                print(f"        {line}")
            if not (entry.get("result") or "").strip():
                print("        (no output)")
    print()
    return {
        "status": "ok",
        "session_id": session_id,
        "results": [dict(e) for e in entries],
    }


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
        tui.render_success(
            f"Session {session_id} killed — exit ordered; the agent stops on its "
            f"next check-in."
        )
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


async def sessions_rename(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Rename a session's operator-visible hostname label.

    Usage: sessions rename <id> <name>
    """
    if len(args) < 2:
        tui.render_error("Usage: sessions rename <id> <name>")
        return {"status": "error", "error": "Usage: sessions rename <id> <name>"}

    session_id, new_name = args[0], " ".join(args[1:])
    if await tui._engine.sessions.get(session_id) is None:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    if not await tui._engine.sessions.rename(session_id, new_name):
        tui.render_error(f"Rename failed for session: {session_id}")
        return {"status": "error", "error": "Rename failed"}

    tui.render_success(f"Session {session_id} renamed to '{new_name}'")
    return {"status": "ok", "session_id": session_id, "name": new_name}


async def sessions_tag(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Add tags to a session.

    Usage: sessions tag <id> <tag> [tag...]
    """
    if len(args) < 2:
        tui.render_error("Usage: sessions tag <id> <tag> [tag...]")
        return {"status": "error", "error": "Usage: sessions tag <id> <tag>"}

    session_id = args[0]
    tags = args[1:]
    if await tui._engine.sessions.get(session_id) is None:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    if not await tui._engine.sessions.tag(session_id, tags):
        tui.render_error(f"Tagging failed for session: {session_id}")
        return {"status": "error", "error": "Tagging failed"}

    session = await tui._engine.sessions.get(session_id)
    shown = ", ".join(session.tags) if session else ", ".join(tags)
    tui.render_success(f"Tags on {session_id}: {shown}")
    return {"status": "ok", "session_id": session_id, "tags": tags}


async def sessions_search(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Search sessions by hostname, user, OS or tag.

    Usage: sessions search <query>
    """
    if not args:
        tui.render_error("Usage: sessions search <query>")
        return {"status": "error", "error": "Usage: sessions search <query>"}

    query = " ".join(args)
    matches = await tui._engine.sessions.search(query)

    if not matches:
        tui.render_warning(f"No sessions matching '{query}'.")
        return {"status": "ok", "query": query, "count": 0, "sessions": []}

    headers = ["ID", "Hostname", "OS", "User", "Status", "Tags"]
    rows = [
        [s.session_id[:12], s.hostname[:20], s.os[:10], s.username[:12], s.state.value, ", ".join(s.tags[:3])]
        for s in matches
    ]
    tui.render_table(headers, rows)
    print(f"\n  {len(matches)} session(s) matching '{query}'")
    return {"status": "ok", "query": query, "count": len(matches), "sessions": [s.to_dict() for s in matches]}


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

    registry = tui._engine.module_registry

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
    "sessions rename": sessions_rename,
    "sessions tag": sessions_tag,
    "sessions search": sessions_search,
    "sessions route": sessions_route,
}
