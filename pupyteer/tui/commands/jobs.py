"""Job management commands for Pupyteer TUI.

Provides MSF-style job interaction:
- jobs list — List running jobs
- jobs kill <id> — Kill job
- jobs info <id> — Job details
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pupyteer.tui.commands.jobs")


async def jobs_list(tui: Any, args: List[str]) -> Dict[str, Any]:
    """List running jobs.

    Usage: jobs list
    """
    tasks = await tui._engine.tasks.list_all()

    if not tasks:
        tui.render_warning("No jobs.")
        return {"status": "ok", "count": 0, "jobs": []}

    headers = ["ID", "Name", "State", "Session", "Module", "Progress"]
    rows = []
    for t in tasks:
        rows.append([
            t.task_id[:12],
            t.name[:25],
            t.state.value,
            (t.session_id or "-")[:12],
            t.module[:15],
            f"{t.progress:.0%}",
        ])

    tui.render_table(headers, rows)
    print(f"\n  Total: {len(tasks)} jobs")
    return {"status": "ok", "count": len(tasks), "jobs": [t.to_dict() for t in tasks]}


async def jobs_kill(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Kill a job.

    Usage: jobs kill <id>
    """
    if not args:
        tui.render_error("Usage: jobs kill <id>")
        return {"status": "error", "error": "Usage: jobs kill <id>"}

    task_id = args[0]
    ok = await tui._engine.tasks.cancel(task_id)

    if ok:
        tui.render_success(f"Job {task_id} killed.")
        return {"status": "ok", "task_id": task_id}
    else:
        tui.render_error(f"Job not found: {task_id}")
        return {"status": "error", "error": f"Job not found: {task_id}"}


async def jobs_info(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show job details.

    Usage: jobs info <id>
    """
    if not args:
        tui.render_error("Usage: jobs info <id>")
        return {"status": "error", "error": "Usage: jobs info <id>"}

    task_id = args[0]
    task = await tui._engine.tasks.get(task_id)

    if not task:
        tui.render_error(f"Job not found: {task_id}")
        return {"status": "error", "error": f"Job not found: {task_id}"}

    d = task.to_dict()
    print(f"\n  Job Details:")
    for key, val in d.items():
        print(f"    {key}: {val}")

    return {"status": "ok", "job": d}


# ─── Command Mapping ─────────────────────────────────────────────────

COMMANDS: Dict[str, Any] = {
    "jobs list": jobs_list,
    "jobs kill": jobs_kill,
    "jobs info": jobs_info,
}
