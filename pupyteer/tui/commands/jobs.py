"""Job management commands for Pupyteer TUI.

These read from and act on the engine's ``ModuleExecutor`` job store — the same
background system that ``sessions route <id> <module> --background`` launches a
job into. An operator sees here exactly what is really running; a job listed as
completed carries the module's actual result, and one that never ran is not
silently dropped from the board.

- jobs list — List background jobs and their real status
- jobs info <id> — One job's details, including its result/error
- jobs kill <id> — Cancel a running background job
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger("pupyteer.tui.commands.jobs")


async def jobs_list(tui: Any, args: List[str]) -> Dict[str, Any]:
    """List background jobs tracked by the module executor.

    Usage: jobs list
    """
    jobs = await tui._engine.modules.list_jobs()

    if not jobs:
        tui.render_warning("No jobs.")
        return {"status": "ok", "count": 0, "jobs": []}

    headers = ["ID", "Module", "State", "Session", "Created"]
    rows = []
    for job in jobs:
        rows.append([
            job.get("job_id", "")[:12],
            job.get("module_name", "")[:20],
            job.get("status", ""),
            (job.get("session_id") or "-")[:12],
            (job.get("created_at") or "")[:19],
        ])

    tui.render_table(headers, rows)
    print(f"\n  Total: {len(jobs)} jobs")
    return {"status": "ok", "count": len(jobs), "jobs": jobs}


async def jobs_kill(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Cancel a running background job.

    Usage: jobs kill <id>
    """
    if not args:
        tui.render_error("Usage: jobs kill <id>")
        return {"status": "error", "error": "Usage: jobs kill <id>"}

    job_id = args[0]
    cancelled = await tui._engine.modules.cancel_job(job_id)

    if cancelled:
        tui.render_success(f"Job {job_id} cancelled.")
        return {"status": "ok", "job_id": job_id}

    # ``cancel_job`` reports False for both an unknown id and a job that has
    # already finished; saying "not found" for a finished job would send the
    # operator looking for a job that is plainly on the board.
    tui.render_error(f"Job not found or already finished: {job_id}")
    return {
        "status": "error",
        "error": f"Job not found or already finished: {job_id}",
    }


async def jobs_info(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show one background job's details.

    Usage: jobs info <id>
    """
    if not args:
        tui.render_error("Usage: jobs info <id>")
        return {"status": "error", "error": "Usage: jobs info <id>"}

    job_id = args[0]
    job = await tui._engine.modules.get_job(job_id)

    if not job:
        tui.render_error(f"Job not found: {job_id}")
        return {"status": "error", "error": f"Job not found: {job_id}"}

    print(f"\n  Job Details:")
    for key, val in job.items():
        print(f"    {key}: {val}")

    return {"status": "ok", "job": job}


# ─── Command Mapping ─────────────────────────────────────────────────

COMMANDS: Dict[str, Any] = {
    "jobs list": jobs_list,
    "jobs kill": jobs_kill,
    "jobs info": jobs_info,
}
