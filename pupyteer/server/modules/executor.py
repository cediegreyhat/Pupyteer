"""Module Execution Engine — dispatches module commands to agents via sessions.

Connects the module system to the listener/session layer:
- Resolves modules from the registry
- Sends commands to agents through session_manager.interact()
- Tracks background jobs with asyncio.create_task
- Returns structured results for the TUI/API layer
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pupyteer.server.modules.registry import ModuleRegistry, PupyModule
from pupyteer.server.sessions.manager import SessionManager, SessionInfo, SessionState

logger = logging.getLogger("pupyteer.executor")


class JobStatus(str, Enum):
    """Status of a background module execution job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class JobRecord:
    """Tracks a background module execution."""
    job_id: str
    module_name: str
    session_id: str
    args: Dict[str, Any]
    status: JobStatus = JobStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    task: Optional[asyncio.Task] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "module_name": self.module_name,
            "session_id": self.session_id,
            "args": self.args,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
        }


class ModuleExecutor:
    """
    Dispatches module.execute() calls to agents via sessions.

    Execution flow:
    1. Resolve module from registry
    2. Look up target session from session_manager
    3. Call module.execute(session, args) — modules dispatch to agents via session_manager
    4. Return structured result dict
    """

    def __init__(
        self,
        registry: ModuleRegistry,
        session_manager: SessionManager,
        audit_logger: Any = None,
    ):
        self._registry = registry
        self._sessions = session_manager
        self._audit = audit_logger
        self._jobs: Dict[str, JobRecord] = {}
        self._job_lock = asyncio.Lock()

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def registry(self) -> ModuleRegistry:
        return self._registry

    @property
    def sessions(self) -> SessionManager:
        return self._sessions

    # ── Core execution ──────────────────────────────────────────────────

    async def execute_module(
        self, module_name: str, session_id: str, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a module against a specific session.

        Args:
            module_name: Registered module name (e.g. "exec", "sysinfo").
            session_id: Target agent session ID.
            args: Module-specific arguments.

        Returns:
            Dict with at least a ``status`` key.
        """
        # 1. Resolve module
        module = self._registry.create(module_name)
        if module is None:
            return {
                "status": "error",
                "error": f"Module not found: {module_name}",
            }

        # 2. Resolve session
        session = await self._sessions.get(session_id)
        if session is None:
            return {
                "status": "error",
                "error": f"Session not found: {session_id}",
            }

        if session.state.value != "connected":
            return {
                "status": "error",
                "error": f"Session {session_id} is not connected (state: {session.state.value})",
            }

        # 3. Validate args
        errors = module.validate_args(args)
        if errors:
            return {"status": "error", "error": "; ".join(errors)}

        # 4. Ensure module is initialized
        if not module._initialized:
            await module.initialize()

        # Inject session_manager into module for agent dispatch
        module._session_manager = self._sessions  # type: ignore[attr-defined]

        # 5. Execute
        try:
            result = await module.execute(session, args)
            # Emit audit event
            if self._audit:
                try:
                    self._audit.log_event(
                        "module_executed",
                        {
                            "module": module_name,
                            "session_id": session_id,
                            "result": result.get("status", "unknown"),
                        },
                        session=session_id,
                    )
                except Exception:
                    pass
            return result
        except Exception as exc:
            logger.exception("Module %s execution failed on session %s", module_name, session_id)
            return {"status": "error", "error": str(exc)}

    async def execute_on_all(
        self, module_name: str, args: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Execute a module on all connected sessions.

        Returns a list of result dicts, one per session.
        """
        sessions = await self._sessions.filter_by_state(SessionState.CONNECTED)
        if not sessions:
            return [{"status": "error", "error": "No connected sessions"}]

        tasks = []
        for session in sessions:
            task = self.execute_module(module_name, session.session_id, args)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            r if isinstance(r, dict) else {"status": "error", "error": str(r)}
            for r in results
        ]

    # ── Background job system ───────────────────────────────────────────

    async def execute_job(
        self, module_name: str, session_id: str, args: Dict[str, Any]
    ) -> str:
        """
        Launch a module execution as a background job.

        Returns the job_id immediately. The job runs as an asyncio.Task.
        Use get_job() or list_jobs() to poll for results.
        """
        job_id = str(uuid.uuid4())[:12]
        record = JobRecord(
            job_id=job_id,
            module_name=module_name,
            session_id=session_id,
            args=args,
        )

        async with self._job_lock:
            self._jobs[job_id] = record

        # Launch background task
        task = asyncio.create_task(self._run_job(job_id))
        record.task = task

        logger.info("Job %s started: %s on session %s", job_id, module_name, session_id)
        return job_id

    async def _run_job(self, job_id: str) -> None:
        """Internal: execute a background job and record its outcome."""
        record = self._jobs.get(job_id)
        if record is None:
            return

        record.status = JobStatus.RUNNING
        record.started_at = datetime.now(timezone.utc).isoformat()

        try:
            result = await self.execute_module(
                record.module_name, record.session_id, record.args
            )
            record.result = result
            if result.get("status") == "error":
                record.status = JobStatus.FAILED
                record.error = result.get("error", "Unknown error")
            else:
                record.status = JobStatus.COMPLETED
        except asyncio.CancelledError:
            record.status = JobStatus.CANCELLED
            record.error = "Job cancelled"
        except Exception as exc:
            record.status = JobStatus.FAILED
            record.error = str(exc)
        finally:
            record.completed_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Job %s finished: status=%s", job_id, record.status.value
        )

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get the current state of a job."""
        record = self._jobs.get(job_id)
        if record is None:
            return None
        return record.to_dict()

    async def list_jobs(
        self, status: Optional[JobStatus] = None
    ) -> List[Dict[str, Any]]:
        """List all jobs, optionally filtered by status."""
        jobs = []
        for record in self._jobs.values():
            if status is None or record.status == status:
                jobs.append(record.to_dict())
        return jobs

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a running background job."""
        record = self._jobs.get(job_id)
        if record is None:
            return False
        if record.task and not record.task.done():
            record.task.cancel()
            record.status = JobStatus.CANCELLED
            record.error = "Cancelled by operator"
            record.completed_at = datetime.now(timezone.utc).isoformat()
            return True
        return False

    async def cleanup_jobs(self, max_age_seconds: float = 3600.0) -> int:
        """
        Remove completed/failed jobs older than max_age_seconds.

        Returns the number of jobs removed.
        """
        now = time.time()
        to_remove = []
        for job_id, record in self._jobs.items():
            if record.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                if record.completed_at:
                    completed = datetime.fromisoformat(record.completed_at)
                    age = now - completed.timestamp()
                    if age > max_age_seconds:
                        to_remove.append(job_id)

        for job_id in to_remove:
            del self._jobs[job_id]

        if to_remove:
            logger.debug("Cleaned up %d old jobs", len(to_remove))
        return len(to_remove)

    async def wait_for_job(self, job_id: str, timeout: float = 60.0) -> Optional[Dict[str, Any]]:
        """
        Block until a job completes or timeout.

        Returns the final job dict, or None on timeout.
        """
        record = self._jobs.get(job_id)
        if record is None:
            return None
        if record.task:
            try:
                await asyncio.wait_for(record.task, timeout=timeout)
            except asyncio.TimeoutError:
                return record.to_dict()
        return record.to_dict()
