"""Task Manager — Async task queue and tracking for Pupyteer."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger

logger = logging.getLogger("pupyteer.tasks")


class TaskState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskInfo:
    """Metadata for a queued or running task."""
    task_id: str
    name: str
    state: TaskState = TaskState.QUEUED
    session_id: Optional[str] = None
    module: str = ""
    args: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    progress: float = 0.0  # 0.0 to 1.0

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "state": self.state.value,
            "session_id": self.session_id,
            "module": self.module,
            "args": self.args,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "progress": self.progress,
            "duration_seconds": self.duration_seconds,
        }


class TaskManager:
    """
    Asynchronous task queue with lifecycle management:
    - Queue tasks for execution on target sessions
    - Track progress, results, and failures
    - Support concurrent execution with configurable concurrency limit
    - Cancel running tasks
    """

    def __init__(self, config: ConfigManager, sessions: Any, audit: AuditLogger):
        self._config = config
        self._sessions = sessions
        self._audit = audit
        self._tasks: Dict[str, TaskInfo] = {}
        self._queue: asyncio.Queue = asyncio.Queue()
        self._workers: List[asyncio.Task] = []
        self._running: Dict[str, asyncio.Task] = {}  # task_id -> asyncio.Task
        self._max_concurrent: int = int(config.get("tasks.max_concurrent", 5))
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Start worker coroutines."""
        for i in range(self._max_concurrent):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self._workers.append(worker)
        logger.info("Task manager initialized (%d workers)", self._max_concurrent)

    async def shutdown(self) -> None:
        """Cancel all workers and running tasks."""
        for task in self._running.values():
            task.cancel()
        for worker in self._workers:
            worker.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        self._running.clear()
        logger.info("Task manager stopped")

    # ------------------------------------------------------------------ #
    #  Task CRUD                                                          #
    # ------------------------------------------------------------------ #

    async def create(
        self,
        name: str,
        module: str = "",
        session_id: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create and queue a new task."""
        task_id = str(uuid.uuid4())[:12]
        task = TaskInfo(
            task_id=task_id,
            name=name,
            module=module,
            session_id=session_id,
            args=args or {},
            created_at=time.time(),
        )
        async with self._lock:
            self._tasks[task_id] = task
        await self._queue.put(task_id)
        self._audit.log_event(
            "task_created",
            {"task_id": task_id, "name": name, "module": module, "session_id": session_id},
            session=session_id,
        )
        return task_id

    async def get(self, task_id: str) -> Optional[TaskInfo]:
        """Retrieve task info."""
        return self._tasks.get(task_id)

    async def cancel(self, task_id: str) -> bool:
        """Cancel a queued or running task."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        if task.state == TaskState.QUEUED:
            task.state = TaskState.CANCELLED
            task.completed_at = time.time()
            return True
        if task.state == TaskState.RUNNING and task_id in self._running:
            self._running[task_id].cancel()
            return True
        return False

    async def list_all(self) -> List[TaskInfo]:
        """Return all tasks."""
        return list(self._tasks.values())

    async def list_by_state(self, state: TaskState) -> List[TaskInfo]:
        """Filter tasks by state."""
        return [t for t in self._tasks.values() if t.state == state]

    async def list_by_session(self, session_id: str) -> List[TaskInfo]:
        """Filter tasks by session."""
        return [t for t in self._tasks.values() if t.session_id == session_id]

    def count(self) -> int:
        return len(self._tasks)

    # ------------------------------------------------------------------ #
    #  Workers                                                            #
    # ------------------------------------------------------------------ #

    async def _worker(self, name: str) -> None:
        """Worker that pulls tasks from the queue and executes them."""
        logger.debug("Task worker %s started", name)
        while True:
            try:
                task_id = await self._queue.get()
                task = self._tasks.get(task_id)
                if not task or task.state == TaskState.CANCELLED:
                    self._queue.task_done()
                    continue

                task.state = TaskState.RUNNING
                task.started_at = time.time()

                exec_task = asyncio.create_task(self._execute(task))
                self._running[task_id] = exec_task
                await exec_task
                self._running.pop(task_id, None)

                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Worker %s error: %s", name, exc)

    async def _execute(self, task: TaskInfo) -> None:
        """Execute a single task (placeholder — dispatches to module system)."""
        try:
            # Simulated execution — in production, dispatches to actual module
            await asyncio.sleep(0.1)
            task.progress = 1.0
            task.state = TaskState.COMPLETED
            task.completed_at = time.time()
            task.result = {"status": "ok", "message": f"Task {task.name} completed"}
            self._audit.log_event(
                "task_completed",
                {"task_id": task.task_id, "name": task.name, "module": task.module},
                session=task.session_id,
                result="success",
            )
        except asyncio.CancelledError:
            task.state = TaskState.CANCELLED
            task.completed_at = time.time()
        except Exception as exc:
            task.state = TaskState.FAILED
            task.error = str(exc)
            task.completed_at = time.time()
            self._audit.log_event(
                "task_failed",
                {"task_id": task.task_id, "name": task.name, "error": str(exc)},
                session=task.session_id,
                result="error",
            )
            logger.error("Task %s failed: %s", task.task_id, exc)
