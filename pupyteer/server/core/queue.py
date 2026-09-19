"""Async priority task queue for the Pupyteer C2 Engine.

Provides:
- Priority-aware async queue (lower number = higher priority)
- Enqueue / dequeue / peek / size / clear operations
- Queue full / empty semantics
- Priority update on existing tasks
"""
from __future__ import annotations

import asyncio
import heapq
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class TaskPriority(IntEnum):
    """Standard task priority levels (lower value = higher priority)."""

    CRITICAL = 0
    HIGH = 10
    NORMAL = 20
    LOW = 30
    BACKGROUND = 40


@dataclass(order=True)
class QueueEntry:
    """A single queue entry ordered by priority then timestamp."""

    priority: int
    created_at: float
    task_id: str = field(compare=False)
    name: str = field(compare=False)
    module: str = field(compare=False, default="")
    session_id: Optional[str] = field(compare=False, default=None)
    args: Dict[str, Any] = field(compare=False, default_factory=dict)
    payload: Dict[str, Any] = field(compare=False, default_factory=dict)


@dataclass
class TaskQueueStats:
    """Aggregate statistics for the task queue."""

    total_enqueued: int = 0
    total_dequeued: int = 0
    total_completed: int = 0
    total_failed: int = 0
    total_cancelled: int = 0
    peak_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_enqueued": self.total_enqueued,
            "total_dequeued": self.total_dequeued,
            "total_completed": self.total_completed,
            "total_failed": self.total_failed,
            "total_cancelled": self.total_cancelled,
            "peak_size": self.peak_size,
        }


class TaskQueue:
    """Async priority task queue with configurable capacity.

    Uses a min-heap under the hood so tasks dequeue in priority order.
    Ties broken by insertion time (FIFO for same priority).
    """

    def __init__(self, max_size: int = 0):
        self._heap: List[QueueEntry] = []
        self._max_size = max_size  # 0 = unlimited
        self._event = asyncio.Event()  # signals when items become available
        self._lock = asyncio.Lock()
        self._stats = TaskQueueStats()
        self._task_positions: Dict[str, int] = {}  # task_id -> heap index (approximate)

    # ── Public API ──────────────────────────────────────────────────

    async def enqueue(
        self,
        name: str,
        module: str = "",
        session_id: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        task_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add a task to the queue. Returns the task_id.

        Raises:
            asyncio.QueueFull if the queue is at capacity.
        """
        async with self._lock:
            if self._max_size and len(self._heap) >= self._max_size:
                raise asyncio.QueueFull(
                    f"Task queue full ({self._max_size} items)"
                )

            tid = task_id or self._generate_id()
            entry = QueueEntry(
                priority=int(priority),
                created_at=time.time(),
                task_id=tid,
                name=name,
                module=module,
                session_id=session_id,
                args=args or {},
                payload=payload or {},
            )
            heapq.heappush(self._heap, entry)
            self._stats.total_enqueued += 1
            self._stats.peak_size = max(self._stats.peak_size, len(self._heap))

        self._event.set()
        return tid

    async def dequeue(self, timeout: Optional[float] = None) -> Optional[QueueEntry]:
        """Remove and return the highest-priority task.

        Blocks until a task is available (or timeout).
        Returns None on timeout.
        """
        while True:
            async with self._lock:
                if self._heap:
                    entry = heapq.heappop(self._heap)
                    self._stats.total_dequeued += 1
                    # If heap is now empty, clear the event for next dequeue's wait
                    if not self._heap:
                        self._event.clear()
                    return entry

            # Wait for new items (or timeout)
            try:
                await asyncio.wait_for(self._event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return None

    async def peek(self) -> Optional[QueueEntry]:
        """Return (without removing) the highest-priority task."""
        async with self._lock:
            return self._heap[0] if self._heap else None

    async def size(self) -> int:
        """Return current number of queued tasks."""
        return len(self._heap)

    async def is_empty(self) -> bool:
        """Return True if the queue has no items."""
        return not self._heap

    async def clear(self) -> int:
        """Remove all queued tasks. Returns number removed."""
        async with self._lock:
            count = len(self._heap)
            self._heap.clear()
            self._event.clear()
            self._stats.total_cancelled += count
            return count

    async def remove(self, task_id: str) -> bool:
        """Remove a specific task by id. Returns True if found."""
        async with self._lock:
            for i, entry in enumerate(self._heap):
                if entry.task_id == task_id:
                    self._heap.pop(i)
                    heapq.heapify(self._heap)
                    self._stats.total_cancelled += 1
                    if not self._heap:
                        self._event.clear()
                    return True
        return False

    async def update_priority(self, task_id: str, new_priority: TaskPriority) -> bool:
        """Change the priority of a queued task. Returns True if found."""
        async with self._lock:
            for entry in self._heap:
                if entry.task_id == task_id:
                    entry.priority = int(new_priority)
                    heapq.heapify(self._heap)
                    return True
        return False

    async def list_tasks(self) -> List[QueueEntry]:
        """Return a copy of all queued tasks in priority order."""
        async with self._lock:
            return list(self._heap)

    async def find_by_session(self, session_id: str) -> List[QueueEntry]:
        """Return queued entries for a given session."""
        async with self._lock:
            return [e for e in self._heap if e.session_id == session_id]

    async def find_by_module(self, module: str) -> List[QueueEntry]:
        """Return queued entries for a given module."""
        async with self._lock:
            return [e for e in self._heap if e.module == module]

    def stats(self) -> TaskQueueStats:
        """Return queue statistics."""
        return self._stats

    def mark_completed(self) -> None:
        """Mark one dequeued task as completed (for stats)."""
        self._stats.total_completed += 1

    def mark_failed(self) -> None:
        """Mark one dequeued task as failed (for stats)."""
        self._stats.total_failed += 1

    # ── Private ──────────────────────────────────────────────────────

    @staticmethod
    def _generate_id() -> str:
        return str(uuid.uuid4())[:12]
