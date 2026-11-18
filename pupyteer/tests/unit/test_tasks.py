"""The task queue dispatches, and survives a cancellation.

`_execute` used to sleep for 0.1s and report "Task <name> completed" no matter
what the task said, so a queued tasking always looked successful and never ran.
Cancelling one task also killed its worker outright, so a pool of five could
drain to zero over a session.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.tasks.manager import TaskManager, TaskState


class _Audit:
    def __init__(self):
        self.events = []

    def log_event(self, *args, **kwargs):
        self.events.append(args[0] if args else None)


class _Executor:
    """Stands in for ModuleExecutor; records what it was asked to run."""

    def __init__(self, gate: asyncio.Event | None = None):
        self.calls = []
        self._gate = gate

    async def execute_module(self, module, session_id, args):
        self.calls.append((module, session_id, dict(args)))
        if self._gate is not None and module == "slow":
            await self._gate.wait()
        if module == "boom":
            return {"status": "error", "error": "module refused"}
        return {"status": "ok", "module": module}


async def _await_terminal(tm, task_id, timeout=5.0):
    """Wait for a task to finish, not merely to exist."""
    terminal = (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED)
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = await tm.get(task_id)
        if task is not None and task.state in terminal:
            return task
        await asyncio.sleep(0.05)
    return None


@pytest.fixture
def audit():
    return _Audit()


@pytest.mark.asyncio
async def test_a_task_runs_through_the_module_executor(audit):
    executor = _Executor()
    tm = TaskManager(ConfigManager(), None, audit, executor=executor)
    await tm.initialize()
    try:
        task_id = await tm.create("recon", module="sysinfo", session_id="s1",
                                  args={"path": "."})
        done = await _await_terminal(tm, task_id)
        assert done.state is TaskState.COMPLETED, done
        assert executor.calls == [("sysinfo", "s1", {"path": "."})], executor.calls
    finally:
        await tm.shutdown()


@pytest.mark.asyncio
async def test_a_module_error_fails_the_task(audit):
    """A refusal from the module is a failure, not a completed task."""
    tm = TaskManager(ConfigManager(), None, audit, executor=_Executor())
    await tm.initialize()
    try:
        task_id = await tm.create("bad", module="boom", session_id="s1")
        done = await _await_terminal(tm, task_id)
        assert done.state is TaskState.FAILED, done
        assert "module refused" in str(done.result)
    finally:
        await tm.shutdown()


@pytest.mark.asyncio
async def test_a_task_with_no_session_fails_and_says_why(audit):
    """It used to complete with "ok" and a message naming nothing."""
    executor = _Executor()
    tm = TaskManager(ConfigManager(), None, audit, executor=executor)
    await tm.initialize()
    try:
        task_id = await tm.create("nowhere", module="sysinfo")
        done = await _await_terminal(tm, task_id)
        assert done.state is TaskState.FAILED, done
        assert "no session" in str(done.result)
        assert executor.calls == [], "nothing ran for a sessionless task"
        assert "task_failed" in audit.events, audit.events
    finally:
        await tm.shutdown()


@pytest.mark.asyncio
async def test_cancelling_a_task_does_not_kill_its_worker(audit):
    """One `tasks cancel` used to take a worker down for good."""
    gate = asyncio.Event()
    executor = _Executor(gate=gate)
    tm = TaskManager(ConfigManager(), None, audit, executor=executor)
    tm._max_concurrent = 1
    await tm.initialize()
    try:
        slow = await tm.create("slow", module="slow", session_id="s1")
        await asyncio.sleep(0.1)          # let the single worker pick it up
        assert await tm.cancel(slow) is True

        fast = await tm.create("fast", module="fast", session_id="s1")
        done = await _await_terminal(tm, fast)
        assert done.state is TaskState.COMPLETED, (
            "the worker died with the task it was cancelling")

        assert await tm.get(slow) is not None
        gate.set()
    finally:
        gate.set()
        await tm.shutdown()


def test_cleanup_finished_drops_old_records(audit):
    tm = TaskManager(ConfigManager(), None, audit, executor=_Executor())
    old = type(tm._tasks).__name__  # sanity: dict
    assert old == "dict"
    from pupyteer.server.tasks.manager import TaskInfo
    tm._tasks["old"] = TaskInfo(task_id="old", name="n",
                                state=TaskState.COMPLETED,
                                completed_at=time.time() - 7200)
    tm._tasks["new"] = TaskInfo(task_id="new", name="n",
                                state=TaskState.COMPLETED,
                                completed_at=time.time())
    tm._tasks["live"] = TaskInfo(task_id="live", name="n",
                                 state=TaskState.RUNNING)
    assert tm.cleanup_finished(max_age_seconds=3600) == 1
    assert sorted(tm._tasks) == ["live", "new"]
