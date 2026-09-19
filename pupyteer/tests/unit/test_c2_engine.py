"""Unit tests for the C2 engine, task queue, and error handling."""
import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.errors import (
    AuthError,
    C2EngineError,
    ConfigError,
    ErrorCode,
    ProfileError,
    SessionError,
    SubsystemError,
    TaskError,
    TransportError,
)
from pupyteer.server.core.queue import QueueEntry, TaskPriority, TaskQueue, TaskQueueStats
from pupyteer.server.core.c2 import C2Engine, EnginePhase
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.core.validation import validate_engine_config
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger


# ─── Error Tests ─────────────────────────────────────────────────────


class TestC2EngineError:
    def test_basic_error(self):
        e = C2EngineError("something failed", code=ErrorCode.ENGINE_START_FAILED)
        assert e.code == ErrorCode.ENGINE_START_FAILED
        assert "something failed" in str(e)

    def test_error_to_dict(self):
        e = C2EngineError(
            "test",
            code=ErrorCode.CONFIG_VALIDATION,
            context={"key": "value"},
        )
        d = e.to_dict()
        assert d["error"] == "E1001"
        assert d["message"] == "[E1001] test (context: {'key': 'value'})"
        assert d["context"] == {"key": "value"}

    def test_error_with_cause(self):
        cause = ValueError("original")
        e = C2EngineError("wrapped", code=ErrorCode.UNKNOWN, cause=cause)
        assert e.cause is cause
        assert "original" in str(e)

    def test_error_context(self):
        e = C2EngineError("ctx test", context={"foo": "bar"})
        assert e.context == {"foo": "bar"}


class TestSubsystemError:
    def test_subsystem_error(self):
        e = SubsystemError("sessions", "init", "failed to start")
        assert e.code == ErrorCode.SUBSYSTEM_INIT_FAILED
        assert "sessions" in str(e)
        assert "init" in str(e)

    def test_subsystem_shutdown_error(self):
        e = SubsystemError("tasks", "shutdown", "timeout")
        assert e.code == ErrorCode.SUBSYSTEM_SHUTDOWN_FAILED

    def test_subsystem_context(self):
        e = SubsystemError("profiles", "init", "bad config")
        assert e.context["subsystem"] == "profiles"
        assert e.context["operation"] == "init"


class TestConfigError:
    def test_config_error(self):
        e = ConfigError("missing section")
        assert e.code == ErrorCode.CONFIG_VALIDATION


class TestSessionError:
    def test_session_error(self):
        e = SessionError("sess-123", "not found")
        assert e.code == ErrorCode.SESSION_NOT_FOUND
        assert e.context["session_id"] == "sess-123"


class TestTaskError:
    def test_task_error(self):
        e = TaskError("task-456", "not found")
        assert e.code == ErrorCode.TASK_NOT_FOUND
        assert e.context["task_id"] == "task-456"


class TestTransportError:
    def test_transport_error(self):
        e = TransportError("tcp", "bind failed")
        assert e.code == ErrorCode.TRANSPORT_INIT_FAILED
        assert e.context["transport"] == "tcp"


class TestProfileError:
    def test_profile_error(self):
        e = ProfileError("HTTPS-Standard", "not found")
        assert e.code == ErrorCode.PROFILE_NOT_FOUND
        assert e.context["profile"] == "HTTPS-Standard"


class TestAuthError:
    def test_auth_error(self):
        e = AuthError("bad password")
        assert e.code == ErrorCode.AUTH_FAILED


# ─── Task Queue Tests ────────────────────────────────────────────────


class TestTaskQueue:
    @pytest.mark.asyncio
    async def test_enqueue_dequeue(self):
        q = TaskQueue()
        tid = await q.enqueue("test-task", module="test")
        assert tid is not None
        assert await q.size() == 1
        entry = await q.dequeue(timeout=1.0)
        assert entry is not None
        assert entry.name == "test-task"
        assert entry.module == "test"

    @pytest.mark.asyncio
    async def test_priority_ordering(self):
        q = TaskQueue()
        await q.enqueue("low", priority=TaskPriority.LOW)
        await q.enqueue("critical", priority=TaskPriority.CRITICAL)
        await q.enqueue("normal", priority=TaskPriority.NORMAL)
        await q.enqueue("high", priority=TaskPriority.HIGH)

        # Should dequeue in priority order: critical, high, normal, low
        names = []
        for _ in range(4):
            entry = await q.dequeue(timeout=0.5)
            if entry:
                names.append(entry.name)
        assert names == ["critical", "high", "normal", "low"]

    @pytest.mark.asyncio
    async def test_fifo_within_same_priority(self):
        q = TaskQueue()
        await q.enqueue("first", priority=TaskPriority.NORMAL)
        await q.enqueue("second", priority=TaskPriority.NORMAL)
        await q.enqueue("third", priority=TaskPriority.NORMAL)

        names = []
        for _ in range(3):
            entry = await q.dequeue(timeout=0.5)
            if entry:
                names.append(entry.name)
        assert names == ["first", "second", "third"]

    @pytest.mark.asyncio
    async def test_peek(self):
        q = TaskQueue()
        await q.enqueue("peek-test", priority=TaskPriority.HIGH)
        entry = await q.peek()
        assert entry is not None
        assert entry.name == "peek-test"
        # Peek should not remove
        assert await q.size() == 1

    @pytest.mark.asyncio
    async def test_clear(self):
        q = TaskQueue()
        await q.enqueue("a")
        await q.enqueue("b")
        await q.enqueue("c")
        count = await q.clear()
        assert count == 3
        assert await q.is_empty()

    @pytest.mark.asyncio
    async def test_remove_by_id(self):
        q = TaskQueue()
        tid = await q.enqueue("removable")
        assert await q.remove(tid) is True
        assert await q.size() == 0

    @pytest.mark.asyncio
    async def test_remove_nonexistent(self):
        q = TaskQueue()
        assert await q.remove("no-such-id") is False

    @pytest.mark.asyncio
    async def test_update_priority(self):
        q = TaskQueue()
        tid = await q.enqueue("change-me", priority=TaskPriority.LOW)
        assert await q.update_priority(tid, TaskPriority.CRITICAL) is True
        entry = await q.peek()
        assert entry.priority == TaskPriority.CRITICAL

    @pytest.mark.asyncio
    async def test_update_priority_nonexistent(self):
        q = TaskQueue()
        assert await q.update_priority("no-such", TaskPriority.HIGH) is False

    @pytest.mark.asyncio
    async def test_find_by_session(self):
        q = TaskQueue()
        await q.enqueue("a", session_id="sess-1")
        await q.enqueue("b", session_id="sess-2")
        await q.enqueue("c", session_id="sess-1")
        results = await q.find_by_session("sess-1")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_find_by_module(self):
        q = TaskQueue()
        await q.enqueue("a", module="recon")
        await q.enqueue("b", module="exploit")
        await q.enqueue("c", module="recon")
        results = await q.find_by_module("recon")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_list_tasks(self):
        q = TaskQueue()
        await q.enqueue("a")
        await q.enqueue("b")
        tasks = await q.list_tasks()
        assert len(tasks) == 2

    @pytest.mark.asyncio
    async def test_queue_full(self):
        q = TaskQueue(max_size=2)
        await q.enqueue("a")
        await q.enqueue("b")
        with pytest.raises(asyncio.QueueFull):
            await q.enqueue("c")

    @pytest.mark.asyncio
    async def test_dequeue_timeout(self):
        q = TaskQueue()
        entry = await q.dequeue(timeout=0.1)
        assert entry is None

    @pytest.mark.asyncio
    async def test_stats(self):
        q = TaskQueue()
        await q.enqueue("a")
        await q.enqueue("b")
        await q.dequeue(timeout=0.5)
        q.mark_completed()
        stats = q.stats()
        assert stats.total_enqueued == 2
        assert stats.total_dequeued == 1
        assert stats.total_completed == 1
        assert stats.peak_size == 2

    @pytest.mark.asyncio
    async def test_custom_task_id(self):
        q = TaskQueue()
        tid = await q.enqueue("custom-id-test", task_id="my-custom-id")
        assert tid == "my-custom-id"

    @pytest.mark.asyncio
    async def test_is_empty(self):
        q = TaskQueue()
        assert await q.is_empty() is True
        await q.enqueue("a")
        assert await q.is_empty() is False


class TestTaskQueueStats:
    def test_to_dict(self):
        stats = TaskQueueStats(total_enqueued=5, peak_size=3)
        d = stats.to_dict()
        assert d["total_enqueued"] == 5
        assert d["peak_size"] == 3


# ─── C2 Engine Tests ─────────────────────────────────────────────────


class TestC2Engine:
    @pytest.mark.asyncio
    async def test_instantiation(self):
        engine = C2Engine()
        assert engine.phase == EnginePhase.INITIALIZED
        assert engine.is_running is False

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        engine = C2Engine()
        await engine.start()
        assert engine.phase == EnginePhase.RUNNING
        assert engine.is_running is True
        await engine.stop()
        assert engine.phase == EnginePhase.STOPPED

    @pytest.mark.asyncio
    async def test_double_start_is_noop(self):
        engine = C2Engine()
        await engine.start()
        await engine.start()  # Should not raise
        assert engine.is_running is True
        await engine.stop()

    @pytest.mark.asyncio
    async def test_get_status(self):
        engine = C2Engine()
        await engine.start()
        status = engine.get_status()
        assert "phase" in status
        assert status["phase"] == "running"
        assert "sessions" in status
        assert "tasks" in status
        assert "queue" in status
        assert "config" in status
        await engine.stop()

    @pytest.mark.asyncio
    async def test_health_check(self):
        engine = C2Engine()
        await engine.start()
        health = await engine.health_check()
        assert "engine" in health
        assert "healthy" in health
        assert health["engine"] is True
        await engine.stop()

    @pytest.mark.asyncio
    async def test_submit_task(self):
        engine = C2Engine()
        await engine.start()
        tid = await engine.submit_task("test", module="test_mod", session_id="s1")
        assert tid is not None
        assert await engine.queue.size() == 1
        await engine.stop()

    @pytest.mark.asyncio
    async def test_submit_task_not_running(self):
        engine = C2Engine()
        with pytest.raises(C2EngineError):
            await engine.submit_task("test")

    @pytest.mark.asyncio
    async def test_submit_task_with_priority(self):
        engine = C2Engine()
        await engine.start()
        tid = await engine.submit_task("prio-test", priority=TaskPriority.CRITICAL)
        entry = await engine.queue.peek()
        assert entry is not None
        assert entry.priority == TaskPriority.CRITICAL
        await engine.stop()

    @pytest.mark.asyncio
    async def test_error_property(self):
        engine = C2Engine()
        assert engine.error is None

    @pytest.mark.asyncio
    async def test_subsystems_accessible(self):
        engine = C2Engine()
        assert engine.sessions is not None
        assert engine.tasks is not None
        assert engine.profiles is not None
        assert engine.transports is not None
        assert engine.config is not None
        assert engine.audit is not None
        assert engine.auth is not None
        assert engine.queue is not None


# ─── PupyteerEngine (backward compat) Tests ──────────────────────────


class TestPupyteerEngine:
    @pytest.mark.asyncio
    async def test_instantiation(self):
        engine = PupyteerEngine()
        assert engine.state is not None
        assert engine.state.started is False
        assert engine.phase == EnginePhase.INITIALIZED

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        engine = PupyteerEngine()
        await engine.start()
        assert engine.state.started is True
        assert engine.is_running is True
        await engine.stop()
        assert engine.state.started is False

    @pytest.mark.asyncio
    async def test_get_status(self):
        engine = PupyteerEngine()
        await engine.start()
        status = engine.get_status()
        assert "state" in status
        assert "config" in status
        assert "profiles" in status
        assert "transports" in status
        assert status["state"]["started"] is True
        await engine.stop()

    @pytest.mark.asyncio
    async def test_submit_task(self):
        engine = PupyteerEngine()
        await engine.start()
        tid = await engine.submit_task("compat-test", module="test")
        assert tid is not None
        await engine.stop()

    @pytest.mark.asyncio
    async def test_queue_property(self):
        engine = PupyteerEngine()
        assert engine.queue is not None
        assert isinstance(engine.queue, TaskQueue)


# ─── Config Validation Tests ─────────────────────────────────────────


class TestValidateEngineConfig:
    def test_valid_config(self):
        config = ConfigManager()
        validate_engine_config(config)  # Should not raise

    def test_invalid_max_concurrent(self):
        config = ConfigManager()
        config.set("tasks.max_concurrent", 0)
        with pytest.raises(ValueError, match="tasks.max_concurrent"):
            validate_engine_config(config)

    def test_invalid_queue_size(self):
        config = ConfigManager()
        config.set("tasks.queue_size", -1)
        with pytest.raises(ValueError, match="tasks.queue_size"):
            validate_engine_config(config)

    def test_invalid_timeout(self):
        config = ConfigManager()
        config.set("session.timeout_seconds", 0)
        with pytest.raises(ValueError, match="session.timeout_seconds"):
            validate_engine_config(config)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
