"""Regression tests — verifying fixed bugs don't return.

These tests exist because a bug was found and fixed. They ensure the
specific failure mode never silently returns.
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions.manager import SessionManager, SessionInfo, SessionState
from pupyteer.server.tasks.manager import TaskManager, TaskState
from pupyteer.server.profiles.manager import ProfileManager
from pupyteer.payloads.manager import PayloadConfig, PayloadPlatform, PayloadArch, PayloadBuilder


# ─── Bug #1: SessionManager.shutdown() deadlocks on kill ─────────────
#
# Root cause: shutdown() held self._lock and then called kill(),
# which also tries to acquire self._lock. Classic reentrant deadlock.
#
# Fix: shutdown() now grabs the session IDs under lock, then releases
# the lock before iterating to kill each session.


class TestShutdownDeadlockRegression:
    @pytest.mark.asyncio
    async def test_shutdown_kills_sessions_without_deadlock(self):
        """Regression: shutdown() must not hang when sessions exist."""
        config = ConfigManager()
        audit = AuditLogger(config)

        class MockTransports:
            pass
        sm = SessionManager(config, MockTransports(), audit)

        # Register multiple sessions
        for i in range(5):
            await sm.register(SessionInfo(
                session_id=f"regression-{i}",
                hostname=f"host-{i}",
                os="linux"
            ))

        await sm.initialize()

        # This must complete within reasonable time (no deadlock)
        try:
            await asyncio.wait_for(sm.shutdown(), timeout=5.0)
        except asyncio.TimeoutError:
            pytest.fail("SessionManager.shutdown() timed out — deadlock detected")

        assert sm.count() == 0

    @pytest.mark.asyncio
    async def test_shutdown_with_no_sessions(self):
        """Edge case: shutdown when no sessions exist."""
        config = ConfigManager()
        audit = AuditLogger(config)

        class MockTransports:
            pass
        sm = SessionManager(config, MockTransports(), audit)
        await sm.initialize()
        await asyncio.wait_for(sm.shutdown(), timeout=5.0)
        assert sm.count() == 0

    @pytest.mark.asyncio
    async def test_engine_full_lifecycle_with_sessions(self):
        """Engine must start and stop cleanly even with active sessions."""
        engine = PupyteerEngine()
        await engine.start()

        for i in range(3):
            await engine.sessions.register(SessionInfo(
                session_id=f"engine-life-{i}",
                hostname=f"host-{i}",
                os="windows"
            ))

        try:
            await asyncio.wait_for(engine.stop(), timeout=5.0)
        except asyncio.TimeoutError:
            pytest.fail("Engine.stop() timed out with active sessions")

        assert engine.state.started is False
        assert engine.sessions.count() == 0


# ─── Bug #2: TaskManager.get() is async, must be awaited ──────────────
#
# Root cause: TaskManager.get() is defined as `async def get()` but some
# code paths (and the original test) called it without await, returning
# a coroutine object instead of the actual result.


class TestTaskGetAsyncRegression:
    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self):
        """TaskManager.get() must return None for missing tasks."""
        config = ConfigManager()
        audit = AuditLogger(config)

        class MockSessions:
            pass
        tm = TaskManager(config, MockSessions(), audit)

        # Must be awaited
        result = await tm.get("does-not-exist")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_returns_task_info(self):
        """TaskManager.get() returns TaskInfo after creation."""
        config = ConfigManager()
        audit = AuditLogger(config)

        class MockSessions:
            pass
        tm = TaskManager(config, MockSessions(), audit)
        await tm.initialize()

        tid = await tm.create("regression-task")
        info = await tm.get(tid)
        assert info is not None
        assert info.name == "regression-task"

        await tm.shutdown()


# ─── Bug #3: Config validation crashes on non-int port ───────────────
#
# Root cause: validate() checked `not isinstance(port, int)` but the
# coercion path could leave port as a string. The original code's
# validate() expected an int after set(), but env overrides or file
# loading could produce string values.


class TestConfigStringPortRegression:
    @pytest.mark.asyncio
    async def test_validate_rejects_string_port(self):
        """String port should be rejected by validate()."""
        config = ConfigManager()
        config.set("server.port", "not-a-number")
        with pytest.raises(ValueError, match="Invalid server.port"):
            await config.validate()

    @pytest.mark.asyncio
    async def test_validate_accepts_valid_port(self):
        """Valid integer port should pass validation."""
        config = ConfigManager()
        config.set("server.port", 8443)
        assert await config.validate() is True


# ─── Bug #4: Import failure on httpx missing ──────────────────────────
#
# Root cause: The main package imports PupyteerEngine at module load time,
# which transitively imports evasion.litterbox_client which needs httpx.
# This made `import pupyteer` fail on minimal installs.


class TestImportChainRegression:
    def test_engine_import_is_clean(self):
        """Importing PupyteerEngine should not raise ModuleNotFoundError."""
        try:
            from pupyteer.server.core.engine import PupyteerEngine
        except ModuleNotFoundError as e:
            pytest.fail(f"Engine import failed: {e}")

    def test_config_import_is_clean(self):
        """Importing ConfigManager should not raise any error."""
        from pupyteer.server.core.config import ConfigManager
        assert ConfigManager is not None

    def test_sessions_import_is_clean(self):
        from pupyteer.server.sessions.manager import SessionManager
        assert SessionManager is not None

    def test_tasks_import_is_clean(self):
        from pupyteer.server.tasks.manager import TaskManager
        assert TaskManager is not None

    def test_profiles_import_is_clean(self):
        from pupyteer.server.profiles.manager import ProfileManager
        assert ProfileManager is not None

    def test_payloads_import_is_clean(self):
        from pupyteer.payloads.manager import PayloadManager
        assert PayloadManager is not None


# ─── Bug #5: C2Profile class referenced but never existed ─────────────
#
# Root cause: test_core.py imported C2Profile from profiles.manager,
# but that class doesn't exist in the codebase. ProfileManager uses
# plain dicts instead.


class TestProfileManagerC2ProfileRegression:
    def test_get_returns_c2profile(self):
        """ProfileManager.get() returns a C2Profile object."""
        config = ConfigManager()
        audit = AuditLogger(config)
        pm = ProfileManager(config, audit)

        import asyncio
        asyncio.run(pm.initialize())

        profile = pm.get("HTTPS-Standard")
        assert profile is not None
        assert hasattr(profile, 'name')
        assert profile.name == "HTTPS-Standard"

    def test_c2profile_has_validate(self):
        """C2Profile has validate() method."""
        config = ConfigManager()
        audit = AuditLogger(config)
        pm = ProfileManager(config, audit)

        import asyncio
        asyncio.run(pm.initialize())

        profile = pm.get("HTTPS-Standard")
        assert profile is not None
        result = profile.validate()
        assert result.is_valid
        errors = profile.validate_errors()
        assert isinstance(errors, list)
        assert len(errors) == 0

    def test_c2profile_get_dotted(self):
        """C2Profile.get() supports dotted key access."""
        config = ConfigManager()
        audit = AuditLogger(config)
        pm = ProfileManager(config, audit)

        import asyncio
        asyncio.run(pm.initialize())

        profile = pm.get("HTTPS-Standard")
        assert profile is not None
        assert profile.get("transport.protocol") == "tcp"
        assert profile.get("transport.port") == 8443
        assert profile.get("missing.key", "default") == "default"

    def test_c2profile_summary(self):
        """C2Profile.summary() returns name and metadata."""
        config = ConfigManager()
        audit = AuditLogger(config)
        pm = ProfileManager(config, audit)

        import asyncio
        asyncio.run(pm.initialize())

        profile = pm.get("HTTPS-Standard")
        assert profile is not None
        s = profile.summary()
        assert s["name"] == "HTTPS-Standard"
        assert "transport" in s

    def test_list_returns_enriched_dicts(self):
        """ProfileManager.list() returns enriched dicts with name/version/transport/source/active."""
        config = ConfigManager()
        audit = AuditLogger(config)
        pm = ProfileManager(config, audit)

        import asyncio
        asyncio.run(pm.initialize())

        profiles = pm.list()
        assert isinstance(profiles, list)
        assert all(isinstance(p, dict) for p in profiles)
        assert all("name" in p for p in profiles)
        assert all("active" in p for p in profiles)


# ─── Bug #6: Two TransportManager classes caused import confusion ─────
#
# Root cause: server/transports/manager.py defines TransportManager
# (simple, 3 methods: initialize, list, shutdown) while
# server/transports/__init__.py defines a different TransportManager
# (full-featured with create, register, unregister, etc).
# engine.py imports from .manager, so the simple one is used.
# Tests should only rely on the simple API.


class TestTransportManagerApiRegression:
    @pytest.mark.asyncio
    async def test_engine_uses_simple_transport_manager(self):
        """Engine's TransportManager has initialize/list/shutdown API."""
        engine = PupyteerEngine()
        await engine.start()
        # The engine should have a transports attribute
        assert engine.transports is not None
        # And the list method should work
        result = engine.transports.list()
        assert isinstance(result, list)
        await engine.stop()

    @pytest.mark.asyncio
    async def test_simple_transport_manager_lifecycle(self):
        """Simple TransportManager can init and shutdown."""
        config = ConfigManager()
        audit = AuditLogger(config)
        profiles = ProfileManager(config, audit)
        tm = __import__("pupyteer.server.transports.manager", fromlist=["TransportManager"]).TransportManager(config, profiles, audit)
        await tm.initialize()
        result = tm.list()
        assert isinstance(result, list)
        await tm.shutdown()


# ─── Bug #7: test_shutdown_kills_all_sessions never completes ─────────
#
# (Subcase of Bug #1 but specific to the test that was added)


class TestShutdownCompletes:
    @pytest.mark.asyncio
    async def test_shutdown_completes_with_many_sessions(self):
        """Shutdown should handle many sessions without hanging."""
        config = ConfigManager()
        audit = AuditLogger(config)

        class MockTransports:
            pass
        sm = SessionManager(config, MockTransports(), audit)

        # Register many sessions
        for i in range(50):
            await sm.register(SessionInfo(
                session_id=f"many-{i}",
                hostname=f"h-{i}"
            ))

        await sm.initialize()

        try:
            await asyncio.wait_for(sm.shutdown(), timeout=10.0)
        except asyncio.TimeoutError:
            pytest.fail("Shutdown timed out with 50 sessions")

        assert sm.count() == 0


# ─── Bug #8: Payload validation allows invalid port ──────────────────
#
# Edge case: port 0 was accepted but should be rejected


class TestPayloadValidationRegression:
    def test_port_zero_rejected(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", host="127.0.0.1", port=0)
        errors = builder.validate_config(cfg)
        assert len(errors) > 0

    def test_port_negative_rejected(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", host="127.0.0.1", port=-1)
        errors = builder.validate_config(cfg)
        assert len(errors) > 0

    def test_port_too_high_rejected(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", host="127.0.0.1", port=70000)
        errors = builder.validate_config(cfg)
        assert len(errors) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
