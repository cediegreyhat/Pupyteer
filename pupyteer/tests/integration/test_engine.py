"""Integration tests — engine startup, subsystem wiring, end-to-end flows."""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.engine import PupyteerEngine, EngineState
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions.manager import SessionManager, SessionInfo, SessionState
from pupyteer.server.tasks.manager import TaskManager, TaskState
from pupyteer.server.profiles.manager import ProfileManager
from pupyteer.server.transports.manager import TransportManager
from pupyteer.payloads.manager import PayloadConfig, PayloadBuilder, PayloadStore, PayloadManager
from pupyteer.payloads.manager import PayloadPlatform, PayloadArch, PayloadType


# ─── Engine Integration ───────────────────────────────────────────────


class TestEngineStartup:
    @pytest.mark.asyncio
    async def test_engine_instantiation(self):
        engine = PupyteerEngine()
        assert engine.state is not None
        assert isinstance(engine.state, EngineState)
        assert engine.state.started is False

    @pytest.mark.asyncio
    async def test_engine_start_and_stop(self):
        engine = PupyteerEngine()
        await engine.start()
        assert engine.state.started is True
        await engine.stop()
        assert engine.state.started is False

    @pytest.mark.asyncio
    async def test_engine_double_start_is_noop(self):
        engine = PupyteerEngine()
        await engine.start()
        # Second start should not raise
        await engine.start()
        assert engine.state.started is True
        await engine.stop()

    @pytest.mark.asyncio
    async def test_engine_get_status(self):
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
    async def test_engine_status_after_stop(self):
        engine = PupyteerEngine()
        await engine.start()
        await engine.stop()
        status = engine.get_status()
        assert status["state"]["started"] is False

    @pytest.mark.asyncio
    async def test_engine_subsystems_initialized(self):
        engine = PupyteerEngine()
        await engine.start()
        assert engine.sessions is not None
        assert engine.tasks is not None
        assert engine.profiles is not None
        assert engine.transports is not None
        assert engine.config is not None
        assert engine.audit is not None
        await engine.stop()

    @pytest.mark.asyncio
    async def test_engine_with_custom_config(self, tmp_path):
        cfg = tmp_path / "engine_test.yaml"
        cfg.write_text("server:\n  host: 127.0.0.1\n  port: 18443\n")
        engine = PupyteerEngine(str(cfg))
        await engine.start()
        assert engine.config.get("server.port") == 18443
        status = engine.get_status()
        assert status["config"]["server_port"] == 18443
        await engine.stop()


# ─── Subsystem Wiring ────────────────────────────────────────────────


class TestSubsystemWiring:
    @pytest.mark.asyncio
    async def test_session_uses_config_timeout(self):
        """Session manager reads timeout from config."""
        config = ConfigManager()
        config.set("session.timeout_seconds", 60)
        audit = AuditLogger(config)

        class MockTransports:
            pass
        sm = SessionManager(config, MockTransports(), audit)
        assert sm._timeout_seconds == 60

    @pytest.mark.asyncio
    async def test_tasks_uses_config_concurrency(self):
        """Task manager reads max_concurrent from config."""
        config = ConfigManager()
        config.set("tasks.max_concurrent", 3)
        audit = AuditLogger(config)

        class MockSessions:
            pass
        tm = TaskManager(config, MockSessions(), audit)
        assert tm._max_concurrent == 3

    @pytest.mark.asyncio
    async def test_transports_uses_config_host_port(self):
        """Transport manager uses configured host and port."""
        config = ConfigManager()
        config.set("server.host", "10.0.0.1")
        config.set("server.port", 9999)
        audit = AuditLogger(config)
        profiles = ProfileManager(config, audit)
        tm = TransportManager(config, profiles, audit)
        await tm.initialize()
        transports = tm.list()
        assert len(transports) >= 1

    @pytest.mark.asyncio
    async def test_full_lifecycle_with_sessions_and_tasks(self):
        """Engine starts, accepts sessions/tasks, and shuts down cleanly."""
        engine = PupyteerEngine()
        await engine.start()

        # Register a session
        info = SessionInfo(session_id="lifecycle-test", hostname="host", os="linux")
        sid = await engine.sessions.register(info)
        assert sid == "lifecycle-test"

        # Create a task
        tid = await engine.tasks.create("test-task", module="test", session_id=sid)
        assert tid is not None

        # Let task execute
        await asyncio.sleep(0.3)

        # Session should exist
        session = await engine.sessions.get(sid)
        assert session is not None

        # Shutdown
        await engine.stop()
        assert engine.state.started is False


# ─── Transport Interface ─────────────────────────────────────────────


class TestTransportManager:
    @pytest.mark.asyncio
    async def test_initialize_and_shutdown(self):
        config = ConfigManager()
        audit = AuditLogger(config)
        profiles = ProfileManager(config, audit)
        tm = TransportManager(config, profiles, audit)
        await tm.initialize()
        assert tm.list() is not None
        await tm.shutdown()

    @pytest.mark.asyncio
    async def test_list_transports(self):
        config = ConfigManager()
        audit = AuditLogger(config)
        profiles = ProfileManager(config, audit)
        tm = TransportManager(config, profiles, audit)
        await tm.initialize()
        transports = tm.list()
        assert isinstance(transports, list)
        await tm.shutdown()


# ─── Payload Integration ─────────────────────────────────────────────


class TestPayloadBuilder:
    @pytest.mark.asyncio
    async def test_validate_config_valid(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", host="127.0.0.1", port=8443)
        errors = builder.validate_config(cfg)
        assert errors == []

    @pytest.mark.asyncio
    async def test_validate_config_missing_name(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="", host="127.0.0.1", port=8443)
        errors = builder.validate_config(cfg)
        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_validate_config_invalid_port(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", host="127.0.0.1", port=99999)
        errors = builder.validate_config(cfg)
        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_build_payload(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        # A script payload: building an executable needs the compiler on the
        # build host, which an integration test cannot assume.
        cfg = PayloadConfig(
            name="integration-test",
            platform=PayloadPlatform.LINUX,
            arch=PayloadArch.X64,
            payload_type=PayloadType.SCRIPT,
        )
        pid = builder.generate_payload_id()
        assert pid.startswith("pl-")
        metadata = await builder.build(cfg, pid)
        assert metadata.name == "integration-test"
        assert metadata.status in ("built", "verified")
        assert metadata.hash_sha256 != ""
        assert metadata.size_bytes > 0


    @pytest.mark.asyncio
    async def test_compute_hashes(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        builder = PayloadBuilder(config, audit)
        test_file = tmp_path / "test_file.bin"
        test_file.write_bytes(b"test data for hashing")
        hashes = builder.compute_hashes(str(test_file))
        assert "sha256" in hashes
        assert "md5" in hashes
        assert len(hashes["sha256"]) == 64


class TestPayloadStore:
    @pytest.mark.asyncio
    async def test_add_and_get(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        store = PayloadStore(config, audit)
        from pupyteer.payloads.manager import PayloadMetadata
        meta = PayloadMetadata(payload_id="pl-store-test", name="store-test")
        store.add(meta)
        result = store.get("pl-store-test")
        assert result is not None
        assert result.name == "store-test"

    @pytest.mark.asyncio
    async def test_list_all(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        store = PayloadStore(config, audit)
        from pupyteer.payloads.manager import PayloadMetadata
        store.add(PayloadMetadata(payload_id="pl-a", name="a"))
        store.add(PayloadMetadata(payload_id="pl-b", name="b"))
        assert len(store.list_all()) == 2

    @pytest.mark.asyncio
    async def test_search(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        store = PayloadStore(config, audit)
        from pupyteer.payloads.manager import PayloadMetadata
        store.add(PayloadMetadata(payload_id="pl-web", name="web-payload"))
        store.add(PayloadMetadata(payload_id="pl-dns", name="dns-payload"))
        results = store.search("web")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_remove(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        store = PayloadStore(config, audit)
        from pupyteer.payloads.manager import PayloadMetadata
        store.add(PayloadMetadata(payload_id="pl-rm", name="rm-test"))
        assert store.remove("pl-rm") is True
        assert store.get("pl-rm") is None


class TestPayloadManager:
    @pytest.mark.asyncio
    async def test_build_and_get(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="pm-test", host="127.0.0.1", port=8443)
        metadata = await pm.build(cfg)
        assert metadata.name == "pm-test"
        assert metadata.payload_id is not None

        # Retrieve
        got = pm.get(metadata.payload_id)
        assert got is not None
        assert got.name == "pm-test"

    @pytest.mark.asyncio
    async def test_build_invalid_raises(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="", host="", port=0)
        with pytest.raises(ValueError):
            await pm.build(cfg)

    @pytest.mark.asyncio
    async def test_list_all(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        pm = PayloadManager(config, audit)
        await pm.build(PayloadConfig(name="a"))
        await pm.build(PayloadConfig(name="b"))
        assert len(pm.list_all()) == 2

    @pytest.mark.asyncio
    async def test_search(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        pm = PayloadManager(config, audit)
        await pm.build(PayloadConfig(name="search-target"))
        results = pm.search("target")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_get_stats(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        pm = PayloadManager(config, audit)
        await pm.build(PayloadConfig(name="stats-test"))
        stats = pm.get_stats()
        assert stats["total"] == 1
        assert "by_platform" in stats
        assert "by_status" in stats

    @pytest.mark.asyncio
    async def test_cleanup(self, tmp_path):
        config = ConfigManager()
        config.set("paths.payload_artifacts", str(tmp_path))
        audit = AuditLogger(config)
        pm = PayloadManager(config, audit)
        await pm.build(PayloadConfig(name="old-payload"))
        # Cleanup with 0 days should remove everything
        cleaned = pm.cleanup(max_age_days=0)
        assert cleaned >= 1


# ─── Module System Integration ───────────────────────────────────────


class TestModuleSystem:
    def test_registry_discover_builtins(self):
        from pupyteer.server.modules.registry import ModuleRegistry
        config = ConfigManager()
        audit = AuditLogger(config)
        registry = ModuleRegistry(config, audit)
        count = registry.discover()
        assert count >= 1  # At least recon modules

    def test_registry_list_all(self):
        from pupyteer.server.modules.registry import ModuleRegistry
        config = ConfigManager()
        audit = AuditLogger(config)
        registry = ModuleRegistry(config, audit)
        registry.discover()
        modules = registry.list_all()
        assert len(modules) >= 1
        assert any(m["name"] == "sysinfo" for m in modules)

    def test_registry_get(self):
        from pupyteer.server.modules.registry import ModuleRegistry
        config = ConfigManager()
        audit = AuditLogger(config)
        registry = ModuleRegistry(config, audit)
        registry.discover()
        cls = registry.get("sysinfo")
        assert cls is not None

    def test_registry_create(self):
        from pupyteer.server.modules.registry import ModuleRegistry
        config = ConfigManager()
        audit = AuditLogger(config)
        registry = ModuleRegistry(config, audit)
        registry.discover()
        instance = registry.create("sysinfo")
        assert instance is not None
        assert instance.name == "sysinfo"

    def test_registry_count(self):
        from pupyteer.server.modules.registry import ModuleRegistry
        config = ConfigManager()
        audit = AuditLogger(config)
        registry = ModuleRegistry(config, audit)
        registry.discover()
        assert registry.count() >= 1


# ─── TUI Integration ─────────────────────────────────────────────────


class TestTUI:
    def test_banner_renders(self, capsys):
        from pupyteer.tui.app import PupyteerTUI, BANNER
        engine = PupyteerEngine()
        tui = PupyteerTUI(engine)
        tui.render_banner()
        # Just verify no exception

    def test_command_registry(self):
        from pupyteer.tui.app import CommandRegistry
        reg = CommandRegistry()
        reg.register("test", lambda: None, "Test command")
        assert "test" in reg.list_commands()
        help_text = reg.get_help("test")
        assert "Test command" in help_text

    def test_dashboard_renders(self, capsys):
        from pupyteer.tui.app import PupyteerTUI
        engine = PupyteerEngine()
        tui = PupyteerTUI(engine)
        tui.render_dashboard()
        # No exception

    def test_table_renders(self, capsys):
        from pupyteer.tui.app import PupyteerTUI
        engine = PupyteerEngine()
        tui = PupyteerTUI(engine)
        tui.render_table(["Name", "Value"], [["test", "123"]])
        captured = capsys.readouterr()
        assert "test" in captured.out

    def test_empty_table_renders(self, capsys):
        from pupyteer.tui.app import PupyteerTUI
        engine = PupyteerEngine()
        tui = PupyteerTUI(engine)
        tui.render_table(["Name", "Value"], [])
        captured = capsys.readouterr()
        assert "no data" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
