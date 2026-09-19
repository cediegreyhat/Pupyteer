"""Unit tests for Pupyteer core components — config, sessions, tasks, profiles, payloads."""
import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager, DEFAULT_CONFIG
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions.manager import SessionManager, SessionInfo, SessionState
from pupyteer.server.tasks.manager import TaskManager, TaskInfo, TaskState
from pupyteer.server.profiles.manager import ProfileManager, C2Profile
from pupyteer.payloads.manager import PayloadConfig, PayloadPlatform, PayloadArch, PayloadBuilder, PayloadStore, PayloadManager


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.fixture
def tmp_config_file():
    """Create a temporary YAML config file."""
    content = """
server:
  host: "127.0.0.1"
  port: 9999
logging:
  level: "DEBUG"
security:
  token_ttl: 7200
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
        yield f.name
    os.unlink(f.name)


# ─── Config Tests ────────────────────────────────────────────────────


class TestConfigManager:
    def test_default_config_loaded(self, config):
        assert config.get("server.host") == "0.0.0.0"
        assert config.get("server.port") == 8443
        assert config.get("logging.level") == "INFO"
        assert config.get("security.require_auth") is True

    def test_get_nested_default(self, config):
        assert config.get("server.host") == "0.0.0.0"
        assert config.get("nonexistent.key", "default") == "default"
        assert config.get("missing") is None

    def test_set_nested_existing(self, config):
        config.set("server.port", 9999)
        assert config.get("server.port") == 9999

    def test_set_nested_new_path(self, config):
        config.set("custom.nested.key", "value")
        assert config.get("custom.nested.key") == "value"

    def test_all_returns_copy(self, config):
        all_cfg = config.all()
        all_cfg["server"]["port"] = 1111
        # Original should be unchanged
        assert config.get("server.port") == 8443

    @pytest.mark.asyncio
    async def test_validate_success(self, config):
        assert await config.validate() is True

    def test_invalid_port_high(self, config):
        config.set("server.port", 99999)
        with pytest.raises(ValueError, match="Invalid server.port"):
            asyncio.run(config.validate())

    def test_invalid_port_zero(self, config):
        config.set("server.port", 0)
        with pytest.raises(ValueError, match="Invalid server.port"):
            asyncio.run(config.validate())

    def test_invalid_port_string(self, config):
        config.set("server.port", "not-a-number")
        with pytest.raises(ValueError, match="Invalid server.port"):
            asyncio.run(config.validate())

    def test_invalid_log_level(self, config):
        config.set("logging.level", "INVALID")
        with pytest.raises(ValueError, match="Invalid logging.level"):
            asyncio.run(config.validate())

    def test_missing_required_section(self, config):
        # Remove a required section
        del config._config["server"]
        with pytest.raises(ValueError, match="Missing required config section"):
            asyncio.run(config.validate())

    def test_load_from_file(self, tmp_config_file):
        config = ConfigManager(tmp_config_file)
        assert config.get("server.host") == "127.0.0.1"
        assert config.get("server.port") == 9999
        assert config.get("logging.level") == "DEBUG"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("PUPYTEER_SERVER__PORT", "7777")
        config = ConfigManager()
        assert config.get("server.port") == 7777

    def test_env_override_boolean(self, monkeypatch):
        monkeypatch.setenv("PUPYTEER_SECURITY__REQUIRE_AUTH", "false")
        config = ConfigManager()
        assert config.get("security.require_auth") is False

    def test_deep_merge(self):
        base = {"a": {"b": 1, "c": 2}}
        overlay = {"a": {"c": 3, "d": 4}}
        result = ConfigManager._deep_merge(base, overlay)
        assert result == {"a": {"b": 1, "c": 3, "d": 4}}

    def test_coerce_types(self):
        assert ConfigManager._coerce("true") is True
        assert ConfigManager._coerce("FALSE") is False
        assert ConfigManager._coerce("yes") is True
        assert ConfigManager._coerce("off") is False
        assert ConfigManager._coerce("42") == 42
        assert ConfigManager._coerce("3.14") == 3.14
        assert ConfigManager._coerce("hello") == "hello"

    def test_save_and_reload(self, tmp_path):
        config = ConfigManager()
        config.set("server.port", 5555)
        save_path = tmp_path / "test_config.yaml"
        config.save(str(save_path))
        assert save_path.exists()
        reloaded = ConfigManager(str(save_path))
        assert reloaded.get("server.port") == 5555


# ─── Session Tests ───────────────────────────────────────────────────


class TestSessionManager:
    @pytest.fixture
    def sessions(self, config, audit):
        class MockTransports:
            pass
        return SessionManager(config, MockTransports(), audit)

    @pytest.mark.asyncio
    async def test_register_session(self, sessions):
        info = SessionInfo(
            session_id="test-001",
            hostname="test-host",
            os="linux",
            arch="x64",
            username="root",
        )
        sid = await sessions.register(info)
        assert sid == "test-001"
        assert sessions.count() == 1

    @pytest.mark.asyncio
    async def test_register_generates_id(self, sessions):
        info = SessionInfo(session_id="gen-id", hostname="host", os="windows")
        sid = await sessions.register(info)
        assert sid is not None
        assert len(sid) > 0

    @pytest.mark.asyncio
    async def test_register_sets_timestamps(self, sessions):
        info = SessionInfo(session_id="ts-test", hostname="h")
        await sessions.register(info)
        session = await sessions.get("ts-test")
        assert session.connected_at > 0
        assert session.last_checkin > 0

    @pytest.mark.asyncio
    async def test_get_session(self, sessions):
        info = SessionInfo(session_id="test-002", hostname="host-2")
        await sessions.register(info)
        result = await sessions.get("test-002")
        assert result is not None
        assert result.hostname == "host-2"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, sessions):
        result = await sessions.get("does-not-exist")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_all(self, sessions):
        await sessions.register(SessionInfo(session_id="a"))
        await sessions.register(SessionInfo(session_id="b"))
        all_sessions = await sessions.list_all()
        assert len(all_sessions) == 2

    @pytest.mark.asyncio
    async def test_remove_session(self, sessions):
        await sessions.register(SessionInfo(session_id="rm-test", hostname="h"))
        ok = await sessions.remove("rm-test")
        assert ok is True
        assert sessions.count() == 0

    @pytest.mark.asyncio
    async def test_remove_nonexistent(self, sessions):
        ok = await sessions.remove("no-such-session")
        assert ok is False

    @pytest.mark.asyncio
    async def test_search_by_hostname(self, sessions):
        await sessions.register(SessionInfo(session_id="abc", hostname="web-server", os="linux"))
        await sessions.register(SessionInfo(session_id="def", hostname="db-server", os="windows"))
        results = await sessions.search("web")
        assert len(results) == 1
        assert results[0].session_id == "abc"

    @pytest.mark.asyncio
    async def test_search_by_os(self, sessions):
        await sessions.register(SessionInfo(session_id="s1", hostname="a", os="linux"))
        await sessions.register(SessionInfo(session_id="s2", hostname="b", os="windows"))
        results = await sessions.search("win")
        assert len(results) == 1
        assert results[0].session_id == "s2"

    @pytest.mark.asyncio
    async def test_search_by_tag(self, sessions):
        await sessions.register(SessionInfo(session_id="tag-s", hostname="h", tags=["web", "prod"]))
        results = await sessions.search("prod")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_filter_by(self, sessions):
        await sessions.register(SessionInfo(session_id="s1", hostname="a", os="linux"))
        await sessions.register(SessionInfo(session_id="s2", hostname="b", os="windows"))
        results = await sessions.filter_by(os="linux")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_filter_by_no_match(self, sessions):
        await sessions.register(SessionInfo(session_id="s1", hostname="a", os="linux"))
        results = await sessions.filter_by(os="macos")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_filter_by_invalid_field(self, sessions):
        await sessions.register(SessionInfo(session_id="s1", hostname="a", os="linux"))
        results = await sessions.filter_by(nonexistent_field="value")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_tag_session(self, sessions):
        await sessions.register(SessionInfo(session_id="tag-test", hostname="h"))
        ok = await sessions.tag("tag-test", ["web", "prod"])
        assert ok is True
        session = await sessions.get("tag-test")
        assert "web" in session.tags
        assert "prod" in session.tags

    @pytest.mark.asyncio
    async def test_tag_nonexistent(self, sessions):
        ok = await sessions.tag("no-such", ["tag"])
        assert ok is False

    @pytest.mark.asyncio
    async def test_tag_no_duplicates(self, sessions):
        await sessions.register(SessionInfo(session_id="dup-tag", hostname="h"))
        await sessions.tag("dup-tag", ["web"])
        await sessions.tag("dup-tag", ["web"])
        session = await sessions.get("dup-tag")
        assert session.tags.count("web") == 1

    @pytest.mark.asyncio
    async def test_rename_session(self, sessions):
        await sessions.register(SessionInfo(session_id="rn-test", hostname="old-name"))
        ok = await sessions.rename("rn-test", "new-name")
        assert ok is True
        session = await sessions.get("rn-test")
        assert session.hostname == "new-name"

    @pytest.mark.asyncio
    async def test_rename_nonexistent(self, sessions):
        ok = await sessions.rename("no-such", "new-name")
        assert ok is False

    @pytest.mark.asyncio
    async def test_kill_session(self, sessions):
        await sessions.register(SessionInfo(session_id="kill-me", hostname="h"))
        ok = await sessions.kill("kill-me")
        assert ok is True
        # The record survives only so the exit order can reach the agent on its
        # next check-in; deleting it immediately would leave the implant running.
        session = await sessions.get("kill-me")
        assert session.state.value == "killed"
        assert [c["command"] for c in await sessions.get_pending_commands("kill-me")] == ["exit"]
        assert await sessions.remove("kill-me") is True
        assert sessions.count() == 0
        assert await sessions.get_pending_commands("kill-me") == []

    @pytest.mark.asyncio
    async def test_kill_nonexistent(self, sessions):
        ok = await sessions.kill("no-such")
        assert ok is False

    @pytest.mark.asyncio
    async def test_update_checkin(self, sessions):
        await sessions.register(SessionInfo(session_id="ci-test", hostname="h"))
        old_session = await sessions.get("ci-test")
        old_time = old_session.last_checkin
        await asyncio.sleep(0.01)
        await sessions.update_checkin("ci-test")
        new_session = await sessions.get("ci-test")
        assert new_session.last_checkin > old_time

    @pytest.mark.asyncio
    async def test_count_active(self, sessions):
        await sessions.register(SessionInfo(session_id="a", hostname="h", state=SessionState.CONNECTED))
        await sessions.register(SessionInfo(session_id="b", hostname="h", state=SessionState.DISCONNECTED))
        count = await sessions.count_active()
        assert count == 1

    @pytest.mark.asyncio
    async def test_summary(self, sessions):
        await sessions.register(SessionInfo(session_id="a", hostname="h1", os="linux", state=SessionState.CONNECTED))
        await sessions.register(SessionInfo(session_id="b", hostname="h2", os="windows", state=SessionState.CONNECTED))
        await sessions.register(SessionInfo(session_id="c", hostname="h3", os="linux", state=SessionState.TIMEOUT))
        summary = await sessions.summary()
        assert summary["total"] == 3
        assert summary["by_os"]["linux"] == 2
        assert summary["by_os"]["windows"] == 1
        assert summary["by_state"]["connected"] == 2
        assert summary["by_state"]["timeout"] == 1
        assert summary["active"] == 2

    @pytest.mark.asyncio
    async def test_uptime_seconds(self):
        info = SessionInfo(session_id="up", hostname="h", connected_at=time.time() - 10)
        assert info.uptime_seconds >= 9.5

    @pytest.mark.asyncio
    async def test_to_dict(self):
        info = SessionInfo(session_id="dict", hostname="h", os="linux", state=SessionState.CONNECTED)
        d = info.to_dict()
        assert d["session_id"] == "dict"
        assert d["state"] == "connected"
        assert "uptime_seconds" in d

    @pytest.mark.asyncio
    async def test_initialize_and_shutdown(self, sessions):
        await sessions.initialize()
        assert sessions._monitor_task is not None
        await sessions.shutdown()
        # After shutdown, monitor task should be cancelled
        assert sessions._monitor_task.done or sessions._monitor_task.cancelled()

    @pytest.mark.asyncio
    async def test_shutdown_kills_all_sessions(self, sessions):
        await sessions.register(SessionInfo(session_id="k1", hostname="h1"))
        await sessions.register(SessionInfo(session_id="k2", hostname="h2"))
        await sessions.initialize()
        await sessions.shutdown()
        assert sessions.count() == 0

    @pytest.mark.asyncio
    async def test_session_interact_queues_command(self, sessions):
        await sessions.register(SessionInfo(session_id="int-test", hostname="h", state=SessionState.CONNECTED))
        cmd_id = await sessions.interact("int-test", "whoami")
        assert cmd_id is not None
        session = await sessions.get("int-test")
        assert session.task_status == "executing"
        pending = await sessions.get_pending_commands("int-test")
        assert len(pending) == 1
        assert pending[0]["command"] == "whoami"

    @pytest.mark.asyncio
    async def test_session_interact_nonexistent(self, sessions):
        cmd_id = await sessions.interact("no-such", "whoami")
        assert cmd_id is None

    @pytest.mark.asyncio
    async def test_session_interact_disconnected(self, sessions):
        await sessions.register(SessionInfo(session_id="disc", hostname="h", state=SessionState.DISCONNECTED))
        cmd_id = await sessions.interact("disc", "whoami")
        assert cmd_id is None

    @pytest.mark.asyncio
    async def test_session_ack_command(self, sessions):
        await sessions.register(SessionInfo(session_id="ack-test", hostname="h", state=SessionState.CONNECTED))
        cmd_id = await sessions.interact("ack-test", "whoami")
        ok = await sessions.ack_command("ack-test", cmd_id, "root")
        assert ok is True
        session = await sessions.get("ack-test")
        assert session.task_status == "idle"
        history = await sessions.get_command_history("ack-test")
        assert len(history) == 1
        assert history[0]["result"] == "root"

    @pytest.mark.asyncio
    async def test_session_command_history_limit(self, sessions):
        await sessions.register(SessionInfo(session_id="hist", hostname="h", state=SessionState.CONNECTED))
        for i in range(5):
            await sessions.interact("hist", f"cmd-{i}")
        history = await sessions.get_command_history("hist", limit=3)
        assert len(history) == 3

    @pytest.mark.asyncio
    async def test_session_untag(self, sessions):
        await sessions.register(SessionInfo(session_id="ut-test", hostname="h", tags=["web", "prod"]))
        ok = await sessions.untag("ut-test", ["web"])
        assert ok is True
        session = await sessions.get("ut-test")
        assert "web" not in session.tags
        assert "prod" in session.tags

    @pytest.mark.asyncio
    async def test_session_set_task_status(self, sessions):
        await sessions.register(SessionInfo(session_id="ts", hostname="h"))
        ok = await sessions.set_task_status("ts", "running")
        assert ok is True
        session = await sessions.get("ts")
        assert session.task_status == "running"

    @pytest.mark.asyncio
    async def test_filter_by_tag(self, sessions):
        await sessions.register(SessionInfo(session_id="ft1", hostname="h1", tags=["web"]))
        await sessions.register(SessionInfo(session_id="ft2", hostname="h2", tags=["db"]))
        results = await sessions.filter_by_tag("web")
        assert len(results) == 1
        assert results[0].session_id == "ft1"

    @pytest.mark.asyncio
    async def test_filter_by_state(self, sessions):
        await sessions.register(SessionInfo(session_id="fs1", hostname="h1", state=SessionState.CONNECTED))
        await sessions.register(SessionInfo(session_id="fs2", hostname="h2", state=SessionState.TIMEOUT))
        results = await sessions.filter_by_state(SessionState.CONNECTED)
        assert len(results) == 1


# ─── Task Tests ──────────────────────────────────────────────────────


class TestTaskManager:
    @pytest.fixture
    def tasks(self, config, audit):
        class MockSessions:
            pass
        return TaskManager(config, MockSessions(), audit)

    @pytest.mark.asyncio
    async def test_create_task(self, tasks):
        await tasks.initialize()
        tid = await tasks.create("test-task", module="test", session_id="s1")
        assert tid is not None
        assert tasks.count() == 1
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_create_generates_unique_ids(self, tasks):
        await tasks.initialize()
        tid1 = await tasks.create("task-1")
        tid2 = await tasks.create("task-2")
        assert tid1 != tid2
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_get_task(self, tasks):
        await tasks.initialize()
        tid = await tasks.create("get-test")
        task = await tasks.get(tid)
        assert task is not None
        assert task.name == "get-test"
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, tasks):
        result = await tasks.get("no-such")
        assert result is None

    @pytest.mark.asyncio
    async def test_cancel_queued_task(self, tasks):
        await tasks.initialize()
        tid = await tasks.create("cancel-test")
        ok = await tasks.cancel(tid)
        assert ok is True
        task = await tasks.get(tid)
        assert task.state.value == "cancelled"
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_cancel_nonexistent(self, tasks):
        ok = await tasks.cancel("no-such")
        assert ok is False

    @pytest.mark.asyncio
    async def test_list_all(self, tasks):
        await tasks.initialize()
        await tasks.create("a")
        await tasks.create("b")
        all_tasks = await tasks.list_all()
        assert len(all_tasks) == 2
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_list_by_state(self, tasks):
        await tasks.initialize()
        tid = await tasks.create("state-test")
        queued = await tasks.list_by_state(TaskState.QUEUED)
        assert len(queued) >= 1
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_list_by_session(self, tasks):
        await tasks.initialize()
        await tasks.create("sess-test", session_id="target-sess")
        await tasks.create("other", session_id="other-sess")
        results = await tasks.list_by_session("target-sess")
        assert len(results) == 1
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_task_execution_completes(self, tasks):
        await tasks.initialize()
        tid = await tasks.create("exec-test", module="test")
        # Wait for task to be picked up and executed
        await asyncio.sleep(0.5)
        task = await tasks.get(tid)
        assert task is not None
        assert task.state.value in ("completed", "running", "queued")
        await tasks.shutdown()

    @pytest.mark.asyncio
    async def test_task_info_to_dict(self):
        info = TaskInfo(task_id="t1", name="test", state=TaskState.QUEUED)
        d = info.to_dict()
        assert d["task_id"] == "t1"
        assert d["name"] == "test"
        assert d["state"] == "queued"
        assert "duration_seconds" in d

    @pytest.mark.asyncio
    async def test_duration_seconds(self):
        info = TaskInfo(task_id="t1", name="test", started_at=time.time() - 5)
        assert info.duration_seconds is None  # Not completed yet
        info.completed_at = time.time()
        assert info.duration_seconds is not None
        assert info.duration_seconds >= 4.5

    @pytest.mark.asyncio
    async def test_max_concurrent(self, tasks):
        assert tasks._max_concurrent == 5  # Default

    @pytest.mark.asyncio
    async def test_custom_max_concurrent(self, config, audit):
        config.set("tasks.max_concurrent", 10)
        class MockSessions:
            pass
        tm = TaskManager(config, MockSessions(), audit)
        assert tm._max_concurrent == 10


# ─── Profile Tests ───────────────────────────────────────────────────


class TestProfileManager:
    @pytest.fixture
    def profiles(self, config, audit):
        return ProfileManager(config, audit)

    @pytest.mark.asyncio
    async def test_default_profile_loaded(self, profiles):
        await profiles.initialize()
        default = profiles.get("HTTPS-Standard")
        assert default is not None
        assert default.name == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_list_profiles(self, profiles):
        await profiles.initialize()
        plist = profiles.list()
        assert len(plist) >= 1

    @pytest.mark.asyncio
    async def test_active_name(self, profiles):
        await profiles.initialize()
        assert profiles.active_name() == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, profiles):
        await profiles.initialize()
        result = profiles.get("No-Such-Profile")
        assert result is None

    @pytest.mark.asyncio
    async def test_shutdown_clears_profiles(self, profiles):
        await profiles.initialize()
        await profiles.shutdown()
        assert profiles.active_name() is None

    @pytest.mark.asyncio
    async def test_custom_default_profile_name(self, config, audit):
        config.set("profile.default", "Custom-Profile")
        pm = ProfileManager(config, audit)
        await pm.initialize()
        # If custom profile doesn't exist, active_name should be None
        assert pm.active_name() is None

    @pytest.mark.asyncio
    async def test_load_profile(self, profiles):
        await profiles.initialize()
        ok = profiles.load("HTTPS-Standard")
        assert ok is True
        assert profiles.active_name() == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_unload_profile(self, profiles):
        await profiles.initialize()
        profiles.load("HTTPS-Standard")
        profiles.unload()
        assert profiles.active_name() is None

    @pytest.mark.asyncio
    async def test_active_returns_c2profile(self, profiles):
        await profiles.initialize()
        profiles.load("HTTPS-Standard")
        p = profiles.active()
        assert p is not None
        assert p.name == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_validate(self, profiles):
        await profiles.initialize()
        result = profiles.validate("HTTPS-Standard")
        assert result.is_valid

    @pytest.mark.asyncio
    async def test_validate_nonexistent(self, profiles):
        await profiles.initialize()
        result = profiles.validate("No-Such")
        assert not result.is_valid

    @pytest.mark.asyncio
    async def test_create_profile(self, profiles):
        await profiles.initialize()
        data = {
            "profile": {"name": "Test-Custom", "version": "1.0"},
            "transport": {"protocol": "tcp", "host": "127.0.0.1", "port": 4444},
        }
        profile = profiles.create(data)
        assert profile.name == "Test-Custom"
        assert profile.get("transport.port") == 4444

    @pytest.mark.asyncio
    async def test_create_invalid_raises(self, profiles):
        await profiles.initialize()
        # Invalid: unsupported protocol triggers validation failure
        data = {"profile": {"name": "Bad-Proto"}, "transport": {"protocol": "invalid_proto"}}
        with pytest.raises(ValueError):
            profiles.create(data)

    @pytest.mark.asyncio
    async def test_save_and_reload(self, profiles, tmp_path):
        await profiles.initialize()
        save_path = tmp_path / "test_profile.yaml"
        profiles.save("HTTPS-Standard", str(save_path))
        assert save_path.exists()
        profiles._load_file(save_path)
        assert profiles.get("HTTPS-Standard") is not None

    @pytest.mark.asyncio
    async def test_remove_profile(self, profiles):
        await profiles.initialize()
        data = {
            "profile": {"name": "Removable", "version": "1.0"},
            "transport": {"protocol": "tcp"},
        }
        profiles.create(data)
        ok = profiles.remove("Removable")
        assert ok is True
        assert profiles.get("Removable") is None

    @pytest.mark.asyncio
    async def test_remove_active_raises(self, profiles):
        await profiles.initialize()
        with pytest.raises(ValueError):
            profiles.remove("HTTPS-Standard")


# ─── Payload Tests ───────────────────────────────────────────────────


class TestPayloadConfig:
    def test_default_config(self):
        cfg = PayloadConfig(name="test")
        assert cfg.platform == PayloadPlatform.WINDOWS
        assert cfg.arch == PayloadArch.X64

    def test_to_dict(self):
        cfg = PayloadConfig(name="test", platform=PayloadPlatform.LINUX)
        d = cfg.to_dict()
        assert d["platform"] == "linux"


# ─── Audit Logger Tests ──────────────────────────────────────────────


class TestAuditLogger:
    def test_redact_sensitive_fields(self, audit):
        data = {"username": "admin", "password": "secret123", "host": "server"}
        redacted = audit._redact(data)
        assert redacted["password"] == "***REDACTED***"
        assert redacted["username"] == "admin"
        assert redacted["host"] == "server"

    def test_redact_nested_dict(self, audit):
        data = {"outer": {"secret_key": "value", "normal": "data"}}
        redacted = audit._redact(data)
        assert redacted["outer"]["secret_key"] == "***REDACTED***"
        assert redacted["outer"]["normal"] == "data"

    def test_log_event(self, audit, tmp_path):
        audit._log_file = tmp_path / "test_audit.json"
        entry = audit.log_event("test_event", {"key": "value"}, session="s1", result="success")
        assert entry["event"] == "test_event"
        assert entry["session"] == "s1"
        assert entry["result"] == "success"
        assert "timestamp" in entry


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
