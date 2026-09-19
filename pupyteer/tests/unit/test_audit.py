"""Tests for structured audit logging — spec section 11."""
import json
import os
import tempfile
from pathlib import Path

import pytest

from pupyteer.server.core.audit import (
    AUDIT_EVENTS,
    AUDIT_EVENT_ALIAS_MAP,
    AuditEventBuilder,
    AuditLogStore,
    AuditEmitter,
    _redact_value,
)
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger


class TestAuditEvents:
    """Spec section 11 — all ten audit event types exist."""

    def test_all_ten_events_defined(self):
        expected = {
            "server_started",
            "operator_login",
            "profile_loaded",
            "payload_built",
            "agent_connected",
            "task_created",
            "task_completed",
            "module_executed",
            "configuration_changed",
            "session_terminated",
        }
        assert AUDIT_EVENTS == expected

    def test_ten_events_count(self):
        assert len(AUDIT_EVENTS) == 10


class TestAuditEventAliasMap:
    """Legacy event names map to spec section 11 events."""

    def test_all_aliases_map_to_spec_events(self):
        for alias, spec_event in AUDIT_EVENT_ALIAS_MAP.items():
            assert spec_event in AUDIT_EVENTS, f"Alias {alias} maps to unknown event {spec_event}"

    def test_key_aliases_present(self):
        assert "engine_start" in AUDIT_EVENT_ALIAS_MAP
        assert "auth_success" in AUDIT_EVENT_ALIAS_MAP
        assert "session_registered" in AUDIT_EVENT_ALIAS_MAP
        assert "session_killed" in AUDIT_EVENT_ALIAS_MAP
        assert "task_completed" in AUDIT_EVENT_ALIAS_MAP


class TestRedaction:
    """Secrets and sensitive data must never appear in audit logs."""

    def test_password_redacted(self):
        assert _redact_value("password", "secret123") == "***REDACTED***"

    def test_token_redacted(self):
        assert _redact_value("auth_token", "abc123") == "***REDACTED***"

    def test_api_key_redacted(self):
        assert _redact_value("api_key", "xyz") == "***REDACTED***"

    def test_secret_redacted(self):
        assert _redact_value("secret", "mysecret") == "***REDACTED***"

    def test_key_redacted(self):
        assert _redact_value("private_key", "keydata") == "***REDACTED***"

    def test_credential_redacted(self):
        assert _redact_value("credential", "cred") == "***REDACTED***"

    def test_non_sensitive_preserved(self):
        assert _redact_value("username", "admin") == "admin"
        assert _redact_value("hostname", "server01") == "server01"
        assert _redact_value("os", "linux") == "linux"

    def test_nested_dict_redacted(self):
        data = {"user": "admin", "secret_key": "value", "normal": "data"}
        redacted = _redact_value("_root", data)
        assert redacted["secret_key"] == "***REDACTED***"
        assert redacted["user"] == "admin"
        assert redacted["normal"] == "data"


class TestAuditEventBuilder:
    """Fluent builder for structured audit events."""

    def test_build_minimal(self):
        entry = AuditEventBuilder("server_started").build()
        assert entry["event"] == "server_started"
        assert entry["operator"] == "unknown"
        assert "timestamp" in entry

    def test_build_full(self):
        entry = (
            AuditEventBuilder("task_created")
            .operator("admin")
            .session("sess-1")
            .result("success")
            .detail("task_id", "t-001")
            .detail("module", "sysinfo")
            .build()
        )
        assert entry["operator"] == "admin"
        assert entry["session"] == "sess-1"
        assert entry["result"] == "success"
        assert entry["details"]["task_id"] == "t-001"
        assert entry["details"]["module"] == "sysinfo"

    def test_build_with_details_kwargs(self):
        entry = (
            AuditEventBuilder("payload_built")
            .operator("test")
            .details(payload_id="pl-1", platform="windows")
            .build()
        )
        assert entry["details"]["payload_id"] == "pl-1"
        assert entry["details"]["platform"] == "windows"


class TestAuditLogStore:
    """Rotation, compression, and querying."""

    def test_write_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            entry = {"timestamp": "2024-01-01T00:00:00", "operator": "test", "event": "task_created", "session": "s1", "result": "success"}
            store.write_entry(entry)
            results = store.query()
            assert len(results) == 1
            assert results[0]["event"] == "task_created"

    def test_query_by_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            store.write_entry({"timestamp": "2024-01-01T00:00:00", "operator": "test", "event": "task_created", "session": "s1", "result": "success"})
            store.write_entry({"timestamp": "2024-01-02T00:00:00", "operator": "admin", "event": "server_started", "session": None, "result": "success"})
            results = store.query(event="task_created")
            assert len(results) == 1
            assert results[0]["operator"] == "test"

    def test_query_by_operator(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            store.write_entry({"timestamp": "2024-01-01T00:00:00", "operator": "alice", "event": "task_created", "session": None, "result": "success"})
            store.write_entry({"timestamp": "2024-01-02T00:00:00", "operator": "bob", "event": "task_created", "session": None, "result": "success"})
            results = store.query(operator="alice")
            assert len(results) == 1

    def test_query_with_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            for i in range(10):
                store.write_entry({"timestamp": f"2024-01-0{i+1}T00:00:00", "operator": "test", "event": "task_created", "session": None, "result": "success"})
            results = store.query(limit=5)
            assert len(results) == 5

    def test_query_by_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            store.write_entry({"timestamp": "2024-01-01T00:00:00", "operator": "test", "event": "task_created", "session": "sess-a", "result": "success"})
            store.write_entry({"timestamp": "2024-01-02T00:00:00", "operator": "test", "event": "task_created", "session": "sess-b", "result": "success"})
            results = store.query(session="sess-a")
            assert len(results) == 1
            assert results[0]["session"] == "sess-a"

    def test_rotation_by_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Small max_bytes to trigger rotation
            store = AuditLogStore(Path(tmp) / "audit.json", max_bytes=200, backup_count=3, compress=False)
            # Write enough entries to trigger rotation
            for i in range(20):
                store.write_entry({"timestamp": f"2024-01-0{i+1}T00:00:00", "operator": "test", "event": "task_created", "session": None, "result": "success"})
            # Check that rotation happened
            rotated = list(Path(tmp).glob("audit.*"))
            assert len(rotated) > 0

    def test_compression(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json", max_bytes=200, backup_count=3, compress=True)
            for i in range(20):
                store.write_entry({"timestamp": f"2024-01-0{i+1}T00:00:00", "operator": "test", "event": "task_created", "session": None, "result": "success"})
            gz_files = list(Path(tmp).glob("*.gz"))
            assert len(gz_files) > 0


class TestAuditEmitter:
    """High-level emitter with convenience methods."""

    def test_emit_basic(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            emitter = AuditEmitter(store, default_operator="test")
            entry = emitter.emit("task_created", session="s1", result="success", task_id="t-1")
            assert entry["event"] == "task_created"
            assert entry["operator"] == "test"
            assert entry["session"] == "s1"
            assert entry["result"] == "success"
            assert entry["details"]["task_id"] == "t-1"

    def test_emit_with_custom_operator(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            emitter = AuditEmitter(store)
            entry = emitter.emit("operator_login", operator="alice")
            assert entry["operator"] == "alice"

    def test_server_started_convenience(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            emitter = AuditEmitter(store, default_operator="sys")
            entry = emitter.server_started()
            assert entry["event"] == "server_started"
            assert entry["result"] == "success"

    def test_operator_login_convenience(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            emitter = AuditEmitter(store)
            entry = emitter.operator_login("alice", success=True)
            assert entry["event"] == "operator_login"
            assert entry["operator"] == "alice"
            assert entry["result"] == "success"

    def test_operator_login_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            emitter = AuditEmitter(store)
            entry = emitter.operator_login("bob", success=False)
            assert entry["result"] == "failure"

    def test_all_spec_events_have_convenience_methods(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditLogStore(Path(tmp) / "audit.json")
            emitter = AuditEmitter(store, default_operator="test")

            assert emitter.server_started()["event"] == "server_started"
            assert emitter.operator_login("u")["event"] == "operator_login"
            assert emitter.profile_loaded("p")["event"] == "profile_loaded"
            assert emitter.payload_built("pl-1", "windows")["event"] == "payload_built"
            assert emitter.agent_connected("s1")["event"] == "agent_connected"
            assert emitter.task_created("t-1")["event"] == "task_created"
            assert emitter.task_completed("t-1")["event"] == "task_completed"
            assert emitter.module_executed("sysinfo")["event"] == "module_executed"
            assert emitter.configuration_changed("server.port")["event"] == "configuration_changed"
            assert emitter.session_terminated("s1")["event"] == "session_terminated"


class TestAuditLoggerIntegration:
    """AuditLogger integrates with spec section 11 events."""

    def test_audit_logger_creates_store(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        assert audit._store is not None

    def test_log_event_translates_alias(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        entry = audit.log_event("engine_start", {"config_loaded": True}, result="success")
        assert entry["event"] == "server_started"

    def test_log_event_preserves_spec_events(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        entry = audit.log_event("operator_login", {"username": "admin"}, result="success")
        assert entry["event"] == "operator_login"

    def test_log_event_redacts_sensitive_data(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        entry = audit.log_event("auth_success", {"username": "admin", "token": "secret123"}, result="success")
        # Token should be redacted in details
        assert entry.get("details", {}).get("token") == "***REDACTED***"

    def test_emit_spec_directly(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        entry = audit.emit_spec("payload_built", result="success", payload_id="pl-1")
        assert entry["event"] == "payload_built"

    def test_query_delegates_to_store(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        audit.emit_spec("task_created", result="success", task_id="t-1")
        results = audit.query(event="task_created")
        assert len(results) >= 1


class TestAuditLogFileFormat:
    """Verify JSON log file format per spec section 11."""

    def test_json_format_has_required_keys(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        entry = audit.log_event("task_created", {"task_id": "t-1"}, session="s1", result="success")

        # Spec section 11 format: timestamp, operator, event, session, result
        assert "timestamp" in entry
        assert "operator" in entry
        assert "event" in entry
        assert "session" in entry
        assert "result" in entry

    def test_json_is_serializable(self, tmp_path):
        config = ConfigManager()
        audit = AuditLogger(config)
        entry = audit.log_event("task_created", {"task_id": "t-1"}, session="s1", result="success")
        # Should be JSON serializable
        serialized = json.dumps(entry)
        assert isinstance(serialized, str)
        # Roundtrip
        deserialized = json.loads(serialized)
        assert deserialized == entry
