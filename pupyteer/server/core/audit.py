"""Structured JSON audit logging — spec section 11 event types, rotation, and querying."""
from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pupyteer.audit")

# Spec section 11 — all ten audit event types
AUDIT_EVENTS = {
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

# Map legacy event names to spec section 11 events
AUDIT_EVENT_ALIAS_MAP: Dict[str, str] = {
    "engine_start": "server_started",
    "engine_ready": "server_started",
    "engine_stopped": "server_started",
    "auth_success": "operator_login",
    "auth_lockout": "operator_login",
    "auth_unknown_user": "operator_login",
    "auth_failed": "operator_login",
    "profile_loaded": "profile_loaded",
    "profile_created": "profile_loaded",
    "payload_built": "payload_built",
    "payload_build_started": "payload_built",
    "payload_build_failed": "payload_built",
    "session_registered": "agent_connected",
    "session_timeout": "agent_connected",
    "session_killed": "session_terminated",
    "session_terminated": "session_terminated",
    "session_tagged": "agent_connected",
    "session_renamed": "agent_connected",
    "session_command_queued": "module_executed",
    "session_command_ack": "module_executed",
    "task_created": "task_created",
    "task_completed": "task_completed",
    "task_failed": "task_completed",
    "module_executed": "module_executed",
    "configuration_changed": "configuration_changed",
}

# Sensitive field patterns (never stored in audit logs)
_REDACT_PATTERNS = {"password", "secret", "token", "key", "credential", "api_key", "auth_token", "private_key"}


def _redact_value(key: str, value: Any) -> Any:
    """Return redacted placeholder if key matches sensitive patterns."""
    k = key.lower()
    if any(pattern in k for pattern in _REDACT_PATTERNS):
        return "***REDACTED***"
    if isinstance(value, dict):
        return {kk: _redact_value(kk, vv) for kk, vv in value.items()}
    if isinstance(value, list):
        return [_redact_value(f"{key}[{i}]", v) if isinstance(v, dict) else v for i, v in enumerate(value)]
    return value


class AuditLogStore:
    """Handles structured JSON audit log rotation and querying.

    Each line of the log file is a single JSON object per spec section 11.
    Files rotate when they exceed ``max_bytes`` or daily (whichever comes first).
    """

    def __init__(
        self,
        log_path: Path,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
        compress: bool = True,
    ):
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._compress = compress

    def write_entry(self, entry: Dict[str, Any]) -> None:
        """Write a single JSON audit entry, rotating if needed."""
        self._rotate_if_needed()
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.warning("Failed to write audit entry: %s", exc)

    def query(
        self,
        event: Optional[str] = None,
        operator: Optional[str] = None,
        session: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query audit log entries with optional filters.

        Reads the current log file plus any rotated backups, newest first.
        """
        results: List[Dict[str, Any]] = []

        # Collect log files in reverse chronological order (newest first)
        log_files = [self._log_path] if self._log_path.exists() else []
        for p in sorted(self._log_path.parent.glob(f"{self._log_path.stem}*"), reverse=True):
            if p != self._log_path:
                log_files.append(p)

        for log_file in log_files:
            if len(results) >= offset + limit:
                break
            results.extend(self._read_file(log_file))

        # Sort by timestamp descending
        results.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

        # Apply filters
        filtered: List[Dict[str, Any]] = []
        for entry in results:
            if event and entry.get("event") != event:
                continue
            if operator and entry.get("operator") != operator:
                continue
            if session and entry.get("session") != session:
                continue
            if start_time and entry.get("timestamp", "") < start_time:
                continue
            if end_time and entry.get("timestamp", "") > end_time:
                continue
            filtered.append(entry)

        return filtered[offset:offset + limit]

    def _read_file(self, path: Path) -> List[Dict[str, Any]]:
        """Read entries from a single log file (supports .gz)."""
        entries: List[Dict[str, Any]] = []
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            elif path.exists():
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
        except OSError:
            pass
        return entries

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max_bytes or is from a previous day."""
        if not self._log_path.exists():
            return

        stat = self._log_path.stat()
        size_exceeded = stat.st_size >= self._max_bytes

        # Check if file is from a previous day
        file_date = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).date()
        today = datetime.now(timezone.utc).date()
        day_changed = file_date < today

        if size_exceeded or day_changed:
            self._rotate()

    def _rotate(self) -> None:
        """Perform log rotation: shift backups, optionally compress."""
        # Remove oldest backup if at limit
        oldest = self._log_path.with_suffix(f".{self._backup_count}.gz")
        if oldest.exists():
            oldest.unlink()

        # Shift existing backups
        for i in range(self._backup_count - 1, 0, -1):
            src = self._log_path.with_suffix(f".{i}.gz" if self._compress else f".{i}")
            dst = self._log_path.with_suffix(f".{i + 1}.gz" if self._compress else f".{i + 1}")
            if src.exists():
                shutil.move(str(src), str(dst))

        # Compress current log to .1.gz
        if self._compress:
            rotated = self._log_path.with_suffix(".1.gz")
            with open(self._log_path, "rb") as f_in:
                with gzip.open(rotated, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            self._log_path.unlink()
        else:
            rotated = self._log_path.with_suffix(".1")
            shutil.move(str(self._log_path), str(rotated))


class AuditEventBuilder:
    """Fluent builder for constructing structured audit events.

    Usage::

        event = (
            AuditEventBuilder("task_created")
            .operator("admin")
            .session("sess-123")
            .result("success")
            .detail("task_id", "t-001")
            .detail("module", "sysinfo")
            .build()
        )
    """

    def __init__(self, event: str):
        self._event = event
        self._operator = "unknown"
        self._session: Optional[str] = None
        self._result: Optional[str] = None
        self._details: Dict[str, Any] = {}
        self._timestamp = datetime.now(timezone.utc).isoformat()

    def operator(self, name: str) -> "AuditEventBuilder":
        self._operator = name
        return self

    def session(self, session_id: str) -> "AuditEventBuilder":
        self._session = session_id
        return self

    def result(self, value: str) -> "AuditEventBuilder":
        self._result = value
        return self

    def detail(self, key: str, value: Any) -> "AuditEventBuilder":
        self._details[key] = value
        return self

    def details(self, **kwargs) -> "AuditEventBuilder":
        self._details.update(kwargs)
        return self

    def build(self) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "timestamp": self._timestamp,
            "operator": self._operator,
            "event": self._event,
            "session": self._session,
            "result": self._result,
        }
        if self._details:
            entry["details"] = _redact_value("_root", self._details) if isinstance(self._details, dict) else self._details
        return entry


class AuditEmitter:
    """High-level audit event emitter that writes to store + Python logger.

    Wraps the AuditLogger from logging.py for convenience.
    """

    def __init__(self, store: AuditLogStore, default_operator: str = "unknown"):
        self._store = store
        self._default_operator = default_operator

    def set_default_operator(self, name: str) -> None:
        """Change who entries are attributed to from now on.

        The console calls this when an operator signs in and when they sign out.
        Nothing else writes it: an operator's name in a config or in a command
        argument is a claim, and a claim is not proof.
        """
        self._default_operator = name or "unknown"

    def emit(
        self,
        event: str,
        operator: Optional[str] = None,
        session: Optional[str] = None,
        result: Optional[str] = None,
        **details,
    ) -> Dict[str, Any]:
        """Emit a structured audit event.

        Args:
            event: One of the AUDIT_EVENT types.
            operator: Operator name (falls back to default_operator if None).
            session: Session ID, if applicable.
            result: Event outcome ("success", "failure", "ok", "denied", etc.).
            **details: Additional structured detail fields.
        """
        builder = AuditEventBuilder(event)
        builder.operator(operator or self._default_operator)
        if session:
            builder.session(session)
        if result:
            builder.result(result)
        if details:
            builder.details(**details)

        entry = builder.build()

        # Write to structured log file
        self._store.write_entry(entry)

        # Also emit to Python logger for real-time monitoring
        logger.info(
            "audit | %s | operator=%s | session=%s | result=%s | details=%s",
            entry["event"],
            entry["operator"],
            entry["session"],
            entry["result"],
            json.dumps(entry.get("details", {}), default=str),
        )

        return entry

    def server_started(self, **extra) -> Dict[str, Any]:
        return self.emit("server_started", result="success", **extra)

    def operator_login(self, username: str, success: bool = True) -> Dict[str, Any]:
        return self.emit(
            "operator_login",
            operator=username,
            result="success" if success else "failure",
            username=username,
        )

    def profile_loaded(self, profile_name: str, **extra) -> Dict[str, Any]:
        return self.emit(
            "profile_loaded",
            result="success",
            profile=profile_name,
            **extra,
        )

    def payload_built(self, payload_id: str, platform: str, **extra) -> Dict[str, Any]:
        return self.emit(
            "payload_built",
            result="success",
            payload_id=payload_id,
            platform=platform,
            **extra,
        )

    def agent_connected(self, session_id: str, hostname: str = "", **extra) -> Dict[str, Any]:
        return self.emit(
            "agent_connected",
            session=session_id,
            result="success",
            session_id=session_id,
            hostname=hostname,
            **extra,
        )

    def task_created(self, task_id: str, session_id: Optional[str] = None, **extra) -> Dict[str, Any]:
        return self.emit(
            "task_created",
            session=session_id,
            result="success",
            task_id=task_id,
            **extra,
        )

    def task_completed(self, task_id: str, session_id: Optional[str] = None, **extra) -> Dict[str, Any]:
        return self.emit(
            "task_completed",
            session=session_id,
            result="success",
            task_id=task_id,
            **extra,
        )

    def module_executed(self, module_name: str, session_id: Optional[str] = None, **extra) -> Dict[str, Any]:
        return self.emit(
            "module_executed",
            session=session_id,
            result="success",
            module=module_name,
            **extra,
        )

    def configuration_changed(self, key: str, **extra) -> Dict[str, Any]:
        return self.emit(
            "configuration_changed",
            result="success",
            config_key=key,
            **extra,
        )

    def session_terminated(self, session_id: str, reason: str = "", **extra) -> Dict[str, Any]:
        return self.emit(
            "session_terminated",
            session=session_id,
            result="success",
            session_id=session_id,
            reason=reason,
            **extra,
        )
