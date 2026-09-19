"""Structured audit logging for Pupyteer.

Combines the simple ``AuditLogger`` (log_event helper) with the spec section 11
event types and the structured JSON audit store from ``audit.py``.

The ``AuditLogger`` class is the primary interface used throughout the codebase.
It translates the legacy event names into spec section 11 events and forwards
entries to the ``AuditLogStore`` for rotation and querying.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from pupyteer.server.core.config import ConfigManager

# Re-export the spec section 11 event catalog and helpers
from pupyteer.server.core.audit import (
    AUDIT_EVENTS,
    AUDIT_EVENT_ALIAS_MAP,
    AuditEmitter,
    AuditEventBuilder,
    AuditLogStore,
    _redact_value,
)

logger = logging.getLogger("pupyteer.audit")


class AuditLogger:
    """
    Emits structured JSON audit events for operator actions and system lifecycle.

    Never stores secrets or sensitive payload contents.

    Maps legacy event names to spec section 11 events and forwards entries to
    the structured audit log store for rotation and querying.
    """

    REDACTED_FIELDS = {"password", "secret", "token", "key", "credential"}

    def __init__(self, config: ConfigManager):
        self._config = config
        self._operator = config.get("operator.name", "unknown")
        self._log_file: Optional[Path] = None

        log_path = config.get("logging.file")
        if log_path:
            self._log_file = Path(log_path)
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

        # Structured audit log store (rotation + querying)
        audit_log_path = config.get("audit.log_file", "./logs/audit.json")
        self._store = AuditLogStore(
            log_path=Path(audit_log_path),
            max_bytes=config.get("audit.max_bytes", 10 * 1024 * 1024),
            backup_count=config.get("audit.backup_count", 5),
            compress=config.get("audit.compress", True),
        )
        self._emitter = AuditEmitter(self._store, default_operator=self._operator)

    def log_event(
        self,
        event: str,
        data: Dict[str, Any],
        session: Optional[str] = None,
        result: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Emit one structured audit entry.

        Translates legacy event names to spec section 11 events and forwards
        to the structured audit log store.
        """
        spec_event = AUDIT_EVENT_ALIAS_MAP.get(event, event)
        if spec_event not in AUDIT_EVENTS:
            # Allow passthrough for non-spec events (prefixed with "x_")
            spec_event = event

        operator = data.pop("_operator", self._operator)
        entry = self._emitter.emit(
            event=spec_event,
            operator=operator,
            session=session,
            result=result,
            **data,
        )

        # Also write to the legacy plain JSON file if configured
        if self._log_file:
            line = json.dumps(entry, default=str)
            try:
                with open(self._log_file, "a") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                logger.warning("Failed to write audit log: %s", exc)

        return entry

    def emit_spec(
        self,
        event: str,
        session: Optional[str] = None,
        result: Optional[str] = None,
        **details,
    ) -> Dict[str, Any]:
        """Emit a spec section 11 event directly."""
        return self._emitter.emit(
            event=event,
            session=session,
            result=result,
            **details,
        )

    def query(
        self,
        event: Optional[str] = None,
        operator: Optional[str] = None,
        session: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list:
        """Query the structured audit log store."""
        return self._store.query(
            event=event,
            operator=operator,
            session=session,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )

    def _redact(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return _redact_value("_root", data) if isinstance(data, dict) else data
