"""Centralized error handling for the Pupyteer C2 Engine.

Defines a hierarchy of typed errors with error codes, structured context,
and convenience constructors so every subsystem raises consistent,
loggable exceptions.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional


class ErrorCode(str, Enum):
    """Machine-readable error codes for C2 engine failures."""

    # Config errors (1xxx)
    CONFIG_VALIDATION = "E1001"
    CONFIG_MISSING_SECTION = "E1002"

    # Subsystem lifecycle errors (2xxx)
    SUBSYSTEM_INIT_FAILED = "E2001"
    SUBSYSTEM_SHUTDOWN_FAILED = "E2002"
    SUBSYSTEM_NOT_READY = "E2003"

    # Session errors (3xxx)
    SESSION_NOT_FOUND = "E3001"
    SESSION_STATE_INVALID = "E3002"

    # Task errors (4xxx)
    TASK_NOT_FOUND = "E4001"
    TASK_CANCEL_FAILED = "E4002"
    TASK_QUEUE_FULL = "E4003"

    # Transport errors (5xxx)
    TRANSPORT_INIT_FAILED = "E5001"
    TRANSPORT_SHUTDOWN_FAILED = "E5002"

    # Profile errors (6xxx)
    PROFILE_NOT_FOUND = "E6001"
    PROFILE_VALIDATION = "E6002"
    PROFILE_LOAD_FAILED = "E6003"

    # Auth errors (7xxx)
    AUTH_FAILED = "E7001"
    AUTH_UNAUTHORIZED = "E7002"

    # General engine errors (9xxx)
    ENGINE_NOT_RUNNING = "E9001"
    ENGINE_START_FAILED = "E9002"
    ENGINE_STOP_FAILED = "E9003"
    UNKNOWN = "E9999"


class C2EngineError(Exception):
    """Base exception for all C2 engine errors.

    Carries a machine-readable error code, human-readable message,
    and arbitrary structured context for logging / audit.
    """

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.UNKNOWN,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[BaseException] = None,
    ):
        super().__init__(message)
        self.code = code
        self.context = context or {}
        self.cause = cause

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for structured logging / audit."""
        return {
            "error": self.code.value,
            "message": str(self),
            "context": self.context,
            "cause": str(self.cause) if self.cause else None,
        }

    def __str__(self) -> str:
        base = f"[{self.code.value}] {super().__str__()}"
        if self.context:
            base += f" (context: {self.context})"
        if self.cause:
            base += f" (caused by: {self.cause})"
        return base


class ConfigError(C2EngineError):
    """Configuration validation or load failure."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, code=ErrorCode.CONFIG_VALIDATION, **kwargs)


class SubsystemError(C2EngineError):
    """A subsystem failed an operation."""

    def __init__(
        self,
        subsystem: str,
        operation: str,
        message: str,
        **kwargs,
    ):
        ctx = {"subsystem": subsystem, "operation": operation}
        ctx.update(kwargs.pop("context", {}))
        code_map = {
            "init": ErrorCode.SUBSYSTEM_INIT_FAILED,
            "shutdown": ErrorCode.SUBSYSTEM_SHUTDOWN_FAILED,
        }
        code = code_map.get(operation, ErrorCode.SUBSYSTEM_INIT_FAILED)
        super().__init__(f"{subsystem}.{operation}: {message}", code=code, context=ctx, **kwargs)


class SessionError(C2EngineError):
    """Session operation failure."""

    def __init__(self, session_id: str, message: str, **kwargs):
        ctx = {"session_id": session_id}
        ctx.update(kwargs.pop("context", {}))
        super().__init__(message, code=ErrorCode.SESSION_NOT_FOUND, context=ctx, **kwargs)


class TaskError(C2EngineError):
    """Task operation failure."""

    def __init__(self, task_id: str, message: str, **kwargs):
        ctx = {"task_id": task_id}
        ctx.update(kwargs.pop("context", {}))
        super().__init__(message, code=ErrorCode.TASK_NOT_FOUND, context=ctx, **kwargs)


class TransportError(C2EngineError):
    """Transport operation failure."""

    def __init__(self, transport: str, message: str, **kwargs):
        ctx = {"transport": transport}
        ctx.update(kwargs.pop("context", {}))
        code = kwargs.pop("code", ErrorCode.TRANSPORT_INIT_FAILED)
        super().__init__(message, code=code, context=ctx, **kwargs)


class ProfileError(C2EngineError):
    """Profile operation failure."""

    def __init__(self, profile: str, message: str, **kwargs):
        ctx = {"profile": profile}
        ctx.update(kwargs.pop("context", {}))
        code = kwargs.pop("code", ErrorCode.PROFILE_NOT_FOUND)
        super().__init__(message, code=code, context=ctx, **kwargs)


class AuthError(C2EngineError):
    """Authentication or authorization failure."""

    def __init__(self, message: str, **kwargs):
        code = kwargs.pop("code", ErrorCode.AUTH_FAILED)
        super().__init__(message, code=code, **kwargs)
