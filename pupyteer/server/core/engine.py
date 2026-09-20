"""Pupyteer Server Core Engine — Central C2 orchestrator.

This module implements the C2 Engine per spec section 4 architecture.
It integrates:
- Centralized error handling via pupyteer.server.core.errors
- Async priority task queue via pupyteer.server.core.queue
- Engine state management (INITIALIZED → STARTING → RUNNING → STOPPING → STOPPED)
- Graceful shutdown with ordered cleanup
- Config validation via pupyteer.server.core.validation

Architecture:
    PUPYTEER
       |
    Server ---- TUI
       |
  +----+----+
  |         |
Session   Task
Manager   Manager
  |         |
  +----+----+
       |
   C2 Engine  <--- PupyteerEngine (this module)
       |
  +----+----+----+
  |    |    |    |
Profile Auth Queue Transport
Manager Layer Manager
"""
from __future__ import annotations

import asyncio
import logging
import signal
import time
from enum import Enum
from typing import Any, Dict, Optional

from pupyteer.server.core.auth import AuthLayer
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.rbac import PermissionChecker
from pupyteer.server.core.session_auth import SessionAuthorization
from pupyteer.server.core.errors import (
    C2EngineError,
    ErrorCode,
    SubsystemError,
)
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.core.queue import TaskPriority, TaskQueue
from pupyteer.server.core.validation import validate_engine_config
from pupyteer.server.evasion.manager import EvasionTestManager
from pupyteer.payloads.manager import PayloadManager
from pupyteer.server.modules.executor import ModuleExecutor
from pupyteer.server.modules.registry import ModuleRegistry
from pupyteer.server.profiles.manager import ProfileManager
from pupyteer.server.sessions.manager import SessionInfo, SessionManager, SessionState
from pupyteer.server.tasks.manager import TaskManager, TaskState
from pupyteer.server.transports.manager import TransportManager
from pupyteer.server.core.pipeline import PipelineManager

logger = logging.getLogger("pupyteer.engine")


class EnginePhase(str, Enum):
    """Lifecycle phases of the Pupyteer engine."""

    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


from dataclasses import dataclass, field


@dataclass
class EngineState:
    """Tracks the operational state of the Pupyteer engine."""

    started: bool = False
    shutting_down: bool = False
    active_sessions: int = 0
    queued_tasks: int = 0
    loaded_profile: Optional[str] = None
    uptime_seconds: float = 0.0
    phase: str = EnginePhase.INITIALIZED.value


class PupyteerEngine:
    """
    Central C2 orchestrator for the Pupyteer red-team framework.

    Manages lifecycle of all subsystems with:
    - Modular component architecture
    - Clear API boundaries
    - Centralized configuration
    - Asynchronous task handling via priority queue
    - Session lifecycle management
    - Improved error handling with typed exceptions
    - Structured logging and audit trail
    - Graceful shutdown with ordered cleanup
    - Engine state management (starting/running/stopping/error)
    """

    def __init__(self, config_path: Optional[str] = None):
        # Core configuration and audit
        self._config = ConfigManager(config_path)
        self._audit = AuditLogger(self._config)
        self._config._audit = self._audit

        # Lifecycle state
        self._phase = EnginePhase.INITIALIZED
        self._start_time: Optional[float] = None
        self._shutdown_event = asyncio.Event()
        self._error: Optional[C2EngineError] = None

        # Priority task queue
        queue_size = self._config.get("tasks.queue_size", 0)
        self._queue = TaskQueue(max_size=queue_size)

        # Authentication / authorization layer
        self._auth = AuthLayer(self._config, self._audit)
        # The checker reads roles off the credential store, and the authoriser
        # turns a token plus a verb into yes or no. Both belong to the engine so
        # two consoles on one engine cannot disagree about what a token means.
        self._rbac = PermissionChecker(self._auth, self._auth.operators)
        self._authz = SessionAuthorization(self._auth, self._rbac)

        # Subsystem managers (wired in dependency order)
        self._profiles = ProfileManager(self._config, self._audit)
        self._transports = TransportManager(self._config, self._profiles, self._audit)
        self._sessions = SessionManager(
            self._config, self._transports, self._audit, profiles=self._profiles
        )
        # Module system — registry discovers modules, executor dispatches commands
        self._module_registry = ModuleRegistry(self._config, self._audit)
        self._module_executor = ModuleExecutor(
            registry=self._module_registry,
            session_manager=self._sessions,
            audit_logger=self._audit,
        )
        self._tasks = TaskManager(self._config, self._sessions, self._audit)
        self._evasion = EvasionTestManager(self._config, self._audit)
        self._payloads = PayloadManager(self._config, self._audit)
        # Unified payload-to-evasion pipeline
        self._pipeline = PipelineManager(self)

        # Legacy state for backward compatibility
        self.state = EngineState()
        self._logger = logging.getLogger("pupyteer.engine")

    # ── Properties ──────────────────────────────────────────────────

    @property
    def phase(self) -> EnginePhase:
        """Current engine lifecycle phase."""
        return self._phase

    @property
    def is_running(self) -> bool:
        """True if engine is fully started and operational."""
        return self._phase == EnginePhase.RUNNING

    @property
    def config(self) -> ConfigManager:
        return self._config

    @property
    def audit(self) -> AuditLogger:
        return self._audit

    @property
    def auth(self) -> AuthLayer:
        return self._auth

    @property
    def authz(self) -> SessionAuthorization:
        return self._authz

    @property
    def rbac(self) -> PermissionChecker:
        return self._rbac

    @property
    def sessions(self) -> SessionManager:
        return self._sessions

    @property
    def tasks(self) -> TaskManager:
        return self._tasks

    @property
    def profiles(self) -> ProfileManager:
        return self._profiles

    @property
    def transports(self) -> TransportManager:
        return self._transports

    @property
    def evasion(self) -> EvasionTestManager:
        return self._evasion

    @property
    def payloads(self) -> PayloadManager:
        return self._payloads

    @property
    def pipeline(self) -> PipelineManager:
        return self._pipeline

    @property
    def modules(self) -> ModuleExecutor:
        """Module execution engine — dispatches commands to agents via sessions."""
        return self._module_executor

    @property
    def module_registry(self) -> ModuleRegistry:
        """Module registry — discovers and loads modules."""
        return self._module_registry

    @property
    def queue(self) -> TaskQueue:
        """Priority task queue for async task dispatch."""
        return self._queue

    @property
    def error(self) -> Optional[C2EngineError]:
        """Last error that put the engine into ERROR phase."""
        return self._error

    # ── Lifecycle ───────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialize and start all subsystems in dependency order.

        Raises:
            C2EngineError: If any subsystem fails to initialize.
        """
        if self._phase == EnginePhase.RUNNING:
            self._logger.warning("Engine already running")
            return

        if self._phase == EnginePhase.STOPPING:
            raise C2EngineError(
                "Cannot start while stopping",
                code=ErrorCode.ENGINE_START_FAILED,
            )

        self._phase = EnginePhase.STARTING
        self._error = None
        self.state.phase = EnginePhase.STARTING.value
        self.audit.log_event("engine_start", {"config_loaded": True})
        self._logger.info("Starting Pupyteer Engine...")

        try:
            # Validate configuration
            await self._safe_call(
                "config.validate",
                self._config.validate,
                subsystem="config",
                operation="init",
            )
            validate_engine_config(self._config)

            # Initialize subsystems in dependency order
            await self._safe_call(
                "profiles.initialize",
                self._profiles.initialize,
                subsystem="profiles",
                operation="init",
            )
            await self._safe_call(
                "transports.initialize",
                self._transports.initialize,
                subsystem="transports",
                operation="init",
            )
            await self._safe_call(
                "sessions.initialize",
                self._sessions.initialize,
                subsystem="sessions",
                operation="init",
            )
            # Wire session manager into the TCP listener so agent callbacks
            # can create sessions
            await self._transports.start_listener(self._sessions)
            # Discover and register modules
            mod_count = self._module_registry.discover()
            self._logger.info("Discovered %d modules", mod_count)
            await self._safe_call(
                "tasks.initialize",
                self._tasks.initialize,
                subsystem="tasks",
                operation="init",
            )
            await self._safe_call(
                "evasion.initialize",
                self._evasion.initialize,
                subsystem="evasion",
                operation="init",
            )
            await self._safe_call(
                "pipeline.initialize",
                self._pipeline.initialize,
                subsystem="pipeline",
                operation="init",
            )

            self._phase = EnginePhase.RUNNING
            self.state.started = True
            self.state.phase = EnginePhase.RUNNING.value
            self._start_time = time.time()
            self.audit.log_event("engine_ready", {"phase": "running"})
            self._logger.info("Pupyteer Engine ready and running")

        except C2EngineError:
            self._phase = EnginePhase.ERROR
            self.state.phase = EnginePhase.ERROR.value
            await self.stop()
            raise
        except Exception as exc:
            self._phase = EnginePhase.ERROR
            self.state.phase = EnginePhase.ERROR.value
            self._error = C2EngineError(
                f"Unexpected engine start failure: {exc}",
                code=ErrorCode.ENGINE_START_FAILED,
                cause=exc,
            )
            self.audit.log_event("engine_start_failed", self._error.to_dict())
            await self.stop()
            raise self._error

    async def stop(self, timeout: float = 30.0) -> None:
        """Gracefully shut down all subsystems in reverse dependency order.

        Args:
            timeout: Maximum seconds to wait for each subsystem shutdown.
        """
        if self._phase in (EnginePhase.STOPPED, EnginePhase.INITIALIZED):
            return

        if self._phase == EnginePhase.STOPPING:
            return

        self._phase = EnginePhase.STOPPING
        self.state.shutting_down = True
        self.state.phase = EnginePhase.STOPPING.value
        self.audit.log_event("engine_shutdown", {})
        self._logger.info("Initiating graceful shutdown (timeout=%.1fs)...", timeout)

        # Shutdown in reverse order of initialization
        shutdown_order = [
            ("tasks", self._tasks.shutdown),
            ("sessions", self._sessions.shutdown),
            ("transports", self._transports.shutdown),
            ("profiles", self._profiles.shutdown),
            ("pipeline", self._pipeline.shutdown),
            ("evasion", self._evasion.shutdown),
        ]

        for name, shutdown_fn in shutdown_order:
            try:
                await asyncio.wait_for(shutdown_fn(), timeout=timeout)
                self._logger.debug("Subsystem '%s' stopped", name)
            except asyncio.TimeoutError:
                self._logger.error("Subsystem '%s' shutdown timed out after %.1fs", name, timeout)
                self.audit.log_event(
                    "subsystem_shutdown_timeout",
                    {"subsystem": name, "timeout": timeout},
                )
            except Exception as exc:
                self._logger.error("Subsystem '%s' shutdown error: %s", name, exc)
                self.audit.log_event(
                    "subsystem_shutdown_error",
                    {"subsystem": name, "error": str(exc)},
                )

        self._phase = EnginePhase.STOPPED
        self.state.started = False
        self.state.shutting_down = False
        self.state.phase = EnginePhase.STOPPED.value
        self._shutdown_event.set()
        self.audit.log_event("engine_stopped", {})
        self._logger.info("Engine stopped")

    async def wait_for_shutdown(self) -> None:
        """Block until shutdown is complete."""
        await self._shutdown_event.wait()

    # ── Status ──────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Return current engine status snapshot."""
        uptime = 0.0
        if self._start_time:
            uptime = time.time() - self._start_time

        return {
            "state": {
                "started": self.state.started,
                "shutting_down": self.state.shutting_down,
                "active_sessions": self._sessions.count(),
                "queued_tasks": self._tasks.count(),
                "loaded_profile": self._profiles.active_name(),
                "phase": self._phase.value,
                "uptime_seconds": round(uptime, 2),
            },
            "config": {
                "server_host": self._config.get("server.host", "0.0.0.0"),
                "server_port": self._config.get("server.port", 8443),
                # SHA-256 of the certificate the listener actually serves; empty
                # while callbacks run in the clear.
                "listener_tls": getattr(
                    self._transports.listener_tls, "fingerprint", ""
                ),
                # What the config asks for, which is known before anything is
                # listening. Without it the banner cannot tell "server.tls is off"
                # from "nothing has started yet", and says the first when the
                # operator's config says the second.
                "tls_configured": bool(self._config.get("server.tls", True)),
                # True when registrations must carry the enrollment secret,
                # False when the listener accepts anyone, None before it starts.
                "agent_auth": self._transports.listener_requires_auth,
                "log_level": self._config.get("logging.level", "INFO"),
                "operator": self._config.get("operator.name", "unknown"),
                "environment": self._config.environment,
            },
            "modules": self._module_registry.count(),
            "profiles": self._profiles.list(),
            "transports": self._transports.list(),
            "queue_stats": self._queue.stats().to_dict(),
            "error": self._error.to_dict() if self._error else None,
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all subsystems."""
        results = {
            "engine": self.is_running,
            "profiles": False,
            "transports": False,
            "sessions": False,
            "tasks": False,
        }
        try:
            results["profiles"] = self._profiles.active_name() is not None
        except Exception:
            pass
        try:
            results["transports"] = len(self._transports.list()) >= 0
        except Exception:
            pass
        try:
            results["sessions"] = self._sessions.count() >= 0
        except Exception:
            pass
        try:
            results["tasks"] = self._tasks.count() >= 0
        except Exception:
            pass
        results["healthy"] = all(results.values())
        return results

    # ── Task Queue Integration ───────────────────────────────────────

    async def submit_task(
        self,
        name: str,
        module: str = "",
        session_id: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> str:
        """Submit a task to the priority queue.

        Args:
            name: Human-readable task name.
            module: Module to execute.
            session_id: Optional target session.
            args: Module arguments.
            priority: Task priority level.

        Returns:
            task_id: The queued task identifier.

        Raises:
            C2EngineError: If engine is not running.
        """
        if not self.is_running:
            raise C2EngineError(
                "Cannot submit task: engine not running",
                code=ErrorCode.ENGINE_NOT_RUNNING,
            )
        task_id = await self._queue.enqueue(
            name=name,
            module=module,
            session_id=session_id,
            args=args,
            priority=priority,
        )
        self.audit.log_event(
            "task_submitted",
            {"task_id": task_id, "name": name, "priority": priority.name},
            session=session_id,
        )
        return task_id

    # ── Signal Handling ─────────────────────────────────────────────

    def attach_signal_handlers(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """Attach SIGINT/SIGTERM handlers for graceful shutdown."""
        if loop is None:
            loop = asyncio.get_event_loop()

        def _handle_signal(sig):
            self._logger.info("Received signal %s, initiating shutdown...", sig.name)
            asyncio.create_task(self.stop())

        try:
            loop.add_signal_handler(signal.SIGINT, _handle_signal, signal.SIGINT)
            loop.add_signal_handler(signal.SIGTERM, _handle_signal, signal.SIGTERM)
        except NotImplementedError:
            self._logger.warning("Signal handlers not supported on this platform")

    # ── Private Helpers ─────────────────────────────────────────────

    async def _safe_call(
        self,
        label: str,
        coro_func,
        subsystem: str = "unknown",
        operation: str = "init",
    ) -> Any:
        """Call a coroutine, wrapping exceptions in SubsystemError."""
        try:
            return await coro_func()
        except C2EngineError:
            raise
        except Exception as exc:
            raise SubsystemError(
                subsystem=subsystem,
                operation=operation,
                message=str(exc),
                cause=exc,
            )
