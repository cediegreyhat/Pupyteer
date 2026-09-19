"""C2 Engine — Central coordinator for the Pupyteer server.

This module implements the core C2 engine per spec section 4 architecture.
It wires together all subsystems (Session Manager, Task Manager, Profile Manager,
Transport Manager, Auth Layer, Config) into a unified lifecycle with:

- State management (starting/running/stopping/error)
- Graceful shutdown with ordered cleanup
- Centralized error handling via C2EngineError
- Structured logging via AuditLogger
- Async task queue integration via TaskQueue

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
   C2 Engine  <--- This module
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
from enum import Enum
from typing import Any, Dict, Optional

from pupyteer.server.core.auth import AuthLayer
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.errors import (
    C2EngineError,
    ConfigError,
    ErrorCode,
    SubsystemError,
)
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.core.queue import TaskPriority, TaskQueue
from pupyteer.server.core.validation import validate_engine_config
from pupyteer.server.evasion.manager import EvasionTestManager
from pupyteer.server.profiles.manager import ProfileManager
from pupyteer.server.sessions.manager import SessionManager
from pupyteer.server.tasks.manager import TaskManager
from pupyteer.server.transports.manager import TransportManager

logger = logging.getLogger("pupyteer.c2_engine")


class EnginePhase(str, Enum):
    """Lifecycle phases of the C2 engine."""

    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class C2Engine:
    """Central C2 engine that coordinates all Pupyteer subsystems.

    Responsibilities:
    - Orchestrate subsystem initialization in dependency order
    - Manage the lifecycle (start / stop / restart)
    - Expose a unified status and health interface
    - Handle async task dispatching through the priority queue
    - Graceful shutdown with configurable timeout
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

        # Priority task queue (capacity from config)
        queue_size = self._config.get("tasks.queue_size", 0)
        self._queue = TaskQueue(max_size=queue_size)

        # Authentication / authorization layer
        self._auth = AuthLayer(self._config, self._audit)

        # Subsystem managers
        self._profiles = ProfileManager(self._config, self._audit)
        self._transports = TransportManager(self._config, self._profiles, self._audit)
        self._sessions = SessionManager(
            self._config, self._transports, self._audit, profiles=self._profiles
        )
        self._tasks = TaskManager(self._config, self._sessions, self._audit)
        self._evasion = EvasionTestManager(self._config, self._audit)

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
    def queue(self) -> TaskQueue:
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
            logger.warning("Engine already running")
            return

        if self._phase == EnginePhase.STOPPING:
            raise C2EngineError(
                "Cannot start while stopping",
                code=ErrorCode.ENGINE_START_FAILED,
            )

        self._phase = EnginePhase.STARTING
        self._error = None
        logger.info("C2 Engine starting...")

        try:
            # Validate configuration first
            await self._safe_call(
                "config.validate",
                self._config.validate,
                subsystem="config",
                operation="init",
            )

            # Validate engine-specific config constraints
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

            self._phase = EnginePhase.RUNNING
            import time

            self._start_time = time.time()
            self._audit.log_event("engine_ready", {"phase": "running"})
            logger.info("C2 Engine ready and running")

        except C2EngineError:
            self._phase = EnginePhase.ERROR
            await self.stop()
            raise
        except Exception as exc:
            self._phase = EnginePhase.ERROR
            self._error = C2EngineError(
                f"Unexpected engine start failure: {exc}",
                code=ErrorCode.ENGINE_START_FAILED,
                cause=exc,
            )
            self._audit.log_event("engine_start_failed", self._error.to_dict())
            await self.stop()
            raise self._error

    async def stop(self, timeout: float = 30.0) -> None:
        """Gracefully shut down all subsystems in reverse dependency order.

        Args:
            timeout: Maximum seconds to wait for each subsystem shutdown.
        """
        if self._phase in (EnginePhase.STOPPED, EnginePhase.INITIALIZED):
            return

        self._phase = EnginePhase.STOPPING
        logger.info("C2 Engine shutting down (timeout=%.1fs)...", timeout)

        # Shutdown in reverse order of initialization
        shutdown_order = [
            ("evasion", self._evasion.shutdown),
            ("tasks", self._tasks.shutdown),
            ("sessions", self._sessions.shutdown),
            ("transports", self._transports.shutdown),
            ("profiles", self._profiles.shutdown),
        ]

        for name, shutdown_fn in shutdown_order:
            try:
                await asyncio.wait_for(shutdown_fn(), timeout=timeout)
                logger.debug("Subsystem '%s' stopped", name)
            except asyncio.TimeoutError:
                logger.error("Subsystem '%s' shutdown timed out after %.1fs", name, timeout)
                self._audit.log_event(
                    "subsystem_shutdown_timeout",
                    {"subsystem": name, "timeout": timeout},
                )
            except Exception as exc:
                logger.error("Subsystem '%s' shutdown error: %s", name, exc)
                self._audit.log_event(
                    "subsystem_shutdown_error",
                    {"subsystem": name, "error": str(exc)},
                )

        self._phase = EnginePhase.STOPPED
        self._shutdown_event.set()
        self._audit.log_event("engine_stopped", {})
        logger.info("C2 Engine stopped")

    async def restart(self) -> None:
        """Restart the engine (stop then start)."""
        await self.stop()
        await self.start()

    async def wait_for_shutdown(self) -> None:
        """Block until the engine has fully stopped."""
        await self._shutdown_event.wait()

    # ── Status / Health ─────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive engine status snapshot."""
        import time

        uptime = 0.0
        if self._start_time:
            uptime = time.time() - self._start_time

        return {
            "phase": self._phase.value,
            "running": self.is_running,
            "uptime_seconds": round(uptime, 2),
            "error": self._error.to_dict() if self._error else None,
            "sessions": {
                "total": self._sessions.count(),
            },
            "tasks": {
                "total": self._tasks.count(),
            },
            "queue": self._queue.stats().to_dict(),
            "profiles": {
                "active": self._profiles.active_name(),
                "count": len(self._profiles.list()),
            },
            "transports": self._transports.list(),
            "config": {
                "server_host": self._config.get("server.host", "0.0.0.0"),
                "server_port": self._config.get("server.port", 8443),
                "environment": self._config.environment,
            },
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

        self._audit.log_event(
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
            logger.info("Received signal %s, initiating shutdown...", sig.name)
            asyncio.create_task(self.stop())

        try:
            loop.add_signal_handler(signal.SIGINT, _handle_signal, signal.SIGINT)
            loop.add_signal_handler(signal.SIGTERM, _handle_signal, signal.SIGTERM)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            logger.warning("Signal handlers not supported on this platform")

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
