"""Session Manager — Agent/session lifecycle management for Pupyteer.

Manages agent session lifecycle:
- Registration, lookup, and filtering
- State tracking and heartbeat monitoring
- Session metadata, tagging, and search
- Graceful termination

Session timeout and heartbeat settings are sourced from the active C2 profile when available.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger

logger = logging.getLogger("pupyteer.sessions")


class SessionState(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    TIMEOUT = "timeout"
    ERROR = "error"
    KILLED = "killed"


@dataclass
class SessionInfo:
    """Metadata for an active agent session."""
    session_id: str
    hostname: str = ""
    os: str = ""
    arch: str = ""
    username: str = ""
    state: SessionState = SessionState.CONNECTED
    connected_at: float = 0.0
    last_checkin: float = 0.0
    profile: str = ""
    agent_version: str = ""
    tags: List[str] = field(default_factory=list)
    task_status: str = "idle"
    remote_address: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def uptime_seconds(self) -> float:
        if self.connected_at:
            return time.time() - self.connected_at
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        d["uptime_seconds"] = self.uptime_seconds
        return d


class SessionManager:
    """
    Manages agent session lifecycle:
    - Registration, lookup, and filtering
    - State tracking and heartbeat monitoring
    - Session metadata, tagging, and search
    - Graceful termination

    Session timeout and heartbeat settings are sourced from the active C2 profile.
    """

    def __init__(self, config: ConfigManager, transports: Any, audit: AuditLogger, profiles: Any = None):
        self._config = config
        self._transports = transports
        self._audit = audit
        self._profiles = profiles
        self._sessions: Dict[str, SessionInfo] = {}
        self._lock = asyncio.Lock()
        self._monitor_task: Optional[asyncio.Task] = None
        self._timeout_seconds: float = float(config.get("session.timeout_seconds", 300))
        self._heartbeat_interval: int = 30
        self._command_queue: Dict[str, List[Dict[str, Any]]] = {}

        # Try to get session config from active profile
        if profiles and hasattr(profiles, 'get_active_session_config'):
            profile_session = profiles.get_active_session_config()
            if profile_session:
                if "timeout" in profile_session:
                    self._timeout_seconds = float(profile_session["timeout"])
                if "heartbeat_interval" in profile_session:
                    self._heartbeat_interval = int(profile_session["heartbeat_interval"])

    async def initialize(self) -> None:
        """Start session manager background monitoring."""
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info(
            "Session manager initialized (timeout=%ds, heartbeat=%ds)",
            int(self._timeout_seconds),
            self._heartbeat_interval,
        )

    async def shutdown(self) -> None:
        """Terminate all sessions and stop monitoring."""
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        # Kill sessions without holding lock (kill acquires its own lock)
        async with self._lock:
            sids = list(self._sessions)
        for sid in sids:
            await self.kill(sid, reason="engine_shutdown")

        logger.info("Session manager stopped")

    # ------------------------------------------------------------------ #
    #  CRUD                                                               #
    # ------------------------------------------------------------------ #

    async def register(self, info: SessionInfo) -> str:
        """Register a new session. Returns session ID."""
        async with self._lock:
            if not info.session_id:
                import uuid
                info.session_id = str(uuid.uuid4())[:12]
            if not info.connected_at:
                info.connected_at = time.time()
            if not info.last_checkin:
                info.last_checkin = time.time()
            self._sessions[info.session_id] = info

        self._audit.log_event(
            "session_registered",
            {"session_id": info.session_id, "hostname": info.hostname, "os": info.os},
            session=info.session_id,
        )
        logger.info("Session registered: %s (%s@%s)", info.session_id, info.username, info.hostname)
        return info.session_id

    async def get(self, session_id: str) -> Optional[SessionInfo]:
        """Look up a session by ID."""
        return self._sessions.get(session_id)

    async def list_all(self) -> List[SessionInfo]:
        """Return all sessions."""
        return list(self._sessions.values())

    async def remove(self, session_id: str) -> bool:
        """Remove a session from tracking."""
        async with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
        return False

    async def kill(self, session_id: str, reason: str = "operator") -> bool:
        """Terminate a session and notify the agent."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            session.state = SessionState.KILLED
            hostname = session.hostname

        self._audit.log_event(
            "session_killed",
            {"session_id": session_id, "reason": reason, "hostname": hostname},
            session=session_id,
        )
        logger.info("Session killed: %s (reason: %s)", session_id, reason)
        await self.remove(session_id)
        return True

    # ------------------------------------------------------------------ #
    #  Search / Filter                                                    #
    # ------------------------------------------------------------------ #

    async def search(self, query: str) -> List[SessionInfo]:
        """Search sessions by tag, hostname, OS, username, or ID substring."""
        results = []
        q = query.lower()
        for s in self._sessions.values():
            if any([
                q in s.session_id.lower(),
                q in s.hostname.lower(),
                q in s.os.lower(),
                q in s.username.lower(),
                q in s.arch.lower(),
                q in s.profile.lower(),
                q in s.remote_address.lower(),
                q in " ".join(s.tags).lower(),
            ]):
                results.append(s)
        return results

    async def filter_by(self, **kwargs) -> List[SessionInfo]:
        """Filter sessions by keyword args matching SessionInfo fields."""
        results = []
        for s in self._sessions.values():
            match = True
            for key, value in kwargs.items():
                if not hasattr(s, key):
                    match = False
                    break
                actual = getattr(s, key)
                if isinstance(actual, str):
                    if value.lower() not in actual.lower():
                        match = False
                        break
                elif actual != value:
                    match = False
                    break
            if match:
                results.append(s)
        return results

    async def tag(self, session_id: str, tags: List[str]) -> bool:
        """Add tags to a session."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        for t in tags:
            if t not in session.tags:
                session.tags.append(t)
        self._audit.log_event("session_tagged", {"session_id": session_id, "tags": tags}, session=session_id)
        return True

    async def untag(self, session_id: str, tags: List[str]) -> bool:
        """Remove tags from a session."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        for t in tags:
            if t in session.tags:
                session.tags.remove(t)
        self._audit.log_event("session_untagged", {"session_id": session_id, "tags": tags}, session=session_id)
        return True

    async def set_task_status(self, session_id: str, status: str) -> bool:
        """Set task status for a session."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.task_status = status
        return True

    async def interact(self, session_id: str, command: str) -> Optional[str]:
        """
        Queue a command for execution on a session.

        Returns a command_id if the session exists, None otherwise.
        The command is added to the session's command queue and will be
        delivered to the agent on its next check-in.
        """
        session = self._sessions.get(session_id)
        if not session:
            return None
        if session.state != SessionState.CONNECTED:
            return None

        import uuid
        command_id = str(uuid.uuid4())[:12]

        cmd_entry = {
            "command_id": command_id,
            "command": command,
            "queued_at": time.time(),
            "status": "queued",
            "result": None,
        }

        if session_id not in self._command_queue:
            self._command_queue[session_id] = []
        self._command_queue[session_id].append(cmd_entry)

        # Update task status
        session.task_status = "executing"

        self._audit.log_event(
            "session_command_queued",
            {"session_id": session_id, "command_id": command_id, "command": command},
            session=session_id,
        )
        logger.info("Command %s queued for session %s: %s", command_id, session_id, command)
        return command_id

    async def get_pending_commands(self, session_id: str) -> List[Dict[str, Any]]:
        """Get pending commands for a session (called by transport layer)."""
        return self._command_queue.get(session_id, [])

    async def ack_command(self, session_id: str, command_id: str, result: str = "") -> bool:
        """Acknowledge command completion and store result."""
        queue = self._command_queue.get(session_id, [])
        for cmd in queue:
            if cmd["command_id"] == command_id:
                cmd["status"] = "completed"
                cmd["result"] = result
                cmd["completed_at"] = time.time()
                break

        # Update task status based on remaining queue
        session = self._sessions.get(session_id)
        if session:
            remaining = [c for c in queue if c["status"] == "queued"]
            if not remaining:
                session.task_status = "idle"
            else:
                session.task_status = "executing"

        self._audit.log_event(
            "session_command_ack",
            {"session_id": session_id, "command_id": command_id},
            session=session_id,
        )
        return True

    async def get_command_history(self, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get command history for a session."""
        queue = self._command_queue.get(session_id, [])
        return queue[-limit:]

    async def filter_by_tag(self, tag: str) -> List[SessionInfo]:
        """Filter sessions by a specific tag."""
        return [s for s in self._sessions.values() if tag in s.tags]

    async def filter_by_state(self, state: SessionState) -> List[SessionInfo]:
        """Filter sessions by state."""
        return [s for s in self._sessions.values() if s.state == state]

    async def rename(self, session_id: str, new_hostname: str) -> bool:
        """Rename a session (alias for hostname)."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        old = session.hostname
        session.hostname = new_hostname
        self._audit.log_event("session_renamed", {"session_id": session_id, "old": old, "new": new_hostname}, session=session_id)
        return True

    async def update_checkin(self, session_id: str) -> None:
        """Update last check-in timestamp."""
        session = self._sessions.get(session_id)
        if session:
            session.last_checkin = time.time()
            if session.state == SessionState.TIMEOUT:
                session.state = SessionState.CONNECTED

    # ------------------------------------------------------------------ #
    #  Stats                                                              #
    # ------------------------------------------------------------------ #

    def count(self) -> int:
        return len(self._sessions)

    async def count_active(self) -> int:
        return sum(1 for s in self._sessions.values() if s.state == SessionState.CONNECTED)

    async def summary(self) -> Dict[str, Any]:
        """Return aggregate session summary."""
        async with self._lock:
            by_os: Dict[str, int] = {}
            by_state: Dict[str, int] = {}
            for s in self._sessions.values():
                by_os[s.os] = by_os.get(s.os, 0) + 1
                state_val = s.state.value
                by_state[state_val] = by_state.get(state_val, 0) + 1

        return {
            "total": len(self._sessions),
            "by_os": by_os,
            "by_state": by_state,
            "active": by_state.get("connected", 0),
        }

    # ------------------------------------------------------------------ #
    #  Background monitor                                                 #
    # ------------------------------------------------------------------ #

    async def _monitor_loop(self) -> None:
        """Periodically check for timed-out sessions."""
        while True:
            try:
                await asyncio.sleep(30)
                now = time.time()
                async with self._lock:
                    for sid, session in self._sessions.items():
                        if session.state != SessionState.CONNECTED:
                            continue
                        if session.last_checkin and (now - session.last_checkin) > self._timeout_seconds:
                            session.state = SessionState.TIMEOUT
                            self._audit.log_event(
                                "session_timeout",
                                {"session_id": sid, "hostname": session.hostname, "last_checkin": session.last_checkin},
                                session=sid,
                            )
                            logger.warning("Session timed out: %s (%s)", sid, session.hostname)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Session monitor error: %s", exc)
