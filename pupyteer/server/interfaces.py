"""Abstract protocols defining clear API boundaries between engine subsystems.

Each protocol specifies the minimum contract that the corresponding manager
must satisfy, allowing the engine to work against any conforming implementation
without tight coupling.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


# --------------------------------------------------------------------------- #
#  Configuration
# --------------------------------------------------------------------------- #

@runtime_checkable
class IConfig(Protocol):
    """Configuration access contract."""

    def get(self, dotted_key: str, default: Any = None) -> Any: ...

    def set(self, dotted_key: str, value: Any) -> None: ...

    async def validate(self) -> bool: ...

    def all(self) -> Dict[str, Any]: ...


# --------------------------------------------------------------------------- #
#  Audit / Logging
# --------------------------------------------------------------------------- #

@runtime_checkable
class IAudit(Protocol):
    """Structured audit event emitter contract."""

    def log_event(
        self,
        event: str,
        data: Dict[str, Any],
        session: Optional[str] = None,
        result: Optional[str] = None,
    ) -> Dict[str, Any]: ...


# --------------------------------------------------------------------------- #
#  Authentication / Authorization
# --------------------------------------------------------------------------- #

@runtime_checkable
class IAuth(Protocol):
    """Operator authentication and authorization contract."""

    def authenticate(self, username: str, password: str) -> Optional[str]: ...

    def authorize(self, token: str, required_permission: str = "read") -> bool: ...

    def get_operator(self, token: str) -> Optional[str]: ...

    def revoke(self, token: str) -> bool: ...


# --------------------------------------------------------------------------- #
#  Sessions
# --------------------------------------------------------------------------- #

@runtime_checkable
class ISessions(Protocol):
    """Agent session lifecycle management contract."""

    async def initialize(self) -> None: ...

    async def shutdown(self) -> None: ...

    async def register(self, info: Any) -> str: ...

    async def get(self, session_id: str) -> Optional[Any]: ...

    async def list_all(self) -> List[Any]: ...

    async def remove(self, session_id: str) -> bool: ...

    async def kill(self, session_id: str, reason: str = "operator") -> bool: ...

    async def search(self, query: str) -> List[Any]: ...

    async def tag(self, session_id: str, tags: List[str]) -> bool: ...

    async def update_checkin(self, session_id: str) -> None: ...

    def count(self) -> int: ...

    async def count_active(self) -> int: ...

    async def summary(self) -> Dict[str, Any]: ...


# --------------------------------------------------------------------------- #
#  Tasks
# --------------------------------------------------------------------------- #

@runtime_checkable
class ITasks(Protocol):
    """Async task queue and tracking contract."""

    async def initialize(self) -> None: ...

    async def shutdown(self) -> None: ...

    async def create(
        self,
        name: str,
        module: str = "",
        session_id: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
    ) -> str: ...

    async def get(self, task_id: str) -> Optional[Any]: ...

    async def cancel(self, task_id: str) -> bool: ...

    async def list_all(self) -> List[Any]: ...

    async def list_by_state(self, state: Any) -> List[Any]: ...

    async def list_by_session(self, session_id: str) -> List[Any]: ...

    def count(self) -> int: ...


# --------------------------------------------------------------------------- #
#  Transports
# --------------------------------------------------------------------------- #

@runtime_checkable
class ITransports(Protocol):
    """Transport abstraction and lifecycle contract."""

    async def initialize(self) -> None: ...

    async def shutdown(self) -> None: ...

    def create(self, transport_type: str, name: str, config: Dict[str, Any]) -> Any: ...

    async def register(self, name: str, transport: Any) -> None: ...

    async def unregister(self, name: str) -> bool: ...

    async def get(self, name: str) -> Optional[Any]: ...

    def list(self) -> List[Dict[str, Any]]: ...

    def available_types(self) -> List[str]: ...


# --------------------------------------------------------------------------- #
#  Profiles
# --------------------------------------------------------------------------- #

@runtime_checkable
class IProfiles(Protocol):
    """C2 malleable profile loading and validation contract."""

    async def initialize(self) -> None: ...

    async def shutdown(self) -> None: ...

    def load(self, path: str) -> Dict[str, Any]: ...

    def validate(self, profile: Dict[str, Any]) -> bool: ...

    def active_name(self) -> Optional[str]: ...

    def list(self) -> List[str]: ...

    def get_active(self) -> Dict[str, Any]: ...


# --------------------------------------------------------------------------- #
#  Engine (top-down orchestrator)
# --------------------------------------------------------------------------- #

@runtime_checkable
class IEngine(Protocol):
    """Central orchestrator contract."""

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def wait_for_shutdown(self) -> None: ...

    def get_status(self) -> Dict[str, Any]: ...
