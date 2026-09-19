"""Transport Manager — Transport abstraction layer for Pupyteer.

Manages communication transport listeners (HTTP, HTTPS, DNS, DoH, DoT, TCP, WebSocket, NamedPipe).
Transport configuration is sourced from the active C2 profile when available.

The core C2 transport is the async TCP ``AgentListener`` which accepts agent
callbacks over a plain TCP socket using a newline-delimited JSON protocol.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger

logger = logging.getLogger("pupyteer.transports")


class Transport:
    """Base class for all transports."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self._config = config
        self._state = "initialized"
        self._stats = {"bytes_sent": 0, "bytes_received": 0, "connections": 0}

    @property
    def state(self) -> str:
        return self._state

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    async def initialize(self) -> None:
        self._state = "listening"

    async def shutdown(self) -> None:
        self._state = "stopped"


class TransportManager:
    """
    Manages communication transport listeners.
    Supports: http, https, dns, doh, dot, tcp, websocket, namedpipe

    The primary transport is the async TCP AgentListener which handles
    agent registration, check-in, and command dispatch.

    Transport configuration is sourced from the active C2 profile when available.
    Falls back to server config settings if no profile is active.
    """

    def __init__(self, config: ConfigManager, profiles: Any, audit: AuditLogger):
        self._config = config
        self._profiles = profiles
        self._audit = audit
        self._transports: Dict[str, Transport] = {}
        self._listener: Optional[Any] = None  # AgentListener instance

    async def initialize(self) -> None:
        """Initialize transport listeners based on profile or config."""
        # Try to use active profile transport config
        profile_transport: Dict[str, Any] = {}
        if hasattr(self._profiles, 'get_active_transport_config'):
            profile_transport = self._profiles.get_active_transport_config()

        host = profile_transport.get("host", self._config.get("server.host", "0.0.0.0"))
        port = profile_transport.get("port", self._config.get("server.port", 8443))
        protocol = profile_transport.get("protocol", "tcp").lower()

        if protocol in ("tcp",):
            # TCP transport — stub for backward compatibility
            # Real TCP listener is started explicitly via start_listener()
            self._transports["tcp"] = Transport("tcp", {"host": host, "port": port})
            await self._transports["tcp"].initialize()
        elif protocol in ("http",):
            self._transports["http"] = Transport("http", {"host": host, "port": port})
            await self._transports["http"].initialize()
        elif protocol in ("https",):
            self._transports["https"] = Transport("https", {"host": host, "port": port})
            await self._transports["https"].initialize()
        elif protocol in ("websocket", "ws", "wss"):
            self._transports["websocket"] = Transport("websocket", {"host": host, "port": port})
            await self._transports["websocket"].initialize()
        elif protocol == "dns":
            self._transports["dns"] = Transport("dns", {"host": host, "port": port})
            await self._transports["dns"].initialize()
        else:
            # Default: start both http and https
            self._transports["http"] = Transport("http", {"host": host, "port": port})
            await self._transports["http"].initialize()
            self._transports["https"] = Transport("https", {"host": host, "port": port})
            await self._transports["https"].initialize()

        logger.info(
            "Transport manager initialized (%s:%d) — protocol=%s, transports: %s",
            host, port, protocol, list(self._transports.keys()),
        )
        self._audit.log_event("transports_initialized", {
            "transports": list(self._transports.keys()),
            "protocol": protocol,
            "listener": self._listener is not None,
        })

    async def start_listener(self, session_manager: Any) -> None:
        """Start the real TCP agent listener.

        Called by the engine after all subsystems are initialized.
        """
        if self._listener is not None:
            return  # already started
        host = self._config.get("server.host", "0.0.0.0")
        port = self._config.get("server.port", 8443)
        from pupyteer.server.transports.listener import AgentListener
        self._listener = AgentListener(
            config={"host": host, "port": port},
            session_manager=session_manager,
            audit_logger=self._audit,
        )
        await self._listener.start()
        logger.info("Agent listener started on %s:%d", host, port)

    async def shutdown(self) -> None:
        """Stop all transport listeners."""
        # Stop the real TCP listener first
        if self._listener is not None:
            try:
                await self._listener.stop()
                logger.debug("Agent listener stopped")
            except Exception as e:
                logger.warning("Error stopping agent listener: %s", e)
            self._listener = None

        for name, transport in self._transports.items():
            try:
                await transport.shutdown()
                logger.debug("Transport %s stopped", name)
            except Exception as e:
                logger.warning("Error stopping transport %s: %s", name, e)
        self._transports.clear()
        logger.info("Transport manager stopped")

    def set_listener_session_manager(self, session_manager: Any) -> None:
        """Wire a real session manager into the AgentListener.

        Called by the engine after the SessionManager is created, so the
        listener can create/update sessions.
        """
        if self._listener is not None:
            self._listener._session_manager = session_manager
            logger.debug("Session manager wired into AgentListener")

    def create(self, transport_type: str, name: str, config: Dict[str, Any]) -> Optional[Transport]:
        """Create a new transport instance."""
        transport = Transport(name, config)
        self._transports[name] = transport
        return transport

    async def register(self, name: str, transport: Transport) -> None:
        """Register an existing transport."""
        self._transports[name] = transport
        self._audit.log_event("transport_registered", {"name": name})

    async def unregister(self, name: str) -> bool:
        """Remove a transport."""
        if name in self._transports:
            await self._transports[name].shutdown()
            del self._transports[name]
            return True
        return False

    async def get(self, name: str) -> Optional[Transport]:
        """Get a transport by name."""
        return self._transports.get(name)

    def list(self) -> List[Dict[str, Any]]:
        """Return all transport configurations."""
        result = [
            {
                "name": name,
                "state": t.state,
                "stats": t.stats,
            }
            for name, t in self._transports.items()
        ]
        if self._listener is not None:
            result.append({
                "name": "agent_listener",
                "state": "listening" if self._listener.is_running else "stopped",
                "stats": self._listener.stats,
            })
        return result

    def available_types(self) -> List[str]:
        """Return available transport types."""
        return ["http", "https", "dns", "doh", "dot", "tcp", "websocket", "namedpipe"]

    @property
    def listener(self) -> Optional[Any]:
        """Return the active AgentListener instance, if any."""
        return self._listener


class _PlaceholderSessionManager:
    """Lightweight stand-in used before the real SessionManager is wired in.

    Raises if any real operations are attempted — this prevents silent failures
    if the engine startup order is wrong.
    """

    def __getattr__(self, name: str):
        raise RuntimeError(
            "AgentListener session manager not yet wired. "
            "Call TransportManager.set_listener_session_manager() after engine startup."
        )
