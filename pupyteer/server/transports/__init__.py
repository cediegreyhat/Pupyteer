"""Transport abstraction layer for Pupyteer C2."""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger

logger = logging.getLogger("pupyteer.transports")


class TransportState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class TransportStats:
    """Runtime transport statistics."""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    errors: int = 0
    connected_at: Optional[float] = None
    last_activity: Optional[float] = None


class Transport(ABC):
    """
    Abstract transport interface.
    
    All transport implementations must provide:
    - connect() / disconnect() / close()
    - send() / receive()
    - health_check()
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.state = TransportState.DISCONNECTED
        self.stats = TransportStats()
        self._extra: Dict[str, Any] = {}

    @abstractmethod
    async def connect(self, host: str, port: int, **kwargs) -> bool:
        """Establish connection to remote endpoint."""
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully disconnect from remote endpoint."""
        ...

    @abstractmethod
    async def send(self, data: bytes) -> int:
        """Send data. Returns bytes sent."""
        ...

    @abstractmethod
    async def receive(self, timeout: float = 30.0) -> Optional[bytes]:
        """Receive data with optional timeout."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify transport is healthy and responsive."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close transport and release all resources."""
        ...

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "stats": {
                "bytes_sent": self.stats.bytes_sent,
                "bytes_received": self.stats.bytes_received,
                "packets_sent": self.stats.packets_sent,
                "packets_received": self.stats.packets_received,
                "errors": self.stats.errors,
            },
        }


class TCPTransport(Transport):
    """Basic TCP socket transport."""

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self._host: Optional[str] = None
        self._port: Optional[int] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    async def connect(self, host: str, port: int, **kwargs) -> bool:
        try:
            self.state = TransportState.CONNECTING
            self._host = host
            self._port = port
            timeout = kwargs.get("timeout", self.config.get("connect_timeout", 30))
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            self.state = TransportState.CONNECTED
            self.stats.connected_at = time.time()
            return True
        except Exception as exc:
            self.state = TransportState.ERROR
            self.stats.errors += 1
            logger.error("TCP connect failed: %s", exc)
            return False

    async def disconnect(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        self._writer = None
        self.state = TransportState.DISCONNECTED

    async def send(self, data: bytes) -> int:
        if not self._writer or self.state != TransportState.CONNECTED:
            raise ConnectionError("Transport not connected")
        self._writer.write(data)
        await self._writer.drain()
        self.stats.bytes_sent += len(data)
        self.stats.packets_sent += 1
        self.stats.last_activity = time.time()
        return len(data)

    async def receive(self, timeout: float = 30.0) -> Optional[bytes]:
        if not self._reader or self.state != TransportState.CONNECTED:
            raise ConnectionError("Transport not connected")
        try:
            data = await asyncio.wait_for(
                self._reader.read(65536), timeout=timeout
            )
            self.stats.bytes_received += len(data)
            self.stats.packets_received += 1
            self.stats.last_activity = time.time()
            return data
        except asyncio.TimeoutError:
            return None

    async def health_check(self) -> bool:
        if self.state != TransportState.CONNECTED:
            return False
        try:
            # Simple health check — attempt a zero-length read with short timeout
            if self._reader and self._writer:
                return not self._reader.at_eof()
        except Exception:
            pass
        return False

    async def close(self) -> None:
        await self.disconnect()


class WebSocketTransport(Transport):
    """Client-side WebSocket transport.

    This is an outbound *dialer*: it connects to a remote ``ws://``/``wss://``
    endpoint and speaks over that client socket. It is not a server listener and
    binds nothing — the server only accepts callbacks over the tcp/http/https
    listeners in ``transports/manager.py``. Uses the ``websockets`` client.
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self._ws = None

    async def connect(self, host: str, port: int, **kwargs) -> bool:
        try:
            import websockets
            self.state = TransportState.CONNECTING
            uri = kwargs.get("uri", f"ws://{host}:{port}/ws")
            self._ws = await websockets.connect(uri)
            self.state = TransportState.CONNECTED
            self.stats.connected_at = time.time()
            return True
        except Exception as exc:
            self.state = TransportState.ERROR
            self.stats.errors += 1
            logger.error("WebSocket connect failed: %s", exc)
            return False

    async def disconnect(self) -> None:
        if self._ws:
            await self._ws.close()
        self.state = TransportState.DISCONNECTED

    async def send(self, data: bytes) -> int:
        if not self._ws:
            raise ConnectionError("Not connected")
        await self._ws.send(data)
        self.stats.bytes_sent += len(data)
        self.stats.packets_sent += 1
        return len(data)

    async def receive(self, timeout: float = 30.0) -> Optional[bytes]:
        if not self._ws:
            raise ConnectionError("Not connected")
        try:
            data = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
            self.stats.bytes_received += len(data)
            self.stats.packets_received += 1
            return data if isinstance(data, bytes) else data.encode()
        except asyncio.TimeoutError:
            return None

    async def health_check(self) -> bool:
        return self.state == TransportState.CONNECTED and self._ws is not None

    async def close(self) -> None:
        await self.disconnect()


class TransportManager:
    """
    Manages transport lifecycle and registry.
    
    Provides a unified interface for creating, initializing, and 
    tearing down transports based on C2 profiles.
    """

    TRANSPORT_REGISTRY: Dict[str, type] = {
        "tcp": TCPTransport,
        "websocket": WebSocketTransport,
        "ws": WebSocketTransport,
    }

    def __init__(self, config: ConfigManager, profiles: Any, audit: AuditLogger):
        self._config = config
        self._profiles = profiles
        self._audit = audit
        self._active: Dict[str, Transport] = {}
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Transport manager ready — register extended transports."""
        # Register httpx-based HTTP/HTTPS transports
        try:
            from pupyteer.server.transports.http_transports import (
                HTTPTransport,
                HTTPSTransport,
            )
            self.TRANSPORT_REGISTRY["http"] = HTTPTransport
            self.TRANSPORT_REGISTRY["https"] = HTTPSTransport
            logger.info("HTTP/HTTPS transports registered (httpx-based)")
        except ImportError:
            logger.warning("httpx not available — HTTP/HTTPS transports disabled")

        # Register raw TCP transport (extended version)
        try:
            from pupyteer.server.transports.tcp_transport import TCPTransport as ExtTCPTransport
            self.TRANSPORT_REGISTRY["tcp"] = ExtTCPTransport
            logger.info("Extended TCP transport registered")
        except ImportError:
            pass  # Use default TCPTransport

        logger.info("Transport manager initialized (transports: %s)", list(self.TRANSPORT_REGISTRY.keys()))

    async def shutdown(self) -> None:
        """Close all active transports."""
        for name, transport in list(self._active.items()):
            await transport.close()
        self._active.clear()
        logger.info("Transport manager stopped")

    def create(self, transport_type: str, name: str, config: Dict[str, Any]) -> Transport:
        """Create a transport instance by type name."""
        cls = self.TRANSPORT_REGISTRY.get(transport_type.lower())
        if not cls:
            raise ValueError(f"Unknown transport type: {transport_type}. Available: {list(self.TRANSPORT_REGISTRY.keys())}")
        transport = cls(name, config)
        self._audit.log_event("transport_created", {"type": transport_type, "name": name})
        return transport

    async def register(self, name: str, transport: Transport) -> None:
        """Register an active transport."""
        self._active[name] = transport

    async def unregister(self, name: str) -> bool:
        """Remove and close a registered transport."""
        if name in self._active:
            await self._active[name].close()
            del self._active[name]
            return True
        return False

    async def get(self, name: str) -> Optional[Transport]:
        """Retrieve a registered transport."""
        return self._active.get(name)

    def list(self) -> List[Dict[str, Any]]:
        """List all registered transports."""
        return [t.get_info() for t in self._active.values()]

    def available_types(self) -> List[str]:
        """List available transport type names."""
        return list(self.TRANSPORT_REGISTRY.keys())

    def register_type(self, name: str, cls: type) -> None:
        """Register a custom transport implementation."""
        if not issubclass(cls, Transport):
            raise TypeError(f"{cls} must be a subclass of Transport")
        self.TRANSPORT_REGISTRY[name.lower()] = cls

    async def create_from_profile(self, profile: Any) -> Optional[Transport]:
        """Create and initialize a transport from a C2 profile.
        
        Reads transport configuration from the profile and creates
        the appropriate transport instance.
        """
        try:
            transport_type = profile.transport_protocol if hasattr(profile, 'transport_protocol') else "tcp"
            transport_config = {}
            
            # Extract transport config from profile
            if hasattr(profile, 'as_dict'):
                profile_dict = profile.as_dict()
                transport_config = profile_dict.get("transport", {})
                session_config = profile_dict.get("session", {})
                # Merge session jitter into transport config
                if "jitter" in session_config:
                    transport_config["jitter"] = session_config["jitter"]
            
            name = f"profile-{transport_type}"
            transport = self.create(transport_type, name, transport_config)
            
            # Auto-connect if host/port available
            host = transport_config.get("host", "127.0.0.1")
            port = transport_config.get("port", 8443)
            await transport.connect(host, port)
            await self.register(name, transport)
            
            self._audit.log_event("transport_profile_connected", {
                "type": transport_type,
                "host": host,
                "port": port,
            })
            return transport
        except Exception as exc:
            logger.error("Failed to create transport from profile: %s", exc)
            return None
