"""Raw TCP transport for Pupyteer C2.

Features:
- Async TCP using asyncio streams
- Length-prefix framing (4-byte big-endian header)
- Automatic reconnection with exponential backoff and jitter
- Keepalive support
"""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import struct
import time
from typing import Any, Dict, Optional

from pupyteer.server.transports import (
    Transport,
    TransportState,
    TransportStats,
)

logger = logging.getLogger("pupyteer.transports.tcp")


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #


def _apply_jitter(base: float, jitter_pct: float) -> float:
    """Return *base* ± random fraction determined by *jitter_pct* (0.0-1.0)."""
    if jitter_pct <= 0:
        return base
    delta = base * jitter_pct
    return base + random.uniform(-delta, delta)


# --------------------------------------------------------------------------- #
#  TCP Transport
# --------------------------------------------------------------------------- #


class TCPTransport(Transport):
    """Raw TCP transport with length-prefix framing.

    Each message is prefixed with a 4-byte big-endian length header,
    allowing reliable message boundary detection over a persistent
    TCP connection.

    Features:
    - Automatic reconnection with jitter
    - Configurable framing (4-byte length prefix)
    - Keepalive support
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self._host: Optional[str] = None
        self._port: Optional[int] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()
        self._reconnect_task: Optional[asyncio.Task] = None
        self._auto_reconnect = config.get("auto_reconnect", True)
        self._max_retries = config.get("max_retries", 5)
        self._base_delay = config.get("reconnect_delay", 5.0)
        self._jitter = config.get("jitter", 0.3)

    async def connect(self, host: str, port: int, **kwargs) -> bool:
        """Establish a TCP connection with length-prefix framing."""
        async with self._lock:
            return await self._do_connect(host, port, **kwargs)

    async def _do_connect(self, host: str, port: int, **kwargs) -> bool:
        try:
            self.state = TransportState.CONNECTING
            self._host = host
            self._port = port
            timeout = kwargs.get("timeout", self.config.get("connect_timeout", 30))

            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

            # Set TCP keepalive
            sock = self._writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            self.state = TransportState.CONNECTED
            self.stats.connected_at = time.time()
            logger.debug("TCP transport connected to %s:%d", host, port)
            return True
        except Exception as exc:
            self.state = TransportState.ERROR
            self.stats.errors += 1
            logger.error("TCP connect failed: %s", exc)
            return False

    async def _reconnect_loop(self) -> None:
        """Background reconnection with exponential backoff and jitter."""
        retries = 0
        while retries < self._max_retries and self._auto_reconnect:
            delay = self._base_delay * (2**retries)
            delay = _apply_jitter(delay, self._jitter)
            delay = max(0.5, delay)
            logger.info("TCP reconnect attempt %d in %.1fs", retries + 1, delay)
            await asyncio.sleep(delay)
            if self._host and self._port:
                if await self._do_connect(self._host, self._port):
                    logger.info("TCP reconnect successful")
                    return
            retries += 1
        logger.error("TCP reconnect exhausted after %d attempts", self._max_retries)

    async def disconnect(self) -> None:
        async with self._lock:
            self._auto_reconnect = False
            if self._reconnect_task:
                self._reconnect_task.cancel()
                try:
                    await self._reconnect_task
                except asyncio.CancelledError:
                    pass
                self._reconnect_task = None
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
        """Send length-prefixed data."""
        if not self._writer or self.state != TransportState.CONNECTED:
            raise ConnectionError("TCP transport not connected")

        # 4-byte big-endian length prefix
        frame = struct.pack(">I", len(data)) + data

        async with self._lock:
            self._writer.write(frame)
            await self._writer.drain()
            self.stats.bytes_sent += len(frame)
            self.stats.packets_sent += 1
            self.stats.last_activity = time.time()
        return len(frame)

    async def receive(self, timeout: float = 30.0) -> Optional[bytes]:
        """Read a length-prefixed message."""
        if not self._reader or self.state != TransportState.CONNECTED:
            raise ConnectionError("TCP transport not connected")
        try:
            length_data = await asyncio.wait_for(
                self._reader.readexactly(4), timeout=timeout
            )
            msg_len = struct.unpack(">I", length_data)[0]
            if msg_len > 10 * 1024 * 1024:  # 10 MB sanity limit
                raise ValueError(f"Message too large: {msg_len}")
            data = await asyncio.wait_for(
                self._reader.readexactly(msg_len), timeout=timeout
            )
            self.stats.bytes_received += len(data) + 4
            self.stats.packets_received += 1
            self.stats.last_activity = time.time()
            return data
        except asyncio.TimeoutError:
            return None
        except (ConnectionError, OSError) as exc:
            logger.warning("TCP connection lost: %s", exc)
            self.state = TransportState.ERROR
            self.stats.errors += 1
            if self._auto_reconnect and not self._reconnect_task:
                self._reconnect_task = asyncio.create_task(self._reconnect_loop())
            return None

    async def health_check(self) -> bool:
        if self.state != TransportState.CONNECTED:
            return False
        try:
            return self._reader is not None and not self._reader.at_eof()
        except Exception:
            return False

    async def close(self) -> None:
        await self.disconnect()


# --------------------------------------------------------------------------- #
#  Transport Factory
# --------------------------------------------------------------------------- #

TRANSPORT_REGISTRY: Dict[str, type] = {
    "tcp": TCPTransport,
}


def create_transport(
    transport_type: str, name: str, config: Dict[str, Any]
) -> Transport:
    """Factory function to create a transport by type name."""
    cls = TRANSPORT_REGISTRY.get(transport_type.lower())
    if not cls:
        raise ValueError(
            f"Unknown transport type: {transport_type}. "
            f"Available: {list(TRANSPORT_REGISTRY.keys())}"
        )
    return cls(name, config)
