"""Transport Manager — Transport abstraction layer for Pupyteer.

Manages the C2 server's communication listeners. The server binds listeners for
``tcp``, ``http`` and ``https`` (see SUPPORTED_LISTENER_PROTOCOLS); other transport
names a profile may carry (dns, websocket) are agent-side only and are refused
rather than reported as listening. Transport configuration is sourced from the
active C2 profile when available.

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

# The protocols this server can actually bind a listener for. A profile may name
# others (dns, websocket) that only the *agent-side* transport implements; there
# is no server listener for them, so start_listener() refuses rather than showing
# a row that pretends to be listening.
SUPPORTED_LISTENER_PROTOCOLS = ("tcp", "http", "https")


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
        # A base Transport is a configured record, not a bound socket: nothing
        # here has listened yet, so it must not be reported as listening. Real
        # listeners are surfaced separately by TransportManager.list() from what
        # actually bound.
        self._state = "initialized"

    async def shutdown(self) -> None:
        self._state = "stopped"


class TransportManager:
    """
    Manages communication transport listeners.

    Server listeners bind for: tcp, http, https (see SUPPORTED_LISTENER_PROTOCOLS).
    Other transport names (dns, websocket) are agent-side only: there is no server
    listener to bind, so a profile selecting them is refused rather than shown as a
    listening transport that has nothing behind it.

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
        self._http_listener: Optional[Any] = None
        self._tls: Optional[Any] = None  # ListenerTLS once the listeners are up
        # None until a listener is actually running; before that, no registration
        # has been checked against anything.
        self._auth_required: Optional[bool] = None
        # The enrollment file the running listeners check against. Same lifetime
        # as _auth_required: nothing has been checked before a listener exists.
        self._enrollment: Optional[Any] = None
        self._listeners: list = []  # extra listeners (HTTP) shut down with the TCP one
        # Resolved transport intent, so initialize() and start_listener() agree and
        # a refusal can be reported honestly later.
        self._host: str = "0.0.0.0"
        self._port: int = 8443
        self._protocol: str = "tcp"
        # Set when a listener was refused because the protocol cannot be bound.
        # Surfaced by list() as an unavailable row — never as listening.
        self._unsupported_reason: Optional[str] = None
        # True once initialize() has resolved the configured intent. Gates the
        # "configured" row so an untouched manager lists nothing.
        self._configured = False

    def _resolve_transport_settings(self):
        """Return ``(host, port, protocol)`` from the active profile or config.

        Shared by initialize() and start_listener() so the protocol a listener is
        actually asked to honor is the same one the manager reports, whether or not
        initialize() ran first.
        """
        profile_transport: Dict[str, Any] = {}
        if hasattr(self._profiles, 'get_active_transport_config'):
            try:
                profile_transport = self._profiles.get_active_transport_config() or {}
            except Exception:
                profile_transport = {}
        host = profile_transport.get("host", self._config.get("server.host", "0.0.0.0"))
        port = profile_transport.get("port", self._config.get("server.port", 8443))
        protocol = str(profile_transport.get("protocol", "tcp")).lower()
        return host, int(port), protocol

    async def initialize(self) -> None:
        """Record the configured transport intent; bind nothing yet.

        No placeholder transports are created here. A configured protocol is not a
        listening socket, and the earlier stubs — a "dns"/"websocket" row marked
        "listening" with no listener behind it — were exactly the wrong-success this
        manager refuses to report. Real listeners appear in list() only once
        start_listener() has bound them.
        """
        host, port, protocol = self._resolve_transport_settings()
        self._host, self._port, self._protocol = host, port, protocol
        self._configured = True

        if protocol not in SUPPORTED_LISTENER_PROTOCOLS:
            logger.error(
                "Configured transport protocol '%s' has no server listener; agents "
                "built for it will not connect. Supported listener protocols: %s",
                protocol, ", ".join(SUPPORTED_LISTENER_PROTOCOLS))

        logger.info(
            "Transport manager configured (%s:%d) — protocol=%s",
            host, port, protocol,
        )
        self._audit.log_event("transports_initialized", {
            "protocol": protocol,
            "supported": protocol in SUPPORTED_LISTENER_PROTOCOLS,
        })

    async def start_listener(self, session_manager: Any) -> None:
        """Bind the real agent listener(s) for the requested protocol.

        tcp   — TCP AgentListener on the resolved port; the HTTP listener is
                additionally opt-in through server.http_port.
        http  — HTTP agent listener (plaintext) on the resolved port.
        https — HTTP agent listener with the listener TLS on the resolved port.
        other — refused: there is no server listener for it, so nothing is bound
                and list() reports the protocol as unavailable, never listening.
        """
        if self._listener is not None or self._http_listener is not None:
            return  # already started

        host, port, protocol = self._resolve_transport_settings()
        self._host, self._port, self._protocol = host, port, protocol
        self._unsupported_reason = None

        if protocol not in SUPPORTED_LISTENER_PROTOCOLS:
            self._unsupported_reason = (
                f"protocol '{protocol}' has no server listener "
                f"(supported: {', '.join(SUPPORTED_LISTENER_PROTOCOLS)})")
            logger.error(
                "Refusing to start a listener on %s:%d: %s. Nothing is bound — this "
                "port is NOT listening for '%s' agents.",
                host, port, self._unsupported_reason, protocol)
            self._audit.log_event("listener_refused", {
                "host": host, "port": port, "protocol": protocol,
                "reason": self._unsupported_reason}, result="error")
            return

        # One resolution shared by every listener: the certificate a payload pins
        # is decided here, so the listeners must not be able to disagree.
        from pupyteer.server.core.tls import listener_tls
        tls = listener_tls(self._config.get)
        self._tls = tls
        if tls is not None:
            logger.info("Listener TLS active, fingerprint SHA-256 %s", tls.fingerprint)

        # ...and so does the enrollment secret a registration is checked against.
        # All listeners share one ledger: a payload built against one must not be
        # turned away by the other. It is handed to them as the file rather than as
        # a resolved value, so a secret an operator deletes takes effect on the
        # next registration instead of the next restart.
        from pupyteer.server.core.enrollment import listener_ledger
        enrollment = listener_ledger(self._config.get)
        self._auth_required = enrollment is not None
        self._enrollment = enrollment
        if enrollment is None:
            logger.warning(
                "Agent authentication is disabled: anything that reaches %s:%d "
                "can register a session", host, port)
        else:
            enrollment.current()   # generate on first use, while starting up
            if len(enrollment.accepted()) > 1:
                logger.warning(
                    "Accepting %d enrollment secrets; `enrollment show` lists them "
                    "and the ones you no longer need should be revoked",
                    len(enrollment.accepted()))

        if protocol in ("http", "https"):
            await self._start_http_listener(
                session_manager, host, port, tls, enrollment)
            return

        # protocol == "tcp"
        from pupyteer.server.transports.listener import AgentListener
        self._listener = AgentListener(
            config={
                "host": host,
                "port": port,
                "ssl_context": tls.ssl_context if tls else None,
                "enrollment": enrollment,
            },
            session_manager=session_manager,
            audit_logger=self._audit,
        )
        await self._listener.start()
        logger.info("Agent listener started on %s:%d (%s)",
                    host, port, "TLS" if tls else "plaintext")

        # The HTTP listener is additionally opt-in through server.http_port,
        # because port 80/8080 commonly belongs to something else on the box.
        http_port = self._config.get("server.http_port", 0)
        if http_port:
            await self._start_http_listener(
                session_manager, host, int(http_port), tls, enrollment)

    async def _start_http_listener(
        self, session_manager: Any, host: str, port: int,
        tls: Any, enrollment: Any,
    ) -> None:
        """Bind an HTTP(S) agent listener and track it for list()/shutdown."""
        from pupyteer.server.transports.http_listener import HTTPListener
        self._http_listener = HTTPListener(
            config={
                "host": host,
                "port": port,
                "uri": self._config.get("server.http_uri", "/index.html"),
                # server.tls wins over an externally supplied pair: it is the
                # certificate payloads were built to pin.
                "ssl_context": tls.ssl_context if tls else None,
                "enrollment": enrollment,
                "certfile": self._config.get("server.https_cert", "") or None,
                "keyfile": self._config.get("server.https_key", "") or None,
            },
            session_manager=session_manager,
            audit_logger=self._audit,
        )
        await self._http_listener.start()
        self._listeners.append(self._http_listener)
        logger.info("HTTP agent listener started on %s:%d (%s)",
                    host, port, "TLS" if tls else "plaintext")

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

        for extra in self._listeners:
            try:
                await extra.stop()
            except Exception as e:
                logger.warning("Error stopping secondary listener: %s", e)
        self._listeners.clear()
        self._http_listener = None

        for name, transport in self._transports.items():
            try:
                await transport.shutdown()
                logger.debug("Transport %s stopped", name)
            except Exception as e:
                logger.warning("Error stopping transport %s: %s", name, e)
        self._transports.clear()
        # Stopped: nothing is configured-to-bind and nothing is bound, so the
        # manager lists nothing rather than a lingering `configured` row.
        self._configured = False
        self._unsupported_reason = None
        logger.info("Transport manager stopped")

    def set_listener_session_manager(self, session_manager: Any) -> None:
        """Wire a real session manager into the AgentListener.

        Called by the engine after the SessionManager is created, so the
        listener can create/update sessions.
        """
        if self._listener is not None:
            self._listener._session_manager = session_manager
        for extra in self._listeners:
            extra._session_manager = session_manager
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
        if self._http_listener is not None:
            # Its own row, not a merge into the TCP one: the two listeners have
            # different ports and different exposure, and a rejection count that
            # only ever came from the HTTP port is a fact worth locating.
            result.append({
                "name": "agent_listener_http",
                "state": "listening" if self._http_listener.is_running else "stopped",
                "stats": self._http_listener.stats,
            })
        # A protocol that cannot be bound is reported honestly as unavailable —
        # never as listening. This is the row the old fake dns/websocket stubs
        # claimed to be, but it carries the reason instead of a lie.
        if (self._unsupported_reason
                and self._listener is None and self._http_listener is None):
            result.append({
                "name": self._protocol or "unknown",
                "state": "unavailable",
                "stats": {
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "reason": self._unsupported_reason,
                },
            })
        # A supported protocol that has been configured but not yet started is
        # shown as `configured` — the operator sees what the server intends to
        # bind, but it is never reported as `listening` before a socket exists.
        if (self._configured and not self._listener_active
                and self._unsupported_reason is None
                and self._protocol in SUPPORTED_LISTENER_PROTOCOLS):
            result.append({
                "name": self._protocol,
                "state": "configured",
                "stats": {
                    "host": self._host,
                    "port": self._port,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                },
            })
        return result

    def available_types(self) -> List[str]:
        """Transports with a listener the server can actually run."""
        return list(SUPPORTED_LISTENER_PROTOCOLS)

    @property
    def _listener_active(self) -> bool:
        """Whether any real listener is currently bound."""
        return self._listener is not None or self._http_listener is not None

    @property
    def listener(self) -> Optional[Any]:
        """Return the active AgentListener instance, if any."""
        return self._listener or self._http_listener

    @property
    def listener_tls(self) -> Optional[Any]:
        """The TLS material the listeners serve, or None while they are plaintext.

        Reported from what was actually resolved at start, not from config, so a
        console cannot claim TLS it failed to bind.
        """
        if not self._listener_active:
            return None
        return self._tls

    @property
    def listener_requires_auth(self) -> Optional[bool]:
        """Whether registrations are checked against an enrollment secret.

        None while no listener is running, so a status line cannot claim a check
        that nothing is performing.
        """
        if not self._listener_active:
            return None
        return self._auth_required

    @property
    def enrollment(self) -> Optional[Any]:
        """The enrollment ledger the running listeners check, or None.

        None means either no listener is up — nothing is checking registrations
        yet — or agent authentication is switched off, which the console reports
        as the two different things they are.
        """
        if not self._listener_active:
            return None
        return self._enrollment


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
