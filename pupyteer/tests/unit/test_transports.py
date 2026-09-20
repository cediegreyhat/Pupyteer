"""Unit tests for Pupyteer transport abstraction layer.

Tests the Transport ABC, HTTPTransport, HTTPSTransport, TCPTransport,
and the TransportManager integration.
"""
import asyncio
import ssl
import struct
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pupyteer.server.transports import (
    Transport,
    TransportManager,
    TransportState,
    TransportStats,
)
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.fixture
def profiles():
    """Mock profile manager."""
    class MockProfiles:
        def active(self):
            return None
    return MockProfiles()


# ---------------------------------------------------------------------------
# Tests: Transport ABC
# ---------------------------------------------------------------------------


class TestTransportABC:
    """Verify the abstract base class contract."""

    def test_transport_is_abc(self):
        """Transport cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Transport("test", {})

    def test_transport_has_required_methods(self):
        """Transport ABC defines the required interface."""
        assert hasattr(Transport, "connect")
        assert hasattr(Transport, "disconnect")
        assert hasattr(Transport, "send")
        assert hasattr(Transport, "receive")
        assert hasattr(Transport, "health_check")
        assert hasattr(Transport, "close")

    def test_transport_state_enum(self):
        """TransportState enum has expected values."""
        assert TransportState.DISCONNECTED == "disconnected"
        assert TransportState.CONNECTING == "connecting"
        assert TransportState.CONNECTED == "connected"
        assert TransportState.ERROR == "error"

    def test_transport_stats_defaults(self):
        """TransportStats has correct defaults."""
        stats = TransportStats()
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.packets_sent == 0
        assert stats.packets_received == 0
        assert stats.errors == 0
        assert stats.connected_at is None
        assert stats.last_activity is None


# ---------------------------------------------------------------------------
# Tests: TCP Transport
# ---------------------------------------------------------------------------


class TestTCPTransport:
    """Tests for the raw TCP transport."""

    @pytest.fixture
    def tcp_transport(self):
        config = {
            "connect_timeout": 5,
            "auto_reconnect": False,
            "jitter": 0.1,
        }
        from pupyteer.server.transports.tcp_transport import TCPTransport
        return TCPTransport("test-tcp", config)

    @pytest.mark.asyncio
    async def test_tcp_initial_state(self, tcp_transport):
        """TCP transport starts disconnected."""
        assert tcp_transport.state == TransportState.DISCONNECTED
        assert tcp_transport.stats.bytes_sent == 0

    @pytest.mark.asyncio
    async def test_tcp_connect_to_echo_server(self, tcp_transport):
        """TCP transport can connect to a real echo server."""
        # Start a simple echo server
        async def echo_handler(reader, writer):
            data = await reader.read(1024)
            writer.write(data)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            result = await tcp_transport.connect("127.0.0.1", port)
            assert result is True
            assert tcp_transport.state == TransportState.CONNECTED
            assert tcp_transport.stats.connected_at is not None
        finally:
            await tcp_transport.close()
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_tcp_send_receive(self, tcp_transport):
        """TCP transport can send and receive framed data."""
        # Start a length-prefix echo server
        async def echo_handler(reader, writer):
            while True:
                length_data = await reader.readexactly(4)
                msg_len = struct.unpack(">I", length_data)[0]
                data = await reader.readexactly(msg_len)
                response = b"echo:" + data
                frame = struct.pack(">I", len(response)) + response
                writer.write(frame)
                await writer.drain()

        server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            await tcp_transport.connect("127.0.0.1", port)
            test_data = b"hello tcp"
            bytes_sent = await tcp_transport.send(test_data)
            assert bytes_sent > len(test_data)  # Includes frame header

            response = await tcp_transport.receive(timeout=5)
            assert response is not None
            assert b"hello tcp" in response
        finally:
            await tcp_transport.close()
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_tcp_disconnect(self, tcp_transport):
        """TCP transport can disconnect cleanly."""
        async def dummy_handler(reader, writer):
            await asyncio.sleep(10)
            writer.close()

        server = await asyncio.start_server(dummy_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            await tcp_transport.connect("127.0.0.1", port)
            assert tcp_transport.state == TransportState.CONNECTED
            await tcp_transport.disconnect()
            assert tcp_transport.state == TransportState.DISCONNECTED
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_tcp_health_check(self, tcp_transport):
        """TCP health check reflects connection state."""
        assert await tcp_transport.health_check() is False

        async def dummy_handler(reader, writer):
            await asyncio.sleep(10)
            writer.close()

        server = await asyncio.start_server(dummy_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            await tcp_transport.connect("127.0.0.1", port)
            assert await tcp_transport.health_check() is True
        finally:
            await tcp_transport.close()
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_tcp_send_not_connected_raises(self, tcp_transport):
        """Sending without connection raises ConnectionError."""
        with pytest.raises(ConnectionError):
            await tcp_transport.send(b"data")

    @pytest.mark.asyncio
    async def test_tcp_receive_not_connected_raises(self, tcp_transport):
        """Receiving without connection raises ConnectionError."""
        with pytest.raises(ConnectionError):
            await tcp_transport.receive()

    @pytest.mark.asyncio
    async def test_tcp_get_info(self, tcp_transport):
        """get_info returns transport metadata."""
        info = tcp_transport.get_info()
        assert info["name"] == "test-tcp"
        assert info["state"] == "disconnected"
        assert "stats" in info

    @pytest.mark.asyncio
    async def test_tcp_stats_tracking(self, tcp_transport):
        """TCP transport tracks bytes sent/received."""
        async def echo_handler(reader, writer):
            while True:
                length_data = await reader.readexactly(4)
                msg_len = struct.unpack(">I", length_data)[0]
                data = await reader.readexactly(msg_len)
                response = b"ok"
                frame = struct.pack(">I", len(response)) + response
                writer.write(frame)
                await writer.drain()

        server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            await tcp_transport.connect("127.0.0.1", port)
            await tcp_transport.send(b"test")
            await tcp_transport.receive(timeout=5)
            assert tcp_transport.stats.packets_sent >= 1
            assert tcp_transport.stats.packets_received >= 1
            assert tcp_transport.stats.bytes_sent > 0
            assert tcp_transport.stats.bytes_received > 0
        finally:
            await tcp_transport.close()
            server.close()
            await server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: HTTP Transport
# ---------------------------------------------------------------------------


class TestHTTPTransport:
    """Tests for the httpx-based HTTP transport."""

    @pytest.fixture
    def http_transport(self):
        config = {
            "connect_timeout": 5,
            "auto_reconnect": False,
            "jitter": 0.1,
            "host": "127.0.0.1",
            "port": 8080,
        }
        from pupyteer.server.transports.http_transports import HTTPTransport
        return HTTPTransport("test-http", config)

    @pytest.mark.asyncio
    async def test_http_initial_state(self, http_transport):
        """HTTP transport starts disconnected."""
        assert http_transport.state == TransportState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_http_profile_headers(self, http_transport):
        """HTTP transport builds headers from profile."""
        headers = http_transport._profile_headers()
        assert "User-Agent" in headers
        assert "Accept" in headers

    @pytest.mark.asyncio
    async def test_http_custom_headers(self, http_transport):
        """Custom headers from profile are included."""
        http_transport.config["headers"] = {"X-Custom": "test-value"}
        headers = http_transport._profile_headers()
        assert headers["X-Custom"] == "test-value"

    @pytest.mark.asyncio
    async def test_http_uri_rotation(self, http_transport):
        """URI rotation picks from configured list."""
        http_transport.config["uris"] = ["/path1", "/path2", "/path3"]
        uris = set()
        for _ in range(50):
            uris.add(http_transport._next_uri())
        assert len(uris) > 1  # Should rotate

    @pytest.mark.asyncio
    async def test_http_domain_front(self, http_transport):
        """Domain fronting sets separate Host header."""
        http_transport.config["domain_front"] = "front.example.com"
        front = http_transport._front_host()
        assert front == "front.example.com"

    @pytest.mark.asyncio
    async def test_http_send_not_connected_raises(self, http_transport):
        """Sending without connection raises ConnectionError."""
        with pytest.raises(ConnectionError):
            await http_transport.send(b"data")

    @pytest.mark.asyncio
    async def test_http_receive_not_connected_raises(self, http_transport):
        """Receiving without connection raises ConnectionError."""
        with pytest.raises(ConnectionError):
            await http_transport.receive()

    @pytest.mark.asyncio
    async def test_http_get_info(self, http_transport):
        """get_info returns transport metadata."""
        info = http_transport.get_info()
        assert info["name"] == "test-http"
        assert info["state"] == "disconnected"

    @pytest.mark.asyncio
    async def test_http_build_url(self, http_transport):
        """URL building constructs correct base URL."""
        url = http_transport._build_url("/test")
        assert "127.0.0.1" in url
        assert "8080" in url
        assert "/test" in url


# ---------------------------------------------------------------------------
# Tests: HTTPS Transport
# ---------------------------------------------------------------------------


class TestHTTPSTransport:
    """Tests for the httpx-based HTTPS transport."""

    @pytest.fixture
    def https_transport(self):
        config = {
            "connect_timeout": 5,
            "auto_reconnect": False,
            "jitter": 0.1,
            "host": "127.0.0.1",
            "port": 8443,
            "verify_ssl": False,
        }
        from pupyteer.server.transports.http_transports import HTTPSTransport
        return HTTPSTransport("test-https", config)

    @pytest.mark.asyncio
    async def test_https_initial_state(self, https_transport):
        """HTTPS transport starts disconnected."""
        assert https_transport.state == TransportState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_https_build_url(self, https_transport):
        """HTTPS URL uses https scheme."""
        https_transport._base_url = "https://127.0.0.1:8443"
        url = https_transport._build_url("/api")
        assert url.startswith("https://")

    @pytest.mark.asyncio
    async def test_https_ssl_context(self, https_transport):
        """SSL context is built from config."""
        ctx = https_transport._build_ssl_context()
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_https_ssl_context_with_ciphers(self, https_transport):
        """SSL context respects cipher configuration."""
        https_transport.config["ciphers"] = "HIGH:!aNULL:!MD5"
        ctx = https_transport._build_ssl_context()
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_https_pin_hash_storage(self, https_transport):
        """Certificate pin hash is stored after building SSL context."""
        https_transport.config["pin"] = "ab:cd:ef:12:34"
        https_transport._build_ssl_context()
        assert https_transport._pinned_hash == "abcdef1234"


# ---------------------------------------------------------------------------
# Tests: Transport Manager
# ---------------------------------------------------------------------------


class TestTransportManager:
    """Tests for the TransportManager."""

    @pytest.fixture
    def manager(self, config, profiles, audit):
        return TransportManager(config, profiles, audit)

    @pytest.mark.asyncio
    async def test_manager_initialize(self, manager):
        """Manager initializes and registers transports."""
        await manager.initialize()
        assert "tcp" in manager.available_types()

    @pytest.mark.asyncio
    async def test_manager_register_type(self, manager):
        """Custom transport types can be registered."""
        class CustomTransport(Transport):
            async def connect(self, host, port, **kwargs): return True
            async def disconnect(self): pass
            async def send(self, data): return len(data)
            async def receive(self, timeout=30): return None
            async def health_check(self): return True
            async def close(self): pass

        manager.register_type("custom", CustomTransport)
        assert "custom" in manager.available_types()

    @pytest.mark.asyncio
    async def test_manager_register_type_must_be_subclass(self, manager):
        """register_type rejects non-Transport classes."""
        with pytest.raises(TypeError):
            manager.register_type("bad", dict)

    @pytest.mark.asyncio
    async def test_manager_create_transport(self, manager):
        """Manager creates transports by type."""
        await manager.initialize()
        transport = manager.create("tcp", "test", {"auto_reconnect": False})
        assert transport is not None
        assert transport.name == "test"

    @pytest.mark.asyncio
    async def test_manager_create_unknown_raises(self, manager):
        """Creating unknown transport type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown transport type"):
            manager.create("unknown", "test", {})

    @pytest.mark.asyncio
    async def test_manager_register_and_get(self, manager):
        """Transports can be registered and retrieved."""
        await manager.initialize()
        transport = manager.create("tcp", "test", {"auto_reconnect": False})
        await manager.register("test", transport)
        retrieved = await manager.get("test")
        assert retrieved is transport

    @pytest.mark.asyncio
    async def test_manager_unregister(self, manager):
        """Transports can be unregistered."""
        await manager.initialize()
        transport = manager.create("tcp", "test", {"auto_reconnect": False})
        await manager.register("test", transport)
        result = await manager.unregister("test")
        assert result is True
        assert await manager.get("test") is None

    @pytest.mark.asyncio
    async def test_manager_list(self, manager):
        """Manager lists all registered transports."""
        await manager.initialize()
        transport = manager.create("tcp", "test", {"auto_reconnect": False})
        await manager.register("test", transport)
        transports = manager.list()
        assert len(transports) >= 1

    @pytest.mark.asyncio
    async def test_manager_shutdown(self, manager):
        """Manager shuts down all transports."""
        await manager.initialize()
        transport = manager.create("tcp", "test", {"auto_reconnect": False})
        await manager.register("test", transport)
        await manager.shutdown()
        assert len(manager.list()) == 0

    @pytest.mark.asyncio
    async def test_manager_available_types(self, manager):
        """Manager reports available transport types."""
        await manager.initialize()
        types = manager.available_types()
        assert "tcp" in types
        assert "http" in types
        assert "https" in types


# ---------------------------------------------------------------------------
# Tests: Transport Factory
# ---------------------------------------------------------------------------


class TestTransportFactory:
    """Tests for the transport factory functions."""

    def test_create_tcp_transport(self):
        """Factory creates TCP transport."""
        from pupyteer.server.transports.tcp_transport import create_transport
        t = create_transport("tcp", "test", {"auto_reconnect": False})
        assert t is not None
        assert t.name == "test"

    def test_create_http_transport(self):
        """Factory creates HTTP transport."""
        from pupyteer.server.transports.http_transports import create_transport
        t = create_transport("http", "test", {})
        assert t is not None

    def test_create_https_transport(self):
        """Factory creates HTTPS transport."""
        from pupyteer.server.transports.http_transports import create_transport
        t = create_transport("https", "test", {"verify_ssl": False})
        assert t is not None

    def test_create_unknown_raises(self):
        """Factory raises for unknown transport type."""
        from pupyteer.server.transports.tcp_transport import create_transport
        with pytest.raises(ValueError, match="Unknown transport type"):
            create_transport("unknown", "test", {})


# ---------------------------------------------------------------------------
# Tests: Jitter
# ---------------------------------------------------------------------------


class TestJitter:
    """Tests for jitter helpers."""

    def test_apply_jitter_zero(self):
        """Zero jitter returns base value."""
        from pupyteer.server.transports.http_transports import _apply_jitter
        assert _apply_jitter(10.0, 0.0) == 10.0

    def test_apply_jitter_range(self):
        """Jitter applies within expected range."""
        from pupyteer.server.transports.http_transports import _apply_jitter
        base = 10.0
        jitter = 0.3
        for _ in range(100):
            result = _apply_jitter(base, jitter)
            assert base * (1 - jitter) <= result <= base * (1 + jitter)

    def test_random_user_agent(self):
        """Random user agent returns a string."""
        from pupyteer.server.transports.http_transports import _random_user_agent
        ua = _random_user_agent()
        assert isinstance(ua, str)
        assert len(ua) > 0

    def test_rotate_uris(self):
        """URI rotation picks from list."""
        from pupyteer.server.transports.http_transports import _rotate_uris
        uris = ["/a", "/b", "/c"]
        result = _rotate_uris(uris)
        assert result in uris

    def test_rotate_uris_empty(self):
        """URI rotation defaults to / for empty list."""
        from pupyteer.server.transports.http_transports import _rotate_uris
        assert _rotate_uris([]) == "/"


# ---------------------------------------------------------------------------
# Tests: Profile Integration
# ---------------------------------------------------------------------------


class TestProfileIntegration:
    """Tests for transport-to-profile wiring."""

    @pytest.mark.asyncio
    async def test_create_from_profile_tcp(self):
        """Manager creates TCP transport from profile."""
        config = ConfigManager()
        audit = AuditLogger(config)

        class MockProfile:
            transport_protocol = "tcp"
            def as_dict(self):
                return {
                    "transport": {"protocol": "tcp", "host": "127.0.0.1", "port": 0},
                    "session": {"jitter": 0.2},
                }

        class MockProfiles:
            def active(self):
                return MockProfile()

        manager = TransportManager(config, MockProfiles(), audit)
        await manager.initialize()

        profile = MockProfile()
        # Use port 0 to let OS assign — but connect will fail, so we test config extraction
        transport = manager.create("tcp", "profile-tcp", {
            "host": "127.0.0.1",
            "port": 0,
            "jitter": 0.2,
            "auto_reconnect": False,
        })
        assert transport is not None
        assert transport.name == "profile-tcp"

    @pytest.mark.asyncio
    async def test_create_from_profile_http(self):
        """Manager creates HTTP transport from profile."""
        config = ConfigManager()
        audit = AuditLogger(config)

        manager = TransportManager(config, None, audit)
        await manager.initialize()

        transport = manager.create("http", "profile-http", {
            "host": "127.0.0.1",
            "port": 8080,
            "jitter": 0.3,
            "auto_reconnect": False,
        })
        assert transport is not None
        assert transport.name == "profile-http"


class TestListenerTlsResolution:
    """server.tls decides what both listeners serve and what payloads pin."""

    def test_disabled_tls_produces_no_material_and_no_files(self, tmp_path):
        from pupyteer.server.core.tls import listener_tls

        config = ConfigManager()
        config.set("server.tls", False)
        config.set("server.tls_cert", str(tmp_path / "listener.crt"))
        assert listener_tls(config.get) is None
        assert not any(tmp_path.iterdir()), "TLS off must not generate a certificate"

    def test_a_string_true_from_a_config_file_enables_it(self, tmp_path):
        """Environment overrides and hand-edited YAML arrive as strings."""
        from pupyteer.server.core.tls import listener_tls

        config = ConfigManager()
        config.set("server.tls", "true")
        config.set("server.tls_cert", str(tmp_path / "listener.crt"))
        config.set("server.tls_key", str(tmp_path / "listener.key"))
        material = listener_tls(config.get)
        assert material is not None
        assert "BEGIN CERTIFICATE" in material.cert_pem
        assert len(material.fingerprint) == 64

    def test_a_half_pair_is_an_error_not_a_new_certificate(self, tmp_path):
        """Silently replacing a pinned certificate looks like dead agents."""
        from pupyteer.server.core.tls import ensure_listener_cert

        cert = tmp_path / "listener.crt"
        key = tmp_path / "listener.key"
        ensure_listener_cert(str(cert), str(key))
        key.unlink()

        with pytest.raises(FileNotFoundError) as caught:
            ensure_listener_cert(str(cert), str(key))
        assert "incomplete" in str(caught.value)
        assert cert.exists(), "the certificate fielded payloads pin must survive"


class TestHandshakeRefusalReporting:
    """A TLS listener's failure mode is silence, so refusals have to be loud —
    without letting a port sweep turn that noise into an audit log that is all
    noise. The count is exact; the log line is thinned per peer.
    """

    class _Refused:
        """A connection whose peer sends something that is not a ClientHello."""

        def __init__(self, peer):
            self._peer = peer

        def get_extra_info(self, name, default=None):
            return self._peer

        async def start_tls(self, context, *, ssl_handshake_timeout=None):
            raise ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")

    @staticmethod
    def _listener(tmp_path):
        from pupyteer.server.transports.listener import AgentListener

        config = ConfigManager()
        config.set("audit.log_file", str(tmp_path / "audit.json"))
        audit = AuditLogger(config)
        return AgentListener({"ssl_context": object()}, None, audit), audit

    @pytest.mark.asyncio
    async def test_a_flood_from_one_peer_is_counted_but_written_once(self, tmp_path):
        listener, audit = self._listener(tmp_path)
        peer = ("203.0.113.9", 5555)

        for _ in range(25):
            assert await listener._upgrade_tls(None, self._Refused(peer)) is False

        assert listener._stats["handshakes_refused"] == 25
        rows = audit.query(event="handshake_refused")
        assert len(rows) == 1, (
            "25 refusals from one host must not cost 25 audit entries: the log "
            "rotates, so a passerby would choose what the operator keeps"
        )
        # The live counter is the exact total; the durable trace just has to say
        # who was refused and why, or a stranded payload leaves nothing to read.
        assert rows[0]["details"]["peer"].startswith("203.0.113.9")
        assert "WRONG_VERSION_NUMBER" in rows[0]["details"]["reason"]

    @pytest.mark.asyncio
    async def test_a_peer_that_keeps_trying_gets_a_line_again_later(
        self, tmp_path, monkeypatch
    ):
        """Thinning is not once-ever: the next window re-reports, with the tally."""
        import pupyteer.server.transports.listener as listener_module

        listener, audit = self._listener(tmp_path)
        refused = self._Refused(("203.0.113.9", 5555))
        clock = [1000.0]
        monkeypatch.setattr(listener_module.time, "monotonic", lambda: clock[0])

        await listener._upgrade_tls(None, refused)
        for _ in range(3):
            clock[0] += 1.0
            await listener._upgrade_tls(None, refused)
        assert len(audit.query(event="handshake_refused")) == 1

        clock[0] += 240.0
        await listener._upgrade_tls(None, refused)
        again = audit.query(event="handshake_refused")
        assert len(again) == 2, "the second window reported nothing"
        # Both lines were written in the same wall-clock second, so query order
        # proves nothing; pick the line by the total it reports.
        later = next(e for e in again if e["details"]["count"] == 5)
        assert later["details"]["suppressed"] == 3, (
            "the refusals this line stands for have to be named, or the count "
            "and the log disagree about what happened"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
