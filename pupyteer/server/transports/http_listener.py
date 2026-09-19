"""HTTP(S) listener for Pupyteer agent callbacks.

Speaks the same register/checkin/output message set as the TCP AgentListener,
carried one JSON message per HTTP request instead of one per socket line, which
is what the generated agent's HTTPTransport sends:

    POST <uri>                              e.g. /index.html
    Content-Type: application/octet-stream
    <base64(json message)>                  ->  <base64(json reply)>

HTTP is the transport a payload most often needs — egress filtering rarely
permits raw TCP to an arbitrary port, but it permits web traffic. Without this
listener, payloads built with transport=http/https had nothing to talk to and
silently never checked in.

server.tls terminates TLS here with the pinned listener certificate; alternatively
set server.https_cert/https_key for a pair you obtained yourself, or front the
listener with a reverse proxy and point https payloads at that proxy.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import re
import ssl
from typing import Any, Dict, Optional, Tuple

from pupyteer.server.transports.listener import AgentListener

logger = logging.getLogger("pupyteer.transports.http_listener")

# Enough for command output, small enough that a beacon cannot exhaust memory.
MAX_BODY_BYTES = 8 * 1024 * 1024
_REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+) (?P<path>[^ \r\n]+) HTTP/\d(?:\.\d)?\r?\n")


class _NullWriter:
    """Stands in for the TCP connection the per-message HTTP request does not have.

    AgentListener stores the writer on the session state and closes it on stop();
    an HTTP exchange is over the moment the response is written, so nothing is
    held and nothing may be closed.
    """

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


class HTTPListener(AgentListener):
    """AgentListener protocol carried over HTTP POST requests."""

    def __init__(self, config: Dict[str, Any], session_manager: Any, audit_logger: Any):
        self._config = config
        super().__init__(config, session_manager, audit_logger)
        self._uri: str = config.get("uri", "/index.html")

    async def start(self) -> None:
        ssl_context = self._build_ssl_context()
        self._server = await asyncio.start_server(
            self._handle_client, host=self._host, port=self._port,
            ssl=ssl_context, limit=MAX_BODY_BYTES,
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        scheme = "https" if ssl_context else "http"
        logger.info("HTTP agent listener listening on %s://%s%s", scheme, addrs, self._uri)
        self._audit.log_event("http_listener_started", {
            "host": self._host, "port": self._port, "uri": self._uri,
            "tls": ssl_context is not None,
        })

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        # A context the transport manager built from server.tls already carries
        # the certificate payloads were compiled to pin.
        supplied = self._config.get("ssl_context")
        if supplied is not None:
            return supplied
        cert = self._config.get("certfile")
        key = self._config.get("keyfile")
        if not cert or not key:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert, keyfile=key)
        return context

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("HTTP agent listener stopped on %s:%d", self._host, self._port)
        self._audit.log_event("http_listener_stopped", {
            "host": self._host, "port": self._port, "stats": dict(self._stats),
        })

    # ------------------------------------------------------------------
    #  Connection handling
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername") or ("unknown", 0)
        remote = f"{addr[0]}:{addr[1]}"
        self._stats["connections"] += 1
        try:
            status, body = await self._serve_request(reader, remote)
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            writer.close()
            return
        try:
            writer.write(self._render_response(status, body))
            await writer.drain()
            self._stats["bytes_sent"] += len(body)
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _serve_request(
        self, reader: asyncio.StreamReader, remote: str
    ) -> Tuple[int, bytes]:
        """Handle one request; return (http status, response body)."""
        request = await self._read_request(reader)
        if request is None:
            return 400, b"bad request\n"
        method, path, body = request

        if method != "POST":
            return 405, b"method not allowed\n"
        if path != self._uri:
            # A probe of the fronted page looks like any other web server.
            return 404, b"not found\n"

        msg = self._decode_message(body)
        if msg is None:
            return 400, b"bad message\n"

        self._stats["bytes_received"] += len(body)
        try:
            reply = await self._process_message(msg, remote, _NullWriter())
        except Exception as exc:  # never echo internals to the caller
            logger.exception("Error processing %s from %s: %s",
                             msg.get("type"), remote, exc)
            reply = {"type": "error", "message": "internal_error"}

        if reply is None:
            reply = {"type": "ack"}
        return 200, base64.b64encode(json.dumps(reply).encode())

    async def _read_request(
        self, reader: asyncio.StreamReader
    ) -> Optional[Tuple[str, str, bytes]]:
        """Parse the request line, headers and body, with hard size ceilings."""
        head = b""
        while b"\n\n" not in head and b"\r\n\r\n" not in head:
            chunk = await reader.readline()
            if not chunk:
                return None
            head += chunk
            if len(head) > 64 * 1024:
                return None

        match = _REQUEST_LINE.match(head.decode("latin-1"))
        if not match:
            return None
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if not line or b":" not in line:
                continue
            name, _, value = line.partition(b":")
            headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()

        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None

        body = await reader.readexactly(length) if length else b""
        if len(body) < length:
            return None
        return match.group("method"), match.group("path"), body

    @staticmethod
    def _decode_message(body: bytes) -> Optional[Dict[str, Any]]:
        """The agent base64-encodes its JSON; plain JSON is accepted too."""
        raw = body.strip()
        if not raw:
            return None
        try:
            raw = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            pass
        try:
            msg = json.loads(raw.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Malformed HTTP callback body from agent")
            return None
        return msg if isinstance(msg, dict) else None

    @staticmethod
    def _render_response(status: int, body: bytes) -> bytes:
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found",
                  405: "Method Not Allowed"}.get(status, "Error")
        return (
            b"HTTP/1.1 " + str(status).encode() + b" " + reason.encode() + b"\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )


def create_http_listener(
    config: Dict[str, Any], session_manager: Any, audit_logger: Any
) -> HTTPListener:
    return HTTPListener(config, session_manager, audit_logger)
