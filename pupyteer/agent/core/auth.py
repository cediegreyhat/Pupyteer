"""Pupyteer Agent Authentication & TLS.

Provides mutual-TLS certificate handling, JWT token management,
and secure channel setup for agent-server communication.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("pupyteer.agent.auth")


@dataclass
class AuthConfig:
    """Authentication configuration for agent-server channel."""
    # mTLS
    ca_cert: str = ""           # Path to CA certificate
    client_cert: str = ""       # Path to client certificate
    client_key: str = ""        # Path to client private key
    
    # Token auth
    jwt_secret: str = ""        # Shared JWT signing secret
    jwt_algorithm: str = "HS256"  # HS256
    jwt_ttl: int = 3600         # Token lifetime (seconds)
    
    # Registration
    registration_token: str = ""  # One-time registration token
    operator_id: str = ""         # Operator identifier


class AgentAuthenticator:
    """
    Handles agent authentication lifecycle:
    1. mTLS handshake (if certs configured)
    2. JWT token acquisition/refresh
    3. Challenge-response registration
    4. Session token management
    
    TLS is always verified when CA cert is provided (no insecure mode).
    """

    def __init__(self, config: AuthConfig):
        self._config = config
        self._agent_id = str(uuid.uuid4())[:12]
        self._session_token = ""
        self._token_expires = 0.0
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._registration_complete = False

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def is_registered(self) -> bool:
        return self._registration_complete

    @property
    def has_valid_token(self) -> bool:
        return bool(self._session_token and time.time() < self._token_expires)

    def setup_tls(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for mTLS. Verification is always on when CA cert is provided."""
        if not self._config.ca_cert:
            return None

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(self._config.ca_cert)
            
            if self._config.client_cert and self._config.client_key:
                ctx.load_cert_chain(
                    certfile=self._config.client_cert,
                    keyfile=self._config.client_key,
                )
            
            self._ssl_context = ctx
            logger.info("TLS context created (verify=on)")
            return ctx
        except Exception as e:
            logger.error("TLS setup failed: %s", e)
            return None

    def get_ssl_context(self) -> Optional[ssl.SSLContext]:
        return self._ssl_context

    def sign_registration(self, challenge: str) -> str:
        """Sign a server challenge with the registration token."""
        if not self._config.registration_token:
            return ""
        return hmac.new(
            self._config.registration_token.encode(),
            challenge.encode(),
            hashlib.sha256,
        ).hexdigest()

    def create_jwt(self, claims: Optional[Dict[str, Any]] = None) -> str:
        """Create a JWT token (HS256)."""
        import base64

        if not self._config.jwt_secret:
            return ""

        header = {"alg": self._config.jwt_algorithm, "typ": "JWT"}
        now = int(time.time())
        payload = {
            "sub": self._agent_id,
            "iat": now,
            "exp": now + self._config.jwt_ttl,
            "jti": str(uuid.uuid4()),
        }
        if claims:
            payload.update(claims)

        h = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        sig_input = f"{h}.{p}"
        sig = hmac.new(self._config.jwt_secret.encode(), sig_input.encode(), hashlib.sha256).digest()
        s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{sig_input}.{s}"

    def verify_jwt(self, token: str) -> bool:
        """Verify a JWT token signature."""
        if not self._config.jwt_secret:
            return False
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            sig_input = f"{parts[0]}.{parts[1]}"
            expected = hmac.new(self._config.jwt_secret.encode(), sig_input.encode(), hashlib.sha256).digest()
            import base64
            actual = base64.urlsafe_b64decode(parts[2] + "==")
            return hmac.compare_digest(expected, actual)
        except Exception:
            return False

    def set_session_token(self, token: str, ttl: int = 3600) -> None:
        self._session_token = token
        self._token_expires = time.time() + ttl

    def get_authorization_header(self) -> Dict[str, str]:
        if not self.has_valid_token:
            return {}
        return {"Authorization": f"Bearer {self._session_token}"}

    def complete_registration(self) -> None:
        self._registration_complete = True

    def regenerate_agent_id(self) -> None:
        self._agent_id = str(uuid.uuid4())[:12]

    def get_fingerprint(self) -> str:
        """Get CA certificate fingerprint for pinning."""
        if not self._config.ca_cert:
            return ""
        try:
            with open(self._config.ca_cert, "rb") as f:
                data = f.read()
            return hashlib.sha256(data).hexdigest()[:16]
        except Exception:
            return ""
