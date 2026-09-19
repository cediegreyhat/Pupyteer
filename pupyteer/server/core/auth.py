"""Authentication and authorization layer for Pupyteer operators."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger

logger = logging.getLogger("pupyteer.auth")


@dataclass
class OperatorSession:
    """Represents an authenticated operator session."""
    operator: str
    token: str
    issued_at: float
    expires_at: float
    permissions: Set[str] = field(default_factory=lambda: {"read", "execute"})

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at


class AuthLayer:
    """
    Manages operator authentication and token-based authorization.

    Uses simple file-backed credential store (hashed passwords).
    Production deployments should integrate with existing identity providers.
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._ttl: int = config.get("security.token_ttl", 3600)
        self._max_failed: int = config.get("security.max_failed_logins", 5)
        self._sessions: Dict[str, OperatorSession] = {}
        self._failed_attempts: Dict[str, int] = {}
        self._credentials: Dict[str, str] = {}  # username -> sha256 hash
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load operator credentials from config (for development)."""
        operators = self._config.get("security.operators", {})
        if isinstance(operators, dict):
            for user, password in operators.items():
                self._credentials[user] = hashlib.sha256(password.encode()).hexdigest()

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate an operator. Returns a session token on success, None on failure.

        Implements basic rate-limiting via max_failed_logins.
        """
        # Check lockout
        if self._failed_attempts.get(username, 0) >= self._max_failed:
            self._audit.log_event(
                "auth_lockout", {"username": username}, result="denied"
            )
            logger.warning("Auth locked out for user: %s", username)
            return None

        expected_hash = self._credentials.get(username)
        if not expected_hash:
            self._audit.log_event(
                "auth_unknown_user", {"username": username}, result="denied"
            )
            return None

        provided = hashlib.sha256(password.encode()).hexdigest()
        if not hmac.compare_digest(expected_hash, provided):
            self._failed_attempts[username] = self._failed_attempts.get(username, 0) + 1
            self._audit.log_event(
                "auth_failed",
                {"username": username, "attempts": self._failed_attempts[username]},
                result="denied",
            )
            return None

        # Success
        self._failed_attempts[username] = 0
        token = secrets.token_hex(32)
        now = time.time()
        self._sessions[token] = OperatorSession(
            operator=username,
            token=token,
            issued_at=now,
            expires_at=now + self._ttl,
        )
        self._audit.log_event(
            "auth_success", {"username": username, "token": token[:8] + "..."}, result="ok"
        )
        return token

    def authorize(self, token: str, required_permission: str = "read") -> bool:
        """Check if a token is valid and has the required permission."""
        session = self._sessions.get(token)
        if not session or session.expired:
            if session and session.expired:
                del self._sessions[token]
            return False
        return required_permission in session.permissions

    def get_operator(self, token: str) -> Optional[str]:
        """Return the operator name for a valid token."""
        session = self._sessions.get(token)
        if session and not session.expired:
            return session.operator
        return None

    def revoke(self, token: str) -> bool:
        """Revoke a session token."""
        if token in self._sessions:
            session = self._sessions.pop(token)
            self._audit.log_event(
                "auth_revoke", {"operator": session.operator, "token": token[:8] + "..."}
            )
            return True
        return False

    def active_sessions(self) -> Dict[str, OperatorSession]:
        """Return all non-expired sessions."""
        now = time.time()
        expired = [t for t, s in self._sessions.items() if s.expires_at < now]
        for t in expired:
            del self._sessions[t]
        return dict(self._sessions)

    def add_operator(self, username: str, password: str, permissions: Optional[Set[str]] = None) -> None:
        """Add a new operator credential."""
        self._credentials[username] = hashlib.sha256(password.encode()).hexdigest()
        self._audit.log_event(
            "auth_operator_added", {"username": username, "permissions": list(permissions or {"read", "execute"})}
        )
