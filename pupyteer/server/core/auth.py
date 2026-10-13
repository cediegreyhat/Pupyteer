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

# Password hashing parameters. PBKDF2-HMAC-SHA256 with a per-operator random
# salt. Iterations chosen for a balance of security and CPU on modest hosts;
# the count is stored with the hash so it can be raised later without breaking
# existing credentials.
_PBKDF2_ALGO = "pbkdf2_sha256"
_PBKDF2_ITERS = 240_000
_SALT_BYTES = 16


def hash_password(password: str, *, iters: int = _PBKDF2_ITERS) -> str:
    """Return a self-describing salted PBKDF2 hash.

    Format: ``pbkdf2_sha256$<iters>$<salt_hex>$<hash_hex>``.
    The algorithm and iteration count are embedded so verification stays
    correct even if defaults change later.
    """
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return f"{_PBKDF2_ALGO}${iters}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify *password* against a stored hash.

    Accepts the new ``pbkdf2_sha256$...`` format. Legacy bare sha256 hex
    hashes (from the old cleartext-config model) are still accepted so
    existing deployments don't lock out — but a warning is emitted because
    those are unsalted and weak.
    """
    if not stored:
        return False
    if stored.startswith(f"{_PBKDF2_ALGO}$"):
        try:
            _, iters_s, salt_hex, hash_hex = stored.split("$", 3)
            iters = int(iters_s)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except (ValueError, TypeError):
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(dk, expected)
    # Legacy unsalted sha256 — accept but warn (migrate by re-adding operator).
    if len(stored) == 64 and all(c in "0123456789abcdef" for c in stored.lower()):
        legacy = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy.lower(), stored.lower())
    return False


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
        self._credentials: Dict[str, str] = {}  # username -> pbkdf2 hash
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load operator credential hashes from config.

        Accepts either pre-hashed values (``pbkdf2_sha256$...`` or legacy
        sha256 hex) in ``security.operator_hashes``, OR cleartext passwords in
        ``security.operators`` which are hashed in-memory at load (never
        persisted cleartext). Cleartext config is discouraged — prefer
        ``operator_hashes`` or a secrets manager.
        """
        hashes = self._config.get("security.operator_hashes", {})
        if isinstance(hashes, dict):
            for user, stored in hashes.items():
                if isinstance(stored, str) and stored:
                    self._credentials[user] = stored

        operators = self._config.get("security.operators", {})
        if isinstance(operators, dict):
            for user, password in operators.items():
                if not isinstance(password, str) or not password:
                    continue
                # If the value already looks like a hash, keep it; else hash it.
                if password.startswith(f"{_PBKDF2_ALGO}$") or (
                    len(password) == 64
                    and all(c in "0123456789abcdef" for c in password.lower())
                ):
                    self._credentials[user] = password
                else:
                    self._credentials[user] = hash_password(password)

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

        if not verify_password(password, expected_hash):
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
        """Add a new operator credential (stored as a salted PBKDF2 hash)."""
        self._credentials[username] = hash_password(password)
        self._audit.log_event(
            "auth_operator_added", {"username": username, "permissions": list(permissions or {"read", "execute"})}
        )
