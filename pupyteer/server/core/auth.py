"""Authentication and authorization layer for Pupyteer operators.

Two things are checked here and they are not the same question. `authenticate`
answers *who is this* and hands back a token; `authorize` answers *may this token
do that*. The token is the credential the console carries, and the permission set
on it is frozen at login from the stored role — so nothing that happens after a
login can widen what a session may do, including editing the config that names
the operator in the audit log.

Credentials themselves live in `pupyteer.server.core.operators`: this class holds
no password material, only what a password proved.
"""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.core.operators import (
    DEFAULT_OPERATORS_FILE, OperatorRecord, OperatorStore, WeakCredential,
)
from pupyteer.server.core.rbac import ROLE_PERMISSIONS, Role

logger = logging.getLogger("pupyteer.auth")

#: How long a wrong-password counter stays armed before it is forgotten. The
#: lockout used to be forever, which meant five typos locked an operator out of
#: their own server with no way back except editing the file by hand.
DEFAULT_LOCKOUT_SECONDS = 300


@dataclass
class OperatorSession:
    """Represents an authenticated operator session."""
    operator: str
    token: str
    issued_at: float
    expires_at: float
    role: str = Role.VIEWER.value
    #: Snapshot of the role's permissions at login. Deliberately a copy: an
    #: operator who is added to a bigger role later should have to log in again.
    permissions: Set[str] = field(default_factory=lambda: set(ROLE_PERMISSIONS[Role.VIEWER]))

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at


def permissions_for(role: Role) -> Set[str]:
    """The permission set a role grants, as the copy stored on a session."""
    return set(ROLE_PERMISSIONS[Role(role)])


class AuthLayer:
    """
    Manages operator authentication and token-based authorization.

    Backed by the salted-hash credential file, which is written only when an
    operator is added. A server with no operators is not an error and not an open
    door: it is `has_operators == False`, and the console turns that into a
    generated first credential it shows once.
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._ttl: int = int(config.get("security.token_ttl", 3600) or 3600)
        self._max_failed: int = int(config.get("security.max_failed_logins", 5) or 5)
        self._lockout_seconds: float = float(
            config.get("security.lockout_seconds", DEFAULT_LOCKOUT_SECONDS)
            or DEFAULT_LOCKOUT_SECONDS)
        self._operators = OperatorStore(str(
            config.get("security.operators_file") or DEFAULT_OPERATORS_FILE))
        self._sessions: Dict[str, OperatorSession] = {}
        self._failed: Dict[str, List[float]] = {}

    # ------------------------------------------------------------------ #
    #  Credentials                                                        #
    # ------------------------------------------------------------------ #

    @property
    def operators(self) -> OperatorStore:
        """The credential store, for `operator list` and role changes."""
        return self._operators

    @property
    def has_operators(self) -> bool:
        return self._operators.exists

    @property
    def require_auth(self) -> bool:
        """Whether the console has to be logged in at all.

        Read here rather than at each call site so there is one answer. The
        default is on: `security.require_auth: false` is a written-down decision
        to run the console with whoever holds the keyboard as admin.
        """
        value = self._config.get("security.require_auth")
        if value is None:
            return True
        if isinstance(value, str):
            return value.strip().lower() not in ("0", "false", "no", "off")
        return bool(value)

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate an operator. Returns a session token on success, None on failure.

        Unknown name and wrong password are the same answer. The failure counter
        is per name, so an attacker cannot tell the two apart by timing either —
        both pay the same scrypt — and a locked-out name is refused before the
        password is even looked at.
        """
        now = time.monotonic()
        attempts = [t for t in self._failed.get(username, []) if now - t < self._lockout_seconds]
        if len(attempts) >= self._max_failed:
            self._failed[username] = attempts
            self._audit.log_event(
                "auth_lockout", {"username": username,
                                 "retry_in": int(self._lockout_seconds - (now - attempts[0]))},
                result="denied",
            )
            logger.warning("Auth locked out for user: %s", username)
            return None

        record = self._operators.verify(username, password)
        if record is None:
            attempts.append(now)
            self._failed[username] = attempts
            event = "auth_failed" if self._operators.get(username) else "auth_unknown_user"
            self._audit.log_event(event, {"username": username, "attempts": len(attempts)},
                                  result="denied")
            return None

        self._failed.pop(username, None)
        token = secrets.token_hex(32)
        now_wall = time.time()
        self._sessions[token] = OperatorSession(
            operator=record.username,
            token=token,
            issued_at=now_wall,
            expires_at=now_wall + self._ttl,
            role=record.role.value,
            permissions=permissions_for(record.role),
        )
        self._audit.log_event("auth_success", {
            "username": record.username, "role": record.role.value,
            "expires_in": self._ttl,
        })
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

    def role_of(self, token: str) -> Optional[str]:
        """The role a token logs in as, or None when it is no longer one."""
        session = self._sessions.get(token)
        if session and not session.expired:
            return session.role
        return None

    def revoke(self, token: str) -> bool:
        """Revoke a session token."""
        if token in self._sessions:
            session = self._sessions.pop(token)
            # `target`, not `operator`: an entry whose attribution says the victim
            # revoked their own token would read as a confession, not an act.
            self._audit.log_event(
                "auth_revoke", {"target": session.operator}
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

    # ------------------------------------------------------------------ #
    #  Operator management                                                #
    # ------------------------------------------------------------------ #

    def add_operator(self, username: str, password: str,
                     role: Role = Role.ADMIN) -> OperatorRecord:
        """Create or replace a stored credential and its role.

        Replacing is explicit: an operator added with the wrong role is corrected
        in place, and silently creating a second one with the same name is how you
        end up not knowing which credential a login used.
        """
        record = self._operators.add(username, password, role, replace=True)
        self._audit.log_event("auth_operator_added",
                              {"username": record.username, "role": record.role.value})
        return record

    def remove_operator(self, username: str) -> bool:
        """Delete a credential and drop any live session that authenticated with it."""
        removed = self._operators.remove(username)
        if not removed:
            return False
        for token in [t for t, s in self._sessions.items() if s.operator == username]:
            self._sessions.pop(token, None)
        self._audit.log_event("auth_operator_removed", {"username": username})
        return True

    def set_role(self, username: str, role: Role) -> OperatorRecord:
        """Change a stored role. Existing tokens keep the old one until they expire."""
        record = self._operators.set_role(username, role)
        self._audit.log_event("auth_role_changed",
                              {"username": username, "role": record.role.value})
        return record

    def bootstrap(self, username: str = "admin",
                  role: Role = Role.ADMIN) -> Dict[str, Any]:
        """Create the first credential when the store is empty.

        Returns the generated password for one printing. It goes nowhere else —
        not the audit log, not a file — so an operator who scrolls past it has to
        add their own credential to get back in.
        """
        try:
            created = self._operators.bootstrap(username, role)
        except WeakCredential as exc:
            logger.error("Cannot bootstrap an operator: %s", exc)
            raise
        self._audit.log_event("auth_operator_bootstrapped",
                              {"username": created["username"], "role": created["role"]})
        return created
