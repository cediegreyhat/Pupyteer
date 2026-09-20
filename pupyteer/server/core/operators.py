"""Operator credentials: who may drive this console, and which of them is a lie.

Nothing in the running tool consulted this file before now: `AuthLayer` loaded
passwords from `security.operators` in the config, which meant a real install had
`admin: "changeme"` in a YAML file, and an install that did not have it had no way
to log in either. Passwords in a config file are also passwords the audit trail,
the backup of that config and anyone reading over a shoulder all see.

So credentials live in their own file, hashed with a salted KDF, mode 0600 like
the enrollment secret and the TLS key beside it. The hash is not the strength:
unsalted SHA-256 of a password is one GPU afternoon, so each entry carries scrypt
parameters and the salt next to it.

What this gates is the console, not the network. There is no remote API; a second
process on this machine that can import `PupyteerEngine` can do anything an
operator can, and that is why the password is asked for by the console and the
token is checked at the console's command dispatch, and why the banner says so.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pupyteer.server.core.config import DEFAULT_OPERATORS_FILE
from pupyteer.server.core.rbac import Role
from pupyteer.server.core.validation import validate_username

logger = logging.getLogger("pupyteer.operators")

# The file's shape, so a future change can tell an old store from a corrupt one.
STORE_VERSION = 1

_KDF = "scrypt"
_SALT_BYTES = 16
_HASH_BYTES = 32
# 2**15 with r=8 needs ~32 MB and costs ~80 ms here. A login is rare enough that
# paying it is free, and an attacker cracking a stolen file pays it per guess.
_PARAM_DEFAULTS: Dict[str, int] = {"n": 2 ** 15, "r": 8, "p": 1}
_SCRYPT_MAXMEM = 1 << 26

# Below this, a password that survives the KDF is still just a dictionary word.
MIN_PASSWORD_CHARS = 12

# Generated bootstraps are hex so they survive being typed from a terminal, read
# over the phone and pasted into a config-management ticket without ambiguity.
_BOOTSTRAP_BYTES = 16

# A throwaway salt, for work whose result is discarded on purpose.
_GHOST_SALT = bytes(_SALT_BYTES)


class WeakCredential(ValueError):
    """A password or username that must not be stored. Subclasses ValueError so
    callers that already guard on bad input keep working."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _restrict(path: str) -> None:
    """Owner-only access, as far as this filesystem understands the idea."""
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        logger.warning("Could not restrict permissions on %s: %s", path, exc)


def _warn_if_exposed(path: Path) -> None:
    """Complain when the credential file can be read by someone other than us.

    Only where that is a meaningful question: Windows reports 0o666 for every
    writable file whatever the ACL says, so a mode check there warns on every
    write and still tells the operator nothing. The honest note is the one below,
    at debug level, so it is there when somebody looks for why a lab box is open.
    """
    if os.name != "posix":
        logger.debug(
            "%s: POSIX permission bits do not apply on %s filesystems; the "
            "operator store is only as private as the ACL on its directory",
            path, os.name)
        return
    mode = path.stat().st_mode & 0o077
    if mode:
        logger.warning("%s is readable or writable by group/other (%o)", path, mode)


def hash_password(password: str, *, salt: Optional[bytes] = None,
                  params: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Return the stored form of ``password``: salt, parameters and digest.

    The parameters are written next to the hash rather than assumed at read time,
    because a hash verified with the wrong n does not fail loudly — it just
    refuses the right password and looks like a broken login.
    """
    if not isinstance(password, str) or not password:
        raise WeakCredential("a credential needs a password")
    salt = salt if salt is not None else secrets.token_bytes(_SALT_BYTES)
    merged = dict(_PARAM_DEFAULTS)
    if params:
        merged.update({k: int(v) for k, v in params.items()})
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=merged["n"], r=merged["r"], p=merged["p"],
                            dklen=_HASH_BYTES, maxmem=_SCRYPT_MAXMEM)
    return {"kdf": _KDF, "salt": salt.hex(), "params": merged, "hash": digest.hex()}


def _pay_kdf(password: str) -> None:
    """Do the work of verifying a password and throw the answer away.

    A lookup miss that returned in microseconds next to a wrong password that
    takes 80 ms is a user enumeration oracle with the units changed, so a miss
    pays what a hit pays.
    """
    hashlib.scrypt(password.encode("utf-8"), salt=_GHOST_SALT,
                   n=_PARAM_DEFAULTS["n"], r=_PARAM_DEFAULTS["r"],
                   p=_PARAM_DEFAULTS["p"], dklen=_HASH_BYTES,
                   maxmem=_SCRYPT_MAXMEM)


@dataclass(frozen=True)
class OperatorRecord:
    """One stored operator: a name, a role, and what proves they know it."""
    username: str
    role: Role
    kdf: str
    salt: bytes
    params: Dict[str, int] = field(default_factory=dict)
    expected: bytes = b""
    created_at: str = ""
    updated_at: str = ""

    def verifies(self, password: str) -> bool:
        """Constant-time compare against this record's own parameters."""
        if self.kdf != _KDF:
            # An entry written by a build we do not understand is not a match, and
            # not a crash either: it says no until somebody looks at the file.
            logger.error("Operator %s stored with unknown kdf %r; refusing login",
                         self.username, self.kdf)
            return False
        try:
            digest = hashlib.scrypt(password.encode("utf-8"), salt=self.salt,
                                    n=self.params["n"], r=self.params["r"],
                                    p=self.params["p"], dklen=len(self.expected),
                                    maxmem=_SCRYPT_MAXMEM)
        except (KeyError, ValueError) as exc:
            logger.error("Operator %s has unusable kdf parameters: %s",
                         self.username, exc)
            return False
        return hmac.compare_digest(self.expected, digest)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "kdf": self.kdf,
            "salt": self.salt.hex(),
            "params": dict(self.params),
            "hash": self.expected.hex(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, username: str, data: Dict[str, Any]) -> "OperatorRecord":
        # An unreadable role is not "no role": defaulting here would turn a typo
        # in the file into a silently powerless operator.
        try:
            role = Role(data.get("role", Role.VIEWER.value))
        except ValueError as exc:
            raise WeakCredential(
                f"operator {username!r} has role {data.get('role')!r}, which is "
                f"not one of {[r.value for r in Role]}") from exc
        return cls(
            username=username,
            role=role,
            kdf=str(data.get("kdf", _KDF)),
            salt=bytes.fromhex(str(data.get("salt", ""))),
            params={k: int(v) for k, v in (data.get("params") or {}).items()},
            expected=bytes.fromhex(str(data.get("hash", ""))),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
        )


class OperatorStore:
    """The credential file: read-only until something is written.

    Constructing it creates nothing, so starting a server on a box with no
    operators is a fact the caller can ask about (``exists``) rather than a side
    effect that leaves a half-built file behind. Every question about it reads it
    again: this is a human-speed file, and a stale answer to "who can log in" is
    worse than one extra read.
    """

    def __init__(self, path: str = DEFAULT_OPERATORS_FILE):
        self._path = Path(path)
        self._records: Dict[str, OperatorRecord] = {}
        self._unreadable = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def exists(self) -> bool:
        """True when the store holds at least one usable credential."""
        self.reload()
        return bool(self._records)

    def reload(self) -> List[str]:
        """Re-read the file; returns the names now known.

        A corrupt file is reported as empty rather than trusted: the alternative
        is that a truncated write turns into "nobody may log in", which is what a
        denied operator sees either way, but this way the log says why.
        """
        self._records = {}
        self._unreadable = False
        if not self._path.exists():
            return []
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Cannot read operator store %s: %s", self._path, exc)
            self._unreadable = True
            return []
        operators = raw.get("operators") if isinstance(raw, dict) else None
        if not isinstance(operators, dict):
            logger.error("Operator store %s has no 'operators' object; ignoring it",
                         self._path)
            self._unreadable = True
            return []
        for name, data in operators.items():
            if not isinstance(data, dict):
                logger.error("Ignoring operator %s: entry is not an object", name)
                continue
            try:
                self._records[name] = OperatorRecord.from_dict(name, data)
            except (WeakCredential, ValueError, TypeError) as exc:
                logger.error("Ignoring operator %s: %s", name, exc)
        return sorted(self._records)

    def names(self) -> List[str]:
        self.reload()
        return sorted(self._records)

    def get(self, username: str) -> Optional[OperatorRecord]:
        self.reload()
        return self._records.get(username)

    def role_of(self, username: str) -> Role:
        self.reload()
        record = self._records.get(username)
        return record.role if record else Role.VIEWER

    def verify(self, username: str, password: str) -> Optional[OperatorRecord]:
        """The record for a correct pair, or None.

        An unknown name and a wrong password both return None: which one it was is
        decided here, and telling the difference out loud is a user enumeration
        oracle on a box whose console is the only door. So the unknown name pays for
        the KDF it did not need, and the two rejects cost the same to observe.
        """
        self.reload()
        record = self._records.get(username)
        if record is None or not record.expected:
            _pay_kdf(password or "")
            return None
        return record if record.verifies(password) else None

    # ------------------------------------------------------------------
    #  Writing
    # ------------------------------------------------------------------

    def add(self, username: str, password: str, role: Role = Role.ADMIN,
            *, replace: bool = False) -> OperatorRecord:
        """Store a new credential, or replace one with ``replace=True``.

        Refuses a duplicate without saying so quietly: a second `add` that
        overwrites a working password looks like a broken login later. Loads the
        file first because `_write` rewrites all of it — an add that trusted
        whatever happened to be in memory would delete the operators on disk that
        this process had not read yet.
        """
        name = validate_username(username)
        self.reload()
        if len(password or "") < MIN_PASSWORD_CHARS:
            raise WeakCredential(
                f"a credential needs at least {MIN_PASSWORD_CHARS} characters; "
                f"this one has {len(password or '')}")
        if name in self._records and not replace:
            raise WeakCredential(
                f"operator {name!r} already exists; use replace to set a new "
                f"password for it")
        stored = hash_password(password)
        now = _now()
        previous = self._records.get(name)
        record = OperatorRecord(
            username=name, role=Role(role), kdf=stored["kdf"],
            salt=bytes.fromhex(stored["salt"]), params=stored["params"],
            expected=bytes.fromhex(stored["hash"]),
            created_at=previous.created_at if previous else now, updated_at=now)
        self._records[name] = record
        self._write()
        logger.info("Stored credential for operator %s (role %s)", name, record.role.value)
        return record

    def set_role(self, username: str, role: Role) -> OperatorRecord:
        self.reload()
        record = self._records.get(username)
        if record is None:
            raise WeakCredential(f"no operator {username!r}")
        updated = OperatorRecord(
            username=record.username, role=Role(role), kdf=record.kdf,
            salt=record.salt, params=record.params, expected=record.expected,
            created_at=record.created_at, updated_at=_now())
        self._records[username] = updated
        self._write()
        return updated

    def remove(self, username: str) -> bool:
        if self._records.pop(username, None) is None:
            return False
        self._write()
        return True

    def _write(self) -> None:
        """Rewrite the whole file, atomically and never world-readable.

        os.replace is what keeps a crash mid-write from leaving a half-written
        store, which matters because the alternative to reading it is that nobody
        can log in and there is nothing left to inspect. Writing over a file that
        could not be read is refused for the same reason: the entries we cannot
        see are exactly the ones this would delete.
        """
        if self._unreadable:
            raise WeakCredential(
                f"{self._path} exists but cannot be parsed; not writing over it, "
                f"because that would drop operators this process cannot see")
        payload = {
            "version": STORE_VERSION,
            "updated_at": _now(),
            "operators": {name: rec.to_dict() for name, rec in sorted(self._records.items())},
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent),
                                        prefix=self._path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
                fh.write("\n")
            _restrict(tmp_name)
            os.replace(tmp_name, self._path)
        except BaseException:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
        _warn_if_exposed(self._path)

    # ------------------------------------------------------------------
    #  Bootstrap
    # ------------------------------------------------------------------

    @staticmethod
    def generate_password() -> str:
        return secrets.token_hex(_BOOTSTRAP_BYTES)

    def bootstrap(self, username: str = "admin",
                  role: Role = Role.ADMIN) -> Dict[str, Any]:
        """Create the first credential when the store holds none.

        The password is returned, not stored anywhere else: the caller shows it
        once, and the only copy after that is the hash in this file. An empty
        store means "nobody can log in", which is correct but not actionable, so
        the console calls this instead of leaving the operator outside.
        """
        self.reload()
        if self._records:
            raise WeakCredential(
                f"{self._path} already holds operators "
                f"({', '.join(self.names())}); not generating a password over them")
        password = self.generate_password()
        record = self.add(username, password, role)
        return {"username": record.username, "password": password, "role": record.role.value}
