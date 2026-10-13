"""Which payloads may become a session, and which messages may speak for one.

The channel needs three separate proofs, and each one answers a different
question:

* TLS proves the listener to the agent — the payload knows it is calling home and
  not a sinkhole.
* The enrollment secret proves the payload to the listener. Nothing else does:
  without it any process that can reach the port can register a session, and a
  session is a handler that runs operator commands and receives uploaded files. In
  practice that means a defender or a rival who finds the listener can fill the
  dashboard with machines that are not there, then watch what the operator does
  with them.
* The beacon token proves a beacon to the session it claims. The enrollment secret
  says *a* payload from this team server may enroll; it cannot say *which* session
  a later message belongs to, and a session id is a weak stand-in for that — it is
  twelve hex characters that appear in operator output, in `sessions list`, and in
  the audit trail. Whoever has one could drain that session's queued commands, and
  answer them with text of their own choosing, which the operator then reads as
  something the target said.

The enrollment secret is generated on first use and shared by the two things that
need it: the transport manager checks it, and the payload builder compiles it into
every agent. That is what makes it an enrollment boundary rather than encryption.

It is a shared secret, not per-agent credentials: one recovered payload carries
the same key as every other, so it identifies this team server, not this host. The
beacon token is the opposite shape — one per session, random, never shown to an
operator — which is why it is the thing that authenticates a beacon.

Because it is shared, losing a payload costs the whole enrollment boundary unless
it can be closed, and closing it cannot mean rebuilding every agent at once. So
the file holds more than one secret: the newest line is what `payloads build`
compiles, the lines under it are still admitted so deployed agents keep their
place, and deleting a line is the decision that stops them. The listener reads the
file when a payload arrives rather than when it starts, which is what makes that
decision take effect without a restart — and a restart would drop every session
the operator is working at the moment they noticed.

None of it reaches a session that already exists: after registering, an agent
presents only its beacon token. Cutting a live session off is `sessions kill`.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

logger = logging.getLogger("pupyteer.enrollment")

DEFAULT_SECRET_FILE = "./data/keys/enrollment.key"

# Long enough that guessing one across a network is not a thing that finishes.
_TOKEN_BYTES = 32

# A beacon token travels on every message and lives only in memory on both sides,
# so length costs nothing. It is deliberately not the shape of a session id: a
# session id is twelve characters that leak into operator output and the audit
# trail, and the proof of a beacon has to be something that never looks like it.
_BEACON_TOKEN_BYTES = 32

#: How many retired secrets the file keeps. Rotation without a ceiling turns the
#: acceptance list into a museum — every operator who ever rotated and forgot to
#: prune leaves a door open, which is the opposite of why the rotation happened.
MAX_RETIRED = 8

_FILE_HEADER = (
    "# Enrollment secrets this listener accepts, newest first.\n"
    "# The first one is what `payloads build` compiles into new agents; the rest\n"
    "# are still admitted so payloads already in the field can re-enrol after a\n"
    "# rotation. A line preceded by `# retired` is one of those. Deleting a line\n"
    "# stops it being accepted - new registrations only, since a session that\n"
    "# already exists proves itself with its own beacon token.\n")

ConfigGetter = Callable[[str], Any]


def secret_fingerprint(secret: str) -> str:
    """A short name for a secret that is safe to print.

    Naming a secret by its own characters would put credential material in the
    audit log and the terminal scrollback; sixteen hex digits of a SHA-256 is
    enough to tell two lines of the file apart and not enough to be the secret.
    """
    return hashlib.sha256(secret.encode("ascii")).hexdigest()[:16]


def _new_secret() -> str:
    return secrets.token_hex(_TOKEN_BYTES)


def read_secrets(path: str | Path) -> List[Tuple[str, str]]:
    """The (label, secret) pairs a file holds, newest first.

    A `#` line labels the secret directly under it and nothing further away, so
    the explanatory header at the top of a fresh file cannot become the label of
    the current secret. A file that does not exist or cannot be read yields no
    pairs: failing closed is the only safe answer for a server that is running
    and finds its own credential file gone.
    """
    try:
        # The secrets themselves are ASCII hex, but a comment line is something an
        # operator may well hand-write in their own alphabet. Reading the file as
        # pure ASCII would fail on it and report a server with no credentials at
        # all, which reads as "every payload you deployed is turned away".
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    pairs: List[Tuple[str, str]] = []
    label = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            label = stripped.lstrip("#").strip()
            continue
        if not stripped:
            label = ""
            continue
        pairs.append((label, stripped))
        label = ""
    return pairs


class EnrollmentLedger:
    """The enrollment secrets one listener accepts, read from the file each time.

    Reading on every registration rather than resolving once at startup is what
    makes revocation mean anything: an operator who finds a payload they cannot
    account for edits one file and stops it enrolling from that moment, without
    restarting the server and dropping every session that is currently live.

    It does not reach sessions that already exist, and says so rather than
    implying otherwise: after registering, an agent proves itself with its own
    beacon token and never presents the enrollment secret again. Cutting a
    session off is `sessions kill`, not this file.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def current(self) -> str:
        """The secret new payloads are built with, creating the file if absent."""
        pairs = read_secrets(self._path)
        if pairs:
            return pairs[0][1]
        if self._path.exists():
            # Exists and holds nothing: writing a fresh secret here would look
            # like a recovery while silently meaning "every payload you built
            # before today is now turned away".
            raise ValueError(
                f"{self._path} exists but is empty; restore the enrollment "
                "secret it held or delete the file to start a new one and "
                "rebuild every payload.")
        secret = _new_secret()
        self._write([("", secret)])
        logger.info("Generated enrollment secret at %s", self._path)
        return secret

    def accepted(self) -> List[str]:
        """Every secret a registration may present right now.

        A file that has gone missing accepts nothing, rather than generating a
        replacement on the spot. A fresh secret looks like a server that works
        while turning every deployed payload into a stranger, and that is a
        decision somebody has to make with their eyes open — which is what
        `current()` is for, at startup or from the console.
        """
        return [secret for _, secret in read_secrets(self._path)]

    def accepts(self, presented: Any) -> bool:
        """Whether this value is one of the secrets, checked against all of them.

        Every entry is compared even after a match: stopping at the first one
        that fits would make the loop's running time say which line of the file
        the caller matched, and the check is cheap enough to be worth doing
        without that hint.
        """
        if not isinstance(presented, str) or not presented:
            return False
        wanted = presented.strip()
        match = False
        for secret in self.accepted():
            if hmac.compare_digest(secret, wanted):
                match = True
        return match

    def status(self) -> List[Dict[str, str]]:
        """What the console shows: each secret by fingerprint and role, never by value."""
        rows = []
        for index, (label, secret) in enumerate(read_secrets(self._path)):
            rows.append({
                "fingerprint": secret_fingerprint(secret),
                "role": "current" if index == 0 else (label or "retired"),
            })
        return rows

    def revoke(self, fingerprint: str) -> bool:
        """Drop one retired secret by the fingerprint `enrollment show` printed.

        The current line is not revocable: it is what new payloads are being
        built with as this is typed, and deleting it would quietly promote a
        retired secret into that job. Rotate first — that is how a secret in use
        becomes a retired one.
        """
        wanted = str(fingerprint).strip().lower()
        pairs = read_secrets(self._path)
        kept = []
        dropped = False
        for index, (label, secret) in enumerate(pairs):
            if index and secret_fingerprint(secret) == wanted:
                dropped = True
                continue
            kept.append((label, secret))
        if dropped:
            self._write(kept)
        return dropped

    def rotate(self) -> Tuple[str, str]:
        """Make a new secret current and retire the one that was.

        Returns (new, retired). The retired secret stays in the file, so the
        rotation does not itself orphan the payloads already deployed — it moves
        the boundary, and deleting the retired line is the decision that closes
        it. Both are reported so the operator can say which fingerprint is which
        when that decision comes.
        """
        previous = self.current()
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Everything the file held before this call is retired by it, and keeps
        # whatever label it already carried so a second rotation does not lose
        # the date of the first.
        entries = [(label or f"retired {stamp}", secret)
                   for label, secret in read_secrets(self._path)]
        if len(entries) > MAX_RETIRED:
            logger.warning(
                "Dropping %d retired enrollment secret(s) beyond the %d kept; "
                "payloads built with them can no longer enrol",
                len(entries) - MAX_RETIRED, MAX_RETIRED)
        secret = _new_secret()
        self._write([("", secret)] + entries[:MAX_RETIRED])
        return secret, previous

    def _write(self, entries: List[Tuple[str, str]]) -> None:
        """Rewrite the file whole, through a temporary it cannot be caught mid-way in.

        A credential file caught half-written reads as empty, and the server's
        answer to that is to stop accepting every payload.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        body = _FILE_HEADER + "\n" + "".join(
            (f"# {label}\n" if label else "") + secret + "\n"
            for label, secret in entries)
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(body, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path)


def ensure_team_secret(path: str) -> str:
    """Return the enrollment secret at ``path``, writing one if it is missing.

    The file is the only copy: a server that loses it cannot authenticate the
    payloads already deployed, and a new secret silently means "nothing you built
    before today will check in".
    """
    return EnrollmentLedger(path).current()


def listener_ledger(get: ConfigGetter) -> Optional[EnrollmentLedger]:
    """The ledger registrations are checked against, or None when auth is off.

    Off only for an operator who has said so explicitly: with it off the listener
    trusts whoever reaches it, which is fine on a loopback lab interface and not
    fine anywhere else.
    """
    value = get("server.agent_auth")
    if value is None:
        value = True
    if isinstance(value, str):
        # An unrecognised string stays enabled. `agent_auth: ""` is a line nobody
        # typed meaning "hand me an open listener".
        value = value.strip().lower() not in ("0", "false", "no", "off")
    if not value:
        return None
    return EnrollmentLedger(str(get("server.agent_auth_file") or DEFAULT_SECRET_FILE))


def listener_secret(get: ConfigGetter) -> Optional[str]:
    """The one enrollment secret a *new* payload is built with.

    Listeners check registrations against the whole ledger; a builder wants the
    current line, which is what this returns. None means auth is off.
    """
    ledger = listener_ledger(get)
    return None if ledger is None else ledger.current()


def new_beacon_token() -> str:
    """The credential one session presents on every message after registering.

    Random per session rather than derived from the enrollment secret, so that a
    payload in the field cannot compute the token for a session it did not create.
    """
    return secrets.token_hex(_BEACON_TOKEN_BYTES)


def beacon_accepts(expected: Any, presented: Any) -> bool:
    """Whether this message may speak for the session holding ``expected``.

    There is no disabled case here. A session with no token — one built directly
    through the session manager, or a record written by an older server — fails,
    because the alternative is that forgetting to hand out a proof means the
    sessions without one are the only ones anyone may command.
    """
    if not isinstance(expected, str) or not expected:
        return False
    if not isinstance(presented, str) or not presented:
        return False
    return hmac.compare_digest(expected, presented.strip())
