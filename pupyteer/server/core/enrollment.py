"""The enrollment secret: which payloads are allowed to become sessions.

TLS proves the listener to the agent. Nothing in the protocol proves the agent to
the listener, so without this any process that can reach the port can register a
session — and a session is a handler that runs operator commands and receives
uploaded files. In practice that means a defender or a rival who finds the
listener can fill the dashboard with machines that are not there, then watch what
the operator does with them.

The secret is generated on first use and shared by the two things that need it:
the transport manager checks it, and the payload builder compiles it into every
agent. That is what makes it an enrollment boundary rather than encryption — the
certificate proves *where* to call, this proves *who may* call.

It is a shared secret, not per-agent credentials: one recovered payload carries
the same key as every other, so it identifies this team server, not this host.
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("pupyteer.enrollment")

DEFAULT_SECRET_FILE = "./data/keys/enrollment.key"

# Long enough that guessing one across a network is not a thing that finishes.
_TOKEN_BYTES = 32

ConfigGetter = Callable[[str], Any]


def ensure_team_secret(path: str) -> str:
    """Return the enrollment secret at ``path``, writing one if it is missing.

    The file is the only copy: a server that loses it cannot authenticate the
    payloads already deployed, and a new secret silently means "nothing you built
    before today will check in".
    """
    secret_path = Path(path)
    if secret_path.exists():
        stored = secret_path.read_text(encoding="ascii").strip()
        if stored:
            return stored
        # An empty file reads as "auth is on and nothing may register", which is
        # a worse failure than saying so here.
        raise ValueError(
            f"{secret_path} exists but is empty; restore the enrollment secret "
            f"it held or delete it to start a new one and rebuild every payload."
        )

    token = secrets.token_hex(_TOKEN_BYTES)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_text(token + "\n", encoding="ascii")
    # Same reasoning as the TLS private key: world-writable would let a local
    # user replace the secret and enroll their own sessions.
    os.chmod(secret_path, 0o600)
    logger.info("Generated enrollment secret at %s", secret_path)
    return token


def listener_secret(get: ConfigGetter) -> Optional[str]:
    """The secret registrations must present, or None when auth is disabled.

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
    path = str(get("server.agent_auth_file") or DEFAULT_SECRET_FILE)
    return ensure_team_secret(path)


def secret_accepts(expected: Optional[str], presented: Any) -> bool:
    """Constant-time check of what an agent sent against what it should send.

    ``expected`` of None is the disabled case and admits anything; an empty
    expected value is not the same thing and admits nothing, so a misconfigured
    server fails closed rather than open.
    """
    if expected is None:
        return True
    if not isinstance(presented, str) or not presented:
        return False
    return hmac.compare_digest(expected, presented.strip())
