"""Pupyteer Agent Key Management — per-agent asymmetric identity + registry.

Replaces the old shared-secret JWT model. Each agent is issued an Ed25519
keypair at build time:

  - The PRIVATE key + a stable agent_id are baked into the payload.
  - The PUBLIC key is stored in the server-side AgentKeyRegistry.

Because verification is asymmetric, extracting one payload yields only that
one agent's private key. An attacker CANNOT forge the C2's identity or
impersonate a *different* agent — the fundamental weakness of a shared
HS256 secret (which every payload had to embed and which let a single
captured binary forge every agent's token).

Registration handshake (challenge / response, prevents replay):

    Server -> Agent : {"type": "challenge", "nonce": "<32-byte hex>"}
    Agent  -> Server : {"type": "register", "agent_id": "...",
                        "pubkey": "<hex>", "signature": "<hex of nonce>",
                        "hostname": ..., ...}
    Server verifies signature against the stored pubkey for agent_id.

The private key NEVER leaves the payload; the server never holds it.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger("pupyteer.agent_keys")

# Backward-compat: allow config to point at a JSON file holding the registry.
# In-memory by default; persisted lazily by the engine if a path is set.


def _pub_hex(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _pub_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


@dataclass
class AgentKeyPair:
    """A generated Ed25519 identity for one agent."""

    agent_id: str
    priv_pem: str                 # PEM private key (baked into payload)
    pub_hex: str                  # hex public key (stored server-side)
    created_at: float = field(default_factory=time.time)

    @property
    def pub_short(self) -> str:
        return self.pub_hex[:16]


class AgentKeyRegistry:
    """Server-side registry of trusted agent public keys.

    The server verifies every registration and check-in against the pubkey
    on file for a given agent_id. Unknown agents (no pubkey) are rejected.
    """

    def __init__(self) -> None:
        self._keys: Dict[str, str] = {}          # agent_id -> pub_hex
        self._nonces: Dict[str, str] = {}        # agent_id -> outstanding nonce
        self._lock: "object" = None              # set by caller if needed

    # ------------------------------------------------------------------ #
    #  Key lifecycle                                                      #
    # ------------------------------------------------------------------ #

    def generate(self, agent_id: Optional[str] = None) -> AgentKeyPair:
        """Generate a fresh Ed25519 identity for a new agent."""
        agent_id = agent_id or f"agt-{uuid.uuid4().hex[:12]}"
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        pub_hex = _pub_hex(priv.public_key())
        pair = AgentKeyPair(agent_id=agent_id, priv_pem=priv_pem, pub_hex=pub_hex)
        # Auto-trust keys we generate (server minted this agent).
        self.register_pubkey(agent_id, pub_hex)
        return pair

    def register_pubkey(self, agent_id: str, pub_hex: str) -> None:
        """Trust a public key for an agent_id (idempotent)."""
        self._keys[agent_id] = pub_hex
        logger.debug("Registered pubkey for agent %s (%s...)", agent_id, pub_hex[:12])

    def is_known(self, agent_id: str) -> bool:
        return agent_id in self._keys

    def pubkey(self, agent_id: str) -> Optional[str]:
        return self._keys.get(agent_id)

    # ------------------------------------------------------------------ #
    #  Challenge / response                                               #
    # ------------------------------------------------------------------ #

    def issue_nonce(self, agent_id: str) -> str:
        """Issue a fresh single-use challenge nonce for an agent."""
        nonce = os.urandom(32).hex()
        self._nonces[agent_id] = nonce
        return nonce

    def verify_registration(
        self, agent_id: str, signature_hex: str, nonce: str
    ) -> bool:
        """Verify an agent's registration signature against its pubkey.

        Returns True only if:
          - agent_id is known (pubkey on file), AND
          - signature is a valid Ed25519 signature over the nonce, AND
          - the nonce matches the outstanding challenge for this agent.
        The nonce is consumed on success (single-use, replay-proof).
        """
        expected = self._nonces.get(agent_id)
        pub_hex = self._keys.get(agent_id)
        if not pub_hex or expected is None or not hmac_compare(nonce, expected):
            return False
        try:
            pub = _pub_from_hex(pub_hex)
            sig = bytes.fromhex(signature_hex)
            pub.verify(sig, nonce.encode("ascii"))
        except Exception:
            return False
        # Consume the nonce — one registration attempt per challenge.
        del self._nonces[agent_id]
        return True

    # ------------------------------------------------------------------ #
    #  Persistence                                                        #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, str]:
        return dict(self._keys)

    def load_from_dict(self, data: Dict[str, str]) -> None:
        self._keys.update(data or {})


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string compare (avoids importing secrets for one call)."""
    import hmac
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sign_payload(priv_pem: str, message: str) -> str:
    """Sign *message* with an agent private key. Used by generated payloads."""
    priv = serialization.load_pem_private_key(
        priv_pem.encode("ascii"), password=None
    )
    if not isinstance(priv, Ed25519PrivateKey):  # pragma: no cover - defensive
        raise TypeError("Expected an Ed25519 private key")
    return priv.sign(message.encode("ascii")).hex()


def build_agent_config_block(pair: AgentKeyPair) -> str:
    """Render the identity block embedded into a generated agent stub.

    The PEM is emitted as a Python literal the payload loads at runtime.
    """
    return json.dumps(
        {
            "agent_id": pair.agent_id,
            "priv_pem": pair.priv_pem,
        }
    )
