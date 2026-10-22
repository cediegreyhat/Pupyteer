"""AES-256-GCM payload-level channel cipher (server-side primitive).

This is the *optional* layer gated by ``security.channel_cipher``. It is NOT a
replacement for TLS — confidentiality on the wire still comes from TLS. It adds a
second, per-session AEAD envelope around command/output payloads for defence in
depth and for cases where the operator terminates TLS at a reverse proxy.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class ChannelKey:
    key: bytes  # 32 bytes

    def __post_init__(self):
        if len(self.key) != 32:
            raise ValueError("ChannelKey must be 32 bytes")


def generate_key() -> ChannelKey:
    return ChannelKey(key=os.urandom(32))


def encrypt(plaintext: bytes, key: ChannelKey, aad: bytes = b"") -> bytes:
    """Return nonce(12) || ciphertext+tag."""
    aes = AESGCM(key.key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(blob: bytes, key: ChannelKey, aad: bytes = b"") -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("blob too short")
    nonce, ct = blob[:12], blob[12:]
    aes = AESGCM(key.key)
    return aes.decrypt(nonce, ct, aad)
