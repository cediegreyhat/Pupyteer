"""
Regression tests for pupyteer/server/evasion/obfuscator.py.

Covers the production-grade upgrade:
- AEAD primitives (ChaCha20-Poly1305, AES-256-GCM) incl. round-trip and tamper rejection
- Back-compat AES-256-CBC (real cipher, not an XOR fallback)
- PE hardening: real debug-directory/Rich/COFF-symbol stripping, overlay append/detect,
  code caves, plausible-timestamp generation
- entropy() / is_probably_packed() heuristics
- Public API preservation for the legacy primitives
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from cryptography.exceptions import InvalidTag

from pupyteer.server.evasion.obfuscator import (  # noqa: E402
    EncodingScheme,
    ObfuscationConfig,
    ObfuscationEngine,
    PEHeaderInfo,
    TIMESTAMP_YEAR_END,
    TIMESTAMP_YEAR_START,
    aes_256_cbc_encrypt,
    aes_256_gcm_decrypt,
    aes_256_gcm_encrypt,
    base64_custom_encode,
    chacha20poly1305_encrypt,
    entropy,
    is_probably_packed,
    parse_pe_header,
    pe_append_overlay,
    pe_find_code_cave,
    pe_has_overlay,
    pe_modify_timestamp,
    pe_randomize_sections,
    pe_strip_debug,
    plausible_timestamp,
    rc4_crypt,
    rc4_ksa,
    xor_crypt,
)


# ─── Synthetic PE builder ────────────────────────────────────────────────────

DOS_HEADER_SIZE = 0x40
DOS_STUB_SIZE = 0x40
OPTIONAL_HEADER_SIZE = 224  # PE32

IMAGE_FILE_HEADER = 0x14
PE_SIG = b"PE\x00\x00"


def _build_pe(
    *,
    num_sections: int = 2,
    debug_dir: bool = True,
    rich: bool = True,
    symtab: bool = True,
    overlay: bytes = b"",
    code_padding: int = 0,
) -> bytes:
    """Build a minimal but structurally valid PE32 image."""
    num_dirs = 16
    num_sections_offset = DOS_HEADER_SIZE + DOS_STUB_SIZE
    optional_header_offset = DOS_HEADER_SIZE + DOS_STUB_SIZE + 4 + IMAGE_FILE_HEADER
    dirs_offset = optional_header_offset + 96  # PE32 data directories
    sections_offset = optional_header_offset + OPTIONAL_HEADER_SIZE

    section_names = [".text", ".rdata", ".data", ".idata"][:num_sections]
    sections_raw_size = 0x200
    headers_size = sections_offset + 40 * num_sections
    file_align = 0x200
    headers_size = ((headers_size + file_align - 1) // file_align) * file_align

    buf = bytearray(headers_size)

    # DOS header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, DOS_HEADER_SIZE + DOS_STUB_SIZE)
    # DOS stub (non-zero junk)
    stub = bytes((0x41 + (i % 26)) for i in range(DOS_STUB_SIZE))
    buf[DOS_HEADER_SIZE:DOS_HEADER_SIZE + DOS_STUB_SIZE] = stub
    if rich:
        rich_blob = b"DanS" + bytes(16) + b"Rich" + struct.pack("<I", 0x12345678)
        off = DOS_HEADER_SIZE + 0x10
        buf[off:off + len(rich_blob)] = rich_blob

    # PE signature + COFF header
    #   num_sections_offset: "PE\0\0" (4) | Machine(2) | NumberOfSections(2) |
    #   TimeDateStamp(4) | PointerToSymbolTable(4) | NumberOfSymbols(4) |
    #   SizeOfOptionalHeader(2) | Characteristics(2)
    buf[num_sections_offset:num_sections_offset + 4] = PE_SIG
    coff = num_sections_offset + 4
    struct.pack_into("<H", buf, coff + 0, 0x8664)  # Machine
    struct.pack_into("<H", buf, coff + 2, num_sections)  # NumberOfSections
    struct.pack_into("<I", buf, coff + 4, 0x5F5E1000)  # TimeDateStamp
    struct.pack_into("<I", buf, coff + 8, 0x1000 if symtab else 0)  # PointerToSymbolTable
    struct.pack_into("<I", buf, coff + 12, 4 if symtab else 0)  # NumberOfSymbols
    struct.pack_into("<H", buf, coff + 16, OPTIONAL_HEADER_SIZE)  # SizeOfOptionalHeader
    struct.pack_into("<H", buf, coff + 18, 0x0102)  # Characteristics

    # Optional header (PE32)
    struct.pack_into("<H", buf, optional_header_offset, 0x010B)  # Magic
    struct.pack_into("<I", buf, optional_header_offset + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", buf, optional_header_offset + 28, 0x400000)  # ImageBase
    struct.pack_into("<I", buf, optional_header_offset + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", buf, optional_header_offset + 36, file_align)  # FileAlignment
    struct.pack_into("<I", buf, optional_header_offset + 56, 0x20000)  # SizeOfImage
    struct.pack_into("<I", buf, optional_header_offset + 60, headers_size)  # SizeOfHeaders
    struct.pack_into("<I", buf, optional_header_offset + 92, num_dirs)  # NumberOfRvaAndSizes

    # Debug data directory (index 6)
    if debug_dir:
        struct.pack_into("<I", buf, dirs_offset + 6 * 8, 0x3000)
        struct.pack_into("<I", buf, dirs_offset + 6 * 8 + 4, 28)

    # Section table
    for i in range(num_sections):
        off = sections_offset + 40 * i
        name = section_names[i].encode() if i < len(section_names) else b"".encode()
        buf[off:off + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<I", buf, off + 8, sections_raw_size)
        struct.pack_into("<I", buf, off + 12, 0x1000 * (i + 1))
        struct.pack_into("<I", buf, off + 16, sections_raw_size)
        struct.pack_into("<I", buf, off + 20, headers_size + i * sections_raw_size)
        chars = 0x60000020 if i == 0 else 0x40000040
        struct.pack_into("<I", buf, off + 36, chars)

    # Section bodies
    body_offset = headers_size
    for i in range(num_sections):
        body = bytearray(sections_raw_size)
        if i == 0:
            # Real code-ish bytes at the front, zero padding (a code cave) after
            body[0:16] = bytes(range(0x90, 0xA0))
            if code_padding:
                body[16:16 + code_padding] = bytes(code_padding)
        buf[body_offset:body_offset + sections_raw_size] = body
        body_offset += sections_raw_size

    if overlay:
        buf.extend(overlay)
    return bytes(buf)


def _write_tmp(tmp_path: Path, data: bytes, name: str) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# ─── Cipher primitives ───────────────────────────────────────────────────────


def test_xor_crypt_roundtrip():
    import warnings
    data = b"hello obfuscator world" * 3
    key = b"supersecretkey"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert xor_crypt(data, key) != data
        assert xor_crypt(xor_crypt(data, key), key) == data


def test_xor_crypt_empty_and_key_reuse():
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert xor_crypt(b"", b"k") == b""
        # Single-byte key must not divide by zero
        assert xor_crypt(b"abc", b"K") == bytes([ord("a") ^ ord("K"), ord("b") ^ ord("K"), ord("c") ^ ord("K")])


def test_rc4_roundtrip_and_ksa():
    import warnings
    s = rc4_ksa(b"key")
    assert isinstance(s, list) and len(s) == 256 and sorted(s) == list(range(256))
    data = b"RC4 test payload" * 5
    key = b"anotherkey123"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert rc4_crypt(data, key) != data
        assert rc4_crypt(rc4_crypt(data, key), key) == data


def test_aes_cbc_is_real_cipher_not_xor_fallback():
    key = bytes(range(32))
    iv = bytes(range(16, 32))
    data = b"A" * 32
    ct = aes_256_cbc_encrypt(data, key, iv)
    assert len(ct) == 48  # PKCS7 padded
    assert ct != data
    # Decrypt with cryptography directly to prove real AES-CBC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    assert padded == b"A" * 32 + bytes([16] * 16)


def test_aes_cbc_pads_empty_input():
    key = bytes(32)
    iv = bytes(16)
    ct = aes_256_cbc_encrypt(b"", key, iv)
    assert len(ct) == 16


def test_chacha20poly1305_layout_and_roundtrip():
    key = bytes(range(32))
    data = b"secret payload bytes" * 4
    blob = chacha20poly1305_encrypt(data, key)
    assert blob != data
    nonce, ct = blob[:12], blob[12:]
    assert ct != data
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    aead = ChaCha20Poly1305(key)
    assert aead.decrypt(nonce, ct, b"") == data


def test_chacha20poly1305_aad_is_authenticated():
    key = bytes(range(32))
    data = b"payload"
    blob = chacha20poly1305_encrypt(data, key, aad=b"metadata")
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    with pytest.raises(InvalidTag):
        ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], b"wrong-aad")
    # Nonce uniqueness across calls
    b2 = chacha20poly1305_encrypt(data, key)
    assert blob[:12] != b2[:12]


def test_chacha20poly1305_empty_and_short_key():
    key = bytes(range(32))
    blob = chacha20poly1305_encrypt(b"", key)
    assert len(blob) == 12 + 16  # nonce + tag
    with pytest.raises(ValueError):
        chacha20poly1305_encrypt(b"x", b"tooshort")


def test_aes_gcm_roundtrip_and_tamper_rejection():
    key = bytes(range(32))
    data = b"aes-gcm payload" * 7
    blob = aes_256_gcm_encrypt(data, key)
    assert len(blob) == 12 + len(data) + 16
    assert aes_256_gcm_decrypt(blob, key) == data

    # Tamper with ciphertext
    tampered = bytearray(blob)
    tampered[20] ^= 0xFF
    with pytest.raises(InvalidTag):
        aes_256_gcm_decrypt(bytes(tampered), key)

    # Wrong key
    with pytest.raises(InvalidTag):
        aes_256_gcm_decrypt(blob, bytes(range(1, 33)))


def test_aes_gcm_aad_required_for_decrypt():
    key = bytes(range(32))
    blob = aes_256_gcm_encrypt(b"payload", key, aad=b"header")
    with pytest.raises(InvalidTag):
        aes_256_gcm_decrypt(blob, key)  # missing aad
    assert aes_256_gcm_decrypt(blob, key, aad=b"header") == b"payload"


def test_aes_gcm_truncated_blob_rejected():
    key = bytes(range(32))
    with pytest.raises(ValueError):
        aes_256_gcm_decrypt(b"short", key)


def test_aead_key_length_validation():
    with pytest.raises(ValueError):
        aes_256_gcm_encrypt(b"x", b"short")
    with pytest.raises(ValueError):
        aes_256_gcm_decrypt(bytes(16), b"short")


# ─── Encoding ────────────────────────────────────────────────────────────────


def test_encoding_scheme_members():
    assert EncodingScheme.XOR.value == "xor"
    assert EncodingScheme.AES.value == "aes"
    assert EncodingScheme.RC4.value == "rc4"
    assert EncodingScheme.CHAIN.value == "chain"
    assert EncodingScheme.BASE64_CUSTOM.value == "b64_custom"


def test_base64_custom_encode_roundtrip_with_returned_alphabet():
    data = b"custom base64 payload!!" * 3
    encoded, alphabet = base64_custom_encode(data)
    assert isinstance(encoded, str)
    assert len(alphabet) == 64
    assert sorted(alphabet) == sorted(set(alphabet))

    import base64

    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    back = encoded.translate(str.maketrans(alphabet, standard))
    assert base64.b64decode(back) == data


def test_base64_custom_encode_supplied_alphabet():
    import base64

    data = b"supplied alphabet"
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alphabet = standard[::-1]  # deterministic reversed
    encoded, used = base64_custom_encode(data, alphabet)
    assert used == alphabet
    back = encoded.translate(str.maketrans(alphabet, standard))
    assert base64.b64decode(back) == data


def test_base64_custom_encode_bad_alphabet_rejected():
    with pytest.raises(ValueError):
        base64_custom_encode(b"x", "short")
    with pytest.raises(ValueError):
        base64_custom_encode(b"x", "A" * 64)  # duplicates


# ─── entropy / packing heuristic ─────────────────────────────────────────────


def test_entropy_values():
    assert entropy(b"") == 0.0
    assert entropy(b"\x00" * 100) == 0.0
    # "hello world hello world": 8 distinct symbols, max 3 bits
    assert 0.0 < entropy(b"hello world hello world") <= 3.0
    import math

    # 4 equally likely symbols -> exactly 2 bits
    data = bytes([0, 1, 2, 3] * 250)
    assert entropy(data) == pytest.approx(2.0)


def test_entropy_uniform_bytes_near_max():
    assert entropy(bytes(range(256)) * 8) == pytest.approx(8.0, abs=0.01)


def test_is_probably_packed():
    packed = bytes(range(256)) * 64  # high entropy
    plain = b"\x00" * 8192  # zero entropy
    assert is_probably_packed(packed) is True
    assert is_probably_packed(plain) is False
    assert is_probably_packed(b"") is False
    assert is_probably_packed(b"ab") is False  # too small to judge


# ─── PE parsing / hardening ──────────────────────────────────────────────────


def test_parse_pe_header_ok(tmp_path):
    data = _build_pe()
    path = _write_tmp(tmp_path, data, "ok.exe")
    info = parse_pe_header(path)
    assert isinstance(info, PEHeaderInfo)
    assert info.timestamp == 0x5F5E1000
    assert info.entry_point == 0x1000
    assert info.image_base == 0x400000
    assert len(info.sections) == 2
    assert info.sections[0]["name"] == ".text"


def test_parse_pe_header_rejects_non_pe(tmp_path):
    path = _write_tmp(tmp_path, b"NOTMZ" + bytes(0x100), "bad.bin")
    with pytest.raises(ValueError):
        parse_pe_header(path)


def test_parse_pe_header_rejects_truncated(tmp_path):
    path = _write_tmp(tmp_path, b"MZ", "trunc.bin")
    with pytest.raises(ValueError):
        parse_pe_header(path)


def test_pe_strip_debug_removes_debug_rich_and_symtab(tmp_path):
    data = _build_pe(debug_dir=True, rich=True, symtab=True)
    src = _write_tmp(tmp_path, data, "full.exe")
    dst = str(tmp_path / "stripped.exe")

    assert pe_strip_debug(src, dst) is True

    out = Path(dst).read_bytes()
    pe_offset = struct.unpack_from("<I", out, 0x3C)[0]
    dirs_offset = pe_offset + 24 + 96
    # Debug directory entry zeroed
    assert struct.unpack_from("<I", out, dirs_offset + 6 * 8)[0] == 0
    assert struct.unpack_from("<I", out, dirs_offset + 6 * 8 + 4)[0] == 0
    # COFF symbol pointer/count zeroed
    assert struct.unpack_from("<I", out, pe_offset + 12)[0] == 0
    assert struct.unpack_from("<I", out, pe_offset + 16)[0] == 0
    # Rich header zeroed (no 'Rich' signature left)
    assert out.find(b"Rich") == -1
    # Size preserved
    assert len(out) == len(data)


def test_pe_strip_debug_noop_returns_false(tmp_path):
    data = _build_pe(debug_dir=False, rich=False, symtab=False)
    src = _write_tmp(tmp_path, data, "clean.exe")
    dst = str(tmp_path / "clean_out.exe")
    # Nothing to strip -> False, output still written (unchanged copy)
    assert pe_strip_debug(src, dst) is False
    assert Path(dst).read_bytes() == data


def test_pe_strip_debug_rejects_non_pe(tmp_path):
    src = _write_tmp(tmp_path, b"junk", "junk.bin")
    dst = str(tmp_path / "out.bin")
    assert pe_strip_debug(src, dst) is False


def test_pe_strip_debug_truncated_is_safe(tmp_path):
    # MZ header claims a PE offset past EOF — must not crash, and the
    # non-PE input must return False without writing anything
    data = bytearray(b"MZ" + bytes(0x80))
    struct.pack_into("<I", data, 0x3C, 0xFFFF)
    src = _write_tmp(tmp_path, bytes(data), "evil.exe")
    dst = str(tmp_path / "out.exe")
    assert pe_strip_debug(src, dst) is False
    assert not Path(dst).exists()


def test_pe_strip_debug_tiny_file(tmp_path):
    # Files shorter than the DOS header e_lfanew field must not crash
    src = _write_tmp(tmp_path, b"MZ", "tiny.exe")
    dst = str(tmp_path / "out.exe")
    assert pe_strip_debug(src, dst) is False


def test_pe_randomize_sections_renames(tmp_path):
    data = _build_pe()
    src = _write_tmp(tmp_path, data, "sec.exe")
    dst = str(tmp_path / "renamed.exe")
    assert pe_randomize_sections(src, dst) is True
    out = Path(dst).read_bytes()
    # Section names differ, size preserved
    assert len(out) == len(data)
    pe_offset = struct.unpack_from("<I", out, 0x3C)[0]
    opt_size = struct.unpack_from("<H", out, pe_offset + 20)[0]
    sec0 = pe_offset + 24 + opt_size
    new_name = out[sec0:sec0 + 8].rstrip(b"\x00").decode("ascii", errors="replace")
    assert new_name != ".text"
    assert new_name.isalpha() and len(new_name) == 8


def test_pe_randomize_sections_non_pe(tmp_path):
    src = _write_tmp(tmp_path, b"nope", "n.bin")
    dst = str(tmp_path / "o.bin")
    assert pe_randomize_sections(src, dst) is False


# ─── overlay ─────────────────────────────────────────────────────────────────


def test_pe_append_overlay_and_detect(tmp_path):
    data = _build_pe()
    src = _write_tmp(tmp_path, data, "plain.exe")
    dst = str(tmp_path / "overlaid.exe")
    blob = b"OVERLAY-PAYLOAD-\x00\x01\x02" * 10

    assert pe_append_overlay(src, dst, blob) is True

    out = Path(dst).read_bytes()
    assert len(out) == len(data) + len(blob)
    assert out.endswith(blob)
    assert pe_has_overlay(dst, src) is True
    assert pe_has_overlay(src, src) is False


def test_pe_append_overlay_empty_blob_rejected(tmp_path):
    data = _build_pe()
    src = _write_tmp(tmp_path, data, "e.exe")
    dst = str(tmp_path / "e2.exe")
    assert pe_append_overlay(src, dst, b"") is False


def test_pe_has_overlay_non_pe(tmp_path):
    src = _write_tmp(tmp_path, b"nope", "n.bin")
    dst = str(tmp_path / "o.bin")
    assert pe_has_overlay(dst, src) is False


def test_pe_append_overlay_non_pe(tmp_path):
    src = _write_tmp(tmp_path, b"nope", "n.bin")
    dst = str(tmp_path / "o.bin")
    assert pe_append_overlay(src, dst, b"blob") is False


# ─── code caves ──────────────────────────────────────────────────────────────


def test_pe_find_code_cave_located(tmp_path):
    # .text has real code for the first 16 bytes then zero padding = a cave
    data = _build_pe(code_padding=0x100)
    path = _write_tmp(tmp_path, data, "cave.exe")
    cave = pe_find_code_cave(path, min_size=32)
    assert cave is not None
    offset, size = cave
    assert size >= 32
    assert 0 <= offset < len(data)


def test_pe_find_code_cave_none_when_full(tmp_path):
    # Sections with no executable characteristics -> no cave
    data = bytearray(_build_pe())
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    sec0 = pe_off + 24 + opt_size
    struct.pack_into("<I", data, sec0 + 36, 0x40000040)  # read-only, non-exec
    path = _write_tmp(tmp_path, bytes(data), "nocave.exe")
    assert pe_find_code_cave(path, min_size=32) is None


def test_pe_find_code_cave_bounds_safe(tmp_path):
    data = _build_pe(code_padding=0x80)
    path = _write_tmp(tmp_path, data, "c.exe")
    assert pe_find_code_cave(path, min_size=10_000_000) is None


def test_pe_find_code_cave_non_pe(tmp_path):
    path = _write_tmp(tmp_path, b"junk", "j.bin")
    assert pe_find_code_cave(path) is None


# ─── timestamps ──────────────────────────────────────────────────────────────


def test_plausible_timestamp_range_and_business_hours():
    import calendar
    import datetime

    # plausible_timestamp() is TZ-agnostic in its window (calendar.timegm
    # against UTC fields) and weights toward 09:00-17:59 UTC.
    lo = calendar.timegm((TIMESTAMP_YEAR_START, 1, 1, 0, 0, 0))
    hi = calendar.timegm((TIMESTAMP_YEAR_END, 12, 31, 23, 59, 59))
    hours = []
    for _ in range(200):
        ts = plausible_timestamp()
        assert lo <= ts <= hi
        hours.append(datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).hour)
    # Majority should land in business hours 09:00-17:59 UTC
    business = sum(1 for h in hours if 9 <= h <= 17)
    assert business / len(hours) > 0.5


def test_pe_modify_timestamp_plausible(tmp_path):
    import datetime

    data = _build_pe()
    src = _write_tmp(tmp_path, data, "ts.exe")
    dst = str(tmp_path / "ts_out.exe")
    assert pe_modify_timestamp(src, dst) is True

    out = Path(dst).read_bytes()
    pe_offset = struct.unpack_from("<I", out, 0x3C)[0]
    ts = struct.unpack_from("<I", out, pe_offset + 8)[0]
    lo = datetime.datetime(2015, 1, 1, tzinfo=datetime.timezone.utc).timestamp()
    hi = datetime.datetime(2021, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc).timestamp()
    assert lo <= ts <= hi
    assert ts != 0x5F5E1000  # original value replaced


def test_pe_modify_timestamp_matches_reference(tmp_path):
    data = _build_pe()
    ref = bytearray(_build_pe())
    ref_pe_off = struct.unpack_from("<I", ref, 0x3C)[0]
    struct.pack_into("<I", ref, ref_pe_off + 8, 0x5C0DEAD0)
    ref_path = _write_tmp(tmp_path, bytes(ref), "ref.exe")
    src = _write_tmp(tmp_path, data, "ts.exe")
    dst = str(tmp_path / "ts_out.exe")

    assert pe_modify_timestamp(src, dst, reference_pe=ref_path) is True
    out = Path(dst).read_bytes()
    pe_offset = struct.unpack_from("<I", out, 0x3C)[0]
    assert struct.unpack_from("<I", out, pe_offset + 8)[0] == 0x5C0DEAD0


def test_pe_modify_timestamp_non_pe(tmp_path):
    src = _write_tmp(tmp_path, b"nope", "n.bin")
    dst = str(tmp_path / "o.bin")
    assert pe_modify_timestamp(src, dst) is False


def test_pe_modify_timestamp_bad_reference_falls_back(tmp_path):
    data = _build_pe()
    src = _write_tmp(tmp_path, data, "ts.exe")
    dst = str(tmp_path / "ts_out.exe")
    bad_ref = _write_tmp(tmp_path, b"nope", "badref.bin")
    assert pe_modify_timestamp(src, dst, reference_pe=bad_ref) is True


# ─── engine integration ──────────────────────────────────────────────────────


def test_obfuscation_engine_full_pipeline(tmp_path, monkeypatch):
    """The engine must produce a real output artifact without raising."""

    class _Cfg:
        def get(self, key, default=None):
            if key == "paths.obfuscated_artifacts":
                return str(tmp_path / "out")
            return default

    monkeypatch.setattr("asyncio.get_event_loop", lambda: __import__("asyncio").new_event_loop())
    engine = ObfuscationEngine(_Cfg(), None)

    payload = tmp_path / "payload.exe"
    payload.write_bytes(_build_pe(overlay=b"ORIGINAL-DATA"))

    out = engine._obfuscate_sync(str(payload), ObfuscationConfig(scheme=EncodingScheme.AES))
    assert Path(out).exists()
    assert Path(out).name == f"obf_{payload.name}"
    data = Path(out).read_bytes()
    # AES-CBC scheme: ciphertext differs from input, length is block-multiple
    assert data[:2] != b"MZ"
    assert len(data) % 16 == 0


def test_engine_missing_input_raises(tmp_path):
    class _Cfg:
        def get(self, key, default=None):
            if key == "paths.obfuscated_artifacts":
                return str(tmp_path / "out")
            return default

    engine = ObfuscationEngine(_Cfg(), None)
    with pytest.raises(FileNotFoundError):
        engine._obfuscate_sync(str(tmp_path / "missing.bin"), ObfuscationConfig())


def test_engine_helper_methods_preserved():
    import warnings
    engine = ObfuscationEngine.__new__(ObfuscationEngine)
    names = ObfuscationEngine.generate_random_section_names(3)
    assert len(names) == 3 and all(len(n) == 8 for n in names)
    mz = ObfuscationEngine.generate_random_mz_header()
    assert mz[:2] == b"MZ" and len(mz) == 64
    assert engine.generate_anti_analysis_stub("linux")
    assert engine.generate_anti_analysis_stub("windows")
    assert engine.generate_import_hashtable(["kernel32.dll"]) != ""
    assert engine.generate_syscall_stubs(["NtAllocateVirtualMemory"]) != ""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        code = engine.encrypt_agent_strings("x = 'secretvalue'\n")
    assert "_d(" in code
