import pytest
from pupyteer.server.crypto.channel import ChannelKey, generate_key, encrypt, decrypt


def test_roundtrip():
    k = generate_key()
    pt = b"hello world"
    blob = encrypt(pt, k)
    assert decrypt(blob, k) == pt


def test_aad_mismatch_fails():
    k = generate_key()
    blob = encrypt(b"data", k, aad=b"ctx")
    with pytest.raises(Exception):
        decrypt(blob, k, aad=b"other")


def test_tamper_fails():
    k = generate_key()
    blob = bytearray(encrypt(b"data", k))
    blob[-1] ^= 1
    with pytest.raises(Exception):
        decrypt(bytes(blob), k)


def test_wrong_key_fails():
    k1 = generate_key()
    k2 = generate_key()
    blob = encrypt(b"data", k1)
    with pytest.raises(Exception):
        decrypt(blob, k2)


def test_key_length_validation():
    with pytest.raises(ValueError):
        ChannelKey(key=b"\x00" * 16)
