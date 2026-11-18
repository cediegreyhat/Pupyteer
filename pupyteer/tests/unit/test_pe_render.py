"""What the PE builder refuses to compile.

`payloads build` for a Windows target renders a C template and hands it to a
cross-compiler, so every value the listener later checks has to survive that
substitution. Two failure shapes are worth pinning down with a test, because both
produce a working compiler exit code and a payload that never calls home: a
placeholder the renderer stopped filling, and a value that cannot sit inside a C
string literal. Neither needs a compiler to check, so these run anywhere.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pupyteer.agent.core.stub import StubConfig
from pupyteer.payloads.pe_builder import PEBuilder, TEMPLATE_PLACEHOLDERS
from pupyteer.server.core.tls import (
    certificate_fingerprint, ensure_listener_cert, fingerprint_from_pem)


class _Config:
    def get(self, key, default=None):
        return default


class _Audit:
    def log_event(self, *args, **kwargs):
        pass


@pytest.fixture
def builder():
    return PEBuilder(_Config(), _Audit())


@pytest.fixture
def template():
    """The shipped template, so a guard tested against a copy of it is worthless."""
    return PEBuilder(_Config(), _Audit())._load_template()


def _cfg(**overrides) -> StubConfig:
    settings = {"name": "unit", "host": "127.0.0.1", "port": 8443,
                "sleep": 1, "jitter": 0, "auth_secret": "a" * 32}
    settings.update(overrides)
    return StubConfig(**settings)


def _listener_cert(tmp_path: Path) -> str:
    cert, _, _ = ensure_listener_cert(
        str(tmp_path / "listener.crt"), str(tmp_path / "listener.key"),
        host_names=("127.0.0.1", "localhost"))
    return Path(cert).read_text(encoding="ascii")


class TestPlaceholders:
    def test_every_placeholder_the_builder_fills_is_in_the_template(self, builder, template):
        missing = [p for p in TEMPLATE_PLACEHOLDERS if p not in template]
        assert not missing, f"template dropped {missing}"

    def test_a_placeholder_nothing_fills_refuses_the_build(self, builder, template):
        """The template asking for a value is the only signal a build is blind.

        A compiled agent that never learned its sleep interval still compiles,
        and on the target it looks like an implant that is not responding.
        """
        with pytest.raises(RuntimeError, match="no longer carries|placeholders"):
            builder._render(template + '\nconst char *x = "{{PROFILE}}";\n', _cfg())

    def test_a_value_that_cannot_end_its_own_string_literal_refuses(self, builder, template):
        for bad in ('quote"here', "back\\slash", "line\nbreak"):
            with pytest.raises(ValueError, match="cannot be compiled"):
                builder._render(template, _cfg(auth_secret=bad))

    def test_a_host_with_an_escape_in_it_refuses(self, builder, template):
        with pytest.raises(ValueError, match="server host"):
            builder._render(template, _cfg(host="127.0.0.1\r\nX-Evil: 1"))


class TestPinning:
    def test_tls_without_a_certificate_to_pin_refuses_the_build(self, builder, template):
        """The alternative is an agent that rejects every listener it meets."""
        with pytest.raises(RuntimeError, match="no listener certificate"):
            builder._render(template, _cfg(tls=True, tls_cert_pem=""))

    def test_a_plaintext_build_carries_no_pin(self, builder, template):
        source = builder._render(template, _cfg(tls=False))
        assert "#define AGENT_TLS 0" in source
        assert '#define AGENT_TLS_FINGERPRINT ""' in source

    def test_the_pin_compiled_in_is_the_fingerprint_the_agent_compares(
            self, builder, template, tmp_path):
        """One number, computed once, by the code that checks it and the code that obeys it."""
        pem = _listener_cert(tmp_path)
        source = builder._render(template, _cfg(tls=True, tls_cert_pem=pem))
        expected = certificate_fingerprint(str(tmp_path / "listener.crt"))
        assert f'#define AGENT_TLS_FINGERPRINT "{expected}"' in source
        assert fingerprint_from_pem(pem.encode("ascii")) == expected

    def test_the_enrollment_secret_reaches_the_rendered_source(self, builder, template):
        secret = "deadbeef" * 4
        source = builder._render(template, _cfg(auth_secret=secret))
        assert f'#define AGENT_AUTH "{secret}"' in source


class _ConfigWithKey:
    """A config that answers one key, the way ConfigManager does."""

    def __init__(self, **values):
        self.values = values

    def get(self, key, default=None):
        return self.values.get(key, default)


class TestRC4Key:
    """The wire the payload speaks has to be a wire the listener speaks.

    The builder reads `payloads.pe_rc4_key` and the listener reads
    `transports.rc4_key`. When the builder invented a random key at build time
    and wrote it nowhere, a default PE build produced an artifact that could
    never register — the listener stayed on plaintext and the payload's first
    message was ciphertext nobody could decrypt.
    """

    def test_no_key_anywhere_means_the_plaintext_wire(self, builder, template):
        assert builder._resolve_rc4_key(_cfg()) == ""
        source = builder._render(template, _cfg())
        assert '#define AGENT_RC4KEY ""' in source

    def test_a_configured_key_reaches_the_rendered_source(self, builder, template):
        key = "00112233445566778899aabbccddeeff"
        source = builder._render(template, _cfg(rc4_key=key))
        assert f'#define AGENT_RC4KEY "{key}"' in source

    def test_the_build_record_names_the_key_it_compiled_in(self, builder):
        key = "00112233445566778899aabbccddeeff"
        builder._config = _ConfigWithKey(**{"payloads.pe_rc4_key": key})
        assert builder._resolve_rc4_key(_cfg()) == key

    def test_the_listener_key_drives_the_payload_when_no_payload_key_is_set(
            self, builder):
        """One config key has to be enough to agree on both ends."""
        key = "00112233445566778899aabbccddeeff"
        builder._config = _ConfigWithKey(**{"transports.rc4_key": key})
        assert builder._resolve_rc4_key(_cfg()) == key

    def test_the_payload_key_wins_over_the_listener_key(self, builder):
        builder._config = _ConfigWithKey(**{
            "payloads.pe_rc4_key": "aabbccddeeff00112233445566778899",
            "transports.rc4_key": "00112233445566778899aabbccddeeff",
        })
        assert builder._resolve_rc4_key(_cfg()) == "aabbccddeeff00112233445566778899"

    def test_a_key_that_is_not_hex_refuses_the_build(self, builder, template):
        """The C agent silently degrades to plaintext on an unparseable key.

        Accepting one here would compile a payload the build log calls framed
        and the wire calls plaintext — the operator's only symptom is a payload
        that never registers.
        """
        for bad in ("not-hex", "abc", "zz" * 16, "00 11"):
            with pytest.raises(ValueError, match="not a hex string"):
                builder._render(template, _cfg(rc4_key=bad))

