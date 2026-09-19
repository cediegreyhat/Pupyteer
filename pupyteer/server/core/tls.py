"""TLS material for the agent-facing listeners.

The session protocol is newline-delimited JSON with no payload-level cipher, so
confidentiality and server authentication have to come from TLS. A team server is
usually a bare IP with no hope of a CA-issued certificate, so the listener serves
a self-signed one and the agent trusts *that certificate alone* — the PEM is
compiled into the payload and installed as its only verification anchor. That is
certificate pinning: as strong as a CA chain here, because there is exactly one
certificate in the world the agent will accept, and it is not one an attacker can
obtain. "Verify nothing" would be a man-in-the-middle with extra steps; "verify
against the system store" would reject our own server.

Also generates the pair on first use and refuses to replace a certificate that
fielded payloads already pin, so restarting the server cannot strand them.
"""
from __future__ import annotations

import hashlib
import logging
import os
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, List, NamedTuple, Optional, Tuple

logger = logging.getLogger("pupyteer.tls")

DEFAULT_CERT_FILE = "./data/tls/listener.crt"
DEFAULT_KEY_FILE = "./data/tls/listener.key"

# Both callers pass a ConfigManager.get bound method; a plain callable keeps this
# module free of the config manager's import cycle.
ConfigGetter = Callable[[str], Any]


def certificate_fingerprint(cert_file: str) -> str:
    """SHA-256 of the certificate's DER encoding — the value an agent pins."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    pem = Path(cert_file).read_bytes()
    der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def _subject_alt_names(host_names):
    """SAN entries for the names a payload may dial, IP or DNS as appropriate."""
    import ipaddress

    from cryptography import x509

    names = []
    for raw in host_names:
        value = (raw or "").strip()
        if not value:
            continue
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            names.append(x509.DNSName(value))
    if not names:
        return None
    return x509.SubjectAlternativeName(names)


def ensure_listener_cert(cert_file: str, key_file: str, *,
                         common_name: str = "pupyteer-listener",
                         host_names: Tuple[str, ...] = (),
                         validity_days: int = 3650) -> Tuple[str, str, str]:
    """Return (cert_path, key_path, fingerprint), creating a self-signed pair.

    An existing certificate is reused rather than replaced: every payload already
    in the field pins the current fingerprint, and regenerating it on the next
    restart would strand them all.
    """
    cert_path, key_path = Path(cert_file), Path(key_file)
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path), certificate_fingerprint(cert_path)
    if cert_path.exists() or key_path.exists():
        # Half a pair. Regenerating would silently hand fielded payloads a new
        # fingerprint, which looks like dead agents and not like a missing file.
        present = cert_path if cert_path.exists() else key_path
        missing = key_path if present == cert_path else cert_path
        raise FileNotFoundError(
            f"listener TLS material is incomplete: {missing} is missing but "
            f"{present} exists. Restore the missing file, or move both aside to "
            f"start a new certificate and rebuild every payload."
        )

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    not_before = datetime.now(timezone.utc) - timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    # The names a payload might dial. Without them the certificate is unusable
    # for hostname verification and pinning is the only check the agent can make.
    san = _subject_alt_names(host_names)
    if san:
        builder = builder.add_extension(san, critical=False)
    cert = builder.sign(key, hashes.SHA256())

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    # The key is unprotected on disk, so it must at least not be world-readable.
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    fingerprint = certificate_fingerprint(cert_path)
    logger.info("Generated listener certificate %s (SHA-256 %s)",
                cert_path, fingerprint[:16])
    return str(cert_path), str(key_path), fingerprint


def server_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """A server-side TLS context for the given certificate pair."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


class ListenerTLS(NamedTuple):
    """Everything the two sides of a TLS callback need to agree on.

    ``cert_pem`` is what a payload compiles in as its pin and ``ssl_context`` is
    what the listener answers with; handing them over together is what keeps the
    two from drifting apart into a listener no agent can reach.
    """

    ssl_context: ssl.SSLContext
    cert_pem: str
    fingerprint: str


def listener_tls(get: ConfigGetter) -> Optional[ListenerTLS]:
    """Resolve the listener's TLS material from server.* config, or None.

    Called by both the transport manager and the payload builder: whichever runs
    first creates the certificate pair and the other reuses it, so a payload
    built before the server started still pins the certificate it will meet.
    Reuse also means the names are fixed by the first call — add every hostname
    you expect to dial to server.tls_hostnames before the certificate exists.

    A failure is raised rather than swallowed. A listener that quietly falls back
    to plaintext while its payloads speak TLS produces no sessions and no hint as
    to why.
    """
    if not _truthy(get("server.tls")):
        return None

    cert = _first_of(get("server.tls_cert"), DEFAULT_CERT_FILE)
    key = _first_of(get("server.tls_key"), DEFAULT_KEY_FILE)
    names = list(_host_names(get("server.tls_hostnames")))
    # The bind address is a name payloads may dial when it is a real one; the
    # wildcard forms name no host at all, so they do not belong in a certificate.
    bind = str(get("server.host", "") or "").strip()
    if bind and bind not in ("0.0.0.0", "::", "*") and bind not in names:
        names.append(bind)
    _, _, fingerprint = ensure_listener_cert(cert, key, host_names=tuple(names))
    return ListenerTLS(
        ssl_context=server_context(cert, key),
        cert_pem=Path(cert).read_text(encoding="ascii"),
        fingerprint=fingerprint,
    )


def _host_names(value) -> List[str]:
    """Normalise a config value that may be a list, a comma string, or absent."""
    if isinstance(value, str):
        names = value.split(",")
    elif value:
        names = [str(v) for v in value]
    else:
        names = []
    return [n for n in (name.strip() for name in names) if n]


def _first_of(*values) -> str:
    for value in values:
        if value:
            return str(value)
    return ""


def _truthy(value) -> bool:
    """Config files and env vars both spell "on" as a string."""
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)

