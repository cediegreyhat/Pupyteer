"""Profile Validator — Schema validation for Pupyteer C2 profiles.

Validates profile data against the C2 profile specification, providing
detailed, actionable error messages for each validation failure.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger_name = "pupyteer.profiles.validator"


class ProfileValidationError:
    """A single profile validation error with context."""

    def __init__(self, path: str, message: str, severity: str = "error"):
        self.path = path
        self.message = message
        self.severity = severity

    def __str__(self) -> str:
        return f"[{self.severity}] {self.path}: {self.message}"

    def __repr__(self) -> str:
        return f"ProfileValidationError({self.path!r}, {self.message!r}, {self.severity!r})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


class ProfileValidationResult:
    """Aggregated result of profile validation."""

    def __init__(self):
        self.errors: List[ProfileValidationError] = []
        self.warnings: List[ProfileValidationError] = []

    @property
    def is_valid(self) -> bool:
        return not any(e.severity == "error" for e in self.errors) and not any(
            w.severity == "error" for w in self.warnings
        )

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

    def add_error(self, path: str, message: str) -> None:
        self.errors.append(ProfileValidationError(path, message, "error"))

    def add_warning(self, path: str, message: str) -> None:
        self.warnings.append(ProfileValidationError(path, message, "warning"))

    def merge(self, other: "ProfileValidationResult") -> None:
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.is_valid,
            "error_count": len([e for e in self.errors if e.severity == "error"]),
            "warning_count": len(self.warnings),
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
        }

    def error_messages(self) -> List[str]:
        return [str(e) for e in self.errors if e.severity == "error"]

    def __str__(self) -> str:
        if self.is_valid:
            return "Profile is valid."
        msgs = [str(e) for e in self.errors if e.severity == "error"]
        return f"Profile has {len(msgs)} error(s):\n" + "\n".join(f"  - {m}" for m in msgs)


# Supported transport protocols
SUPPORTED_PROTOCOLS: Set[str] = {
    "tcp", "udp", "http", "https", "websocket", "ws", "wss", "dns", "doh", "dot", "namedpipe"
}

# Supported encoding modes
SUPPORTED_ENCODING_MODES: Set[str] = {"raw", "base64", "hex", "xor", "aes"}

# Valid log levels
VALID_LOG_LEVELS: Set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# Profile name pattern: alphanumeric, hyphens, underscores
_PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


def validate_profile(data: Dict[str, Any]) -> ProfileValidationResult:
    """Validate a complete profile dictionary against the specification.

    Performs comprehensive validation including:
    - Required sections and fields
    - Value ranges and types
    - Cross-field consistency
    - Best-practice recommendations

    Args:
        data: Profile dictionary to validate.

    Returns:
        ProfileValidationResult with errors and warnings.
    """
    result = ProfileValidationResult()

    if not isinstance(data, dict):
        result.add_error("profile", "Profile must be a mapping/dictionary")
        return result

    _validate_profile_section(data, result)
    _validate_transport_section(data, result)
    _validate_session_section(data, result)
    _validate_encoding_section(data, result)
    _validate_logging_section(data, result)
    _validate_timeouts_section(data, result)
    _validate_security_section(data, result)
    _validate_cross_field_consistency(data, result)

    return result


def _validate_profile_section(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate the profile identity section."""
    if "profile" not in data:
        result.add_error("profile", "Missing required section: 'profile'")
        return

    profile = data["profile"]
    if not isinstance(profile, dict):
        result.add_error("profile", "Section 'profile' must be a mapping")
        return

    # Name is required
    if "name" not in profile:
        result.add_error("profile.name", "Profile name is required")
    elif not isinstance(profile["name"], str) or not profile["name"].strip():
        result.add_error("profile.name", "Profile name must be a non-empty string")
    elif not _PROFILE_NAME_PATTERN.match(profile["name"]):
        result.add_error(
            "profile.name",
            f"Invalid profile name '{profile['name']}'. Use alphanumeric characters, hyphens, and underscores. "
            f"Must start with alphanumeric and be 1-64 characters.",
        )

    # Version validation
    if "version" in profile:
        version = profile["version"]
        if not isinstance(version, str) or not version.strip():
            result.add_error("profile.version", "Version must be a non-empty string")
        elif not re.match(r"^\d+(\.\d+)*$", version):
            result.add_warning(
                "profile.version",
                f"Version '{version}' should follow semver (e.g., '1.0.0')",
            )


def _validate_transport_section(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate the transport configuration section."""
    if "transport" not in data:
        result.add_error("transport", "Missing required section: 'transport'")
        return

    transport = data["transport"]
    if not isinstance(transport, dict):
        result.add_error("transport", "Section 'transport' must be a mapping")
        return

    # Protocol is required
    if "protocol" not in transport:
        result.add_error("transport.protocol", "Transport protocol is required")
    else:
        protocol = str(transport.get("protocol", "")).lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            result.add_error(
                "transport.protocol",
                f"Unsupported transport protocol: '{protocol}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_PROTOCOLS))}",
            )

    # Host validation
    if "host" in transport:
        host = transport["host"]
        if not isinstance(host, str) or not host.strip():
            result.add_error("transport.host", "Host must be a non-empty string")

    # Port validation
    if "port" in transport:
        port = transport["port"]
        if isinstance(port, bool) or not isinstance(port, int):
            result.add_error("transport.port", "Port must be an integer")
        elif not (1 <= port <= 65535):
            result.add_error("transport.port", f"Port must be between 1 and 65535, got: {port}")

    # TLS cert/key consistency
    has_cert = "tls_cert" in transport
    has_key = "tls_key" in transport
    if has_cert and not has_key:
        result.add_warning("transport", "TLS certificate specified without a key")
    if has_key and not has_cert:
        result.add_warning("transport", "TLS key specified without a certificate")

    # Custom headers validation
    if "custom_headers" in transport:
        headers = transport["custom_headers"]
        if not isinstance(headers, dict):
            result.add_error("transport.custom_headers", "Custom headers must be a mapping")
        else:
            for hk, hv in headers.items():
                if not isinstance(hk, str):
                    result.add_error(f"transport.custom_headers.{hk}", "Header name must be a string")


def _validate_session_section(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate the session configuration section."""
    if "session" not in data:
        return  # Optional section

    session = data["session"]
    if not isinstance(session, dict):
        result.add_error("session", "Section 'session' must be a mapping")
        return

    # Heartbeat interval
    if "heartbeat_interval" in session:
        hb = session["heartbeat_interval"]
        if isinstance(hb, bool) or not isinstance(hb, int):
            result.add_error("session.heartbeat_interval", "Heartbeat interval must be an integer (seconds)")
        elif hb < 1:
            result.add_error("session.heartbeat_interval", "Heartbeat interval must be positive")
        elif hb < 5:
            result.add_warning(
                "session.heartbeat_interval",
                f"Heartbeat interval {hb}s may cause excessive network traffic",
            )
        elif hb > 3600:
            result.add_warning(
                "session.heartbeat_interval",
                f"Heartbeat interval {hb}s may delay failure detection",
            )

    # Timeout
    if "timeout" in session:
        timeout = session["timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            result.add_error("session.timeout", "Timeout must be an integer (seconds)")
        elif timeout < 1:
            result.add_error("session.timeout", "Timeout must be positive")

    # Jitter
    if "jitter" in session:
        jitter = session["jitter"]
        if isinstance(jitter, bool) or not isinstance(jitter, (int, float)):
            result.add_error("session.jitter", "Jitter must be a number between 0.0 and 1.0")
        elif not (0.0 <= float(jitter) <= 1.0):
            result.add_error("session.jitter", f"Jitter must be between 0.0 and 1.0, got: {jitter}")

    # Consistency: timeout should be greater than heartbeat_interval
    hb = session.get("heartbeat_interval")
    timeout = session.get("timeout")
    if (
        isinstance(hb, int)
        and isinstance(timeout, int)
        and not isinstance(hb, bool)
        and not isinstance(timeout, bool)
        and timeout <= hb
    ):
        result.add_error(
            "session.timeout",
            f"Session timeout ({timeout}s) must be greater than heartbeat_interval ({hb}s)",
        )


def _validate_encoding_section(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate the encoding configuration section."""
    if "encoding" not in data:
        return  # Optional section

    encoding = data["encoding"]
    if not isinstance(encoding, dict):
        result.add_error("encoding", "Section 'encoding' must be a mapping")
        return

    # Mode validation
    if "mode" in encoding:
        mode = str(encoding["mode"]).lower()
        if mode not in SUPPORTED_ENCODING_MODES:
            result.add_error(
                "encoding.mode",
                f"Unsupported encoding mode: '{mode}'. Supported: {', '.join(sorted(SUPPORTED_ENCODING_MODES))}",
            )

    # Key required for xor/aes modes
    if "mode" in encoding:
        mode = str(encoding["mode"]).lower()
        if mode in ("xor", "aes") and "key" not in encoding:
            result.add_error("encoding.key", f"Encoding mode '{mode}' requires a 'key' field")

    if "key" in encoding and not isinstance(encoding["key"], str):
        result.add_error("encoding.key", "Encoding key must be a string")


def _validate_logging_section(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate the logging configuration section."""
    if "logging" not in data:
        return  # Optional section

    logging_section = data["logging"]
    if not isinstance(logging_section, dict):
        result.add_error("logging", "Section 'logging' must be a mapping")
        return

    if "level" in logging_section:
        level = str(logging_section["level"]).upper()
        if level not in VALID_LOG_LEVELS:
            result.add_error(
                "logging.level",
                f"Invalid log level: '{level}'. Valid: {', '.join(sorted(VALID_LOG_LEVELS))}",
            )


def _validate_timeouts_section(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate the timeouts configuration section."""
    if "timeouts" not in data:
        return  # Optional section

    timeouts = data["timeouts"]
    if not isinstance(timeouts, dict):
        result.add_error("timeouts", "Section 'timeouts' must be a mapping")
        return

    # Connect timeout
    if "connect" in timeouts:
        connect = timeouts["connect"]
        if isinstance(connect, bool) or not isinstance(connect, int):
            result.add_error("timeouts.connect", "Connect timeout must be an integer (seconds)")
        elif connect < 1:
            result.add_error("timeouts.connect", "Connect timeout must be positive")
        elif connect > 120:
            result.add_warning("timeouts.connect", f"Connect timeout {connect}s may cause slow failure detection")

    # Response timeout
    if "response" in timeouts:
        response = timeouts["response"]
        if isinstance(response, bool) or not isinstance(response, int):
            result.add_error("timeouts.response", "Response timeout must be an integer (seconds)")
        elif response < 1:
            result.add_error("timeouts.response", "Response timeout must be positive")
        elif response > 600:
            result.add_warning("timeouts.response", f"Response timeout {response}s may delay failure detection")

    # Consistency
    connect = timeouts.get("connect")
    response = timeouts.get("response")
    if (
        isinstance(connect, int)
        and isinstance(response, int)
        and not isinstance(connect, bool)
        and not isinstance(response, bool)
        and response < connect
    ):
        result.add_error(
            "timeouts.response",
            f"Response timeout ({response}s) should be >= connect timeout ({connect}s)",
        )


def _validate_security_section(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate the security configuration section."""
    if "security" not in data:
        return  # Optional section

    security = data["security"]
    if not isinstance(security, dict):
        result.add_error("security", "Section 'security' must be a mapping")
        return

    if "require_auth" in security and not isinstance(security["require_auth"], bool):
        result.add_error("security.require_auth", "require_auth must be a boolean")

    if "token_ttl" in security:
        ttl = security["token_ttl"]
        if isinstance(ttl, bool) or not isinstance(ttl, int):
            result.add_error("security.token_ttl", "Token TTL must be an integer (seconds)")
        elif ttl < 60:
            result.add_warning("security.token_ttl", f"Token TTL {ttl}s may cause frequent re-authentication")
        elif ttl > 86400:
            result.add_warning("security.token_ttl", f"Token TTL {ttl}s is very long")


def _validate_cross_field_consistency(data: Dict[str, Any], result: ProfileValidationResult) -> None:
    """Validate consistency across different sections."""
    transport = data.get("transport", {})
    security = data.get("security", {})

    if not isinstance(transport, dict) or not isinstance(security, dict):
        return

    # Warn if auth disabled on non-loopback
    protocol = str(transport.get("protocol", "tcp")).lower()
    host = str(transport.get("host", "0.0.0.0"))
    require_auth = security.get("require_auth", True)

    if protocol in ("tcp", "http", "https", "websocket", "ws", "wss"):
        if not require_auth and host not in ("127.0.0.1", "::1", "localhost"):
            result.add_warning(
                "security.require_auth",
                "Authentication is disabled for a network-exposed transport. "
                "This allows any network client to connect to your C2 server.",
            )

    # Warn if no encryption for network protocols
    if protocol in ("tcp", "http") and host not in ("127.0.0.1", "::1", "localhost"):
        result.add_warning(
            "transport.protocol",
            f"Using unencrypted protocol '{protocol}' over network. "
            f"Consider using 'https' or 'wss' for production deployments.",
        )
