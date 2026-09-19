"""Profile Parser — YAML/JSON profile file parsing for Pupyteer C2 profiles.

Handles loading profile data from files and strings, with support for
both YAML and JSON formats. Performs structural normalization and
basic type coercion.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml

logger = logging.getLogger("pupyteer.profiles.parser")


class ProfileParseError(Exception):
    """Raised when a profile file cannot be parsed."""

    def __init__(self, message: str, path: Optional[str] = None, line: Optional[int] = None):
        self.path = path
        self.line = line
        if path and line:
            super().__init__(f"{path}:{line}: {message}")
        elif path:
            super().__init__(f"{path}: {message}")
        else:
            super().__init__(message)


def parse_yaml(content: str, source: Optional[str] = None) -> Dict[str, Any]:
    """Parse YAML content into a dictionary.

    Args:
        content: YAML text to parse.
        source: Optional source identifier for error messages.

    Returns:
        Parsed dictionary.

    Raises:
        ProfileParseError: If YAML parsing fails.
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        line = None
        if hasattr(exc, 'problem_mark') and exc.problem_mark:
            line = exc.problem_mark.line + 1
        raise ProfileParseError(f"YAML parse error: {exc}", path=source, line=line) from exc

    if not isinstance(data, dict):
        raise ProfileParseError(
            f"Expected mapping at top level, got {type(data).__name__}",
            path=source,
        )
    return data


def parse_json(content: str, source: Optional[str] = None) -> Dict[str, Any]:
    """Parse JSON content into a dictionary.

    Args:
        content: JSON text to parse.
        source: Optional source identifier for error messages.

    Returns:
        Parsed dictionary.

    Raises:
        ProfileParseError: If JSON parsing fails.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ProfileParseError(
            f"JSON parse error: {exc.msg}",
            path=source,
            line=exc.lineno,
        ) from exc

    if not isinstance(data, dict):
        raise ProfileParseError(
            f"Expected object at top level, got {type(data).__name__}",
            path=source,
        )
    return data


def parse_file(path: Union[str, os.PathLike]) -> Dict[str, Any]:
    """Parse a profile file (YAML or JSON) into a dictionary.

    Auto-detects format based on file extension.

    Args:
        path: Path to the profile file.

    Returns:
        Parsed profile dictionary.

    Raises:
        ProfileParseError: If the file cannot be read or parsed.
        FileNotFoundError: If the file does not exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Profile file not found: {path}")

    content = path.read_text(encoding="utf-8")
    source = str(path)

    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        return parse_yaml(content, source=source)
    elif suffix == ".json":
        return parse_json(content, source=source)
    else:
        # Try YAML first, then JSON
        try:
            return parse_yaml(content, source=source)
        except ProfileParseError:
            return parse_json(content, source=source)


def parse_string(content: str, format: str = "yaml") -> Dict[str, Any]:
    """Parse profile data from a string.

    Args:
        content: Profile data as a string.
        format: Format to parse — "yaml" or "json".

    Returns:
        Parsed profile dictionary.

    Raises:
        ProfileParseError: If parsing fails.
        ValueError: If format is not recognized.
    """
    if format == "yaml":
        return parse_yaml(content)
    elif format == "json":
        return parse_json(content)
    else:
        raise ValueError(f"Unknown format: {format}. Use 'yaml' or 'json'.")


def normalize_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a parsed profile dictionary.

    Ensures all expected sections exist with sensible defaults and
    coerces types where needed.

    Args:
        data: Raw parsed profile data.

    Returns:
        Normalized profile dictionary.
    """
    normalized: Dict[str, Any] = {}

    # Profile section
    profile = data.get("profile", {})
    if not isinstance(profile, dict):
        profile = {}
    normalized["profile"] = {
        "name": str(profile.get("name", "unnamed")),
        "version": str(profile.get("version", "1.0")),
    }
    if "description" in profile:
        normalized["profile"]["description"] = str(profile["description"])

    # Transport section
    transport = data.get("transport", {})
    if not isinstance(transport, dict):
        transport = {}
    normalized["transport"] = {
        "protocol": str(transport.get("protocol", "tcp")).lower(),
        "host": str(transport.get("host", "0.0.0.0")),
        "port": int(transport.get("port", 8443)),
    }
    if "tls_cert" in transport:
        normalized["transport"]["tls_cert"] = str(transport["tls_cert"])
    if "tls_key" in transport:
        normalized["transport"]["tls_key"] = str(transport["tls_key"])
    if "custom_headers" in transport:
        headers = transport["custom_headers"]
        if isinstance(headers, dict):
            normalized["transport"]["custom_headers"] = {
                str(k): str(v) for k, v in headers.items()
            }

    # Session section
    session = data.get("session", {})
    if not isinstance(session, dict):
        session = {}
    normalized["session"] = {
        "heartbeat_interval": _to_positive_int(session.get("heartbeat_interval", 30), "heartbeat_interval"),
        "timeout": _to_positive_int(session.get("timeout", 300), "timeout"),
        "jitter": _to_float_in_range(session.get("jitter", 0.2), 0.0, 1.0, "jitter"),
    }

    # Encoding section
    encoding = data.get("encoding", {})
    if not isinstance(encoding, dict):
        encoding = {}
    normalized["encoding"] = {
        "mode": str(encoding.get("mode", "raw")).lower(),
    }
    if "key" in encoding:
        normalized["encoding"]["key"] = str(encoding["key"])

    # Logging section
    logging_section = data.get("logging", {})
    if not isinstance(logging_section, dict):
        logging_section = {}
    normalized["logging"] = {
        "level": str(logging_section.get("level", "INFO")).upper(),
    }

    # Timeouts section
    timeouts = data.get("timeouts", {})
    if not isinstance(timeouts, dict):
        timeouts = {}
    normalized["timeouts"] = {
        "connect": _to_positive_int(timeouts.get("connect", 30), "timeouts.connect"),
        "response": _to_positive_int(timeouts.get("response", 60), "timeouts.response"),
    }

    # Security section
    security = data.get("security", {})
    if not isinstance(security, dict):
        security = {}
    normalized["security"] = {
        "require_auth": bool(security.get("require_auth", True)),
        "token_ttl": _to_positive_int(security.get("token_ttl", 3600), "security.token_ttl"),
    }

    return normalized


def _to_positive_int(value: Any, name: str) -> int:
    """Coerce value to a positive integer."""
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise ProfileParseError(f"{name} must be an integer, got: {value!r}")
    if result <= 0:
        raise ProfileParseError(f"{name} must be positive, got: {result}")
    return result


def _to_float_in_range(value: Any, min_val: float, max_val: float, name: str) -> float:
    """Coerce value to a float within [min_val, max_val]."""
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ProfileParseError(f"{name} must be a number, got: {value!r}")
    if not (min_val <= result <= max_val):
        raise ProfileParseError(f"{name} must be between {min_val} and {max_val}, got: {result}")
    return result
