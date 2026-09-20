"""Centralized configuration management for Pupyteer."""
from __future__ import annotations

import json
import os
import copy
import logging
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

import yaml

from pupyteer.server.core.enrollment import DEFAULT_SECRET_FILE
from pupyteer.server.core.tls import DEFAULT_CERT_FILE, DEFAULT_KEY_FILE

logger = logging.getLogger("pupyteer.config")

DEFAULT_CONFIG: Dict[str, Any] = {
    "server": {
        "host": "0.0.0.0",
        "port": 8443,
        "backlog": 10,
        # HTTP callbacks share the session protocol with TCP; 0 disables them.
        # Off by default because port 8080 is routinely occupied on a team box.
        "http_port": 0,
        "http_uri": "/index.html",
        # On by default: the session protocol is JSON, so without TLS everything an
        # operator types and everything the target answers is readable to whoever
        # owns the network, and a C2 that is plaintext unless you remember a flag is
        # plaintext on the one engagement where it mattered. Enabling it makes the
        # agent pin the listener's certificate, which is the only check either side
        # can make on a self-signed team server reached by IP.
        #
        # `server.tls: false` is the opt-out, and it is a visible one: the build log
        # says so and the listener reports it. Turning this on for a server that
        # already has fielded payloads strands them — they speak plaintext to a port
        # that now refuses it, which `transports list` shows as handshakes_refused.
        "tls": True,
        "tls_cert": DEFAULT_CERT_FILE,
        "tls_key": DEFAULT_KEY_FILE,
        # Names in the certificate besides server.host. Set them before the
        # certificate is first created; an existing one is never rewritten.
        "tls_hostnames": [],
        # Registrations must carry this secret, so only payloads built by this
        # server can become sessions. On by default: reaching the port should not
        # be enough to hand someone a handler.
        "agent_auth": True,
        "agent_auth_file": DEFAULT_SECRET_FILE,
    },
    "logging": {
        "level": "INFO",
        "format": "json",
        "file": None,
    },
    "operator": {
        "name": "unknown",
        "theme": "dark",
    },
    "profile": {
        "default": "HTTPS-Standard",
    },
    "security": {
        "require_auth": True,
        "token_ttl": 3600,
        "max_failed_logins": 5,
    },
    "paths": {
        "payload_artifacts": "./payloads/artifacts",
        "profiles": "./config/profiles",
        "logs": "./logs",
    },
    "payloads": {
        "mingw_path": "x86_64-w64-mingw32-gcc",
    },
    "evasion": {
        "test_mode": False,
        "litterbox_url": "",
        "litterbox_token": "",
        "litterbox_timeout": 120,
        "virustotal_enabled": True,
        "virustotal_max_positives": 5,
        "virustotal_use_composio": True,
        "history_path": "./logs/evasion_history.json",
    },
}

# Keys that contain sensitive data — redacted in logs/exports
_SENSITIVE_KEYS: Set[str] = {
    "password", "secret", "token", "api_key", "apikey",
    "private_key", "credential", "auth_token", "secret_key",
}


def _redact_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy with sensitive values replaced by ***REDACTED***."""
    redacted: Dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in _SENSITIVE_KEYS and isinstance(value, str):
            redacted[key] = "***REDACTED***"
        elif isinstance(value, dict):
            redacted[key] = _redact_sensitive(value)
        else:
            redacted[key] = value
    return redacted


class ConfigManager:
    """Hierarchical config loader with environment-specific overrides.

    Search order:
      1. Explicit path (if provided)
      2. pupyteer.yaml / .json in cwd
      3. ~/.config/pupyteer/config.yaml / .json
      4. /etc/pupyteer/config.yaml / .json
      5. Environment-specific overlay (based on PUPTYEER_ENV)
      6. PUPYTEER_* env vars (uppercase, double-underscore separator)
    """

    def __init__(self, path: Optional[str] = None):
        self._config: Dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)
        self._sources: list[str] = []
        self._environment: str = os.environ.get("PUPTYEER_ENV", "dev")
        self._audit: Any = None  # Set by engine after construction

        # Load explicit path first
        if path:
            self._load_file(path)

        # Standard search locations (YAML then JSON)
        for candidate in [
            Path.cwd() / "pupyteer.yaml",
            Path.cwd() / "pupyteer.json",
            Path.home() / ".config" / "pupyteer" / "config.yaml",
            Path.home() / ".config" / "pupyteer" / "config.json",
            Path("/etc/pupyteer/config.yaml"),
            Path("/etc/pupyteer/config.json"),
        ]:
            if candidate.exists():
                self._load_file(str(candidate))

        # Environment-specific overlay
        self._load_environment_config()

        # Environment variable overrides
        self._apply_env_overrides()

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Retrieve value via dotted path (e.g. 'server.port')."""
        node: Any = self._config
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted_key: str, value: Any) -> None:
        """Set value via dotted path, creating intermediate dicts as needed."""
        node = self._config
        parts = dotted_key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

        # Emit configuration_changed audit event (spec section 11)
        try:
            from pupyteer.server.core.audit import AUDIT_EVENTS
            audit = getattr(self, "_audit", None)
            if audit and hasattr(audit, "emit_spec"):
                # Redact sensitive values
                from pupyteer.server.core.audit import _redact_value
                safe_value = _redact_value(dotted_key, value)
                audit.emit_spec(
                    "configuration_changed",
                    config_key=dotted_key,
                    value=safe_value,
                )
        except Exception:
            pass  # Never let audit failure break config changes

    def all(self) -> Dict[str, Any]:
        """Return a deep copy of the full config."""
        return copy.deepcopy(self._config)

    def all_safe(self) -> Dict[str, Any]:
        """Return a deep copy with sensitive values redacted."""
        return _redact_sensitive(copy.deepcopy(self._config))

    @property
    def environment(self) -> str:
        """Return the current environment name (dev/staging/prod)."""
        return self._environment

    @property
    def sources(self) -> List[str]:
        """Return list of loaded config file paths."""
        return list(self._sources)

    async def validate(self) -> bool:
        """Validate the loaded configuration."""
        required_sections = ("server", "logging", "security")
        for section in required_sections:
            if section not in self._config:
                raise ValueError(f"Missing required config section: {section}")

        port = self.get("server.port")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError(f"Invalid server.port: {port}")

        log_level = self.get("logging.level", "INFO")
        valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        if log_level.upper() not in valid_levels:
            raise ValueError(f"Invalid logging.level: {log_level}")

        # Validate operator name is a non-empty string
        operator_name = self.get("operator.name")
        if not isinstance(operator_name, str) or not operator_name.strip():
            raise ValueError(f"Invalid operator.name: {operator_name}")

        return True

    def save(self, path: str) -> None:
        """Persist current config to YAML or JSON (inferred from extension)."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        suffix = Path(path).suffix.lower()
        with open(path, "w") as fh:
            if suffix == ".json":
                json.dump(self._config, fh, indent=2, default=str)
            else:
                yaml.safe_dump(self._config, fh, default_flow_style=False)

    @classmethod
    def generate_default(cls, path: str) -> None:
        """Write the default configuration to a file."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        suffix = Path(path).suffix.lower()
        with open(path, "w") as fh:
            if suffix == ".json":
                json.dump(DEFAULT_CONFIG, fh, indent=2, default=str)
            else:
                yaml.safe_dump(DEFAULT_CONFIG, fh, default_flow_style=False)

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    def _load_file(self, path: str) -> None:
        """Load a YAML or JSON config file."""
        try:
            suffix = Path(path).suffix.lower()
            with open(path) as fh:
                if suffix == ".json":
                    data = json.load(fh)
                else:
                    data = yaml.safe_load(fh)
            if isinstance(data, dict):
                self._deep_merge(self._config, data)
                self._sources.append(path)
                logger.debug("Loaded config from %s", path)
        except Exception as exc:
            logger.warning("Failed to load config %s: %s", path, exc)

    def _load_environment_config(self) -> None:
        """Load environment-specific config overlay based on PUPTYEER_ENV."""
        env = self._environment
        env_files = [
            Path.cwd() / f"pupyteer.{env}.yaml",
            Path.cwd() / f"pupyteer.{env}.json",
            Path.home() / ".config" / "pupyteer" / f"config.{env}.yaml",
            Path.home() / ".config" / "pupyteer" / f"config.{env}.json",
            Path(f"/etc/pupyteer/config.{env}.yaml"),
            Path(f"/etc/pupyteer/config.{env}.json"),
        ]
        for candidate in env_files:
            if candidate.exists():
                self._load_file(str(candidate))

    def _apply_env_overrides(self) -> None:
        prefix = "PUPYTEER_"
        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue
            # PUPYTEER_SERVER__PORT -> server.port
            dotted = key[len(prefix):].replace("__", ".").lower()
            self.set(dotted, self._coerce(value))

    @staticmethod
    def _deep_merge(base: Dict, overlay: Dict) -> Dict:
        for k, v in overlay.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                ConfigManager._deep_merge(base[k], v)
            else:
                base[k] = v
        return base

    @staticmethod
    def _coerce(value: str) -> Any:
        if value.lower() in ("true", "yes", "on"):
            return True
        if value.lower() in ("false", "no", "off"):
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value
