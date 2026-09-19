"""Profile Manager — C2 malleable profile loading and validation for Pupyteer.

Manages the lifecycle of C2 communication profiles:
- Load from YAML/JSON files in config/profiles/
- Validate against the profile schema before activation
- Track the active profile
- Provide CRUD operations (list, show, validate, load, unload, create)
- Wire profile settings to TransportManager and SessionManager
"""
from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.profiles.parser import (
    parse_file,
    parse_string,
    normalize_profile,
    ProfileParseError,
)
from pupyteer.server.profiles.validator import (
    validate_profile,
    ProfileValidationResult,
)

logger = logging.getLogger("pupyteer.profiles")

# Default C2 profile
DEFAULT_PROFILE: Dict[str, Any] = {
    "profile": {
        "name": "HTTPS-Standard",
        "version": "1.0",
    },
    "transport": {
        "protocol": "tcp",
        "host": "0.0.0.0",
        "port": 8443,
    },
    "session": {
        "heartbeat_interval": 30,
        "timeout": 300,
        "jitter": 0.2,
    },
    "encoding": {
        "mode": "raw",
    },
    "logging": {
        "level": "INFO",
    },
    "timeouts": {
        "connect": 30,
        "response": 60,
    },
    "security": {
        "require_auth": True,
        "token_ttl": 3600,
    },
}


class C2Profile:
    """Represents a validated C2 communication profile."""

    REQUIRED_SECTIONS = ("profile", "transport")

    def __init__(self, data: Dict[str, Any], source: str = "inline"):
        self._data = data
        self._source = source
        self._name = data.get("profile", {}).get("name", "unnamed")
        self._version = data.get("profile", {}).get("version", "0.0.0")
        self._validation_result: Optional[ProfileValidationResult] = None

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    @property
    def source(self) -> str:
        return self._source

    @property
    def transport_protocol(self) -> str:
        return self._data.get("transport", {}).get("protocol", "tcp")

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Get value from profile by dotted path."""
        node: Any = self._data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def as_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    def summary(self) -> Dict[str, Any]:
        return {
            "name": self._name,
            "version": self._version,
            "source": self._source,
            "transport": self._data.get("transport", {}),
            "session": self._data.get("session", {}),
            "encoding": self._data.get("encoding", {}),
            "timeouts": self._data.get("timeouts", {}),
        }

    def validate(self) -> ProfileValidationResult:
        """Validate the profile using the schema validator.

        Returns:
            ProfileValidationResult with errors and warnings.
        """
        self._validation_result = validate_profile(self._data)
        return self._validation_result

    def validate_errors(self) -> List[str]:
        """Return list of validation error messages (empty = valid)."""
        result = self.validate()
        return result.error_messages()

    @property
    def is_valid(self) -> bool:
        """Check if the profile passes validation."""
        if self._validation_result is None:
            self.validate()
        return self._validation_result.is_valid if self._validation_result else False


class ProfileManager:
    """
    Manages C2 malleable profiles:
    - Load from YAML/JSON files in config/profiles/
    - Validate before activation
    - Track active profile
    - CRUD operations: list, show, validate, load, unload, create
    - Wire profile settings to TransportManager and SessionManager
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._profiles: Dict[str, C2Profile] = {}
        self._active_name: Optional[str] = None
        self._search_paths: List[Path] = []
        self._active_profile_data: Optional[Dict[str, Any]] = None

        # Build search paths
        self._search_paths.append(Path(config.get("paths.profiles", "./config/profiles")))
        self._search_paths.append(Path.cwd() / "config" / "profiles")

    async def initialize(self) -> None:
        """Load default profile and scan for profile files."""
        # Always have the default
        default = C2Profile(copy.deepcopy(DEFAULT_PROFILE), source="default")
        self._profiles[default.name] = default

        # Scan paths
        for search_path in self._search_paths:
            if not search_path.exists():
                search_path.mkdir(parents=True, exist_ok=True)
                continue
            for ext in ("*.yaml", "*.yml", "*.json"):
                for f in search_path.glob(ext):
                    try:
                        self._load_file(f)
                    except Exception as exc:
                        logger.warning("Failed to load profile %s: %s", f, exc)

        # Load Cobalt Strike profiles from default_profiles/
        await self._load_cs_profiles()

        # Activate default if configured
        default_name = self._config.get("profile.default", "HTTPS-Standard")
        if default_name in self._profiles:
            self._active_name = default_name

        logger.info("Profile manager initialized (%d profiles)", len(self._profiles))

    async def _load_cs_profiles(self) -> None:
        """Load Cobalt Strike .profile files from default_profiles/ directory."""
        from pupyteer.server.profiles.cs_parser import parse_cs_file
        from pupyteer.server.profiles.cs_converter import convert_cs_to_pupyteer, _get_category

        for search_path in self._search_profiles():
            default_dir = search_path / "default_profiles"
            if not default_dir.exists():
                continue
            for cs_file in default_dir.glob("*.profile"):
                try:
                    parsed = parse_cs_file(str(cs_file))
                    profile_name = cs_file.stem
                    category = _get_category(profile_name=profile_name)
                    converted = convert_cs_to_pupyteer(
                        parsed,
                        profile_name=profile_name,
                        source=f"BC-SECURITY/Malleable-C2-Profiles/{cs_file.name}",
                        category=category,
                    )
                    profile = C2Profile(converted, source=str(cs_file))
                    profile._data["profile"]["category"] = category
                    self._profiles[profile.name] = profile
                    logger.info("Loaded CS profile: %s (category=%s)", profile.name, category)
                except Exception as exc:
                    logger.warning("Failed to load CS profile %s: %s", cs_file, exc)

    def _search_profiles(self) -> List[Path]:
        """Return list of paths to search for profiles."""
        paths = list(self._search_paths)
        # Also check the module's own profiles directory
        module_dir = Path(__file__).parent
        paths.append(module_dir)
        return paths

    async def shutdown(self) -> None:
        """Clear active profile."""
        self._active_name = None
        self._active_profile_data = None

    def _load_file(self, path: Path) -> C2Profile:
        """Load a profile from a file using the parser module."""
        data = parse_file(path)
        data = normalize_profile(data)
        profile = C2Profile(data, source=str(path))
        errors = profile.validate_errors()
        if errors:
            logger.warning("Profile %s has errors: %s", path, errors)
        self._profiles[profile.name] = profile
        return profile

    # ------------------------------------------------------------------ #
    #  Profile CRUD operations                                            #
    # ------------------------------------------------------------------ #

    def list(self) -> List[Dict[str, Any]]:
        """List all available profiles with metadata.

        Returns:
            List of profile summary dictionaries.
        """
        return [
            {
                "name": p.name,
                "version": p.version,
                "transport": p.transport_protocol,
                "source": p.source,
                "active": name == self._active_name,
                "valid": p.is_valid,
            }
            for name, p in self._profiles.items()
        ]

    def show(self, name: str) -> Optional[Dict[str, Any]]:
        """Show detailed information about a profile.

        Args:
            name: Profile name.

        Returns:
            Full profile details or None if not found.
        """
        profile = self._profiles.get(name)
        if not profile:
            return None
        result = profile.validate()
        return {
            "profile": profile.as_dict(),
            "summary": profile.summary(),
            "validation": result.to_dict(),
            "active": name == self._active_name,
        }

    def validate(self, name: str) -> ProfileValidationResult:
        """Validate a profile by name.

        Args:
            name: Profile name.

        Returns:
            ProfileValidationResult.
        """
        profile = self._profiles.get(name)
        if not profile:
            result = ProfileValidationResult()
            result.add_error("profile", f"Profile not found: {name}")
            return result
        return profile.validate()

    def validate_errors(self, name: str) -> List[str]:
        """Return list of validation error messages for a profile.

        Args:
            name: Profile name.

        Returns:
            List of error message strings (empty = valid).
        """
        return self.validate(name).error_messages()

    def load(self, name: str) -> bool:
        """Load (activate) a profile.

        Validates the profile before activation. On success, stores
        the active profile data for use by TransportManager and
        SessionManager.

        Args:
            name: Profile name to activate.

        Returns:
            True if profile was loaded successfully.

        Raises:
            ValueError: If profile not found or validation fails.
        """
        if name not in self._profiles:
            raise ValueError(f"Profile not found: {name}")
        profile = self._profiles[name]
        result = profile.validate()
        if not result.is_valid:
            raise ValueError(f"Profile validation failed: {result.error_messages()}")
        self._active_name = name
        self._active_profile_data = copy.deepcopy(profile.as_dict())
        self._audit.log_event("profile_loaded", {"name": name, "transport": profile.transport_protocol})
        logger.info("Profile loaded: %s", name)
        return True

    def unload(self) -> None:
        """Unload the currently active profile."""
        if self._active_name:
            self._audit.log_event("profile_unloaded", {"name": self._active_name})
            self._active_name = None
            self._active_profile_data = None
            logger.info("Profile unloaded")

    def create(
        self,
        data: Dict[str, Any],
        name: Optional[str] = None,
        validate: bool = True,
    ) -> C2Profile:
        """Create and register a new profile.

        Args:
            data: Profile data dictionary.
            name: Optional name override.
            validate: Whether to validate before registering.

        Returns:
            The created C2Profile.

        Raises:
            ValueError: If validation fails or profile name already exists.
        """
        data = normalize_profile(data)
        if name:
            data.setdefault("profile", {})["name"] = name
        profile = C2Profile(data, source="inline")
        if validate:
            result = profile.validate()
            if not result.is_valid:
                raise ValueError(f"Invalid profile: {result.error_messages()}")
        if profile.name in self._profiles:
            raise ValueError(f"Profile already exists: {profile.name}")
        self._profiles[profile.name] = profile
        self._audit.log_event("profile_created", {"name": profile.name})
        return profile

    def create_from_file(
        self,
        path: Union[str, os.PathLike],
        name: Optional[str] = None,
    ) -> C2Profile:
        """Create a profile from a file.

        Args:
            path: Path to YAML/JSON profile file.
            name: Optional name override.

        Returns:
            The created C2Profile.
        """
        data = parse_file(path)
        if name:
            data.setdefault("profile", {})["name"] = name
        return self.create(data)

    def create_from_string(
        self,
        content: str,
        format: str = "yaml",
        name: Optional[str] = None,
    ) -> C2Profile:
        """Create a profile from a string.

        Args:
            content: Profile data as string.
            format: "yaml" or "json".
            name: Optional name override.

        Returns:
            The created C2Profile.
        """
        data = parse_string(content, format=format)
        if name:
            data.setdefault("profile", {})["name"] = name
        return self.create(data)

    def save(self, name: str, path: Optional[str] = None) -> str:
        """Persist a profile to YAML file.

        Args:
            name: Profile name to save.
            path: Optional destination path.

        Returns:
            Path where the profile was saved.

        Raises:
            ValueError: If profile not found.
        """
        profile = self._profiles.get(name)
        if not profile:
            raise ValueError(f"Profile not found: {name}")
        if not path:
            path = str(self._search_paths[0] / f"{name.lower().replace(' ', '_')}.yaml")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as fh:
            yaml.safe_dump(profile.as_dict(), fh, default_flow_style=False, sort_keys=False)
        return path

    def remove(self, name: str) -> bool:
        """Remove a profile.

        Args:
            name: Profile name to remove.

        Returns:
            True if removed successfully.

        Raises:
            ValueError: If trying to remove the active profile.
        """
        if name not in self._profiles:
            return False
        if name == self._active_name:
            raise ValueError(f"Cannot remove active profile: {name}")
        profile = self._profiles[name]
        if profile.source == "default":
            return False
        del self._profiles[name]
        self._audit.log_event("profile_removed", {"name": name})
        return True

    # ------------------------------------------------------------------ #
    #  Accessors                                                          #
    # ------------------------------------------------------------------ #

    def get(self, name: str) -> Optional[C2Profile]:
        """Get a profile by name."""
        return self._profiles.get(name)

    def active_name(self) -> Optional[str]:
        """Get the name of the currently active profile."""
        return self._active_name

    def active(self) -> Optional[C2Profile]:
        """Get the currently active profile object."""
        if self._active_name:
            return self._profiles.get(self._active_name)
        return None

    def get_active(self) -> Dict[str, Any]:
        """Get the active profile data dictionary.

        Returns:
            Active profile data or empty dict if none active.
        """
        if self._active_profile_data:
            return copy.deepcopy(self._active_profile_data)
        return {}

    def get_active_transport_config(self) -> Dict[str, Any]:
        """Get transport configuration from the active profile.

        Returns:
            Transport config dict with protocol, host, port, etc.
        """
        if self._active_profile_data:
            return copy.deepcopy(self._active_profile_data.get("transport", {}))
        return {}

    def get_active_session_config(self) -> Dict[str, Any]:
        """Get session configuration from the active profile.

        Returns:
            Session config dict with heartbeat, timeout, jitter.
        """
        if self._active_profile_data:
            return copy.deepcopy(self._active_profile_data.get("session", {}))
        return {}

    def get_active_encoding_config(self) -> Dict[str, Any]:
        """Get encoding configuration from the active profile.

        Returns:
            Encoding config dict with mode, key, etc.
        """
        if self._active_profile_data:
            return copy.deepcopy(self._active_profile_data.get("encoding", {}))
        return {}

    def get_active_timeouts_config(self) -> Dict[str, Any]:
        """Get timeouts configuration from the active profile.

        Returns:
            Timeouts config dict with connect and response values.
        """
        if self._active_profile_data:
            return copy.deepcopy(self._active_profile_data.get("timeouts", {}))
        return {}
