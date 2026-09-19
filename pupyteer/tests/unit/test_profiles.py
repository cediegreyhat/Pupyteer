"""Unit tests for Pupyteer Profile System — parser, validator, and manager."""
import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager, DEFAULT_CONFIG
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.profiles.parser import (
    parse_yaml,
    parse_json,
    parse_file,
    parse_string,
    normalize_profile,
    ProfileParseError,
)
from pupyteer.server.profiles.validator import (
    validate_profile,
    ProfileValidationResult,
    ProfileValidationError,
)
from pupyteer.server.profiles.manager import ProfileManager, C2Profile, DEFAULT_PROFILE


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.fixture
def valid_profile_data():
    return {
        "profile": {"name": "Test-Profile", "version": "1.0"},
        "transport": {"protocol": "https", "host": "127.0.0.1", "port": 443},
        "session": {"heartbeat_interval": 30, "timeout": 300, "jitter": 0.2},
        "encoding": {"mode": "base64"},
        "logging": {"level": "INFO"},
        "timeouts": {"connect": 10, "response": 30},
        "security": {"require_auth": True, "token_ttl": 3600},
    }


@pytest.fixture
def valid_profile_yaml(valid_profile_data):
    return yaml.safe_dump(valid_profile_data)


@pytest.fixture
def valid_profile_json(valid_profile_data):
    return json.dumps(valid_profile_data)


# ─── Parser Tests ─────────────────────────────────────────────────────


class TestParseYaml:
    def test_parse_valid_yaml(self, valid_profile_yaml):
        data = parse_yaml(valid_profile_yaml)
        assert data["profile"]["name"] == "Test-Profile"
        assert data["transport"]["protocol"] == "https"

    def test_parse_invalid_yaml(self):
        with pytest.raises(ProfileParseError):
            parse_yaml("{{invalid: yaml: [")

    def test_parse_yaml_non_mapping(self):
        with pytest.raises(ProfileParseError):
            parse_yaml("- item1\n- item2")

    def test_parse_yaml_list(self):
        with pytest.raises(ProfileParseError):
            parse_yaml("[]")


class TestParseJson:
    def test_parse_valid_json(self, valid_profile_json):
        data = parse_json(valid_profile_json)
        assert data["profile"]["name"] == "Test-Profile"

    def test_parse_invalid_json(self):
        with pytest.raises(ProfileParseError):
            parse_json("{invalid json")

    def test_parse_json_non_object(self):
        with pytest.raises(ProfileParseError):
            parse_json("[1, 2, 3]")


class TestParseFile:
    def test_parse_yaml_file(self, valid_profile_data):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(valid_profile_data, f)
            f.flush()
            path = f.name
        try:
            data = parse_file(path)
            assert data["profile"]["name"] == "Test-Profile"
        finally:
            os.unlink(path)

    def test_parse_json_file(self, valid_profile_data):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(valid_profile_data, f)
            f.flush()
            path = f.name
        try:
            data = parse_file(path)
            assert data["profile"]["name"] == "Test-Profile"
        finally:
            os.unlink(path)

    def test_parse_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_file("/nonexistent/path/profile.yaml")


class TestParseString:
    def test_parse_yaml_string(self, valid_profile_yaml):
        data = parse_string(valid_profile_yaml, format="yaml")
        assert data["profile"]["name"] == "Test-Profile"

    def test_parse_json_string(self, valid_profile_json):
        data = parse_string(valid_profile_json, format="json")
        assert data["profile"]["name"] == "Test-Profile"

    def test_parse_invalid_format(self):
        with pytest.raises(ValueError):
            parse_string("data", format="xml")


class TestNormalizeProfile:
    def test_full_profile(self, valid_profile_data):
        result = normalize_profile(valid_profile_data)
        assert result["profile"]["name"] == "Test-Profile"
        assert result["transport"]["protocol"] == "https"
        assert result["transport"]["host"] == "127.0.0.1"
        assert result["transport"]["port"] == 443
        assert result["session"]["heartbeat_interval"] == 30
        assert result["session"]["timeout"] == 300
        assert result["session"]["jitter"] == 0.2
        assert result["encoding"]["mode"] == "base64"
        assert result["logging"]["level"] == "INFO"
        assert result["timeouts"]["connect"] == 10
        assert result["timeouts"]["response"] == 30
        assert result["security"]["require_auth"] is True
        assert result["security"]["token_ttl"] == 3600

    def test_minimal_profile(self):
        data = {"profile": {"name": "Minimal"}, "transport": {"protocol": "tcp"}}
        result = normalize_profile(data)
        assert result["profile"]["name"] == "Minimal"
        assert result["profile"]["version"] == "1.0"
        assert result["transport"]["host"] == "0.0.0.0"
        assert result["transport"]["port"] == 8443
        assert result["session"]["heartbeat_interval"] == 30
        assert result["encoding"]["mode"] == "raw"

    def test_protocol_lowered(self):
        data = {"profile": {"name": "P"}, "transport": {"protocol": "HTTPS"}}
        result = normalize_profile(data)
        assert result["transport"]["protocol"] == "https"

    def test_missing_profile_section(self):
        data = {"transport": {"protocol": "tcp"}}
        result = normalize_profile(data)
        assert result["profile"]["name"] == "unnamed"
        assert result["profile"]["version"] == "1.0"

    def test_missing_transport_section(self):
        data = {"profile": {"name": "Test"}}
        result = normalize_profile(data)
        assert result["transport"]["protocol"] == "tcp"
        assert result["transport"]["host"] == "0.0.0.0"
        assert result["transport"]["port"] == 8443

    def test_invalid_heartbeat_type(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "session": {"heartbeat_interval": "not-a-number"},
        }
        with pytest.raises(ProfileParseError):
            normalize_profile(data)

    def test_negative_heartbeat(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "session": {"heartbeat_interval": -5},
        }
        with pytest.raises(ProfileParseError):
            normalize_profile(data)

    def test_jitter_out_of_range(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "session": {"jitter": 5.0},
        }
        with pytest.raises(ProfileParseError):
            normalize_profile(data)

    def test_custom_headers_preserved(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {
                "protocol": "https",
                "custom_headers": {"User-Agent": "Mozilla/5.0"},
            },
        }
        result = normalize_profile(data)
        assert result["transport"]["custom_headers"]["User-Agent"] == "Mozilla/5.0"


# ─── Validator Tests ──────────────────────────────────────────────────


class TestValidateProfile:
    def test_valid_profile(self, valid_profile_data):
        result = validate_profile(valid_profile_data)
        assert result.is_valid

    def test_missing_profile_section(self):
        result = validate_profile({"transport": {"protocol": "tcp"}})
        assert not result.is_valid
        assert any("profile" in e.path and "Missing" in e.message for e in result.errors)

    def test_missing_transport_section(self):
        result = validate_profile({"profile": {"name": "Test"}})
        assert not result.is_valid
        assert any("transport" in e.path for e in result.errors)

    def test_missing_profile_name(self):
        data = {"profile": {"version": "1.0"}, "transport": {"protocol": "tcp"}}
        result = validate_profile(data)
        assert not result.is_valid
        assert any("profile.name" in e.path for e in result.errors)

    def test_empty_profile_name(self):
        data = {"profile": {"name": "  "}, "transport": {"protocol": "tcp"}}
        result = validate_profile(data)
        assert not result.is_valid

    def test_invalid_profile_name(self):
        data = {"profile": {"name": "invalid name with spaces!"}, "transport": {"protocol": "tcp"}}
        result = validate_profile(data)
        assert not result.is_valid

    def test_unsupported_protocol(self):
        data = {"profile": {"name": "Test"}, "transport": {"protocol": "ftp"}}
        result = validate_profile(data)
        assert not result.is_valid
        assert any("protocol" in e.path for e in result.errors)

    def test_port_too_high(self):
        data = {"profile": {"name": "Test"}, "transport": {"protocol": "tcp", "port": 99999}}
        result = validate_profile(data)
        assert not result.is_valid
        assert any("port" in e.path for e in result.errors)

    def test_port_negative(self):
        data = {"profile": {"name": "Test"}, "transport": {"protocol": "tcp", "port": -1}}
        result = validate_profile(data)
        assert not result.is_valid

    def test_port_zero(self):
        data = {"profile": {"name": "Test"}, "transport": {"protocol": "tcp", "port": 0}}
        result = validate_profile(data)
        assert not result.is_valid

    def test_heartbeat_too_low(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "session": {"heartbeat_interval": 1},
        }
        result = validate_profile(data)
        assert result.is_valid  # Still valid, but warning
        assert result.has_warnings

    def test_timeout_less_than_heartbeat(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "session": {"heartbeat_interval": 100, "timeout": 30},
        }
        result = validate_profile(data)
        assert not result.is_valid

    def test_unsupported_encoding_mode(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "encoding": {"mode": "rot13"},
        }
        result = validate_profile(data)
        assert not result.is_valid
        assert any("encoding.mode" in e.path for e in result.errors)

    def test_xor_without_key(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "encoding": {"mode": "xor"},
        }
        result = validate_profile(data)
        assert not result.is_valid
        assert any("key" in e.path for e in result.errors)

    def test_aes_without_key(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "encoding": {"mode": "aes"},
        }
        result = validate_profile(data)
        assert not result.is_valid

    def test_invalid_log_level(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "logging": {"level": "TRACE"},
        }
        result = validate_profile(data)
        assert not result.is_valid

    def test_non_dict_profile(self):
        result = validate_profile("not a dict")
        assert not result.is_valid

    def test_non_dict_transport(self):
        data = {"profile": {"name": "Test"}, "transport": "not-a-dict"}
        result = validate_profile(data)
        assert not result.is_valid

    def test_non_dict_session(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "session": "not-a-dict",
        }
        result = validate_profile(data)
        assert not result.is_valid

    def test_warn_auth_disabled_on_network(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp", "host": "10.0.0.1", "port": 8080},
            "security": {"require_auth": False},
        }
        result = validate_profile(data)
        assert result.is_valid  # Still valid
        assert result.has_warnings
        assert any("require_auth" in w.path for w in result.warnings)

    def test_no_warn_auth_disabled_on_loopback(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp", "host": "127.0.0.1", "port": 8080},
            "security": {"require_auth": False},
        }
        result = validate_profile(data)
        assert result.is_valid
        # No auth-related warning for loopback
        auth_warnings = [w for w in result.warnings if "require_auth" in w.path]
        assert len(auth_warnings) == 0

    def test_connect_timeout_greater_than_response(self):
        data = {
            "profile": {"name": "Test"},
            "transport": {"protocol": "tcp"},
            "timeouts": {"connect": 60, "response": 10},
        }
        result = validate_profile(data)
        assert not result.is_valid

    def test_valid_websocket_profile(self):
        data = {
            "profile": {"name": "WS-Profile"},
            "transport": {"protocol": "websocket", "host": "0.0.0.0", "port": 8080},
        }
        result = validate_profile(data)
        assert result.is_valid

    def test_valid_dns_profile(self):
        data = {
            "profile": {"name": "DNS-Profile"},
            "transport": {"protocol": "dns", "host": "0.0.0.0", "port": 53},
        }
        result = validate_profile(data)
        assert result.is_valid

    def test_valid_protocols(self):
        for protocol in ("tcp", "udp", "http", "https", "websocket", "ws", "wss", "dns", "doh", "dot", "namedpipe"):
            data = {"profile": {"name": f"P-{protocol}"}, "transport": {"protocol": protocol}}
            result = validate_profile(data)
            assert result.is_valid, f"Protocol {protocol} should be valid"

    def test_to_dict(self, valid_profile_data):
        result = validate_profile(valid_profile_data)
        d = result.to_dict()
        assert d["valid"] is True
        assert d["error_count"] == 0
        assert d["warning_count"] >= 0

    def test_merge_results(self):
        r1 = ProfileValidationResult()
        r1.add_error("field1", "Error 1")
        r2 = ProfileValidationResult()
        r2.add_error("field2", "Error 2")
        r1.merge(r2)
        assert len(r1.errors) == 2


# ─── C2Profile Tests ─────────────────────────────────────────────────


class TestC2Profile:
    def test_name_property(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        assert p.name == "Test-Profile"

    def test_version_property(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        assert p.version == "1.0"

    def test_source_default(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        assert p.source == "inline"

    def test_transport_protocol(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        assert p.transport_protocol == "https"

    def test_get_dotted(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        assert p.get("profile.name") == "Test-Profile"
        assert p.get("transport.port") == 443
        assert p.get("session.heartbeat_interval") == 30

    def test_get_missing(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        assert p.get("nonexistent.key") is None
        assert p.get("nonexistent.key", "default") == "default"

    def test_as_dict(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        d = p.as_dict()
        assert d == valid_profile_data

    def test_as_dict_is_deep_copy(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        d = p.as_dict()
        d["profile"]["name"] = "modified"
        assert p.name == "Test-Profile"  # Original unchanged

    def test_summary(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        s = p.summary()
        assert s["name"] == "Test-Profile"
        assert s["version"] == "1.0"
        assert "transport" in s
        assert "session" in s
        assert "encoding" in s
        assert "timeouts" in s

    def test_validate(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        result = p.validate()
        assert result.is_valid

    def test_validate_errors(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        errors = p.validate_errors()
        assert errors == []

    def test_is_valid(self, valid_profile_data):
        p = C2Profile(valid_profile_data)
        assert p.is_valid

    def test_is_not_valid(self):
        p = C2Profile({"profile": {"name": "X"}, "transport": {"protocol": "invalid"}})
        assert not p.is_valid

    def test_default_name(self):
        p = C2Profile({})
        assert p.name == "unnamed"

    def test_validate_invalid_profile(self):
        p = C2Profile({"transport": {"protocol": "tcp"}})  # Missing profile
        result = p.validate()
        assert not result.is_valid


# ─── ProfileManager Tests ────────────────────────────────────────────


class TestProfileManager:
    @pytest.fixture
    def profiles(self, config, audit):
        return ProfileManager(config, audit)

    @pytest.mark.asyncio
    async def test_default_profile_loaded(self, profiles):
        await profiles.initialize()
        default = profiles.get("HTTPS-Standard")
        assert default is not None
        assert default.name == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_list_profiles(self, profiles):
        await profiles.initialize()
        plist = profiles.list()
        assert len(plist) >= 1
        names = [p["name"] for p in plist]
        assert "HTTPS-Standard" in names

    @pytest.mark.asyncio
    async def test_active_name(self, profiles):
        await profiles.initialize()
        assert profiles.active_name() == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_active(self, profiles):
        await profiles.initialize()
        p = profiles.active()
        assert p is not None
        assert p.name == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, profiles):
        await profiles.initialize()
        result = profiles.get("No-Such-Profile")
        assert result is None

    @pytest.mark.asyncio
    async def test_shutdown_clears_profiles(self, profiles):
        await profiles.initialize()
        await profiles.shutdown()
        assert profiles.active_name() is None

    @pytest.mark.asyncio
    async def test_load_profile(self, profiles):
        await profiles.initialize()
        ok = profiles.load("HTTPS-Standard")
        assert ok is True
        assert profiles.active_name() == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_unload_profile(self, profiles):
        await profiles.initialize()
        profiles.load("HTTPS-Standard")
        profiles.unload()
        assert profiles.active_name() is None

    @pytest.mark.asyncio
    async def test_validate(self, profiles):
        await profiles.initialize()
        result = profiles.validate("HTTPS-Standard")
        assert result.is_valid

    @pytest.mark.asyncio
    async def test_validate_nonexistent(self, profiles):
        await profiles.initialize()
        result = profiles.validate("No-Such")
        assert not result.is_valid

    @pytest.mark.asyncio
    async def test_create_profile(self, profiles):
        await profiles.initialize()
        data = {
            "profile": {"name": "Test-Custom", "version": "1.0"},
            "transport": {"protocol": "tcp", "host": "127.0.0.1", "port": 4444},
        }
        profile = profiles.create(data)
        assert profile.name == "Test-Custom"
        assert profile.get("transport.port") == 4444

    @pytest.mark.asyncio
    async def test_create_invalid_raises(self, profiles):
        await profiles.initialize()
        # Invalid: unsupported protocol triggers validation failure
        data = {"profile": {"name": "Bad-Proto"}, "transport": {"protocol": "invalid_proto"}}
        with pytest.raises(ValueError):
            profiles.create(data)

    @pytest.mark.asyncio
    async def test_create_duplicate_raises(self, profiles):
        await profiles.initialize()
        data = {
            "profile": {"name": "HTTPS-Standard", "version": "1.0"},
            "transport": {"protocol": "tcp"},
        }
        with pytest.raises(ValueError):
            profiles.create(data)

    @pytest.mark.asyncio
    async def test_save_and_reload(self, profiles, tmp_path):
        await profiles.initialize()
        save_path = tmp_path / "test_profile.yaml"
        profiles.save("HTTPS-Standard", str(save_path))
        assert save_path.exists()
        profiles._load_file(Path(save_path))
        assert profiles.get("HTTPS-Standard") is not None

    @pytest.mark.asyncio
    async def test_remove_profile(self, profiles):
        await profiles.initialize()
        data = {
            "profile": {"name": "Removable", "version": "1.0"},
            "transport": {"protocol": "tcp"},
        }
        profiles.create(data)
        ok = profiles.remove("Removable")
        assert ok is True
        assert profiles.get("Removable") is None

    @pytest.mark.asyncio
    async def test_remove_active_raises(self, profiles):
        await profiles.initialize()
        with pytest.raises(ValueError):
            profiles.remove("HTTPS-Standard")

    @pytest.mark.asyncio
    async def test_remove_default_fails(self, profiles):
        await profiles.initialize()
        # Default profile (HTTPS-Standard) cannot be removed
        # - source == "default" → remove returns False
        # - loaded as active → remove raises ValueError
        try:
            ok = profiles.remove("HTTPS-Standard")
            # If we get here, the profile wasn't active
            assert ok is False
        except ValueError:
            # Expected when the profile is both default AND active
            pass
        assert profiles.get("HTTPS-Standard") is not None

    @pytest.mark.asyncio
    async def test_show(self, profiles):
        await profiles.initialize()
        info = profiles.show("HTTPS-Standard")
        assert info is not None
        assert "profile" in info
        assert "summary" in info
        assert "validation" in info

    @pytest.mark.asyncio
    async def test_show_nonexistent(self, profiles):
        await profiles.initialize()
        info = profiles.show("No-Such")
        assert info is None

    @pytest.mark.asyncio
    async def test_get_active_transport_config(self, profiles):
        await profiles.initialize()
        profiles.load("HTTPS-Standard")
        tc = profiles.get_active_transport_config()
        assert "protocol" in tc
        assert "host" in tc
        assert "port" in tc

    @pytest.mark.asyncio
    async def test_get_active_session_config(self, profiles):
        await profiles.initialize()
        profiles.load("HTTPS-Standard")
        sc = profiles.get_active_session_config()
        assert "heartbeat_interval" in sc
        assert "timeout" in sc
        assert "jitter" in sc

    @pytest.mark.asyncio
    async def test_get_active_encoding_config(self, profiles):
        await profiles.initialize()
        profiles.load("HTTPS-Standard")
        ec = profiles.get_active_encoding_config()
        assert "mode" in ec

    @pytest.mark.asyncio
    async def test_get_active_timeouts_config(self, profiles):
        await profiles.initialize()
        profiles.load("HTTPS-Standard")
        tc = profiles.get_active_timeouts_config()
        assert "connect" in tc
        assert "response" in tc

    @pytest.mark.asyncio
    async def test_get_active_no_profile(self, profiles):
        await profiles.initialize()
        # No active profile
        profiles.unload()
        assert profiles.get_active() == {}
        assert profiles.get_active_transport_config() == {}

    @pytest.mark.asyncio
    async def test_create_from_file(self, profiles, tmp_path, valid_profile_data):
        await profiles.initialize()
        file_path = tmp_path / "custom_profile.yaml"
        with open(file_path, "w") as f:
            yaml.safe_dump(valid_profile_data, f)
        profile = profiles.create_from_file(file_path)
        assert profile.name == "Test-Profile"

    @pytest.mark.asyncio
    async def test_create_from_string_yaml(self, profiles, valid_profile_yaml):
        await profiles.initialize()
        profile = profiles.create_from_string(valid_profile_yaml, format="yaml")
        assert profile.name == "Test-Profile"

    @pytest.mark.asyncio
    async def test_create_from_string_json(self, profiles, valid_profile_json):
        await profiles.initialize()
        profile = profiles.create_from_string(valid_profile_json, format="json")
        assert profile.name == "Test-Profile"

    @pytest.mark.asyncio
    async def test_create_with_name_override(self, profiles, valid_profile_data):
        await profiles.initialize()
        profile = profiles.create(valid_profile_data, name="Overridden-Name")
        assert profile.name == "Overridden-Name"

    @pytest.mark.asyncio
    async def test_create_skip_validation(self, profiles):
        await profiles.initialize()
        data = {"profile": {"name": "No-Validate"}}
        # Missing transport, would fail validation
        profile = profiles.create(data, validate=False)
        assert profile.name == "No-Validate"

    @pytest.mark.asyncio
    async def test_list_includes_active_status(self, profiles):
        await profiles.initialize()
        plist = profiles.list()
        active_profiles = [p for p in plist if p["active"]]
        assert len(active_profiles) == 1
        assert active_profiles[0]["name"] == "HTTPS-Standard"

    @pytest.mark.asyncio
    async def test_list_includes_validity(self, profiles):
        await profiles.initialize()
        plist = profiles.list()
        for p in plist:
            assert "valid" in p

    @pytest.mark.asyncio
    async def test_custom_default_profile_name(self, config, audit):
        config.set("profile.default", "Custom-Profile")
        pm = ProfileManager(config, audit)
        await pm.initialize()
        # If custom profile doesn't exist, active_name should be None
        assert pm.active_name() is None

    @pytest.mark.asyncio
    async def test_load_invalid_profile_raises(self, profiles):
        await profiles.initialize()
        # Create an invalid profile directly
        invalid_data = {"profile": {"name": "Invalid-Profile"}}
        profiles._profiles["Invalid-Profile"] = C2Profile(invalid_data)
        with pytest.raises(ValueError):
            profiles.load("Invalid-Profile")

    @pytest.mark.asyncio
    async def test_load_nonexistent_raises(self, profiles):
        await profiles.initialize()
        with pytest.raises(ValueError):
            profiles.load("Does-Not-Exist")

    @pytest.mark.asyncio
    async def test_initialize_scans_profiles_dir(self, config, audit, tmp_path):
        # Create a profiles directory with a custom profile
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir()
        custom = profiles_dir / "custom.yaml"
        custom.write_text(yaml.safe_dump({
            "profile": {"name": "Scanned-Profile", "version": "1.0"},
            "transport": {"protocol": "tcp", "host": "127.0.0.1", "port": 9999},
        }))
        config.set("paths.profiles", str(profiles_dir))
        pm = ProfileManager(config, audit)
        await pm.initialize()
        assert pm.get("Scanned-Profile") is not None

    @pytest.mark.asyncio
    async def test_yaml_profile_from_existing_file(self, config, audit):
        """Test loading the pre-existing https_standard.yaml profile."""
        pm = ProfileManager(config, audit)
        await pm.initialize()
        p = pm.get("HTTPS-Standard")
        assert p is not None


class TestProfileValidationError:
    def test_str_representation(self):
        e = ProfileValidationError("path", "message")
        assert str(e) == "[error] path: message"

    def test_to_dict(self):
        e = ProfileValidationError("path", "message", "warning")
        d = e.to_dict()
        assert d["path"] == "path"
        assert d["message"] == "message"
        assert d["severity"] == "warning"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
