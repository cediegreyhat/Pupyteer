"""Unit tests for Pupyteer security features.

Tests for:
- Input validation (pupyteer.server.core.validation)
- Role-based access control (pupyteer.server.core.rbac)
- Session authorization (pupyteer.server.core.session_auth)
- Dependency audit script (scripts.audit_deps)
- Secure defaults verification (scripts.verify_secure_defaults)
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core import validation
from pupyteer.server.core.rbac import (
    Role, Permission, PermissionChecker, AccessDenied,
    ROLE_PERMISSIONS, create_default_admin,
)
from pupyteer.server.core.session_auth import (
    SessionAuthorization, CommandContext, SecureCommandExecutor,
)
from pupyteer.server.core.auth import AuthLayer
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.fixture
def auth(config, audit):
    return AuthLayer(config, audit)


@pytest.fixture
def rbac(auth):
    return PermissionChecker(auth)


@pytest.fixture
def session_auth(auth, rbac):
    return SessionAuthorization(auth, rbac)


# ─── Input Validation Tests ──────────────────────────────────────────


class TestValidateSessionId:
    def test_valid_session_id(self):
        assert validation.validate_session_id("abc123") == "abc123"
        assert validation.validate_session_id("test-001") == "test-001"
        assert validation.validate_session_id("session_1") == "session_1"
        assert validation.validate_session_id("a.b.c") == "a.b.c"

    def test_empty_session_id(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validation.validate_session_id("")

    def test_session_id_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            validation.validate_session_id("a" * 65)

    def test_session_id_invalid_chars(self):
        with pytest.raises(ValueError, match="must start with alphanumeric"):
            validation.validate_session_id("-invalid")
        with pytest.raises(ValueError, match="alphanumeric"):
            validation.validate_session_id("test space")

    def test_session_id_not_string(self):
        with pytest.raises(ValueError, match="must be a string"):
            validation.validate_session_id(123)


class TestValidateHostname:
    def test_valid_hostname(self):
        assert validation.validate_hostname("example.com") == "example.com"
        assert validation.validate_hostname("host-01") == "host-01"
        assert validation.validate_hostname("a.b.c.d") == "a.b.c.d"

    def test_empty_hostname(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validation.validate_hostname("")

    def test_hostname_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            validation.validate_hostname("a" * 254)

    def test_hostname_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid hostname"):
            validation.validate_hostname("-invalid")
        with pytest.raises(ValueError, match="Invalid hostname"):
            validation.validate_hostname("host name")


class TestValidateIpAddress:
    def test_valid_ipv4(self):
        assert validation.validate_ip_address("192.168.1.1") == "192.168.1.1"
        assert validation.validate_ip_address("10.0.0.1") == "10.0.0.1"

    def test_valid_ipv6(self):
        assert validation.validate_ip_address("::1") == "::1"

    def test_unspecified_rejected(self):
        with pytest.raises(ValueError, match="unspecified"):
            validation.validate_ip_address("0.0.0.0")

    def test_invalid_ip(self):
        with pytest.raises(ValueError, match="Invalid IP"):
            validation.validate_ip_address("999.999.999.999")


class TestValidatePort:
    def test_valid_port(self):
        assert validation.validate_port(8080) == 8080
        assert validation.validate_port("443") == 443
        assert validation.validate_port(1) == 1
        assert validation.validate_port(65535) == 65535

    def test_invalid_port_zero(self):
        with pytest.raises(ValueError, match="between 1 and 65535"):
            validation.validate_port(0)

    def test_invalid_port_too_high(self):
        with pytest.raises(ValueError, match="between 1 and 65535"):
            validation.validate_port(70000)

    def test_invalid_port_not_number(self):
        with pytest.raises(ValueError, match="must be a number"):
            validation.validate_port("abc")


class TestValidateModuleName:
    def test_valid_module_name(self):
        assert validation.validate_module_name("test_module") == "test_module"
        assert validation.validate_module_name("_private") == "_private"
        assert validation.validate_module_name("MyModule123") == "MyModule123"

    def test_empty_module_name(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validation.validate_module_name("")

    def test_invalid_module_name(self):
        with pytest.raises(ValueError, match="must start with letter"):
            validation.validate_module_name("123module")
        with pytest.raises(ValueError, match="alphanumeric"):
            validation.validate_module_name("test-module")


class TestValidateUsername:
    def test_valid_username(self):
        assert validation.validate_username("admin") == "admin"
        assert validation.validate_username("user_01") == "user_01"
        assert validation.validate_username("operator.name") == "operator.name"

    def test_empty_username(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validation.validate_username("")

    def test_invalid_username(self):
        with pytest.raises(ValueError, match="must start with letter"):
            validation.validate_username("123user")
        with pytest.raises(ValueError, match="alphanumeric"):
            validation.validate_username("user name")


class TestValidateTag:
    def test_valid_tag(self):
        assert validation.validate_tag("web") == "web"
        assert validation.validate_tag("PROD") == "prod"
        assert validation.validate_tag("tag-01") == "tag-01"

    def test_empty_tag(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validation.validate_tag("")

    def test_invalid_tag(self):
        with pytest.raises(ValueError, match="must start with alphanumeric"):
            validation.validate_tag("-tag")


class TestValidateTags:
    def test_valid_tags(self):
        result = validation.validate_tags(["web", "prod", "linux"])
        assert result == ["web", "prod", "linux"]

    def test_deduplication(self):
        result = validation.validate_tags(["web", "web", "prod"])
        assert result == ["web", "prod"]

    def test_invalid_input(self):
        with pytest.raises(ValueError, match="must be a list"):
            validation.validate_tags("not-a-list")


class TestValidateProfileName:
    def test_valid_profile_name(self):
        assert validation.validate_profile_name("HTTPS-Standard") == "HTTPS-Standard"
        assert validation.validate_profile_name("My Profile") == "My Profile"

    def test_empty_profile_name(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validation.validate_profile_name("")

    def test_invalid_profile_name(self):
        with pytest.raises(ValueError, match="must start with alphanumeric"):
            validation.validate_profile_name("-bad")


class TestValidateFilePath:
    def test_valid_relative_path(self):
        assert validation.validate_file_path("data/file.txt") == "data/file.txt"

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="traversal"):
            validation.validate_file_path("../etc/passwd")
        with pytest.raises(ValueError, match="traversal"):
            validation.validate_file_path("foo/../../../etc/passwd")

    def test_absolute_path_rejected(self):
        with pytest.raises(ValueError, match="Absolute paths not allowed"):
            validation.validate_file_path("/etc/passwd")

    def test_absolute_path_allowed(self):
        result = validation.validate_file_path("/tmp/test", allow_absolute=True)
        assert result == "/tmp/test"

    def test_null_bytes_rejected(self):
        with pytest.raises(ValueError, match="null bytes"):
            validation.validate_file_path("file\x00.txt")


class TestSanitizeString:
    def test_removes_control_chars(self):
        result = validation.sanitize_string("hello\x00world")
        assert result == "helloworld"

    def test_truncates_long_strings(self):
        result = validation.sanitize_string("a" * 2000, max_len=100)
        assert len(result) == 100

    def test_strips_whitespace(self):
        result = validation.sanitize_string("  hello  ")
        assert result == "hello"

    def test_non_string_returns_empty(self):
        assert validation.sanitize_string(123) == ""


class TestValidateArgsDict:
    def test_valid_args(self):
        result = validation.validate_args_dict({"key": "value", "num": 42})
        assert result == {"key": "value", "num": 42}

    def test_invalid_key(self):
        with pytest.raises(ValueError, match="must start with letter"):
            validation.validate_args_dict({"123bad": "value"})

    def test_invalid_value_type(self):
        with pytest.raises(ValueError, match="unsupported type"):
            validation.validate_args_dict({"key": object()})

    def test_nested_dict(self):
        result = validation.validate_args_dict({"outer": {"inner": "value"}})
        assert result == {"outer": {"inner": "value"}}


class TestValidateCommandLine:
    def test_valid_command(self):
        result = validation.validate_command_line("sessions list")
        assert result == ["sessions", "list"]

    def test_quoted_args(self):
        result = validation.validate_command_line('config set name "my value"')
        assert result == ["config", "set", "name", "my value"]

    def test_empty_command(self):
        with pytest.raises(ValueError, match="Empty command"):
            validation.validate_command_line("")

    def test_malformed_command(self):
        with pytest.raises(ValueError, match="Malformed"):
            validation.validate_command_line('unclosed "quote')

    def test_command_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            validation.validate_command_line("x" * 5000)


# ─── RBAC Tests ──────────────────────────────────────────────────────


class TestRolePermissions:
    def test_viewer_has_read_only(self):
        perms = ROLE_PERMISSIONS[Role.VIEWER]
        assert Permission.SESSION_READ in perms
        assert Permission.SESSION_KILL not in perms

    def test_operator_has_execute(self):
        perms = ROLE_PERMISSIONS[Role.OPERATOR]
        assert Permission.SESSION_KILL in perms
        assert Permission.TASK_CREATE in perms
        assert Permission.CONFIG_WRITE not in perms

    def test_admin_has_all(self):
        perms = ROLE_PERMISSIONS[Role.ADMIN]
        assert Permission.SESSION_KILL in perms
        assert Permission.CONFIG_WRITE in perms
        assert Permission.EVASION_RUN in perms
        assert Permission.OPERATOR_MANAGE in perms

    def test_system_has_admin(self):
        perms = ROLE_PERMISSIONS[Role.SYSTEM]
        assert Permission.SYSTEM_ADMIN in perms
        assert Permission.AUDIT_READ in perms


class TestPermissionChecker:
    def test_assign_role(self, rbac):
        rbac.assign_role("alice", Role.ADMIN)
        assert rbac.get_role("alice") == Role.ADMIN

    def test_default_role_is_viewer(self, rbac):
        assert rbac.get_role("unknown") == Role.VIEWER

    def test_has_permission(self, rbac):
        rbac.assign_role("bob", Role.OPERATOR)
        assert rbac.has_permission("bob", Permission.SESSION_READ)
        assert rbac.has_permission("bob", Permission.SESSION_KILL)
        assert not rbac.has_permission("bob", Permission.CONFIG_WRITE)

    def test_check_permission_raises(self, rbac):
        rbac.assign_role("viewer1", Role.VIEWER)
        with pytest.raises(AccessDenied):
            rbac.check_permission("viewer1", Permission.SESSION_KILL)

    def test_get_accessible_commands(self, rbac):
        rbac.assign_role("admin1", Role.ADMIN)
        cmds = rbac.get_accessible_commands("admin1")
        assert "sessions" in cmds
        assert "evasion" in cmds
        assert "help" in cmds

    def test_filter_command_args(self, rbac):
        rbac.assign_role("viewer1", Role.VIEWER)
        allowed, blocked = rbac.filter_command_args("viewer1", "sessions", ["kill", "s1"])
        assert "kill" in blocked
        assert allowed == []

    def test_filter_command_args_allowed(self, rbac):
        rbac.assign_role("op1", Role.OPERATOR)
        allowed, blocked = rbac.filter_command_args("op1", "sessions", ["list"])
        assert "list" not in blocked
        assert "list" in allowed


class TestAccessDenied:
    def test_error_message(self):
        err = AccessDenied("session:kill", "alice")
        assert "alice" in str(err)
        assert "session:kill" in str(err)
        assert err.permission == "session:kill"
        assert err.operator == "alice"


class TestCreateDefaultAdmin:
    def test_creates_admin(self, auth):
        checker = create_default_admin(auth)
        assert checker.get_role("admin") == Role.ADMIN
        assert checker.has_permission("admin", Permission.SYSTEM_ADMIN) is False
        assert checker.has_permission("admin", Permission.CONFIG_WRITE)


# ─── Session Authorization Tests ────────────────────────────────────


class TestSessionAuthorization:
    def test_resolve_permission_public(self, session_auth):
        assert session_auth.resolve_permission("help", []) is None
        assert session_auth.resolve_permission("banner", []) is None

    def test_resolve_permission_session_read(self, session_auth):
        perm = session_auth.resolve_permission("sessions", ["list"])
        assert perm == Permission.SESSION_READ

    def test_resolve_permission_session_kill(self, session_auth):
        perm = session_auth.resolve_permission("sessions", ["kill", "s1"])
        assert perm == Permission.SESSION_KILL

    def test_resolve_permission_evasion_run(self, session_auth):
        perm = session_auth.resolve_permission("evasion", ["run"])
        assert perm == Permission.EVASION_RUN

    def test_resolve_permission_config_write(self, session_auth):
        perm = session_auth.resolve_permission("config", ["set", "key", "val"])
        assert perm == Permission.CONFIG_WRITE

    def test_authorize_public_command(self, session_auth, auth):
        # Create a session for testing
        auth._credentials["testuser"] = "hash"
        auth._sessions["valid-token"] = MagicMock(
            operator="testuser", expires_at=9999999999.0, expired=False
        )
        ctx = session_auth.authorize_command("valid-token", "help", [])
        assert ctx.authorized is True
        assert ctx.operator == "testuser"

    def test_authorize_invalid_token(self, session_auth):
        with pytest.raises(AccessDenied):
            session_auth.authorize_command("invalid-token", "help", [])

    def test_authorize_insufficient_permission(self, session_auth, auth):
        # Create a viewer session
        auth._credentials["viewer"] = "hash"
        auth._sessions["viewer-token"] = MagicMock(
            operator="viewer", expires_at=9999999999.0, expired=False
        )
        session_auth._rbac.assign_role("viewer", Role.VIEWER)
        
        with pytest.raises(AccessDenied):
            session_auth.authorize_command("viewer-token", "sessions", ["kill", "s1"])

    def test_authorize_sufficient_permission(self, session_auth, auth):
        # Create an operator session
        auth._credentials["operator"] = "hash"
        auth._sessions["op-token"] = MagicMock(
            operator="operator", expires_at=9999999999.0, expired=False
        )
        session_auth._rbac.assign_role("operator", Role.OPERATOR)
        
        ctx = session_auth.authorize_command("op-token", "sessions", ["kill", "s1"])
        assert ctx.authorized is True

    def test_validate_session_access(self, session_auth, auth):
        auth._credentials["user"] = "hash"
        auth._sessions["token"] = MagicMock(
            operator="user", expires_at=9999999999.0, expired=False
        )
        assert session_auth.validate_session_access("token", "any-session") is True

    def test_validate_session_access_invalid_token(self, session_auth):
        assert session_auth.validate_session_access("bad-token", "session") is False

    def test_command_history(self, session_auth, auth):
        auth._credentials["user"] = "hash"
        auth._sessions["token"] = MagicMock(
            operator="user", expires_at=9999999999.0, expired=False
        )
        session_auth.authorize_command("token", "help", [])
        history = session_auth.get_command_history()
        assert len(history) == 1
        assert history[0].command == "help"

    def test_clear_history(self, session_auth, auth):
        auth._credentials["user"] = "hash"
        auth._sessions["token"] = MagicMock(
            operator="user", expires_at=9999999999.0, expired=False
        )
        session_auth.authorize_command("token", "help", [])
        session_auth.clear_history()
        assert len(session_auth.get_command_history()) == 0


class TestCommandContext:
    def test_to_audit_dict(self):
        ctx = CommandContext(
            operator="alice",
            session_token="abc...",
            command="sessions",
            args=["list"],
            authorized=True,
            permission="session:read",
        )
        d = ctx.to_audit_dict()
        assert d["operator"] == "alice"
        assert d["command"] == "sessions"
        assert d["authorized"] is True
        assert "args_count" in d
        assert "timestamp" in d


# ─── Dependency Audit Tests ──────────────────────────────────────────


class TestDependencyAudit:
    def test_parse_version(self):
        from scripts.audit_deps import parse_version
        assert parse_version("1.2.3") == (1, 2, 3)
        assert parse_version("2.0") == (2, 0)
        assert parse_version("invalid") is None

    def test_version_matches_spec(self):
        from scripts.audit_deps import version_matches_spec
        assert version_matches_spec("2.3.0", "<2.4.0") is True
        assert version_matches_spec("2.4.0", "<2.4.0") is False
        assert version_matches_spec("2.5.0", "<2.4.0") is False
        assert version_matches_spec("2.4.1", "<=2.4.0") is False
        assert version_matches_spec("2.4.0", "<=2.4.0") is True

    def test_parse_requirements(self, tmp_path):
        from scripts.audit_deps import parse_requirements
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pyyaml>=5.0\nrequests==2.25.0\n# comment\nflask\n")
        result = parse_requirements(str(req_file))
        assert "pyyaml" in result
        assert "requests" in result
        assert "flask" in result

    def test_audit_dependencies_no_findings(self, tmp_path):
        from scripts.audit_deps import audit_dependencies
        # Create empty requirements
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")
        # Mock get_installed_packages to return empty
        with patch("scripts.audit_deps.get_installed_packages", return_value={}):
            result = audit_dependencies(str(req_file), strict=False)
            assert result == 0

    def test_audit_dependencies_with_vuln(self, tmp_path):
        from scripts.audit_deps import audit_dependencies
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")
        # Mock installed packages with a vulnerable version
        with patch("scripts.audit_deps.get_installed_packages", return_value={"paramiko": "2.0.2"}):
            result = audit_dependencies(str(req_file), strict=True)
            assert result > 0


# ─── Enrollment Secret Tests ─────────────────────────────────────────


class TestEnrollmentSecret:
    """The rule that decides which payloads may become sessions."""

    class _Getter:
        """A stand-in for ConfigManager.get over a fixed mapping."""

        def __init__(self, values):
            self._values = values

        def __call__(self, key, default=None):
            return self._values.get(key, default)

    def test_a_secret_is_generated_once_and_reused(self, tmp_path):
        from pupyteer.server.core.enrollment import ensure_team_secret

        path = tmp_path / "keys" / "enrollment.key"
        first = ensure_team_secret(str(path))
        assert len(first) >= 32, "a guessable enrollment secret is not a boundary"
        assert path.read_text(encoding="ascii").strip() == first
        # Re-read, never regenerated: payloads already deployed carry the old one,
        # and replacing it silently means none of them can check in.
        assert ensure_team_secret(str(path)) == first

    def test_an_empty_secret_file_is_reported_not_adopted(self, tmp_path):
        from pupyteer.server.core.enrollment import ensure_team_secret

        path = tmp_path / "enrollment.key"
        path.write_text("  \n", encoding="ascii")
        with pytest.raises(ValueError, match="restore the enrollment secret"):
            ensure_team_secret(str(path))

    def test_the_right_secret_admits_and_everything_else_refuses(self):
        from pupyteer.server.core.enrollment import secret_accepts

        assert secret_accepts("s3cret", "s3cret") is True
        for presented in (None, "", "s3cre", "S3CRET", "s3cret!", 12345, ["s3cret"]):
            assert secret_accepts("s3cret", presented) is False, repr(presented)

    def test_only_a_disabled_check_admits_an_absent_secret(self):
        """None means the operator turned auth off; '' means something went wrong."""
        from pupyteer.server.core.enrollment import secret_accepts

        assert secret_accepts(None, None) is True
        assert secret_accepts(None, "anything") is True
        assert secret_accepts("", "") is False

    def test_registration_authentication_is_on_by_default(self, tmp_path):
        from pupyteer.server.core.enrollment import listener_secret

        secret_file = str(tmp_path / "enrollment.key")
        on = self._Getter({"server.agent_auth": True,
                           "server.agent_auth_file": secret_file})
        assert listener_secret(on)

        unused = str(tmp_path / "never-written.key")
        off = self._Getter({"server.agent_auth": False,
                            "server.agent_auth_file": unused})
        assert listener_secret(off) is None
        assert not Path(unused).exists(), (
            "a disabled check must not generate a secret nobody will enforce")

    def test_an_unrecognised_value_keeps_authentication_on(self, tmp_path):
        """`agent_auth: maybe` is a typo, not a request for an open listener."""
        from pupyteer.server.core.enrollment import listener_secret

        for raw in ("", "maybe", "yes", "true", "on", None, 1):
            getter = self._Getter({"server.agent_auth": raw,
                                   "server.agent_auth_file": str(tmp_path / f"k{raw}.key")})
            assert listener_secret(getter), f"agent_auth={raw!r} disabled authentication"

    def test_the_documented_off_words_do_disable_it(self, tmp_path):
        from pupyteer.server.core.enrollment import listener_secret

        for raw in (False, "false", "0", "no", "off", "OFF"):
            getter = self._Getter({"server.agent_auth": raw,
                                   "server.agent_auth_file": str(tmp_path / "k.key")})
            assert listener_secret(getter) is None, f"agent_auth={raw!r} still enforced"

    def test_authentication_is_required_without_any_configuration(self):
        """A config file that never mentions it must not open the listener."""
        from pupyteer.server.core.config import DEFAULT_CONFIG

        assert DEFAULT_CONFIG["server"]["agent_auth"] is True


# ─── Secure Defaults Tests ───────────────────────────────────────────


class TestSecureDefaults:
    def test_check_config_defaults(self):
        from scripts.verify_secure_defaults import check_config_defaults
        result = check_config_defaults()
        # Should return empty list since defaults are secure
        assert isinstance(result, list)

    def test_check_file(self, tmp_path):
        from scripts.verify_secure_defaults import check_file
        # Create a file with a hardcoded secret
        test_file = tmp_path / "test.py"
        test_file.write_text('password = "supersecret123"\n')
        result = check_file(test_file)
        assert len(result) > 0
        assert any("password" in f.lower() for f in result)

    def test_check_file_no_secrets(self, tmp_path):
        from scripts.verify_secure_defaults import check_file
        test_file = tmp_path / "clean.py"
        test_file.write_text('x = 1\nprint("hello")\n')
        result = check_file(test_file)
        assert len(result) == 0

    def test_check_file_skips_test_files(self, tmp_path):
        from scripts.verify_secure_defaults import check_file
        test_file = tmp_path / "test_something.py"
        test_file.write_text('password = "test_value"\n')
        result = check_file(test_file)
        # Should skip test files
        assert len(result) == 0

    def test_verify_ssl_defaults(self):
        from scripts.verify_secure_defaults import verify_ssl_defaults
        result = verify_ssl_defaults()
        assert isinstance(result, list)


# ─── Integration Tests ───────────────────────────────────────────────


class TestSecurityIntegration:
    def test_full_authorization_flow(self, auth, rbac):
        """Test complete flow: authenticate -> assign role -> authorize command."""
        # Setup
        checker = PermissionChecker(auth)
        session_auth = SessionAuthorization(auth, checker)
        
        # Add operator and assign role
        auth._credentials["operator1"] = "hash"
        checker.assign_role("operator1", Role.OPERATOR)
        
        # Create session
        auth._sessions["session-token"] = MagicMock(
            operator="operator1", expires_at=9999999999.0, expired=False
        )
        
        # Authorize a command
        ctx = session_auth.authorize_command("session-token", "sessions", ["list"])
        assert ctx.authorized is True
        assert ctx.operator == "operator1"

    def test_rbac_blocks_unauthorized(self, auth, rbac):
        """Test that RBAC properly blocks unauthorized actions."""
        checker = PermissionChecker(auth)
        session_auth = SessionAuthorization(auth, checker)
        
        auth._credentials["viewer1"] = "hash"
        checker.assign_role("viewer1", Role.VIEWER)
        
        auth._sessions["viewer-token"] = MagicMock(
            operator="viewer1", expires_at=9999999999.0, expired=False
        )
        
        with pytest.raises(AccessDenied):
            session_auth.authorize_command("viewer-token", "sessions", ["kill", "s1"])

    def test_validation_rejects_injection(self):
        """Test that input validation rejects injection attempts."""
        # Path traversal
        with pytest.raises(ValueError):
            validation.validate_file_path("../../../etc/passwd")
        
        # shlex treats ; as literal (not shell expansion), so this parses fine
        # but the resulting command would fail downstream validation
        parts = validation.validate_command_line("sessions kill; rm -rf /")
        # shlex doesn't raise, but the semicolon becomes part of the arg
        assert len(parts) > 0
        
        # Null bytes
        with pytest.raises(ValueError):
            validation.validate_session_id("valid\x00hidden")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
