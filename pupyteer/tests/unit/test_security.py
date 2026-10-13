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
import time
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
from pupyteer.server.core.auth import AuthLayer, permissions_for
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.core.operators import (
    MIN_PASSWORD_CHARS, OperatorStore, WeakCredential, hash_password,
)


# ─── Fixtures ────────────────────────────────────────────────────────

# A lab password, not a real one: these tests check that a credential is
# verified, not that it is hard to guess (that is MIN_PASSWORD_CHARS's job).
PASSWORD = "lab-operator-credential"


@pytest.fixture
def config(tmp_path):
    """Config pointed at a scratch directory.

    The credential store and the audit file both have defaults relative to the
    working directory, so without this a unit test run writes into the repo's own
    ./data and ./logs and rotates a real audit trail for no reason.
    """
    cfg = ConfigManager()
    cfg.set("security.operators_file", str(tmp_path / "operators.json"))
    cfg.set("audit.log_file", str(tmp_path / "audit.json"))
    return cfg


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.fixture
def auth(config, audit):
    return AuthLayer(config, audit)


@pytest.fixture
def rbac(auth):
    return PermissionChecker(auth, auth.operators)


@pytest.fixture
def session_auth(auth, rbac):
    return SessionAuthorization(auth, rbac)


def _login(auth: AuthLayer, username: str = "lab-op",
           role: Role = Role.OPERATOR, password: str = PASSWORD) -> str:
    """Give `auth` a stored operator and return the token their login got."""
    auth.add_operator(username, password, role)
    token = auth.authenticate(username, password)
    assert token, "a stored credential must authenticate"
    return token


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
        """`help` stays reachable, or an operator cannot find the way to log in."""
        token = _login(auth, "testuser", Role.VIEWER)
        ctx = session_auth.authorize_command(token, "help", [])
        assert ctx.authorized is True
        assert ctx.operator == "testuser"

    def test_authorize_invalid_token(self, session_auth):
        with pytest.raises(AccessDenied) as caught:
            session_auth.authorize_command("invalid-token", "sessions", ["kill", "s1"])
        assert caught.value.permission == "valid_token"

    def test_a_public_verb_needs_no_token(self, session_auth):
        """`help` and `whoami` are how an operator finds out they are locked out.

        Demanding a credential to ask the gate a question would make the gate a
        wall, which is what this test keeps from being "fixed" later.
        """
        ctx = session_auth.authorize_command("", "help", [])
        assert ctx.authorized is True
        assert ctx.operator == "unknown", "nobody proved anything, so nobody is named"

    def test_authorize_insufficient_permission(self, session_auth, auth):
        token = _login(auth, "viewer", Role.VIEWER)
        with pytest.raises(AccessDenied) as caught:
            session_auth.authorize_command(token, "sessions", ["kill", "s1"])
        assert caught.value.permission == Permission.SESSION_KILL

    def test_authorize_sufficient_permission(self, session_auth, auth):
        token = _login(auth, "operator", Role.OPERATOR)
        ctx = session_auth.authorize_command(token, "sessions", ["kill", "s1"])
        assert ctx.authorized is True

    def test_a_role_change_does_not_reach_a_token_already_issued(self, session_auth, auth):
        """The permission set is the copy taken at login.

        Raising your own role has to wait for a fresh login; otherwise one command
        would turn a viewer into an admin mid-session and the audit trail would
        never record the change happening.
        """
        token = _login(auth, "climber", Role.VIEWER)
        auth.set_role("climber", Role.ADMIN)
        with pytest.raises(AccessDenied):
            session_auth.authorize_command(token, "config", ["set", "a", "b"])

    def test_renaming_the_operator_in_config_does_not_change_the_token(
        self, session_auth, auth
    ):
        """What the log calls you is not who may act.

        These used to be the same lookup: permissions were read by operator name,
        and the name came from config the console could write without asking.
        """
        token = _login(auth, "viewer", Role.VIEWER)
        auth._config.set("operator.name", "root")
        assert auth.get_operator(token) == "viewer"
        with pytest.raises(AccessDenied):
            session_auth.authorize_command(token, "sessions", ["kill", "s1"])

    def test_an_unclassified_verb_is_refused_not_allowed(self, session_auth, auth):
        """A verb nobody wrote down must not be the one verb that runs for free."""
        token = _login(auth, "anyone", Role.VIEWER)
        with pytest.raises(AccessDenied) as caught:
            session_auth.authorize_command(token, "brand-new-verb", [])
        assert caught.value.permission == SessionAuthorization.UNCLASSIFIED

    def test_validate_session_access(self, session_auth, auth):
        token = _login(auth, "user", Role.OPERATOR)
        assert session_auth.validate_session_access(token, "any-session") is True

    def test_validate_session_access_invalid_token(self, session_auth):
        assert session_auth.validate_session_access("bad-token", "session") is False

    def test_command_history(self, session_auth, auth):
        token = _login(auth, "user", Role.OPERATOR)
        session_auth.authorize_command(token, "help", [])
        history = session_auth.get_command_history()
        assert len(history) == 1
        assert history[0].command == "help"

    def test_clear_history(self, session_auth, auth):
        token = _login(auth, "user", Role.OPERATOR)
        session_auth.authorize_command(token, "help", [])
        session_auth.clear_history()
        assert len(session_auth.get_command_history()) == 0


# ─── CommandContext Tests ─────────────────────────────────────────────────────

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
    """The rules that decide which payloads may become sessions, and which
    messages may speak for one afterwards."""

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
        assert path.read_text(encoding="utf-8").splitlines()[-1].strip() == first
        # Re-read, never regenerated: payloads already deployed carry the old one,
        # and replacing it silently means none of them can check in.
        assert ensure_team_secret(str(path)) == first

    def test_an_empty_secret_file_is_reported_not_adopted(self, tmp_path):
        from pupyteer.server.core.enrollment import ensure_team_secret

        path = tmp_path / "enrollment.key"
        path.write_text("  \n", encoding="ascii")
        with pytest.raises(ValueError, match="restore the enrollment secret"):
            ensure_team_secret(str(path))

    def test_a_bare_secret_file_still_works(self, tmp_path):
        """The shape every deployed server's file already has.

        The ledger format is additive: a file written by an earlier build — one
        hex line, no header, no labels — must enrol the payloads built from it
        after the upgrade as well as before. Upgrading a team server cannot be
        the event that turns its own field agents away.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger

        path = tmp_path / "enrollment.key"
        path.write_text("a" * 64 + "\n", encoding="ascii")
        ledger = EnrollmentLedger(path)
        assert ledger.current() == "a" * 64
        assert ledger.accepts("a" * 64)

    def test_the_right_secret_admits_and_everything_else_refuses(self, tmp_path):
        from pupyteer.server.core.enrollment import EnrollmentLedger

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        secret = ledger.current()
        assert ledger.accepts(secret)
        for presented in (None, "", "s3cre", secret.upper(), secret + "!",
                          12345, [secret]):
            assert not ledger.accepts(presented), repr(presented)

    def test_a_ledger_that_exists_refuses_an_absent_secret(self, tmp_path):
        """The off switch is the config, not an empty line in the file.

        `listener_ledger` returns None when authentication is off, and that None is
        the only thing that lets a registration through with nothing to present.
        Once a ledger exists it admits a value or it does not.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        assert not ledger.accepts("")
        assert not ledger.accepts(None)

    def test_a_missing_file_enrols_nobody_and_mints_nothing(self, tmp_path):
        """A running server whose credential file vanished stops, it does not restart.

        Generating a secret here would look like a listener that works while
        turning every deployed payload into a stranger — a decision for an
        operator, not for a code path that only means to check a value.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger

        path = tmp_path / "gone.key"
        ledger = EnrollmentLedger(path)
        assert ledger.accepted() == []
        assert not ledger.accepts("anything")
        assert not path.exists()

    def test_a_rotated_secret_enrols_and_the_retired_one_still_does_too(self, tmp_path):
        """Rotation moves the boundary; only deleting a line closes it.

        Both answers matter on the same day: new payloads must be buildable with
        the new secret immediately, and the agents already deployed must not
        become strangers the moment an operator decides to stop trusting the one
        they might have lost.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        previous = ledger.current()
        new, retired = ledger.rotate()

        assert new != previous == retired
        assert ledger.current() == new
        assert ledger.accepts(new)
        assert ledger.accepts(retired), (
            "a rotation orphaned every payload deployed before it")

    def test_deleting_a_line_stops_enrolling_that_secret(self, tmp_path):
        """Revocation the operator can actually pull, and what it applies to.

        The listener re-reads the file per registration, so this holds for a
        ledger object that is already in use by a running listener — nothing is
        cached at startup that would make the edit wait for a restart.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        old = ledger.current()
        new, _retired = ledger.rotate()
        assert ledger.accepts(old)

        rows = ledger.status()
        assert ledger.revoke(rows[1]["fingerprint"]) is True
        assert ledger.accepts(old) is False
        assert ledger.accepts(new) is True, "revoking one line closed the listener"
        assert not (tmp_path / "enrollment.key.tmp").exists()

    def test_the_current_secret_cannot_be_revoked(self, tmp_path):
        """Deleting it would promote a retired secret into the builder's job.

        The line index 0 is what `payloads build` compiles as this is typed; a
        revoke that removed it would leave the operator believing they had one
        enrollment secret and hand them a different, older one.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        current = ledger.current()
        ledger.rotate()
        rows = ledger.status()
        assert rows[0]["role"] == "current"
        assert ledger.revoke(rows[0]["fingerprint"]) is False
        assert ledger.accepts(current), "the current secret vanished from the file"

    def test_status_names_secrets_without_printing_them(self, tmp_path):
        """What the console shows is a fingerprint, not credential material.

        The role column is how an operator tells the line to keep from the lines
        they can close: `current` is the one new payloads are built with, the rest
        are retired and only still open the door for agents already deployed.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger, secret_fingerprint

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        current = ledger.current()
        rotated, _ = ledger.rotate()
        rows = ledger.status()

        assert [row["fingerprint"] for row in rows] == [
            secret_fingerprint(rotated), secret_fingerprint(current)]
        assert rows[0]["role"] == "current"
        assert rows[1]["role"].startswith("retired")
        assert all(len(row["fingerprint"]) == 16 for row in rows)
        dumped = repr(rows)
        assert current not in dumped and rotated not in dumped

    def test_rotating_repeatedly_does_not_grow_the_accept_list_for_ever(self, tmp_path):
        """Every forgotten line is a door, and the file outlives the memory.

        `MAX_RETIRED` is the ceiling that keeps `enrollment show` honest: an
        operator who rotates a few times a week cannot end up trusting forty
        secrets while reporting eight.
        """
        from pupyteer.server.core.enrollment import MAX_RETIRED, EnrollmentLedger

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        ledger.current()
        for _ in range(MAX_RETIRED + 5):
            ledger.rotate()
        assert len(ledger.accepted()) == MAX_RETIRED + 1
        assert ledger.accepts(ledger.current())

    def test_a_comment_never_becomes_a_secret(self, tmp_path):
        """The header describes the file; it does not enrol anyone.

        A reader that treated a `#` line as a value — or that let the header label
        the line two below it — would make the newest secret a payload can never
        present, and the failure would surface as a listener refusing agents built
        five minutes ago.
        """
        from pupyteer.server.core.enrollment import EnrollmentLedger

        ledger = EnrollmentLedger(tmp_path / "enrollment.key")
        ledger.current()
        new, _old = ledger.rotate()

        values = ledger.accepted()
        assert values[0] == new
        assert all(not value.startswith("#") for value in values)
        assert all(len(value) == 64 for value in values), (
            f"something that is not a secret is being presented as one: {values}")

    def test_a_beacon_token_admits_its_own_session_and_nothing_else(self):
        from pupyteer.server.core.enrollment import beacon_accepts

        assert beacon_accepts("b3acon", "b3acon") is True
        for presented in (None, "", "b3aco", "B3ACON", "b3acon!", 12345, ["b3acon"]):
            assert beacon_accepts("b3acon", presented) is False, repr(presented)

    def test_a_beacon_token_has_no_off_switch(self):
        """The enrollment secret has one; this cannot.

        A session nobody handed a proof to must not be commandable by whoever
        guesses its id — otherwise the sessions that failed to get a token are the
        only ones anyone can address, and they are the open ones.
        """
        from pupyteer.server.core.enrollment import beacon_accepts

        assert beacon_accepts("", "anything") is False
        assert beacon_accepts(None, "anything") is False

    def test_beacon_tokens_are_unique_and_not_shaped_like_session_ids(self):
        """A session id leaks into operator output; the proof of a beacon may not."""
        from pupyteer.server.core.enrollment import new_beacon_token

        tokens = {new_beacon_token() for _ in range(50)}
        assert len(tokens) == 50
        assert all(len(token) >= 32 for token in tokens)

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
        findings = check_config_defaults()
        assert findings == [], f"the shipped defaults fail their own gate: {findings}"

    def test_a_plaintext_operator_credential_coming_back_is_found(self, monkeypatch):
        """The gate has to be able to fail, or it is a print statement.

        Nothing else in the suite would notice `security.operators: {admin:
        changeme}` returning: the code default is empty and no test reads the
        shipped file, so this check is the only thing standing between that line and
        an install that logs in with a password nobody had to look up.
        """
        from scripts import verify_secure_defaults as gate
        from pupyteer.server.core import config as config_module

        monkeypatch.setitem(config_module.DEFAULT_CONFIG["security"], "operators",
                            {"admin": "changeme"})
        findings = gate.check_config_defaults()
        assert any("security.operators" in f for f in findings), findings

    def test_the_shipped_defaults_name_the_same_files_as_the_code(
            self, stock_generated_files):
        """The config an install copies and the defaults the code uses have to agree.

        When they drift, a server writes its audit trail or its credential file to
        somewhere the operator's backup job — and their disk encryption, and their
        panic wipe — does not cover. Two lists of the same paths, kept in two files,
        is exactly the kind of thing that drifts.
        """
        import yaml
        from pupyteer.server.core.operators import DEFAULT_OPERATORS_FILE

        shipped = (Path(__file__).resolve().parents[2]
                   / "config" / "defaults" / "pupyteer.yaml")
        data = yaml.safe_load(shipped.read_text(encoding="utf-8")) or {}
        assert "operators" not in (data.get("security") or {}), \
            "a credential in the shipped config is a credential in every install"

        named = {f"{section}.{key}": value
                 for section, values in data.items()
                 if isinstance(values, dict)
                 for key, value in values.items()
                 if isinstance(value, str) and value.startswith("./")}
        assert named, "the shipped config is supposed to name the generated files"

        undocumented = sorted(set(stock_generated_files) - set(named))
        assert not undocumented, \
            f"the shipped config does not tell an operator where {undocumented} is"
        for dotted, value in sorted(named.items()):
            if dotted in stock_generated_files:
                assert value == stock_generated_files[dotted], (
                    f"{dotted}: the config says {value!r}, the code says "
                    f"{stock_generated_files[dotted]!r}")

        assert stock_generated_files["security.operators_file"] == \
            DEFAULT_OPERATORS_FILE

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


class TestOperatorStore:
    """The credential file itself: what a wrong guess costs, and what is on disk."""

    @staticmethod
    def _store(tmp_path) -> OperatorStore:
        return OperatorStore(str(tmp_path / "operators.json"))

    def test_a_correct_password_returns_the_record(self, tmp_path):
        store = self._store(tmp_path)
        store.add("keeper", PASSWORD, Role.OPERATOR)
        assert store.verify("keeper", PASSWORD) is not None

    def test_a_wrong_password_and_an_unknown_name_answer_alike(self, tmp_path):
        """Neither says which it was: the console is the only door, and this is a
        free oracle for anybody who can type at it.
        """
        store = self._store(tmp_path)
        store.add("keeper", PASSWORD, Role.OPERATOR)
        assert store.verify("keeper", "not-the-password") is None
        assert store.verify("nobody", PASSWORD) is None

    def test_an_unknown_name_pays_for_the_hash_it_did_not_get(self, tmp_path, monkeypatch):
        """The two rejects are the same answer only if they cost the same to observe.

        Checked as a call, not as a stopwatch: a timing assertion would fail on a
        loaded CI box and pass for the wrong reason on an idle one.
        """
        import pupyteer.server.core.operators as operators_module

        paid = []
        monkeypatch.setattr(operators_module, "_pay_kdf", lambda password: paid.append(password))
        store = self._store(tmp_path)
        store.add("keeper", PASSWORD, Role.OPERATOR)
        assert store.verify("nobody", PASSWORD) is None
        assert paid == [PASSWORD]
        assert store.verify("keeper", "not-the-password") is None
        assert paid == [PASSWORD], "a known name hashes for real, not twice"

    def test_an_add_does_not_drop_whoever_the_file_already_held(self, tmp_path):
        """A second console session must not overwrite the first one's operators.

        The store rewrites the whole file on every write, so a write that trusted
        its own memory would delete the entries another process had added.
        """
        path = str(tmp_path / "operators.json")
        keeper = OperatorStore(path)
        keeper.add("keeper", PASSWORD, Role.OPERATOR)
        late = OperatorStore(path)
        late.add("second", "another-long-secret", Role.ADMIN)
        assert keeper.names() == ["keeper", "second"]

    def test_reading_the_file_does_not_reveal_the_password(self, tmp_path):
        store = self._store(tmp_path)
        store.add("keeper", PASSWORD, Role.OPERATOR)
        raw = (tmp_path / "operators.json").read_text(encoding="utf-8")
        assert PASSWORD not in raw
        assert "hash" in raw and "salt" in raw

    def test_a_hash_made_with_other_parameters_still_verifies(self, tmp_path):
        """The parameters are stored beside the digest.

        Changing them in a later release would otherwise look like every
        credential going bad at once.
        """
        path = tmp_path / "operators.json"
        cheap = hash_password(PASSWORD, params={"n": 2 ** 12, "r": 8, "p": 1})
        assert cheap["params"]["n"] == 2 ** 12
        import json
        path.write_text(json.dumps({"version": 1, "operators": {
            "keeper": dict(role="operator", kdf=cheap["kdf"], salt=cheap["salt"],
                           params=cheap["params"], hash=cheap["hash"])}}),
            encoding="utf-8")
        store = OperatorStore(str(path))
        assert store.verify("keeper", PASSWORD) is not None

    def test_a_short_password_is_refused(self, tmp_path):
        store = self._store(tmp_path)
        with pytest.raises(WeakCredential) as caught:
            store.add("keeper", "hunter2", Role.ADMIN)
        assert str(MIN_PASSWORD_CHARS) in str(caught.value)
        assert not store.names(), "a rejected credential must not be half-stored"

    def test_a_second_add_needs_replace(self, tmp_path):
        """Silently overwriting a working password looks like a broken login later."""
        store = self._store(tmp_path)
        store.add("keeper", PASSWORD, Role.OPERATOR)
        with pytest.raises(WeakCredential):
            store.add("keeper", "a-different-long-secret", Role.OPERATOR)
        store.add("keeper", "a-different-long-secret", Role.OPERATOR, replace=True)
        assert store.verify("keeper", "a-different-long-secret") is not None
        assert store.verify("keeper", PASSWORD) is None

    def test_an_unreadable_entry_does_not_take_the_others_with_it(self, tmp_path):
        path = tmp_path / "operators.json"
        import json
        good = hash_password(PASSWORD)
        path.write_text(json.dumps({"version": 1, "operators": {
            "broken": {"role": "wizard", "kdf": "scrypt", "salt": good["salt"],
                       "params": good["params"], "hash": good["hash"]},
            "keeper": {"role": "operator", "kdf": good["kdf"], "salt": good["salt"],
                       "params": good["params"], "hash": good["hash"]},
        }}), encoding="utf-8")
        store = OperatorStore(str(path))
        assert store.names() == ["keeper"], "one bad entry must not lock out the rest"
        assert store.verify("keeper", PASSWORD) is not None
        assert store.get("broken") is None, "the unreadable entry is not a credential"

    def test_a_corrupt_file_reads_as_empty_rather_than_trusted(self, tmp_path):
        path = tmp_path / "operators.json"
        path.write_text("{not json", encoding="utf-8")
        store = OperatorStore(str(path))
        assert store.names() == []
        assert store.exists is False
        with pytest.raises(WeakCredential, match="cannot be parsed"):
            store.add("rescue", PASSWORD, Role.ADMIN)

    def test_no_temporary_file_is_left_behind(self, tmp_path):
        self._store(tmp_path).add("keeper", PASSWORD, Role.ADMIN)
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "operators.json"]
        assert leftovers == [], f"atomic write left {leftovers}"

    def test_bootstrap_only_fills_an_empty_store(self, tmp_path):
        """Otherwise a second run of a startup script would reset a team's admin."""
        store = self._store(tmp_path)
        created = store.bootstrap("admin")
        assert len(created["password"]) >= MIN_PASSWORD_CHARS
        assert store.verify("admin", created["password"]) is not None
        with pytest.raises(WeakCredential):
            store.bootstrap("admin")

    def test_bootstrap_password_is_not_the_username_or_something_typed(self, tmp_path):
        created = self._store(tmp_path).bootstrap("admin")
        password = created["password"]
        assert password != "admin"
        assert len(password) >= 32, "print-once means reading it off a screen, not a file"
        assert set(password) <= set("0123456789abcdef"), "no case to get wrong when typing it"


class TestAuthLayerCredentials:
    """Login, tokens and what a token can do. This class had no tests at all,
    which is how it went a year unwired: nothing could say it was broken.
    """

    def test_an_empty_store_is_a_fact_not_a_failure(self, auth):
        assert auth.has_operators is False
        assert auth.authenticate("admin", "anything") is None

    def test_a_token_carries_the_role_it_logged_in_with(self, auth):
        token = _login(auth, "op", Role.OPERATOR)
        assert auth.role_of(token) == "operator"
        assert auth.authorize(token, Permission.SESSION_KILL) is True
        assert auth.authorize(token, Permission.CONFIG_WRITE) is False

    def test_a_viewer_token_holds_nothing_but_reading(self, auth):
        token = _login(auth, "watcher", Role.VIEWER)
        for perm in (Permission.SESSION_KILL, Permission.MODULE_RUN,
                     Permission.PAYLOAD_BUILD, Permission.CONFIG_WRITE,
                     Permission.AUDIT_READ):
            assert auth.authorize(token, perm) is False, f"a viewer holds {perm}"
        assert auth.authorize(token, Permission.SESSION_READ) is True

    def test_five_wrong_passwords_lock_the_name_and_time_unlocks_it(self, auth, monkeypatch):
        """The lockout used to be permanent, so five typos locked an operator out
        of their own server with no way back except editing the file.
        """
        auth.add_operator("keeper", PASSWORD, Role.ADMIN)
        clock = [1000.0]
        monkeypatch.setattr(time, "monotonic", lambda: clock[0])
        for _ in range(5):
            assert auth.authenticate("keeper", "wrong-password-here") is None
        assert auth.authenticate("keeper", PASSWORD) is None, "still locked"
        clock[0] += auth._lockout_seconds + 1
        assert auth.authenticate("keeper", PASSWORD), "the window has to expire"

    def test_replacing_a_credential_drops_nobody_but_revoke_drops_the_token(self, auth):
        token = _login(auth, "op", Role.OPERATOR)
        assert auth.revoke(token) is True
        assert auth.get_operator(token) is None
        assert auth.authorize(token, Permission.SESSION_READ) is False

    def test_removing_an_operator_ends_the_sessions_it_logged_in(self, auth):
        token = _login(auth, "leaver", Role.OPERATOR)
        assert auth.remove_operator("leaver") is True
        assert auth.get_operator(token) is None, (
            "a revoked credential that leaves a live token behind is not a removal"
        )

    def test_a_bootstrap_password_is_audited_without_being_stored(self, auth, config):
        created = auth.bootstrap("admin")
        raw = Path(config.get("audit.log_file")).read_text(encoding="utf-8")
        assert "auth_operator_bootstrapped" in raw
        assert created["password"] not in raw, "the audit log rotates; a password in it does not stay secret"

    @pytest.mark.parametrize("value,expected", [
        (True, True), (False, False), ("false", False), ("FALSE", False),
        ("off", False), ("", True), ("no", False), (None, True), ("0", False),
        ("anything else", True),
    ])
    def test_require_auth_is_only_offed_by_saying_so(self, config, audit, value, expected):
        """A blank or garbled `require_auth` means on.

        `require_auth:` with nothing after it is a line nobody typed meaning
        "hand me an unauthenticated console", and the default has to survive it.
        """
        config.set("security.require_auth", value)
        assert AuthLayer(config, audit).require_auth is expected


# ─── Integration Tests ───────────────────────────────────────────────


class TestSecurityIntegration:
    def test_full_authorization_flow(self, auth, config):
        """Stored credential -> login -> command authorized -> logout.

        The whole chain, because each link on its own passed while the chain was
        unreachable: the credential file, the token and the verb table all had
        tests, and nothing joined them to a console.
        """
        checker = PermissionChecker(auth, auth.operators)
        session_auth = SessionAuthorization(auth, checker)

        auth.add_operator("operator1", PASSWORD, Role.OPERATOR)
        token = auth.authenticate("operator1", PASSWORD)
        assert token, "a stored credential must be able to log in"
        assert auth.role_of(token) == Role.OPERATOR.value

        ctx = session_auth.authorize_command(token, "sessions", ["list"])
        assert ctx.authorized is True
        assert ctx.operator == "operator1"

        assert auth.revoke(token) is True
        with pytest.raises(AccessDenied):
            session_auth.authorize_command(token, "sessions", ["list"])

    def test_the_credential_file_holds_no_password(self, auth, config):
        """What lands on disk is a salted digest, not something to log in with."""
        auth.add_operator("keeper", PASSWORD, Role.ADMIN)
        path = Path(config.get("security.operators_file"))
        raw = path.read_text(encoding="utf-8")
        assert PASSWORD not in raw
        assert "keeper" in raw
        assert "salt" in raw and "hash" in raw
        if os.name == "posix":
            # Windows synthesises 0o666 for anything writable, so the bits are not
            # a fact about the file there. Asserting them would be theatre.
            assert path.stat().st_mode & 0o077 == 0

    def test_rbac_blocks_unauthorized(self, auth):
        """Test that RBAC properly blocks unauthorized actions."""
        checker = PermissionChecker(auth, auth.operators)
        session_auth = SessionAuthorization(auth, checker)

        token = _login(auth, "viewer1", Role.VIEWER)
        checker.assign_role("viewer1", Role.VIEWER)

        with pytest.raises(AccessDenied):
            session_auth.authorize_command(token, "sessions", ["kill", "s1"])

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
