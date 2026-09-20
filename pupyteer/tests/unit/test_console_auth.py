"""The console's operator gate: what a login has to be worth before it counts.

These run against a real `PupyteerEngine`, not a mock. The whole question is
whether the token, the stored role and the verb table agree with each other, and a
mocked engine would let a gate that nobody can pass — or one everybody can — look
like a gate that works.
"""
import asyncio
import os
import sys

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pupyteer.server.core.auth as auth_module
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.core.rbac import Role
from pupyteer.server.core.session_auth import SessionAuthorization
from pupyteer.tui.app import PupyteerTUI

PASSWORD = "lab-operator-credential"


def _engine(tmp_path, monkeypatch, **over):
    """A real engine whose files are all inside `tmp_path`.

    Every path is set through the environment because `AuthLayer` reads the
    credential file's location when it is constructed; setting it on the config
    afterwards would leave the test logging in against the repository's store.
    """
    for key, value in {
        "SECURITY__OPERATORS_FILE": str(tmp_path / "operators.json"),
        "SECURITY__REQUIRE_AUTH": "true",
        "AUDIT__LOG_FILE": str(tmp_path / "audit.json"),
        "LOGGING__FILE": str(tmp_path / "pupyteer.log"),
    }.items():
        monkeypatch.setenv(f"PUPYTEER_{key}", value)
    for key, value in over.items():
        monkeypatch.setenv(f"PUPYTEER_{key}", value)
    return PupyteerEngine()


def _keyboard(tui, values):
    """Give a console a keyboard that says `values` in order, then nothing.

    `_read` is the only door from the TUI to a terminal, so stubbing it covers the
    name-and-password prompts without a tty and leaves the gate's own logic real.
    """
    queue = iter(values)
    tui._read = lambda prompt, secret=False: asyncio.sleep(
        0, result=next(queue, None))
    return tui


def _console(tmp_path, monkeypatch, name="lab-op", role=Role.OPERATOR, **over):
    engine = _engine(tmp_path, monkeypatch, **over)
    if name:
        engine.auth.add_operator(name, PASSWORD, role)
    return engine, PupyteerTUI(engine)


@pytest_asyncio.fixture
async def signed_in(tmp_path, monkeypatch):
    """A console that has logged in as a real operator, through the gate."""
    engine, tui = _console(tmp_path, monkeypatch)
    _keyboard(tui, ["lab-op", PASSWORD])
    assert await tui.prompt_login(), "the fixture's own login has to work"
    return tui, engine


class TestStartupGate:
    @pytest.mark.asyncio
    async def test_the_engine_is_not_started_for_someone_who_did_not_sign_in(
            self, tmp_path, monkeypatch, capsys):
        engine, tui = _console(tmp_path, monkeypatch)
        _keyboard(tui, ["lab-op", "not-the-password"])
        started = False

        async def fake_start():
            nonlocal started
            started = True

        engine.start = fake_start
        await tui.run()
        assert started is False, "a refused login must not open the listeners"
        assert "Not starting" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_a_credential_is_asked_for_before_a_single_verb_runs(
            self, tmp_path, monkeypatch):
        engine, tui = _console(tmp_path, monkeypatch)
        _keyboard(tui, ["lab-op", PASSWORD])
        assert await tui._authorize("sessions", ["list"]) is True
        assert tui._operator == "lab-op"
        assert await tui._authorize("sessions", ["kill", "1"]) is True

    @pytest.mark.asyncio
    async def test_a_blank_console_may_still_read_its_own_help(self, tmp_path, monkeypatch):
        """`help` has to be reachable from outside the gate, or it is a wall."""
        engine, tui = _console(tmp_path, monkeypatch, role=Role.VIEWER)
        _keyboard(tui, [])
        assert await tui._authorize("help", []) is True
        assert tui._token is None

    @pytest.mark.asyncio
    async def test_the_first_run_makes_a_credential_and_shows_it_once(
            self, tmp_path, monkeypatch, capsys):
        engine = _engine(tmp_path, monkeypatch)
        assert engine.auth.has_operators is False
        tui = _keyboard(PupyteerTUI(engine), [])
        assert await tui._gate_startup() is False, "printing it is not signing in"
        out = capsys.readouterr().out
        created = engine.auth.operators.names()
        assert len(created) == 1
        assert "password:" in out
        password = [line.split("password:")[1].strip()
                    for line in out.splitlines() if "password:" in line][0]
        assert engine.auth.operators.verify(created[0], password) is not None
        # Printed once means the durable record does not carry it.
        assert password not in (tmp_path / "audit.json").read_text(encoding="utf-8")

    @pytest.mark.asyncio
    async def test_require_auth_off_says_so_instead_of_pretending_to_be_logged_in(
            self, tmp_path, monkeypatch, capsys):
        engine, tui = _console(tmp_path, monkeypatch, name=None,
                               **{"SECURITY__REQUIRE_AUTH": "false"})
        _keyboard(tui, [])
        assert await tui._gate_startup() is True
        assert tui._token is None, "no token, so nothing can claim a role it was not"
        assert await tui._authorize("sessions", ["kill", "1"]) is True
        assert "require_auth is off" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_the_pre_login_banner_does_not_report_the_channel_as_open_clothes(
            self, tmp_path, monkeypatch, capsys):
        """TLS is on by default, but the banner is drawn before the listeners are.

        This is the one window a gate puts everyone in: an operator who has not
        signed in yet, reading a server that has not started yet. Saying
        PLAINTEXT there is a false alarm about the thing the warning exists to
        make them check, and it fires on every default install since the gate
        made the pre-start banner the last thing some consoles ever show.
        """
        engine, tui = _console(tmp_path, monkeypatch, role=Role.VIEWER)
        assert engine.config.get("server.tls") is True
        tui.render_banner()
        out = capsys.readouterr().out
        assert "plaintext" not in out.lower()
        assert "[Channel]" in out


class TestRoleGate:
    @pytest.mark.asyncio
    async def test_a_viewer_may_read_the_board_but_not_touch_a_session(
            self, tmp_path, monkeypatch, capsys):
        engine, tui = _console(tmp_path, monkeypatch, name="watcher", role=Role.VIEWER)
        _keyboard(tui, ["watcher", PASSWORD])
        assert await tui._authorize("sessions", ["list"]) is True
        assert await tui._authorize("sessions", ["kill", "41"]) is False
        assert "Refused" in capsys.readouterr().out
        assert await tui._authorize("run", []) is False

    @pytest.mark.asyncio
    async def test_an_operator_cannot_change_how_the_server_listens(
            self, signed_in, capsys):
        tui, engine = signed_in
        assert await tui._authorize("config", ["get", "server.port"]) is True
        assert await tui._authorize("config", ["set", "server.port", "9001"]) is False

    @pytest.mark.asyncio
    async def test_making_a_credential_is_not_part_of_being_an_operator(
            self, signed_in):
        """`operator list` prints everyone the team has credentials for.

        That is a target list in the hands of whoever is next at this keyboard, so
        it is the same permission as adding one.
        """
        tui, engine = signed_in
        assert await tui._authorize("operator", ["list"]) is False
        assert await tui._authorize("operator", ["add", "budddy"]) is False

    @pytest.mark.asyncio
    async def test_a_refusal_is_in_the_audit_log_with_its_reason(self, signed_in):
        tui, engine = signed_in
        await tui._authorize("payloads", ["remove", "deadbeef"])
        rows = engine.audit._store.query(event="command_denied")
        assert len(rows) == 1
        assert rows[0]["details"]["permission"] == "payload:remove"
        assert rows[0]["details"]["args_count"] == 2

    @pytest.mark.asyncio
    async def test_the_denied_verb_never_reaches_its_handler(
            self, tmp_path, monkeypatch):
        engine, tui = _console(tmp_path, monkeypatch, name="watcher", role=Role.VIEWER)
        _keyboard(tui, ["watcher", PASSWORD])
        called = []
        monkeypatch.setattr(PupyteerTUI, "cmd_run",
                            lambda self, args: called.append(args))
        assert await tui._authorize("run", []) is False
        assert called == []
        assert tui._operator == "watcher", "refused, but not unauthenticated"


class TestAttribution:
    def test_the_login_is_what_the_audit_log_blames(self, signed_in):
        tui, engine = signed_in
        assert engine.audit.operator == "lab-op"

    def test_renaming_the_config_operator_does_not_move_the_blame(
            self, tmp_path, monkeypatch):
        engine, _tui = _console(tmp_path, monkeypatch)
        blamed = engine.audit.operator
        engine.config.set("operator.name", "whoever")
        engine.audit.set_operator(None)
        assert engine.audit.operator == blamed, \
            "attribution is what the process started with, not what a config " \
            "edit says to be called"

    @pytest.mark.asyncio
    async def test_signing_out_revokes_the_token_and_the_console_asks_again(
            self, signed_in):
        tui, engine = signed_in
        token = tui._token
        tui._sign_out()
        assert engine.auth.get_operator(token) is None, \
            "a logout that left the token live would not have logged anything out"
        _keyboard(tui, ["lab-op", PASSWORD])
        assert await tui._authorize("sessions", ["list"]) is True
        assert tui._operator == "lab-op"

    def test_the_console_cannot_rename_its_own_audit_attribution(self, signed_in):
        tui, engine = signed_in
        assert tui._locked_at_runtime("operator.name")
        assert tui._locked_at_runtime("security.require_auth")
        assert tui._locked_at_runtime("security.token_ttl")
        assert tui._locked_at_runtime("server.port") is False
        assert tui._locked_at_runtime("operator.theme") is False

    @pytest.mark.asyncio
    async def test_config_set_refuses_the_locked_keys(self, signed_in, capsys):
        tui, engine = signed_in
        before = engine.config.get("operator.name")
        await tui.cmd_config(["set", "operator.name", "alice"])
        assert engine.config.get("operator.name") == before
        assert "Refused" in capsys.readouterr().out
        await tui.cmd_config(["set", "security.require_auth", "false"])
        assert engine.auth.require_auth is True


class TestExpiry:
    @pytest.mark.asyncio
    async def test_an_expired_sign_in_costs_a_password_and_not_the_board(
            self, signed_in, monkeypatch, capsys):
        tui, engine = signed_in
        session = engine.auth._sessions[tui._token]
        monkeypatch.setattr(auth_module.time, "time",
                            lambda: session.expires_at + 1)
        assert engine.auth.remaining(tui._token) is None

        _keyboard(tui, ["lab-op", PASSWORD])
        assert await tui._authorize("sessions", ["list"]) is True
        assert tui._operator == "lab-op"
        out = capsys.readouterr().out.lower()
        assert "expired" in out
        assert engine.auth.operators.verify("lab-op", PASSWORD) is not None, \
            "the credential outlives the token, so re-signing in is enough"

    @pytest.mark.asyncio
    async def test_a_sign_in_that_does_not_happen_leaves_the_verb_refused(
            self, signed_in, monkeypatch, capsys):
        tui, engine = signed_in
        session = engine.auth._sessions[tui._token]
        monkeypatch.setattr(auth_module.time, "time",
                            lambda: session.expires_at + 1)
        _keyboard(tui, [])          # no terminal, so nobody can answer
        assert await tui._authorize("sessions", ["list"]) is False
        assert tui._token is None
        # The operator's role was never the question. A denial that names a
        # permission here points at the role table when the missing thing is a
        # credential, and sends them to fix the wrong file.
        out = capsys.readouterr().out.lower()
        assert "permission" not in out
        assert "needs a credential" in out


@pytest_asyncio.fixture
async def admin(tmp_path, monkeypatch):
    """A console that reached `operator` through the gate, as an admin."""
    engine, tui = _console(tmp_path, monkeypatch, name="boss", role=Role.ADMIN)
    _keyboard(tui, ["boss", PASSWORD])
    assert await tui._authorize("operator", ["list"]) is True
    return tui, engine


class TestOperatorVerb:
    @pytest.mark.asyncio
    async def test_adding_an_operator_asks_and_never_takes_it_from_argv(
            self, admin, tmp_path, capsys):
        """A password in argv is readable by any process and kept by history."""
        tui, engine = admin
        _keyboard(tui, ["a-second-long-secret", "a-second-long-secret"])
        await tui.cmd_operator(["add", "colleague", "viewer"])
        assert engine.auth.operators.role_of("colleague") == Role.VIEWER
        assert "colleague" in capsys.readouterr().out
        stored = (tmp_path / "operators.json").read_text(encoding="utf-8")
        assert "a-second-long-secret" not in stored

    @pytest.mark.asyncio
    async def test_the_two_entries_have_to_agree(self, admin, tmp_path):
        tui, engine = admin
        _keyboard(tui, ["a-second-long-secret", "typed-it-wrong-this-time"])
        await tui.cmd_operator(["add", "colleague"])
        assert engine.auth.operators.names() == ["boss"]

    @pytest.mark.asyncio
    async def test_a_short_credential_is_refused_before_it_is_stored(
            self, admin, capsys):
        tui, engine = admin
        _keyboard(tui, ["short", "short"])
        await tui.cmd_operator(["add", "colleague"])
        assert "colleague" not in engine.auth.operators.names()
        assert "characters" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_a_role_change_survives_a_restart_because_it_is_written(
            self, admin, tmp_path, monkeypatch):
        tui, engine = admin
        await tui.cmd_operator(["role", "boss", "viewer"])
        again = _engine(tmp_path, monkeypatch)
        assert again.auth.operators.role_of("boss") == Role.VIEWER

    @pytest.mark.asyncio
    async def test_the_engine_role_is_not_one_an_operator_can_give_out(
            self, admin, capsys):
        tui, engine = admin
        await tui.cmd_operator(["role", "boss", "system"])
        assert engine.auth.operators.role_of("boss") == Role.ADMIN
        assert "own role" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_removing_an_operator_ends_their_live_sessions(self, admin):
        tui, engine = admin
        other = engine.auth.authenticate("boss", PASSWORD)
        assert engine.auth.get_operator(other) == "boss"
        await tui.cmd_operator(["remove", "boss"])
        assert engine.auth.get_operator(other) is None
        assert engine.auth.operators.names() == []

    @pytest.mark.asyncio
    async def test_whoami_says_what_it_actually_knows(self, signed_in, capsys):
        tui, engine = signed_in
        await tui.cmd_whoami([])
        out = capsys.readouterr().out
        assert "lab-op" in out and "operator" in out and "expires" in out

    @pytest.mark.asyncio
    async def test_whoami_says_not_signed_in_when_it_is_not(
            self, tmp_path, monkeypatch, capsys):
        engine, tui = _console(tmp_path, monkeypatch)
        await tui.cmd_whoami([])
        assert "Not signed in" in capsys.readouterr().out


class TestVerbTableIsComplete:
    """The table and the console must not drift apart.

    `resolve_permission` refuses a verb it does not know, so a verb registered
    without being written down would be refused at the keyboard and look like a bug
    in the gate. This names which one it is while that is still cheap to fix.
    """

    def test_every_registered_verb_is_classified(self, signed_in):
        tui, _engine = signed_in
        registered = set(tui._registry.list_commands())
        classified = set(SessionAuthorization.COMMAND_PERMISSIONS)
        assert registered - classified == set(), \
            f"verbs the gate has no answer for: {sorted(registered - classified)}"

    def test_every_subcommand_choice_is_classified(self, signed_in):
        tui, _ = signed_in
        for command, choices in tui._SUBCOMMANDS.items():
            if SessionAuthorization.COMMAND_PERMISSIONS.get(command) is None:
                continue  # a public verb's arguments touch nothing worth gating
            table = SessionAuthorization.SUBCOMMAND_PERMISSIONS.get(command, {})
            if "*" in table:
                continue
            unclassified = [c for c in choices if c not in table]
            assert not unclassified, \
                f"{command} {unclassified} fall through with no '*' default"

    def test_the_table_holds_no_verb_the_console_does_not_have(self, signed_in):
        tui, _ = signed_in
        phantom = set(SessionAuthorization.COMMAND_PERMISSIONS) - set(
            tui._registry.list_commands())
        assert phantom == set(), f"classified but unreachable: {sorted(phantom)}"

    def test_no_verb_that_touches_a_target_is_public(self):
        public = {name for name, perm in SessionAuthorization.COMMAND_PERMISSIONS.items()
                  if perm is None}
        assert public == {"help", "banner", "clear", "theme", "exit", "quit",
                          "login", "logout", "whoami"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
