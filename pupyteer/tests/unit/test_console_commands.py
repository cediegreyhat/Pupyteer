"""Tests for the console command layer: subsystem wiring and dispatch.

These pin down that TUI commands operate on the *running* engine rather than
constructing a throwaway one, and that the dispatcher routes and renders.
"""
import os
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.tui.app import PupyteerTUI, TabCompleter
from pupyteer.tui.commands import payloads as payloads_cmds
from pupyteer.tui.commands import evasion as evasion_cmds
from pupyteer.tui.commands import sessions as sessions_cmds


def _payload_meta(**overrides):
    base = dict(
        payload_id="payload-0001",
        name="agent",
        version="1.0.0",
        platform="windows",
        arch="x64",
        status="built",
        hash_sha256="a" * 64,
        created_at="2026-01-01T00:00:00",
        size_bytes=2048,
        operator="ced",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture
def engine():
    """A running-engine stand-in with the subsystems the console touches."""
    engine = MagicMock()
    engine.config.get.return_value = "dark"
    engine.payloads.list_all.return_value = [_payload_meta()]
    engine.payloads.get_stats.return_value = {"total": 1}
    engine.payloads.get.return_value = _payload_meta()
    engine.payloads.verify.return_value = (True, "hash matches")
    engine.payloads.remove.return_value = True
    engine.payloads.cleanup.return_value = 2
    engine.payloads.mark_expired.return_value = 0
    engine.payloads.get_version_history.return_value = [
        {"version": "1.0.0", "payload_id": "payload-0001", "status": "built",
         "created_at": "2026-01-01T00:00:00", "hash_sha256": "a" * 64},
    ]
    engine.evasion.test_mode = True
    engine.evasion.litterbox_configured = False
    engine.evasion.get_stats.return_value = {"total": 3}
    engine.evasion.get_history.return_value = []
    engine.sessions.rename = AsyncMock(return_value=True)
    engine.sessions.tag = AsyncMock(return_value=True)
    engine.sessions.get = AsyncMock(return_value=None)
    engine.sessions.search = AsyncMock(return_value=[])
    return engine


@pytest.fixture
def tui(engine):
    tui = MagicMock()
    tui._engine = engine
    return tui


# ─── Live-engine wiring ───────────────────────────────────────────────


class TestCommandsUseRunningEngine:
    """Regression: these commands once built a second PupyteerEngine."""

    @pytest.mark.asyncio
    async def test_payload_list_reads_running_engine(self, tui, engine):
        result = await payloads_cmds.payload_list(tui, [])
        assert result["status"] == "ok"
        assert result["total"] == 1
        assert result["payloads"][0]["payload_id"] == "payload-0001"
        engine.payloads.list_all.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_payload_status_reads_running_engine(self, tui, engine):
        result = await payloads_cmds.payload_status(tui, [])
        assert result["stats"] == {"total": 1}

    @pytest.mark.asyncio
    async def test_payload_verify_reports_integrity(self, tui, engine):
        result = await payloads_cmds.payload_verify(tui, ["payload-0001"])
        assert result["verified"] is True
        engine.payloads.verify.assert_called_once_with("payload-0001")

    @pytest.mark.asyncio
    async def test_payload_verify_missing_id(self, tui):
        result = await payloads_cmds.payload_verify(tui, [])
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_payload_versions_reads_running_engine(self, tui, engine):
        result = await payloads_cmds.payload_versions(tui, ["agent"])
        assert result["versions"][0]["version"] == "1.0.0"
        engine.payloads.get_version_history.assert_called_once_with("agent")

    @pytest.mark.asyncio
    async def test_evasion_status_reads_running_engine(self, tui, engine):
        result = await evasion_cmds.evasion_status(tui, [])
        assert result["test_mode"] is True
        assert result["litterbox_configured"] is False
        assert result["stats"] == {"total": 3}

    @pytest.mark.asyncio
    async def test_evasion_list_does_not_shut_down_subsystem(self, tui, engine):
        await evasion_cmds.evasion_list(tui, [])
        await evasion_cmds.evasion_stats(tui, [])
        engine.evasion.shutdown.assert_not_called()
        engine.evasion.initialize.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_command_module_references_engine_factory(self):
        """The command layer must own no engine construction."""
        for module in (payloads_cmds, evasion_cmds):
            assert not hasattr(module, "PupyteerEngine")


# ─── Session commands ─────────────────────────────────────────────────


class TestSessionCommands:
    @pytest.mark.asyncio
    async def test_rename_requires_name(self, tui):
        result = await sessions_cmds.sessions_rename(tui, ["s1"])
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_rename_unknown_session(self, tui, engine):
        result = await sessions_cmds.sessions_rename(tui, ["nope", "web-01"])
        assert result["status"] == "error"
        engine.sessions.rename.assert_not_called()

    @pytest.mark.asyncio
    async def test_rename_joins_multi_word_name(self, tui, engine):
        engine.sessions.get.return_value = SimpleNamespace(session_id="s1")
        result = await sessions_cmds.sessions_rename(tui, ["s1", "win", "dc", "01"])
        assert result["status"] == "ok"
        engine.sessions.rename.assert_awaited_once_with("s1", "win dc 01")

    @pytest.mark.asyncio
    async def test_tag_accepts_multiple_tags(self, tui, engine):
        engine.sessions.get.return_value = SimpleNamespace(session_id="s1", tags=["a", "b"])
        result = await sessions_cmds.sessions_tag(tui, ["s1", "a", "b"])
        assert result["status"] == "ok"
        engine.sessions.tag.assert_awaited_once_with("s1", ["a", "b"])

    @pytest.mark.asyncio
    async def test_search_joins_query_and_reports_count(self, tui, engine):
        match = SimpleNamespace(
            session_id="s1", hostname="web01", os="windows",
            username="ced", state=SimpleNamespace(value="connected"), tags=["x"],
            to_dict=lambda: {"session_id": "s1"},
        )
        engine.sessions.search.return_value = [match]
        result = await sessions_cmds.sessions_search(tui, ["web", "01"])
        assert result["query"] == "web 01"
        assert result["count"] == 1


# ─── Dispatcher ───────────────────────────────────────────────────────


@pytest.fixture
def live_tui(engine):
    with patch("pupyteer.tui.app.readline"):
        return PupyteerTUI(engine)


class TestSubcommandDispatch:
    @pytest.mark.asyncio
    async def test_payloads_registered(self, live_tui):
        assert live_tui._registry.get("payloads") is not None

    @pytest.mark.asyncio
    async def test_payloads_without_args_shows_usage(self, live_tui, capsys):
        await live_tui.cmd_payloads([])
        assert "payloads [" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_payloads_unknown_action(self, live_tui, capsys):
        await live_tui.cmd_payloads(["frobnicate"])
        assert "Unknown payloads command: frobnicate" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_payloads_list_renders_table(self, live_tui, capsys):
        await live_tui.cmd_payloads(["list"])
        out = capsys.readouterr().out
        assert "payload-0001" in out
        assert "Total: 1 payloads" in out

    @pytest.mark.asyncio
    async def test_payloads_versions_renders_history(self, live_tui, capsys):
        await live_tui.cmd_payloads(["versions", "agent"])
        assert "1.0.0" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_listed_payload_ids_are_reusable(self, live_tui, engine, capsys):
        """The id on screen is the exact string `remove`/`info` expect.

        Truncating it to a 12-char column made every copy-pasted id fail with
        "Payload not found", and payload ids are longer than 12 characters.
        """
        full_id = "pl-d856ddbc03f8"
        engine.payloads.list_all.return_value = [_payload_meta(payload_id=full_id)]
        engine.payloads.get_version_history.return_value = [
            {"version": "1.0.0", "payload_id": full_id, "status": "verified",
             "created_at": "2026-01-01T00:00:00", "hash_sha256": "b" * 64},
        ]

        await live_tui.cmd_payloads(["list"])
        assert full_id in capsys.readouterr().out

        await live_tui.cmd_payloads(["versions", "agent"])
        assert full_id in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_payloads_error_result_surfaces_message(self, live_tui, engine, capsys):
        engine.payloads.verify.return_value = (False, "hash mismatch")
        await live_tui.cmd_payloads(["verify", "payload-0001"])
        assert "hash mismatch" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_sessions_routes_to_new_subcommands(self, live_tui, engine):
        engine.sessions.get.return_value = SimpleNamespace(session_id="s1", tags=["t"])
        await live_tui.cmd_sessions(["rename", "s1", "web-01"])
        engine.sessions.rename.assert_awaited_once_with("s1", "web-01")
        await live_tui.cmd_sessions(["tag", "s1", "t"])
        engine.sessions.tag.assert_awaited_once_with("s1", ["t"])

    @pytest.mark.asyncio
    async def test_profiles_validate_uses_error_list(self, live_tui, engine, capsys):
        engine.profiles.validate_errors.return_value = []
        await live_tui.cmd_profiles(["validate", "HTTPS-Standard"])
        engine.profiles.validate_errors.assert_called_once_with("HTTPS-Standard")
        assert "is valid" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_profiles_validate_reports_errors(self, live_tui, engine, capsys):
        engine.profiles.validate_errors.return_value = ["bad uri"]
        await live_tui.cmd_profiles(["validate", "Broken"])
        assert "bad uri" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_profiles_unload(self, live_tui, engine, capsys):
        await live_tui.cmd_profiles(["unload"])
        engine.profiles.unload.assert_called_once_with()
        assert "unloaded" in capsys.readouterr().out


# ─── Completion ───────────────────────────────────────────────────────


class TestArgumentCompletion:
    def test_first_word_completes_commands(self):
        with patch("pupyteer.tui.app.readline") as rl:
            rl.get_line_buffer.return_value = "pay"
            completer = TabCompleter(["payloads", "profiles", "help"])
            assert completer.complete("pay", 0) == "payloads"

    def test_second_word_completes_subcommands(self):
        with patch("pupyteer.tui.app.readline") as rl:
            rl.get_line_buffer.return_value = "sessions re"
            completer = TabCompleter(
                ["sessions"], {"sessions": ["rename", "remove"]}, lambda c: ["s1"]
            )
            assert completer.complete("re", 0) == "rename"

    def test_third_word_uses_dynamic_names(self):
        with patch("pupyteer.tui.app.readline") as rl:
            rl.get_line_buffer.return_value = "sessions info we"
            completer = TabCompleter(
                ["sessions"], {"sessions": ["info"]}, lambda c: ["web-01", "web-02"]
            )
            assert completer.complete("we", 0) == "web-01"

    def test_dynamic_lookup_failure_is_quiet(self):
        def boom(_command):
            raise RuntimeError("engine not ready")

        with patch("pupyteer.tui.app.readline") as rl:
            rl.get_line_buffer.return_value = "sessions info x"
            completer = TabCompleter(["sessions"], {}, boom)
            assert completer.complete("x", 0) is None

    def test_tui_session_ids_are_completable(self, live_tui, engine):
        engine.sessions.list_ids.return_value = ["sess-a", "sess-b"]
        assert live_tui._complete_names("sessions") == ["sess-a", "sess-b"]

    def test_tui_payload_ids_are_completable(self, live_tui, engine):
        assert live_tui._complete_names("payloads") == ["payload-0001"]

    def test_tui_unknown_command_has_no_names(self, live_tui):
        assert live_tui._complete_names("nonsense") == []


# ─── Argument parsing ─────────────────────────────────────────────────


class TestUnknownArguments:
    """A mistyped flag must not be silently dropped from a build config."""

    @pytest.mark.asyncio
    async def test_payload_build_rejects_typo_flag(self, tui):
        result = await payloads_cmds.payload_build(
            tui, ["--name", "a", "--expirationn", "5"]
        )
        assert result["status"] == "error"
        assert "--expirationn" in result["error"]

    @pytest.mark.asyncio
    async def test_payload_cleanup_rejects_typo_flag(self, tui):
        result = await payloads_cmds.payload_cleanup(tui, ["--max-aged", "5"])
        assert result["status"] == "error"
        assert "--max-aged" in result["error"]

    @pytest.mark.asyncio
    async def test_payload_cleanup_accepts_real_flags(self, tui, engine):
        result = await payloads_cmds.payload_cleanup(tui, ["--max-age", "5"])
        assert result["status"] == "ok"
        engine.payloads.cleanup.assert_called_once_with(5)


# ─── Module load failures are visible ─────────────────────────────────


class TestModuleLoadVisibility:
    @pytest.mark.asyncio
    async def test_show_modules_warns_about_failed_files(self, live_tui, engine, tmp_path, capsys):
        from pupyteer.server.modules.registry import ModuleRegistry
        from pupyteer.tui.commands.msf_core import show_modules

        (tmp_path / "broken.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
        registry = ModuleRegistry(engine.config, MagicMock())
        registry._paths = [tmp_path]
        registry.discover()
        engine.module_registry = registry

        await show_modules(live_tui, [])
        assert "failed to load: file:broken" in capsys.readouterr().out
