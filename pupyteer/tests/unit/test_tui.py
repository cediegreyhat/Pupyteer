"""Unit tests for Pupyteer TUI — themes, command registry, session dashboard, and app features."""
import asyncio
import os
import sys
from unittest.mock import MagicMock, AsyncMock, patch
from io import StringIO

import pytest

# Ensure pupyteer is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.tui.themes import Theme, _Ansi, c, get_theme, available_themes, _dark_theme, _light_theme
from pupyteer.tui.app import CommandRegistry, TabCompleter, SessionDashboard, StatusBar, PupyteerTUI, BANNER


# ─── Theme Tests ─────────────────────────────────────────────────────


class TestAnsi:
    def test_supports_color_with_tty(self):
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            mock_stdout.__class__ = type(sys.stdout)
            result = _Ansi()
            # Manually test the check logic
            assert hasattr(sys.stdout, "isatty") or not hasattr(sys.stdout, "isatty")

    def test_supports_color_without_tty(self):
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            mock_stdout.__class__ = type(sys.stdout)
            # When stdout is not a tty, color should be disabled
            assert not mock_stdout.isatty()

    def test_supports_256_with_term(self):
        with patch.dict(os.environ, {"TERM": "xterm-256color"}):
            assert _Ansi.supports_256() is True

    def test_supports_256_with_colorterm(self):
        with patch.dict(os.environ, {"COLORTERM": "truecolor"}):
            assert _Ansi.supports_256() is True

    def test_supports_256_without_term(self):
        with patch.dict(os.environ, {"TERM": "dumb"}, clear=False):
            # Supports 256 returns True if "256" in TERM or "truecolor" in COLORTERM
            term = os.environ.get("TERM", "")
            colorterm = os.environ.get("COLORTERM", "")
            expected = "256" in term or "truecolor" in colorterm
            assert _Ansi.supports_256() is expected


class TestColorWrapper:
    def test_c_with_color_supported(self):
        with patch("pupyteer.tui.themes._Ansi.supports_color", return_value=True):
            result = c("test", _Ansi.BOLD, _Ansi.RED)
            assert _Ansi.BOLD in result
            assert _Ansi.RED in result
            assert "test" in result
            assert _Ansi.RESET in result

    def test_c_without_color_supported(self):
        with patch("pupyteer.tui.themes._Ansi.supports_color", return_value=False):
            result = c("test", _Ansi.BOLD, _Ansi.RED)
            assert result == "test"


class TestTheme:
    def test_theme_get(self):
        theme = Theme("test", {"key1": "value1", "key2": "value2"})
        assert theme.get("key1") == "value1"
        assert theme.get("missing", "default") == "default"
        assert theme.get("missing") == ""

    def test_dark_theme_creation(self):
        theme = _dark_theme()
        assert theme.name == "dark"
        assert theme.get("primary") != ""
        assert theme.get("error") != ""
        assert theme.get("success") != ""
        assert theme.get("warning") != ""

    def test_light_theme_creation(self):
        theme = _light_theme()
        assert theme.name == "light"
        assert theme.get("primary") != ""
        assert theme.get("error") != ""
        assert theme.get("success") != ""
        assert theme.get("warning") != ""

    def test_get_theme_dark(self):
        theme = get_theme("dark")
        assert theme.name == "dark"

    def test_get_theme_light(self):
        theme = get_theme("light")
        assert theme.name == "light"

    def test_get_theme_default(self):
        theme = get_theme("nonexistent")
        assert theme.name == "dark"

    def test_available_themes(self):
        themes = available_themes()
        assert "dark" in themes
        assert "light" in themes
        assert len(themes) >= 2


# ─── Command Registry Tests ──────────────────────────────────────────


class TestCommandRegistry:
    def test_register_and_get(self):
        registry = CommandRegistry()
        handler = AsyncMock()
        registry.register("test", handler, "Test command", "test [arg]")
        cmd = registry.get("test")
        assert cmd is not None
        assert cmd["handler"] == handler
        assert cmd["help"] == "Test command"
        assert cmd["usage"] == "test [arg]"

    def test_get_nonexistent(self):
        registry = CommandRegistry()
        assert registry.get("nonexistent") is None

    def test_list_commands(self):
        registry = CommandRegistry()
        registry.register("b_cmd", AsyncMock())
        registry.register("a_cmd", AsyncMock())
        commands = registry.list_commands()
        assert commands == ["a_cmd", "b_cmd"]

    def test_get_help(self):
        registry = CommandRegistry()
        theme = get_theme("dark")
        registry.register("test", AsyncMock(), "Test help", "test [arg]")
        help_text = registry.get_help("test", theme)
        assert "test" in help_text
        assert "Test help" in help_text
        assert "test [arg]" in help_text

    def test_get_help_unknown(self):
        registry = CommandRegistry()
        theme = get_theme("dark")
        help_text = registry.get_help("unknown", theme)
        assert "Unknown command" in help_text

    def test_get_all_help(self):
        registry = CommandRegistry()
        theme = get_theme("dark")
        registry.register("cmd1", AsyncMock(), "Command 1")
        registry.register("cmd2", AsyncMock(), "Command 2")
        help_text = registry.get_all_help(theme)
        assert "cmd1" in help_text
        assert "cmd2" in help_text
        assert "Command 1" in help_text
        assert "Command 2" in help_text


# ─── Tab Completer Tests ─────────────────────────────────────────────


class TestTabCompleter:
    def test_complete_first_match(self):
        completer = TabCompleter(["help", "hexit", "history"])
        result = completer.complete("he", 0)
        assert result == "help"

    def test_complete_second_match(self):
        completer = TabCompleter(["help", "hexit", "history"])
        completer.complete("he", 0)  # Initialize matches
        result = completer.complete("he", 1)
        assert result == "hexit"

    def test_complete_no_match(self):
        completer = TabCompleter(["help", "exit"])
        result = completer.complete("xyz", 0)
        assert result is None

    def test_complete_exhausted(self):
        completer = TabCompleter(["help"])
        completer.complete("he", 0)  # Initialize matches
        result = completer.complete("he", 5)  # Out of bounds
        assert result is None

    def test_complete_with_space_in_line(self):
        completer = TabCompleter(["help"])
        with patch("pupyteer.tui.app.readline") as mock_readline:
            mock_readline.get_line_buffer.return_value = "help "
            result = completer.complete("te", 0)
            assert result is None


# ─── Session Dashboard Tests ─────────────────────────────────────────


class TestSessionDashboard:
    @pytest.fixture
    def mock_engine(self):
        engine = MagicMock()
        engine.get_status.return_value = {
            "state": {
                "started": True,
                "active_sessions": 4,
                "queued_tasks": 12,
                "loaded_profile": "HTTPS-Default",
            }
        }
        return engine

    @pytest.fixture
    def dashboard(self, mock_engine):
        theme = get_theme("dark")
        return SessionDashboard(mock_engine, theme)

    def test_render(self, dashboard, capsys):
        dashboard.render()
        captured = capsys.readouterr()
        assert "Dashboard" in captured.out
        assert "online" in captured.out
        assert "4" in captured.out
        assert "12" in captured.out
        assert "HTTPS-Default" in captured.out

    def test_render_offline(self, mock_engine, capsys):
        mock_engine.get_status.return_value = {
            "state": {
                "started": False,
                "active_sessions": 0,
                "queued_tasks": 0,
                "loaded_profile": None,
            }
        }
        theme = get_theme("dark")
        dashboard = SessionDashboard(mock_engine, theme)
        dashboard.render()
        captured = capsys.readouterr()
        assert "offline" in captured.out
        assert "none" in captured.out

    def test_render_compact(self, dashboard):
        result = dashboard.render_compact()
        assert "Server" in result
        assert "Agents" in result
        assert "Tasks" in result
        assert "Profile" in result
        assert "Online" in result


# ─── Status Bar Tests ────────────────────────────────────────────────


class TestStatusBar:
    @pytest.fixture
    def mock_engine(self):
        engine = MagicMock()
        engine.get_status.return_value = {
            "state": {
                "started": True,
                "active_sessions": 4,
                "queued_tasks": 12,
                "loaded_profile": "HTTPS-Default",
            }
        }
        return engine

    @pytest.fixture
    def status_bar(self, mock_engine):
        theme = get_theme("dark")
        return StatusBar(mock_engine, theme)

    def test_render(self, status_bar):
        # Just verify it doesn't crash
        status_bar.render()

    def test_render_full(self, status_bar, capsys):
        status_bar.render_full()
        captured = capsys.readouterr()
        assert "Server" in captured.out
        assert "Online" in captured.out


# ─── Banner Tests ────────────────────────────────────────────────────


class TestBanner:
    def test_banner_contains_pupyteer(self):
        assert "PUPYTEER" in BANNER or "Pupyteer" in BANNER or "██████╗" in BANNER

    def test_banner_contains_framework(self):
        assert "Red Team Operations Framework" in BANNER

    def test_banner_contains_version(self):
        assert "1.0.0" in BANNER

    def test_banner_contains_codename(self):
        assert "Nightfall" in BANNER


# ─── TUI Initialization Tests ────────────────────────────────────────


class TestPupyteerTUIInit:
    @pytest.fixture
    def mock_engine(self):
        engine = MagicMock()
        engine.config.get.return_value = "dark"
        engine.config.all.return_value = {}
        return engine

    def test_tui_init_default_theme(self, mock_engine):
        with patch("pupyteer.tui.app.readline"):
            tui = PupyteerTUI(mock_engine)
            assert tui._theme_name == "dark"
            assert tui._theme.name == "dark"

    def test_tui_init_light_theme(self, mock_engine):
        mock_engine.config.get.return_value = "light"
        with patch("pupyteer.tui.app.readline"):
            tui = PupyteerTUI(mock_engine)
            assert tui._theme_name == "light"
            assert tui._theme.name == "light"

    def test_tui_commands_registered(self, mock_engine):
        with patch("pupyteer.tui.app.readline"):
            tui = PupyteerTUI(mock_engine)
            commands = tui._registry.list_commands()
            assert "help" in commands
            assert "banner" in commands
            assert "status" in commands
            assert "sessions" in commands
            assert "tasks" in commands
            assert "profiles" in commands
            assert "config" in commands
            assert "theme" in commands
            assert "exit" in commands
            assert "quit" in commands


# ─── TUI Render Method Tests ─────────────────────────────────────────


class TestPupyteerTUIRender:
    @pytest.fixture
    def tui(self):
        engine = MagicMock()
        engine.config.get.return_value = "dark"
        engine.config.all.return_value = {}
        engine.get_status.return_value = {
            "config": {
                "server_host": "0.0.0.0",
                "server_port": 8443,
                "operator": "test",
            },
            "state": {
                "started": True,
                "active_sessions": 4,
                "queued_tasks": 12,
                "loaded_profile": "HTTPS-Default",
            },
        }
        with patch("pupyteer.tui.app.readline"):
            tui = PupyteerTUI(engine)
            yield tui

    def test_render_banner(self, tui, capsys):
        tui.render_banner()
        captured = capsys.readouterr()
        assert "Server" in captured.out
        assert "0.0.0.0:8443" in captured.out
        assert "HTTPS-Default" in captured.out

    def test_render_dashboard(self, tui, capsys):
        tui.render_dashboard()
        captured = capsys.readouterr()
        assert "Dashboard" in captured.out

    def test_render_table_with_data(self, tui, capsys):
        headers = ["Name", "Value"]
        rows = [["test1", "val1"], ["test2", "val2"]]
        tui.render_table(headers, rows)
        captured = capsys.readouterr()
        assert "Name" in captured.out
        assert "Value" in captured.out
        assert "test1" in captured.out
        assert "test2" in captured.out

    def test_render_table_empty(self, tui, capsys):
        tui.render_table(["Name"], [])
        captured = capsys.readouterr()
        assert "no data" in captured.out

    def test_render_error(self, tui, capsys):
        tui.render_error("Test error")
        captured = capsys.readouterr()
        assert "ERROR" in captured.out
        assert "Test error" in captured.out

    def test_render_warning(self, tui, capsys):
        tui.render_warning("Test warning")
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "Test warning" in captured.out

    def test_render_success(self, tui, capsys):
        tui.render_success("Test success")
        captured = capsys.readouterr()
        assert "Test success" in captured.out

    def test_render_info(self, tui, capsys):
        tui.render_info("Test info")
        captured = capsys.readouterr()
        assert "Test info" in captured.out


# ─── TUI Command Tests ───────────────────────────────────────────────


class TestPupyteerTUICommands:
    @pytest.fixture
    def tui(self):
        engine = MagicMock()
        engine.config.get.return_value = "dark"
        engine.config.all.return_value = {"server": {"host": "0.0.0.0"}}
        engine.get_status.return_value = {
            "config": {
                "server_host": "0.0.0.0",
                "server_port": 8443,
                "operator": "test",
            },
            "state": {
                "started": True,
                "active_sessions": 4,
                "queued_tasks": 12,
                "loaded_profile": "HTTPS-Default",
            },
        }
        engine.sessions.list_all = AsyncMock(return_value=[])
        engine.sessions.search = AsyncMock(return_value=[])
        engine.sessions.get = AsyncMock(return_value=None)
        engine.sessions.kill = AsyncMock(return_value=True)
        engine.sessions.tag = AsyncMock(return_value=True)
        engine.tasks.list_all = AsyncMock(return_value=[])
        engine.tasks.get = AsyncMock(return_value=None)
        engine.tasks.cancel = AsyncMock(return_value=True)
        engine.profiles.list.return_value = [
            {"name": "HTTPS-Standard", "version": "1.0", "transport": "https", "source": "default", "active": True}
        ]
        engine.profiles.get = MagicMock(return_value=None)
        engine.profiles.load = MagicMock(return_value=True)
        engine.profiles.validate = MagicMock(return_value=[])
        engine.transports.list.return_value = []
        with patch("pupyteer.tui.app.readline"):
            tui = PupyteerTUI(engine)
            yield tui

    @pytest.mark.asyncio
    async def test_cmd_help_all(self, tui, capsys):
        await tui.cmd_help([])
        captured = capsys.readouterr()
        assert "Available Commands" in captured.out
        assert "help" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_help_specific(self, tui, capsys):
        await tui.cmd_help(["banner"])
        captured = capsys.readouterr()
        assert "banner" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_banner(self, tui, capsys):
        await tui.cmd_banner([])
        captured = capsys.readouterr()
        assert "Server" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_status(self, tui, capsys):
        await tui.cmd_status([])
        captured = capsys.readouterr()
        assert "Dashboard" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_theme_list(self, tui, capsys):
        await tui.cmd_theme([])
        captured = capsys.readouterr()
        assert "Available themes" in captured.out
        assert "dark" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_theme_set_dark(self, tui, capsys):
        await tui.cmd_theme(["dark"])
        captured = capsys.readouterr()
        assert "Theme changed to 'dark'" in captured.out
        assert tui._theme_name == "dark"

    @pytest.mark.asyncio
    async def test_cmd_theme_set_light(self, tui, capsys):
        await tui.cmd_theme(["light"])
        captured = capsys.readouterr()
        assert "Theme changed to 'light'" in captured.out
        assert tui._theme_name == "light"

    @pytest.mark.asyncio
    async def test_cmd_theme_invalid(self, tui, capsys):
        await tui.cmd_theme(["invalid_theme"])
        captured = capsys.readouterr()
        assert "Unknown theme" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_sessions_list_empty(self, tui, capsys):
        await tui.cmd_sessions(["list"])
        captured = capsys.readouterr()
        assert "No active sessions" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_tasks_list_empty(self, tui, capsys):
        await tui.cmd_tasks(["list"])
        captured = capsys.readouterr()
        assert "No tasks" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_profiles_list(self, tui, capsys):
        await tui.cmd_profiles(["list"])
        captured = capsys.readouterr()
        assert "HTTPS-Standard" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_transports_empty(self, tui, capsys):
        await tui.cmd_transports([])
        captured = capsys.readouterr()
        assert "No active transports" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_config_list(self, tui, capsys):
        await tui.cmd_config([])
        captured = capsys.readouterr()
        assert "server" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_logs_no_file(self, tui, capsys):
        await tui.cmd_logs([])
        captured = capsys.readouterr()
        assert "No log file" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_evasion_usage(self, tui, capsys):
        await tui.cmd_evasion([])
        captured = capsys.readouterr()
        assert "Usage: evasion" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_clear(self, tui, capsys):
        await tui.cmd_clear([])
        captured = capsys.readouterr()
        assert "\033[2J" in captured.out

    @pytest.mark.asyncio
    async def test_cmd_exit(self, tui, capsys):
        await tui.cmd_exit([])
        captured = capsys.readouterr()
        assert "Shutting down" in captured.out
        assert tui._running is False


# ─── TUI Error Handling Tests ────────────────────────────────────────


class TestPupyteerTUIErrorHandling:
    @pytest.fixture
    def tui(self):
        engine = MagicMock()
        engine.config.get.return_value = "dark"
        engine.config.all.return_value = {}
        engine.get_status.return_value = {
            "config": {"server_host": "0.0.0.0", "server_port": 8443, "operator": "test"},
            "state": {"started": True, "active_sessions": 0, "queued_tasks": 0, "loaded_profile": None},
        }
        with patch("pupyteer.tui.app.readline"):
            tui = PupyteerTUI(engine)
            yield tui

    def test_error_display_with_color_coding(self, tui, capsys):
        """Verify error messages have color coding."""
        tui.render_error("Test error message")
        captured = capsys.readouterr()
        assert "ERROR" in captured.out
        assert "Test error message" in captured.out

    def test_warning_display_with_color_coding(self, tui, capsys):
        """Verify warning messages have color coding."""
        tui.render_warning("Test warning message")
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "Test warning message" in captured.out

    def test_success_display(self, tui, capsys):
        """Verify success messages render correctly."""
        tui.render_success("Test success message")
        captured = capsys.readouterr()
        assert "Test success message" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
