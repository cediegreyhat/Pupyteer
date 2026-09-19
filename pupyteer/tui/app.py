"""Pupyteer TUI — Terminal User Interface with branding and command system."""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
import signal
import sys
import time
from typing import Any, Callable, Dict, List, Optional

try:
    import readline
except ImportError:
    # Windows ships no readline; the console falls back to plain input().
    readline = None  # type: ignore[assignment]

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.tui.themes import Theme, _Ansi, c, get_theme, available_themes

logger = logging.getLogger("pupyteer.tui")


# ─── Banner ────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ██╗   ██╗██████╗ ██╗   ██╗████████╗███████╗███████╗  ║
║   ██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝██╔════╝  ║
║   ██████╔╝██║   ██║██████╔╝ ╚████╔╝    ██║   █████╗  █████╗    ║
║   ██╔═══╝ ██║   ██║██╔═══╝   ╚██╔╝     ██║   ██╔══╝  ██╔══╝    ║
║   ██║     ╚██████╔╝██║        ██║      ██║   ███████╗███████╗  ║
║   ╚═╝      ╚═════╝ ╚═╝        ╚═╝      ╚═╝   ╚══════╝╚══════╝  ║
║                                                                  ║
║          Red Team Operations Framework  v{codename} {version}     ║
╚══════════════════════════════════════════════════════════════════╝
""".format(codename="Nightfall", version="1.0.0")


# ─── Command Registry ─────────────────────────────────────────────────
class CommandRegistry:
    """Maps command names to their handler functions and help text."""

    def __init__(self):
        self._commands: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, handler: Callable, help_text: str = "", usage: str = "") -> None:
        self._commands[name] = {"handler": handler, "help": help_text, "usage": usage}

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self._commands.get(name)

    def list_commands(self) -> List[str]:
        return sorted(self._commands.keys())

    def get_help(self, name: str, theme: Optional[Theme] = None) -> str:
        if theme is None:
            theme = get_theme("dark")
        cmd = self._commands.get(name)
        if not cmd:
            return c(f"  Unknown command: {name}", theme.get("error"))
        lines = [c(f"  {name}", theme.get("primary"), _Ansi.BOLD), f"    {cmd['help']}"]
        if cmd["usage"]:
            lines.append(c(f"    Usage: {cmd['usage']}", theme.get("muted")))
        return "\n".join(lines)

    def get_all_help(self, theme: Optional[Theme] = None) -> str:
        if theme is None:
            theme = get_theme("dark")
        lines = [c("\nAvailable Commands:", theme.get("primary"), _Ansi.BOLD)]
        for name in sorted(self._commands.keys()):
            cmd = self._commands[name]
            lines.append(f"  {c(name, theme.get('success')):20s} {cmd['help']}")
        lines.append(c("\nUse 'help <command>' for details.\n", theme.get("muted")))
        return "\n".join(lines)


# ─── Tab Completer ────────────────────────────────────────────────────
class TabCompleter:
    """Readline tab-completion for commands, subcommands and live names."""

    def __init__(
        self,
        commands: List[str],
        subcommands: Optional[Dict[str, List[str]]] = None,
        dynamic: Optional[Callable[[str], List[str]]] = None,
    ):
        self._commands = commands
        self._subcommands = subcommands or {}
        self._dynamic = dynamic
        self._matches: List[str] = []

    def _candidates(self, words: List[str], typing_last: bool) -> List[str]:
        """Choices for the token being completed.

        `words` is the split line buffer; when the caret is not just past a
        space, the final token is the partial input and is not a completed word.
        """
        prefix = words if typing_last else words[:-1]
        if not prefix:
            return self._commands
        command = prefix[0]
        if len(prefix) == 1:
            return list(self._subcommands.get(command, []))
        # Deeper positions -> dynamic names (sessions, modules, profiles, payloads).
        if self._dynamic is None:
            return []
        # Providers read live engine state, which may not be ready.
        try:
            return self._dynamic(command) or []
        except Exception:
            logger.debug("Completion lookup failed for %s", command, exc_info=True)
            return []

    def complete(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            # Without readline there is no line buffer, so the cursor position is
            # unknown — assume the operator is completing the first word.
            if readline is None:
                self._matches = [m for m in self._commands if m.startswith(text)]
            else:
                line = readline.get_line_buffer()
                typing_last = line.endswith((" ", "\t"))
                words = line.split()
                self._matches = [
                    m for m in self._candidates(words, typing_last)
                    if m.startswith(text)
                ]
        try:
            return self._matches[state]
        except IndexError:
            return None


# ─── Session Dashboard Widget ─────────────────────────────────────────
class SessionDashboard:
    """Renders the session dashboard widget."""

    def __init__(self, engine: PupyteerEngine, theme: Theme):
        self._engine = engine
        self._theme = theme

    def render(self) -> None:
        """Render the session dashboard."""
        status = self._engine.get_status()
        state = status["state"]
        theme = self._theme

        # Dashboard box
        print(c("\n  ┌─── Dashboard ───────────────────────────────────┐", theme.get("dashboard_border")))
        print(c("  │", theme.get("dashboard_border")), f"  {c('Server:', theme.get('info'))}    {'online' if state['started'] else 'offline'}")
        print(c("  │", theme.get("dashboard_border")), f"  {c('Agents:', theme.get('info'))}    {state['active_sessions']}")
        print(c("  │", theme.get("dashboard_border")), f"  {c('Tasks:', theme.get('info'))}     {state['queued_tasks']}")
        print(c("  │", theme.get("dashboard_border")), f"  {c('Profile:', theme.get('info'))}   {state['loaded_profile'] or 'none'}")
        print(c("  └─────────────────────────────────────────────────┘\n", theme.get("dashboard_border")))

    def render_compact(self) -> str:
        """Render a compact status line for the status bar."""
        status = self._engine.get_status()
        state = status["state"]
        theme = self._theme
        return (
            f"{c('[Server]', theme.get('success'))} {'Online' if state['started'] else 'Offline'} "
            f"{c('[Agents]', theme.get('info'))} {state['active_sessions']} "
            f"{c('[Tasks]', theme.get('warning'))} {state['queued_tasks']} "
            f"{c('[Profile]', theme.get('accent'))} {state['loaded_profile'] or 'none'}"
        )


# ─── Status Bar ───────────────────────────────────────────────────────
class StatusBar:
    """Renders the persistent status bar."""

    def __init__(self, engine: PupyteerEngine, theme: Theme):
        self._engine = engine
        self._theme = theme
        self._dashboard = SessionDashboard(engine, theme)

    def render(self) -> None:
        """Render the status bar."""
        theme = self._theme
        status_str = self._dashboard.render_compact()
        # Clear line and print status bar
        print(f"\r{' ' * 80}\r{status_str}", end="", flush=True)

    def render_full(self) -> None:
        """Render full status bar with newline."""
        theme = self._theme
        status_str = self._dashboard.render_compact()
        print(f"\n{status_str}\n")


# ─── Main TUI ─────────────────────────────────────────────────────────
class PupyteerTUI:
    """
    Pupyteer Terminal Interface

    Features:
    - Startup banner with version info
    - Command system with autocomplete and history
    - Session dashboard (server status, agent count, tasks)
    - Themed output (dark/light themes)
    - Structured tables for session/task listings
    - Graceful shutdown on SIGINT
    - Terminal resize handling
    """

    def __init__(self, engine: PupyteerEngine):
        self._engine = engine
        self._config = engine.config
        self._registry = CommandRegistry()
        self._running = False
        self._theme_name = self._config.get("operator.theme", "dark")
        self._theme = get_theme(self._theme_name)
        self._prompt = c("pupyteer", self._theme.get("prompt"), _Ansi.BOLD) + c(" > ", self._theme.get("muted"))
        self._history_file = os.path.expanduser("~/.pupyteer_history")
        self._status_bar = StatusBar(engine, self._theme)
        self._dashboard = SessionDashboard(engine, self._theme)

        self._register_commands()
        self._setup_readline()
        self._setup_signal_handlers()

    def _register_commands(self) -> None:
        """Register all TUI commands."""
        r = self._registry
        r.register("help", self.cmd_help, "Show help for commands", "help [command]")
        r.register("banner", self.cmd_banner, "Display the Pupyteer banner")
        r.register("status", self.cmd_status, "Show engine and server status")
        # MSF-style commands
        r.register("use", self.cmd_use, "Select a module", "use <module_name>")
        r.register("set", self.cmd_set, "Set a module option", "set <option> <value>")
        r.register("unset", self.cmd_unset, "Unset a module option", "unset <option|all>")
        r.register("search", self.cmd_search, "Search modules", "search <query>")
        r.register("info", self.cmd_info, "Show active module info")
        r.register("back", self.cmd_back, "Deselect active module")
        r.register("options", self.cmd_options, "Show module options")
        r.register("modules", self.cmd_modules, "List all modules")
        r.register("exploit", self.cmd_exploit, "Execute (exploit) the active module")
        r.register("run", self.cmd_run, "Run the active module")
        r.register("reload", self.cmd_reload, "Reload module registry")
        # Session/job commands
        r.register("sessions", self.cmd_sessions, "Manage sessions",
                   "sessions [list|info <id>|interact <id>|kill <id>|rename <id> <name>|tag <id> <tag>|search <query>]")
        r.register("jobs", self.cmd_jobs, "Manage background jobs", "jobs [list|kill <id>|info <id>]")
        r.register("tasks", self.cmd_tasks, "Manage tasks", "tasks [list|info <id>|cancel <id>]")
        r.register("payloads", self.cmd_payloads, "Payload lifecycle",
                   "payloads [status|list|build|info|verify|remove|cleanup|versions]")
        r.register("profiles", self.cmd_profiles, "Manage C2 profiles",
                   "profiles [list|show <name>|validate <name>|load <name>|unload|new <file>]")
        r.register("transports", self.cmd_transports, "List active transports")
        r.register("config", self.cmd_config, "View configuration", "config [get <key>|set <key> <value>]")
        r.register("logs", self.cmd_logs, "View recent audit logs")
        r.register("evasion", self.cmd_evasion, "Evasion testing", "evasion [status|run|list|stats]")
        r.register("pipeline", self.cmd_pipeline, "Unified payload-to-evasion pipeline", "pipeline [run|build|test|auto|status|history]")
        r.register("theme", self.cmd_theme, "Change TUI theme", "theme [dark|list]")
        r.register("clear", self.cmd_clear, "Clear the screen")
        r.register("exit", self.cmd_exit, "Exit Pupyteer")
        r.register("quit", self.cmd_exit, "Exit Pupyteer")

    #: Second-token choices for commands that take a subcommand.
    _SUBCOMMANDS = {
        "sessions": ["list", "info", "interact", "kill", "rename", "tag", "search"],
        "jobs": ["list", "kill", "info"],
        "tasks": ["list", "info", "cancel"],
        "profiles": ["list", "show", "validate", "load", "unload", "new"],
        "payloads": ["status", "list", "build", "info", "verify", "remove", "cleanup", "versions"],
        "config": ["get", "set"],
        "theme": ["dark", "light", "list"],
        "evasion": ["status", "run", "list", "stats"],
        "pipeline": ["run", "build", "test", "auto", "status", "history"],
    }

    def _complete_names(self, command: str) -> List[str]:
        """Live object names for the argument position of `command`."""
        if command == "sessions":
            return self._engine.sessions.list_ids()
        if command in ("use", "modules", "info"):
            return [m["name"] for m in self._engine.module_registry.list_all()]
        if command == "profiles":
            return [p["name"] for p in self._engine.profiles.list()]
        if command == "payloads":
            return [p.payload_id for p in self._engine.payloads.list_all()]
        return []

    def _setup_readline(self) -> None:
        """Configure readline for command history and tab completion."""
        if readline is None:
            logger.debug("readline unavailable — history and tab completion disabled")
            return
        try:
            readline.set_history_length(1000)
            readline.set_completer(
                TabCompleter(
                    self._registry.list_commands(),
                    self._SUBCOMMANDS,
                    self._complete_names,
                ).complete
            )
            readline.parse_and_bind("tab: complete")
            if os.path.exists(self._history_file):
                readline.read_history_file(self._history_file)
        except Exception:
            logger.debug("readline setup failed", exc_info=True)

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for terminal resize and interrupt."""
        try:
            signal.signal(signal.SIGWINCH, self._handle_resize)
        except (AttributeError, OSError):
            # Windows doesn't support SIGWINCH
            pass

    def _handle_resize(self, signum: int, frame: Any) -> None:
        """Handle terminal resize events."""
        # Get new terminal size
        try:
            import shutil
            size = shutil.get_terminal_size()
            logger.debug("Terminal resized to %dx%d", size.columns, size.lines)
            # Re-render status bar on resize
            if self._running:
                self._status_bar.render()
        except Exception:
            pass

    def _update_theme(self, theme_name: str) -> None:
        """Update the current theme."""
        self._theme_name = theme_name
        self._theme = get_theme(theme_name)
        self._prompt = c("pupyteer", self._theme.get("prompt"), _Ansi.BOLD) + c(" > ", self._theme.get("muted"))
        self._status_bar = StatusBar(self._engine, self._theme)
        self._dashboard = SessionDashboard(self._engine, self._theme)

    # ------------------------------------------------------------------ #
    #  Render                                                             #
    # ------------------------------------------------------------------ #

    def render_banner(self) -> None:
        """Print the startup banner."""
        theme = self._theme
        print(c(BANNER, theme.get("banner"), _Ansi.BOLD))
        status = self._engine.get_status()
        server = status["config"]
        print(c(f"  [Server]", theme.get("success")), f"{server['server_host']}:{server['server_port']}")
        print(c(f"  [Operator]", theme.get("warning")), f"{server['operator']}")
        print(c(f"  [Profile]", theme.get("accent")), f"{status['state']['loaded_profile'] or 'none'}")
        print(c(f"  [Agents]", theme.get("info")), f"{status['state']['active_sessions']}")
        print()

    def render_dashboard(self) -> None:
        """Render the session dashboard."""
        self._dashboard.render()

    def render_table(self, headers: List[str], rows: List[List[str]]) -> None:
        """Render a simple ASCII table."""
        theme = self._theme
        if not rows:
            print(c("  (no data)", theme.get("muted")))
            return

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))

        # Header
        header_line = "  " + " │ ".join(c(h.ljust(w), theme.get("table_header")) for h, w in zip(headers, widths))
        print(header_line)
        print(c("  " + "─┼─".join("─" * w for w in widths), theme.get("table_border")))

        # Rows
        for row in rows:
            line = "  " + " │ ".join(str(cell).ljust(w) for cell, w in zip(row, widths))
            print(line)

    def render_error(self, message: str) -> None:
        """Render an error message with color coding."""
        print(c(f"  ✗ ERROR: {message}", self._theme.get("error"), _Ansi.BOLD))

    def render_warning(self, message: str) -> None:
        """Render a warning message with color coding."""
        print(c(f"  ⚠ WARNING: {message}", self._theme.get("warning")))

    def render_success(self, message: str) -> None:
        """Render a success message with color coding."""
        print(c(f"  ✓ {message}", self._theme.get("success")))

    def render_info(self, message: str) -> None:
        """Render an info message with color coding."""
        print(c(f"  ℹ {message}", self._theme.get("info")))

    # ------------------------------------------------------------------ #
    #  Commands                                                            #
    # ------------------------------------------------------------------ #

    async def cmd_help(self, args: List[str]) -> None:
        if args:
            print(self._registry.get_help(args[0], self._theme))
        else:
            print(self._registry.get_all_help(self._theme))

    async def cmd_banner(self, args: List[str]) -> None:
        self.render_banner()

    async def cmd_status(self, args: List[str]) -> None:
        status = self._engine.get_status()
        self.render_dashboard()

    async def cmd_theme(self, args: List[str]) -> None:
        """Change TUI theme."""
        if not args or args[0] == "list":
            themes = available_themes()
            print(c("\n  Available themes:", self._theme.get("primary"), _Ansi.BOLD))
            for t in themes:
                marker = "→" if t == self._theme_name else " "
                print(f"    {c(marker, self._theme.get('success'))} {t}")
            print()
        elif args[0] in available_themes():
            self._update_theme(args[0])
            self._config.set("operator.theme", args[0])
            self.render_success(f"Theme changed to '{args[0]}'")
        else:
            self.render_error(f"Unknown theme: {args[0]}. Available: {', '.join(available_themes())}")

    async def cmd_tasks(self, args: List[str]) -> None:
        if not args or args[0] == "list":
            tasks = await self._engine.tasks.list_all()
            if not tasks:
                self.render_warning("No tasks.")
                return
            headers = ["ID", "Name", "State", "Session", "Module", "Progress"]
            rows = []
            for t in tasks:
                rows.append([
                    t.task_id[:12],
                    t.name[:25],
                    t.state.value,
                    (t.session_id or "-")[:12],
                    t.module[:15],
                    f"{t.progress:.0%}",
                ])
            self.render_table(headers, rows)

        elif args[0] == "info" and len(args) > 1:
            task = await self._engine.tasks.get(args[1])
            if task:
                d = task.to_dict()
                for key, val in d.items():
                    print(f"    {c(key + ':', self._theme.get('info'))} {val}")
            else:
                self.render_error(f"Task not found: {args[1]}")

        elif args[0] == "cancel" and len(args) > 1:
            ok = await self._engine.tasks.cancel(args[1])
            if ok:
                self.render_success(f"Task {args[1]} cancelled.")
            else:
                self.render_error(f"Task not found: {args[1]}")

    async def cmd_profiles(self, args: List[str]) -> None:
        action = args[0] if args else "list"
        rest = args[1:]
        manager = self._engine.profiles

        if action == "list":
            profiles = manager.list()
            if not profiles:
                self.render_warning("No profiles loaded.")
                return
            headers = ["Name", "Version", "Transport", "Source", "Active"]
            self.render_table(
                headers,
                [[p["name"], p["version"], p["transport"], p["source"], "✓" if p["active"] else ""]
                 for p in profiles],
            )

        elif action == "show" and rest:
            profile = manager.get(rest[0])
            if profile:
                for key, val in profile.as_dict().items():
                    print(f"    {c(key + ':', self._theme.get('info'))} {val}")
            else:
                self.render_error(f"Profile not found: {rest[0]}")

        elif action == "load" and rest:
            if manager.load(rest[0]):
                self.render_success(f"Profile {rest[0]} loaded.")
            else:
                self.render_error(f"Failed to load profile: {rest[0]}")

        elif action == "validate" and rest:
            errors = manager.validate_errors(rest[0])
            if errors:
                for e in errors:
                    self.render_error(e)
            else:
                self.render_success(f"Profile {rest[0]} is valid.")

        elif action == "unload":
            manager.unload()
            self.render_success("Active profile unloaded.")

        elif action == "new":
            if not rest:
                self.render_error("Usage: profiles new <source.yaml>")
                return
            try:
                profile = manager.create_from_file(rest[0])
            except Exception as e:
                self.render_error(f"Could not create profile: {e}")
                return
            errors = profile.validate_errors()
            self.render_success(f"Profile '{profile.name}' created from {rest[0]}.")
            if not profile.is_valid():
                self.render_warning("It has validation errors — run "
                                    f"'profiles validate {profile.name}' before loading.")
            elif errors:
                for e in errors:
                    self.render_warning(e)

        else:
            self.render_warning(
                "Usage: profiles [list|show <name>|validate <name>|load <name>"
                "|unload|new <source.yaml>]"
            )

    async def cmd_transports(self, args: List[str]) -> None:
        transports = self._engine.transports.list()
        if not transports:
            self.render_warning("No active transports.")
            return
        for t in transports:
            print(f"    {c(t['name'], self._theme.get('success'))} [{t['state']}]  sent={t['stats']['bytes_sent']}B  recv={t['stats']['bytes_received']}B")

    async def cmd_config(self, args: List[str]) -> None:
        if not args or args[0] == "list":
            import json
            print(json.dumps(self._engine.config.all(), indent=2, default=str))
        elif args[0] == "get" and len(args) > 1:
            print(f"  {args[1]} = {self._engine.config.get(args[1])}")
        elif args[0] == "set" and len(args) > 2:
            self._engine.config.set(args[1], args[2])
            print(f"  Set {args[1]} = {args[2]}")

    async def cmd_logs(self, args: List[str]) -> None:
        log_path = self._engine.config.get("logging.file")
        if not log_path or not os.path.exists(log_path):
            self.render_warning("No log file configured or found.")
            return
        try:
            with open(log_path) as f:
                lines = f.readlines()
            tail = int(args[0]) if args else 20
            for line in lines[-tail:]:
                print("  " + line.rstrip())
        except Exception as e:
            self.render_error(f"Error reading logs: {e}")

    async def cmd_evasion(self, args: List[str]) -> None:
        """Run evasion testing commands."""
        from pupyteer.tui.commands import evasion

        handlers = {
            "status": evasion.evasion_status,
            "run": evasion.evasion_run,
            "list": evasion.evasion_list,
            "stats": evasion.evasion_stats,
            "profiles": evasion.evasion_profiles,
            "runner": evasion.evasion_runner,
        }
        await self._dispatch_subcommand(handlers, args, "evasion")

    async def cmd_pipeline(self, args: List[str]) -> None:
        """Run unified payload-to-evasion pipeline commands."""
        from pupyteer.tui.commands import pipeline

        handlers = {
            "run": pipeline.pipeline_run,
            "build": pipeline.pipeline_build,
            "test": pipeline.pipeline_test,
            "auto": pipeline.pipeline_auto,
            "status": pipeline.pipeline_status,
            "history": pipeline.pipeline_history,
            "profiles": pipeline.pipeline_profiles,
            "info": pipeline.pipeline_info,
        }
        await self._dispatch_subcommand(handlers, args, "pipeline")

    async def cmd_payloads(self, args: List[str]) -> None:
        """Manage payload lifecycle — build, verify, list, cleanup."""
        from pupyteer.tui.commands import payloads

        handlers = {
            "status": payloads.payload_status,
            "list": payloads.payload_list,
            "build": payloads.payload_build,
            "info": payloads.payload_info,
            "verify": payloads.payload_verify,
            "remove": payloads.payload_remove,
            "cleanup": payloads.payload_cleanup,
            "versions": payloads.payload_versions,
        }
        await self._dispatch_subcommand(handlers, args, "payloads")

    async def _dispatch_subcommand(
        self,
        handlers: Dict[str, Any],
        args: List[str],
        command: str,
    ) -> None:
        """Resolve `<command> <action>` against a handler table and render the result."""
        usage = f"{command} [{'|'.join(handlers)}] ..."
        if not args:
            self.render_warning(f"Usage: {usage}")
            return
        handler = handlers.get(args[0])
        if handler is None:
            self.render_error(f"Unknown {command} command: {args[0]}\n  Usage: {usage}")
            return
        try:
            result = await handler(self, args[1:])
        except Exception as e:
            self.render_error(f"{command.title()} error: {e}")
            logger.exception("%s command error", command)
            return
        if result.get("status") != "ok":
            self.render_error(
                result.get("error")
                or result.get("message")
                or f"{command} {args[0]} failed"
            )
            return
        self._render_command_result(result)

    def _render_command_result(self, result: Dict[str, Any]) -> None:
        """Render a command result as a table when its shape allows, else as JSON."""
        import json

        payloads = result.get("payloads")
        if payloads is not None:
            if not payloads:
                self.render_warning("No payloads built.")
                return
            headers = ["ID", "Name", "Ver", "Platform", "Arch", "Status", "Size", "Operator"]
            rows = [
                [
                    p["payload_id"][:12], p["name"][:20], p["version"],
                    p["platform"], p["arch"], p["status"],
                    f"{p['size_bytes'] // 1024}KB" if p["size_bytes"] else "-",
                    (p.get("operator") or "-")[:12],
                ]
                for p in payloads
            ]
            self.render_table(headers, rows)
            print(f"\n  Total: {len(payloads)} payloads")
            return

        history = result.get("versions")
        if history is not None:
            if not history:
                self.render_warning("No version history.")
                return
            headers = ["Version", "ID", "Status", "Built", "SHA-256"]
            rows = [
                [
                    h.get("version", "-"), str(h.get("payload_id", ""))[:12],
                    h.get("status", "-"), str(h.get("created_at", ""))[:19],
                    str(h.get("hash_sha256", ""))[:16],
                ]
                for h in history
            ]
            self.render_table(headers, rows)
            return

        print(json.dumps(result, indent=2, default=str))

    async def cmd_clear(self, args: List[str]) -> None:
        # Clear screen — no user input passed, safe
        print("\033[2J\033[H", end="")

    async def cmd_exit(self, args: List[str]) -> None:
        print(c("\n  Shutting down Pupyteer...", self._theme.get("warning")))
        self._running = False

    async def cmd_sessions(self, args: List[str]) -> None:
        """Manage sessions — MSF-style."""
        from pupyteer.tui.commands.sessions import (
            sessions_list, sessions_info, sessions_interact, sessions_kill,
            sessions_rename, sessions_tag, sessions_search,
        )
        if not args:
            args = ["list"]
        action = args[0]
        action_args = args[1:]
        handlers = {
            "list": sessions_list,
            "info": sessions_info,
            "interact": sessions_interact,
            "kill": sessions_kill,
            "rename": sessions_rename,
            "tag": sessions_tag,
            "search": sessions_search,
        }
        handler = handlers.get(action)
        if handler is None:
            self.render_warning(
                "Usage: sessions [list|info <id>|interact <id>|kill <id>"
                "|rename <id> <name>|tag <id> <tag>|search <query>]"
            )
            return
        try:
            result = await handler(self, action_args)
            if result.get("status") == "ok":
                await self._render_msf_result(result)
        except Exception as e:
            self.render_error(f"Sessions error: {e}")

    async def cmd_jobs(self, args: List[str]) -> None:
        """Manage background jobs."""
        from pupyteer.tui.commands.jobs import jobs_list, jobs_kill, jobs_info
        if not args:
            args = ["list"]
        action = args[0]
        action_args = args[1:]
        try:
            if action == "list":
                result = await jobs_list(self, action_args)
            elif action == "kill" and action_args:
                result = await jobs_kill(self, action_args)
            elif action == "info" and action_args:
                result = await jobs_info(self, action_args)
            else:
                self.render_warning("Usage: jobs [list|kill <id>|info <id>]")
                return
            if result.get("status") == "ok":
                await self._render_msf_result(result)
        except Exception as e:
            self.render_error(f"Jobs error: {e}")

    # ------------------------------------------------------------------ #
    #  MSF-Style Commands                                                 #
    # ------------------------------------------------------------------ #

    async def cmd_use(self, args: List[str]) -> None:
        """Select a module."""
        from pupyteer.tui.commands.msf_core import use
        try:
            result = await use(self, args)
        except Exception as e:
            self.render_error(f"use error: {e}")

    async def cmd_set(self, args: List[str]) -> None:
        """Set a module option."""
        from pupyteer.tui.commands.msf_core import set_option
        try:
            result = await set_option(self, args)
        except Exception as e:
            self.render_error(f"set error: {e}")

    async def cmd_unset(self, args: List[str]) -> None:
        """Unset a module option."""
        from pupyteer.tui.commands.msf_core import unset_option
        try:
            result = await unset_option(self, args)
        except Exception as e:
            self.render_error(f"unset error: {e}")

    async def cmd_search(self, args: List[str]) -> None:
        """Search modules."""
        from pupyteer.tui.commands.msf_core import search_modules
        try:
            result = await search_modules(self, args)
        except Exception as e:
            self.render_error(f"search error: {e}")

    async def cmd_info(self, args: List[str]) -> None:
        """Show active module info."""
        from pupyteer.tui.commands.msf_core import show_info
        try:
            result = await show_info(self, args)
        except Exception as e:
            self.render_error(f"info error: {e}")

    async def cmd_back(self, args: List[str]) -> None:
        """Deselect active module."""
        from pupyteer.tui.commands.msf_core import back
        try:
            result = await back(self, args)
        except Exception as e:
            self.render_error(f"back error: {e}")

    async def cmd_options(self, args: List[str]) -> None:
        """Show module options."""
        from pupyteer.tui.commands.msf_core import show_options
        try:
            result = await show_options(self, args)
        except Exception as e:
            self.render_error(f"options error: {e}")

    async def cmd_modules(self, args: List[str]) -> None:
        """List all modules."""
        from pupyteer.tui.commands.msf_core import show_modules
        try:
            result = await show_modules(self, args)
        except Exception as e:
            self.render_error(f"modules error: {e}")

    async def cmd_exploit(self, args: List[str]) -> None:
        """Execute (exploit) the active module."""
        from pupyteer.tui.commands.msf_core import exploit
        try:
            result = await exploit(self, args)
        except Exception as e:
            self.render_error(f"exploit error: {e}")

    async def cmd_run(self, args: List[str]) -> None:
        """Run the active module."""
        from pupyteer.tui.commands.msf_core import run_module
        try:
            result = await run_module(self, args)
        except Exception as e:
            self.render_error(f"run error: {e}")

    async def cmd_reload(self, args: List[str]) -> None:
        """Reload module registry."""
        from pupyteer.tui.commands.msf_core import reload_modules
        try:
            result = await reload_modules(self, args)
        except Exception as e:
            self.render_error(f"reload error: {e}")

    async def _render_msf_result(self, result: Dict[str, Any]) -> None:
        """Render an MSF-style command result dict."""
        import json
        status = result.get("status")
        if status == "ok":
            if "message" in result:
                self.render_success(result["message"])
            if "data" in result:
                for key, val in result["data"].items():
                    print(f"    {key}: {val}")
            if "table" in result:
                t = result["table"]
                self.render_table(t["headers"], t["rows"])
        elif status == "error":
            self.render_error(result.get("error", "unknown error"))
        else:
            print(json.dumps(result, indent=2, default=str))

    # ------------------------------------------------------------------ #
    #  Main Loop                                                           #
    # ------------------------------------------------------------------ #

    async def run(self) -> None:
        """Main TUI event loop."""
        self._running = True
        self.render_banner()

        # Start engine
        try:
            await self._engine.start()
        except Exception as e:
            self.render_error(f"Engine failed to start: {e}")
            return

        self.render_dashboard()

        loop = asyncio.get_event_loop()

        while self._running:
            try:
                # Read input in a non-blocking manner
                line = await loop.run_in_executor(None, lambda: input(self._prompt))

                line = line.strip()
                if not line:
                    continue

                parts = shlex.split(line)
                if not parts:
                    continue

                cmd_name = parts[0]
                cmd_args = parts[1:]

                cmd = self._registry.get(cmd_name)
                if cmd:
                    try:
                        await cmd["handler"](cmd_args)
                    except Exception as e:
                        self.render_error(f"{e}")
                        logger.exception("Command error")
                else:
                    self.render_error(f"Unknown command: {cmd_name}. Type 'help' for available commands.")

            except (EOFError, KeyboardInterrupt):
                await self.cmd_exit([])
            except Exception as e:
                logger.error("TUI error: %s", e)

        # Shutdown
        await self._engine.stop()
        if readline is not None:
            try:
                readline.write_history_file(self._history_file)
            except Exception:
                logger.debug("Could not write history file", exc_info=True)
        print(c("  Goodbye.\n", self._theme.get("primary")))
