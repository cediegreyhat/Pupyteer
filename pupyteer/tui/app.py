"""Pupyteer TUI — Terminal User Interface with branding and command system."""
from __future__ import annotations

import asyncio
import getpass
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

from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.core.enrollment import secret_fingerprint
from pupyteer.server.core.operators import MIN_PASSWORD_CHARS, WeakCredential
from pupyteer.server.core.rbac import AccessDenied, Role
from pupyteer.tui.themes import (
    Theme, _Ansi, c, c_dim, gradient_line, get_theme, available_themes,
    theme_blurb, status_dot, ramp, _CYAN, _MAGENTA, strip_ansi, THEMES,
)

logger = logging.getLogger("pupyteer.tui")

#: Times the console asks for a credential before it gives up. The store locks a
#: name after five misses on its own, so this only stops someone fumbling at a
#: terminal that is not theirs.
LOGIN_ATTEMPTS = 3


# ─── Banner ────────────────────────────────────────────────────────────

#: Inner width of the banner frame, in visible columns. The gradient ramp and
#: the right-hand padding are both computed against this so the box never
#: drifts open when a terminal renders the box-drawing glyphs at double width.
_W = 64

_BANNER_WORDMARK = [
    "██████╗ ██╗   ██╗██████╗ ██╗   ██╗████████╗███████╗███████╗",
    "██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝██╔════╝",
    "██████╔╝██║   ██║██████╔╝ ╚████╔╝    ██║   █████╗  █████╗  ",
    "██╔═══╝ ██║   ██║██╔═══╝   ╚██╔╝     ██║   ██╔══╝  ██╔══╝  ",
    "██║     ╚██████╔╝██║        ██║      ██║   ███████╗███████╗",
    "╚═╝      ╚═════╝ ╚═╝        ╚═╝      ╚═╝   ╚══════╝╚══════╝",
]


def _render_banner(codename: str, version: str, theme: Theme) -> str:
    """Compose the startup banner: gradient wordmark, boxed tagline.

    Rendered per-theme at draw time rather than frozen at import, so switching
    themes re-sweeps the wordmark in the new palette instead of leaving the old
    gradient burned in.
    """
    grad = ramp(_CYAN, _MAGENTA, _W)
    box_c = theme.get("dashboard_border")

    def _row(content: str) -> str:
        # Pad to the inner width using VISIBLE length, so an already-colored
        # content string does not leave the frame short by its escape codes.
        vis = strip_ansi(content)
        pad = " " * max(0, _W - len(vis))
        return f"{c('║', box_c)}{content}{pad}{c('║', box_c)}"

    rows = ["",
            c("╔" + "═" * _W + "╗", box_c),
            _row("")]
    for line in _BANNER_WORDMARK:
        rows.append(_row(gradient_line("  " + line, grad)))
    rows.append(_row(""))
    tagline = f"   Red Team Operations Framework · v{codename} {version}   "
    rows.append(_row(c(tagline, theme.get("banner_text"), _Ansi.BOLD)))
    rows.append(_row(""))
    rows.append(c("╚" + "═" * _W + "╝", box_c))
    return "\n".join(rows)
#: The banner rendered once in the default (dark) palette. Kept as a module
#: constant because callers import it to check the wordmark/tagline without
#: standing up an engine; the live TUI re-renders it in the active theme.
BANNER = _render_banner("Nightfall", "1.0.0", THEMES["dark"])



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
        lines = [c(f"\n  {name}", theme.get("primary"), _Ansi.BOLD),
                 c("  " + "─" * (len(name) + 4), theme.get("table_border")),
                 f"    {cmd['help']}"]
        if cmd["usage"]:
            lines.append(c(f"    Usage: {cmd['usage']}", theme.get("muted")))
        return "\n".join(lines)

    def get_all_help(self, theme: Optional[Theme] = None) -> str:
        if theme is None:
            theme = get_theme("dark")
        lines = [c("\n  Available Commands", theme.get("primary"), _Ansi.BOLD),
                 c("  " + "─" * 46, theme.get("table_border"))]
        for name in sorted(self._commands.keys()):
            cmd = self._commands[name]
            lines.append(f"    {c(name.ljust(16), theme.get('success'), _Ansi.BOLD)}"
                         f"  {c(cmd['help'], theme.get('text'))}")
        lines.append(c("\n  Use 'help <command>' for details.\n", theme.get("muted")))
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
        b = theme.get("dashboard_border")
        val = theme.get("text")

        online = bool(state["started"])
        agents = state["active_sessions"]
        tasks = state["queued_tasks"]
        profile = state["loaded_profile"] or "none"

        #: Inner width between the frame glyphs. Every row and rule is built
        #: against this one number so a long value can never push the frame open.
        inner = 50
        side = c("│", b)
        #: The panel title lives inside the top rule, so it is part of the same
        #: fixed-width line rather than a separate row that could drift.
        title = " Dashboard "
        # ┌ + ─ + title + rule + ┐ must total inner + 2, so the rule fills
        # inner - 1 - len(title) and the frame never drifts.
        rule = "─" * max(0, inner - 1 - len(title))
        top = (c("┌─", b) + c(title, theme.get("table_header"), _Ansi.BOLD)
               + c(rule + "┐", b))
        bot = c("└" + "─" * inner + "┘", b)

        def _row(label: str, value: str, kind: str) -> str:
            # 2 pad + 9 label + 2 pad + 1 dot + 2 pad + value + slack + frame.
            head = 2 + 9 + 2 + 1 + 2
            slack = max(0, inner - head - len(str(value)))
            return (f"{side}  {c(label.ljust(9), theme.get('muted'))}"
                    f"  {status_dot(theme, kind)}  {c(value, val)}"
                    f"{' ' * slack}{side}")

        print()
        print(top)
        print(_row("Server", "online" if online else "offline",
                   "ok" if online else "off"))
        print(_row("Agents", str(agents), "ok" if agents else "off"))
        print(_row("Tasks", str(tasks), "warn" if tasks else "ok"))
        print(_row("Profile", profile, "none" if profile == "none" else "ok"))
        print(bot)
        print()

    def render_compact(self) -> str:
        """Render a compact status line for the status bar."""
        status = self._engine.get_status()
        state = status["state"]
        theme = self._theme
        return (
            f"{status_dot(theme, 'ok' if state['started'] else 'off')} "
            f"{c('Server', theme.get('muted'))} {'Online' if state['started'] else 'Offline'}  "
            f"{c('Agents', theme.get('info'))} {state['active_sessions']}  "
            f"{c('Tasks', theme.get('warning'))} {state['queued_tasks']}  "
            f"{c('Profile', theme.get('accent'))} {state['loaded_profile'] or 'none'}"
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
        self._prompt = (c("pupyteer", self._theme.get("prompt"), _Ansi.BOLD)
                                    + c(" ▸ ", self._theme.get("muted")))
        self._history_file = os.path.expanduser("~/.pupyteer_history")
        self._status_bar = StatusBar(engine, self._theme)
        self._dashboard = SessionDashboard(engine, self._theme)

        # What a login proved, not what the config says to be called. None means
        # this console has not been through the gate for any verb that needs one.
        self._token: Optional[str] = None
        self._operator: Optional[str] = None
        self._role: Optional[str] = None

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
                   "sessions [list|info <id>|interact <id>|results <id>|kill <id>|rename <id> <name>|tag <id> <tag>|search <query>]")
        r.register("jobs", self.cmd_jobs, "Manage background jobs", "jobs [list|kill <id>|info <id>]")
        r.register("tasks", self.cmd_tasks, "Manage tasks", "tasks [list|info <id>|cancel <id>]")
        r.register("payloads", self.cmd_payloads, "Payload lifecycle",
                   "payloads [status|list|build|info|verify|remove|cleanup|versions]")
        r.register("profiles", self.cmd_profiles, "Manage C2 profiles",
                   "profiles [list|show <name>|validate <name>|load <name>|unload|new <file>]")
        r.register("transports", self.cmd_transports, "List active transports")
        r.register("config", self.cmd_config, "View configuration", "config [get <key>|set <key> <value>]")
        r.register("logs", self.cmd_logs, "View recent audit logs")
        r.register("history", self.cmd_history, "Search/export command history",
                   "history [search <term>|export <file>|clear]")
        r.register("bookmark", self.cmd_bookmark, "Bookmark a session for quick access",
                   "bookmark [add <id> <name>|list|remove <name>|jump <name>]")
        r.register("alias", self.cmd_alias, "Define a command alias",
                   "alias [name=command|list|remove <name>]")
        r.register("watch", self.cmd_watch, "Repeat a command at an interval",
                   "watch <seconds> <command...>")
        r.register("export", self.cmd_export, "Export session results to a file",
                   "export [sessions|modules|history] <file>")
        r.register("uuid", self.cmd_uuid, "Generate UUIDs",
                   "uuid [count]")
        r.register("b64", self.cmd_b64, "Base64 encode/decode",
                   "b64 [encode|decode] <text>")
        r.register("hash", self.cmd_hash, "Hash text (md5/sha1/sha256)",
                   "hash [md5|sha1|sha256] <text>")
        r.register("time", self.cmd_time, "Show current time",
                   "time [utc|local|epoch]")
        r.register("random", self.cmd_random, "Generate random strings",
                   "random [length] [count]")
        r.register("calc", self.cmd_calc, "Evaluate a math expression",
                   "calc <expression>")
        r.register("ip", self.cmd_ip, "Show IP addresses",
                   "ip [local|public]")
        r.register("encode", self.cmd_encode, "URL/HTML encode text",
                   "encode [url|html] <text>")
        r.register("macro", self.cmd_macro, "Record/playback command macros",
                   "macro [record <name>|stop|play <name>|list|delete <name>]")
        r.register("evasion", self.cmd_evasion, "Evasion testing", "evasion [status|run|list|stats]")
        r.register("pipeline", self.cmd_pipeline, "Unified payload-to-evasion pipeline", "pipeline [run|build|test|auto|status|history]")
        r.register("theme", self.cmd_theme, "Change TUI theme", "theme [dark|list]")
        r.register("clear", self.cmd_clear, "Clear the screen")
        # These three are the only way through the gate, so they have to be
        # reachable with nobody logged in.
        r.register("login", self.cmd_login, "Sign in as an operator", "login [name]")
        r.register("logout", self.cmd_logout, "Sign out and revoke this token")
        r.register("whoami", self.cmd_whoami, "Show who this console is acting as")
        r.register("operator", self.cmd_operator, "Manage operator credentials",
                   "operator [list|add <name> <role>|role <name> <role>|remove <name>]")
        r.register("enrollment", self.cmd_enrollment,
                   "Which payloads may enrol: show, rotate, revoke",
                   "enrollment [show|rotate|revoke <fingerprint>]")
        r.register("exit", self.cmd_exit, "Exit Pupyteer")
        r.register("quit", self.cmd_exit, "Exit Pupyteer")

    #: Second-token choices for commands that take a subcommand.
    _SUBCOMMANDS = {
        "sessions": ["list", "info", "interact", "results", "download", "upload",
                     "kill", "rename", "tag", "search"],
        "jobs": ["list", "kill", "info"],
        "tasks": ["list", "info", "cancel"],
        "profiles": ["list", "show", "validate", "load", "unload", "new"],
        "payloads": ["status", "list", "build", "info", "verify", "remove", "cleanup", "versions"],
        "config": ["get", "set"],
        "theme": ["dark", "aurora", "light", "list"],
        "evasion": ["status", "run", "list", "stats"],
        "pipeline": ["run", "build", "test", "auto", "status", "history"],
        "operator": ["list", "add", "role", "remove"],
        "enrollment": ["show", "rotate", "revoke"],
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
        self._prompt = (c("pupyteer", self._theme.get("prompt"), _Ansi.BOLD)
                                    + c(" ▸ ", self._theme.get("muted")))
        self._status_bar = StatusBar(self._engine, self._theme)
        self._dashboard = SessionDashboard(self._engine, self._theme)

    # ------------------------------------------------------------------ #
    #  Operator gate                                                     #
    # ------------------------------------------------------------------ #
    #
    # What this gates is the console, not the network. There is no remote API: a
    # second process on this machine that can import PupyteerEngine can do what an
    # operator can. So a login decides which verbs this keyboard may run and who the
    # audit log blames for them, and claims nothing beyond that.

    def _first_credential(self) -> None:
        """Create one operator when the store holds none, and show it once.

        An empty store is not a broken server, but it is a door with no handle:
        nobody can get in to make the first account. Generating a password turns
        that into a five-second setup instead of a documentation hunt, and printing
        it once — never to the audit log, never to a file — is the same bargain the
        enrollment secret makes.
        """
        auth = self._engine.auth
        name = str(self._config.get("operator.name") or "").strip() or "admin"
        try:
            created = auth.bootstrap(name)
        except WeakCredential as exc:
            self.render_error(f"Cannot create the first operator: {exc}")
            return
        self.render_warning(
            "No operator credential exists yet, so this server made one to let you "
            "in. It is shown once and stored nowhere else:")
        print(c(f"    operator: {created['username']}", self._theme.get("info")))
        print(c(f"    password: {created['password']}\n", self._theme.get("info")))
        self.render_warning(
            f"Copy it now, then add your own with 'operator add <name>' and retire "
            f"this one with 'operator remove {created['username']}'.")

    async def _read(self, prompt: str, secret: bool = False) -> Optional[str]:
        """Read one line off the terminal without freezing the engine.

        The read runs in a worker thread because the event loop is what keeps live
        sessions being served; waiting for a password on the loop would stall every
        handler on this box for as long as someone takes to type it.
        """
        loop = asyncio.get_event_loop()
        reader = getpass.getpass if secret else input
        try:
            line = await loop.run_in_executor(None, reader, prompt)
        except Exception as exc:      # EOF, a closed stdin, a terminal that is not there
            logger.debug("Prompt abandoned: %s", exc)
            return None
        return line if secret else (line or "").strip()

    async def _sign_in(self, username: str, password: str) -> bool:
        auth = self._engine.auth
        token = auth.authenticate(username, password)
        if token is None:
            return False
        self._token = token
        self._operator = auth.get_operator(token)
        self._role = auth.role_of(token)
        self._engine.audit.set_operator(self._operator)
        return True

    def _sign_out(self) -> None:
        if self._token:
            self._engine.auth.revoke(self._token)
        self._token = None
        self._operator = None
        self._role = None
        self._engine.audit.set_operator(None)

    async def prompt_login(self, why: str = "") -> bool:
        """Ask for a credential, up to LOGIN_ATTEMPTS times."""
        auth = self._engine.auth
        if not auth.has_operators:
            self.render_error(
                "Nobody can sign in: no usable credential is stored in "
                f"{auth.operators.path}.")
            return False
        if why:
            self.render_info(why)
        default = str(self._config.get("operator.name") or "").strip()
        for _ in range(LOGIN_ATTEMPTS):
            asked = await self._read(f"  operator [{default}]: ")
            if asked is None:
                self.render_error("No terminal to ask for a credential in.")
                return False
            username = asked.strip() or default
            password = await self._read(f"  {username} password: ", secret=True)
            if password is None:
                return False
            if await self._sign_in(username, password):
                self.render_success(
                    f"Signed in as {self._operator} ({self._role}).")
                return True
            self.render_error("Wrong name or password.")
        return False

    async def _gate_startup(self) -> bool:
        """Whether this console may start the engine at all.

        Refusing to start is part of the design: a team server that opens its
        listeners for whoever ran the command has already accepted the connection
        nobody authorised, and whatever calls back cannot be unseen.
        """
        auth = self._engine.auth
        if not auth.require_auth:
            self.render_warning(
                "security.require_auth is off — no credential is asked for, "
                "everyone at this console is admin, and the audit log attributes "
                "everything to the configured name.")
            return True
        if not auth.has_operators:
            self._first_credential()
        return await self.prompt_login()

    async def _authorize(self, command: str, args: List[str],
                         _retried: bool = False) -> bool:
        """Whether this line may run now, rendering the refusal when it may not.

        Re-signing in place rather than exiting is what makes a long engagement
        survivable: the token holds an hour and a live session does not care, so an
        expired credential should cost a password and not the board.
        """
        auth = self._engine.auth
        if not auth.require_auth:
            return True
        try:
            self._engine.authz.authorize_command(self._token or "", command, args)
            return True
        except AccessDenied as exc:
            if exc.permission == "valid_token" and not _retried:
                expired = self._token is not None
                self._sign_out()
                if await self.prompt_login(
                        "Your sign-in expired — this server and its live sessions "
                        "keep running while you sign in again." if expired
                        else "This console is not signed in."):
                    return await self._authorize(command, args, _retried=True)
                # Asked, and no credential came. Reporting the generic denial here
                # reads as "your role may not", which is a different problem from
                # the one the operator is looking at and would send them to the
                # wrong file to fix.
                self._refused_without_credential(command, args)
                return False
            self._refused(command, args, exc)
            return False

    def _refused_without_credential(self, command: str,
                                    args: List[str]) -> None:
        verb = " ".join([command] + list(args)[:1]).strip()
        self.render_error(
            f"Not signed in — '{verb}' needs a credential. Run 'login'.")
        self._engine.audit.log_event(
            "command_denied",
            {"command": command, "permission": "valid_token",
             "args_count": len(args)},
            result="denied",
        )

    def _refused(self, command: str, args: List[str], exc: AccessDenied) -> None:
        self.render_error(f"Refused: {exc}")
        # A refusal is the entry an operator will later say they never typed, so it
        # is recorded with the same care as the command itself.
        self._engine.audit.log_event(
            "command_denied",
            {"command": command, "permission": exc.permission,
             "args_count": len(args)},
            result="denied",
        )

    # ------------------------------------------------------------------ #
    #  Gate verbs                                                        #
    # ------------------------------------------------------------------ #

    async def cmd_login(self, args: List[str]) -> None:
        if self._operator:
            self.render_info(
                f"Already signed in as {self._operator} ({self._role}); signing in "
                "again replaces that credential.")
        username = (args[0] if args
                    else str(self._config.get("operator.name") or "").strip())
        if not username:
            self.render_warning("Usage: login <name>")
            return
        password = await self._read(f"  {username} password: ", secret=True)
        if password is None:
            return
        if await self._sign_in(username, password):
            self.render_success(f"Signed in as {self._operator} ({self._role}).")
        else:
            self.render_error("Wrong name or password.")

    async def cmd_logout(self, args: List[str]) -> None:
        if not self._token:
            self.render_info("Not signed in.")
            return
        who = self._operator
        self._sign_out()
        self.render_success(f"Signed out {who}. That token is revoked.")

    async def cmd_whoami(self, args: List[str]) -> None:
        auth = self._engine.auth
        if not auth.require_auth:
            self.render_warning(
                "Authentication is off, so this console is whoever holds the "
                f"keyboard. Entries are attributed to "
                f"'{self._engine.audit.operator}'.")
            return
        remaining = auth.remaining(self._token) if self._token else None
        if remaining is None:
            self.render_warning(
                "Not signed in. Every verb that touches a session, a listener or "
                "an artifact is refused until you are.")
            return
        print(c(f"  operator: {self._operator}", self._theme.get("info")))
        print(c(f"  role:     {self._role}", self._theme.get("info")))
        print(c(f"  expires:  in {int(remaining)}s", self._theme.get("info")))

    async def cmd_operator(self, args: List[str]) -> None:
        """`operator list|add|role|remove` — the credential file, from the console.

        There is deliberately no password argument: argv is readable by any process
        on the box and the console's own history file would keep it.
        """
        auth = self._engine.auth
        usage = "operator [list|add <name> [role]|role <name> <role>|remove <name>]"
        if not args:
            self.render_warning(f"Usage: {usage}")
            return
        verb, rest = args[0], args[1:]
        if verb == "list":
            store = auth.operators
            names = store.names()
            if not names:
                self.render_warning(f"No operators stored in {store.path}.")
                return
            self.render_table(["OPERATOR", "ROLE"],
                              [[n, store.role_of(n).value] for n in names])
            return
        if verb == "add":
            await self._operator_add(rest)
            return
        if verb == "role":
            if len(rest) < 2:
                self.render_warning("Usage: operator role <name> <role>")
                return
            role, problem = self._parse_role(rest[1])
            if problem:
                self.render_error(problem)
                return
            try:
                record = auth.set_role(rest[0], role)
            except ValueError as exc:
                self.render_error(f"Refused: {exc}")
                return
            self.render_success(
                f"{record.username} is now {record.role.value}. A token already "
                "issued to them keeps the old role until it expires.")
            return
        if verb == "remove":
            if not rest:
                self.render_warning("Usage: operator remove <name>")
                return
            if not auth.remove_operator(rest[0]):
                self.render_error(f"No operator named {rest[0]}.")
                return
            self.render_success(f"Removed {rest[0]} and ended their live sessions.")
            return
        self.render_error(f"Unknown operator command: {verb}\n  Usage: {usage}")

    async def _operator_add(self, rest: List[str]) -> None:
        if not rest:
            self.render_warning("Usage: operator add <name> [role]")
            return
        role, problem = self._parse_role(rest[1] if len(rest) > 1 else "operator")
        if problem:
            self.render_error(problem)
            return
        name = rest[0]
        first = await self._read(f"  new password for {name}: ", secret=True)
        if first is None:
            return
        if len(first) < MIN_PASSWORD_CHARS:
            self.render_error(
                f"Refused: a credential needs at least {MIN_PASSWORD_CHARS} "
                "characters.")
            return
        if await self._read("  repeat it: ", secret=True) != first:
            self.render_error("Refused: the two entries did not match.")
            return
        try:
            record = self._engine.auth.add_operator(name, first, role)
        except ValueError as exc:
            self.render_error(f"Refused: {exc}")
            return
        self.render_success(f"Stored {record.username} as {record.role.value}.")

    @staticmethod
    def _parse_role(value: str) -> tuple:
        """Role from a typed word, and the reason it is not one.

        `system` is not offered: it is what the engine's own internals are allowed
        to do, and a console that could hand it out would be one mistyped verb away
        from having no rules left.
        """
        word = str(value).strip().lower()
        if word == Role.SYSTEM.value:
            return None, f"{Role.SYSTEM.value!r} is the engine's own role, not one " \
                         "an operator can be given"
        try:
            return Role(word), None
        except ValueError:
            offered = ", ".join(r.value for r in Role if r is not Role.SYSTEM)
            return None, f"Unknown role {word!r}; choose from {offered}"


    # ------------------------------------------------------------------ #
    #  Enrollment boundary                                               #
    # ------------------------------------------------------------------ #

    async def cmd_enrollment(self, args: List[str]) -> None:
        """`enrollment show|rotate|revoke` — which payloads may become a session.

        The secret is named here by fingerprint and its value is never printed.
        It is the one credential every deployed agent shares, which makes it the
        one worth the most to whoever finds it in a terminal scrollback or an
        audit line; the file is the only copy and the console's job is to keep it
        that way.
        """
        ledger = self._engine.transports.enrollment
        usage = "enrollment [show|rotate|revoke <fingerprint>]"
        if ledger is None:
            if self._engine.transports.listener_requires_auth is False:
                self.render_error(
                    "Agent authentication is off, so this listener enrols "
                    "whatever reaches its port — there is no boundary to manage "
                    "until server.agent_auth is on.")
            else:
                self.render_warning(
                    "No agent listener is running yet, so nothing is checking "
                    "registrations against anything.")
            return

        verb = args[0] if args else "show"
        if verb == "show":
            self._enrollment_show(ledger)
            return
        if verb == "rotate":
            await self._enrollment_rotate(ledger)
            return
        if verb == "revoke":
            self._enrollment_revoke(ledger, args[1:])
            return
        self.render_error(f"Unknown enrollment command: {verb}\n  Usage: {usage}")

    def _enrollment_show(self, ledger) -> None:
        rows = ledger.status()
        if not rows:
            self.render_error(
                f"{ledger.path} holds no enrollment secret, so this listener "
                "admits nobody. Restore the file, or delete it and restart to "
                "start a new boundary and rebuild the payloads.")
            return
        self.render_table(["FINGERPRINT", "ROLE"],
                          [[r["fingerprint"], r["role"]] for r in rows])
        retired = len(rows) - 1
        if retired:
            self.render_warning(
                f"{retired} retired secret(s) still enrol payloads built with "
                "them. That is the point of a rotation, not a leak — but each "
                "one is a door, and `enrollment revoke <fingerprint>` is how you "
                "close one you no longer need.")

    async def _enrollment_rotate(self, ledger) -> None:
        try:
            new, retired = ledger.rotate()
        except ValueError as exc:
            self.render_error(f"Refused: {exc}")
            return
        self._engine.audit.log_event(
            "enrollment_rotated",
            {"new": secret_fingerprint(new), "retired": secret_fingerprint(retired)},
            result="success")
        self.render_success(
            "New enrollment secret in place. Payloads built from here on carry "
            f"it ({secret_fingerprint(new)[:8]}…); the one before "
            f"({secret_fingerprint(retired)[:8]}…) is still accepted, so "
            "everything already deployed keeps its session.")
        print("  Nothing you build now will use the old one. Once no session you "
              "care about is built with it, close it:\n"
              f"    enrollment revoke {secret_fingerprint(retired)}")

    def _enrollment_revoke(self, ledger, rest: List[str]) -> None:
        if not rest:
            self.render_warning("Usage: enrollment revoke <fingerprint>")
            return
        wanted = rest[0].strip().lower()
        rows = ledger.status()
        if rows and wanted == rows[0]["fingerprint"]:
            # The message is the difference between this and a typo: the current
            # secret is the one new payloads are built with, so cutting it off is
            # a rotation, and saying "not found" would send an operator hunting
            # for a fingerprint that is plainly on the screen.
            self.render_error(
                "Refused: that is the current secret, and what `payloads build` "
                "compiles into new agents. Run `enrollment rotate` first — that "
                "retires it and keeps it working until you revoke it here.")
            return
        if not ledger.revoke(wanted):
            self.render_error(
                f"No retired secret with fingerprint {wanted!r}. "
                "`enrollment show` lists what is accepted.")
            return
        self._engine.audit.log_event(
            "enrollment_revoked", {"fingerprint": wanted}, result="success")
        self.render_success(
            f"{wanted} no longer enrols anything. Payloads built with it will be "
            "turned away on their next registration; sessions that already exist "
            "keep running on their own beacon token — kill those with "
            "`sessions kill <id>` if that is what you meant.")


    # ------------------------------------------------------------------ #
    #  Render                                                             #
    # ------------------------------------------------------------------ #

    def render_banner(self) -> None:
        """Print the startup banner."""
        theme = self._theme
        print(_render_banner("Nightfall", "1.0.0", theme))
        status = self._engine.get_status()
        server = status["config"]
        print(f"  {c('Server', theme.get('muted'))}  {c(f'{server['server_host']}:{server['server_port']}', theme.get('text'))}")
        # Whether callbacks are encrypted is the first thing that decides if this
        # server is safe to start using, so it goes where the operator looks first.
        fingerprint = server.get("listener_tls") or ""

        def _stat(label: str, value: str, kind: str) -> str:
            """A labelled status line: dim label, colored dot, plain value."""
            return (f"  {c(label.ljust(11), theme.get('muted'))}  "
                    f"{status_dot(theme, kind)}  {value}")

        if fingerprint:
            print(_stat("Channel", f"TLS, pinned to SHA-256 {fingerprint[:16]}…", "ok"))
        elif server.get("tls_configured") is False:
            print(_stat("Channel",
                        "PLAINTEXT callbacks — server.tls is off, so anyone on the "
                        "network reads every command and every result", "error"))
        else:
            # The banner is drawn before the engine starts, and the console now
            # starts it only after a sign-in. A missing fingerprint here means
            # nothing is listening yet, not that the channel is in the clear;
            # shouting PLAINTEXT at that would train operators to ignore the
            # warning for the case where it is true.
            print(_stat("Channel",
                        "TLS configured, no listener serving yet — 'banner' after "
                        "sign-in shows the pinned certificate", "warn"))
        # Encryption says nobody on the wire can read the sessions; it does not say
        # who is allowed to start one. That is what the enrollment secret is for.
        auth = server.get("agent_auth")
        if auth is False:
            print(_stat("Enrollment",
                        "unauthenticated — anything that reaches the port gets a session",
                        "error"))
        elif auth:
            print(_stat("Enrollment",
                        "registrations checked against this server's secret", "ok"))
        # No listener yet means there is no boundary to describe; saying so here
        # would claim a state the operator has not actually put the server in.
        # The third line a buyer of this banner reads is "who is doing this". A name
        # in a config file is what the audit log falls back to, not proof of who is
        # typing, so it is only ever shown as that.
        engine_auth = self._engine.auth
        if self._operator:
            print(_stat("Operator", f"{self._operator} as {self._role}", "ok"))
        elif engine_auth.require_auth:
            print(_stat("Operator",
                        "not signed in — verbs that touch a target are refused until "
                        "you are", "warn"))
        else:
            print(_stat("Operator",
                        f"console authentication is off; whoever holds this keyboard "
                        f"is admin, blamed as {server['operator']!r}", "error"))
        print(_stat("Profile", status['state']['loaded_profile'] or 'none', "none"))
        print(_stat("Agents", str(status['state']['active_sessions']),
                    "ok" if status['state']['active_sessions'] else "off"))
        print()

    def render_dashboard(self) -> None:
        """Render the session dashboard."""
        self._dashboard.render()

    def render_table(self, headers: List[str], rows: List[List[str]]) -> None:
        """Render a table with a boxed header row and dim separators."""
        theme = self._theme
        if not rows:
            print(c("  (no data)", theme.get("muted")))
            return

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))

        b = theme.get("table_border")
        hdr = theme.get("table_header")

        def _sep(l: str, m: str, r: str) -> str:
            return c("  " + l + m.join("─" * (w + 2) for w in widths) + r, b)

        # Header — bold gradient title in a boxed row
        header_line = c("  │", b)
        for h, w in zip(headers, widths):
            header_line += " " + c(h.ljust(w), hdr, _Ansi.BOLD) + " " + c("│", b)
        print(_sep("┌", "┬", "┐"))
        print(header_line)
        print(_sep("├", "┼", "┤"))

        # Rows — alternating dim stripe on even rows for scannability
        for idx, row in enumerate(rows):
            cells = []
            for cell, w in zip(row, widths):
                text = str(cell).ljust(w)
                if idx % 2 == 1:
                    text = c(text, theme.get("muted"))
                cells.append(text)
            print(c("  │", b) + " " + f" {c('│', b)} ".join(cells) + " " + c("│", b))
        print(_sep("└", "┴", "┘"))

    def render_error(self, message: str) -> None:
        """Render an error message with color coding."""
        print(c(f"  ✗  ERROR: {message}", self._theme.get("error"), _Ansi.BOLD))

    def render_warning(self, message: str) -> None:
        """Render a warning message with color coding."""
        print(c(f"  ⚠  WARNING: {message}", self._theme.get("warning")))

    def render_success(self, message: str) -> None:
        """Render a success message with color coding."""
        print(c(f"  ✓  {message}", self._theme.get("success")))

    def render_info(self, message: str) -> None:
        """Render an info message with color coding."""
        print(c(f"  ℹ  {message}", self._theme.get("info")))

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
                marker = "▸" if t == self._theme_name else " "
                blurb = c(theme_blurb(t), self._theme.get("muted"))
                line = f"    {c(marker, self._theme.get('success'))} {c(t, self._theme.get('text'), _Ansi.BOLD)}"
                print(f"{line:<32}  {blurb}")
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
            stats = t["stats"]
            # Whoever is refused at this port is the one fact in this table the
            # operator has to notice, and it is absent until it happens. Each kind
            # of refusal means something different: a stranger reaching the port, a
            # payload that cannot finish a handshake, and someone speaking for a
            # session whose id they got hold of without its token.
            suffix = "".join(
                "  " + c(f"{label}={stats[key]}", self._theme.get("error"))
                for key, label in (
                    ("registrations_rejected", "registrations rejected"),
                    ("beacons_refused", "beacons refused"),
                    ("handshakes_refused", "handshakes refused"),
                )
                if stats.get(key)
            )
            print(f"    {c(t['name'], self._theme.get('success'))} [{t['state']}]  sent={stats['bytes_sent']}B  recv={stats['bytes_received']}B{suffix}")

    async def cmd_config(self, args: List[str]) -> None:
        if not args or args[0] == "list":
            import json
            print(json.dumps(self._engine.config.all(), indent=2, default=str))
        elif args[0] == "get" and len(args) > 1:
            print(f"  {args[1]} = {self._engine.config.get(args[1])}")
        elif args[0] == "set" and len(args) > 2:
            if self._locked_at_runtime(args[1]):
                self.render_error(
                    f"Refused: {args[1]} is not a runtime preference. Set it in the "
                    "config file before starting the server.")
                self._engine.audit.log_event(
                    "configuration_refused", {"key": args[1]}, result="denied")
                return
            self._engine.config.set(args[1], args[2])
            print(f"  Set {args[1]} = {args[2]}")

    #: Keys the console will not rewrite while it is running. `operator.name` is
    #: who the audit log blames when nobody has signed in, and `security.*` is the
    #: gate itself: a server whose console can switch off its own gate has no gate.
    _LOCKED_KEYS = frozenset({"operator.name"})
    _LOCKED_PREFIXES = ("security.",)

    @classmethod
    def _locked_at_runtime(cls, key: str) -> bool:
        return key in cls._LOCKED_KEYS or key.startswith(cls._LOCKED_PREFIXES)

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

    async def cmd_history(self, args: List[str]) -> None:
        """Search or export the operator command history."""
        import readline
        try:
            n = readline.get_current_history_length()
            entries = [readline.get_history_item(i) for i in range(1, n + 1)]
            entries = [e for e in entries if e]
        except Exception as e:
            self.render_error(f"Could not read history: {e}")
            return

        if not args:
            for i, e in enumerate(entries[-20:], start=max(1, len(entries) - 19)):
                print(f"  {i:4d}  {e}")
            self.render_info(f"Showing last {min(20, len(entries))} of {len(entries)} entries.")
            return

        sub = args[0].lower()
        if sub == "search":
            term = " ".join(args[1:]).lower()
            matches = [(i, e) for i, e in enumerate(entries, 1) if term in e.lower()]
            for i, e in matches[-50:]:
                print(f"  {i:4d}  {e}")
            self.render_info(f"{len(matches)} match(es) for '{term}'.")
        elif sub == "export":
            path = args[1] if len(args) > 1 else "pupyteer_history.txt"
            try:
                with open(path, "w") as f:
                    for e in entries:
                        f.write(e + "\n")
                self.render_success(f"Exported {len(entries)} entries to {path}.")
            except Exception as e:
                self.render_error(f"Export failed: {e}")
        elif sub == "clear":
            try:
                readline.clear_history()
                if os.path.exists(self._history_file):
                    os.remove(self._history_file)
                self.render_success("Command history cleared.")
            except Exception as e:
                self.render_error(f"Clear failed: {e}")
        else:
            self.render_warning("Usage: history [search <term>|export <file>|clear]")

    async def cmd_bookmark(self, args: List[str]) -> None:
        """Bookmark sessions for quick access."""
        bookmarks = getattr(self, "_bookmarks", None)
        if bookmarks is None:
            bookmarks = {}
            self._bookmarks = bookmarks

        if not args:
            if not bookmarks:
                self.render_info("No bookmarks. Use: bookmark add <session_id> <name>")
                return
            for name, sid in bookmarks.items():
                print(f"  {name.ljust(16)} -> {sid}")
            self.render_info(f"{len(bookmarks)} bookmark(s).")
            return

        sub = args[0].lower()
        if sub == "add":
            if len(args) < 3:
                self.render_warning("Usage: bookmark add <session_id> <name>")
                return
            sid, name = args[1], args[2]
            bookmarks[name] = sid
            self.render_success(f"Bookmarked session {sid} as '{name}'.")
        elif sub == "remove":
            if len(args) < 2:
                self.render_warning("Usage: bookmark remove <name>")
                return
            name = args[1]
            if name in bookmarks:
                del bookmarks[name]
                self.render_success(f"Removed bookmark '{name}'.")
            else:
                self.render_warning(f"No bookmark named '{name}'.")
        elif sub == "jump":
            if len(args) < 2:
                self.render_warning("Usage: bookmark jump <name>")
                return
            name = args[1]
            if name in bookmarks:
                sid = bookmarks[name]
                self.render_info(f"Jumping to session {sid} ('{name}').")
                # Delegate to sessions interact
                await self.cmd_sessions(["interact", sid])
            else:
                self.render_warning(f"No bookmark named '{name}'.")
        elif sub == "list":
            if not bookmarks:
                self.render_info("No bookmarks.")
                return
            for name, sid in bookmarks.items():
                print(f"  {name.ljust(16)} -> {sid}")
        else:
            self.render_warning("Usage: bookmark [add <id> <name>|list|remove <name>|jump <name>]")

    async def cmd_alias(self, args: List[str]) -> None:
        """Define, list, or remove command aliases."""
        aliases = getattr(self, "_aliases", None)
        if aliases is None:
            aliases = {}
            self._aliases = aliases

        if not args:
            if not aliases:
                self.render_info("No aliases defined. Use: alias name=command")
                return
            for name, cmd in aliases.items():
                print(f"  {name.ljust(16)} -> {cmd}")
            self.render_info(f"{len(aliases)} alias(es).")
            return

        if args[0].lower() == "list":
            if not aliases:
                self.render_info("No aliases defined.")
                return
            for name, cmd in aliases.items():
                print(f"  {name.ljust(16)} -> {cmd}")
            return

        if args[0].lower() == "remove":
            if len(args) < 2:
                self.render_warning("Usage: alias remove <name>")
                return
            name = args[1]
            if name in aliases:
                del aliases[name]
                self.render_success(f"Removed alias '{name}'.")
            else:
                self.render_warning(f"No alias named '{name}'.")
            return

        # name=command form
        joined = " ".join(args)
        if "=" in joined:
            name, cmd = joined.split("=", 1)
            name = name.strip()
            cmd = cmd.strip()
            if not name or not cmd:
                self.render_warning("Usage: alias name=command")
                return
            aliases[name] = cmd
            self.render_success(f"Alias '{name}' -> '{cmd}'.")
        else:
            self.render_warning("Usage: alias name=command | alias list | alias remove <name>")

    async def cmd_watch(self, args: List[str]) -> None:
        """Repeat a command at a fixed interval (Ctrl+C to stop)."""
        if len(args) < 2:
            self.render_warning("Usage: watch <seconds> <command...>")
            return
        try:
            interval = float(args[0])
        except ValueError:
            self.render_error(f"Invalid interval: {args[0]}")
            return
        if interval < 0.5:
            self.render_warning("Minimum interval is 0.5 seconds.")
            return
        watch_cmd = args[1:]
        import asyncio as _a
        self.render_info(f"Watching every {interval}s: {' '.join(watch_cmd)} (Ctrl+C to stop)")
        try:
            while self._running:
                line = " ".join(watch_cmd)
                parts = shlex.split(line)
                if parts:
                    cmd = self._registry.get(parts[0])
                    if cmd:
                        try:
                            await cmd["handler"](parts[1:])
                        except Exception as e:
                            self.render_error(f"{e}")
                await _a.sleep(interval)
        except (KeyboardInterrupt, asyncio.CancelledError):
            self.render_info("Watch stopped.")

    async def cmd_export(self, args: List[str]) -> None:
        """Export session results, modules, or history to a file."""
        if not args:
            self.render_warning("Usage: export [sessions|modules|history] <file>")
            return
        kind = args[0].lower()
        path = args[1] if len(args) > 1 else f"pupyteer_{kind}.txt"
        try:
            if kind == "sessions":
                sessions = self._engine.sessions.list_all() if hasattr(self._engine, "sessions") else []
                with open(path, "w") as f:
                    for s in sessions:
                        f.write(f"{getattr(s, 'session_id', s)}\n")
                self.render_success(f"Exported {len(sessions)} session(s) to {path}.")
            elif kind == "modules":
                mods = self._registry.list_commands() if hasattr(self, "_registry") else []
                with open(path, "w") as f:
                    for m in mods:
                        f.write(m + "\n")
                self.render_success(f"Exported {len(mods)} module(s) to {path}.")
            elif kind == "history":
                import readline
                n = readline.get_current_history_length()
                entries = [readline.get_history_item(i) for i in range(1, n + 1)]
                entries = [e for e in entries if e]
                with open(path, "w") as f:
                    for e in entries:
                        f.write(e + "\n")
                self.render_success(f"Exported {len(entries)} history entries to {path}.")
            else:
                self.render_warning(f"Unknown export kind: {kind}. Use sessions|modules|history.")
        except Exception as e:
            self.render_error(f"Export failed: {e}")

    async def cmd_macro(self, args: List[str]) -> None:
        """Record, play, list, or delete command macros."""
        macros = getattr(self, "_macros", None)
        if macros is None:
            macros = {}
            self._macros = macros
        recording = getattr(self, "_macro_recording", None)

        if not args:
            if not macros:
                self.render_info("No macros. Use: macro record <name>")
                return
            for name, cmds in macros.items():
                print(f"  {name.ljust(16)} ({len(cmds)} cmd(s))")
            self.render_info(f"{len(macros)} macro(s).")
            return

        sub = args[0].lower()
        if sub == "record":
            if len(args) < 2:
                self.render_warning("Usage: macro record <name>")
                return
            self._macro_recording = args[1]
            self._macro_buffer = []
            self.render_success(f"Recording macro '{args[1]}'. Run commands, then 'macro stop'.")
        elif sub == "stop":
            if recording is None:
                self.render_warning("Not recording a macro.")
                return
            macros[recording] = list(getattr(self, "_macro_buffer", []))
            self._macro_recording = None
            self._macro_buffer = []
            self.render_success(f"Saved macro '{recording}' ({len(macros[recording])} cmd(s)).")
        elif sub == "play":
            if len(args) < 2:
                self.render_warning("Usage: macro play <name>")
                return
            name = args[1]
            if name not in macros:
                self.render_warning(f"No macro named '{name}'.")
                return
            for cmd_line in macros[name]:
                self.render_info(f"> {cmd_line}")
                parts = shlex.split(cmd_line)
                if not parts:
                    continue
                cmd = self._registry.get(parts[0])
                if cmd:
                    try:
                        await cmd["handler"](parts[1:])
                    except Exception as e:
                        self.render_error(f"{e}")
        elif sub == "list":
            if not macros:
                self.render_info("No macros defined.")
                return
            for name, cmds in macros.items():
                print(f"  {name.ljust(16)} ({len(cmds)} cmd(s))")
        elif sub == "delete":
            if len(args) < 2:
                self.render_warning("Usage: macro delete <name>")
                return
            name = args[1]
            if name in macros:
                del macros[name]
                self.render_success(f"Deleted macro '{name}'.")
            else:
                self.render_warning(f"No macro named '{name}'.")
        else:
            self.render_warning("Usage: macro [record <name>|stop|play <name>|list|delete <name>]")

    async def cmd_uuid(self, args: List[str]) -> None:
        """Generate one or more UUIDs."""
        try:
            count = int(args[0]) if args else 1
        except ValueError:
            self.render_error(f"Invalid count: {args[0]}")
            return
        if count < 1 or count > 100:
            self.render_warning("Count must be between 1 and 100.")
            return
        import uuid as _uuid
        for _ in range(count):
            print(f"  {_uuid.uuid4()}")

    async def cmd_b64(self, args: List[str]) -> None:
        """Base64 encode or decode text."""
        if len(args) < 2:
            self.render_warning("Usage: b64 [encode|decode] <text>")
            return
        mode = args[0].lower()
        text = " ".join(args[1:])
        import base64 as _b64
        try:
            if mode == "encode":
                out = _b64.b64encode(text.encode()).decode()
            elif mode == "decode":
                out = _b64.b64decode(text.encode()).decode()
            else:
                self.render_warning("Mode must be 'encode' or 'decode'.")
                return
            print(f"  {out}")
        except Exception as e:
            self.render_error(f"b64 failed: {e}")

    async def cmd_hash(self, args: List[str]) -> None:
        """Hash text using md5/sha1/sha256."""
        if len(args) < 2:
            self.render_warning("Usage: hash [md5|sha1|sha256] <text>")
            return
        algo = args[0].lower()
        text = " ".join(args[1:])
        import hashlib as _hl
        try:
            if algo == "md5":
                h = _hl.md5(text.encode()).hexdigest()
            elif algo == "sha1":
                h = _hl.sha1(text.encode()).hexdigest()
            elif algo == "sha256":
                h = _hl.sha256(text.encode()).hexdigest()
            else:
                self.render_warning("Algorithm must be md5, sha1, or sha256.")
                return
            print(f"  {algo}: {h}")
        except Exception as e:
            self.render_error(f"hash failed: {e}")

    async def cmd_time(self, args: List[str]) -> None:
        """Show current time in various formats."""
        import datetime as _dt
        mode = (args[0].lower() if args else "local")
        now = _dt.datetime.now(_dt.timezone.utc)
        if mode == "utc":
            print(f"  UTC:   {now.strftime('%Y-%m-%d %H:%M:%S')}")
        elif mode == "epoch":
            print(f"  Epoch: {int(now.timestamp())}")
        else:
            local = now.astimezone()
            print(f"  Local: {local.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            print(f"  UTC:   {now.strftime('%Y-%m-%d %H:%M:%S')}")

    async def cmd_random(self, args: List[str]) -> None:
        """Generate random alphanumeric strings."""
        try:
            length = int(args[0]) if args else 16
        except ValueError:
            self.render_error(f"Invalid length: {args[0]}")
            return
        try:
            count = int(args[1]) if len(args) > 1 else 1
        except ValueError:
            self.render_error(f"Invalid count: {args[1]}")
            return
        if length < 1 or length > 256 or count < 1 or count > 50:
            self.render_warning("length 1-256, count 1-50.")
            return
        import secrets as _sec
        import string as _str
        alphabet = _str.ascii_letters + _str.digits
        for _ in range(count):
            print(f"  {''.join(_sec.choice(alphabet) for _ in range(length))}")

    async def cmd_calc(self, args: List[str]) -> None:
        """Evaluate a math expression safely."""
        if not args:
            self.render_warning("Usage: calc <expression>")
            return
        expr = " ".join(args)
        try:
            # Safe eval: only math operations
            import math as _math
            allowed = {k: getattr(_math, k) for k in dir(_math) if not k.startswith("_")}
            allowed.update({"abs": abs, "round": round, "min": min, "max": max, "pow": pow})
            result = eval(expr, {"__builtins__": {}}, allowed)
            print(f"  {expr} = {result}")
        except Exception as e:
            self.render_error(f"calc failed: {e}")

    async def cmd_ip(self, args: List[str]) -> None:
        """Show local (and optionally public) IP addresses."""
        mode = (args[0].lower() if args else "local")
        import socket as _sock
        try:
            hostname = _sock.gethostname()
            local_ip = _sock.gethostbyname(hostname)
            print(f"  Hostname: {hostname}")
            print(f"  Local IP: {local_ip}")
        except Exception as e:
            self.render_error(f"Could not resolve local IP: {e}")
        if mode == "public":
            try:
                import urllib.request as _ur
                with _ur.urlopen("https://api.ipify.org", timeout=5) as resp:
                    print(f"  Public IP: {resp.read().decode().strip()}")
            except Exception as e:
                self.render_error(f"Could not fetch public IP: {e}")

    async def cmd_encode(self, args: List[str]) -> None:
        """URL or HTML encode text."""
        if len(args) < 2:
            self.render_warning("Usage: encode [url|html] <text>")
            return
        mode = args[0].lower()
        text = " ".join(args[1:])
        import urllib.parse as _up
        import html as _html
        try:
            if mode == "url":
                print(f"  {_up.quote(text)}")
            elif mode == "html":
                print(f"  {_html.escape(text)}")
            else:
                self.render_warning("Mode must be 'url' or 'html'.")
        except Exception as e:
            self.render_error(f"encode failed: {e}")

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
                    # Identifiers are never truncated: the table is where the
                    # operator reads the id they then pass to `remove`/`info`.
                    p["payload_id"], p["name"][:20], p["version"],
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
                    h.get("version", "-"), str(h.get("payload_id", "")),
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
            sessions_rename, sessions_tag, sessions_search, sessions_results,
            sessions_download, sessions_upload, sessions_screenshot,
            sessions_route,
        )
        if not args:
            args = ["list"]
        action = args[0]
        action_args = args[1:]
        handlers = {
            "list": sessions_list,
            "info": sessions_info,
            "interact": sessions_interact,
            "results": sessions_results,
            "download": sessions_download,
            "upload": sessions_upload,
            "screenshot": sessions_screenshot,
            "kill": sessions_kill,
            "rename": sessions_rename,
            "tag": sessions_tag,
            "search": sessions_search,
            "route": sessions_route,
        }
        handler = handlers.get(action)
        if handler is None:
            self.render_warning(
                "Usage: sessions [list|info <id>|interact <id>|results <id>"
                "|download <id> <remote> [local]|upload <id> <local> <remote>"
                "|screenshot <id> [local]|kill <id>|rename <id> <name>"
                "|tag <id> <tag>|search <query>|route <id> <module>]"
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
        from pupyteer.tui.commands.msf_core import search
        try:
            result = await search(self, args)
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
        from pupyteer.tui.commands.msf_core import run as run_module
        try:
            result = await run_module(self, args)
        except Exception as e:
            self.render_error(f"run error: {e}")

    async def cmd_reload(self, args: List[str]) -> None:
        """Reload module registry."""
        from pupyteer.tui.commands.msf_core import reload as reload_modules
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

        # Before the listeners, not after: signing in is what decides whether this
        # machine starts serving at all. A failed login here leaves no port open.
        if not await self._gate_startup():
            self.render_error("Not starting: no operator signed in. No listener was "
                              "opened and no payload has anywhere to call back to.")
            return

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

                # Record into active macro if recording
                if getattr(self, "_macro_recording", None):
                    buf = getattr(self, "_macro_buffer", None)
                    if buf is not None:
                        buf.append(line)

                parts = shlex.split(line)
                if not parts:
                    continue

                cmd_name = parts[0]
                cmd_args = parts[1:]

                # Expand aliases
                aliases = getattr(self, "_aliases", None) or {}
                if cmd_name in aliases:
                    expanded = shlex.split(aliases[cmd_name])
                    cmd_name = expanded[0]
                    cmd_args = expanded[1:] + cmd_args

                cmd = self._registry.get(cmd_name)
                if cmd:
                    if not await self._authorize(cmd_name, cmd_args):
                        continue
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
