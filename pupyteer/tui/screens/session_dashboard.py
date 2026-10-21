"""Session dashboard screen for the Pupyteer TUI."""
from __future__ import annotations

from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.tui.screens.base import Screen
from pupyteer.tui.themes import Theme, _Ansi, c, status_dot


class SessionDashboard(Screen):
    """Renders the session dashboard widget."""

    def __init__(self, engine: PupyteerEngine, theme: Theme):
        super().__init__(engine, theme)

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

        inner = 50
        side = c("│", b)
        title = " Dashboard "
        rule = "─" * max(0, inner - 1 - len(title))
        top = (c("┌─", b) + c(title, theme.get("table_header"), _Ansi.BOLD)
               + c(rule + "┐", b))
        bot = c("└" + "─" * inner + "┘", b)

        def _row(label: str, value: str, kind: str) -> str:
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
