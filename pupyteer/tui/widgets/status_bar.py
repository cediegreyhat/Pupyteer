"""Status bar widget for the Pupyteer TUI."""
from __future__ import annotations

from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.tui.screens.session_dashboard import SessionDashboard
from pupyteer.tui.themes import Theme, c


class StatusBar:
    """Renders the persistent status bar."""

    SHORTCUTS = "Tab complete · Ctrl+L clear · Ctrl+K dashboard · Ctrl+T theme · Ctrl+D exit"

    def __init__(self, engine: PupyteerEngine, theme: Theme):
        self._engine = engine
        self._theme = theme
        self._dashboard = SessionDashboard(engine, theme)

    def render(self) -> None:
        """Render the status bar (compact + shortcut hints)."""
        theme = self._theme
        status_str = self._dashboard.render_compact()
        hint = c(self.SHORTCUTS, theme.get("muted"))
        print(f"\r{' ' * 80}\r{status_str}  {hint}", end="", flush=True)

    def render_full(self) -> None:
        """Render full status bar with newline."""
        theme = self._theme
        status_str = self._dashboard.render_compact()
        print(f"\n{status_str}\n")

    def render_compact(self) -> str:
        """Return the compact status string (no newline)."""
        return self._dashboard.render_compact()

    def refresh(self) -> None:
        """Re-render in place (resize-safe reprint)."""
        self.render()
