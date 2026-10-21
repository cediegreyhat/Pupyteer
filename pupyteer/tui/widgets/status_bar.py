"""Status bar widget for the Pupyteer TUI."""
from __future__ import annotations

from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.tui.screens.session_dashboard import SessionDashboard
from pupyteer.tui.themes import Theme


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
        print(f"\r{' ' * 80}\r{status_str}", end="", flush=True)

    def render_full(self) -> None:
        """Render full status bar with newline."""
        theme = self._theme
        status_str = self._dashboard.render_compact()
        print(f"\n{status_str}\n")
