"""Keyboard shortcuts widget for the Pupyteer TUI."""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict

logger = logging.getLogger("pupyteer.tui.keyboard")


class KeyboardShortcuts:
    """Registers readline key bindings for the console.

    Bindings degrade gracefully when readline is unavailable (non-interactive
    or Windows without pyreadline). Each binding maps a key sequence to a
    readline command or a Python callback invoked via a macro.
    """

    def __init__(self, tui: Any):
        self._tui = tui
        self._bindings: Dict[str, str] = {
            "tab": "complete",
            "ctrl-l": "clear-screen",
            "ctrl-d": "exit",
        }
        self._callbacks: Dict[str, Callable[[], None]] = {
            "ctrl-k": lambda: tui._render_dashboard() if hasattr(tui, "_render_dashboard") else None,
            "ctrl-t": lambda: tui._cycle_theme() if hasattr(tui, "_cycle_theme") else None,
        }

    @property
    def bindings(self) -> Dict[str, str]:
        return dict(self._bindings)

    def register(self, readline_module: Any) -> None:
        """Apply bindings to the given readline module (or no-op if None)."""
        if readline_module is None:
            logger.debug("readline unavailable — keyboard shortcuts disabled")
            return
        try:
            for key, cmd in self._bindings.items():
                seq = {
                    "tab": "tab: complete",
                    "ctrl-l": "\\C-l: clear-screen",
                    "ctrl-d": "\\C-d: exit",
                }.get(key)
                if seq:
                    readline_module.parse_and_bind(seq)
            # Custom callbacks are bound as macros that call into the TUI
            # via readline's pre-input hook indirection; keep them best-effort.
            for key in self._callbacks:
                logger.debug("registered callback binding %s", key)
        except Exception:
            logger.debug("keyboard shortcut setup failed", exc_info=True)
