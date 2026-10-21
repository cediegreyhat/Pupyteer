"""Base class for Pupyteer TUI screens.

Screens are extractable rendering units that own a slice of the operator
console. Each screen holds a reference to the engine and the active theme
and exposes `render()` (full) plus optional `render_compact()` for the
status bar.
"""
from __future__ import annotations

from typing import Any


class Screen:
    """Base class for extracted TUI screens."""

    def __init__(self, engine: Any, theme: Any):
        self._engine = engine
        self._theme = theme

    def render(self) -> None:
        raise NotImplementedError

    def render_compact(self) -> str:
        return ""
