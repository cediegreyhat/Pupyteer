"""Pupyteer TUI theme definitions — dark and light color palettes."""
from __future__ import annotations

from typing import Dict, Any


class Theme:
    """A TUI color theme."""

    def __init__(self, name: str, colors: Dict[str, str]):
        self.name = name
        self._colors = colors

    def get(self, key: str, default: str = "") -> str:
        return self._colors.get(key, default)


# ANSI escape helpers
class _Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    BG_GRAY = "\033[100m"
    BG_DARK = "\033[40m"
    BG_LIGHT = "\033[107m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"

    @staticmethod
    def supports_color() -> bool:
        import sys
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    @staticmethod
    def supports_256() -> bool:
        import os
        term = os.environ.get("TERM", "")
        return "256" in term or "truecolor" in os.environ.get("COLORTERM", "")


def _dark_theme() -> Theme:
    """Dark terminal theme — optimized for dark backgrounds."""
    return Theme("dark", {
        "primary": _Ansi.CYAN,
        "secondary": _Ansi.BLUE,
        "accent": _Ansi.MAGENTA,
        "success": _Ansi.GREEN,
        "warning": _Ansi.YELLOW,
        "error": _Ansi.RED,
        "info": _Ansi.BLUE,
        "text": _Ansi.WHITE,
        "muted": _Ansi.GRAY,
        "border": _Ansi.DIM + _Ansi.WHITE,
        "prompt": _Ansi.GREEN,
        "banner": _Ansi.CYAN,
        "banner_text": _Ansi.BOLD + _Ansi.CYAN,
        "status_bar_bg": _Ansi.BG_BLUE,
        "status_bar_fg": _Ansi.WHITE,
        "dashboard_border": _Ansi.DIM + _Ansi.CYAN,
        "table_header": _Ansi.BOLD + _Ansi.CYAN,
        "table_border": _Ansi.DIM + _Ansi.WHITE,
        "error_bg": _Ansi.BG_RED,
        "error_fg": _Ansi.WHITE,
        "warning_bg": _Ansi.BG_YELLOW,
        "warning_fg": _Ansi.BG_DARK,
        "success_bg": _Ansi.BG_GREEN,
        "success_fg": _Ansi.WHITE,
    })


def _light_theme() -> Theme:
    """Light terminal theme — optimized for light backgrounds."""
    return Theme("light", {
        "primary": _Ansi.BLUE,
        "secondary": _Ansi.CYAN,
        "accent": _Ansi.MAGENTA,
        "success": "\033[32m",  # Darker green
        "warning": "\033[33m",  # Darker yellow
        "error": "\033[31m",  # Darker red
        "info": "\033[34m",  # Darker blue
        "text": "\033[30m",  # Black
        "muted": "\033[90m",
        "border": "\033[37m",
        "prompt": "\033[32m",
        "banner": "\033[34m",
        "banner_text": _Ansi.BOLD + "\033[34m",
        "status_bar_bg": "\033[44m",
        "status_bar_fg": "\033[97m",
        "dashboard_border": "\033[36m",
        "table_header": _Ansi.BOLD + "\033[34m",
        "table_border": "\033[37m",
        "error_bg": "\033[41m",
        "error_fg": "\033[97m",
        "warning_bg": "\033[43m",
        "warning_fg": "\033[30m",
        "success_bg": "\033[42m",
        "success_fg": "\033[97m",
    })


# Registry of available themes
THEMES: Dict[str, Theme] = {
    "dark": _dark_theme(),
    "light": _light_theme(),
}


def get_theme(name: str) -> Theme:
    """Get a theme by name, defaulting to dark."""
    return THEMES.get(name, THEMES["dark"])


def available_themes() -> list[str]:
    """Return list of available theme names."""
    return list(THEMES.keys())


def c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes (no-op if terminal doesn't support color)."""
    if _Ansi.supports_color():
        return "".join(codes) + text + _Ansi.RESET
    return text
