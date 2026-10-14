"""Pupyteer TUI theme definitions — truecolor palettes with gradient support.

The look is a cyber-operations aesthetic: a cool cyan→magenta ramp against a
near-black field, with electric accents for state. Everything degrades
gracefully — a terminal with no color capability gets plain text, a 16-color
terminal gets the classic palette, and a truecolor terminal gets the full
24-bit gradient.

Two escape strategies coexist on purpose. `Theme.get()` returns a single
foreground color for a semantic key (success/error/…) and is what every call
site already uses; `gradient()` is the richer one, stepping a color across a
block of text. A palette therefore names each semantic role with a truecolor
triple AND a 16-color fallback, and `fg()` picks the richer code the terminal
can actually render.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Dict, List, Tuple


# ─── Truecolor primitives ──────────────────────────────────────────────

def rgb(r: int, g: int, b: int) -> str:
    """24-bit foreground ANSI code."""
    return f"\033[38;2;{r};{g};{b}m"


def bg_rgb(r: int, g: int, b: int) -> str:
    """24-bit background ANSI code."""
    return f"\033[48;2;{r};{g};{b}m"


def _hex_to_rgb(h: str) -> Tuple[int, int, int]:
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def ramp(c_from: Tuple[int, int, int], c_to: Tuple[int, int, int],
         steps: int) -> List[str]:
    """A list of `steps` truecolor codes fading from one color to another."""
    if steps <= 1:
        return [rgb(*c_from)]
    return [
        rgb(*tuple(_lerp(c_from[i], c_to[i], i and s / (steps - 1))
                   for i in range(3)))
        for s in range(steps)
    ]


# ─── Capability detection ──────────────────────────────────────────────

_COLOR_NO = 0
_COLOR_16 = 16
_COLOR_TRUE = 1 << 24


def _detect_color_level() -> int:
    """How many colors this terminal can render, honoring NO_COLOR / TERM=dumb."""
    if os.environ.get("NO_COLOR") is not None:
        return _COLOR_NO
    if os.environ.get("TERM", "").lower() == "dumb":
        return _COLOR_NO
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return _COLOR_NO
    colorterm = os.environ.get("COLORTERM", "").lower()
    if "truecolor" in colorterm or "24bit" in colorterm:
        return _COLOR_TRUE
    term = os.environ.get("TERM", "")
    if "256" in term:
        return 256
    if "color" in term or "ansi" in term or "xterm" in term:
        return _COLOR_16
    return _COLOR_NO


def _supports_truecolor() -> bool:
    return _detect_color_level() == _COLOR_TRUE


def supports_color() -> bool:
    return _detect_color_level() >= _COLOR_16


# ─── Classic 16-color ANSI (fallback + reference) ──────────────────────

class _Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
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
    BLINK = "\033[5m"
    REVERSE = "\033[7m"

    @staticmethod
    def supports_color() -> bool:
        """Whether the terminal can render color at all. The single point the
        `c()` helper consults, so a test can disable color by patching here."""
        return supports_color()

    @staticmethod
    def supports_256() -> bool:
        """256-color capability from TERM/COLORTERM alone.

        Deliberately NOT gated on isatty: this answers "could this terminal
        show 256 colors", which is a property of the terminal, not of whether
        stdout happens to be one right now.
        """
        term = os.environ.get("TERM", "")
        return ("256" in term
                or "truecolor" in os.environ.get("COLORTERM", "").lower())


# ─── Palette: semantic role → (truecolor triple, 16-color fallback) ────

def _p(tc: str, ansi: str) -> Tuple[str, str]:
    return (_hex_to_rgb(tc), ansi)


# The cyber ramp: deep teal → electric cyan → violet → magenta.
_CYAN = (86, 227, 255)
_TEAL = (34, 160, 196)
_BLUE = (88, 146, 255)
_INDIGO = (110, 110, 230)
_VIOLET = (168, 110, 245)
_MAGENTA = (230, 90, 210)
_GREEN = (70, 235, 130)
_AMBER = (245, 190, 60)
_RED = (245, 80, 80)
_GRAY = (120, 128, 140)
_TEXT = (226, 232, 240)


class Theme:
    """A TUI color theme with truecolor gradient support."""

    def __init__(self, name: str, colors: Dict[str, Tuple[str, str]],
                 field: Tuple[int, int, int] = (12, 16, 24)):
        self.name = name
        self._colors = colors
        self._field = field
        self._true = _supports_truecolor()

    def fg(self, key: str) -> str:
        """The ANSI foreground code for a semantic role, truecolor when available."""
        pair = self._colors.get(key)
        if not pair:
            return _Ansi.GRAY
        if isinstance(pair, str):
            return pair
        if self._true:
            return rgb(*pair[0])
        return pair[1]

    def get(self, key: str, default: str = "") -> str:
        """The ANSI code for a semantic role, truecolor when available.

        A palette value is normally a ``(truecolor, ansi)`` pair; a bare ANSI
        string is also accepted and returned as-is, so a caller can still build
        a Theme from plain escape codes.
        """
        pair = self._colors.get(key)
        if not pair:
            return default
        if isinstance(pair, str):
            return pair
        if self._true:
            return rgb(*pair[0])
        return pair[1]

    # -- special roles that are not simple foregrounds -------------------
    def banner(self) -> str:
        return self.fg("primary")

    def prompt(self) -> str:
        return self.fg("prompt")

    def success(self) -> str:
        return self.fg("success")

    def error(self) -> str:
        return self.fg("error")

    def warning(self) -> str:
        return self.fg("warning")

    def info(self) -> str:
        return self.fg("info")

    def accent(self) -> str:
        return self.fg("accent")


# ─── Palette definitions ───────────────────────────────────────────────

def _cyber_palette() -> Dict[str, Tuple[str, str]]:
    """The default: cyber-ops ramp, electric accents, dark field."""
    return {
        "primary": _p("#56e3ff", _Ansi.CYAN),       # electric cyan
        "secondary": _p("#5892ff", _Ansi.BLUE),     # cool blue
        "accent": _p("#e65ad2", _Ansi.MAGENTA),     # neon magenta
        "success": _p("#46eb82", _Ansi.GREEN),      # lime
        "warning": _p("#f5be3c", _Ansi.YELLOW),     # amber
        "error": _p("#f55050", _Ansi.RED),          # hot red
        "info": _p("#56e3ff", _Ansi.CYAN),          # cyan
        "text": _p("#e2e8f0", _Ansi.WHITE),         # near-white
        "muted": _p("#78809a", _Ansi.GRAY),         # cool gray
        "border": _p("#22304a", _Ansi.GRAY),        # steel border
        "prompt": _p("#46eb82", _Ansi.GREEN),       # lime prompt
        "banner": _p("#56e3ff", _Ansi.CYAN),
        "banner_text": _p("#a68ef5", _Ansi.MAGENTA),
        "dashboard_border": _p("#22304a", _Ansi.GRAY),
        "table_header": _p("#a68ef5", _Ansi.MAGENTA),
        "table_border": _p("#22304a", _Ansi.GRAY),
        "status_bar_bg": _p("#0c1018", _Ansi.BG_BLUE),
        "status_bar_fg": _p("#56e3ff", _Ansi.WHITE),
        "error_bg": _p("#2a0f14", _Ansi.BG_RED),
        "error_fg": _p("#f55050", _Ansi.WHITE),
        "warning_bg": _p("#2a2010", _Ansi.BG_YELLOW),
        "warning_fg": _p("#f5be3c", _Ansi.BG_DARK),
        "success_bg": _p("#0f2a18", _Ansi.BG_GREEN),
        "success_fg": _p("#46eb82", _Ansi.WHITE),
    }


def _aurora_palette() -> Dict[str, Tuple[str, str]]:
    """Variant: violet-forward ramp for a softer night-time look."""
    return {
        "primary": _p("#a68ef5", _Ansi.MAGENTA),
        "secondary": _p("#5892ff", _Ansi.BLUE),
        "accent": _p("#e65ad2", _Ansi.MAGENTA),
        "success": _p("#46eb82", _Ansi.GREEN),
        "warning": _p("#f5be3c", _Ansi.YELLOW),
        "error": _p("#f55050", _Ansi.RED),
        "info": _p("#8eb5ff", _Ansi.BLUE),
        "text": _p("#e2e8f0", _Ansi.WHITE),
        "muted": _p("#8890a0", _Ansi.GRAY),
        "border": _p("#2a2350", _Ansi.GRAY),
        "prompt": _p("#e65ad2", _Ansi.MAGENTA),
        "banner": _p("#a68ef5", _Ansi.MAGENTA),
        "banner_text": _p("#56e3ff", _Ansi.CYAN),
        "dashboard_border": _p("#2a2350", _Ansi.GRAY),
        "table_header": _p("#e65ad2", _Ansi.MAGENTA),
        "table_border": _p("#2a2350", _Ansi.GRAY),
        "status_bar_bg": _p("#120e1e", _Ansi.BG_BLUE),
        "status_bar_fg": _p("#e2e8f0", _Ansi.WHITE),
        "error_bg": _p("#2a0f14", _Ansi.BG_RED),
        "error_fg": _p("#f55050", _Ansi.WHITE),
        "warning_bg": _p("#2a2010", _Ansi.BG_YELLOW),
        "warning_fg": _p("#f5be3c", _Ansi.BG_DARK),
        "success_bg": _p("#0f2a18", _Ansi.BG_GREEN),
        "success_fg": _p("#46eb82", _Ansi.WHITE),
    }


def _light_palette() -> Dict[str, Tuple[str, str]]:
    """Light terminal theme — deeper colors that read on a white field."""
    return {
        "primary": _p("#0d7ea4", "\033[34m"),
        "secondary": _p("#1d4ed8", "\033[34m"),
        "accent": _p("#9333ea", "\033[35m"),
        "success": _p("#15803d", "\033[32m"),
        "warning": _p("#b45309", "\033[33m"),
        "error": _p("#dc2626", "\033[31m"),
        "info": _p("#0369a1", "\033[34m"),
        "text": _p("#1e293b", "\033[30m"),
        "muted": _p("#64748b", "\033[90m"),
        "border": _p("#94a3b8", "\033[37m"),
        "prompt": _p("#15803d", "\033[32m"),
        "banner": _p("#0d7ea4", "\033[34m"),
        "banner_text": _p("#7c3aed", "\033[35m"),
        "dashboard_border": _p("#94a3b8", "\033[36m"),
        "table_header": _p("#1d4ed8", "\033[34m"),
        "table_border": _p("#94a3b8", "\033[37m"),
        "status_bar_bg": _p("#e2e8f0", "\033[44m"),
        "status_bar_fg": _p("#1e293b", "\033[97m"),
        "error_bg": _p("#fee2e2", "\033[41m"),
        "error_fg": _p("#7f1d1d", "\033[97m"),
        "warning_bg": _p("#fef3c7", "\033[43m"),
        "warning_fg": _p("#78350f", "\033[30m"),
        "success_bg": _p("#dcfce7", "\033[42m"),
        "success_fg": _p("#14532d", "\033[97m"),
    }


# ─── Theme registry ────────────────────────────────────────────────────

THEMES: Dict[str, Theme] = {
    "dark": Theme("dark", _cyber_palette(), _hex_to_rgb("#0c1018")),
    "aurora": Theme("aurora", _aurora_palette(), _hex_to_rgb("#120e1e")),
    "light": Theme("light", _light_palette(), _hex_to_rgb("#e2e8f0")),
}

# Human-facing one-liners for `theme list`.
THEME_BLURB = {
    "dark": "cyber ramp, electric accents (default)",
    "aurora": "violet-forward, softer night look",
    "light": "daytime field, deep readable colors",
}


def _dark_theme() -> Theme:
    """The default cyber theme (kept as a factory for callers that want one)."""
    return THEMES["dark"]


def _light_theme() -> Theme:
    """The light theme (kept as a factory for callers that want one)."""
    return THEMES["light"]


def _aurora_theme() -> Theme:
    """The violet-forward variant."""
    return THEMES["aurora"]


def get_theme(name: str) -> Theme:
    return THEMES.get(name, THEMES["dark"])


def available_themes() -> list:
    return list(THEMES.keys())


def theme_blurb(name: str) -> str:
    return THEME_BLURB.get(name, "")


# ─── c(): the one color call sites use ─────────────────────────────────

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Visible length of a string, ignoring ANSI escape codes."""
    return _ANSI_RE.sub("", text)


def c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes (no-op if terminal doesn't support color).

    `codes` are raw ANSI strings, so a caller passes e.g. `theme.get("info")`.
    A code that is empty is skipped, so a missing palette key just renders
    plain text instead of emitting a stray escape.
    """
    if not _Ansi.supports_color():
        return text
    joined = "".join(cd for cd in codes if cd)
    if not joined:
        return text
    return joined + text + _Ansi.RESET


def c_dim(text: str, *codes: str) -> str:
    """Dim + colored variant for de-emphasized lines (captions, separators)."""
    if not supports_color():
        return text
    joined = _Ansi.DIM + "".join(cd for cd in codes if cd)
    return joined + text + _Ansi.RESET


def gradient_line(text: str, codes: List[str]) -> str:
    """Color `text` so each visible character walks the `codes` ramp.

    The ramp is sampled per column so a long line and a short one both read as
    a smooth sweep from the first color to the last. Any character that is
    part of an ANSI escape already present in `text` is left untouched, so
    this composes with a `c()`-wrapped string instead of fighting it.
    """
    if not _Ansi.supports_color() or not text:
        return text
    if not codes:
        return text
    visible = strip_ansi(text)
    n = len(visible)
    if n == 0:
        return text
    out: List[str] = []
    vi = 0
    i = 0
    while i < len(text):
        m = _ANSI_RE.match(text, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        ch = text[i]
        if codes:
            # Sample the ramp by visible-column position.
            idx = min(len(codes) - 1, int(vi / max(1, n - 1) * (len(codes) - 1)))
            out.append(codes[idx] + ch + _Ansi.RESET)
        vi += 1
        i += 1
    return "".join(out)


def status_dot(theme: Theme, kind: str) -> str:
    """A colored status indicator: green ● online, red ● down, etc."""
    glyph = {
        "ok": "●", "success": "●", "online": "●",
        "error": "●", "down": "●", "critical": "●",
        "warning": "◐", "warn": "◐", "idle": "◐",
        "off": "○", "none": "○", "unknown": "○",
    }.get(kind, "●")
    color = {
        "ok": theme.success(), "success": theme.success(),
        "online": theme.success(), "error": theme.error(),
        "down": theme.error(), "critical": theme.error(),
        "warning": theme.warning(), "warn": theme.warning(),
        "idle": theme.warning(),
    }.get(kind, theme.get("muted"))
    return c(glyph, color)
