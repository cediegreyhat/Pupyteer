"""Banner screen for the Pupyteer TUI."""
from __future__ import annotations

from pupyteer.tui.themes import (
    Theme, _Ansi, c, gradient_line, ramp, strip_ansi, THEMES, _CYAN, _MAGENTA,
)

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
    """Compose the startup banner: gradient wordmark, boxed tagline."""
    grad = ramp(_CYAN, _MAGENTA, _W)
    box_c = theme.get("dashboard_border")

    def _row(content: str) -> str:
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


BANNER = _render_banner("Nightfall", "1.0.0", THEMES["dark"])
