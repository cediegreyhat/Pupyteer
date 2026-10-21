"""Table renderer widget for the Pupyteer TUI."""
from __future__ import annotations

from typing import Any, List

from pupyteer.tui.themes import Theme, _Ansi, c


class TableRenderer:
    """Renders boxed tables with a header row and dim separators."""

    def __init__(self, theme: Theme):
        self._theme = theme

    def render(self, headers: List[str], rows: List[List[Any]]) -> None:
        theme = self._theme
        if not rows:
            print(c("  (no data)", theme.get("muted")))
            return

        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))

        b = theme.get("table_border")
        hdr = theme.get("table_header")

        def _sep(l: str, m: str, r: str) -> str:
            return c("  " + l + m.join("─" * (w + 2) for w in widths) + r, b)

        header_line = c("  │", b)
        for h, w in zip(headers, widths):
            header_line += " " + c(h.ljust(w), hdr, _Ansi.BOLD) + " " + c("│", b)
        print(_sep("┌", "┬", "┐"))
        print(header_line)
        print(_sep("├", "┼", "┤"))

        for idx, row in enumerate(rows):
            cells = []
            for cell, w in zip(row, widths):
                text = str(cell).ljust(w)
                if idx % 2 == 1:
                    text = c(text, theme.get("muted"))
                cells.append(text)
            print(c("  │", b) + " " + f" {c('│', b)} ".join(cells) + " " + c("│", b))
        print(_sep("└", "┴", "┘"))
