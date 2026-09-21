"""Render a real CLI run to docs/screenshot.svg for the README.

    python tools/render_screenshot.py

The picture is generated from the actual output of ``unspool summary
examples/demo.pcapng``: the command runs, its ANSI colours are translated into
SVG text spans, and the result is drawn in a terminal window. Nothing is drawn
by hand, so the screenshot cannot drift away from what the tool prints.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "docs" / "screenshot.svg"
DEFAULT_COMMAND = ["summary", "examples/demo.pcapng"]

CHAR_WIDTH = 8.4
LINE_HEIGHT = 19.0
PADDING_X = 18.0
PADDING_Y = 46.0

BACKGROUND = "#11151c"
TITLE_BAR = "#1b212b"
DEFAULT_FG = "#c8d3e0"

COLOURS = {
    "31": "#f07178", "32": "#a3d977", "33": "#e7c664", "34": "#7aa2f7",
    "35": "#c792ea", "36": "#63d2e0", "90": "#6b7684",
}
DIM = "#7c8796"
ANSI = re.compile(r"\x1b\[([0-9;]*)m")


class Span:
    __slots__ = ("bold", "fill", "opacity", "text")

    def __init__(self, text: str, fill: str, bold: bool, opacity: float) -> None:
        self.text, self.fill, self.bold, self.opacity = text, fill, bold, opacity


def parse_ansi(line: str) -> list[Span]:
    """Split one line into styled spans."""
    spans: list[Span] = []
    fill, bold, opacity = DEFAULT_FG, False, 1.0
    pos = 0
    for match in ANSI.finditer(line):
        if match.start() > pos:
            spans.append(Span(line[pos:match.start()], fill, bold, opacity))
        for code in (match.group(1) or "0").split(";"):
            if code in ("", "0"):
                fill, bold, opacity = DEFAULT_FG, False, 1.0
            elif code == "1":
                bold = True
            elif code == "2":
                fill, opacity = DIM, 0.85
            elif code in COLOURS:
                fill = COLOURS[code]
        pos = match.end()
    if pos < len(line):
        spans.append(Span(line[pos:], fill, bold, opacity))
    return spans


def escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


#: The eighth-block characters the CLI draws bars with, and the fraction each fills.
BLOCKS = {chr(0x2588): 1.0, **{chr(0x258F - i): (i + 1) / 8 for i in range(7)}}


def bar_width(text: str) -> float | None:
    """Width in pixels if ``text`` is one of the CLI's bars, else None."""
    body = text.rstrip()
    if not body or any(char not in BLOCKS for char in body):
        return None
    return sum(BLOCKS[char] for char in body) * CHAR_WIDTH


def render(lines: list[str], title: str) -> str:
    rows = [parse_ansi(line) for line in lines]
    columns = max((sum(len(s.text) for s in row) for row in rows), default=80)
    width = columns * CHAR_WIDTH + PADDING_X * 2
    height = len(rows) * LINE_HEIGHT + PADDING_Y + 18

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}" font-family="ui-monospace, SFMono-Regular, '
        f'Menlo, Consolas, &quot;DejaVu Sans Mono&quot;, monospace" font-size="13">',
        f'<rect width="{width:.0f}" height="{height:.0f}" rx="10" fill="{BACKGROUND}"/>',
        f'<path d="M0 10a10 10 0 0 1 10-10h{width - 20:.0f}a10 10 0 0 1 10 10v22H0z" '
        f'fill="{TITLE_BAR}"/>',
        '<circle cx="20" cy="16" r="5.5" fill="#f0776c"/>',
        '<circle cx="38" cy="16" r="5.5" fill="#e7c664"/>',
        '<circle cx="56" cy="16" r="5.5" fill="#a3d977"/>',
        f'<text x="{width / 2:.0f}" y="21" fill="#8a94a6" font-size="12" '
        f'text-anchor="middle">{escape(title)}</text>',
    ]
    for index, row in enumerate(rows):
        y = PADDING_Y + index * LINE_HEIGHT
        pieces = []
        column = 0
        for span in row:
            x = PADDING_X + column * CHAR_WIDTH
            column += len(span.text)
            if not span.text.strip():
                continue
            width = bar_width(span.text)
            if width is not None:
                # Block-drawing characters leave gaps in most fonts, so the bars
                # are drawn as a rectangle of exactly the width they represent.
                out.append(f'<rect x="{x:.1f}" y="{y - 10.5:.1f}" width="{width:.1f}" '
                           f'height="12.5" rx="1.5" fill="{span.fill}" opacity="0.85"/>')
                continue
            weight = ' font-weight="600"' if span.bold else ""
            fade = f' opacity="{span.opacity}"' if span.opacity != 1.0 else ""
            # textLength pins each run to the monospace grid even when a glyph
            # (an arrow, an ellipsis) comes from a fallback font of another width.
            length = len(span.text) * CHAR_WIDTH
            pieces.append(f'<tspan x="{x:.1f}" fill="{span.fill}"{weight}{fade} '
                          f'textLength="{length:.1f}" lengthAdjust="spacing">'
                          f'{escape(span.text)}</tspan>')
        if pieces:
            out.append(f'<text y="{y:.1f}" xml:space="preserve">{"".join(pieces)}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("command", nargs="*", default=DEFAULT_COMMAND)
    args = parser.parse_args()

    command = args.command or DEFAULT_COMMAND
    env = {**os.environ, "FORCE_COLOR": "1", "PYTHONPATH": str(ROOT / "src"),
           "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run([sys.executable, "-m", "unspool", *command, "--color", "always"],
                          capture_output=True, cwd=ROOT, env=env)
    if proc.returncode:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return proc.returncode
    lines = proc.stdout.decode("utf-8").replace("\r\n", "\n").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    svg = render(lines, "unspool " + " ".join(command))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(svg, encoding="utf-8")
    print(f"wrote {args.out.relative_to(ROOT)} ({len(lines)} lines, {len(svg):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
