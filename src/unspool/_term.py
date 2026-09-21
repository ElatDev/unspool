"""Minimal ANSI styling for the CLI. No dependencies, honours NO_COLOR."""

from __future__ import annotations

import contextlib
import os
import re
import sys
from typing import TextIO

_CODES = {
    "bold": "1", "dim": "2", "italic": "3", "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "magenta": "35", "cyan": "36", "grey": "90",
}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: object, *styles: str) -> str:
        text = str(text)
        if not self.enabled or not styles:
            return text
        codes = ";".join(_CODES[s] for s in styles)
        return f"\x1b[{codes}m{text}\x1b[0m"


def visible_len(text: str) -> int:
    return len(_ANSI.sub("", text))


def pad(text: str, width: int, align: str = "<") -> str:
    """Pad to ``width`` visible characters, ignoring ANSI escapes."""
    gap = max(width - visible_len(text), 0)
    return text + " " * gap if align == "<" else " " * gap + text


def truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[:max(width - 1, 0)] + "…"


def want_color(mode: str, stream: TextIO) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def prepare_stdout() -> None:
    """Make stdout safe for UTF-8 output and ANSI colour on every platform."""
    stream = sys.stdout
    if not stream.isatty() and (stream.encoding or "").lower().replace("-", "") != "utf8":
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    if sys.platform == "win32" and stream.isatty():
        try:  # enable VT processing so escape codes render in older consoles
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except (AttributeError, OSError):
            pass


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1000 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {secs:04.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes):02d}m {int(secs):02d}s"
