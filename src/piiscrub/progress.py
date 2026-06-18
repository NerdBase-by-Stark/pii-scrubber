"""Lightweight, dependency-free progress reporting.

A :class:`ProgressEvent` is emitted as work proceeds; a
:data:`ProgressCallback` consumes it. :func:`make_cli_renderer` returns a
callback that draws a single-line, carriage-return progress bar to a stream
(stderr by default) so it never pollutes the JSON written to stdout. The
renderer no-ops when disabled or when the target stream is not a TTY, so it is
safe to wire in unconditionally (tests/pipes stay quiet).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable


@dataclass
class ProgressEvent:
    files_done: int
    files_total: int
    current_file: str
    bytes_done: int
    bytes_total: int


ProgressCallback = Callable[["ProgressEvent"], None]


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024.0 or unit == "TB":
            return f"{f:.0f}{unit}" if unit == "B" else f"{f:.1f}{unit}"
        f /= 1024.0


def make_cli_renderer(stream=None, enabled: bool = True, width: int = 24) -> ProgressCallback:
    """Return a :data:`ProgressCallback` that renders a one-line progress bar.

    No-ops (returns a callback that does nothing) when ``enabled`` is False or
    when ``stream`` is not a TTY. Output goes to ``stream`` (default stderr)
    with a leading carriage return so successive updates overwrite in place.
    """
    if stream is None:
        stream = sys.stderr

    isatty = getattr(stream, "isatty", lambda: False)
    if not enabled or not isatty():
        def _noop(_ev: ProgressEvent) -> None:
            return None
        return _noop

    state = {"last_len": 0}

    def _render(ev: ProgressEvent) -> None:
        total = ev.files_total or 1
        frac = max(0.0, min(1.0, ev.files_done / total))
        filled = int(frac * width)
        bar = "#" * filled + "-" * (width - filled)
        name = ev.current_file
        if len(name) > 40:
            name = "..." + name[-37:]
        line = f"[{bar}] {ev.files_done}/{ev.files_total} {name}"
        if ev.bytes_total:
            line += f" ({_human(ev.bytes_done)}/{_human(ev.bytes_total)})"
        pad = max(0, state["last_len"] - len(line))
        stream.write("\r" + line + (" " * pad))
        if ev.files_done >= ev.files_total and ev.files_total > 0:
            stream.write("\n")
        stream.flush()
        state["last_len"] = len(line)

    return _render
