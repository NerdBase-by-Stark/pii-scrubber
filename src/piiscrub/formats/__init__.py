"""Format-extractor registry.

Handlers register themselves at import time by calling :func:`register`. The
walker looks one up by file suffix via :func:`get_handler` and, when extraction
is enabled and the handler's ``name`` is not disabled, calls
``handler.process(...)``. On :class:`ExtractError` the walker falls back to the
old copy-through + flag behaviour, so a not-yet-implemented (stub) handler keeps
the tool behaving exactly as it did before extraction existed.

Importing this package imports every handler module below, which is what
populates the registry — keep the imports at the bottom so ``register`` exists
first.
"""

from __future__ import annotations

from .base import (
    ExtractError,
    ExtractLimits,
    ExtractOutcome,
    FormatHandler,
    ScrubFn,
)

__all__ = [
    "ExtractError",
    "ExtractLimits",
    "ExtractOutcome",
    "FormatHandler",
    "ScrubFn",
    "register",
    "get_handler",
    "handler_suffixes",
    "handler_names",
]

# suffix (lowercase, with dot) -> handler. One handler may own several suffixes.
_BY_SUFFIX: dict[str, FormatHandler] = {}
# name -> handler, so ``[extract] disable`` / --extract-disable can target a
# whole format family by its short name.
_BY_NAME: dict[str, FormatHandler] = {}


def register(handler: FormatHandler) -> FormatHandler:
    """Register ``handler`` under each of its suffixes and its name.

    Returns the handler so a module can ``HANDLER = register(MyHandler())``.
    Re-registering the same name replaces the prior handler (so a real
    implementation cleanly supersedes a stub if both are somehow imported).
    """
    _BY_NAME[handler.name] = handler
    for suffix in handler.suffixes:
        _BY_SUFFIX[suffix.lower()] = handler
    return handler


def get_handler(suffix: str) -> FormatHandler | None:
    """Return the handler for a file suffix (e.g. ``".pcap"``), or None.

    ``suffix`` is matched case-insensitively; the dot is expected (this mirrors
    :attr:`pathlib.Path.suffix`, which the walker passes straight through).
    """
    return _BY_SUFFIX.get(suffix.lower())


def handler_suffixes() -> frozenset[str]:
    """All suffixes any handler claims (lowercase, with dot)."""
    return frozenset(_BY_SUFFIX)


def handler_names() -> frozenset[str]:
    """All registered handler names (for disable-list validation/help)."""
    return frozenset(_BY_NAME)


# Import the concrete handlers so they self-register. These are stubs today
# (their ``process`` raises ExtractError("not implemented yet")); replacing a
# module body is the only change needed to light one up.
from . import pcap as _pcap          # noqa: E402,F401
from . import archives as _archives  # noqa: E402,F401
from . import office as _office      # noqa: E402,F401
from . import sqlitedb as _sqlitedb  # noqa: E402,F401
