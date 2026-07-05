"""Format-extractor contract shared by every handler (pcap / archive / office /
sqlite).

Design invariants (see docs/plans/2026-07-05-format-extractors-design.md):

* Handlers turn a binary source file into scrubbed TEXT/repacked output by
  pushing every recovered string through the ``scrub`` closure the walker
  provides. That closure wraps the tokeniser with the run's detectors, AliasMap
  and allowlist — so **format modules never import the engine** and never see
  the decode map. They only ever produce plain text and hand it to ``scrub``.
* Failure is fail-OPEN: on any structural problem (corrupt/encrypted/locked
  input, exceeded guard) a handler raises :class:`ExtractError` with a human
  reason and the walker falls back to the *old* behaviour for that file —
  copy the original through unchanged and flag it "may contain PII". A handler
  MUST delete any half-written derivative BEFORE raising, so the fallback never
  leaves a truncated partial derivative behind (fail-open to copy-through, never
  to a silent partial).
* Stdlib only. Nothing under this package may import a third-party module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

# ``scrub(rel, text) -> (scrubbed_text, replacement_count)``.
#
# The walker builds this closure per run so a handler can tokenise any recovered
# text (a packet payload, a spreadsheet cell, an archived log line) without ever
# touching the engine or the AliasMap directly. ``rel`` is a display path for
# the chunk (e.g. ``"cap.pcap!packet-12"`` or ``"logs.zip!inner/app.log"``) used
# only for per-file attribution in the alias table.
ScrubFn = Callable[[str, str], tuple[str, int]]


class ExtractError(Exception):
    """Raised by a handler when a source cannot be fully/safely extracted.

    The walker catches this and falls back to copy-through-unchanged + flag,
    appending ``str(self)`` (a human reason) to the skip warning. Corrupt pcap,
    encrypted zip, password-protected office doc, locked/corrupt sqlite, and any
    tripped guard (size/depth/member cap) all land here. The handler must have
    already removed any partial derivative before raising.
    """


@dataclass(frozen=True)
class ExtractLimits:
    """Guard rails applied by every handler, wired from the ``[extract]`` config.

    * ``max_out_bytes`` — cap on total expanded text produced per source file
      (a decompression-bomb / runaway-dissection guard). Default 512 MB.
    * ``max_depth`` — nested-archive recursion cap. Default 3.
    * ``max_members`` — member / row cap for archives and sqlite dumps.
      Default 50 000.

    Exceeding any limit raises :class:`ExtractError` (→ copy-through + flag).
    """

    max_out_bytes: int = 512 * 1024 * 1024
    max_depth: int = 3
    max_members: int = 50_000


@dataclass
class ExtractOutcome:
    """What a handler produced for one source file.

    * ``kind`` — ``"derivative"`` (a new scrubbed text/CSV file whose name
      differs from the source, e.g. ``x.pcap`` -> ``x.pcap.txt``) or
      ``"repack"`` (same-format archive rewritten with scrubbed members, same
      name as the source).
    * ``out_rel`` — output path RELATIVE TO DST (posix). For a repack this
      equals the source rel; for a derivative it is the source rel plus the
      derivative suffix.
    * ``replacements`` — total alias substitutions made across everything the
      handler scrubbed for this source file.
    * ``members_processed`` / ``members_copied`` — archive bookkeeping: members
      scrubbed as text/nested-derivative vs. binary members copied in unchanged
      and flagged. Zero for single-file derivatives.
    * ``warnings`` — human notes (truncated capture, skipped member, …) the
      walker surfaces in the report, never containing raw PII.
    """

    kind: str
    out_rel: str
    replacements: int
    members_processed: int = 0
    members_copied: int = 0
    warnings: list[str] = field(default_factory=list)


@runtime_checkable
class FormatHandler(Protocol):
    """A registered extractor for one family of binary formats.

    Implementations live one-per-module under this package and register
    themselves with the registry (see ``formats/__init__.py``). The walker only
    ever calls :meth:`process`; everything else about a format is private to its
    module.
    """

    name: str                     # "pcap" | "archive" | "office" | "sqlite"
    suffixes: tuple[str, ...]      # lowercase, leading dot, e.g. (".pcap", …)

    def process(
        self,
        path: Path,
        rel: str,
        out_path: Path | None,
        scrub: ScrubFn,
        *,
        write: bool,
        limits: ExtractLimits,
    ) -> ExtractOutcome:
        """Extract + scrub ``path`` (source rel ``rel``).

        ``out_path`` is ``dst/rel`` when writing, or ``None`` for a dry-run
        (scan). A derivative handler writes to a name DERIVED from ``out_path``
        (e.g. ``out_path`` with the derivative suffix appended) and returns that
        derived location as ``out_rel``; a repack handler writes ``out_path``
        itself. When ``write`` is False (or ``out_path`` is None) the handler
        runs fully in memory — driving ``scrub`` so the AliasMap/report reflect
        what a strip would do — but writes nothing.

        Raises :class:`ExtractError` (after deleting any partial output) if the
        source cannot be fully and safely extracted.
        """
        ...
