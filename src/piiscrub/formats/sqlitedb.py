"""sqlite (.db / .sqlite / .sqlite3) -> scrubbed text dump derivative.

Opens the database strictly READ-ONLY via a URI (``mode=ro&immutable=1``) so a
scan/strip never mutates the source and never fights a WAL/lock, dumps every
user table to CSV-ish text (``data.db`` -> ``data.db.txt``), and pushes the whole
dump through the walker's ``scrub`` closure so any PII in cell values is aliased.

Invariants (see docs/plans/2026-07-05-format-extractors-design.md, "sqlite"):

* Kind is always ``"derivative"``; ``out_rel`` is ``rel`` + ``.txt``. The source
  binary is NOT copied into DST (it would carry the very PII we scrubbed).
* Only user tables are dumped — internal ``sqlite_*`` tables (sequence/stat) are
  skipped. Tables are visited in a deterministic (name-sorted) order.
* Each table is written as ``# table: <name>``, a header row of column names,
  then one CSV-quoted row per record. BLOB columns are rendered as
  ``<blob N bytes>`` and NEVER hex-dumped — hex can encode PII invisibly to the
  text detectors. NULLs render as an empty field.
* Caps are fail-OPEN: exceeding ``max_members`` (total rows) or ``max_out_bytes``
  (total dump text) raises :class:`ExtractError`, as does ANY ``sqlite3.Error``
  (corrupt/locked/not-a-database). The walker then copies the original through
  unchanged and flags it. Because the full dump is built and scrubbed in memory
  BEFORE the derivative is written, an ExtractError can never leave a partial
  derivative behind; a write that still manages to fail mid-way is cleaned up.
* Stdlib only.
"""

from __future__ import annotations

import csv
import io
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

from . import register
from .base import ExtractError, ExtractLimits, ExtractOutcome, ScrubFn


def _cell(value: object) -> str:
    """Render one sqlite cell value as text for the CSV dump.

    BLOBs become ``<blob N bytes>`` (never hex — hex could smuggle PII past the
    text detectors); NULL becomes an empty field; everything else (int/float/str)
    is stringified and left for :mod:`csv` to quote as needed.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return f"<blob {len(value)} bytes>"
    return str(value)


def _user_tables(cur: sqlite3.Cursor) -> list[str]:
    """Return user table names (excluding internal ``sqlite_*`` tables), sorted
    for deterministic output."""
    cur.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' "
        "ORDER BY name"
    )
    return [row[0] for row in cur.fetchall()]


def _dump(conn: sqlite3.Connection, limits: ExtractLimits) -> str:
    """Build the full CSV-ish text dump of every user table.

    Enforces the row cap (``max_members``, total across all tables) and the byte
    cap (``max_out_bytes``, on the accumulated dump text) as it goes — either
    overrun raises :class:`ExtractError`.
    """
    buf = io.StringIO()
    # lineterminator="\n" keeps rows single-\n (csv defaults to \r\n) so the dump
    # reads like a normal text file and hashes stably across platforms.
    writer = csv.writer(buf, lineterminator="\n")
    total_rows = 0

    def _check_bytes() -> None:
        if buf.tell() > limits.max_out_bytes:
            raise ExtractError(
                f"dump exceeds max_out_bytes ({limits.max_out_bytes})"
            )

    with closing(conn.cursor()) as cur:
        for i, name in enumerate(_user_tables(cur)):
            if i:
                buf.write("\n")
            buf.write(f"# table: {name}\n")
            # Double-quote the identifier (escaping embedded quotes) so table
            # names with punctuation can't break or inject SQL.
            quoted = '"' + name.replace('"', '""') + '"'
            cur.execute(f"SELECT * FROM {quoted}")
            writer.writerow([d[0] for d in cur.description])
            _check_bytes()
            for row in cur:
                total_rows += 1
                if total_rows > limits.max_members:
                    raise ExtractError(
                        f"row count exceeds max_members ({limits.max_members})"
                    )
                writer.writerow([_cell(v) for v in row])
                _check_bytes()

    return buf.getvalue()


class _SqliteHandler:
    """Dump every user table to scrubbed CSV-ish text (``data.db`` ->
    ``data.db.txt``). Kind is always ``"derivative"``.
    """

    name = "sqlite"
    suffixes = (".db", ".sqlite", ".sqlite3")

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
        # Read-only + immutable: never touch the source, never create a WAL, and
        # never block on another process's lock. Any sqlite failure (corrupt,
        # not-a-database, locked) is a sqlite3.Error -> ExtractError -> the walker
        # copies the original through and flags it.
        uri = f"file:{path}?mode=ro&immutable=1"
        try:
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                dump = _dump(conn, limits)
        except sqlite3.Error as e:
            raise ExtractError(f"sqlite error: {e}") from e

        out_rel = rel + ".txt"
        scrubbed, reps = scrub(rel, dump)

        if write and out_path is not None:
            deriv = out_path.parent / (out_path.name + ".txt")
            deriv.parent.mkdir(parents=True, exist_ok=True)
            try:
                deriv.write_text(scrubbed, encoding="utf-8")
            except OSError:
                # Never leave a half-written derivative behind on a write error.
                if deriv.exists():
                    deriv.unlink()
                raise

        return ExtractOutcome(kind="derivative", out_rel=out_rel, replacements=reps)


HANDLER = register(_SqliteHandler())
