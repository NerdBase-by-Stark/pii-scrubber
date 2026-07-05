"""csv / json / jsonl field-aware scrub -> same-format, same-name output.

Structured sources are parsed, every recovered string is pushed through the
walker's ``scrub`` closure, and the result is re-serialised IN THE SAME format
under the SAME name (design doc, decision #7): a scrubbed ``.csv`` is still a
valid CSV, a ``.json`` stays ``json.loads``-able, and a ``.jsonl`` keeps one
JSON document per non-blank line. Every string is scrubbed — VALUES and dict
KEYS alike (a JSON key is just a string, and PII keys an object as readily as it
fills a value); numbers are scrubbed via their rendered text and become the
ALIAS STRING when they carried PII (a Luhn-valid card typed as an int must not
survive merely because of its JSON type), while booleans and null pass through
untouched — so downstream tooling keeps its field structure while the PII inside
the fields (and the keys) is aliased.

* csv: dialect sniffed from a bounded sample over a RESTRICTED delimiter set
  (``, ; \\t |``; fallback ``excel``); every cell — the header row included,
  hostnames live there — is scrubbed individually and rewritten with the same
  dialect (same delimiter / quotechar; the sniffed dialect's ``\\r\\n`` line
  terminator applies, a formatting change that keeps the output valid CSV).
  Constraining the delimiters stops :class:`csv.Sniffer` picking a character
  INSIDE the data on degenerate single-column content (a column of IPs would
  otherwise sniff delimiter ``'1'`` and reassemble raw addresses cell-by-cell).
* json: whole-document ``json.loads`` -> recursive value walk ->
  ``json.dumps(indent=2, ensure_ascii=False)`` (a formatting change,
  documented in the design doc).
* jsonl: per non-blank line loads -> walk -> compact dumps
  (``ensure_ascii=False``); blank lines are preserved. Any bad line fails the
  WHOLE file (a half-parsed jsonl must not ship half field-aware, half raw).

Fail-open invariant (see ``base.py``) with a structured-specific twist the
walker implements: these sources ARE text, so on :class:`ExtractError`
(undecodable bytes, malformed JSON/CSV, tripped ``max_out_bytes``) the walker
falls THROUGH to the plain regex-on-text scrub path — NOT copy-through —
because copying a text file through unchanged would ship raw PII. Nothing is
written before the whole output has been built and scrubbed in memory, so an
:class:`ExtractError` never leaves a partial derivative behind; a failure
*during* the final write deletes the half-written file before re-raising.

Stdlib only.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from . import register
from .base import ExtractError, ExtractLimits, ExtractOutcome, ScrubFn

# Chars of decoded text handed to csv.Sniffer. Bounded so a pathological
# single-line file cannot make dialect detection crawl; 64 KB of a real CSV is
# plenty to see the delimiter and quotechar.
_SNIFF_SAMPLE = 64 * 1024


def _csv_dialect(text: str):
    """Sniff the CSV dialect from a bounded sample, falling back to ``excel``.

    Sniffing is constrained to plausible field separators (``, ; \\t |``).
    Left unconstrained, :class:`csv.Sniffer` will happily pick a character
    INSIDE the data as the delimiter on degenerate single-column content — a
    column of IPs yields delimiter ``'1'`` (splitting ``10.0.0.1`` into cells
    that reassemble the raw address untouched), a column of MACs yields ``':'``
    — smuggling the PII straight through the per-cell scrub. On ANY sniff
    failure (a sample with none of those delimiters — single column, empty
    file, …) fall back to ``excel``, which reads the content as one cell per
    line so every character still round-trips through ``scrub``."""
    try:
        return csv.Sniffer().sniff(text[:_SNIFF_SAMPLE], delimiters=",;\t|")
    except csv.Error:
        return csv.excel


def _scrub_csv(text: str, rel: str, scrub: ScrubFn, budget: int) -> tuple[str, int]:
    """Parse ``text`` as CSV, scrub every cell, re-write with the same dialect.

    The header row is scrubbed like any other row (hostnames and contact
    columns live there). The running output is guarded against ``budget``
    per row (chars — a lower bound on bytes — so a runaway expansion trips
    before exhausting memory; the byte-accurate check happens in
    :meth:`_StructuredHandler.process` on the finished text)."""
    dialect = _csv_dialect(text)
    out = io.StringIO()
    writer = csv.writer(out, dialect)
    reps = 0
    try:
        for row in csv.reader(io.StringIO(text, newline=""), dialect):
            scrubbed_row: list[str] = []
            for cell in row:
                new, n = scrub(rel, cell)
                reps += n
                scrubbed_row.append(new)
            writer.writerow(scrubbed_row)
            if out.tell() > budget:
                raise ExtractError(
                    f"expanded text exceeds max_out_bytes ({budget})")
    except csv.Error as e:
        # e.g. a field larger than csv.field_size_limit() mid-file.
        raise ExtractError(f"malformed CSV: {e}") from e
    return out.getvalue(), reps


def _scrub_json_value(obj, cell):
    """Recursively scrub a decoded JSON structure through ``cell``.

    Every string VALUE is scrubbed. Dict KEYS are scrubbed too — a JSON key is
    always a string, and pre-v4 the whole-document text path aliased PII wherever
    it sat, keys included; leaving keys raw is a leak (an IP-keyed or email-keyed
    object ships its PII untouched). A scrubbed key still holds a string (the
    alias) and aliases are unique, so distinct source keys stay distinct — the
    one exception being the theoretical case where two DISTINCT source keys scrub
    to the SAME string (e.g. one key is raw PII and another is already that PII's
    alias text). The dict rebuild below resolves that deterministically as
    LAST-WINS (the later key/value overwrites), which is acceptable: both keys
    carried the same aliased identity anyway.

    Numeric scalars (int/float) are rendered to text and scrubbed: a Luhn-valid
    card number or an IP-shaped value typed as a JSON number must not survive
    just because of its type. If scrubbing rewrote the rendered form the ALIAS
    STRING replaces the number (an intended int/float -> str type change,
    matching the pre-v4 text path in effect); an untouched number passes through
    unchanged. Booleans and null are left untouched — a ``bool`` is an ``int``
    subclass, so it is filtered out BEFORE the numeric branch."""
    if isinstance(obj, str):
        return cell(obj)
    if isinstance(obj, list):
        return [_scrub_json_value(v, cell) for v in obj]
    if isinstance(obj, dict):
        scrubbed: dict = {}
        for k, v in obj.items():
            # JSON keys are always strings; scrub them like values. On a
            # post-scrub duplicate key (two distinct source keys aliasing to the
            # same string) the later assignment wins — deterministic last-wins.
            new_k = cell(k) if isinstance(k, str) else k
            scrubbed[new_k] = _scrub_json_value(v, cell)
        return scrubbed
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        rendered = str(obj)
        replaced = cell(rendered)
        # A hit means the rendered number carried PII -> ship the alias string
        # (type change is intentional); no hit -> keep the original number.
        return replaced if replaced != rendered else obj
    return obj


def _scrub_json_doc(text: str, rel: str, scrub: ScrubFn) -> tuple[str, int]:
    """Whole-document JSON: loads -> walk -> 2-space-indent dumps."""
    reps = 0

    def cell(s: str) -> str:
        nonlocal reps
        new, n = scrub(rel, s)
        reps += n
        return new

    try:
        obj = json.loads(text)
        scrubbed = _scrub_json_value(obj, cell)
    except json.JSONDecodeError as e:
        raise ExtractError(f"malformed JSON: {e}") from e
    except RecursionError as e:
        # A pathologically nested document blows the interpreter recursion
        # limit inside json.loads (or our mirror walk); RecursionError is not
        # an ExtractError, so without this the whole run would abort instead
        # of falling back to the text path.
        raise ExtractError("JSON nested too deeply") from e
    return json.dumps(scrubbed, indent=2, ensure_ascii=False) + "\n", reps


def _scrub_jsonl(text: str, rel: str, scrub: ScrubFn, budget: int) -> tuple[str, int]:
    """JSON Lines: per non-blank line loads -> walk -> compact dumps.

    Blank lines are preserved verbatim (including the implicit trailing blank
    from a final newline). Any unparseable line fails the WHOLE file with
    :class:`ExtractError` — a mixed half-field-aware output would be
    misleading, and the walker's text-path fallback scrubs every line anyway."""
    reps = 0

    def cell(s: str) -> str:
        nonlocal reps
        new, n = scrub(rel, s)
        reps += n
        return new

    out_lines: list[str] = []
    used = 0
    for i, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            out_lines.append(line)
            continue
        try:
            obj = json.loads(line)
            scrubbed = _scrub_json_value(obj, cell)
        except json.JSONDecodeError as e:
            raise ExtractError(f"malformed JSONL line {i}: {e}") from e
        except RecursionError as e:
            raise ExtractError(f"JSONL line {i} nested too deeply") from e
        dumped = json.dumps(scrubbed, ensure_ascii=False)
        used += len(dumped.encode("utf-8")) + 1
        if used > budget:
            raise ExtractError(
                f"expanded text exceeds max_out_bytes ({budget})")
        out_lines.append(dumped)
    return "\n".join(out_lines), reps


class _StructuredHandler:
    """Parse csv/json/jsonl, scrub every string value, re-serialise in the
    same format.

    Kind is ``"derivative"`` with ``out_rel == rel``: the output stays valid
    in its own format, so it keeps the source filename (the walker exempts a
    same-rel derivative from collision uniquification, like a repack).
    """

    name = "structured"
    suffixes = (".csv", ".json", ".jsonl")

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
        from ..walker import decode_bytes  # deferred: avoids import cycle

        budget = limits.max_out_bytes
        # Size guard BEFORE reading (mirrors archives.py): the output of a
        # field-aware scrub is at least as big as its input, so a source over
        # the budget cannot succeed — refuse it before slurping it into RAM.
        try:
            if path.stat().st_size > budget:
                raise ExtractError(
                    f"source exceeds max_out_bytes ({budget})")
            raw = path.read_bytes()
        except OSError as e:
            raise ExtractError(f"cannot read source: {e}") from e

        decoded = decode_bytes(raw)
        if decoded is None:
            raise ExtractError("not text-decodable")
        text, _enc = decoded

        suffix = path.suffix.lower()
        if suffix == ".csv":
            out_text, reps = _scrub_csv(text, rel, scrub, budget)
        elif suffix == ".jsonl":
            out_text, reps = _scrub_jsonl(text, rel, scrub, budget)
        else:
            out_text, reps = _scrub_json_doc(text, rel, scrub)

        if len(out_text.encode("utf-8")) > budget:
            # Byte-accurate final check (the per-row/per-line guards count a
            # chars/bytes lower bound while the output is being built).
            raise ExtractError(
                f"expanded text exceeds max_out_bytes ({budget})")

        if write and out_path is not None:
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(out_text, encoding="utf-8")
            except OSError as e:
                # A failure mid-write must not leave a truncated output behind
                # (fail-open invariant) and must not abort the whole run:
                # convert to ExtractError so the walker falls back — for this
                # handler, to the plain text scrub path.
                try:
                    out_path.unlink()
                except OSError:
                    pass
                raise ExtractError(f"could not write output: {e}") from e
        return ExtractOutcome(kind="derivative", out_rel=rel, replacements=reps)


HANDLER = register(_StructuredHandler())
