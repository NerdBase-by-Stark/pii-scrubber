"""Folder walking, encoding detection, binary handling, and mirrored output.

Decoding strategy (stdlib only):
  BOM (utf-8-sig / utf-16 / utf-32) -> else utf-8 -> else cp1252.
A NUL byte in the first 4 KB (without a UTF-16/32 BOM) marks the file binary.
Binary / undecodable / oversized files are copied through UNCHANGED and flagged
in the report as "not processed" — never silently half-stripped.

Streamed huge files detect their encoding from a small probe window (so a
multibyte char split by the large read boundary cannot misdetect a clean utf-8
file as cp1252) and, if a LATER block turns out to contain invalid bytes,
fall back to copy-through-as-undecodable (deleting any partial output) so the
streaming path matches the whole-file not-processed contract exactly.
"""

from __future__ import annotations

import codecs
import csv
import fnmatch
import json
import os
import re
import shutil
import tempfile
import warnings
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .engine import AliasMap, tokenize, tokenize_segment
from .detectors import Detector
from .formats import ExtractError, ExtractLimits, get_handler
from .progress import ProgressCallback, ProgressEvent

if TYPE_CHECKING:      # runtime-decoupled: only a duck-typed .enabled/.disable/.limits
    from .config import ExtractConfig

# Streaming controls (see process_tree).
READ_BLOCK = 8 * 1024 * 1024   # raw bytes pulled per read for huge files
# OVERLAP is the number of decoded chars held back from each commit and carried
# into the next chunk so a token straddling a commit boundary is never split.
# INVARIANT: OVERLAP MUST stay larger than the longest token any detector can
# emit. If a single matched span is longer than OVERLAP, its tail can fall
# outside the carried window and the un-aliased remainder could be emitted raw
# (a PII leak). Most detectors cap at tens of chars, but the private-key
# detector matches a whole PEM block (potentially many KB), so keep OVERLAP
# comfortably large (>= a few KB; default 256 KB). _stream_file additionally
# guards against an over-long span rather than silently leaking it.
OVERLAP = 256 * 1024           # decoded chars carried between chunks so a token
                               # straddling a commit boundary is never split

# Bytes inspected to DETECT encoding for a streamed file. Kept small (and equal
# to the NUL-byte binary window used by decode_bytes) so a multibyte char split
# by the much larger READ_BLOCK boundary cannot make a strict decode of the
# whole 8 MB head fail and misdetect a clean utf-8 file as cp1252. The actual
# content is still decoded with the full incremental decoder.
PROBE_BLOCK = 4096


class _UndecodableStream(Exception):
    """Raised inside :func:`_stream_file` when a byte block beyond the encoding
    probe fails to decode under the chosen incremental encoding. Signals the
    caller to fall back to copy-through-as-undecodable (matching whole-file
    semantics) instead of leaving a half-written, truncated output behind."""


# Extensions we never try to treat as text.
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".tif", ".tiff", ".webp",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".7z", ".rar", ".bz2", ".xz",
    ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".odt", ".ods",
    ".evtx", ".etl", ".pcap", ".pcapng", ".cap",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".db", ".sqlite",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac",
    ".class", ".pyc", ".o", ".a", ".lib",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
}


# Binary capture/log formats that typically hold lots of PII but must be
# exported to TEXT first — piiscrub is a text scrubber, so it copies these
# through untouched. Map extension -> a one-line "how to get text out" hint
# that is appended to the skip warning so the operator isn't left guessing
# why a capture full of IPs/MACs produced zero replacements.
_CAPTURE_EXPORT_HINTS: dict[str, str] = {
    ".pcap": ("export to text first (Wireshark: File > Export Packet Dissections "
              "> As CSV/Plain Text, or `tshark -r FILE -V > out.txt`), then re-run "
              "on the text with --profile pcap-text"),
    ".evtx": ("export to text first (`wevtutil qe FILE /lf:true /f:text > out.txt`), "
              "then re-run"),
}
_CAPTURE_EXPORT_HINTS[".pcapng"] = _CAPTURE_EXPORT_HINTS[".pcap"]
_CAPTURE_EXPORT_HINTS[".cap"] = _CAPTURE_EXPORT_HINTS[".pcap"]
_CAPTURE_EXPORT_HINTS[".etl"] = _CAPTURE_EXPORT_HINTS[".evtx"]


def _capture_export_hint(suffix: str) -> str:
    """Return ' — <hint>' for binary capture/log formats that need a text
    export first (pcap/evtx/…), else ''. Appended to the skip warning."""
    hint = _CAPTURE_EXPORT_HINTS.get(suffix.lower())
    return f" — {hint}" if hint else ""


@dataclass
class FileStat:
    rel: str
    status: str           # "processed" | "extracted" | "binary" | "undecodable" | "oversize"
    encoding: str = ""
    replacements: int = 0
    # For status == "extracted": the DST-relative path of the derivative /
    # repacked output (differs from ``rel`` for derivatives, equals it for
    # repacks). Empty ⇒ output shares ``rel`` (all non-extracted files).
    out_rel: str = ""


@dataclass
class ExtractRecord:
    """One source file a format handler turned into scrubbed output. Feeds the
    report's "extracted" section — aliases/counts only, never raw PII."""
    rel: str                    # source path (DST-relative)
    out_rel: str                # derivative / repacked output path (DST-relative)
    kind: str                   # "derivative" | "repack"
    replacements: int
    members_processed: int = 0  # archives: members scrubbed as text/nested
    members_copied: int = 0     # archives: binary members copied in + flagged


@dataclass
class RunStats:
    files_total: int = 0
    files_processed: int = 0
    files_copied: int = 0       # binary / undecodable / oversize passthrough
    files_extracted: int = 0    # binary formats turned into scrubbed derivatives
    replacements: int = 0
    per_file: list[FileStat] = field(default_factory=list)
    skipped: list[FileStat] = field(default_factory=list)
    extracted: list[ExtractRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def decode_bytes(raw: bytes) -> tuple[str, str] | None:
    """Return (text, write_encoding) or None if the bytes are binary."""
    if raw.startswith(codecs.BOM_UTF8):
        return raw[len(codecs.BOM_UTF8):].decode("utf-8", "strict"), "utf-8-sig"
    if raw.startswith(codecs.BOM_UTF32_LE) or raw.startswith(codecs.BOM_UTF32_BE):
        try:
            return raw.decode("utf-32"), "utf-32"
        except UnicodeDecodeError:
            return None
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        try:
            return raw.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8", "strict"), "utf-8"
    except UnicodeDecodeError:
        try:
            return raw.decode("cp1252", "strict"), "cp1252"
        except UnicodeDecodeError:
            return None


def detect_stream_encoding(head: bytes) -> str | None:
    """Choose the write/decode encoding for a streamed file from its ``head``.

    Returns the encoding name (as :func:`decode_bytes` would) or None if the
    head is binary/undecodable. BOMs are honoured from the full head, but the
    utf-8 vs cp1252 decision probes only the first :data:`PROBE_BLOCK` bytes so
    a multibyte char split by the (much larger) READ_BLOCK boundary cannot
    cause a strict-decode failure that misdetects a clean utf-8 file as cp1252.

    For the no-BOM utf-8 probe we decode the small window with ``errors="ignore"``
    purely to gate the cp1252 fallback: if the window decodes clean under utf-8
    except for a truncated trailing multibyte sequence, we still pick utf-8 (the
    incremental decoder handles the real boundaries during content decoding). We
    fall back to cp1252 only when the window contains bytes that cp1252 can
    represent but utf-8 genuinely cannot at a non-trailing position.
    """
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if head.startswith(codecs.BOM_UTF32_LE) or head.startswith(codecs.BOM_UTF32_BE):
        return "utf-32"
    if head.startswith(codecs.BOM_UTF16_LE) or head.startswith(codecs.BOM_UTF16_BE):
        return "utf-16"
    if b"\x00" in head[:PROBE_BLOCK]:
        return None
    probe = head[:PROBE_BLOCK]
    # Use an incremental decoder so a multibyte char truncated by the PROBE_BLOCK
    # cut is treated as "needs more bytes", not as an invalid sequence — only a
    # genuine mid-stream invalid byte makes strict utf-8 fail here.
    try:
        codecs.getincrementaldecoder("utf-8")().decode(probe, False)
        return "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        probe.decode("cp1252", "strict")
        return "cp1252"
    except UnicodeDecodeError:
        return None


def _included(rel: str, include: list[str], exclude: list[str]) -> bool:
    if include and not any(fnmatch.fnmatch(rel, g) for g in include):
        return False
    if any(fnmatch.fnmatch(rel, g) for g in exclude):
        return False
    return True


def iter_files(src: Path, exclude_dirs: set[str]) -> list[Path]:
    out: list[Path] = []
    for p in sorted(src.rglob("*")):
        if p.is_dir():
            continue
        # Skip anything under an excluded dir name (e.g. the _pii sidecar).
        if any(part in exclude_dirs for part in p.relative_to(src).parts):
            continue
        out.append(p)
    return out


# ---------------------------------------------------------------------------
# Out-format adapter (--out-format text|csv|jsonl). "text" is the default and
# means exactly today's mirror behaviour (nothing below runs). For csv/jsonl the
# scrubbed TEXT outputs (plain files, the streaming path, and .txt derivatives
# from pcap/office/sqlite) are re-shaped AT WRITE TIME into per-line records
# ({"src", "n", "ts", "text"}) — except pcap derivatives, which group per packet
# ({"src", "packet", "ts", "text"}). Structured (csv/json/jsonl) handler outputs
# and repacked archives are NEVER re-shaped (no double-wrapping; archives keep
# their text members). See docs/plans/2026-07-05-llm-prep-mode-design.md #4/#5.

OUT_FORMATS = ("text", "csv", "jsonl")

# A pcap-derivative packet block header: ``# packet <N> ts=<value> caplen=...``.
# ``ts=n/a`` (pcapng SPB, which carries no capture timestamp) maps to null.
_PACKET_HDR_RE = re.compile(r"^# packet (\d+) ts=(\S+)")

# ts extraction (best-effort, NEVER synthesised; the matched substring passes
# through EXACTLY as it appears — timestamps are a sacred correlation key and are
# never reformatted). Leading ISO-8601 (T or space separator, optional fraction/
# offset/Z), leading syslog date ('Mon dd hh:mm:ss', incl. the double-space day),
# or a ``ts=<value>`` field anywhere in the line (pcap headers).
_ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
_SYSLOG_TS_RE = re.compile(
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
_TS_FIELD_RE = re.compile(r"ts=(\S+)")


def _extract_ts(line: str) -> str | None:
    """Best-effort timestamp for one line, or None. Returns the exact substring
    as it appears (never reformatted)."""
    s = line.lstrip()
    m = _ISO_TS_RE.match(s)
    if m:
        return m.group(0)
    m = _SYSLOG_TS_RE.match(s)
    if m:
        return m.group(0)
    m = _TS_FIELD_RE.search(line)
    if m:
        val = m.group(1)
        return None if val == "n/a" else val
    return None


def _iter_lines(text: str):
    """Yield each line of ``text`` (one record per line). A single trailing
    newline is a terminator, not an empty final line; internal blank lines are
    kept. A trailing carriage-return (CRLF input) is dropped from each line."""
    if text == "":
        return
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    for line in parts:
        yield line[:-1] if line.endswith("\r") else line


def _iter_packet_blocks(text: str):
    """Yield ``(packet_number|None, ts|None, block_text)`` for each
    ``# packet N ts=...`` block of a pcap derivative. ``block_text`` includes the
    header line. Any lines before the first packet header (rare structural
    warnings) form one leading block with a None packet number."""
    num: int | None = None
    ts: str | None = None
    buf: list[str] = []
    for line in _iter_lines(text):
        m = _PACKET_HDR_RE.match(line)
        if m:
            if buf:
                yield num, ts, "\n".join(buf)
            buf = [line]
            num = int(m.group(1))
            ts_raw = m.group(2)
            ts = None if ts_raw == "n/a" else ts_raw
        else:
            buf.append(line)
    if buf:
        yield num, ts, "\n".join(buf)


class _RecordWriter:
    """Writes reshaped records to an open text file in ``fmt`` (csv|jsonl). csv
    emits a header row first (columns ``src,n,ts,text``); the ``num_key`` names
    the jsonl number field (``"n"`` for line records, ``"packet"`` for pcap
    blocks). The file must be opened with ``newline=""`` so csv controls its own
    line terminator and jsonl's explicit ``\\n`` is not translated."""

    def __init__(self, fh, fmt: str, num_key: str = "n") -> None:
        self._fmt = fmt
        self._fh = fh
        self._num_key = num_key
        if fmt == "csv":
            self._csv = csv.writer(fh)
            self._csv.writerow(["src", "n", "ts", "text"])

    def write(self, src: str, num: int | None, ts: str | None, text: str) -> None:
        if self._fmt == "csv":
            self._csv.writerow([src, "" if num is None else num,
                                "" if ts is None else ts, text])
        else:
            rec = {"src": src, self._num_key: num, "ts": ts, "text": text}
            self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _reshape_text(text: str, src_rel: str, out_path: Path, fmt: str,
                  *, per_packet: bool) -> None:
    """Write ``text`` reshaped into records at ``out_path`` in ``fmt``. Per line
    for plain/office/sqlite text; per packet for pcap derivatives."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = _RecordWriter(fh, fmt, num_key="packet" if per_packet else "n")
        if per_packet:
            for num, ts, block in _iter_packet_blocks(text):
                w.write(src_rel, num, ts, block)
        else:
            for n, line in enumerate(_iter_lines(text), 1):
                w.write(src_rel, n, _extract_ts(line), line)


class _StreamRecordWriter:
    """Line-record writer for the streaming path: buffers only the incomplete
    trailing line between commits (line-by-line shaping, never whole-file
    buffering) and keeps a global 1-based line counter. Matches ``_iter_lines``:
    a trailing newline yields no empty final record; a file not ending in a
    newline emits its last partial line on :meth:`close`."""

    def __init__(self, fh, fmt: str, src_rel: str) -> None:
        self._w = _RecordWriter(fh, fmt, num_key="n")
        self._src = src_rel
        self._pending = ""
        self._lineno = 0

    def _emit(self, line: str) -> None:
        if line.endswith("\r"):
            line = line[:-1]
        self._lineno += 1
        self._w.write(self._src, self._lineno, _extract_ts(line), line)

    def feed(self, text: str) -> None:
        parts = (self._pending + text).split("\n")
        self._pending = parts.pop()          # incomplete trailing line
        for line in parts:
            self._emit(line)

    def close(self) -> None:
        if self._pending != "":
            self._emit(self._pending)
        self._pending = ""


def _stream_file(
    path: Path,
    out_path: Path | None,
    rel: str,
    detectors: list[Detector],
    amap: AliasMap,
    allowlist_cf: frozenset[str],
    enc: str,
    write: bool,
    *,
    files_done: int,
    files_total: int,
    bytes_total: int,
    bytes_base: int,
    progress: ProgressCallback | None,
    out_format: str = "text",
    style: Callable[[Detector, str], str] | None = None,
) -> int:
    """Stream a single (already-confirmed-text) huge file in overlapping chunks.

    Decodes raw byte blocks incrementally with the encoding ``enc`` chosen for
    the whole file, tokenises a growing text buffer, and commits only the
    portion whose replacement spans end at least ``OVERLAP`` chars from the
    buffer tail — carrying the remainder forward so no token is split across a
    commit boundary. Returns the number of replacements made.

    The committed output is written incrementally to ``out_path`` (when
    ``write``). Because spans are committed in the same left-to-right order and
    against the same ``amap`` as whole-file :func:`tokenize`, the result is
    byte-identical to whole-file processing of the same content.
    """
    dec = codecs.getincrementaldecoder(enc)()
    total_reps = 0
    buf = ""
    bytes_done = 0
    fh = None
    rec_writer: _StreamRecordWriter | None = None
    try:
        if write and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if out_format == "text":
                # newline="" preserves line endings exactly, like whole-file write.
                fh = open(out_path, "w", encoding=enc, newline="")
            else:
                # Reshaped records are a fresh utf-8 csv/jsonl container; the
                # source encoding is irrelevant to the record file itself.
                fh = open(out_path, "w", encoding="utf-8", newline="")
                rec_writer = _StreamRecordWriter(fh, out_format, rel)
        with open(path, "rb") as src_fh:
            while True:
                block = src_fh.read(READ_BLOCK)
                if not block:
                    break
                bytes_done += len(block)
                # FIX 1: invalid bytes in a LATER block must NOT crash streaming
                # and truncate output. The whole-file path would copy such a
                # file through as "undecodable"; match that by signalling the
                # caller to fall back to copy-through (which also deletes any
                # partial output, see process_tree).
                try:
                    buf += dec.decode(block, False)
                except UnicodeDecodeError as e:
                    raise _UndecodableStream(str(e)) from e
                if len(buf) > OVERLAP:
                    safe_end = len(buf) - OVERLAP
                    out_text, reps, consumed = tokenize_segment(
                        buf, detectors, amap, allowlist_cf, file=rel,
                        safe_end=safe_end, style=style,
                    )
                    if rec_writer is not None:
                        rec_writer.feed(out_text)
                    elif fh is not None:
                        fh.write(out_text)
                    total_reps += len(reps)
                    # Guard the OVERLAP invariant: if nothing was consumed even
                    # though the buffer is well over OVERLAP, a single span is
                    # longer than the carry window. tokenize_segment carries the
                    # whole span forward (so it is NOT leaked), but the buffer
                    # will keep growing until the span completes — surface it so
                    # a pathological input is visible rather than silent.
                    if consumed == 0 and len(buf) > 2 * OVERLAP:
                        import warnings as _warnings
                        _warnings.warn(
                            f"{rel}: a single detected span exceeds OVERLAP "
                            f"({OVERLAP} chars); buffering until it completes",
                            RuntimeWarning, stacklevel=2,
                        )
                    buf = buf[consumed:]
                # FIX 5: report cumulative bytes across the whole run so the bar
                # advances monotonically toward bytes_total.
                if progress is not None:
                    progress(ProgressEvent(files_done, files_total, rel,
                                           bytes_base + bytes_done, bytes_total))
            # Flush the incremental decoder and the final carry-over buffer.
            try:
                buf += dec.decode(b"", True)
            except UnicodeDecodeError as e:
                raise _UndecodableStream(str(e)) from e
            out_text, reps, _consumed = tokenize_segment(
                buf, detectors, amap, allowlist_cf, file=rel, safe_end=len(buf),
                style=style,
            )
            if rec_writer is not None:
                rec_writer.feed(out_text)
                rec_writer.close()
            elif fh is not None:
                fh.write(out_text)
            total_reps += len(reps)
    except _UndecodableStream:
        # Discard the half-written stripped output so no truncated file remains;
        # the caller will copy the original through unchanged.
        if fh is not None:
            fh.close()
            fh = None
        if write and out_path is not None and out_path.exists():
            out_path.unlink()
        raise
    finally:
        if fh is not None:
            fh.close()
    return total_reps


def process_tree(
    src: Path,
    dst: Path | None,
    detectors: list[Detector],
    amap: AliasMap,
    *,
    allowlist_cf: frozenset[str] = frozenset(),
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_bytes: int,
    write: bool,
    exclude_dirs: set[str],
    stream_threshold: int = 50 * 1024 * 1024,
    progress: ProgressCallback | None = None,
    post_pass: Callable[[str, str], tuple[str, int]] | None = None,
    extract: "ExtractConfig | None" = None,
    out_format: str = "text",
    style: Callable[[Detector, str], str] | None = None,
) -> RunStats:
    """Walk ``src``; tokenise text files into ``dst`` (when ``write``).

    When ``write`` is False (dry-run / scan) nothing is written but the
    AliasMap and stats are still populated for the report.

    Files at or below ``stream_threshold`` bytes are processed whole (preserving
    multi-line token detection, e.g. PEM private-key blocks). Larger files are
    streamed in overlapping chunks so memory stays flat while tokens straddling
    chunk boundaries are still caught (see :func:`_stream_file`). ``max_bytes``
    is a hard skip ceiling, defaulted effectively off so nothing is skipped.

    ``progress`` (if given) is called once per file on completion with the run's
    cumulative byte count (``bytes_done`` advances monotonically toward
    ``bytes_total`` across the whole run, not per file); streamed huge files are
    additionally called per chunk with the same cumulative byte accounting.

    ``post_pass`` (if given) is an OPTIONAL second pass applied ONLY to
    whole-file processed text AFTER the regex tokenize and BEFORE writing. It is
    called as ``post_pass(rel, stripped_text) -> (new_text, extra_replacements)``
    and runs on the already-stripped text, never on raw input. Streamed huge
    files SKIP the post-pass (a warning is emitted) because the streaming path
    commits incrementally; v1 leaves them regex-only.

    ``out_format`` (``"text"`` | ``"csv"`` | ``"jsonl"``) re-shapes scrubbed TEXT
    outputs at write time (plain files, streaming path, and pcap/office/sqlite
    ``.txt`` derivatives) into per-line / per-packet records; ``"text"`` (default)
    is exactly today's mirror behaviour. Structured (csv/json/jsonl) handler
    outputs and repacked archives are never re-shaped. See
    docs/plans/2026-07-05-llm-prep-mode-design.md decisions #4/#5. ``out_format``
    only affects strip (``write``); scan reports as today.

    ``style`` (optional ``(detector, value) -> alias_prefix`` callable, e.g.
    :func:`engine.make_structured_style`) is threaded into every tokenize call —
    the whole-file path, the ``_scrub`` closure handed to format handlers, and
    the streaming path — so structured aliases are applied uniformly across
    plain files, derivatives, and huge files. None (default) = opaque prefixes.
    """
    if out_format not in OUT_FORMATS:
        raise ValueError(
            f"out_format must be one of {OUT_FORMATS}, got {out_format!r}")
    include = include or []
    exclude = exclude or []
    stats = RunStats()

    # Count total files up front so progress can report files_total/bytes_total.
    candidates: list[tuple[Path, str, int]] = []
    bytes_total = 0
    for path in iter_files(src, exclude_dirs):
        rel = path.relative_to(src).as_posix()
        if not _included(rel, include, exclude):
            continue
        size = path.stat().st_size
        candidates.append((path, rel, size))
        bytes_total += size

    files_total = len(candidates)
    files_done = 0
    bytes_done_total = 0   # cumulative bytes of finished files (FIX 5)

    def _emit(rel: str) -> None:
        if progress is not None:
            progress(ProgressEvent(files_done, files_total, rel,
                                   bytes_done_total, bytes_total))

    def _copy_through(rel: str, status: str, warning: str) -> None:
        """Record a copy-through (binary/undecodable/oversize) and mirror the
        original unchanged when writing. Whole-file and streaming share this so
        their not-processed semantics stay identical."""
        stats.skipped.append(FileStat(rel, status))
        stats.files_copied += 1
        stats.warnings.append(warning)
        if write and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, out_path)

    # Extraction settings (format handlers). Default = ON with default limits and
    # nothing disabled, matching the CLI default. ``extract`` is duck-typed
    # (.enabled/.disable/.limits) so the walker stays decoupled from config.
    if extract is None:
        extract_enabled = True
        extract_disable: frozenset[str] = frozenset()
        extract_limits = ExtractLimits()
    else:
        extract_enabled = extract.enabled
        extract_disable = frozenset(extract.disable)
        extract_limits = extract.limits
    # Handlers receive the disable set folded into their limits so an archive
    # applies the SAME per-format disable contract to its members that the walker
    # applies to top-level files (findings: disable ignored for archive members).
    handler_limits = replace(extract_limits, disable=extract_disable)

    # Output-namespace bookkeeping so a format derivative (``x.pcap`` ->
    # ``x.pcap.txt``) can never silently clobber, or be clobbered by, a real
    # sibling source file that already lives at that exact name (e.g. a plain
    # ``x.pcap.txt`` created by the old export-to-text hint). ``reserved_rels`` is
    # every source rel (any of which may be written at its own path);
    # ``claimed_out_rels`` accrues derivative outputs. We resolve the derivative's
    # unique name here and MOVE the handler's staged output onto it (see the
    # extraction block); the handler never writes into DST directly, so ordering
    # between a producer and its colliding sibling no longer matters — critically,
    # on a case-INSENSITIVE filesystem (macOS/APFS, Windows/NTFS) where writing
    # ``x.pcap.txt`` would truncate an already-written ``X.PCAP.TXT`` sibling, the
    # move targets only the collision-resolved name and never the sibling.
    reserved_rels = {rel for _p, rel, _s in candidates}
    claimed_out_rels: set[str] = set()

    def _unique_out_rel(desired: str) -> str:
        # Compare case-INSENSITIVELY: on case-insensitive filesystems (Windows/
        # NTFS, macOS/APFS — the tool's primary pcap/evtx target platform)
        # ``X.PCAP.txt`` and a plain sibling ``x.pcap.txt`` are the SAME file, so
        # an exact-string check would let a derivative silently clobber (or be
        # clobbered by) that sibling and misattribute the manifest. Fold case for
        # the collision test but keep ``desired``'s original case for the output
        # name. On case-sensitive filesystems this is merely conservative (it may
        # relocate a derivative that would not truly collide) — safe either way.
        taken = {r.casefold() for r in reserved_rels}
        taken |= {r.casefold() for r in claimed_out_rels}
        if desired.casefold() not in taken:
            return desired
        i = 1
        while f"{desired}.dup{i}".casefold() in taken:
            i += 1
        return f"{desired}.dup{i}"

    def _scrub(chunk_rel: str, text: str) -> tuple[str, int]:
        """The closure handed to every format handler: run the run's detectors/
        amap/allowlist over ``text`` and return (scrubbed_text, count). Handlers
        never import the engine or touch the AliasMap directly."""
        new_text, reps = tokenize(text, detectors, amap, allowlist_cf,
                                  file=chunk_rel, style=style)
        return new_text, len(reps)

    for path, rel, size in candidates:
        stats.files_total += 1
        out_path = (dst / rel) if dst is not None else None

        if size > max_bytes:
            _copy_through(rel, "oversize",
                          f"{rel}: {size} bytes > max ({max_bytes}); copied unprocessed")
            files_done += 1
            bytes_done_total += size
            _emit(rel)
            continue

        # Format extraction: turn a supported binary (pcap/archive/office/
        # sqlite) into scrubbed text/repacked output, BEFORE the plain
        # copy-through. On ExtractError (corrupt/encrypted/guard tripped) fall
        # back to the exact old behaviour: copy the original through + flag.
        # The handler is responsible for deleting any partial derivative before
        # raising, so the fallback never leaves a half-written output behind.
        handler = get_handler(path.suffix) if extract_enabled else None
        if handler is not None and handler.name not in extract_disable:
            # STAGE the handler's output in a private temp dir under DST rather
            # than letting it write ``dst/rel`` (+suffix) directly. A derivative's
            # collision-resolved name is only known AFTER the handler reports its
            # ``out_rel``; if the handler wrote the natural name first, then on a
            # case-INSENSITIVE filesystem it would already have truncated a
            # case-differing sibling (e.g. a plain ``X.PCAP.TXT``) that sorted
            # first — the post-write relocation cannot undo that. Staging lets us
            # place the single produced file onto the resolved-unique path ourselves
            # (an atomic same-filesystem rename), never touching the sibling.
            stage_dir: Path | None = None
            if write and dst is not None:
                dst.mkdir(parents=True, exist_ok=True)
                stage_dir = Path(tempfile.mkdtemp(
                    dir=str(dst), prefix=".piiscrub-stage-"))
            stage_out_path = (stage_dir / Path(rel).name) if stage_dir else None
            placement_error: OSError | None = None
            outcome = None
            try:
                try:
                    outcome = handler.process(path, rel, stage_out_path, _scrub,
                                              write=write, limits=handler_limits)
                except ExtractError as e:
                    if handler.name == "structured":
                        # A structured source (.csv/.json/.jsonl) IS text: fail
                        # open to the plain TEXT scrub path below — regex-on-
                        # text is the correct degraded mode — never to
                        # copy-through with raw PII. Re-raise to the outer
                        # handler so the name-resolution/placement bookkeeping
                        # is skipped; the stage dir (holding no placed output)
                        # is discarded in ``finally``, preserving the
                        # no-partial-derivative contract.
                        raise
                    _copy_through(
                        rel, "binary",
                        f"{rel}: binary type, copied unprocessed (may contain PII)"
                        + _capture_export_hint(path.suffix)
                        + f" — extraction skipped: {e}",
                    )
                    files_done += 1
                    bytes_done_total += size
                    _emit(rel)
                    continue

                # Resolve the final output name. A derivative whose name collides
                # (case-insensitively) with a real source file or an earlier
                # derivative is uniquified so neither file is lost and the manifest
                # attributes each output to the right source. A repack keeps its
                # own rel (equal to a source path, so it cannot collide) — and so
                # does an in-format derivative whose out_rel EQUALS its source rel
                # (structured csv/json/jsonl): its only "collision" would be with
                # itself in reserved_rels, and the source is not written when it
                # is extracted.
                # Out-format re-shaping applies only to scrubbed TEXT derivatives
                # from pcap/office/sqlite (``.txt``). A pcap derivative groups per
                # packet; office/sqlite per line. Office .xlsx (.csv derivative),
                # the structured handler (in-format csv/json/jsonl), and archive
                # repacks are all left exactly as the handler wrote them — no
                # double-wrapping (design #4/#5).
                reshape = (
                    write and out_format != "text"
                    and outcome.kind == "derivative"
                    and handler.name in ("pcap", "office", "sqlite")
                    and outcome.out_rel.endswith(".txt"))
                desired_out_rel = (
                    outcome.out_rel[:-len(".txt")] + "." + out_format
                    if reshape else outcome.out_rel)

                out_rel = desired_out_rel
                if outcome.kind == "derivative" and out_rel != rel:
                    out_rel = _unique_out_rel(desired_out_rel)
                    if out_rel != desired_out_rel:
                        stats.warnings.append(
                            f"{rel}: derivative {desired_out_rel!r} collides with "
                            f"an existing file; written as {out_rel!r} instead")

                # Move the handler's single staged output onto the resolved path
                # (or re-shape it there, for csv/jsonl text derivatives).
                if stage_dir is not None and dst is not None:
                    produced = sorted(
                        p for p in stage_dir.rglob("*") if p.is_file())
                    if produced:
                        final = dst / out_rel
                        try:
                            final.parent.mkdir(parents=True, exist_ok=True)
                            if reshape:
                                staged_text = produced[0].read_text(
                                    encoding="utf-8")
                                _reshape_text(
                                    staged_text, rel, final, out_format,
                                    per_packet=(handler.name == "pcap"))
                            else:
                                os.replace(produced[0], final)
                        except OSError as e:
                            # e.g. ENAMETOOLONG on the resolved output name: fail
                            # OPEN to copy-through + flag (the staged file is
                            # discarded with the stage dir in ``finally``).
                            placement_error = e
                if placement_error is None and outcome.kind == "derivative":
                    claimed_out_rels.add(out_rel)
            except ExtractError as e:
                # Only the structured handler re-raises to here (see above):
                # record the reason and drop into the plain text scrub path
                # below for this file — these are text files, so the degraded
                # mode is a normal regex-on-text scrub, never copy-through
                # with raw PII.
                outcome = None
                stats.warnings.append(
                    f"{rel}: structured parse failed; scrubbed as plain "
                    f"text — {e}")
            finally:
                if stage_dir is not None:
                    shutil.rmtree(stage_dir, ignore_errors=True)

            if outcome is not None:
                if placement_error is not None:
                    _copy_through(
                        rel, "binary",
                        f"{rel}: binary type, copied unprocessed (may contain PII)"
                        + _capture_export_hint(path.suffix)
                        + f" — extraction skipped: could not place output: "
                        f"{placement_error}",
                    )
                    files_done += 1
                    bytes_done_total += size
                    _emit(rel)
                    continue

                stats.extracted.append(ExtractRecord(
                    rel=rel, out_rel=out_rel, kind=outcome.kind,
                    replacements=outcome.replacements,
                    members_processed=outcome.members_processed,
                    members_copied=outcome.members_copied,
                ))
                stats.per_file.append(FileStat(
                    rel, "extracted", replacements=outcome.replacements,
                    out_rel=out_rel))
                stats.files_extracted += 1
                stats.replacements += outcome.replacements
                for w in outcome.warnings:
                    stats.warnings.append(f"{rel}: {w}")
                files_done += 1
                bytes_done_total += size
                _emit(rel)
                continue
            # ``outcome is None``: the structured handler failed open. Fall
            # through to the normal text path (.csv/.json/.jsonl are not in
            # BINARY_EXTS and decode as text), which scrubs and writes
            # ``dst/rel`` itself.

        if path.suffix.lower() in BINARY_EXTS:
            _copy_through(rel, "binary",
                          f"{rel}: binary type, copied unprocessed (may contain PII)"
                          + _capture_export_hint(path.suffix))
            files_done += 1
            bytes_done_total += size
            _emit(rel)
            continue

        if size > stream_threshold:
            # Detect encoding robustly (small probe window, FIX 2), then stream
            # incrementally.
            with open(path, "rb") as fh:
                head = fh.read(READ_BLOCK)
            enc = detect_stream_encoding(head)
            if enc is None:
                _copy_through(rel, "undecodable",
                              f"{rel}: not text-decodable, copied unprocessed (may contain PII)")
                files_done += 1
                bytes_done_total += size
                _emit(rel)
                continue
            # Reshaped streaming output goes to a suffixed csv/jsonl name; the
            # aliases produced are identical to a text-mode run (only the write
            # shape differs). scan (write=False) writes nothing → no reshape.
            stream_out_rel = rel
            stream_out_path = out_path
            if write and out_format != "text" and dst is not None:
                stream_out_rel = _unique_out_rel(rel + "." + out_format)
                claimed_out_rels.add(stream_out_rel)
                stream_out_path = dst / stream_out_rel
            try:
                n = _stream_file(
                    path, stream_out_path, rel, detectors, amap, allowlist_cf, enc,
                    write, files_done=files_done, files_total=files_total,
                    bytes_total=bytes_total, bytes_base=bytes_done_total,
                    progress=progress, out_format=out_format, style=style,
                )
            except _UndecodableStream:
                # FIX 1: invalid bytes appeared in a later block. _stream_file
                # has already deleted any partial output; fall back to
                # copy-through-as-undecodable to match whole-file semantics.
                _copy_through(rel, "undecodable",
                              f"{rel}: not text-decodable (invalid bytes mid-stream), "
                              f"copied unprocessed (may contain PII)")
                files_done += 1
                bytes_done_total += size
                _emit(rel)
                continue
            if post_pass is not None:
                warnings.warn(
                    f"{rel}: streamed (> {stream_threshold} bytes); LLM second "
                    f"pass skipped for this file (regex-only)",
                    RuntimeWarning, stacklevel=2,
                )
                stats.warnings.append(
                    f"{rel}: streamed huge file; LLM second pass skipped (regex-only)"
                )
            fs = FileStat(rel, "processed", encoding=enc, replacements=n)
            if stream_out_rel != rel:
                fs.out_rel = stream_out_rel
            stats.per_file.append(fs)
            stats.files_processed += 1
            stats.replacements += n
            files_done += 1
            bytes_done_total += size
            # No extra _emit here: _stream_file's last per-chunk event already
            # reported cumulative bytes; emit one completion event carrying the
            # incremented files_done (FIX 5: no duplicate, files_done advances).
            _emit(rel)
            continue

        raw = path.read_bytes()
        decoded = decode_bytes(raw)
        if decoded is None:
            _copy_through(rel, "undecodable",
                          f"{rel}: not text-decodable, copied unprocessed (may contain PII)")
            files_done += 1
            bytes_done_total += size
            _emit(rel)
            continue

        text, enc = decoded
        new_text, reps = tokenize(text, detectors, amap, allowlist_cf, file=rel,
                                  style=style)
        rep_count = len(reps)
        # Optional second pass: runs on the ALREADY-STRIPPED text (``new_text``),
        # never on raw ``text``. Adds extra aliases via the shared amap.
        if post_pass is not None:
            new_text, extra = post_pass(rel, new_text)
            rep_count += extra
        fs = FileStat(rel, "processed", encoding=enc, replacements=rep_count)
        if write and out_path is not None:
            if out_format == "text":
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, "w", encoding=enc, newline="") as fh:
                    fh.write(new_text)
            else:
                # Re-shape the scrubbed text into per-line csv/jsonl records under
                # a suffixed name (x.log -> x.log.jsonl); the original mirror name
                # is not written.
                reshaped_rel = _unique_out_rel(rel + "." + out_format)
                claimed_out_rels.add(reshaped_rel)
                fs.out_rel = reshaped_rel
                _reshape_text(new_text, rel, dst / reshaped_rel, out_format,
                              per_packet=False)
        stats.per_file.append(fs)
        stats.files_processed += 1
        stats.replacements += rep_count
        files_done += 1
        bytes_done_total += size
        _emit(rel)

    return stats
