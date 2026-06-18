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
import fnmatch
import shutil
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .engine import AliasMap, tokenize, tokenize_segment
from .detectors import Detector
from .progress import ProgressCallback, ProgressEvent

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


@dataclass
class FileStat:
    rel: str
    status: str           # "processed" | "binary" | "undecodable" | "oversize"
    encoding: str = ""
    replacements: int = 0


@dataclass
class RunStats:
    files_total: int = 0
    files_processed: int = 0
    files_copied: int = 0       # binary / undecodable / oversize passthrough
    replacements: int = 0
    per_file: list[FileStat] = field(default_factory=list)
    skipped: list[FileStat] = field(default_factory=list)
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
    try:
        if write and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            # newline="" preserves line endings exactly, like whole-file write.
            fh = open(out_path, "w", encoding=enc, newline="")
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
                        safe_end=safe_end,
                    )
                    if fh is not None:
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
            )
            if fh is not None:
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
    """
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

        if path.suffix.lower() in BINARY_EXTS:
            _copy_through(rel, "binary",
                          f"{rel}: binary type, copied unprocessed (may contain PII)")
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
            try:
                n = _stream_file(
                    path, out_path, rel, detectors, amap, allowlist_cf, enc, write,
                    files_done=files_done, files_total=files_total,
                    bytes_total=bytes_total, bytes_base=bytes_done_total,
                    progress=progress,
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
        new_text, reps = tokenize(text, detectors, amap, allowlist_cf, file=rel)
        rep_count = len(reps)
        # Optional second pass: runs on the ALREADY-STRIPPED text (``new_text``),
        # never on raw ``text``. Adds extra aliases via the shared amap.
        if post_pass is not None:
            new_text, extra = post_pass(rel, new_text)
            rep_count += extra
        fs = FileStat(rel, "processed", encoding=enc, replacements=rep_count)
        stats.per_file.append(fs)
        stats.files_processed += 1
        stats.replacements += rep_count
        if write and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding=enc, newline="") as fh:
                fh.write(new_text)
        files_done += 1
        bytes_done_total += size
        _emit(rel)

    return stats
