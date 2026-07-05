"""zip / tar(.gz/.bz2/.xz) / tgz / gz / bz2 / xz — recurse + repack same format.

An archive is turned back into an archive of the SAME format and (for tar/zip)
the SAME member order, with every member rewritten by the same per-file decision
tree the walker applies at the top level:

* text member (``decode_bytes`` succeeds)  -> scrubbed through the ``scrub``
  closure and written back under its own name.
* supported-binary member (a suffix some handler owns: ``.pcap``, a nested
  ``.zip``, ``.docx``, ``.db`` …) -> delegated to that handler via the registry,
  depth-capped; its derivative/repacked output is stored in place. If the nested
  handler raises :class:`ExtractError` (not implemented, corrupt, too deep, …)
  the member is copied in unchanged + flagged, exactly like the top level.
* unknown-binary member -> copied into the repack unchanged + flagged.

Single-file ``.gz``/``.bz2``/``.xz`` (not ``.tar.*``) are treated as one member:
text inner content is scrubbed and recompressed to the same format (a repack);
a binary inner is delegated to a nested handler when one claims its suffix
(e.g. ``x.pcap.gz`` -> pcap dissection -> ``x.pcap.gz.txt`` derivative) and
otherwise raises :class:`ExtractError` (whole file copy+flag).

Guards (all -> :class:`ExtractError`, i.e. copy-through+flag of the WHOLE
archive, except member-name violations which skip only the offending member):

* member names that are absolute or contain a ``..`` component are skipped and
  flagged (never written into the repack — a repacked path-traversal entry would
  re-arm the exploit on extraction);
* total decompressed bytes across the archive are capped by
  ``limits.max_out_bytes`` (checked against each member's *declared* size before
  it is read, so a zip/tar bomb never expands into memory);
* member count is capped by ``limits.max_members``;
* nesting is capped by ``limits.max_depth`` (each recursion spends one level);
* an encrypted zip member fails the WHOLE archive (we refuse to emit a partial
  repack of an archive we cannot fully read).

Every write goes to a sibling ``*.part`` temp that is atomically renamed onto the
final output only after the whole archive is built, so an :class:`ExtractError`
mid-build never leaves a half-written derivative behind (the fail-open invariant).

Stdlib only.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Iterator

from . import get_handler, register
from .base import ExtractError, ExtractLimits, ExtractOutcome, ScrubFn


# ---------------------------------------------------------------------------
# Format classification (by full name, so ``x.tar.gz`` reads as a tar and
# ``x.gz`` as a single compressed file even though both have suffix ``.gz``).

def _classify(name: str) -> tuple[str, str]:
    """Return ``(kind, comp)`` where kind is ``"zip"`` | ``"tar"`` | ``"single"``
    and comp is ``""`` | ``"gz"`` | ``"bz2"`` | ``"xz"`` (the codec to read/write).
    Raises :class:`ExtractError` for a name this handler does not recognise."""
    low = name.lower()
    if low.endswith(".zip"):
        return "zip", ""
    if low.endswith(".tar.gz") or low.endswith(".tgz"):
        return "tar", "gz"
    if low.endswith(".tar.bz2") or low.endswith(".tbz2") or low.endswith(".tbz"):
        return "tar", "bz2"
    if low.endswith(".tar.xz") or low.endswith(".txz"):
        return "tar", "xz"
    if low.endswith(".tar"):
        return "tar", ""
    if low.endswith(".gz"):
        return "single", "gz"
    if low.endswith(".bz2"):
        return "single", "bz2"
    if low.endswith(".xz"):
        return "single", "xz"
    raise ExtractError(f"unrecognised archive suffix: {name!r}")


def _strip_comp_suffix(name: str) -> str:
    """Drop a trailing ``.gz``/``.bz2``/``.xz`` to recover the inner file name."""
    low = name.lower()
    for suf in (".gz", ".bz2", ".xz"):
        if low.endswith(suf):
            return name[: -len(suf)]
    return name


def _unique_member_name(name: str, used: set[str]) -> str:
    """Return ``name`` if free within this repack, else a ``.dupN`` variant.

    A member's rewritten name can collide with another member's (e.g. a repack
    of both ``x.pcap`` -> ``x.pcap.txt`` and a sibling plain ``x.pcap.txt``); two
    entries with one name would silently drop content on extraction, so the
    second claimant is renamed instead."""
    if name not in used:
        return name
    i = 1
    while f"{name}.dup{i}" in used:
        i += 1
    return f"{name}.dup{i}"


def _bad_name(name: str) -> bool:
    """True if a member name is absolute or escapes the archive root (``..``).

    Such names are path-traversal hazards: writing them back into the repack (or
    letting a downstream tool extract them) would place files outside the target
    tree. We skip + flag them rather than repack them.
    """
    if not name:
        return True
    norm = name.replace("\\", "/")
    if norm.startswith("/"):    # POSIX-absolute, or UNC (``\\host`` -> ``//host``)
        return True
    # Windows drive-absolute: an ALPHA drive letter, a colon, then a separator
    # (``C:\...`` -> ``C:/...``) or the bare 2-char drive spec (``C:``). Requiring
    # the letter + separator avoids misclassifying a POSIX-legal member name that
    # merely has a colon at index 1 (e.g. ``a:notes.txt`` or ``t: results.log``),
    # which would silently drop a harmless member from the repack.
    if (len(norm) >= 2 and norm[0].isalpha() and norm[1] == ":"
            and (len(norm) == 2 or norm[2] == "/")):
        return True
    return ".." in PurePosixPath(norm).parts


# ---------------------------------------------------------------------------
# Single-stream (de)compression helpers.

def _decompress_capped(raw: bytes, comp: str, cap: int) -> bytes:
    """Decompress a single ``.gz``/``.bz2``/``.xz`` stream, refusing to expand
    past ``cap`` bytes (bomb guard — we read only ``cap + 1`` decompressed bytes
    and raise if the stream is bigger)."""
    bio = io.BytesIO(raw)
    if comp == "gz":
        fh = gzip.open(bio, "rb")
    elif comp == "bz2":
        fh = bz2.open(bio, "rb")
    elif comp == "xz":
        fh = lzma.open(bio, "rb")
    else:  # pragma: no cover - _classify never yields another comp here
        raise ExtractError(f"unsupported single-file codec: {comp!r}")
    with fh:
        data = fh.read(cap + 1)
    if len(data) > cap:
        raise ExtractError(f"decompressed size exceeds max_out_bytes ({cap})")
    return data


def _compress(data: bytes, comp: str) -> bytes:
    if comp == "gz":
        return gzip.compress(data, mtime=0)  # mtime=0 -> deterministic output
    if comp == "bz2":
        return bz2.compress(data)
    if comp == "xz":
        return lzma.compress(data)
    raise ExtractError(f"unsupported single-file codec: {comp!r}")  # pragma: no cover


def _atomic_write(dest: Path, data: bytes) -> None:
    """Write ``data`` to ``dest`` via a sibling ``*.part`` temp + rename, deleting
    the temp on any failure so no partial output is left behind."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), suffix=".part")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# ---------------------------------------------------------------------------
# Nested-handler delegation (a supported-binary member inside an archive).

def _run_nested(
    handler,
    name: str,
    data: bytes,
    member_rel: str,
    scrub: ScrubFn,
    nested_limits: ExtractLimits,
    write: bool,
) -> tuple[str, bytes | None, str, int]:
    """Materialise a member's bytes to a temp file, run ``handler.process`` on
    it, and return ``(out_name, out_data | None, kind, replacements)``.

    ``out_name`` is the member's own name plus whatever suffix the handler
    appended for a derivative (``""`` for a repack). In ``write`` mode the
    handler's single output file is read back into ``out_data``; in scan mode
    ``out_data`` is None (nothing was written) but ``scrub`` was still driven so
    the AliasMap/report reflect what a strip would do. Any
    :class:`ExtractError` the handler raises propagates to the caller, which
    turns it into a copy-through of this member.
    """
    base = Path(name).name
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        in_dir = tdp / "in"
        in_dir.mkdir()
        in_path = in_dir / base
        in_path.write_bytes(data)
        if write:
            out_dir = tdp / "out"
            out_dir.mkdir()
            out_path: Path | None = out_dir / base
        else:
            out_dir = None
            out_path = None
        outcome = handler.process(in_path, member_rel, out_path, scrub,
                                  write=write, limits=nested_limits)
        if write and out_dir is not None:
            produced = [p for p in out_dir.rglob("*") if p.is_file()]
            if not produced:
                raise ExtractError("nested handler produced no output")
            wf = produced[0]
            out_data = wf.read_bytes()
            deriv_suffix = wf.name[len(base):]
            return name + deriv_suffix, out_data, outcome.kind, outcome.replacements
        # scan: derive the suffix from the handler's reported out_rel.
        deriv_suffix = (outcome.out_rel[len(member_rel):]
                        if outcome.out_rel.startswith(member_rel) else "")
        return name + deriv_suffix, None, outcome.kind, outcome.replacements


def _handle_member(
    name: str,
    data: bytes,
    arch_rel: str,
    scrub: ScrubFn,
    limits: ExtractLimits,
    write: bool,
    remaining_budget: int,
) -> tuple[str, bytes | None, bool, bool, int, list[str], int]:
    """Apply the per-file decision tree to one archive member.

    Returns ``(out_name, out_data | None, processed, copied, replacements,
    warnings, out_size)``. ``out_data`` is None in scan mode. ``processed`` marks
    a member scrubbed as text or successfully nested-extracted; ``copied`` marks a
    binary member carried through unchanged + flagged. ``out_size`` is the byte
    length of the output this member contributes to the repack (a nested
    handler's derivative can be much LARGER than the raw member — a pcap
    dissection expands ~4x); the caller debits it from the archive's running
    ``max_out_bytes`` budget so total expanded text stays bounded (see the call
    sites). In scan mode the nested-handler output size is not materialised, so
    ``out_size`` is 0 for that path (nothing is written; only the in-memory
    per-member budget the handler already enforces applies).

    ``remaining_budget`` is what is left of the source file's ``max_out_bytes``
    after this archive's members read so far; a nested handler is capped to it so
    total expanded text stays bounded ACROSS nesting, not reset per member.
    """
    from ..walker import BINARY_EXTS, decode_bytes  # deferred: avoids import cycle

    member_rel = f"{arch_rel}!{name}"
    suffix = Path(name).suffix.lower()
    handler = get_handler(suffix)
    # Honor the run's per-format disable set for members exactly as the walker
    # does for top-level files: a disabled extractor's member is copied through
    # unchanged + flagged (never silently turned into a derivative), so the
    # original binary member survives the repack.
    if handler is not None and handler.name in limits.disable:
        handler = None

    if handler is not None:
        nested_limits = ExtractLimits(
            max_out_bytes=max(0, remaining_budget),
            max_depth=limits.max_depth - 1,
            max_members=limits.max_members,
            disable=limits.disable,
        )
        try:
            out_name, out_data, _kind, reps = _run_nested(
                handler, name, data, member_rel, scrub, nested_limits, write)
        except ExtractError as e:
            # Fail-open per member: copy the binary in unchanged and flag it.
            return (name, data if write else None, False, True, 0,
                    [f"member {name!r}: nested extraction skipped ({e}); "
                     f"copied unchanged (may contain PII)"],
                    len(data))
        out_size = len(out_data) if out_data is not None else 0
        return out_name, out_data, True, False, reps, [], out_size

    if suffix in BINARY_EXTS or get_handler(suffix) is not None:
        # ``get_handler(...) is not None`` catches a DISABLED handler's suffix
        # that is not in BINARY_EXTS (e.g. ``.sqlite3``): still binary, copy+flag.
        return (name, data if write else None, False, True, 0,
                [f"member {name!r}: binary type, copied unchanged (may contain PII)"],
                len(data))

    decoded = decode_bytes(data)
    if decoded is None:
        return (name, data if write else None, False, True, 0,
                [f"member {name!r}: not text-decodable, copied unchanged (may contain PII)"],
                len(data))

    text, enc = decoded
    scrubbed, reps = scrub(member_rel, text)
    encoded = scrubbed.encode(enc)
    return name, (encoded if write else None), True, False, reps, [], len(encoded)


# ---------------------------------------------------------------------------
# Per-format processing.

def _process_zip(path: Path, rel: str, out_path: Path | None,
                 scrub: ScrubFn, write: bool, limits: ExtractLimits) -> ExtractOutcome:
    try:
        zin = zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, OSError) as e:
        raise ExtractError(f"cannot open zip: {e}") from e

    total_reps = mproc = mcopied = 0
    warnings: list[str] = []
    running = 0
    members_seen = 0
    used_names: set[str] = set()
    zout = None
    tmp_path: str | None = None
    try:
        infos = zin.infolist()
        # Encrypted zip -> refuse the whole archive (we can't fully read it).
        for info in infos:
            if info.flag_bits & 0x1:
                raise ExtractError("encrypted zip member(s); cannot fully read")

        if write and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=str(out_path.parent), suffix=".part")
            os.close(fd)
            zout = zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED)

        for info in infos:
            name = info.filename
            if _bad_name(name):
                warnings.append(f"member {name!r}: unsafe path, skipped (not written)")
                continue
            if name.endswith("/"):  # directory entry: structural, copy as-is
                if zout is not None:
                    zi = zipfile.ZipInfo(name, date_time=info.date_time)
                    zi.external_attr = info.external_attr
                    zout.writestr(zi, b"")
                continue

            members_seen += 1
            if members_seen > limits.max_members:
                raise ExtractError(f"member count exceeds max_members ({limits.max_members})")
            if running + info.file_size > limits.max_out_bytes:
                raise ExtractError(f"decompressed size exceeds max_out_bytes ({limits.max_out_bytes})")
            try:
                data = zin.read(info)
            except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError) as e:
                # Bad CRC (BadZipFile), broken deflate stream (zlib.error),
                # encrypted member (RuntimeError), or truncated member (EOFError)
                # — fail the whole archive open to copy-through + flag rather than
                # letting a non-ExtractError abort the run.
                raise ExtractError(f"cannot read member {name!r}: {e}") from e
            running += len(data)

            out_name, out_data, processed, copied, reps, warns, out_size = _handle_member(
                name, data, rel, scrub, limits, write,
                limits.max_out_bytes - running)
            # Debit any EXPANSION the member's output added beyond its raw bytes
            # (a nested pcap/office/sqlite derivative is larger than the raw
            # member) so ``running`` tracks total PRODUCED text, not just raw
            # decompressed bytes. Otherwise N expanding members could each grow up
            # to the full remaining budget and the repack would exceed
            # ``max_out_bytes`` by roughly the member count.
            running += max(0, out_size - len(data))
            if running > limits.max_out_bytes:
                raise ExtractError(
                    f"expanded size exceeds max_out_bytes ({limits.max_out_bytes})")
            total_reps += reps
            mproc += int(processed)
            mcopied += int(copied)
            warnings.extend(warns)
            unique = _unique_member_name(out_name, used_names)
            if unique != out_name:
                warnings.append(
                    f"member {out_name!r}: name collides with another member; "
                    f"stored as {unique!r}")
            used_names.add(unique)
            if zout is not None:
                zi = zipfile.ZipInfo(unique, date_time=info.date_time)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, out_data or b"")

        if zout is not None and out_path is not None:
            zout.close()
            zout = None
            os.replace(tmp_path, out_path)
            tmp_path = None
    finally:
        if zout is not None:
            zout.close()
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        zin.close()

    return ExtractOutcome(kind="repack", out_rel=rel, replacements=total_reps,
                          members_processed=mproc, members_copied=mcopied,
                          warnings=warnings)


def _process_tar(path: Path, rel: str, out_path: Path | None, scrub: ScrubFn,
                 write: bool, limits: ExtractLimits, comp: str) -> ExtractOutcome:
    try:
        tin = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError, EOFError, lzma.LZMAError) as e:
        raise ExtractError(f"cannot open tar: {e}") from e

    total_reps = mproc = mcopied = 0
    warnings: list[str] = []
    running = 0
    members_seen = 0
    used_names: set[str] = set()
    tout = None
    tmp_path: str | None = None
    try:
        # A tar truncated/corrupted mid-archive raises tarfile.ReadError from
        # getmembers() (or from a member read below); convert every such
        # structural failure to ExtractError so the walker falls back to
        # copy-through + flag instead of aborting the whole run with a traceback.
        try:
            members = tin.getmembers()
        except (tarfile.TarError, EOFError, OSError, lzma.LZMAError) as e:
            raise ExtractError(f"corrupt tar: {e}") from e
        if write and out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=str(out_path.parent), suffix=".part")
            os.close(fd)
            tout = tarfile.open(tmp_path, "w:" + comp)

        for m in members:
            name = m.name
            if _bad_name(name):
                warnings.append(f"member {name!r}: unsafe path, skipped (not written)")
                continue
            if not m.isfile():
                # Directory / symlink / device / fifo: no file content to scrub;
                # carry the structural entry through unchanged.
                if tout is not None:
                    tout.addfile(m)
                continue

            members_seen += 1
            if members_seen > limits.max_members:
                raise ExtractError(f"member count exceeds max_members ({limits.max_members})")
            if running + m.size > limits.max_out_bytes:
                raise ExtractError(f"decompressed size exceeds max_out_bytes ({limits.max_out_bytes})")
            try:
                src = tin.extractfile(m)
                data = src.read() if src is not None else b""
            except (tarfile.TarError, EOFError, OSError, lzma.LZMAError) as e:
                raise ExtractError(f"corrupt tar member {name!r}: {e}") from e
            running += len(data)

            out_name, out_data, processed, copied, reps, warns, out_size = _handle_member(
                name, data, rel, scrub, limits, write,
                limits.max_out_bytes - running)
            # Debit expansion beyond raw bytes so ``running`` tracks total
            # PRODUCED text (see the zip site for the rationale).
            running += max(0, out_size - len(data))
            if running > limits.max_out_bytes:
                raise ExtractError(
                    f"expanded size exceeds max_out_bytes ({limits.max_out_bytes})")
            total_reps += reps
            mproc += int(processed)
            mcopied += int(copied)
            warnings.extend(warns)
            unique = _unique_member_name(out_name, used_names)
            if unique != out_name:
                warnings.append(
                    f"member {out_name!r}: name collides with another member; "
                    f"stored as {unique!r}")
            used_names.add(unique)
            if tout is not None:
                payload = out_data or b""
                ti = tarfile.TarInfo(unique)
                ti.size = len(payload)
                ti.mtime = m.mtime          # preserve member timestamp
                ti.mode = m.mode
                ti.uid, ti.gid = m.uid, m.gid
                ti.uname, ti.gname = m.uname, m.gname
                ti.type = tarfile.REGTYPE
                tout.addfile(ti, io.BytesIO(payload))

        if tout is not None and out_path is not None:
            tout.close()
            tout = None
            os.replace(tmp_path, out_path)
            tmp_path = None
    finally:
        if tout is not None:
            tout.close()
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        tin.close()

    return ExtractOutcome(kind="repack", out_rel=rel, replacements=total_reps,
                          members_processed=mproc, members_copied=mcopied,
                          warnings=warnings)


def _process_single(path: Path, rel: str, out_path: Path | None, scrub: ScrubFn,
                    write: bool, limits: ExtractLimits, comp: str) -> ExtractOutcome:
    from ..walker import BINARY_EXTS, decode_bytes  # deferred: avoids import cycle

    # Size guard BEFORE reading: a multi-GB compressed file must not be slurped
    # whole into RAM (a MemoryError is not an ExtractError, so the walker would
    # abort the run instead of falling back to copy-through). Cap the raw read at
    # max_out_bytes; a bigger source fails open to copy+flag.
    try:
        if path.stat().st_size > limits.max_out_bytes:
            raise ExtractError(
                f"compressed source exceeds max_out_bytes ({limits.max_out_bytes})")
        raw = path.read_bytes()
    except OSError as e:
        raise ExtractError(f"cannot read compressed source: {e}") from e
    try:
        inner = _decompress_capped(raw, comp, limits.max_out_bytes)
    except (OSError, EOFError, lzma.LZMAError) as e:
        raise ExtractError(f"cannot decompress: {e}") from e

    inner_name = _strip_comp_suffix(path.name)
    inner_suffix = Path(inner_name).suffix.lower()
    handler = get_handler(inner_suffix)
    # Honor the run's per-format disable set (findings: disable ignored for a
    # single-file .gz/.bz2/.xz wrapping a disabled format): a disabled inner
    # handler is treated as an unextractable binary, so the WHOLE compressed
    # file copies through unchanged + flagged (the original binary survives).
    if handler is not None and handler.name in limits.disable:
        handler = None

    if handler is not None:
        nested_limits = ExtractLimits(
            max_out_bytes=max(0, limits.max_out_bytes - len(inner)),
            max_depth=limits.max_depth - 1,
            max_members=limits.max_members,
            disable=limits.disable,
        )
        out_name, out_data, kind, reps = _run_nested(
            handler, inner_name, inner, rel, scrub, nested_limits, write)
        deriv_suffix = out_name[len(inner_name):]
        if kind == "derivative":
            # e.g. x.pcap.gz -> dissect inner x.pcap -> x.pcap.gz.txt (uncompressed).
            final_rel = rel + deriv_suffix
            if write and out_path is not None:
                dest = out_path.parent / (out_path.name + deriv_suffix)
                try:
                    _atomic_write(dest, out_data or b"")
                except OSError as e:
                    # A write failure (e.g. ENAMETOOLONG when out_path.name +
                    # deriv_suffix exceeds NAME_MAX) must not abort the whole run:
                    # _atomic_write already removed its temp, so convert to
                    # ExtractError and the walker copies the original through
                    # under its (shorter) name + flags it.
                    raise ExtractError(f"could not write derivative: {e}") from e
            return ExtractOutcome(kind="derivative", out_rel=final_rel, replacements=reps)
        # Inner was itself an archive: recompress its repack to the same format.
        if write and out_path is not None:
            try:
                _atomic_write(out_path, _compress(out_data or b"", comp))
            except OSError as e:
                raise ExtractError(f"could not write repack: {e}") from e
        return ExtractOutcome(kind="repack", out_rel=rel, replacements=reps)

    if inner_suffix in BINARY_EXTS:
        raise ExtractError("compressed content is binary with no handler")

    decoded = decode_bytes(inner)
    if decoded is None:
        raise ExtractError("compressed content is not text-decodable")
    text, enc = decoded
    scrubbed, reps = scrub(f"{rel}!inner", text)
    if write and out_path is not None:
        try:
            _atomic_write(out_path, _compress(scrubbed.encode(enc), comp))
        except OSError as e:
            raise ExtractError(f"could not write repack: {e}") from e
    return ExtractOutcome(kind="repack", out_rel=rel, replacements=reps)


class _ArchiveHandler:
    """Recurse into an archive, scrub text members, repack the same format.

    Kind is ``"repack"`` for real archives (zip/tar and their compressed
    variants): the output keeps the source name and format with members
    scrubbed (text), nested-extracted (supported binary), or copied in unchanged
    + flagged (unknown binary). A single-file ``.gz``/``.bz2``/``.xz`` is a
    ``"repack"`` when its inner content is text, or a ``"derivative"`` when a
    nested handler turns a binary inner into text (e.g. ``x.pcap.gz.txt``).
    """

    name = "archive"
    suffixes = (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz")

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
        if limits.max_depth < 1:
            raise ExtractError("archive nesting exceeds max_depth")
        kind, comp = _classify(path.name)
        if kind == "zip":
            return _process_zip(path, rel, out_path, scrub, write, limits)
        if kind == "tar":
            return _process_tar(path, rel, out_path, scrub, write, limits, comp)
        return _process_single(path, rel, out_path, scrub, write, limits, comp)


# ---------------------------------------------------------------------------
# Verify support: yield the decoded text of every scrubbable member of a
# repacked archive in DST (recursing into nested archives, depth-capped) so
# audit.verify_tree can re-scan them for residual PII. Binary members that were
# copied+flagged are intentionally skipped (they were reported, not scrubbed).

# Sentinel yielded in place of member text when archive verification stops early
# because a cap (max_members / max_out_bytes) tripped. verify_tree turns it into
# a finding so a partially-scanned archive can never silently pass as clean (the
# fail-closed guarantee would otherwise be hollow for exactly the archives that
# outgrew a cap — e.g. a repack whose scrubbed text expanded past max_out_bytes).
SCAN_TRUNCATED = object()


def iter_text_members(path: Path, rel: str, limits: ExtractLimits) -> Iterator[tuple[str, object]]:
    """Yield ``(display_rel, text)`` for each text member of the archive at
    ``path``. ``display_rel`` uses ``archive.zip!member/path`` notation (and
    nests further for archives inside archives). Best-effort: an unreadable or
    encrypted archive yields nothing (it was copied+flagged, not repacked)."""
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > limits.max_out_bytes:
        # Size guard BEFORE slurping the archive into RAM. A huge copied-through
        # archive in DST (e.g. a 20 GB zip that tripped max_out_bytes on strip and
        # was copied+flagged) would otherwise be read whole and MemoryError —
        # which is NOT an OSError — would abort the entire verify/strip run with a
        # traceback. Fail CLOSED: an archive too big to scan under the cap yields
        # SCAN_TRUNCATED so it can never pass verify as clean without a byte
        # scanned. (Nested archives are already bounded because their bytes come
        # from members debited against max_out_bytes in _iter_text_zip/_tar.)
        yield f"{rel}!<scan truncated at cap>", SCAN_TRUNCATED
        return
    try:
        data = path.read_bytes()
    except OSError:
        return
    yield from _iter_text(data, path.name, rel, limits, limits.max_depth)


def _iter_text(data: bytes, name: str, rel: str, limits: ExtractLimits,
               depth: int) -> Iterator[tuple[str, object]]:
    if depth < 1:
        return
    try:
        kind, comp = _classify(name)
    except ExtractError:
        return
    try:
        if kind == "zip":
            yield from _iter_text_zip(data, rel, limits, depth)
        elif kind == "tar":
            yield from _iter_text_tar(data, rel, limits, depth)
        else:
            yield from _iter_text_single(data, name, comp, rel, limits, depth)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError,
            lzma.LZMAError, RuntimeError, zlib.error):
        return


def _yield_member_text(name: str, data: bytes, rel: str, limits: ExtractLimits,
                       depth: int) -> Iterator[tuple[str, str]]:
    from ..walker import BINARY_EXTS, decode_bytes  # deferred: avoids import cycle

    member_rel = f"{rel}!{name}"
    suffix = Path(name).suffix.lower()
    handler = get_handler(suffix)
    if handler is not None:
        if handler.name == "archive":
            yield from _iter_text(data, name, member_rel, limits, depth - 1)
        # A non-archive supported-binary appearing raw means its derivative was
        # not produced (copied+flagged); nothing text to re-scan here.
        return
    if suffix in BINARY_EXTS:
        return
    decoded = decode_bytes(data)
    if decoded is None:
        return
    yield member_rel, decoded[0]


def _iter_text_zip(data: bytes, rel: str, limits: ExtractLimits,
                   depth: int) -> Iterator[tuple[str, object]]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        running = 0
        seen = 0
        for info in z.infolist():
            if info.flag_bits & 0x1:
                # Encrypted member: opaque, cannot be read/scanned. Skip ONLY this
                # member and keep scanning the readable ones. Bailing on the whole
                # archive here would make the verdict member-ORDER dependent — an
                # encrypted-first entry would hide a readable plaintext member that
                # still holds raw PII (the copy+flag fallback places the ORIGINAL
                # encrypted zip, plaintext members and all, into DST). Scanning
                # readable members regardless keeps verify deterministic and
                # fail-closed.
                continue
            name = info.filename
            if _bad_name(name) or name.endswith("/"):
                continue
            seen += 1
            if seen > limits.max_members or running + info.file_size > limits.max_out_bytes:
                yield f"{rel}!<scan truncated at cap>", SCAN_TRUNCATED
                return
            try:
                mdata = z.read(info)
            except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError):
                continue
            running += len(mdata)
            yield from _yield_member_text(name, mdata, rel, limits, depth)


def _iter_text_tar(data: bytes, rel: str, limits: ExtractLimits,
                   depth: int) -> Iterator[tuple[str, object]]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
        running = 0
        seen = 0
        for m in t.getmembers():
            if not m.isfile() or _bad_name(m.name):
                continue
            seen += 1
            if seen > limits.max_members or running + m.size > limits.max_out_bytes:
                yield f"{rel}!<scan truncated at cap>", SCAN_TRUNCATED
                return
            src = t.extractfile(m)
            mdata = src.read() if src is not None else b""
            running += len(mdata)
            yield from _yield_member_text(m.name, mdata, rel, limits, depth)


def _iter_text_single(data: bytes, name: str, comp: str, rel: str,
                      limits: ExtractLimits, depth: int) -> Iterator[tuple[str, object]]:
    try:
        inner = _decompress_capped(data, comp, limits.max_out_bytes)
    except ExtractError:
        # The inner stream exceeded max_out_bytes. Fail CLOSED exactly like the
        # zip/tar member paths: a single-file .gz/.bz2/.xz in DST whose inner text
        # is bigger than the cap must NOT silently pass verify as clean without a
        # byte scanned — yield the sentinel so verify_tree records a finding.
        yield f"{rel}!<scan truncated at cap>", SCAN_TRUNCATED
        return
    except (OSError, EOFError, lzma.LZMAError):
        # Corrupt/unreadable stream: it was copied+flagged (not repacked), so
        # there is nothing to re-scan — best-effort, like an unreadable archive.
        return
    yield from _yield_member_text(_strip_comp_suffix(name), inner, rel, limits, depth)


HANDLER = register(_ArchiveHandler())
