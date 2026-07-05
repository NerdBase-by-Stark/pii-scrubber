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


def _bad_name(name: str) -> bool:
    """True if a member name is absolute or escapes the archive root (``..``).

    Such names are path-traversal hazards: writing them back into the repack (or
    letting a downstream tool extract them) would place files outside the target
    tree. We skip + flag them rather than repack them.
    """
    if not name:
        return True
    norm = name.replace("\\", "/")
    if norm.startswith("/"):
        return True
    # Windows drive-absolute (``C:\...``) or UNC (``\\host``).
    if len(norm) >= 2 and norm[1] == ":":
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
) -> tuple[str, bytes | None, bool, bool, int, list[str]]:
    """Apply the per-file decision tree to one archive member.

    Returns ``(out_name, out_data | None, processed, copied, replacements,
    warnings)``. ``out_data`` is None in scan mode. ``processed`` marks a member
    scrubbed as text or successfully nested-extracted; ``copied`` marks a binary
    member carried through unchanged + flagged.
    """
    from ..walker import BINARY_EXTS, decode_bytes  # deferred: avoids import cycle

    member_rel = f"{arch_rel}!{name}"
    suffix = Path(name).suffix.lower()
    handler = get_handler(suffix)

    if handler is not None:
        nested_limits = ExtractLimits(
            max_out_bytes=limits.max_out_bytes,
            max_depth=limits.max_depth - 1,
            max_members=limits.max_members,
        )
        try:
            out_name, out_data, _kind, reps = _run_nested(
                handler, name, data, member_rel, scrub, nested_limits, write)
        except ExtractError as e:
            # Fail-open per member: copy the binary in unchanged and flag it.
            return (name, data if write else None, False, True, 0,
                    [f"member {name!r}: nested extraction skipped ({e}); "
                     f"copied unchanged (may contain PII)"])
        return out_name, out_data, True, False, reps, []

    if suffix in BINARY_EXTS:
        return (name, data if write else None, False, True, 0,
                [f"member {name!r}: binary type, copied unchanged (may contain PII)"])

    decoded = decode_bytes(data)
    if decoded is None:
        return (name, data if write else None, False, True, 0,
                [f"member {name!r}: not text-decodable, copied unchanged (may contain PII)"])

    text, enc = decoded
    scrubbed, reps = scrub(member_rel, text)
    return name, (scrubbed.encode(enc) if write else None), True, False, reps, []


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
            except (RuntimeError, zipfile.BadZipFile) as e:
                raise ExtractError(f"cannot read member {name!r}: {e}") from e
            running += len(data)

            out_name, out_data, processed, copied, reps, warns = _handle_member(
                name, data, rel, scrub, limits, write)
            total_reps += reps
            mproc += int(processed)
            mcopied += int(copied)
            warnings.extend(warns)
            if zout is not None:
                zi = zipfile.ZipInfo(out_name, date_time=info.date_time)
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
    tout = None
    tmp_path: str | None = None
    try:
        members = tin.getmembers()
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
            src = tin.extractfile(m)
            data = src.read() if src is not None else b""
            running += len(data)

            out_name, out_data, processed, copied, reps, warns = _handle_member(
                name, data, rel, scrub, limits, write)
            total_reps += reps
            mproc += int(processed)
            mcopied += int(copied)
            warnings.extend(warns)
            if tout is not None:
                payload = out_data or b""
                ti = tarfile.TarInfo(out_name)
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

    raw = path.read_bytes()
    try:
        inner = _decompress_capped(raw, comp, limits.max_out_bytes)
    except (OSError, EOFError, lzma.LZMAError) as e:
        raise ExtractError(f"cannot decompress: {e}") from e

    inner_name = _strip_comp_suffix(path.name)
    inner_suffix = Path(inner_name).suffix.lower()
    handler = get_handler(inner_suffix)

    if handler is not None:
        nested_limits = ExtractLimits(
            max_out_bytes=limits.max_out_bytes,
            max_depth=limits.max_depth - 1,
            max_members=limits.max_members,
        )
        out_name, out_data, kind, reps = _run_nested(
            handler, inner_name, inner, rel, scrub, nested_limits, write)
        deriv_suffix = out_name[len(inner_name):]
        if kind == "derivative":
            # e.g. x.pcap.gz -> dissect inner x.pcap -> x.pcap.gz.txt (uncompressed).
            final_rel = rel + deriv_suffix
            if write and out_path is not None:
                dest = out_path.parent / (out_path.name + deriv_suffix)
                _atomic_write(dest, out_data or b"")
            return ExtractOutcome(kind="derivative", out_rel=final_rel, replacements=reps)
        # Inner was itself an archive: recompress its repack to the same format.
        if write and out_path is not None:
            _atomic_write(out_path, _compress(out_data or b"", comp))
        return ExtractOutcome(kind="repack", out_rel=rel, replacements=reps)

    if inner_suffix in BINARY_EXTS:
        raise ExtractError("compressed content is binary with no handler")

    decoded = decode_bytes(inner)
    if decoded is None:
        raise ExtractError("compressed content is not text-decodable")
    text, enc = decoded
    scrubbed, reps = scrub(f"{rel}!inner", text)
    if write and out_path is not None:
        _atomic_write(out_path, _compress(scrubbed.encode(enc), comp))
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

def iter_text_members(path: Path, rel: str, limits: ExtractLimits) -> Iterator[tuple[str, str]]:
    """Yield ``(display_rel, text)`` for each text member of the archive at
    ``path``. ``display_rel`` uses ``archive.zip!member/path`` notation (and
    nests further for archives inside archives). Best-effort: an unreadable or
    encrypted archive yields nothing (it was copied+flagged, not repacked)."""
    try:
        data = path.read_bytes()
    except OSError:
        return
    yield from _iter_text(data, path.name, rel, limits, limits.max_depth)


def _iter_text(data: bytes, name: str, rel: str, limits: ExtractLimits,
               depth: int) -> Iterator[tuple[str, str]]:
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
            lzma.LZMAError, RuntimeError):
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
                   depth: int) -> Iterator[tuple[str, str]]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        running = 0
        seen = 0
        for info in z.infolist():
            if info.flag_bits & 0x1:  # encrypted -> was copied+flagged, skip archive
                return
            name = info.filename
            if _bad_name(name) or name.endswith("/"):
                continue
            seen += 1
            if seen > limits.max_members or running + info.file_size > limits.max_out_bytes:
                return
            try:
                mdata = z.read(info)
            except (RuntimeError, zipfile.BadZipFile):
                continue
            running += len(mdata)
            yield from _yield_member_text(name, mdata, rel, limits, depth)


def _iter_text_tar(data: bytes, rel: str, limits: ExtractLimits,
                   depth: int) -> Iterator[tuple[str, str]]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
        running = 0
        seen = 0
        for m in t.getmembers():
            if not m.isfile() or _bad_name(m.name):
                continue
            seen += 1
            if seen > limits.max_members or running + m.size > limits.max_out_bytes:
                return
            src = t.extractfile(m)
            mdata = src.read() if src is not None else b""
            running += len(mdata)
            yield from _yield_member_text(m.name, mdata, rel, limits, depth)


def _iter_text_single(data: bytes, name: str, comp: str, rel: str,
                      limits: ExtractLimits, depth: int) -> Iterator[tuple[str, str]]:
    try:
        inner = _decompress_capped(data, comp, limits.max_out_bytes)
    except (OSError, EOFError, lzma.LZMAError, ExtractError):
        return
    yield from _yield_member_text(_strip_comp_suffix(name), inner, rel, limits, depth)


HANDLER = register(_ArchiveHandler())
