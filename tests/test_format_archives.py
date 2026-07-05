"""Tests for the archives format handler (zip / tar(.gz/.bz2/.xz) / tgz /
single-file gz/bz2/xz) and the verify archive-recursion hook.

All fixtures are built programmatically in-test with the stdlib (zipfile /
tarfile / gzip / bz2 / lzma); no binary blobs live in git. The archives handler
turns a supported archive in SRC into a same-format archive in DST whose text
members are scrubbed, whose supported-binary members are delegated to a nested
handler, and whose unknown-binary members are copied in unchanged + flagged.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from pathlib import Path

import pytest

from piiscrub.config import ExtractConfig
from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap
from piiscrub.formats import ExtractError, ExtractLimits, get_handler, register
from piiscrub.formats.base import ExtractOutcome
from piiscrub.walker import process_tree
from piiscrub import audit


# ----------------------------------------------------------------------
# Helpers.

def _zip_bytes(members: dict[str, bytes | str]) -> bytes:
    """Build a zip in memory. String values are stored utf-8, bytes as-is."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data if isinstance(data, bytes) else data.encode("utf-8"))
    return buf.getvalue()


def _targz_bytes(members: dict[str, bytes | str], comp: str = "gz",
                 mtime: int = 111) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:" + comp) as t:
        for name, data in members.items():
            raw = data if isinstance(data, bytes) else data.encode("utf-8")
            ti = tarfile.TarInfo(name)
            ti.size = len(raw)
            ti.mtime = mtime
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(raw))
    return buf.getvalue()


def _encrypted_zip_bytes() -> bytes:
    """Build a normal zip then flip the general-purpose 'encrypted' bit (0x01)
    in every local + central-directory header. The stdlib cannot WRITE an
    encrypted zip, but the handler only needs to *detect* the flag to refuse the
    archive, and flipping the bit is enough to exercise that path."""
    data = bytearray(_zip_bytes({"secret.log": "ip 10.0.0.9"}))
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = 0
        while (i := data.find(sig, i)) >= 0:
            data[i + off] |= 0x01
            i += 4
    return bytes(data)


def _run(src: Path, dst: Path | None, *, write: bool = True, extract=None):
    return process_tree(src, dst, build_active(), AliasMap(), max_bytes=10 ** 9,
                        write=write, exclude_dirs=set(), extract=extract)


# ----------------------------------------------------------------------
# Registration.

def test_handler_registered_for_all_suffixes():
    for suffix in (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"):
        h = get_handler(suffix)
        assert h is not None and h.name == "archive"


# ----------------------------------------------------------------------
# zip round-trip: text scrubbed, binary copied+flagged, stdlib-readable.

def test_zip_roundtrip_text_scrubbed_binary_copied(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    png = b"\x89PNG\r\n\x1a\n raw 10.0.0.9 bytes"
    (src / "logs.zip").write_bytes(_zip_bytes({
        "logs/app.log": "user a@b.com ip 10.0.0.9\n",
        "pic.png": png,
    }))
    stats = _run(src, dst)

    assert stats.files_extracted == 1 and stats.files_copied == 0
    rec = stats.extracted[0]
    assert rec.kind == "repack" and rec.rel == "logs.zip" and rec.out_rel == "logs.zip"
    assert rec.members_processed == 1 and rec.members_copied == 1
    # original NOT copied into DST as a plain binary; the repack shares the name.
    with zipfile.ZipFile(dst / "logs.zip") as z:      # stdlib-readable
        assert z.namelist() == ["logs/app.log", "pic.png"]   # source order kept
        body = z.read("logs/app.log").decode("utf-8")
        assert "a@b.com" not in body and "10.0.0.9" not in body
        assert "<EMAIL_1>" in body and "<IP_1>" in body
        assert z.read("pic.png") == png               # binary member untouched
    # the copied binary member is flagged in the run warnings (no raw PII in it)
    assert any("pic.png" in w and "copied unchanged" in w for w in stats.warnings)


def test_tar_gz_roundtrip_preserves_mtime_and_order(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "bundle.tar.gz").write_bytes(_targz_bytes({
        "a/first.log": "mail c@d.com host 192.168.1.5\n",
        "a/second.log": "ip 10.1.2.3\n",
    }, mtime=1234567))
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    with tarfile.open(dst / "bundle.tar.gz") as t:
        assert t.getnames() == ["a/first.log", "a/second.log"]   # order kept
        m = t.getmember("a/first.log")
        assert m.mtime == 1234567                                # timestamp kept
        body = t.extractfile("a/first.log").read().decode("utf-8")
        assert "c@d.com" not in body and "192.168.1.5" not in body
        assert "<EMAIL_1>" in body and "<IP_1>" in body


@pytest.mark.parametrize("comp,mode", [("bz2", "r:bz2"), ("xz", "r:xz")])
def test_tar_bz2_and_xz_roundtrip(tmp_path: Path, comp: str, mode: str):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    name = f"pack.tar.{comp}"
    (src / name).write_bytes(_targz_bytes({"log.txt": "ip 8.8.8.8\n"}, comp=comp))
    stats = _run(src, dst)
    assert stats.files_extracted == 1
    with tarfile.open(dst / name, mode) as t:
        body = t.extractfile("log.txt").read().decode("utf-8")
        assert "8.8.8.8" not in body and "<IP_1>" in body


def test_tgz_extension_treated_as_tar_gz(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "arch.tgz").write_bytes(_targz_bytes({"a.log": "ip 10.0.0.9\n"}))
    _run(src, dst)
    with tarfile.open(dst / "arch.tgz") as t:
        assert "<IP_1>" in t.extractfile("a.log").read().decode("utf-8")


# ----------------------------------------------------------------------
# Nested archives (depth) + shared aliasing.

def test_nested_zip_members_scrubbed(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    inner = _zip_bytes({"deep.log": "ip 10.0.0.7 mail x@y.com\n"})
    (src / "outer.zip").write_bytes(_zip_bytes({"nested.zip": inner}))
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    with zipfile.ZipFile(dst / "outer.zip") as z:
        nz = z.read("nested.zip")
    with zipfile.ZipFile(io.BytesIO(nz)) as z:          # still a valid nested zip
        body = z.read("deep.log").decode("utf-8")
        assert "10.0.0.7" not in body and "x@y.com" not in body
        assert "<IP_1>" in body and "<EMAIL_1>" in body


def test_depth_cap_copies_too_deep_nested_archive_unchanged(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    lvl3 = _zip_bytes({"deep.log": "ip 10.0.0.3\n"})
    lvl2 = _zip_bytes({"l3.zip": lvl3})
    lvl1 = _zip_bytes({"l2.zip": lvl2})
    (src / "l1.zip").write_bytes(lvl1)
    # max_depth=2 -> l1 (budget 2) and l2 (budget 1) recurse; l3 (budget 0) is
    # refused by the nested handler and copied in unchanged, so deep.log is raw.
    stats = _run(src, dst, extract=ExtractConfig(limits=ExtractLimits(max_depth=2)))
    assert stats.files_extracted == 1
    assert stats.replacements == 0     # nothing at depths 1-2 held text
    with zipfile.ZipFile(dst / "l1.zip") as z:
        l2 = z.read("l2.zip")
    with zipfile.ZipFile(io.BytesIO(l2)) as z:
        l3 = z.read("l3.zip")
    with zipfile.ZipFile(io.BytesIO(l3)) as z:
        assert z.read("deep.log") == b"ip 10.0.0.3\n"   # copied unchanged (raw)


def test_same_ip_across_archive_and_plain_log_shares_alias(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "a.log").write_text("ip 10.0.0.9\n", encoding="utf-8")
    (src / "b.zip").write_bytes(_zip_bytes({"inner.log": "ip 10.0.0.9\n"}))
    amap = AliasMap()
    process_tree(src, dst, build_active(), amap, max_bytes=10 ** 9, write=True,
                 exclude_dirs=set())
    # one alias for the shared value -> exactly one IP entry in the map
    ip_aliases = {a for a, m in amap.decode_table().items() if m["category"] == "ipv4"}
    assert len(ip_aliases) == 1
    alias = next(iter(ip_aliases))
    assert alias in (dst / "a.log").read_text()
    with zipfile.ZipFile(dst / "b.zip") as z:
        assert alias in z.read("inner.log").decode("utf-8")


# ----------------------------------------------------------------------
# Guards.

def test_traversal_member_skipped_and_flagged(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "trav.zip").write_bytes(_zip_bytes({
        "../evil.txt": "ip 10.0.0.9",
        "ok.txt": "ip 10.0.0.8",
    }))
    stats = _run(src, dst)
    with zipfile.ZipFile(dst / "trav.zip") as z:
        assert z.namelist() == ["ok.txt"]            # '..' member not repacked
    assert any("../evil.txt" in w and "unsafe path" in w for w in stats.warnings)


def test_absolute_member_skipped(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "abs.zip").write_bytes(_zip_bytes({"/etc/passwd": "ip 10.0.0.9", "ok.log": "x"}))
    _run(src, dst)
    with zipfile.ZipFile(dst / "abs.zip") as z:
        assert "/etc/passwd" not in z.namelist() and "ok.log" in z.namelist()


def test_encrypted_zip_falls_back_to_copy_and_flag(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "enc.zip").write_bytes(_encrypted_zip_bytes())
    stats = _run(src, dst)
    assert stats.files_extracted == 0 and stats.files_copied == 1
    # whole archive copied through byte-for-byte, NOT partially repacked
    assert (dst / "enc.zip").read_bytes() == (src / "enc.zip").read_bytes()
    warn = next(w for w in stats.warnings if "enc.zip" in w)
    assert "encrypted" in warn and "may contain PII" in warn


def test_max_members_cap_trips_extracterror_copy_through(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "many.zip").write_bytes(_zip_bytes({f"f{i}.log": f"ip 10.0.0.{i}" for i in range(5)}))
    stats = _run(src, dst, extract=ExtractConfig(limits=ExtractLimits(max_members=2)))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "many.zip").read_bytes() == (src / "many.zip").read_bytes()
    assert any("max_members" in w for w in stats.warnings)


def test_max_out_bytes_bomb_cap_trips_extracterror(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    # a member whose declared uncompressed size dwarfs the cap
    (src / "bomb.zip").write_bytes(_zip_bytes({"big.log": "A" * 100_000}))
    stats = _run(src, dst, extract=ExtractConfig(limits=ExtractLimits(max_out_bytes=1000)))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "bomb.zip").read_bytes() == (src / "bomb.zip").read_bytes()
    assert any("max_out_bytes" in w for w in stats.warnings)


def test_corrupt_zip_falls_back_to_copy(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "broken.zip").write_bytes(b"PK\x03\x04 not really a zip \x00\x01")
    stats = _run(src, dst)
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "broken.zip").read_bytes() == (src / "broken.zip").read_bytes()


def test_partial_output_not_left_on_extracterror(tmp_path: Path):
    """A cap tripped mid-build must leave NO repacked archive in DST (fail-open
    to copy-through, never a truncated partial)."""
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "many.zip").write_bytes(_zip_bytes({f"f{i}.log": f"ip 10.0.0.{i}" for i in range(5)}))
    _run(src, dst, extract=ExtractConfig(limits=ExtractLimits(max_members=2)))
    # exactly one file in DST: the copied-through original (no *.part leftovers)
    assert sorted(p.name for p in dst.iterdir()) == ["many.zip"]
    assert (dst / "many.zip").read_bytes() == (src / "many.zip").read_bytes()


# ----------------------------------------------------------------------
# Single-file gz / bz2 / xz.

@pytest.mark.parametrize("comp,compress", [
    ("gz", gzip.compress), ("bz2", bz2.compress), ("xz", lzma.compress)])
def test_single_file_text_recompressed_same_format(tmp_path: Path, comp, compress):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    name = f"note.log.{comp}"
    (src / name).write_bytes(compress(b"email e@f.com ip 8.8.4.4\n"))
    stats = _run(src, dst)
    assert stats.files_extracted == 1
    rec = stats.extracted[0]
    assert rec.kind == "repack" and rec.out_rel == name
    decompress = {"gz": gzip.decompress, "bz2": bz2.decompress, "xz": lzma.decompress}[comp]
    body = decompress((dst / name).read_bytes()).decode("utf-8")
    assert "e@f.com" not in body and "8.8.4.4" not in body
    assert "<EMAIL_1>" in body and "<IP_1>" in body


def test_single_file_binary_without_handler_copies_through(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    # a gz of a NUL-laden binary whose inner suffix (.bin) has no handler
    (src / "blob.bin.gz").write_bytes(gzip.compress(b"\x00\x01\x02 ip 10.0.0.9 \x00"))
    stats = _run(src, dst)
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "blob.bin.gz").read_bytes() == (src / "blob.bin.gz").read_bytes()


def test_single_file_gz_delegates_to_nested_handler_derivative(tmp_path: Path):
    """x.<fmt>.gz whose inner suffix has a handler -> dissect inner -> a TEXT
    derivative named x.<fmt>.gz.txt (uncompressed), original gz not written."""
    from piiscrub.formats import _BY_NAME, _BY_SUFFIX

    class _Dummy:
        name = "dummyx"
        suffixes = (".dummyx",)

        def process(self, path, rel, out_path, scrub, *, write, limits):
            text = path.read_bytes().decode("latin-1")
            scrubbed, n = scrub(f"{rel}!body", text)
            if write and out_path is not None:
                d = out_path.parent / (out_path.name + ".txt")
                d.parent.mkdir(parents=True, exist_ok=True)
                d.write_text(scrubbed, encoding="utf-8")
            return ExtractOutcome(kind="derivative", out_rel=rel + ".txt", replacements=n)

    register(_Dummy())
    try:
        src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
        (src / "x.dummyx.gz").write_bytes(gzip.compress(b"mail g@h.com ip 1.2.3.4"))
        stats = _run(src, dst)
        assert stats.files_extracted == 1
        rec = stats.extracted[0]
        assert rec.kind == "derivative" and rec.out_rel == "x.dummyx.gz.txt"
        deriv = dst / "x.dummyx.gz.txt"
        assert deriv.exists() and not (dst / "x.dummyx.gz").exists()
        body = deriv.read_text()
        assert "g@h.com" not in body and "1.2.3.4" not in body
        assert "<EMAIL_1>" in body and "<IP_1>" in body
    finally:
        _BY_NAME.pop("dummyx", None)
        _BY_SUFFIX.pop(".dummyx", None)


# ----------------------------------------------------------------------
# scan (write=False) drives extraction in memory, writes nothing.

def test_scan_writes_nothing_but_counts_and_aliases(tmp_path: Path):
    src = tmp_path / "src"; src.mkdir()
    (src / "logs.zip").write_bytes(_zip_bytes({"app.log": "user a@b.com ip 10.0.0.9\n"}))
    amap = AliasMap()
    stats = process_tree(src, None, build_active(), amap, max_bytes=10 ** 9,
                         write=False, exclude_dirs=set())
    assert stats.files_extracted == 1 and stats.replacements >= 2
    assert list(src.iterdir()) == [src / "logs.zip"]        # nothing written
    cats = {m["category"] for m in amap.decode_table().values()}
    assert "email" in cats and "ipv4" in cats               # aliases populated


# ----------------------------------------------------------------------
# verify archive-recursion.

def test_verify_recursion_catches_planted_leak_inside_zip(tmp_path: Path):
    dst = tmp_path / "dst"; dst.mkdir()
    (dst / "planted.zip").write_bytes(_zip_bytes({
        "m/plain.log": "contact leak@evil.com from 203.0.113.9\n"}))
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    files = {l["file"] for l in res["leaks"]}
    cats = {l["category"] for l in res["leaks"]}
    assert "planted.zip!m/plain.log" in files
    assert "email" in cats and "ipv4" in cats


def test_verify_recursion_into_nested_archive(tmp_path: Path):
    dst = tmp_path / "dst"; dst.mkdir()
    inner = _zip_bytes({"deep.log": "leak 203.0.113.9\n"})
    (dst / "outer.zip").write_bytes(_zip_bytes({"nested.zip": inner}))
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    assert any(l["file"] == "outer.zip!nested.zip!deep.log" for l in res["leaks"])


def test_verify_clean_when_members_scrubbed(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"; src.mkdir()
    (src / "logs.zip").write_bytes(_zip_bytes({"app.log": "ip 10.0.0.9 mail a@b.com\n"}))
    _run(src, dst)
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is True and res["leaks"] == []


def test_verify_no_extract_skips_archive_recursion(tmp_path: Path):
    dst = tmp_path / "dst"; dst.mkdir()
    (dst / "planted.zip").write_bytes(_zip_bytes({
        "plain.log": "leak leak@evil.com 203.0.113.9\n"}))
    # --no-extract -> archive members are NOT re-scanned (documented weaker)
    res = audit.verify_tree(dst, build_active(), extract=ExtractConfig(enabled=False))
    assert res["clean"] is True and res["leaks"] == []


def test_verify_recursion_into_single_file_gz(tmp_path: Path):
    dst = tmp_path / "dst"; dst.mkdir()
    (dst / "note.log.gz").write_bytes(gzip.compress(b"leak 203.0.113.9\n"))
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    assert any("note.log.gz" in l["file"] for l in res["leaks"])


# ----------------------------------------------------------------------
# Handler contract via the registry (unit-level).

def test_process_raises_for_unreadable_and_leaves_no_output(tmp_path: Path):
    h = get_handler(".zip")
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip at all")
    out = tmp_path / "out.zip"
    with pytest.raises(ExtractError):
        h.process(bad, "bad.zip", out, lambda r, t: (t, 0),
                  write=True, limits=ExtractLimits())
    assert not out.exists()
