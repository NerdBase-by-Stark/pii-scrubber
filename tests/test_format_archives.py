"""Tests for the archives format handler (zip / tar(.gz/.bz2/.xz) / tgz /
single-file gz/bz2/xz) and the verify archive-recursion hook.

All fixtures are built programmatically in-test with the stdlib (zipfile /
tarfile / gzip / bz2 / lzma)
no binary blobs live in git. The archives handler
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    name = f"pack.tar.{comp}"
    (src / name).write_bytes(_targz_bytes({"log.txt": "ip 8.8.8.8\n"}, comp=comp))
    stats = _run(src, dst)
    assert stats.files_extracted == 1
    with tarfile.open(dst / name, mode) as t:
        body = t.extractfile("log.txt").read().decode("utf-8")
        assert "8.8.8.8" not in body and "<IP_1>" in body


def test_tgz_extension_treated_as_tar_gz(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "arch.tgz").write_bytes(_targz_bytes({"a.log": "ip 10.0.0.9\n"}))
    _run(src, dst)
    with tarfile.open(dst / "arch.tgz") as t:
        assert "<IP_1>" in t.extractfile("a.log").read().decode("utf-8")


# ----------------------------------------------------------------------
# Nested archives (depth) + shared aliasing.

def test_nested_zip_members_scrubbed(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "trav.zip").write_bytes(_zip_bytes({
        "../evil.txt": "ip 10.0.0.9",
        "ok.txt": "ip 10.0.0.8",
    }))
    stats = _run(src, dst)
    with zipfile.ZipFile(dst / "trav.zip") as z:
        assert z.namelist() == ["ok.txt"]            # '..' member not repacked
    assert any("../evil.txt" in w and "unsafe path" in w for w in stats.warnings)


def test_absolute_member_skipped(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "abs.zip").write_bytes(_zip_bytes({"/etc/passwd": "ip 10.0.0.9", "ok.log": "x"}))
    _run(src, dst)
    with zipfile.ZipFile(dst / "abs.zip") as z:
        assert "/etc/passwd" not in z.namelist() and "ok.log" in z.namelist()


def test_encrypted_zip_falls_back_to_copy_and_flag(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "enc.zip").write_bytes(_encrypted_zip_bytes())
    stats = _run(src, dst)
    assert stats.files_extracted == 0 and stats.files_copied == 1
    # whole archive copied through byte-for-byte, NOT partially repacked
    assert (dst / "enc.zip").read_bytes() == (src / "enc.zip").read_bytes()
    warn = next(w for w in stats.warnings if "enc.zip" in w)
    assert "encrypted" in warn and "may contain PII" in warn


def test_max_members_cap_trips_extracterror_copy_through(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "many.zip").write_bytes(_zip_bytes({f"f{i}.log": f"ip 10.0.0.{i}" for i in range(5)}))
    stats = _run(src, dst, extract=ExtractConfig(limits=ExtractLimits(max_members=2)))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "many.zip").read_bytes() == (src / "many.zip").read_bytes()
    assert any("max_members" in w for w in stats.warnings)


def test_max_out_bytes_bomb_cap_trips_extracterror(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    # a member whose declared uncompressed size dwarfs the cap
    (src / "bomb.zip").write_bytes(_zip_bytes({"big.log": "A" * 100_000}))
    stats = _run(src, dst, extract=ExtractConfig(limits=ExtractLimits(max_out_bytes=1000)))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "bomb.zip").read_bytes() == (src / "bomb.zip").read_bytes()
    assert any("max_out_bytes" in w for w in stats.warnings)


def test_corrupt_zip_falls_back_to_copy(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "broken.zip").write_bytes(b"PK\x03\x04 not really a zip \x00\x01")
    stats = _run(src, dst)
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "broken.zip").read_bytes() == (src / "broken.zip").read_bytes()


def test_partial_output_not_left_on_extracterror(tmp_path: Path):
    """A cap tripped mid-build must leave NO repacked archive in DST (fail-open
    to copy-through, never a truncated partial)."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
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
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
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
    src = tmp_path / "src"
    src.mkdir()
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
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "planted.zip").write_bytes(_zip_bytes({
        "m/plain.log": "contact leak@evil.com from 203.0.113.9\n"}))
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    files = {leak["file"] for leak in res["leaks"]}
    cats = {leak["category"] for leak in res["leaks"]}
    assert "planted.zip!m/plain.log" in files
    assert "email" in cats and "ipv4" in cats


def test_verify_recursion_into_nested_archive(tmp_path: Path):
    dst = tmp_path / "dst"
    dst.mkdir()
    inner = _zip_bytes({"deep.log": "leak 203.0.113.9\n"})
    (dst / "outer.zip").write_bytes(_zip_bytes({"nested.zip": inner}))
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    assert any(l["file"] == "outer.zip!nested.zip!deep.log" for leak in res["leaks"])


def test_verify_clean_when_members_scrubbed(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "logs.zip").write_bytes(_zip_bytes({"app.log": "ip 10.0.0.9 mail a@b.com\n"}))
    _run(src, dst)
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is True and res["leaks"] == []


def test_verify_no_extract_skips_archive_recursion(tmp_path: Path):
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "planted.zip").write_bytes(_zip_bytes({
        "plain.log": "leak leak@evil.com 203.0.113.9\n"}))
    # --no-extract -> archive members are NOT re-scanned (documented weaker)
    res = audit.verify_tree(dst, build_active(), extract=ExtractConfig(enabled=False))
    assert res["clean"] is True and res["leaks"] == []


def test_verify_recursion_into_single_file_gz(tmp_path: Path):
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "note.log.gz").write_bytes(gzip.compress(b"leak 203.0.113.9\n"))
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    assert any("note.log.gz" in leak["file"] for leak in res["leaks"])


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


# ----------------------------------------------------------------------
# Corrupt / truncated tar must fail open to copy-through, not abort the run
# (regression: getmembers()/member read raised tarfile.ReadError uncaught).

def test_truncated_tar_falls_back_to_copy_and_flag(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    # A member whose DATA block spans well past the cut: getmembers() sees a
    # valid header (declared size 3000) but the member read hits EOF and
    # tarfile raises ReadError('unexpected end of data').
    full = _targz_bytes({"big.log": "ip 10.0.0.9\n" * 250}, comp="")
    (src / "cut.tar").write_bytes(full[:700])
    stats = _run(src, dst)   # must NOT raise
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "cut.tar").read_bytes() == (src / "cut.tar").read_bytes()
    assert any("cut.tar" in w and "may contain PII" in w for w in stats.warnings)


def test_truncated_targz_falls_back_to_copy(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    full = _targz_bytes({"a.log": "ip 10.0.0.9\n" * 500}, comp="gz")
    (src / "cut.tar.gz").write_bytes(full[:len(full) - 40])   # truncate the gz tail
    stats = _run(src, dst)   # must NOT raise
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "cut.tar.gz").read_bytes() == (src / "cut.tar.gz").read_bytes()


# ----------------------------------------------------------------------
# --extract-disable / [extract].disable is honored for archive MEMBERS, not
# only top-level files: a disabled extractor's member is copied through
# unchanged + flagged, so the original binary survives the repack.

def _pcap_bytes(payload: bytes) -> bytes:
    import struct
    magic = b"\xd4\xc3\xb2\xa1"
    out = bytearray(magic)
    out += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)   # header, linktype eth
    eth = (b"\x11\x22\x33\x44\x55\x66\xaa\xbb\xcc\xdd\xee\x01"
           + struct.pack(">H", 0x0800) + payload)
    out += struct.pack("<IIII", 1, 0, len(eth), len(eth)) + eth
    return bytes(out)


def test_disabled_extractor_not_run_on_archive_member(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    pcap = _pcap_bytes(b"filler payload bytes here")
    (src / "bundle.zip").write_bytes(_zip_bytes({
        "cap.pcap": pcap, "app.log": "ip 10.0.0.9\n"}))
    stats = _run(src, dst, extract=ExtractConfig(disable={"pcap"}))
    assert stats.files_extracted == 1        # the zip itself still repacks
    with zipfile.ZipFile(dst / "bundle.zip") as z:
        names = z.namelist()
        # the pcap member is preserved raw (NOT replaced by cap.pcap.txt), the
        # text member is still scrubbed.
        assert "cap.pcap" in names and "cap.pcap.txt" not in names
        assert z.read("cap.pcap") == pcap
        assert "10.0.0.9" not in z.read("app.log").decode()
    assert any("cap.pcap" in w and "copied unchanged" in w for w in stats.warnings)


def test_disabled_extractor_run_on_archive_member_when_enabled(tmp_path: Path):
    # Sanity opposite of the above: with pcap enabled the member IS dissected.
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    pcap = _pcap_bytes(b"filler payload bytes here")
    (src / "bundle.zip").write_bytes(_zip_bytes({"cap.pcap": pcap}))
    _run(src, dst)   # extraction on by default
    with zipfile.ZipFile(dst / "bundle.zip") as z:
        assert z.namelist() == ["cap.pcap.txt"]


# ----------------------------------------------------------------------
# Member-name collision inside a repack: a dissected derivative and a sibling
# plain file that share the derivative's name must both survive (one renamed).

def test_member_name_collision_deduped_in_repack(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    pcap = _pcap_bytes(b"filler bytes")
    (src / "mix.zip").write_bytes(_zip_bytes({
        "cap.pcap": pcap,                       # -> cap.pcap.txt derivative
        "cap.pcap.txt": "plain note 10.0.0.9\n",  # already named cap.pcap.txt
    }))
    stats = _run(src, dst)
    with zipfile.ZipFile(dst / "mix.zip") as z:
        names = z.namelist()
        assert len(names) == 2 and len(set(names)) == 2   # no silent overwrite
        assert "cap.pcap.txt" in names
        assert any(n.startswith("cap.pcap.txt.dup") for n in names)


# ----------------------------------------------------------------------
# verify: a cap that stops archive recursion early must surface as a finding,
# never silently pass as clean (fail-closed guarantee otherwise hollow).

def test_verify_truncated_archive_scan_reports_finding(tmp_path: Path):
    dst = tmp_path / "dst"
    dst.mkdir()
    # A leak sits in the 3rd member, beyond a max_members=2 verify cap.
    (dst / "big.zip").write_bytes(_zip_bytes({
        "a.log": "clean\n", "b.log": "clean\n",
        "c.log": "leak leak@evil.com 203.0.113.9\n",
    }))
    res = audit.verify_tree(
        dst, build_active(),
        extract=ExtractConfig(limits=ExtractLimits(max_members=2)))
    assert res["clean"] is False
    cats = {leak["category"] for leak in res["leaks"]}
    assert "archive-scan-truncated" in cats


# ======================================================================
# Audit round-2 regression tests.

import os
import struct


def _pcap_member_bytes(payload: bytes = b"GET /x HTTP/1.1 printable payload abcdefghij") -> bytes:
    """A minimal single-packet classic pcap (Ethernet/IPv4/TCP) whose dissected
    text derivative is larger than the raw bytes (used to exercise the
    expansion-budget debit)."""
    import socket
    ip = (struct.pack(">BBHHHBBH", 0x45, 0, 20 + 20 + len(payload), 0x1234, 0, 64, 6, 0)
          + socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2")
          + struct.pack(">HHIIHHHH", 4000, 80, 0, 0, (5 << 12) | 0x18, 65535, 0, 0)
          + payload)
    eth = (b"\x11\x22\x33\x44\x55\x66\xaa\xbb\xcc\xdd\xee\x01"
           + struct.pack(">H", 0x0800) + ip)
    out = bytearray(b"\xd4\xc3\xb2\xa1")
    out += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)     # linktype ethernet
    out += struct.pack("<IIII", 1, 0, len(eth), len(eth)) + eth
    return bytes(out)


def _zip_with_encrypted_flag(members: dict[str, str | bytes],
                             encrypted: set[str]) -> bytes:
    """Build a normal zip then flip ONLY the general-purpose 'encrypted' bit
    (0x01) on the local + central headers of the members named in ``encrypted``.

    The bytes stay readable (we only set the flag) so verify can still decode the
    OTHER, unflagged members — exactly what strip's copy+flag fallback places in
    DST for an encrypted zip (the ORIGINAL archive, plaintext members and all)."""
    raw = bytearray(_zip_bytes(members))
    i = 0
    while (i := raw.find(b"PK\x03\x04", i)) >= 0:      # local file headers
        nlen = int.from_bytes(raw[i + 26:i + 28], "little")
        name = raw[i + 30:i + 30 + nlen].decode("utf-8", "replace")
        if name in encrypted:
            raw[i + 6] |= 0x01
        i += 4
    i = 0
    while (i := raw.find(b"PK\x01\x02", i)) >= 0:      # central directory headers
        nlen = int.from_bytes(raw[i + 28:i + 30], "little")
        name = raw[i + 46:i + 46 + nlen].decode("utf-8", "replace")
        if name in encrypted:
            raw[i + 8] |= 0x01
        i += 4
    return bytes(raw)


# --- Fix 2: verify recursion into single-file .gz must fail CLOSED when the
# inner stream exceeds the cap (was: silent return -> planted leak passes).

def test_verify_single_file_gz_over_cap_reports_truncated(tmp_path: Path):
    dst = tmp_path / "dst"
    dst.mkdir()
    inner = b"leak carol@evil.com 203.0.113.9\n" + b"x" * 240
    (dst / "logs.gz").write_bytes(gzip.compress(inner))
    res = audit.verify_tree(
        dst, build_active(),
        extract=ExtractConfig(limits=ExtractLimits(max_out_bytes=100)))
    assert res["clean"] is False
    cats = {leak["category"] for leak in res["leaks"]}
    assert "archive-scan-truncated" in cats
    assert any("logs.gz" in leak["file"] for leak in res["leaks"])


def test_verify_single_file_gz_under_cap_still_catches_leak(tmp_path: Path):
    # Control: within the cap the inner text is scanned normally and the planted
    # leak is caught as a real finding (not the truncation sentinel).
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "note.gz").write_bytes(gzip.compress(b"leak dave@evil.com 203.0.113.9\n"))
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    cats = {leak["category"] for leak in res["leaks"]}
    assert "email" in cats and "archive-scan-truncated" not in cats


# --- Fix 4: iter_text_members must not slurp a huge DST archive into RAM; an
# archive larger than the cap fails CLOSED (SCAN_TRUNCATED), never MemoryError.

def test_verify_oversize_archive_reports_truncated_not_read(tmp_path: Path):
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "big.zip").write_bytes(_zip_bytes({"m/plain.log": "leak eve@evil.com 203.0.113.9\n"}))
    size = (dst / "big.zip").stat().st_size
    # Cap set BELOW the on-disk archive size -> the size guard trips before read.
    res = audit.verify_tree(
        dst, build_active(),
        extract=ExtractConfig(limits=ExtractLimits(max_out_bytes=size - 1)))
    assert res["clean"] is False
    cats = {leak["category"] for leak in res["leaks"]}
    assert "archive-scan-truncated" in cats


def test_iter_text_members_oversize_yields_only_sentinel(tmp_path: Path):
    from piiscrub.formats.archives import iter_text_members, SCAN_TRUNCATED
    z = tmp_path / "a.zip"
    z.write_bytes(_zip_bytes({"x.log": "ip 203.0.113.9\n"}))
    limits = ExtractLimits(max_out_bytes=z.stat().st_size - 1)
    out = list(iter_text_members(z, "a.zip", limits))
    assert len(out) == 1 and out[0][1] is SCAN_TRUNCATED


# --- Fix 5: verify of a copied-through zip with an encrypted member must scan
# the readable plaintext members regardless of member ORDER (deterministic).

@pytest.mark.parametrize("order", [
    ["locked.bin", "plain.log"],     # encrypted FIRST (the failing case)
    ["plain.log", "locked.bin"],     # plaintext first
])
def test_verify_encrypted_member_order_independent(tmp_path: Path, order):
    dst = tmp_path / "dst"
    dst.mkdir()
    members = {name: ("john.doe@example.com / 10.1.2.3\n" if name == "plain.log"
                      else "opaque-cipher-bytes") for name in order}
    data = _zip_with_encrypted_flag(members, encrypted={"locked.bin"})
    (dst / "mix.zip").write_bytes(data)
    res = audit.verify_tree(dst, build_active())
    assert res["clean"] is False
    files = {leak["file"] for leak in res["leaks"]}
    cats = {leak["category"] for leak in res["leaks"]}
    assert "mix.zip!plain.log" in files
    assert "email" in cats and "ipv4" in cats


# --- Fix 7: single-file .gz derivative write failure (ENAMETOOLONG) must fail
# OPEN to copy-through + flag, never abort the run.

def test_single_file_gz_write_enametoolong_falls_back(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    long_name = "a" * 245 + ".pcap.gz"       # 253 chars
    deriv +'.txt' = 257 > 255
    (src / long_name).write_bytes(gzip.compress(_pcap_member_bytes()))
    (src / "ok.log.gz").write_bytes(gzip.compress(b"ip 10.0.0.9\n"))
    stats = _run(src, dst)                    # must NOT raise
    assert (dst / long_name).read_bytes() == (src / long_name).read_bytes()
    assert not os.path.exists(str(dst / (long_name + ".txt")))
    warn = next(w for w in stats.warnings if long_name in w)
    assert "may contain PII" in warn and "could not write derivative" in warn
    # the following compressed file was still processed -> run continued
    assert (dst / "ok.log.gz").exists()


# --- Fix 9: _bad_name must not misclassify a POSIX member whose name merely has
# a ':' at index 1 as Windows drive-absolute.

def test_bad_name_colon_at_index_one_is_not_drive_absolute():
    from piiscrub.formats.archives import _bad_name
    # POSIX-legal names with a colon that are NOT drive-absolute:
    assert _bad_name("a:notes.txt") is False
    assert _bad_name("t: results.log") is False
    assert _bad_name("x:y/z.txt") is False
    # Genuine drive-absolute / UNC / traversal are still rejected:
    assert _bad_name("C:/evil.txt") is True
    assert _bad_name("C:\\evil.txt") is True
    assert _bad_name("C:") is True
    assert _bad_name("/etc/passwd") is True
    assert _bad_name("\\\\host\\share") is True
    assert _bad_name("../escape.txt") is True
    # ordinary relative names pass:
    assert _bad_name("dir/rel.txt") is False


def test_posix_colon_member_survives_repack_and_is_scrubbed(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "bundle.tar").write_bytes(_targz_bytes(
        {"a:notes.txt": "contact frank@corp.com ip 10.7.7.7\n"}, comp=""))
    stats = _run(src, dst)
    assert stats.files_extracted == 1
    with tarfile.open(dst / "bundle.tar") as t:
        assert "a:notes.txt" in t.getnames()
        body = t.extractfile("a:notes.txt").read().decode()
        assert "frank@corp.com" not in body and "10.7.7.7" not in body
        assert "<EMAIL_1>" in body and "<IP_1>" in body
    assert not any("unsafe path" in w for w in stats.warnings)


# --- Fix 11: a nested handler's EXPANDED output must be debited from the
# archive's running max_out_bytes budget, so total produced text stays bounded.

def test_nested_expansion_debited_against_budget(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    pcap = _pcap_member_bytes()
    members = {f"cap{i}.pcap": pcap for i in range(6)}
    (src / "caps.zip").write_bytes(_zip_bytes(members))

    # Raw member bytes sum well under the cap, but the six dissected derivatives
    # (each larger than its raw member) do NOT: with the expansion debit the
    # archive trips max_out_bytes and copies through + flags, rather than
    # silently writing a repack several times the cap.
    raw_sum = 6 * len(pcap)
    cap = raw_sum + (len(pcap) // 2)          # fits raw, not the expanded text
    stats = _run(src, dst, extract=ExtractConfig(limits=ExtractLimits(max_out_bytes=cap)))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "caps.zip").read_bytes() == (src / "caps.zip").read_bytes()
    warn = next(w for w in stats.warnings if "caps.zip" in w)
    assert "may contain PII" in warn

    # Control: with a generous cap the same archive fully extracts all members.
    dst2 = tmp_path / "dst2"
    stats2 = _run(src, dst2)
    assert stats2.files_extracted == 1
    with zipfile.ZipFile(dst2 / "caps.zip") as z:
        assert sorted(z.namelist()) == sorted(f"cap{i}.pcap.txt" for i in range(6))
