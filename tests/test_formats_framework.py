"""Framework-layer tests for format extractors (base contract + registry +
walker/config/report/manifest plumbing).

These do NOT exercise any concrete dissector — the real handlers are stubs that
raise ExtractError. Instead they lock down the framework: the registry lookup,
the fail-open fallback (ExtractError -> old copy-through + flag), the --no-extract
switch, [extract] config parsing, and the scan-writes-nothing-but-counts path.
A local dummy handler stands in for a "successful" extraction so the success
path is covered without any binary fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from piiscrub.config import ExtractConfig, resolve_config
from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap
from piiscrub.formats import (
    ExtractError,
    ExtractLimits,
    ExtractOutcome,
    get_handler,
    handler_names,
    handler_suffixes,
    register,
)
from piiscrub.formats.base import FormatHandler
from piiscrub.walker import FileStat, RunStats, process_tree
from piiscrub import manifest as manifest_mod
from piiscrub import report as report_mod


# ----------------------------------------------------------------------
# Registry

def test_registry_lookup_and_names():
    for suffix, name in [(".pcap", "pcap"), (".pcapng", "pcap"), (".cap", "pcap"),
                         (".zip", "archive"), (".tar", "archive"), (".gz", "archive"),
                         (".bz2", "archive"), (".xz", "archive"), (".tgz", "archive"),
                         (".docx", "office"), (".xlsx", "office"), (".pptx", "office"),
                         (".db", "sqlite"), (".sqlite", "sqlite"), (".sqlite3", "sqlite")]:
        h = get_handler(suffix)
        assert h is not None and h.name == name

    assert get_handler(".txt") is None and get_handler(".log") is None
    assert handler_names() == {"pcap", "archive", "office", "sqlite"}
    assert {".pcap", ".zip", ".docx", ".db"} <= handler_suffixes()


def test_registry_lookup_is_case_insensitive():
    assert get_handler(".PCAP").name == "pcap"
    assert get_handler(".Zip").name == "archive"


def test_stub_handlers_conform_to_protocol_and_raise():
    for suffix in (".pcap", ".zip", ".docx", ".db"):
        h = get_handler(suffix)
        assert isinstance(h, FormatHandler)   # runtime_checkable Protocol
        with pytest.raises(ExtractError):
            h.process(Path("x"), "x", None, lambda r, t: (t, 0),
                      write=False, limits=ExtractLimits())


# ----------------------------------------------------------------------
# A dummy handler for the success path (registered on a throwaway suffix).

class _DummyHandler:
    name = "dummy"
    suffixes = (".dummy",)

    def __init__(self) -> None:
        self.calls: list[str] = []

    def process(self, path, rel, out_path, scrub, *, write, limits):
        # Recover "text" from the source bytes and push it through the run's
        # scrub closure — exactly what a real derivative handler does.
        text = path.read_bytes().decode("latin-1")
        scrubbed, n = scrub(f"{rel}!body", text)
        out_rel = rel + ".txt"
        if write and out_path is not None:
            deriv = out_path.parent / (out_path.name + ".txt")
            deriv.parent.mkdir(parents=True, exist_ok=True)
            deriv.write_text(scrubbed, encoding="utf-8")
        self.calls.append(rel)
        return ExtractOutcome(kind="derivative", out_rel=out_rel, replacements=n,
                              members_processed=1)


@pytest.fixture
def dummy_handler():
    """Register a dummy '.dummy' handler and remove it after the test so the
    global registry is not polluted for other tests."""
    from piiscrub.formats import _BY_NAME, _BY_SUFFIX
    h = register(_DummyHandler())
    try:
        yield h
    finally:
        _BY_NAME.pop("dummy", None)
        _BY_SUFFIX.pop(".dummy", None)


# ----------------------------------------------------------------------
# ExtractError -> copy-through + flag preserves the OLD behaviour.

def test_extracterror_falls_back_to_copy_through_and_flag(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    # .pcap -> stub raises ExtractError -> exact old copy-through+flag path.
    (src / "cap.pcap").write_bytes(b"\xd4\xc3\xb2\xa1\x00\x01 ip 10.0.0.9 here")
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_processed == 0
    assert stats.files_extracted == 0
    assert stats.files_copied == 1
    # original copied through byte-for-byte, unchanged
    assert (dst / "cap.pcap").read_bytes() == (src / "cap.pcap").read_bytes()
    assert any(s.status == "binary" for s in stats.skipped)
    # warning keeps the old capture export hint AND records the real reason
    warn = next(w for w in stats.warnings if "cap.pcap" in w)
    assert "may contain PII" in warn and "pcap-text" in warn
    # the real pcap handler genuinely parses the fixture and fails open with a
    # concrete reason (the fixture's global header is < 24 bytes); the framework
    # surfaces it under the "extraction skipped:" prefix.
    assert "extraction skipped:" in warn
    assert "global header truncated" in warn


def test_extraction_success_records_stats_and_writes_derivative(tmp_path, dummy_handler):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "note.dummy").write_bytes(b"contact a@b.com at 10.0.0.9")
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_extracted == 1
    assert stats.files_processed == 0 and stats.files_copied == 0
    assert stats.replacements >= 2            # email + ip aliased
    # derivative written, original NOT copied into DST
    deriv = dst / "note.dummy.txt"
    assert deriv.exists() and not (dst / "note.dummy").exists()
    body = deriv.read_text()
    assert "a@b.com" not in body and "10.0.0.9" not in body
    assert "<EMAIL_1>" in body and "<IP_1>" in body
    # rich record for the report
    assert len(stats.extracted) == 1
    rec = stats.extracted[0]
    assert rec.rel == "note.dummy" and rec.out_rel == "note.dummy.txt"
    assert rec.kind == "derivative" and rec.members_processed == 1


def test_extract_disable_by_name_falls_back(tmp_path, dummy_handler):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "note.dummy").write_bytes(b"ip 10.0.0.9")
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set(),
                         extract=ExtractConfig(disable={"dummy"}))
    # disabled handler -> not a handler match -> plain copy-through (no BINARY
    # ext for .dummy, so it's actually treated as text here). Either way it is
    # NOT counted as extracted.
    assert stats.files_extracted == 0
    assert not (dst / "note.dummy.txt").exists()


# ----------------------------------------------------------------------
# --no-extract / extract disabled entirely.

def test_no_extract_restores_old_behavior(tmp_path, dummy_handler):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "cap.pcap").write_bytes(b"\xd4\xc3\xb2\xa1\x00\x01 ip 10.0.0.9")
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set(),
                         extract=ExtractConfig(enabled=False))
    # extraction off -> handler never consulted -> straight to BINARY copy-through
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "cap.pcap").read_bytes() == (src / "cap.pcap").read_bytes()
    warn = next(w for w in stats.warnings if "cap.pcap" in w)
    assert "extraction skipped" not in warn   # handler was never invoked


# ----------------------------------------------------------------------
# scan (write=False) exercises extraction in memory but writes nothing.

def test_scan_writes_nothing_but_counts_extraction(tmp_path, dummy_handler):
    src = tmp_path / "src"
    src.mkdir()
    (src / "note.dummy").write_bytes(b"user a@b.com ip 10.0.0.9")
    amap = AliasMap()
    stats = process_tree(src, None, build_active(), amap, max_bytes=10**9,
                         write=False, exclude_dirs=set())
    assert stats.files_extracted == 1
    assert stats.replacements >= 2
    # nothing written anywhere
    assert list(src.iterdir()) == [src / "note.dummy"]
    assert (src / "note.dummy").read_bytes() == b"user a@b.com ip 10.0.0.9"
    # aliases still populated so the report/scan reflects what strip would do
    assert dummy_handler.calls == ["note.dummy"]
    assert any(m["category"] == "email" for m in amap.decode_table().values())


# ----------------------------------------------------------------------
# FileStat / RunStats new fields.

def test_filestat_out_rel_default():
    assert FileStat("a", "processed").out_rel == ""
    assert RunStats().files_extracted == 0
    assert RunStats().extracted == []


# ----------------------------------------------------------------------
# [extract] config parsing (defaults, TOML table, CLI-style merge).

def test_extract_config_defaults():
    cfg = resolve_config(None, None)
    assert isinstance(cfg.extract, ExtractConfig)
    assert cfg.extract.enabled is True
    assert cfg.extract.disable == set()
    assert cfg.extract.limits == ExtractLimits()
    assert cfg.extract.limits.max_out_bytes == 512 * 1024 * 1024
    assert cfg.extract.limits.max_depth == 3
    assert cfg.extract.limits.max_members == 50_000


def test_extract_config_from_toml(tmp_path: Path):
    toml = tmp_path / "piiscrub.toml"
    toml.write_text(
        "[extract]\n"
        "enabled = false\n"
        'disable = ["pcap", "office"]\n'
        "max_out_bytes = 1048576\n"
        "max_depth = 5\n"
        "max_members = 10\n",
        encoding="utf-8",
    )
    cfg = resolve_config(None, toml)
    assert cfg.extract.enabled is False
    assert cfg.extract.disable == {"pcap", "office"}
    assert cfg.extract.limits.max_out_bytes == 1048576
    assert cfg.extract.limits.max_depth == 5
    assert cfg.extract.limits.max_members == 10


def test_extract_disable_lists_union_across_layers(tmp_path: Path):
    # profile layer + toml layer -> disable lists concat/dedupe like detectors.
    toml = tmp_path / "piiscrub.toml"
    toml.write_text('[extract]\ndisable = ["sqlite"]\n', encoding="utf-8")
    cfg = resolve_config("generic", toml)
    assert "sqlite" in cfg.extract.disable


# ----------------------------------------------------------------------
# report + manifest sections for extracted files.

def test_report_and_manifest_record_extracted(tmp_path, dummy_handler):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "note.dummy").write_bytes(b"ip 10.0.0.9 mail a@b.com")
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())

    summary = report_mod.build_summary(
        mode="strip", src=str(src), dst=str(dst), timestamp="t", version="v",
        amap=amap, stats=stats)
    assert summary["files_extracted"] == 1
    assert summary["extracted"] == [{
        "file": "note.dummy", "output_file": "note.dummy.txt",
        "kind": "derivative", "replacements": stats.replacements,
        "members_processed": 1, "members_copied": 0,
    }]
    # HTML render must not raise and should mention the derivative
    out_html = dst / "report.html"
    report_mod.write_html(summary, out_html)
    assert "note.dummy.txt" in out_html.read_text()

    manifest = manifest_mod.build_manifest(src, dst, stats, timestamp="t", version="v")
    rec = next(r for r in manifest["files"] if r["file"] == "note.dummy")
    assert rec["status"] == "extracted"
    assert rec["output_file"] == "note.dummy.txt"
    # original hashed at src rel, derivative hashed at out_rel
    assert rec["source_sha256"] == manifest_mod.hash_file(src / "note.dummy")
    assert rec["output_sha256"] == manifest_mod.hash_file(dst / "note.dummy.txt")
    assert rec["source_sha256"] != rec["output_sha256"]


def test_derivative_name_collision_with_sibling_preserves_both(tmp_path, dummy_handler):
    # Regression: a derivative (note.dummy -> note.dummy.txt) whose name equals a
    # real sibling source file (a plain note.dummy.txt, exactly the layout the
    # old export-to-text hint told operators to create) silently overwrote one
    # of them and misattributed the manifest. Both outputs must now survive with
    # distinct content and correct per-source manifest hashes.
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "note.dummy").write_bytes(b"dissected ip 10.0.0.9")
    (src / "note.dummy.txt").write_text("plain sibling mail a@b.com\n",
                                        encoding="utf-8")
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())

    # The plain sibling keeps its exact name; the derivative is relocated.
    plain = (dst / "note.dummy.txt").read_text()
    assert "a@b.com" not in plain and "<EMAIL_1>" in plain      # scrubbed sibling
    deriv_rec = next(r for r in stats.extracted if r.rel == "note.dummy")
    assert deriv_rec.out_rel != "note.dummy.txt"                # relocated
    deriv_body = (dst / deriv_rec.out_rel).read_text()
    assert "10.0.0.9" not in deriv_body and "<IP_1>" in deriv_body
    assert any("collides" in w for w in stats.warnings)

    # Manifest attributes each output to the RIGHT source (distinct hashes).
    manifest = manifest_mod.build_manifest(src, dst, stats, timestamp="t", version="v")
    rec_pcapish = next(r for r in manifest["files"] if r["file"] == "note.dummy")
    rec_plain = next(r for r in manifest["files"] if r["file"] == "note.dummy.txt")
    assert rec_pcapish["output_file"] == deriv_rec.out_rel
    assert rec_pcapish["output_sha256"] == manifest_mod.hash_file(dst / deriv_rec.out_rel)
    assert rec_plain["output_sha256"] == manifest_mod.hash_file(dst / "note.dummy.txt")
    assert rec_pcapish["output_sha256"] != rec_plain["output_sha256"]
