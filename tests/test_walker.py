from pathlib import Path

from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap
from piiscrub.walker import decode_bytes, process_tree


def test_decode_utf16_with_bom():
    raw = "ip 10.0.0.9\n".encode("utf-16")  # includes BOM
    decoded = decode_bytes(raw)
    assert decoded is not None
    text, enc = decoded
    assert "10.0.0.9" in text and enc == "utf-16"


def test_decode_binary_returns_none():
    assert decode_bytes(b"\x00\x01\x02PK\x03\x04binary") is None


def test_utf16_roundtrips_through_strip(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "win.log").write_bytes("user a@b.com ip 10.0.0.9\n".encode("utf-16"))
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_processed == 1
    out_raw = (dst / "win.log").read_bytes()
    out_text, enc = decode_bytes(out_raw)
    assert enc == "utf-16"
    assert "10.0.0.9" not in out_text and "<IP_1>" in out_text


def test_binary_files_passed_through_and_flagged(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "pic.png").write_bytes(b"\x89PNG\r\n\x1a\n raw 10.0.0.9 bytes")
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_processed == 0
    assert stats.files_copied == 1
    assert (dst / "pic.png").read_bytes() == (src / "pic.png").read_bytes()
    assert any(s.status == "binary" for s in stats.skipped)
    # a plain binary (no capture hint) keeps the generic warning only
    assert any("may contain PII" in w and "pcap-text" not in w for w in stats.warnings)


def test_pcap_skip_warning_has_export_hint(tmp_path: Path):
    """A binary capture (.pcap) is still copied through, but its skip warning
    must tell the operator how to get usable text out (export + --profile)."""
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    # pcap magic + a NUL byte so it's unambiguously binary
    (src / "cap.pcap").write_bytes(b"\xd4\xc3\xb2\xa1\x00\x01 ip 10.0.0.9 here")
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_processed == 0 and stats.files_copied == 1
    hint = next(w for w in stats.warnings if "cap.pcap" in w)
    assert "pcap-text" in hint and ("tshark" in hint or "Export Packet" in hint)


def test_evtx_skip_warning_has_export_hint(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "win.evtx").write_bytes(b"ElfFile\x00\x00 ip 10.0.0.9")
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert any("win.evtx" in w and "wevtutil" in w for w in stats.warnings)


def test_include_exclude_globs(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "a.log").write_text("ip 10.0.0.1", encoding="utf-8")
    (src / "b.txt").write_text("ip 10.0.0.2", encoding="utf-8")
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, include=["*.log"],
                         max_bytes=10**9, write=True, exclude_dirs=set())
    assert stats.files_total == 1
    assert (dst / "a.log").exists() and not (dst / "b.txt").exists()
