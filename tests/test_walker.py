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
