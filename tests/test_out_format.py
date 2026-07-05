"""Tests for the out-format adapter (--out-format text|csv|jsonl, decisions
#4/#5 of docs/plans/2026-07-05-llm-prep-mode-design.md).

``text`` is the default and must be byte-identical to today (the rest of the
suite is the regression net). For csv/jsonl the scrubbed TEXT outputs are
re-shaped at write time into per-line records — and pcap derivatives into
per-packet records — while structured (csv/json/jsonl) handler outputs and
repacked archives are left exactly as the handler wrote them.

All fixtures are client-ref-clean: RFC-5737 / RFC-1918 addresses and
``example.com`` names only, built in-test (pcap byte-by-byte with ``struct``).
"""

from __future__ import annotations

import csv
import io
import json
import socket
import struct
import zipfile
from pathlib import Path

import piiscrub.walker as walker
from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap, reverse_text
from piiscrub.walker import process_tree


# ---------------------------------------------------------------------------
# Minimal pcap builders (byte-by-byte, mirroring tests/test_format_pcap.py).

def _mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack(">H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0, 64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def classic_pcap(packets) -> bytes:
    out = bytearray(b"\xd4\xc3\xb2\xa1")                    # little-endian, us
    out += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)    # linktype 1 = Ethernet
    for ts_sec, ts_sub, pkt in packets:
        out += struct.pack("<IIII", ts_sec, ts_sub, len(pkt), len(pkt))
        out += pkt
    return bytes(out)


def _udp_pkt(mac_src: str, ip_src: str, ip_dst: str, body: bytes) -> bytes:
    return eth("11:22:33:44:55:66", mac_src, 0x0800,
               ipv4(ip_src, ip_dst, 17, udp(40000, 53, body)))


def _run(tmp_path: Path, files: dict[str, bytes], out_format: str = "text",
         *, amap: AliasMap | None = None, stream_threshold: int = 50 * 1024 * 1024):
    """Write ``files`` into a src tree, strip into a dst tree with ``out_format``,
    return (stats, dst, amap)."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir(parents=True)
    for rel, data in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    amap = amap or AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10 ** 12,
                         write=True, exclude_dirs=set(), out_format=out_format,
                         stream_threshold=stream_threshold)
    return stats, dst, amap


def _reshaped_files(dst: Path) -> list[str]:
    return sorted(p.name for p in dst.rglob("*")
                  if p.is_file() and p.suffix in (".jsonl", ".csv"))


# ---------------------------------------------------------------------------
# text default == today (byte-identical) and never reshapes.

def test_text_default_is_byte_identical_and_makes_no_records(tmp_path: Path):
    files = {
        "a.log": b"login from 198.51.100.7\n",
        "b.txt": b"contact user@example.com ok\n",
        "pic.png": b"\x89PNG\r\n\x1a\n raw 10.0.0.9 bytes",   # binary passthrough
    }
    # Default (no out_format arg) vs explicit out_format="text": identical trees.
    src_a = tmp_path / "ta"
    src_a.mkdir()
    for rel, data in files.items():
        (src_a / rel).write_bytes(data)
    dst_default = tmp_path / "ta_default"
    dst_text = tmp_path / "ta_text"
    process_tree(src_a, dst_default, build_active(), AliasMap(), max_bytes=10 ** 12,
                 write=True, exclude_dirs=set())                    # default
    process_tree(src_a, dst_text, build_active(), AliasMap(), max_bytes=10 ** 12,
                 write=True, exclude_dirs=set(), out_format="text")  # explicit

    got_default = {p.relative_to(dst_default).as_posix(): p.read_bytes()
                   for p in dst_default.rglob("*") if p.is_file()}
    got_text = {p.relative_to(dst_text).as_posix(): p.read_bytes()
                for p in dst_text.rglob("*") if p.is_file()}
    assert got_default == got_text
    # No reshaped outputs at all; the plain mirror names are used.
    assert _reshaped_files(dst_default) == []
    assert (dst_default / "a.log").exists() and (dst_default / "b.txt").exists()


def test_invalid_out_format_rejected(tmp_path: Path):
    import pytest
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.log").write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError):
        process_tree(src, tmp_path / "dst", build_active(), AliasMap(),
                     max_bytes=10 ** 12, write=True, exclude_dirs=set(),
                     out_format="yaml")


# ---------------------------------------------------------------------------
# jsonl per-line records: ts extraction, n, aliasing.

def test_jsonl_per_line_records(tmp_path: Path):
    log = (
        "2026-07-05T03:04:05 login from 198.51.100.7\n"
        "retry from 198.51.100.7 failed\n"
        "done\n"
    )
    stats, dst, amap = _run(tmp_path, {"app.log": log.encode()}, "jsonl")

    out = dst / "app.log.jsonl"
    assert out.exists()
    assert not (dst / "app.log").exists()                 # mirror name not written
    # FileStat carries the reshaped out_rel.
    fs = next(f for f in stats.per_file if f.rel == "app.log")
    assert fs.out_rel == "app.log.jsonl"

    recs = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(recs) == 3
    assert [r["n"] for r in recs] == [1, 2, 3]
    assert [r["src"] for r in recs] == ["app.log"] * 3
    # ts extracted only for the ISO-prefixed line, exactly as it appears.
    assert recs[0]["ts"] == "2026-07-05T03:04:05"
    assert recs[1]["ts"] is None and recs[2]["ts"] is None
    # IP aliased inside the "text" field on both lines (same alias, correlation).
    assert "198.51.100.7" not in out.read_text()
    assert "<IP_1>" in recs[0]["text"] and "<IP_1>" in recs[1]["text"]
    assert recs[2]["text"] == "done"


def test_jsonl_syslog_and_tsfield_extraction(tmp_path: Path):
    log = (
        "Jul  5 03:04:05 host sshd: from 198.51.100.7\n"     # syslog (double-space)
        "level=info ts=2026-07-05T03:04:05.5Z msg from 198.51.100.8\n"  # ts= field
    )
    _, dst, _ = _run(tmp_path, {"sys.log": log.encode()}, "jsonl")
    recs = [json.loads(l) for l in (dst / "sys.log.jsonl").read_text().splitlines()]
    assert recs[0]["ts"] == "Jul  5 03:04:05"               # verbatim double-space
    assert recs[1]["ts"] == "2026-07-05T03:04:05.5Z"


# ---------------------------------------------------------------------------
# csv per-line records parse back with csv.reader, same data.

def test_csv_per_line_records(tmp_path: Path):
    log = (
        "2026-07-05T03:04:05 login from 198.51.100.7\n"
        "retry from 198.51.100.7 failed\n"
    )
    _, dst, _ = _run(tmp_path, {"app.log": log.encode()}, "csv")
    out = dst / "app.log.csv"
    assert out.exists() and not (dst / "app.log").exists()

    rows = list(csv.reader(io.StringIO(out.read_text(), newline="")))
    assert rows[0] == ["src", "n", "ts", "text"]             # header included
    data = rows[1:]
    assert len(data) == 2
    assert [r[0] for r in data] == ["app.log", "app.log"]
    assert [r[1] for r in data] == ["1", "2"]                # n column
    assert data[0][2] == "2026-07-05T03:04:05" and data[1][2] == ""   # ts, then null
    assert "198.51.100.7" not in out.read_text()
    assert "<IP_1>" in data[0][3] and "<IP_1>" in data[1][3]


# ---------------------------------------------------------------------------
# pcap derivative -> per-packet records (packet numbers + ts from header).

def test_pcap_derivative_per_packet_records(tmp_path: Path):
    p1 = _udp_pkt("aa:bb:cc:dd:ee:01", "198.51.100.7", "198.51.100.9", b"hello one")
    p2 = _udp_pkt("aa:bb:cc:dd:ee:02", "203.0.113.5", "203.0.113.9", b"hello two")
    # ts_sec 1751684645 = 2025-07-05T...Z; exact value asserted via the header.
    raw = classic_pcap([(1751684645, 6, p1), (1751684645, 7, p2)])
    stats, dst, _ = _run(tmp_path, {"cap.pcap": raw}, "jsonl")

    out = dst / "cap.pcap.jsonl"
    assert out.exists()
    assert not (dst / "cap.pcap.txt").exists()               # .txt reshaped away
    rec = next(r for r in stats.extracted if r.rel == "cap.pcap")
    assert rec.out_rel == "cap.pcap.jsonl" and rec.kind == "derivative"

    body = out.read_text()
    recs = [json.loads(line) for line in body.splitlines()]
    assert len(recs) == 2                                    # one record PER PACKET
    assert [r["packet"] for r in recs] == [1, 2]             # "packet" key, not "n"
    assert all(r["src"] == "cap.pcap" for r in recs)
    # ts comes from the '# packet N ts=...' header and is non-null / real.
    assert recs[0]["ts"] is not None and recs[0]["ts"].startswith("2025-")
    # The record ts equals the ts= value embedded in the block header text.
    for r in recs:
        assert f"ts={r['ts']}" in r["text"]
        assert r["text"].startswith(f"# packet {r['packet']} ts=")
    # No raw addresses survive; aliases present in the block text.
    for raw_val in ("198.51.100.7", "198.51.100.9", "203.0.113.5", "203.0.113.9",
                    "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"):
        assert raw_val not in body
    assert "<IP_" in recs[0]["text"] and "<MAC_" in recs[0]["text"]


# ---------------------------------------------------------------------------
# structured (.csv source) is NOT double-wrapped: stays valid in-format CSV.

def test_structured_csv_source_not_double_wrapped(tmp_path: Path):
    data = b"host,ip\nweb01.example.com,198.51.100.7\napi.example.com,198.51.100.8\n"
    stats, dst, _ = _run(tmp_path, {"data.csv": data}, "jsonl")

    # The structured handler kept the in-format name; NO .jsonl re-wrap happened.
    assert (dst / "data.csv").exists()
    assert not (dst / "data.csv.jsonl").exists()
    rec = next(r for r in stats.extracted if r.rel == "data.csv")
    assert rec.out_rel == "data.csv"                         # unchanged by out_format

    rows = list(csv.reader(io.StringIO((dst / "data.csv").read_text(), newline="")))
    assert rows[0] == ["host", "ip"]                         # header (no PII) intact
    assert len(rows) == 3
    text = (dst / "data.csv").read_text()
    assert "198.51.100.7" not in text and "web01.example.com" not in text
    assert "<IP_" in text                                    # cell PII aliased


# ---------------------------------------------------------------------------
# repacked archive is untouched by out_format (archives keep their text members).

def test_repacked_zip_untouched_by_out_format(tmp_path: Path):
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("inner/app.log", "conn from 198.51.100.7 ok\n")
    stats, dst, _ = _run(tmp_path, {"logs.zip": zbuf.getvalue()}, "jsonl")

    out = dst / "logs.zip"
    assert out.exists() and zipfile.is_zipfile(out)          # still a zip, not records
    assert _reshaped_files(dst) == []
    rec = next(r for r in stats.extracted if r.rel == "logs.zip")
    assert rec.kind == "repack" and rec.out_rel == "logs.zip"
    with zipfile.ZipFile(out) as z:
        member = z.read("inner/app.log").decode()
    assert "198.51.100.7" not in member and "<IP_1>" in member   # scrubbed, plain text


# ---------------------------------------------------------------------------
# streaming path: line-by-line shaping == whole-file, aliases == text run.

def test_streaming_jsonl_matches_whole_file_and_text_aliases(tmp_path: Path, monkeypatch):
    # Force multiple READ_BLOCK/OVERLAP commits so lines straddle commit
    # boundaries and the partial-line buffer is exercised.
    monkeypatch.setattr(walker, "READ_BLOCK", 512)
    monkeypatch.setattr(walker, "OVERLAP", 256)

    lines = []
    for i in range(400):
        ip = f"198.51.100.{i % 256}"
        prefix = "2026-07-05T03:04:05 " if i % 3 == 0 else ""
        lines.append(f"{prefix}row {i} from {ip} user u{i}@example.com")
    content = ("\n".join(lines) + "\n").encode("utf-8")
    assert len(content) > 4 * 512                            # several commits

    # Baseline aliases from a plain text-mode run.
    _, _, amap_text = _run(tmp_path / "t", {"big.log": content}, "text",
                           stream_threshold=10 ** 12)

    # Whole-file jsonl (no streaming) vs streamed jsonl (tiny threshold).
    _, dst_whole, amap_whole = _run(tmp_path / "w", {"big.log": content}, "jsonl",
                                    stream_threshold=10 ** 12)
    stats_s, dst_stream, amap_stream = _run(tmp_path / "s", {"big.log": content},
                                            "jsonl", stream_threshold=1024)

    # The streamed file really took the streaming path (processed, out_rel set).
    fs = next(f for f in stats_s.per_file if f.rel == "big.log")
    assert fs.status == "processed" and fs.out_rel == "big.log.jsonl"

    whole = (dst_whole / "big.log.jsonl").read_bytes()
    streamed = (dst_stream / "big.log.jsonl").read_bytes()
    assert streamed == whole, "streamed reshaping differs from whole-file reshaping"

    # Aliases identical across all three runs (out_format never affects aliasing).
    assert amap_stream.reverse_pairs() == amap_whole.reverse_pairs()
    assert amap_stream.reverse_pairs() == amap_text.reverse_pairs()

    # Records are well-formed: n is 1..N contiguous, no raw IP leaks.
    recs = [json.loads(l) for l in (dst_stream / "big.log.jsonl").read_text().splitlines()]
    assert [r["n"] for r in recs] == list(range(1, len(lines) + 1))
    assert recs[0]["ts"] == "2026-07-05T03:04:05" and recs[1]["ts"] is None
    assert "198.51.100." not in (dst_stream / "big.log.jsonl").read_text()


# ---------------------------------------------------------------------------
# verify/reverse: aliases inside the JSON "text" field survive a json round-trip
# and reverse_text restores originals inside the records.

def test_reverse_roundtrip_through_jsonl(tmp_path: Path):
    log = (
        "2026-07-05T03:04:05 login from 198.51.100.7 as user@example.com\n"
        "retry from 198.51.100.7\n"
    )
    _, dst, amap = _run(tmp_path, {"app.log": log.encode()}, "jsonl")
    body = (dst / "app.log.jsonl").read_text()

    # Aliases survive JSON escaping (<, >, _, alnum are never escaped), so
    # reverse_text over the whole jsonl body restores the originals in place.
    restored = reverse_text(body, amap.reverse_pairs())
    recs = [json.loads(line) for line in restored.splitlines()]
    assert "198.51.100.7" in recs[0]["text"]
    assert "user@example.com" in recs[0]["text"]
    assert "198.51.100.7" in recs[1]["text"]
    # ts (never aliased) is unchanged by the reverse.
    assert recs[0]["ts"] == "2026-07-05T03:04:05"
