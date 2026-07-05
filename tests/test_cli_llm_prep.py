"""CLI wiring tests for LLM-prep mode (design 2026-07-05):
``--alias-style`` / ``--out-format`` / ``keep_wellknown`` / ``--profile llm``.

These exercise the CLI end-to-end (``cli.main`` with argv). The engine pieces
(structured style, out-format reshaping, well-known exemption) are tested
elsewhere; here we prove they are wired to config/profiles/CLI correctly — most
importantly that strip and its auto-verify agree on ``keep_wellknown`` so kept
well-knowns never read as leaks.

Pcap fixtures are built byte-by-byte (pattern borrowed from
tests/test_format_pcap.py) — no binary blobs are committed.
"""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path

from piiscrub.cli import main


# --- minimal pcap builders (borrowed from tests/test_format_pcap.py) --------

def _mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack(">H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0, ttl, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def classic_pcap(packets, *, linktype: int = 1, snaplen: int = 65535) -> bytes:
    out = bytearray(b"\xd4\xc3\xb2\xa1")                       # little-endian magic
    out += struct.pack("<HHiIII", 2, 4, 0, 0, snaplen, linktype)
    for ts_sec, ts_sub, pkt in packets:
        out += struct.pack("<IIII", ts_sec, ts_sub, len(pkt), len(pkt))
        out += pkt
    return bytes(out)


# Well-known PTP primary multicast group — identical on every network, kept
# verbatim by default. Two unicast hosts share ONE /24 so structured aliasing
# groups them under the same NET label.
WELLKNOWN = "224.0.1.129"
LOG_IP = "192.0.2.20"
PCAP_SRC_IP = "192.0.2.10"


def _make_src(tmp_path: Path) -> Path:
    """A tree with a plain .log (unicast IP + well-known multicast) and a pcap
    whose dissected source IP shares the log IP's /24."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.log").write_text(
        f"conn from {LOG_IP} to {WELLKNOWN} established\n",
        encoding="utf-8",
    )
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:01", 0x0800,
              ipv4(PCAP_SRC_IP, WELLKNOWN, 17, udp(320, 320, b"hello world data")))
    (src / "cap.pcap").write_bytes(classic_pcap([(1609556645, 0, pkt)]))
    return src


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln]


# --------------------------------------------------------------------------
# (a) end-to-end: --profile llm => jsonl records, structured aliases,
#     well-known kept verbatim, auto-verify PASSES.
# --------------------------------------------------------------------------

def test_profile_llm_end_to_end(tmp_path, capsys):
    src = _make_src(tmp_path)
    dst = tmp_path / "dst"
    rc = main(["strip", str(src), str(dst), "--profile", "llm", "--no-progress"])
    assert rc == 0                                          # auto-verify PASS

    log_out = dst / "app.log.jsonl"
    pcap_out = dst / "cap.pcap.jsonl"
    assert log_out.is_file() and pcap_out.is_file()
    # jsonl suffix => NO plain mirror / .txt derivative / original binary written
    assert not (dst / "app.log").exists()
    assert not (dst / "cap.pcap.txt").exists()
    assert not (dst / "cap.pcap").exists()

    # documented record shapes: per-line for text, per-packet for pcap
    log_recs = _read_jsonl(log_out)
    assert log_recs and all({"src", "n", "ts", "text"} <= r.keys() for r in log_recs)
    pcap_recs = _read_jsonl(pcap_out)
    assert pcap_recs and all("packet" in r for r in pcap_recs)

    log_text, pcap_text = log_out.read_text(), pcap_out.read_text()
    body = log_text + pcap_text
    # structured (subnet-grouped) aliases in BOTH the plain file AND the pcap
    # derivative — the pcap one proves the walker style pass-through reaches the
    # _scrub closure handed to format handlers.
    assert "<IP_NET" in log_text
    assert "<IP_NET" in pcap_text
    # raw unicast IPs gone; well-known multicast kept VERBATIM (identifies nothing)
    assert LOG_IP not in body and PCAP_SRC_IP not in body
    assert WELLKNOWN in log_text and WELLKNOWN in pcap_text


# --------------------------------------------------------------------------
# (b) reverse: originals restored from a jsonl output body via the decode map.
# --------------------------------------------------------------------------

def test_reverse_restores_from_jsonl(tmp_path, capsys):
    src = _make_src(tmp_path)
    dst = tmp_path / "dst"
    assert main(["strip", str(src), str(dst), "--profile", "llm", "--no-progress"]) == 0

    decode = src / "_pii" / "decode.json"
    assert decode.is_file()
    restored = tmp_path / "restored.jsonl"
    rc = main(["reverse", str(dst / "app.log.jsonl"), str(restored), "--map", str(decode)])
    assert rc == 0

    text = restored.read_text(encoding="utf-8")
    assert LOG_IP in text                                  # structured alias reversed
    assert "<IP_NET" not in text                           # no alias left behind
    # aliases round-trip inside JSON strings: the reversed body is still valid jsonl
    for ln in text.splitlines():
        if ln:
            json.loads(ln)


# --------------------------------------------------------------------------
# (c) --alias-style structured with the DEFAULT out-format => text mirror that
#     carries structured aliases.
# --------------------------------------------------------------------------

def test_alias_style_structured_text_mirror(tmp_path, capsys):
    src = _make_src(tmp_path)
    dst = tmp_path / "dst"
    rc = main(["strip", str(src), str(dst), "--alias-style", "structured", "--no-progress"])
    assert rc == 0

    assert not (dst / "app.log.jsonl").exists()            # default out-format = text
    out = (dst / "app.log").read_text(encoding="utf-8")    # plain mirror
    assert "<IP_NET" in out
    assert LOG_IP not in out
    assert WELLKNOWN in out                                # well-known kept verbatim


# --------------------------------------------------------------------------
# (d) CLI --alias-style overrides the config-file value.
# --------------------------------------------------------------------------

def test_cli_alias_style_overrides_config(tmp_path, capsys):
    src = _make_src(tmp_path)
    dst = tmp_path / "dst"
    cfg = tmp_path / "piiscrub.toml"
    cfg.write_text('alias_style = "structured"\n', encoding="utf-8")
    # config says structured; the CLI flag opaque must WIN.
    rc = main(["strip", str(src), str(dst), "--config", str(cfg),
               "--alias-style", "opaque", "--no-progress"])
    assert rc == 0

    out = (dst / "app.log").read_text(encoding="utf-8")
    assert "<IP_NET" not in out                            # opaque won (no subnet grammar)
    assert "<IP_" in out                                   # IPs still aliased, opaquely
    assert LOG_IP not in out


# --------------------------------------------------------------------------
# (e) keep_wellknown=false in TOML: the well-known is now TOKENISED, and strip's
#     auto-verify still PASSES — proof strip and verify share one resolution
#     (a mismatch would flag the value as a leak).
# --------------------------------------------------------------------------

def test_keep_wellknown_false_is_consistent(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.log").write_text(
        f"ptp group {WELLKNOWN} host {LOG_IP}\n", encoding="utf-8")
    dst = tmp_path / "dst"
    cfg = tmp_path / "piiscrub.toml"
    cfg.write_text("keep_wellknown = false\n", encoding="utf-8")

    rc = main(["strip", str(src), str(dst), "--config", str(cfg), "--no-progress"])
    assert rc == 0                                         # strip+verify agree => PASS

    out = (dst / "app.log").read_text(encoding="utf-8")
    assert WELLKNOWN not in out                            # now tokenised, not verbatim
    assert "<IP_" in out


# --------------------------------------------------------------------------
# (f) scan --profile llm writes nothing (report only; no jsonl/derivatives).
# --------------------------------------------------------------------------

def test_scan_profile_llm_writes_nothing(tmp_path, capsys):
    src = _make_src(tmp_path)
    rc = main(["scan", str(src), "--profile", "llm", "--no-progress"])
    assert rc == 0
    assert (src / "_pii" / "scan_report.json").is_file()
    # no stripped tree created anywhere and no derivatives written into src
    assert list(tmp_path.iterdir()) == [src]
    assert not (src / "app.log.jsonl").exists()
    assert not (src / "cap.pcap.jsonl").exists()
