"""Tests for gui_runner.py — headless, in-process, no Qt/PySide6."""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path

import pytest

from piiscrub.cli import main as cli_main
from piiscrub.gui_runner import RunOptions, run_scan, run_strip
from piiscrub.progress import ProgressEvent


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


# --- minimal pcap builders (borrowed from tests/test_cli_llm_prep.py) --------

def _mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack(">H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0, ttl, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _classic_pcap(packets, *, linktype: int = 1, snaplen: int = 65535) -> bytes:
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


def _make_llm_src(root: Path) -> Path:
    """A tree with a plain .log (unicast IP + well-known multicast) and a pcap
    whose dissected source IP shares the log IP's /24 (same fixture shape as
    tests/test_cli_llm_prep.py)."""
    src = root / "src"
    src.mkdir(parents=True)
    (src / "app.log").write_text(
        f"conn from {LOG_IP} to {WELLKNOWN} established\n",
        encoding="utf-8",
    )
    pkt = _eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:01", 0x0800,
               _ipv4(PCAP_SRC_IP, WELLKNOWN, 17, _udp(320, 320, b"hello world data")))
    (src / "cap.pcap").write_bytes(_classic_pcap([(1609556645, 0, pkt)]))
    return src


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln]


# ---- basic strip ----------------------------------------------------------

def test_run_strip_basic(tmp_path):
    """Strip a log containing IP + email; verify dict keys and file contents."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    _write(src / "access.log", "user admin@example.com from 192.0.2.55 connected\n")

    opts = RunOptions(source=str(src), target=str(dst))
    result = run_strip(opts)

    # dict shape
    assert result["mode"] == "strip"
    assert result["replacements"] > 0
    assert result["verify"] == "PASS"
    assert result["verify_clean"] is True

    # stripped output must not contain raw PII
    stripped = (dst / "access.log").read_text(encoding="utf-8")
    assert "192.0.2.55" not in stripped
    assert "admin@example.com" not in stripped
    # alias tokens present
    assert "<" in stripped

    # decode.json written to src/_pii
    decode_path = src / "_pii" / "decode.json"
    assert decode_path.is_file()
    assert result["decode_map"] == str(decode_path)


# ---- CLI parity guard ------------------------------------------------------

def test_run_strip_matches_cli(tmp_path):
    """run_strip and cli main(['strip', ...]) on identical trees produce identical output."""
    content = "host db.internal.example.com ip 192.0.2.7 user ops@example.com\n"

    src_api = tmp_path / "api_src"
    dst_api = tmp_path / "api_dst"
    _write(src_api / "svc.log", content)

    src_cli = tmp_path / "cli_src"
    dst_cli = tmp_path / "cli_dst"
    _write(src_cli / "svc.log", content)

    run_strip(RunOptions(source=str(src_api), target=str(dst_api)))
    cli_main(["strip", str(src_cli), str(dst_cli)])

    api_out = (dst_api / "svc.log").read_text(encoding="utf-8")
    cli_out = (dst_cli / "svc.log").read_text(encoding="utf-8")
    assert api_out == cli_out


# ---- project vault ---------------------------------------------------------

def test_run_strip_project_vault(tmp_path):
    """Project mode: map.json created, lock released, alias reused on second run."""
    vault = tmp_path / "vault"
    src1 = tmp_path / "r1"
    dst1 = tmp_path / "o1"
    src2 = tmp_path / "r2"
    dst2 = tmp_path / "o2"

    _write(src1 / "a.log", "ip 192.0.2.20 seen\n")
    _write(src2 / "b.log", "ip 192.0.2.20 again\n")

    run_strip(RunOptions(source=str(src1), target=str(dst1), project=str(vault)))
    run_strip(RunOptions(source=str(src2), target=str(dst2), project=str(vault)))

    # vault map written
    assert (vault / "map.json").is_file()
    # lock released between runs
    assert not (vault / ".lock").exists()

    out1 = (dst1 / "a.log").read_text(encoding="utf-8")
    out2 = (dst2 / "b.log").read_text(encoding="utf-8")
    # extract the alias token used for the IP in each run
    import re
    tok1 = re.search(r"<[^>]+>", out1)
    tok2 = re.search(r"<[^>]+>", out2)
    assert tok1 and tok2
    assert tok1.group() == tok2.group(), "same IP must get same alias across runs"


# ---- scan ------------------------------------------------------------------

def test_run_scan(tmp_path):
    """Scan returns would_replace>0, writes scan_report.json, does NOT create target."""
    src = tmp_path / "src"
    _write(src / "app.log", "client 192.0.2.99 sent request to ops@example.com\n")

    opts = RunOptions(source=str(src))
    result = run_scan(opts)

    assert result["mode"] == "scan"
    assert result["would_replace"] > 0
    assert (src / "_pii" / "scan_report.json").is_file()
    # no target was created
    assert not (tmp_path / "dst").exists()


# ---- progress callback -----------------------------------------------------

def test_progress_callback_invoked(tmp_path):
    """Progress callback is invoked; final event has files_done == files_total."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    _write(src / "f1.log", "ip 192.0.2.1 here\n")
    _write(src / "f2.log", "email x@example.com here\n")

    events: list[ProgressEvent] = []

    def capture(ev: ProgressEvent) -> None:
        events.append(ev)

    run_strip(RunOptions(source=str(src), target=str(dst)), progress=capture)

    assert len(events) > 0
    last = events[-1]
    assert last.files_done == last.files_total


# ---- bad max_bytes raises ValueError (not SystemExit) ----------------------

def test_run_strip_bad_max_bytes_raises_valueerror(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    _write(src / "a.log", "nothing sensitive\n")

    with pytest.raises(ValueError):
        run_strip(RunOptions(source=str(src), target=str(dst), max_bytes=0))


# ---- containment guard raises ValueError -----------------------------------

def test_run_strip_guard_containment(tmp_path):
    """source == target must raise ValueError, not SystemExit."""
    src = tmp_path / "src"
    _write(src / "a.log", "ip 192.0.2.5\n")

    with pytest.raises(ValueError):
        run_strip(RunOptions(source=str(src), target=str(src)))


# ---- emit_entities ---------------------------------------------------------

def test_run_scan_emit_entities(tmp_path):
    """emit_entities=True writes entities_starter.csv into src/_pii."""
    src = tmp_path / "src"
    _write(src / "a.log", "host db1.internal.example.com ip 192.0.2.10\n")

    opts = RunOptions(source=str(src), emit_entities=True)
    result = run_scan(opts)

    starter = src / "_pii" / "entities_starter.csv"
    assert starter.is_file()
    assert result.get("entities_starter") == str(starter)
    body = starter.read_text(encoding="utf-8")
    assert body.splitlines()[0].startswith("id,type,pretty_name,identifiers,notes")


def test_run_strip_emit_entities_returns_rows(tmp_path):
    """emit_entities=True on strip writes the starter CSV AND returns both
    entities_starter and entities_rows (matches the run_strip docstring)."""
    src = tmp_path / "src"
    _write(src / "a.log", "host db1.internal.example.com ip 192.0.2.10\n")

    opts = RunOptions(source=str(src), target=str(tmp_path / "dst"), emit_entities=True)
    result = run_strip(opts)

    starter = src / "_pii" / "entities_starter.csv"
    assert starter.is_file()
    assert result.get("entities_starter") == str(starter)
    assert isinstance(result.get("entities_rows"), int)
    assert result["entities_rows"] >= 1


# ---- LLM-prep mode: profile "llm" via the GUI runner ------------------------

def test_run_strip_profile_llm_jsonl_structured(tmp_path):
    """profile="llm" through the GUI runner: jsonl records, structured aliases,
    well-known kept verbatim, and the run's own verify PASSES (parity with
    tests/test_cli_llm_prep.py::test_profile_llm_end_to_end)."""
    src = _make_llm_src(tmp_path)
    dst = tmp_path / "dst"

    result = run_strip(RunOptions(source=str(src), target=str(dst), profile="llm"))
    assert result["verify"] == "PASS"
    assert result["verify_clean"] is True

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
    # derivative — proves style reaches the walker via the GUI runner too.
    assert "<IP_NET" in log_text
    assert "<IP_NET" in pcap_text
    # raw unicast IPs gone; well-known multicast kept VERBATIM
    assert LOG_IP not in body and PCAP_SRC_IP not in body
    assert WELLKNOWN in log_text and WELLKNOWN in pcap_text


# ---- keep_wellknown=false via config: strip and verify stay consistent -----

def test_run_strip_keep_wellknown_false_is_consistent(tmp_path):
    """keep_wellknown=false in TOML: the well-known is TOKENISED, and the run's
    own verify still PASSES — proof the GUI runner feeds ONE detectors object
    to both strip and verify (a mismatch would flag the value as a leak)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.log").write_text(
        f"ptp group {WELLKNOWN} host {LOG_IP}\n", encoding="utf-8")
    dst = tmp_path / "dst"
    cfg = tmp_path / "piiscrub.toml"
    cfg.write_text("keep_wellknown = false\n", encoding="utf-8")

    result = run_strip(RunOptions(source=str(src), target=str(dst), config=str(cfg)))
    assert result["verify"] == "PASS"                      # strip+verify agree
    assert result["verify_clean"] is True

    out = (dst / "app.log").read_text(encoding="utf-8")
    assert WELLKNOWN not in out                            # now tokenised, not verbatim
    assert "<IP_" in out
    assert LOG_IP not in out


# ---- [extract] disable via config is honoured -------------------------------

def test_run_strip_extract_disable_honoured(tmp_path):
    """[extract] disable=["pcap"] in TOML: the pcap handler is skipped, the
    binary is copied through verbatim (no .txt/.jsonl derivative)."""
    src = _make_llm_src(tmp_path)
    dst = tmp_path / "dst"
    cfg = tmp_path / "piiscrub.toml"
    cfg.write_text('[extract]\ndisable = ["pcap"]\n', encoding="utf-8")

    result = run_strip(RunOptions(source=str(src), target=str(dst), config=str(cfg)))
    assert result["verify"] == "PASS"
    assert result["verify_clean"] is True

    # pcap NOT extracted: byte-identical copy-through, no derivative
    assert (dst / "cap.pcap").read_bytes() == (src / "cap.pcap").read_bytes()
    assert not (dst / "cap.pcap.txt").exists()
    assert not (dst / "cap.pcap.jsonl").exists()
    # the plain log is still processed normally
    out = (dst / "app.log").read_text(encoding="utf-8")
    assert LOG_IP not in out


# ---- default behaviour regression guard --------------------------------------

def test_run_strip_default_behaviour_unchanged(tmp_path):
    """No profile/config: opaque aliases, text mirror (no jsonl), well-known
    kept verbatim, pcap extracted to a scrubbed derivative — and byte-identical
    to a default CLI strip on an identical tree (regression guard for the
    LLM-prep plumbing staying inert by default)."""
    src_api = _make_llm_src(tmp_path / "api")
    dst_api = tmp_path / "api" / "dst"
    src_cli = _make_llm_src(tmp_path / "cli")
    dst_cli = tmp_path / "cli" / "dst"

    result = run_strip(RunOptions(source=str(src_api), target=str(dst_api)))
    assert result["verify"] == "PASS"
    assert cli_main(["strip", str(src_cli), str(dst_cli), "--no-progress"]) == 0

    # default shape: plain text mirror, no jsonl records
    assert (dst_api / "app.log").is_file()
    assert not (dst_api / "app.log.jsonl").exists()
    out = (dst_api / "app.log").read_text(encoding="utf-8")
    assert "<IP_NET" not in out                            # opaque, not structured
    assert "<IP_" in out
    assert LOG_IP not in out
    assert WELLKNOWN in out                                # well-known kept verbatim

    # byte-parity with the CLI default run, including the pcap derivative
    api_files = sorted(p.relative_to(dst_api) for p in dst_api.rglob("*") if p.is_file())
    cli_files = sorted(p.relative_to(dst_cli) for p in dst_cli.rglob("*") if p.is_file())
    assert api_files == cli_files
    for rel in api_files:
        assert (dst_api / rel).read_bytes() == (dst_cli / rel).read_bytes(), rel
