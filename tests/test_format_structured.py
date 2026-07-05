"""Tests for the structured format handler (.csv / .json / .jsonl field-aware
scrub -> same-format, same-name output) and the walker's structured-specific
fail-open rule.

All fixtures are built programmatically in-test — no blobs in git. The handler
parses a structured text source, scrubs every string value through the run's
tokeniser, and re-serialises IN THE SAME FORMAT under the SAME name, so the
output stays machine-readable (csv.reader / json.loads) with PII aliased.
Unlike the binary handlers, an ExtractError here must fall THROUGH to the
plain regex-on-text scrub path (these are text files) — never copy-through
with raw PII.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

from piiscrub.config import ExtractConfig
from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap
from piiscrub.formats import ExtractLimits, get_handler
from piiscrub.formats.structured import _csv_dialect
from piiscrub.walker import process_tree


def _run(src: Path, dst: Path | None, *, write: bool = True, extract=None,
         amap: AliasMap | None = None):
    return process_tree(src, dst, build_active(), amap or AliasMap(),
                        max_bytes=10 ** 9, write=write, exclude_dirs=set(),
                        extract=extract)


# ----------------------------------------------------------------------
# Registration.

def test_handler_registered_for_all_suffixes():
    for suffix in (".csv", ".json", ".jsonl"):
        h = get_handler(suffix)
        assert h is not None and h.name == "structured"


# ----------------------------------------------------------------------
# csv: sniffed dialect round-trip, same name, cells aliased, structure intact.

def test_csv_semicolon_dialect_scrubbed_in_format(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "inventory.csv").write_text(
        "device;owner;ip\n"
        '"core; sw1";alice@example.com;10.20.30.40\n'
        "edge2;bob@example.com;10.20.30.41\n"
        "spare;;10.20.30.42\n",
        encoding="utf-8",
    )
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    assert stats.files_processed == 0 and stats.files_copied == 0
    rec = stats.extracted[0]
    # Same-format derivative keeps the SOURCE name (no .txt suffix, no .dup1).
    assert rec.kind == "derivative"
    assert rec.rel == "inventory.csv" and rec.out_rel == "inventory.csv"
    assert (dst / "inventory.csv").exists()
    assert not (dst / "inventory.csv.txt").exists()
    assert not (dst / "inventory.csv.dup1").exists()

    body = (dst / "inventory.csv").read_text(encoding="utf-8")
    assert "alice@example.com" not in body and "bob@example.com" not in body
    assert "10.20.30.40" not in body and "10.20.30.41" not in body

    # Output parses with the SAME delimiter and keeps the row/cell structure,
    # including the quoted delimiter-bearing cell and the empty cell.
    rows = list(csv.reader(io.StringIO(body, newline=""), delimiter=";"))
    assert len(rows) == 4 and all(len(r) == 3 for r in rows)
    assert rows[0] == ["device", "owner", "ip"]
    assert rows[1][0] == "core; sw1"
    assert rows[1][1].startswith("<EMAIL_") and rows[1][2].startswith("<IP_")
    assert rows[2][1].startswith("<EMAIL_") and rows[2][2].startswith("<IP_")
    assert rows[3][1] == "" and rows[3][2].startswith("<IP_")
    # Two distinct emails -> two distinct aliases.
    assert rows[1][1] != rows[2][1]


def test_csv_header_row_scrubbed_like_any_row(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "report.csv").write_text(
        "hostname;contact alice@example.com\nrow1;x\n", encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "report.csv").read_text(encoding="utf-8")
    assert "alice@example.com" not in body
    rows = list(csv.reader(io.StringIO(body, newline=""), delimiter=";"))
    assert rows[0][0] == "hostname" and "<EMAIL_1>" in rows[0][1]
    assert rows[1] == ["row1", "x"]


# ----------------------------------------------------------------------
# json: values AND PII-shaped keys aliased (nested dict/list); bool/null kept.

def test_json_values_and_pii_keys_aliased_bool_null_untouched(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    doc = {
        "device": {"name": "core-sw", "mgmt": "10.20.30.40"},
        "contacts": ["alice@example.com", {"email": "bob@example.com"}],
        "routes": {"10.99.0.1": "gateway"},   # PII-shaped KEY now aliased too
        "port": 443,
        "active": True,
        "note": None,
    }
    (src / "config.json").write_text(json.dumps(doc), encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    rec = stats.extracted[0]
    assert rec.rel == "config.json" and rec.out_rel == "config.json"
    body = (dst / "config.json").read_text(encoding="utf-8")
    assert "alice@example.com" not in body and "bob@example.com" not in body
    assert "10.20.30.40" not in body

    parsed = json.loads(body)                 # output stays valid JSON
    assert set(parsed) == set(doc)            # top-level keys untouched
    assert parsed["device"]["name"] == "core-sw"
    assert parsed["device"]["mgmt"].startswith("<IP_")
    assert parsed["contacts"][0].startswith("<EMAIL_")
    assert parsed["contacts"][1]["email"].startswith("<EMAIL_")
    assert parsed["contacts"][0] != parsed["contacts"][1]["email"]
    # A PII-shaped dict KEY is now aliased too (pre-v4 the whole-text path
    # aliased PII wherever it sat; leaving a key raw was a leak). The clean
    # value survives and the raw IP is gone from the whole document.
    routes = parsed["routes"]
    assert list(routes.values()) == ["gateway"]
    assert list(routes)[0].startswith("<IP_") and "10.99.0.1" not in body
    # non-PII scalars pass through as-is (443 renders to text with no PII match)
    assert parsed["port"] == 443 and parsed["active"] is True
    assert parsed["note"] is None


# ----------------------------------------------------------------------
# jsonl: per-line valid, blank lines preserved, non-strings untouched.

def test_jsonl_per_line_valid_and_blank_lines_preserved(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "events.jsonl").write_text(
        '{"host": "10.0.0.1", "mail": "alice@example.com"}\n'
        "\n"
        '{"tags": ["bob@example.com", 7]}\n',
        encoding="utf-8",
    )
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "events.jsonl").read_text(encoding="utf-8")
    assert "alice@example.com" not in body and "10.0.0.1" not in body
    lines = body.split("\n")
    assert len(lines) == 4 and lines[1] == "" and lines[3] == ""  # blanks kept
    rec1 = json.loads(lines[0])               # every non-blank line valid JSON
    rec2 = json.loads(lines[2])
    assert rec1["host"].startswith("<IP_") and rec1["mail"].startswith("<EMAIL_")
    assert rec2["tags"][0].startswith("<EMAIL_") and rec2["tags"][1] == 7


# ----------------------------------------------------------------------
# Broken structured input -> TEXT path fallback (never copy-through raw PII).

def test_broken_json_falls_back_to_text_scrub(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    raw = '{"user": "alice@example.com", oops trailing 10.0.0.9\n'
    (src / "broken.json").write_text(raw, encoding="utf-8")
    stats = _run(src, dst)

    # NOT copied through, NOT extracted: processed on the plain text path.
    assert stats.files_extracted == 0 and stats.files_copied == 0
    assert stats.files_processed == 1
    assert stats.per_file[0].status == "processed"
    body = (dst / "broken.json").read_text(encoding="utf-8")
    assert body != raw                                   # not the raw original
    assert "alice@example.com" not in body and "10.0.0.9" not in body
    assert "<EMAIL_1>" in body and "<IP_1>" in body
    assert "oops trailing" in body       # rest of the text survives unchanged
    assert any("broken.json" in w and "structured parse failed" in w
               for w in stats.warnings)


def test_bad_jsonl_line_fails_whole_file_to_text_path(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "mixed.jsonl").write_text(
        '{"mail": "alice@example.com"}\nnot json at all 10.0.0.9\n',
        encoding="utf-8",
    )
    stats = _run(src, dst)

    assert stats.files_extracted == 0 and stats.files_processed == 1
    body = (dst / "mixed.jsonl").read_text(encoding="utf-8")
    assert "alice@example.com" not in body and "10.0.0.9" not in body
    assert "<EMAIL_1>" in body and "<IP_1>" in body


# ----------------------------------------------------------------------
# scan (write=False): counts + aliases populated, nothing written.

def test_scan_counts_but_writes_nothing(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "data.csv").write_text(
        "host;mail\ncore1;alice@example.com\nedge9;10.0.0.9\n",
        encoding="utf-8",
    )
    amap = AliasMap()
    stats = _run(src, None, write=False, amap=amap)

    assert stats.files_extracted == 1
    assert stats.replacements >= 2
    # nothing written anywhere; source untouched
    assert list(src.iterdir()) == [src / "data.csv"]
    assert "alice@example.com" in (src / "data.csv").read_text(encoding="utf-8")
    # aliases still populated so scan reflects what strip would do
    assert any(m["category"] == "email" for m in amap.decode_table().values())


# ----------------------------------------------------------------------
# disable={"structured"} -> old plain-text path (formatting preserved).

def test_disable_structured_restores_text_path(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "cfg.json").write_text('{"h":"10.0.0.9"}', encoding="utf-8")
    stats = _run(src, dst, extract=ExtractConfig(disable={"structured"}))

    assert stats.files_extracted == 0 and stats.files_copied == 0
    assert stats.files_processed == 1
    # Text path: in-place regex substitution, original compact formatting kept
    # (the structured handler would have re-serialised with indent=2).
    assert (dst / "cfg.json").read_text(encoding="utf-8") == '{"h":"<IP_1>"}'


# ----------------------------------------------------------------------
# A .csv member inside a zip routes through the structured handler.

def test_csv_member_inside_zip_routed_through_structured(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inventory.csv",
                   "host;mail\ncore1;alice@example.com\n")   # '\n' endings
    (src / "bundle.zip").write_bytes(buf.getvalue())
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    rec = stats.extracted[0]
    assert rec.kind == "repack" and rec.out_rel == "bundle.zip"
    assert rec.members_processed == 1 and rec.members_copied == 0

    with zipfile.ZipFile(dst / "bundle.zip") as z:
        assert z.namelist() == ["inventory.csv"]          # same member name
        member = z.read("inventory.csv")
    # csv.writer re-serialised the member with the sniffed dialect's '\r\n'
    # line terminator — proof it went through the structured handler, not the
    # archive's plain text-member path (which substitutes in place).
    assert b"\r\n" in member
    body = member.decode("utf-8")
    assert "alice@example.com" not in body
    rows = list(csv.reader(io.StringIO(body, newline=""), delimiter=";"))
    assert rows[0] == ["host", "mail"]
    assert rows[1][0] == "core1" and rows[1][1].startswith("<EMAIL_")


# ----------------------------------------------------------------------
# max_out_bytes trip -> ExtractError -> text-path fallback (never raw copy).

def test_max_out_bytes_trip_falls_back_to_text_path(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "big.csv").write_text(
        "host;mail\ncore1;alice@example.com\n", encoding="utf-8")
    stats = _run(src, dst,
                 extract=ExtractConfig(limits=ExtractLimits(max_out_bytes=8)))

    assert stats.files_extracted == 0 and stats.files_copied == 0
    assert stats.files_processed == 1
    body = (dst / "big.csv").read_text(encoding="utf-8")
    assert "alice@example.com" not in body and "<EMAIL_1>" in body
    assert any("big.csv" in w and "structured parse failed" in w
               and "max_out_bytes" in w for w in stats.warnings)


# ----------------------------------------------------------------------
# json: PII in dict KEYS is aliased and the output stays valid JSON
# (regression — pre-v4 whole-text tokenize aliased keys; the field-aware
# handler used to ship IP-/email-keyed objects untouched).

def test_json_ip_and_email_keys_aliased_output_still_valid(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    doc = {
        "192.0.2.50": "gateway",             # IP as KEY (RFC-5737 TEST-NET-1)
        "user@corp.example.com": "admin",    # email as KEY (RFC-2606 domain)
    }
    (src / "keys.json").write_text(json.dumps(doc), encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "keys.json").read_text(encoding="utf-8")
    assert "192.0.2.50" not in body and "user@corp.example.com" not in body

    parsed = json.loads(body)                # output is still valid JSON
    keys = sorted(parsed)                     # both keys are now aliases
    assert len(keys) == 2
    assert any(k.startswith("<IP_") for k in keys)
    assert any(k.startswith("<EMAIL_") for k in keys)
    # values ride along with their (now-aliased) keys, unchanged
    assert set(parsed.values()) == {"gateway", "admin"}


# ----------------------------------------------------------------------
# json: a Luhn-valid card number typed as a JSON NUMBER must not survive its
# type — it is aliased and lands in the output as a STRING (type change is
# intentional; pre-v4 the whole-text path aliased the digits in place).

def test_json_numeric_credit_card_value_aliased_as_string(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    doc = {"cc": 4111111111111111, "port": 443, "flag": True, "empty": None}
    (src / "pay.json").write_text(json.dumps(doc), encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "pay.json").read_text(encoding="utf-8")
    assert "4111111111111111" not in body

    parsed = json.loads(body)
    assert isinstance(parsed["cc"], str) and parsed["cc"].startswith("<CC_")
    # clean number / bool / null untouched (bool is filtered before the numeric
    # branch, so True does not get rendered-and-scrubbed)
    assert parsed["port"] == 443 and parsed["port"] != "443"
    assert parsed["flag"] is True and parsed["empty"] is None


# ----------------------------------------------------------------------
# jsonl: PII in dict KEYS is aliased per line, every line stays valid JSON.

def test_jsonl_pii_keys_aliased_per_line(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "keyed.jsonl").write_text(
        '{"198.51.100.7": "seen"}\n'
        '{"ops@corp.example.com": "owner"}\n',
        encoding="utf-8",
    )
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "keyed.jsonl").read_text(encoding="utf-8")
    assert "198.51.100.7" not in body and "ops@corp.example.com" not in body
    lines = body.split("\n")
    rec0 = json.loads(lines[0])
    rec1 = json.loads(lines[1])
    assert list(rec0)[0].startswith("<IP_") and list(rec0.values()) == ["seen"]
    assert list(rec1)[0].startswith("<EMAIL_") and list(rec1.values()) == ["owner"]


# ----------------------------------------------------------------------
# csv: a degenerate single-column file must NOT let the Sniffer split a
# delimiter out of the PII. Constrained sniffing fails -> excel fallback ->
# one cell per row -> each value scrubbed whole.

def test_csv_single_column_ips_scrubbed_one_column(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "ips.csv").write_text(
        "10.11.12.13\n10.11.12.14\n10.11.12.15\n", encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "ips.csv").read_text(encoding="utf-8")
    assert "10.11.12.13" not in body and "10.11.12.15" not in body
    rows = list(csv.reader(io.StringIO(body, newline="")))
    assert len(rows) == 3 and all(len(r) == 1 for r in rows)   # one column kept
    assert all(r[0].startswith("<IP_") for r in rows)


def test_csv_single_column_macs_scrubbed_one_column(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "macs.csv").write_text(
        "aa:bb:cc:dd:ee:01\naa:bb:cc:dd:ee:02\n", encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "macs.csv").read_text(encoding="utf-8")
    assert "aa:bb:cc:dd:ee:01" not in body and "aa:bb:cc:dd:ee:02" not in body
    rows = list(csv.reader(io.StringIO(body, newline="")))
    assert len(rows) == 2 and all(len(r) == 1 for r in rows)   # colon NOT a delim
    assert all(r[0].startswith("<MAC_") for r in rows)


# ----------------------------------------------------------------------
# Regression guard for the constrained delimiter set: a legitimate multi-column
# semicolon CSV is still sniffed as ';' and round-trips (not swallowed by the
# fallback) — proof the delimiter restriction did not break real dialects.

def test_csv_semicolon_delimiter_still_sniffed_and_round_trips(tmp_path: Path):
    sample = (
        "host;owner;ip\n"
        "core1;alice@example.com;10.20.30.40\n"
        "edge2;bob@example.com;10.20.30.41\n"
    )
    assert _csv_dialect(sample).delimiter == ";"   # ';' is in the allowed set

    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "inv.csv").write_text(sample, encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "inv.csv").read_text(encoding="utf-8")
    assert "alice@example.com" not in body and "10.20.30.40" not in body
    rows = list(csv.reader(io.StringIO(body, newline=""), delimiter=";"))
    assert len(rows) == 3 and all(len(r) == 3 for r in rows)   # 3 columns intact
    assert rows[0] == ["host", "owner", "ip"]
    assert rows[1][0] == "core1" and rows[1][1].startswith("<EMAIL_")
    assert rows[1][2].startswith("<IP_")


# ----------------------------------------------------------------------
# json: documented edge — two DISTINCT source keys that scrub to the SAME
# string collapse to ONE key, deterministic LAST-WINS (the later value stays).
# Here the first key is raw PII and the second is already that PII's alias
# text, so both resolve to <IP_1>.

def test_json_post_scrub_duplicate_key_last_wins(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    # "10.0.0.9" -> "<IP_1>"; the literal "<IP_1>" is not PII, so it stays
    # "<IP_1>" -> both keys collide. json source keeps insertion order, so the
    # second ("last") value wins.
    (src / "dup.json").write_text(
        '{"10.0.0.9": "first", "<IP_1>": "second"}', encoding="utf-8")
    stats = _run(src, dst)

    assert stats.files_extracted == 1
    body = (dst / "dup.json").read_text(encoding="utf-8")
    assert "10.0.0.9" not in body
    parsed = json.loads(body)                    # still valid JSON
    assert parsed == {"<IP_1>": "second"}        # one key, last-wins value
