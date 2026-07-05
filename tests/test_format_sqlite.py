"""Tests for the sqlite format extractor (``.db`` / ``.sqlite`` / ``.sqlite3``).

All fixtures are real sqlite databases created in-test via the stdlib ``sqlite3``
module — no binary blobs are committed. Coverage mirrors the design's sqlite
bullets: PII in rows aliased in the ``.txt`` derivative, BLOBs rendered as
``<blob N bytes>`` (never hex), NULL/quoting handled, internal ``sqlite_*``
tables skipped, read-only open (source untouched), caps and corruption fail open
to copy-through + flag, and cross-cutting alias sharing with plain text files.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from piiscrub.config import ExtractConfig
from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap, tokenize
from piiscrub.formats import ExtractError, ExtractLimits, get_handler
from piiscrub.walker import process_tree


# ----------------------------------------------------------------------
# Helpers

def _make_db(path: Path, tables: dict[str, tuple[list[str], list[tuple]]]) -> None:
    """Create a sqlite db at ``path`` from ``{table: (columns, rows)}``.

    Columns are declared with no type affinity so the value's Python type alone
    decides storage (bytes -> BLOB), which is what the dumper keys off.
    """
    con = sqlite3.connect(path)
    try:
        for name, (cols, rows) in tables.items():
            collist = ", ".join(f'"{c}"' for c in cols)
            con.execute(f'CREATE TABLE "{name}" ({collist})')
            placeholders = ", ".join("?" for _ in cols)
            con.executemany(
                f'INSERT INTO "{name}" VALUES ({placeholders})', rows
            )
        con.commit()
    finally:
        con.close()


def _scrub_closure(amap: AliasMap):
    """A stand-in for the walker's scrub closure: tokenise with default
    detectors over the shared ``amap``."""
    dets = build_active()

    def scrub(rel: str, text: str) -> tuple[str, int]:
        new_text, reps = tokenize(text, dets, amap, file=rel)
        return new_text, len(reps)

    return scrub


def _handler():
    return get_handler(".db")


# ----------------------------------------------------------------------
# Registration

def test_sqlite_handler_registered_for_all_suffixes():
    h = _handler()
    assert h is not None and h.name == "sqlite"
    for suffix in (".db", ".sqlite", ".sqlite3", ".DB", ".SQLite3"):
        assert get_handler(suffix) is h


# ----------------------------------------------------------------------
# Core derivative: PII aliased, structure correct

def test_rows_pii_aliased_in_derivative(tmp_path: Path):
    db = tmp_path / "data.db"
    _make_db(db, {
        "users": (
            ["id", "email", "ip"],
            [(1, "alice@example.com", "10.0.0.9"),
             (2, "bob@corp.net", "192.168.1.1")],
        ),
    })
    amap = AliasMap()
    out = tmp_path / "out" / "data.db"
    oc = _handler().process(db, "data.db", out, _scrub_closure(amap),
                            write=True, limits=ExtractLimits())

    assert oc.kind == "derivative"
    assert oc.out_rel == "data.db.txt"
    assert oc.replacements == 4          # 2 emails + 2 ips

    deriv = tmp_path / "out" / "data.db.txt"
    body = deriv.read_text()
    # no raw PII survives
    for raw in ("alice@example.com", "bob@corp.net", "10.0.0.9", "192.168.1.1"):
        assert raw not in body
    # aliases present, table + header structure intact
    assert "# table: users" in body
    assert "id,email,ip" in body
    assert "<EMAIL_1>" in body and "<EMAIL_2>" in body
    assert "<IP_1>" in body and "<IP_2>" in body
    # original binary is NOT copied into the output tree
    assert not (tmp_path / "out" / "data.db").exists()


def test_blob_rendered_as_placeholder_never_hex(tmp_path: Path):
    # A blob whose bytes, if hex-dumped, would spell an IP-looking / secret token.
    blob = bytes.fromhex("0a0000090a000009")
    db = tmp_path / "b.db"
    _make_db(db, {"t": (["name", "data"], [("x", blob)])})
    amap = AliasMap()
    out = tmp_path / "out" / "b.db"
    _handler().process(db, "b.db", out, _scrub_closure(amap),
                       write=True, limits=ExtractLimits())
    body = (tmp_path / "out" / "b.db.txt").read_text()
    assert f"<blob {len(blob)} bytes>" in body
    # never emit the hex of the blob
    assert "0a0000090a000009" not in body
    assert blob.hex() not in body


def test_null_and_csv_quoting(tmp_path: Path):
    db = tmp_path / "q.db"
    _make_db(db, {
        "t": (
            ["a", "b", "c"],
            [("plain", None, 'has, comma "and" quote\nand newline')],
        ),
    })
    amap = AliasMap()
    out = tmp_path / "out" / "q.db"
    _handler().process(db, "q.db", out, _scrub_closure(amap),
                       write=True, limits=ExtractLimits())
    body = (tmp_path / "out" / "q.db.txt").read_text()
    # NULL -> empty field; the value with a comma/quote/newline is CSV-quoted so
    # the derivative re-parses as CSV with the exact cell values.
    import csv
    import io
    # locate the data row (after '# table: t' and header)
    lines = body.splitlines(keepends=True)
    # Re-parse the whole dump minus the comment/header lines for the data row.
    data_start = body.index("plain")
    row_text = body[data_start:]
    parsed = next(csv.reader(io.StringIO(row_text)))
    assert parsed[0] == "plain"
    assert parsed[1] == ""            # NULL
    assert parsed[2] == 'has, comma "and" quote\nand newline'


def test_multiple_tables_deterministic_order_and_headers(tmp_path: Path):
    db = tmp_path / "m.db"
    # Insert in non-alphabetical creation order; dumper sorts by name.
    _make_db(db, {
        "zeta": (["v"], [("z1",)]),
        "alpha": (["v"], [("a1",)]),
    })
    amap = AliasMap()
    out = tmp_path / "out" / "m.db"
    _handler().process(db, "m.db", out, _scrub_closure(amap),
                       write=True, limits=ExtractLimits())
    body = (tmp_path / "out" / "m.db.txt").read_text()
    assert body.index("# table: alpha") < body.index("# table: zeta")


def test_internal_sqlite_tables_skipped(tmp_path: Path):
    db = tmp_path / "seq.db"
    con = sqlite3.connect(db)
    try:
        # AUTOINCREMENT forces creation of the internal sqlite_sequence table.
        con.execute(
            "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        )
        con.execute("INSERT INTO users(name) VALUES('a')")
        con.commit()
    finally:
        con.close()
    amap = AliasMap()
    out = tmp_path / "out" / "seq.db"
    _handler().process(db, "seq.db", out, _scrub_closure(amap),
                       write=True, limits=ExtractLimits())
    body = (tmp_path / "out" / "seq.db.txt").read_text()
    assert "# table: users" in body
    assert "sqlite_sequence" not in body


def test_empty_table_emits_header_only(tmp_path: Path):
    db = tmp_path / "e.db"
    _make_db(db, {"empty": (["col_a", "col_b"], [])})
    amap = AliasMap()
    out = tmp_path / "out" / "e.db"
    oc = _handler().process(db, "e.db", out, _scrub_closure(amap),
                            write=True, limits=ExtractLimits())
    assert oc.replacements == 0
    body = (tmp_path / "out" / "e.db.txt").read_text()
    assert "# table: empty" in body
    assert "col_a,col_b" in body


def test_database_with_no_user_tables(tmp_path: Path):
    db = tmp_path / "blank.db"
    con = sqlite3.connect(db)
    con.close()   # creates a valid but empty database
    amap = AliasMap()
    out = tmp_path / "out" / "blank.db"
    oc = _handler().process(db, "blank.db", out, _scrub_closure(amap),
                            write=True, limits=ExtractLimits())
    assert oc.kind == "derivative" and oc.out_rel == "blank.db.txt"
    assert oc.replacements == 0
    assert (tmp_path / "out" / "blank.db.txt").exists()


# ----------------------------------------------------------------------
# Read-only guarantee + scan (write=False)

def test_source_not_mutated_and_readonly(tmp_path: Path):
    db = tmp_path / "ro.db"
    _make_db(db, {"t": (["email"], [("a@b.com",)])})
    before = db.read_bytes()
    amap = AliasMap()
    out = tmp_path / "out" / "ro.db"
    _handler().process(db, "ro.db", out, _scrub_closure(amap),
                       write=True, limits=ExtractLimits())
    assert db.read_bytes() == before
    # no WAL/journal sidecar left behind by the read-only open
    assert not (tmp_path / "ro.db-wal").exists()
    assert not (tmp_path / "ro.db-journal").exists()


def test_scan_write_false_writes_nothing_but_scrubs(tmp_path: Path):
    db = tmp_path / "s.db"
    _make_db(db, {"t": (["email", "ip"], [("a@b.com", "10.0.0.9")])})
    amap = AliasMap()
    oc = _handler().process(db, "s.db", None, _scrub_closure(amap),
                            write=False, limits=ExtractLimits())
    assert oc.replacements == 2
    # nothing written anywhere
    assert list(tmp_path.iterdir()) == [db]
    # but aliases were populated for the report
    cats = {m["category"] for m in amap.decode_table().values()}
    assert "email" in cats and "ipv4" in cats


# ----------------------------------------------------------------------
# Fail-open: caps + corruption raise ExtractError (walker copy-through + flag)

def test_max_members_cap_raises_and_deletes_partial(tmp_path: Path):
    db = tmp_path / "big.db"
    _make_db(db, {"t": (["v"], [(i,) for i in range(10)])})
    amap = AliasMap()
    out = tmp_path / "out" / "big.db"
    with pytest.raises(ExtractError, match="max_members"):
        _handler().process(db, "big.db", out, _scrub_closure(amap),
                           write=True, limits=ExtractLimits(max_members=3))
    # fail-open: no partial derivative left behind
    assert not (tmp_path / "out" / "big.db.txt").exists()


def test_max_out_bytes_cap_raises(tmp_path: Path):
    db = tmp_path / "wide.db"
    _make_db(db, {"t": (["v"], [("x" * 500,) for _ in range(50)])})
    amap = AliasMap()
    out = tmp_path / "out" / "wide.db"
    with pytest.raises(ExtractError, match="max_out_bytes"):
        _handler().process(db, "wide.db", out, _scrub_closure(amap),
                           write=True, limits=ExtractLimits(max_out_bytes=1024))
    assert not (tmp_path / "out" / "wide.db.txt").exists()


def test_corrupt_file_raises_extract_error(tmp_path: Path):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"this is not a sqlite database at all" * 4)
    amap = AliasMap()
    out = tmp_path / "out" / "corrupt.db"
    with pytest.raises(ExtractError, match="sqlite error"):
        _handler().process(bad, "corrupt.db", out, _scrub_closure(amap),
                           write=True, limits=ExtractLimits())
    assert not (tmp_path / "out" / "corrupt.db.txt").exists()


# ----------------------------------------------------------------------
# End-to-end through the walker

def test_process_tree_extracts_db(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    _make_db(src / "data.db", {
        "users": (["email", "ip"], [("alice@example.com", "10.0.0.9")]),
    })
    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_extracted == 1
    assert stats.files_copied == 0 and stats.files_processed == 0
    assert stats.replacements == 2
    # derivative written, original not mirrored
    assert (dst / "data.db.txt").exists()
    assert not (dst / "data.db").exists()
    body = (dst / "data.db.txt").read_text()
    assert "alice@example.com" not in body and "10.0.0.9" not in body
    # rich record for the report
    rec = stats.extracted[0]
    assert rec.rel == "data.db" and rec.out_rel == "data.db.txt"
    assert rec.kind == "derivative" and rec.replacements == 2


def test_process_tree_corrupt_db_copies_through_and_flags(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "corrupt.db").write_bytes(b"not a database" * 8)
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_extracted == 0
    assert stats.files_copied == 1
    # original copied through byte-for-byte
    assert (dst / "corrupt.db").read_bytes() == (src / "corrupt.db").read_bytes()
    assert not (dst / "corrupt.db.txt").exists()
    assert any(s.status == "binary" for s in stats.skipped)
    warn = next(w for w in stats.warnings if "corrupt.db" in w)
    assert "may contain PII" in warn
    assert "extraction skipped: sqlite error" in warn


def test_process_tree_no_extract_copies_through(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    _make_db(src / "data.db", {"t": (["email"], [("a@b.com",)])})
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set(),
                         extract=ExtractConfig(enabled=False))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    # .db is a BINARY_EXT -> copied through unchanged, no derivative
    assert (dst / "data.db").exists()
    assert not (dst / "data.db.txt").exists()


def test_process_tree_disable_sqlite_by_name(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    _make_db(src / "data.db", {"t": (["email"], [("a@b.com",)])})
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set(),
                         extract=ExtractConfig(disable={"sqlite"}))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "data.db").exists()
    assert not (dst / "data.db.txt").exists()


def test_process_tree_cap_trips_copy_through(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    _make_db(src / "data.db", {"t": (["v"], [(i,) for i in range(20)])})
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set(),
                         extract=ExtractConfig(limits=ExtractLimits(max_members=5)))
    assert stats.files_extracted == 0 and stats.files_copied == 1
    assert (dst / "data.db").read_bytes() == (src / "data.db").read_bytes()
    assert not (dst / "data.db.txt").exists()
    warn = next(w for w in stats.warnings if "data.db" in w)
    assert "extraction skipped" in warn and "max_members" in warn


# ----------------------------------------------------------------------
# Cross-cutting: shared amap aliases a value the same in a db and a plain log

def test_shared_alias_between_db_and_text(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    _make_db(src / "data.db", {"t": (["ip"], [("10.0.0.9",)])})
    (src / "app.log").write_text("connection from 10.0.0.9 established\n",
                                 encoding="utf-8")
    amap = AliasMap()
    process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                 write=True, exclude_dirs=set())
    db_body = (dst / "data.db.txt").read_text()
    log_body = (dst / "app.log").read_text()
    # same IP -> identical alias across both outputs
    assert "<IP_1>" in db_body and "<IP_1>" in log_body
    assert "10.0.0.9" not in db_body and "10.0.0.9" not in log_body


# ----------------------------------------------------------------------
# URI encoding: a source filename containing URI metacharacters ('?', '#', '%')
# must open the ACTUAL file, never a percent-decoded different path.

@pytest.mark.parametrize("fname", ["we?rd.db", "ta#g.db", "a%62.db"])
def test_uri_metachar_filenames_open_correct_db(tmp_path: Path, fname: str):
    # A decoy file whose name is what a naive raw-path URI would decode/truncate
    # to (e.g. 'a%62.db' -> 'ab.db', 'we?rd.db' -> 'we'); it holds DIFFERENT data
    # that must NEVER be dumped in place of the real file's data.
    real = tmp_path / fname
    _make_db(real, {"t": (["ip"], [("10.0.0.9",)])})
    for decoy in ("ab.db", "we", "ta"):
        d = tmp_path / decoy
        if not d.exists():
            _make_db(d, {"t": (["ip"], [("203.0.113.7",)])})
    amap = AliasMap()
    out = tmp_path / "out" / fname
    oc = _handler().process(real, fname, out, _scrub_closure(amap),
                            write=True, limits=ExtractLimits())
    body = (tmp_path / "out" / (fname + ".txt")).read_text()
    # the real file's IP was seen (aliased); the decoy's IP never leaks in.
    assert oc.replacements == 1
    assert "203.0.113.7" not in body
    assert "<IP_1>" in body
