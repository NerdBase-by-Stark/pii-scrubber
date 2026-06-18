"""Tests for gui_runner.py — headless, in-process, no Qt/PySide6."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from piiscrub.cli import main as cli_main
from piiscrub.gui_runner import RunOptions, run_scan, run_strip
from piiscrub.progress import ProgressEvent


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


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
