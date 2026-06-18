"""Tests for the reconcile subcommand and its supporting functions."""

import hashlib
import json
from pathlib import Path

import pytest

from piiscrub.cli import main
from piiscrub.reconcile import build_canonical_map, reconcile_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def _make_vault_map(entries: dict) -> dict:
    """Wrap an entries dict in valid vault-schema shape."""
    return {
        "_schema": "piiscrub-vault/1",
        "entries": entries,
        "key_index": {},
        "counters": {},
        "entities": {},
        "entity_counters": {},
    }


# ---------------------------------------------------------------------------
# Unit tests: build_canonical_map
# ---------------------------------------------------------------------------

def test_build_canonical_map_basic():
    table = {
        "<IP_1>": {"original": "10.0.0.1", "category": "ipv4", "count": 1, "files": [],
                   "entity": None, "superseded_by": "<DEV0001.IP_1>"},
        "<DEV0001.IP_1>": {"original": "10.0.0.1", "category": "ipv4", "count": 0,
                           "files": [], "entity": "core-sw"},
    }
    cmap = build_canonical_map(table)
    assert cmap == {"<IP_1>": "<DEV0001.IP_1>"}


def test_build_canonical_map_multihop():
    table = {
        "<A_1>": {"original": "x", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<B_1>"},
        "<B_1>": {"original": "x", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<C_1>"},
        "<C_1>": {"original": "x", "category": "test", "count": 0, "files": [], "entity": None},
    }
    cmap = build_canonical_map(table)
    assert cmap["<A_1>"] == "<C_1>"
    assert cmap["<B_1>"] == "<C_1>"
    assert "<C_1>" not in cmap


def test_build_canonical_map_cycle_guard():
    """A pure 2-node cycle has no terminal outside the cycle — result must be {}."""
    table = {
        "<A_1>": {"original": "x", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<B_1>"},
        "<B_1>": {"original": "x", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<A_1>"},
    }
    assert build_canonical_map(table) == {}


def test_build_canonical_map_three_node_cycle():
    """A 3-node cycle has no terminal — result must be {} and must not hang."""
    table = {
        "<A_1>": {"original": "x", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<B_1>"},
        "<B_1>": {"original": "x", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<C_1>"},
        "<C_1>": {"original": "x", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<A_1>"},
    }
    assert build_canonical_map(table) == {}


def test_build_canonical_map_dangling_pointer():
    """A superseded_by that points outside the table is treated as terminal."""
    table = {
        "<IP_1>": {"original": "10.0.0.1", "category": "ipv4", "count": 0, "files": [],
                   "entity": None, "superseded_by": "<DEV0001.IP_1>"},
        # <DEV0001.IP_1> is NOT in table (dangling)
    }
    cmap = build_canonical_map(table)
    assert cmap["<IP_1>"] == "<DEV0001.IP_1>"


def test_build_canonical_map_no_supersessions():
    table = {
        "<IP_1>": {"original": "10.0.0.1", "category": "ipv4", "count": 1, "files": [], "entity": None},
    }
    assert build_canonical_map(table) == {}


# ---------------------------------------------------------------------------
# Unit tests: reconcile_text
# ---------------------------------------------------------------------------

def test_reconcile_text_basic():
    text = "connect from <IP_1> via <IP_1> again"
    cmap = {"<IP_1>": "<DEV0001.IP_1>"}
    new_text, n = reconcile_text(text, cmap)
    assert new_text == "connect from <DEV0001.IP_1> via <DEV0001.IP_1> again"
    assert n == 2


def test_reconcile_text_empty_map():
    text = "no change <IP_1>"
    new_text, n = reconcile_text(text, {})
    assert new_text == text
    assert n == 0


def test_reconcile_text_prefix_safety():
    """<IP_10> and <IP_1> must map to their own canonicals, not mangle each other."""
    cmap = {"<IP_1>": "<DEV0001.IP_1>", "<IP_10>": "<DEV0002.IP_1>"}
    text = "src=<IP_10> dst=<IP_1>"
    new_text, n = reconcile_text(text, cmap)
    assert "<DEV0002.IP_1>" in new_text   # <IP_10> -> DEV0002
    assert "<DEV0001.IP_1>" in new_text   # <IP_1>  -> DEV0001
    assert "<IP_10>" not in new_text
    assert "<IP_1>" not in new_text
    assert n == 2


# ---------------------------------------------------------------------------
# End-to-end CLI test: supersession scenario
# ---------------------------------------------------------------------------

def test_reconcile_e2e_supersession(tmp_path, capsys):
    """Strip run1 -> <IP_1>; add entity; strip run2 -> supersession recorded;
    reconcile out1 -> out1_reconciled has <DEV0001.IP_1>, out1 is UNCHANGED."""
    project = tmp_path / "vault"

    # run 1: no entity table -> plain <IP_1>
    src1 = tmp_path / "run1"
    _write(src1 / "host.log", "connected from 10.1.2.3 at 10.1.2.3 again\n")
    out1 = tmp_path / "out1"
    rc = main(["strip", str(src1), str(out1), "--project", str(project)])
    assert rc == 0
    out1_content_before = (out1 / "host.log").read_text(encoding="utf-8")
    assert "<IP_1>" in out1_content_before

    # operator groups 10.1.2.3 + core-alpha into entity
    _write(project / "entities.csv",
           "id,type,pretty_name,identifiers,notes\n"
           "core-alpha,device,Core Switch Alpha,10.1.2.3;core-alpha.example.com,primary\n")

    # run 2: entity alias assigned + supersession recorded
    src2 = tmp_path / "run2"
    _write(src2 / "switch.log", "host core-alpha.example.com ip 10.1.2.3\n")
    out2 = tmp_path / "out2"
    rc = main(["strip", str(src2), str(out2), "--project", str(project)])
    assert rc == 0
    out2_content = (out2 / "switch.log").read_text(encoding="utf-8")
    assert "<DEV0001.IP_1>" in out2_content

    # confirm vault recorded supersession
    vault_map = json.loads((project / "map.json").read_text())
    assert vault_map["entries"]["<IP_1>"]["superseded_by"] == "<DEV0001.IP_1>"

    # reconcile out1 -> out1_reconciled
    out1_rec = tmp_path / "out1_reconciled"
    rc = main(["reconcile", str(out1), str(out1_rec), "--project", str(project)])
    assert rc == 0

    # reconciled file has canonical alias, not plain
    rec_content = (out1_rec / "host.log").read_text(encoding="utf-8")
    assert "<DEV0001.IP_1>" in rec_content
    assert "<IP_1>" not in rec_content

    # CUSTODY: original out1 is UNCHANGED
    assert (out1 / "host.log").read_text(encoding="utf-8") == out1_content_before

    # manifest.json present with correct file_count
    manifest = json.loads((out1_rec / "_pii" / "manifest.json").read_text())
    assert manifest["file_count"] >= 1

    # reconcile_map.json maps <IP_1> -> <DEV0001.IP_1>
    cmap = json.loads((out1_rec / "_pii" / "reconcile_map.json").read_text())
    assert cmap["<IP_1>"] == "<DEV0001.IP_1>"

    # reconciled file can be reversed back to original value
    restored = tmp_path / "restored.log"
    rc = main(["reverse", str(out1_rec / "host.log"), str(restored),
               "--map", str(project / "map.json")])
    assert rc == 0
    assert "10.1.2.3" in restored.read_text(encoding="utf-8")


def test_reconcile_converges_fqdn_and_ip_together(tmp_path, capsys):
    """A delivered output whose run-1 file held BOTH a plain IP and a plain FQDN
    must converge BOTH to their entity aliases after the operator groups them.
    Guards the composition of the FQDN-supersession fix with reconcile: before
    that fix the host link was never recorded, so <HOST_1> stayed stale."""
    project = tmp_path / "vault"

    # run 1: no entity table -> plain <IP_1> AND plain <HOST_1>
    src1 = tmp_path / "run1"
    _write(src1 / "host.log", "host node-alpha.example.com ip 10.1.2.3\n")
    out1 = tmp_path / "out1"
    assert main(["strip", str(src1), str(out1), "--project", str(project)]) == 0
    before = (out1 / "host.log").read_text(encoding="utf-8")
    assert "<HOST_1>" in before and "<IP_1>" in before

    # operator groups the IP + the FQDN into one device
    _write(project / "entities.csv",
           "id,type,pretty_name,identifiers,notes\n"
           "core-a,device,Core Alpha,10.1.2.3;node-alpha.example.com,primary\n")

    # run 2: entity aliases assigned + supersession recorded for BOTH
    src2 = tmp_path / "run2"
    _write(src2 / "switch.log", "node-alpha.example.com 10.1.2.3\n")
    assert main(["strip", str(src2), str(tmp_path / "out2"), "--project", str(project)]) == 0

    # reconcile the delivered out1
    out1_rec = tmp_path / "out1_reconciled"
    assert main(["reconcile", str(out1), str(out1_rec), "--project", str(project)]) == 0
    rec = (out1_rec / "host.log").read_text(encoding="utf-8")
    assert "<DEV0001.HOST_1>" in rec and "<DEV0001.IP_1>" in rec
    assert "<HOST_1>" not in rec and "<IP_1>" not in rec

    cmap = json.loads((out1_rec / "_pii" / "reconcile_map.json").read_text())
    assert cmap["<HOST_1>"] == "<DEV0001.HOST_1>"
    assert cmap["<IP_1>"] == "<DEV0001.IP_1>"

    # custody: delivered out1 unchanged
    assert (out1 / "host.log").read_text(encoding="utf-8") == before


# ---------------------------------------------------------------------------
# No decode.json leak into reconciled output
# ---------------------------------------------------------------------------

def test_no_decode_json_leak_in_reconciled_output(tmp_path, capsys):
    """_pii/ content from the INPUT tree must NOT appear in the reconciled tree."""
    project = tmp_path / "vault"

    # Create an input tree that already has a _pii/ subdirectory with sidecars
    src = tmp_path / "src"
    _write(src / "data.log", "ip 192.0.2.50 seen\n")
    out_base = tmp_path / "out_base"
    rc = main(["strip", str(src), str(out_base), "--project", str(project)])
    assert rc == 0

    # Manually plant a decode.json inside the input stripped tree (simulating
    # a standalone stripped tree that has _pii/decode.json alongside it)
    pii_dir = out_base / "_pii"
    pii_dir.mkdir(exist_ok=True)
    _write(pii_dir / "decode.json", json.dumps({"<IP_1>": {"original": "192.0.2.50"}}))

    out_rec = tmp_path / "out_rec"
    rc = main(["reconcile", str(out_base), str(out_rec), "--project", str(project)])
    assert rc == 0

    # decode.json must not exist directly in out_rec or in out_rec/_pii
    assert not (out_rec / "decode.json").exists()
    assert not (out_rec / "_pii" / "decode.json").exists()


def test_nested_pii_dir_not_copied(tmp_path, capsys):
    """A _pii dir at any nesting depth in the input is excluded from the reconciled output."""
    project = tmp_path / "vault"
    src = tmp_path / "src"
    _write(src / "sub" / "app.log", "host 10.5.6.7 active\n")
    # Nested _pii with a decode.json — must NOT appear in output
    _write(src / "sub" / "_pii" / "decode.json", json.dumps({"<IP_1>": {"original": "10.5.6.7"}}))

    out_base = tmp_path / "stripped"
    main(["strip", str(src), str(out_base), "--project", str(project)])

    # Plant the same nested _pii in the stripped tree as well
    _write(out_base / "sub" / "_pii" / "decode.json",
           json.dumps({"<IP_1>": {"original": "10.5.6.7"}}))

    out_rec = tmp_path / "reconciled"
    rc = main(["reconcile", str(out_base), str(out_rec), "--project", str(project)])
    assert rc == 0

    # sub/app.log IS present
    assert (out_rec / "sub" / "app.log").exists()
    # No decode.json anywhere under the output
    assert list(out_rec.rglob("decode.json")) == []


def test_input_pii_dir_not_copied(tmp_path, capsys):
    """A _pii/ directory in the input tree is never copied to the reconciled output."""
    project = tmp_path / "vault"
    src = tmp_path / "src"
    _write(src / "app.log", "host 10.5.6.7 active\n")
    out_base = tmp_path / "stripped"
    main(["strip", str(src), str(out_base), "--project", str(project)])

    # Plant an extra file in _pii to verify exclusion
    _write(out_base / "_pii" / "secret_token.txt", "supersecret")

    out_rec = tmp_path / "reconciled"
    rc = main(["reconcile", str(out_base), str(out_rec), "--project", str(project)])
    assert rc == 0
    assert not (out_rec / "_pii" / "secret_token.txt").exists()


# ---------------------------------------------------------------------------
# Multi-hop chain following
# ---------------------------------------------------------------------------

def test_multihop_chain_via_map_file(tmp_path, capsys):
    """<A_1> -> <B_1> -> <C_1>: file containing <A_1> should become <C_1>."""
    entries = {
        "<A_1>": {"original": "val-a", "category": "test", "count": 1, "files": [],
                  "entity": None, "superseded_by": "<B_1>"},
        "<B_1>": {"original": "val-a", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<C_1>"},
        "<C_1>": {"original": "val-a", "category": "test", "count": 0, "files": [], "entity": None},
    }
    map_file = tmp_path / "map.json"
    map_file.write_text(json.dumps(_make_vault_map(entries)), encoding="utf-8")

    src = tmp_path / "src"
    _write(src / "data.txt", "token is <A_1> here\n")

    dst = tmp_path / "dst"
    rc = main(["reconcile", str(src), str(dst), "--map", str(map_file)])
    assert rc == 0
    out = (dst / "data.txt").read_text(encoding="utf-8")
    assert "<C_1>" in out
    assert "<A_1>" not in out
    assert "<B_1>" not in out


# ---------------------------------------------------------------------------
# Cycle guard (unit-level already tested above; CLI-level smoke)
# ---------------------------------------------------------------------------

def test_cycle_in_map_does_not_hang(tmp_path, capsys):
    """reconcile with a cyclic supersession chain must return promptly."""
    entries = {
        "<A_1>": {"original": "v", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<B_1>"},
        "<B_1>": {"original": "v", "category": "test", "count": 0, "files": [],
                  "entity": None, "superseded_by": "<A_1>"},
    }
    map_file = tmp_path / "map.json"
    map_file.write_text(json.dumps(_make_vault_map(entries)), encoding="utf-8")

    src = tmp_path / "src"
    _write(src / "f.txt", "<A_1> and <B_1>\n")

    dst = tmp_path / "dst"
    rc = main(["reconcile", str(src), str(dst), "--map", str(map_file)])
    assert rc == 0


# ---------------------------------------------------------------------------
# No-op: zero supersessions
# ---------------------------------------------------------------------------

def test_noop_zero_supersessions(tmp_path, capsys):
    """When the map has no supersessions, output files are byte-identical to input."""
    project = tmp_path / "vault"
    src = tmp_path / "src"
    _write(src / "clean.log", "prefix <IP_1> suffix\n")
    out_base = tmp_path / "stripped"
    main(["strip", str(src), str(out_base), "--project", str(project)])

    # No entities added, so map has no superseded_by entries.
    # Drain capsys buffer from the strip call before running reconcile.
    capsys.readouterr()

    out_rec = tmp_path / "reconciled"
    rc = main(["reconcile", str(out_base), str(out_rec), "--project", str(project)])
    assert rc == 0

    # The text file is byte-identical
    orig = (out_base / "clean.log").read_bytes()
    recon = (out_rec / "clean.log").read_bytes()
    assert orig == recon

    # stdout reports 0 replacements (only the reconcile output is in the buffer now)
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["replacements"] == 0
    assert result["aliases_reconciled"] == 0


# ---------------------------------------------------------------------------
# Binary copy-through
# ---------------------------------------------------------------------------

def test_binary_file_copied_byte_identical(tmp_path, capsys):
    """A .bin file in the input is copied through byte-for-byte."""
    project = tmp_path / "vault"
    src = tmp_path / "src"
    _write(src / "data.log", "ip 10.9.9.1\n")
    binary_content = bytes(range(256)) * 4
    (src / "firmware.bin").write_bytes(binary_content)

    out_base = tmp_path / "stripped"
    main(["strip", str(src), str(out_base), "--project", str(project)])

    out_rec = tmp_path / "reconciled"
    rc = main(["reconcile", str(out_base), str(out_rec), "--project", str(project)])
    assert rc == 0

    rec_bin = out_rec / "firmware.bin"
    assert rec_bin.exists()
    assert rec_bin.read_bytes() == binary_content


# ---------------------------------------------------------------------------
# FIX 1: refuse non-empty output directory
# ---------------------------------------------------------------------------

def test_reconcile_refuses_nonempty_output(tmp_path):
    """reconcile must raise SystemExit when the output dir already has files."""
    project = tmp_path / "vault"
    src = tmp_path / "src"
    _write(src / "data.log", "ip 10.0.0.1 active\n")
    out_base = tmp_path / "stripped"
    rc = main(["strip", str(src), str(out_base), "--project", str(project)])
    assert rc == 0

    # Pre-populate the intended output dir with a stray file
    out_nonempty = tmp_path / "out_nonempty"
    out_nonempty.mkdir()
    (out_nonempty / "stray.txt").write_text("leftover", encoding="utf-8")

    with pytest.raises(SystemExit):
        main(["reconcile", str(out_base), str(out_nonempty), "--project", str(project)])


# ---------------------------------------------------------------------------
# FIX 5: --map flag takes priority over --project
# ---------------------------------------------------------------------------

def test_map_flag_takes_priority_over_project(tmp_path):
    """When both --map and --project are given, --map's supersessions win."""
    # Build a real vault with NO supersessions via a strip
    project = tmp_path / "vault"
    src_base = tmp_path / "src_base"
    _write(src_base / "f.log", "dummy log\n")
    rc = main(["strip", str(src_base), str(tmp_path / "stripped_base"),
               "--project", str(project)])
    assert rc == 0

    # Build a standalone map.json that DOES have a supersession <X_1> -> <Y_1>
    entries = {
        "<X_1>": {"original": "val-x", "category": "test", "count": 1, "files": [],
                  "entity": None, "superseded_by": "<Y_1>"},
        "<Y_1>": {"original": "val-x", "category": "test", "count": 0, "files": [],
                  "entity": None},
    }
    map_file = tmp_path / "standalone_map.json"
    map_file.write_text(json.dumps(_make_vault_map(entries)), encoding="utf-8")

    # Input tree containing <X_1>
    src = tmp_path / "src_xtoken"
    _write(src / "data.txt", "token is <X_1> here\n")

    dst = tmp_path / "dst_xtoken"
    rc = main(["reconcile", str(src), str(dst),
               "--map", str(map_file), "--project", str(project)])
    assert rc == 0

    out = (dst / "data.txt").read_text(encoding="utf-8")
    # --map supersession applied: <X_1> -> <Y_1>
    assert "<Y_1>" in out
    assert "<X_1>" not in out


# ---------------------------------------------------------------------------
# FIX 6: friendly error on corrupt map file
# ---------------------------------------------------------------------------

def test_reconcile_corrupt_map_errors(tmp_path):
    """A non-JSON map file produces a SystemExit with a readable message."""
    src = tmp_path / "src"
    _write(src / "f.txt", "some content\n")

    bad_map = tmp_path / "map.json"
    bad_map.write_text("not json {{{", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(["reconcile", str(src), str(tmp_path / "dst"),
              "--map", str(bad_map)])
    msg = str(excinfo.value).lower()
    assert "map" in msg and ("invalid" in msg or "json" in msg)


def test_reconcile_wrong_shape_map_errors(tmp_path):
    """Valid JSON with the wrong structure (not an alias->object table) fails
    fast with a readable SystemExit, not an opaque traceback later."""
    src = tmp_path / "src"
    _write(src / "f.txt", "<A_1> here\n")

    # valid JSON, but a list — not an alias table
    bad_shape = tmp_path / "map.json"
    bad_shape.write_text(json.dumps(["not", "a", "table"]), encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(["reconcile", str(src), str(tmp_path / "dst"), "--map", str(bad_shape)])
    assert "map" in str(excinfo.value).lower()

    # valid JSON object, but an entry value is not an object
    bad_entry = tmp_path / "map2.json"
    bad_entry.write_text(json.dumps({"<A_1>": "should-be-an-object"}), encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["reconcile", str(src), str(tmp_path / "dst2"), "--map", str(bad_entry)])


def test_reconcile_output_is_a_file_errors(tmp_path):
    """If the output path already exists as a FILE, reconcile must refuse with a
    clear message rather than crashing on mkdir."""
    src = tmp_path / "src"
    _write(src / "f.txt", "<A_1> here\n")
    entries = {"<A_1>": {"original": "v", "category": "t", "count": 1, "files": [],
                         "entity": None, "superseded_by": "<B_1>"},
               "<B_1>": {"original": "v", "category": "t", "count": 0, "files": [],
                         "entity": None}}
    map_file = tmp_path / "map.json"
    map_file.write_text(json.dumps(_make_vault_map(entries)), encoding="utf-8")

    out_file = tmp_path / "out_is_file"
    out_file.write_text("i am a file, not a dir", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(["reconcile", str(src), str(out_file), "--map", str(map_file)])
    assert "not a directory" in str(excinfo.value).lower()
