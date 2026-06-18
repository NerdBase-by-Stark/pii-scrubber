"""Tests for the v2 core: entity aliasing, cross-run vault, manifest, profiles."""

import json
from pathlib import Path

import pytest

from piiscrub.cli import main
from piiscrub.config import resolve_config
from piiscrub.engine import AliasMap
from piiscrub import manifest as manifest_mod


def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


# ---- entity aliasing ---------------------------------------------------

def test_entity_scoped_aliases(tmp_path, capsys):
    src = tmp_path / "src"
    _write(src / "a.log", "host SRV-AB12 at 10.0.0.5 then 10.0.0.5 again\n")
    entities = tmp_path / "entities.csv"
    entities.write_text(
        "id,type,pretty_name,identifiers,notes\n"
        "core-switch,device,Core Switch Alpha,10.0.0.5;SRV-AB12,core\n",
        encoding="utf-8",
    )
    dst = tmp_path / "dst"
    rc = main(["strip", str(src), str(dst), "--entities", str(entities)])
    assert rc == 0
    out = (dst / "a.log").read_text(encoding="utf-8")
    # entity-scoped, zero-padded device id, identifier type preserved
    assert "<DEV0001.HOST_1>" in out
    assert "<DEV0001.IP_1>" in out
    assert out.count("<DEV0001.IP_1>") == 2  # consistency within the entity
    assert "10.0.0.5" not in out and "SRV-AB12" not in out
    # pretty name kept in the decode map (vault legend / decode), not in output
    decode = json.loads((src / "_pii" / "decode.json").read_text())
    assert any(m.get("entity") == "core-switch" for m in decode.values())
    assert "Core Switch Alpha" not in out


# ---- cross-run vault ---------------------------------------------------

def test_cross_run_vault_same_alias(tmp_path, capsys):
    project = tmp_path / "vault"
    src1 = tmp_path / "run1"; _write(src1 / "x.log", "ip 10.9.9.9 here")
    src2 = tmp_path / "run2"; _write(src2 / "y.log", "ip 10.9.9.9 there")
    rc1 = main(["strip", str(src1), str(tmp_path / "out1"), "--project", str(project)])
    rc2 = main(["strip", str(src2), str(tmp_path / "out2"), "--project", str(project)])
    assert rc1 == 0 and rc2 == 0
    o1 = (tmp_path / "out1" / "x.log").read_text(encoding="utf-8")
    o2 = (tmp_path / "out2" / "y.log").read_text(encoding="utf-8")
    assert "<IP_1>" in o1 and "<IP_1>" in o2          # same alias across runs
    assert (project / "map.json").is_file()
    assert not (project / ".lock").exists()           # lock released


def test_vault_reverse_roundtrip(tmp_path, capsys):
    project = tmp_path / "vault"
    src = tmp_path / "src"; _write(src / "a.log", "mail x@y.com ip 10.1.1.1\n")
    dst = tmp_path / "dst"
    main(["strip", str(src), str(dst), "--project", str(project)])
    restored = tmp_path / "r.log"
    rc = main(["reverse", str(dst / "a.log"), str(restored), "--map", str(project / "map.json")])
    assert rc == 0
    assert restored.read_text(encoding="utf-8") == (src / "a.log").read_text(encoding="utf-8")


# ---- chain-of-custody manifest ----------------------------------------

def test_manifest_has_hashes_and_digest(tmp_path, capsys):
    src = tmp_path / "src"; _write(src / "a.log", "ip 10.2.2.2\n")
    dst = tmp_path / "dst"
    main(["strip", str(src), str(dst)])
    manifest = json.loads((src / "_pii" / "manifest.json").read_text())
    assert manifest["file_count"] == 1
    assert len(manifest["run_digest_sha256"]) == 64
    rec = manifest["files"][0]
    assert rec["source_sha256"] == manifest_mod.hash_file(src / "a.log")
    assert rec["output_sha256"] == manifest_mod.hash_file(dst / "a.log")
    assert rec["source_sha256"] != rec["output_sha256"]   # content changed


# ---- profiles ----------------------------------------------------------

def test_profile_network_gear_disables_credit_card(tmp_path, capsys):
    src = tmp_path / "src"
    _write(src / "a.log", "card 4111 1111 1111 1111 ip 10.3.3.3\n")
    dst = tmp_path / "dst"
    rc = main(["strip", str(src), str(dst), "--profile", "network-gear"])
    assert rc == 0
    out = (dst / "a.log").read_text(encoding="utf-8")
    assert "4111 1111 1111 1111" in out      # credit_card disabled by profile
    assert "10.3.3.3" not in out             # ip still stripped


def test_resolve_config_layers_profile_then_cli():
    cfg = resolve_config("network-gear", None)
    assert "credit_card" in cfg.disable


# ---- starter entity CSV ------------------------------------------------

def test_late_arriving_entity_supersedes_plain_alias(tmp_path, capsys):
    """An IP seen plain on run 1 must not end up with two unrelated aliases when
    the operator later groups it into an entity. Old outputs must still reverse."""
    project = tmp_path / "vault"
    # run 1: no entity table yet -> plain <IP_1>
    src1 = tmp_path / "run1"; _write(src1 / "a.log", "ip 10.5.5.5 seen")
    out1 = tmp_path / "out1"
    main(["strip", str(src1), str(out1), "--project", str(project)])
    assert "<IP_1>" in (out1 / "a.log").read_text(encoding="utf-8")

    # operator now learns 10.5.5.5 + SRV-ZZ are the same device
    (project / "entities.csv").write_text(
        "id,type,pretty_name,identifiers,notes\n"
        "boxzz,device,Box ZZ,10.5.5.5;SRV-ZZ,late\n", encoding="utf-8")

    # run 2: same IP now resolves to the entity alias
    src2 = tmp_path / "run2"; _write(src2 / "b.log", "ip 10.5.5.5 host SRV-ZZ")
    out2 = tmp_path / "out2"
    main(["strip", str(src2), str(out2), "--project", str(project)])
    new_out = (out2 / "b.log").read_text(encoding="utf-8")
    assert "<DEV0001.IP_1>" in new_out and "<DEV0001.HOST_1>" in new_out

    # vault records the supersession + equivalence
    vault_map = json.loads((project / "map.json").read_text())
    assert vault_map["entries"]["<IP_1>"]["superseded_by"] == "<DEV0001.IP_1>"
    legend = json.loads((project / "legend.json").read_text())
    assert "<IP_1>" in legend["DEV0001"]["superseded_aliases"]

    # CRITICAL: the OLD output (still using <IP_1>) must still reverse correctly
    restored = tmp_path / "r1.log"
    main(["reverse", str(out1 / "a.log"), str(restored), "--map", str(project / "map.json")])
    assert "10.5.5.5" in restored.read_text(encoding="utf-8")


def test_emit_starter_entities(tmp_path, capsys):
    src = tmp_path / "src"
    _write(src / "a.log", "host db1.internal.corp ip 10.4.4.4\n")
    rc = main(["scan", str(src), "--emit-entities"])
    assert rc == 0
    starter = src / "_pii" / "entities_starter.csv"
    assert starter.is_file()
    body = starter.read_text(encoding="utf-8")
    assert "db1.internal.corp" in body and "10.4.4.4" in body
    assert body.splitlines()[0].startswith("id,type,pretty_name,identifiers,notes")
