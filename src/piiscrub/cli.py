"""Command-line interface: scan / strip / verify / reverse / --selftest.

Supports a central project vault (--project) for cross-run correlation, an
operator entity table (--entities), named profiles (--profile), and a
chain-of-custody manifest on every strip.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .audit import reverse_file, verify_tree
from .config import Config, resolve_config
from .detectors import build_active
from .engine import AliasMap
from . import entities as entities_mod
from . import llm as llm_mod
from . import manifest as manifest_mod
from .profiles import profile_names
from .progress import make_cli_renderer
from .projectmap import Vault, VaultLocked
from . import reconcile as reconcile_mod
from .report import build_summary, write_html, write_json
from .walker import process_tree

PII_DIRNAME = "_pii"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _merge_cli_into_config(cfg: Config, args: argparse.Namespace) -> Config:
    if getattr(args, "enable", None):
        cfg.enable |= set(args.enable)
    if getattr(args, "disable", None):
        cfg.disable |= set(args.disable)
    if getattr(args, "include", None):
        cfg.include += list(args.include)
    if getattr(args, "exclude", None):
        cfg.exclude += list(args.exclude)
    # FIX 4: use "is not None" so an explicit 0 is honoured (not silently
    # ignored by a falsy check), and reject non-positive values with a clear
    # message instead of letting 0/negative through.
    if getattr(args, "max_bytes", None) is not None:
        if args.max_bytes <= 0:
            raise SystemExit("error: --max-bytes must be > 0")
        cfg.max_bytes = args.max_bytes
    if getattr(args, "stream_threshold", None) is not None:
        if args.stream_threshold <= 0:
            raise SystemExit("error: --stream-threshold must be > 0")
        cfg.stream_threshold = args.stream_threshold
    return cfg


def _resolve(args: argparse.Namespace) -> Config:
    cfg = resolve_config(getattr(args, "profile", None),
                         Path(args.config) if getattr(args, "config", None) else None)
    return _merge_cli_into_config(cfg, args)


def _build_provider_cfg(cfg: Config, args: argparse.Namespace) -> llm_mod.ProviderCfg:
    """Layer the [llm] config table under the CLI flags (flags win). The key is
    NEVER taken from here — only the NAME of the env var holding it."""
    table = dict(cfg.llm or {})
    provider = getattr(args, "llm_provider", None) or table.get("provider") or "ollama"
    endpoint = getattr(args, "llm_endpoint", None) or table.get("endpoint") or ""
    model = getattr(args, "llm_model", None) or table.get("model") or ""
    key_env = getattr(args, "llm_key_env", None) or table.get("key_env") or "PIISCRUB_LLM_KEY"
    return llm_mod.ProviderCfg(
        provider=provider,
        endpoint=endpoint,
        model=model,
        key_env=key_env,
        allow_cloud=bool(getattr(args, "allow_cloud", False)),
        strict=bool(getattr(args, "llm_strict", False)),
        forget_key=bool(getattr(args, "forget_key", False)),
    )


def _llm_enabled(cfg: Config, args: argparse.Namespace) -> bool:
    """The LLM pass runs ONLY when the explicit --llm flag is present. A config
    [llm].enabled=true alone is NOT enough — the flag is the deliberate opt-in,
    so a stray config can never silently start calling a model."""
    return bool(getattr(args, "llm", False))


def _forget_key_now(provider_cfg: llm_mod.ProviderCfg) -> None:
    """Best-effort scrub of the key env var from this process so nothing
    persists for the remainder of the run."""
    if provider_cfg.forget_key:
        os.environ.pop(provider_cfg.key_env, None)


def _lock_dir(path: Path) -> str | None:
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME", "")
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"],
                capture_output=True, check=True,
            )
        else:
            os.chmod(path, 0o700)
        return None
    except (OSError, subprocess.CalledProcessError) as e:
        return f"could not lock {path} to current user ({e}); protect it manually"


def _guard_containment(src: Path, dst: Path) -> None:
    s, d = src.resolve(), dst.resolve()
    if s == d:
        raise SystemExit("error: source and target must differ")
    if d.is_relative_to(s) or s.is_relative_to(d):
        raise SystemExit("error: source and target must not be nested inside each other")


def _load_entities(amap: AliasMap, entities_path: Path | None):
    """Register entities into the map and return their forced detectors."""
    if entities_path is None or not entities_path.is_file():
        return []
    rows = entities_mod.load_entities(entities_path)
    entities_mod.register_entities(amap, rows)
    entities_mod.link_entities(amap, rows)   # reserve + link late-arriving identifiers
    return entities_mod.build_entity_detectors(rows)


# ----------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    src = Path(args.source).resolve()
    if not src.is_dir():
        raise SystemExit(f"error: source not a directory: {src}")
    cfg = _resolve(args)

    # Read-only: load vault map for consistent preview aliases, never mutate it.
    if args.project:
        amap = Vault(Path(args.project)).load_map()
        entities_path = Path(args.entities) if args.entities else Path(args.project) / "entities.csv"
    else:
        amap = AliasMap()
        entities_path = Path(args.entities) if args.entities else None
    entity_dets = _load_entities(amap, entities_path)
    detectors = build_active(disable=cfg.disable, enable=cfg.enable,
                             custom=cfg.custom, denylist=cfg.denylist) + entity_dets

    # ---- optional LLM second pass (PREVIEW: nothing is written) ----
    post_pass = None
    # MED 4: build the provider cfg up-front so the finally block can ALWAYS
    # scrub the key (when --forget-key) regardless of how the run ends.
    provider_cfg = _build_provider_cfg(cfg, args) if _llm_enabled(cfg, args) else None
    try:
        if provider_cfg is not None:
            try:
                llm_mod.enforce_cloud_gate(provider_cfg)
                llm_mod.load_key(provider_cfg)
            except llm_mod.LLMError as e:
                raise SystemExit(f"error: {e}")

            def post_pass(rel: str, stripped_text: str) -> tuple[str, int]:
                try:
                    return llm_mod.second_pass(
                        stripped_text, amap, provider_cfg=provider_cfg, file=rel)
                except llm_mod.LLMError as e:
                    if provider_cfg.strict:
                        raise SystemExit(f"error: LLM pass ({rel}): {e}")
                    sys.stderr.write(f"piiscrub: LLM pass warning ({rel}): {e}\n")
                    return stripped_text, 0

        progress = make_cli_renderer(enabled=not getattr(args, "no_progress", False))
        stats = process_tree(src, None, detectors, amap, allowlist_cf=cfg.allowlist_cf,
                             include=cfg.include, exclude=cfg.exclude,
                             max_bytes=cfg.max_bytes, write=False, exclude_dirs={PII_DIRNAME},
                             stream_threshold=cfg.stream_threshold, progress=progress,
                             post_pass=post_pass)
        pii_dir = src / PII_DIRNAME
        summary = build_summary(mode="scan", src=str(src), dst=None, timestamp=_now(),
                                version=__version__, amap=amap, stats=stats,
                                entities=len(amap.legend()))
        write_json(summary, pii_dir / "scan_report.json")
        write_html(summary, pii_dir / "scan_report.html")

        out = {"mode": "scan", "files_total": stats.files_total,
               "files_processed": stats.files_processed,
               "would_replace": stats.replacements,
               "report": str(pii_dir / "scan_report.html")}
        if args.emit_entities:
            n = entities_mod.write_starter_csv(amap, pii_dir / "entities_starter.csv")
            out["entities_starter"] = str(pii_dir / "entities_starter.csv")
            out["entities_rows"] = n
        print(json.dumps(out, indent=2))
        return 0
    finally:
        if provider_cfg is not None:
            _forget_key_now(provider_cfg)


def cmd_strip(args: argparse.Namespace) -> int:
    src = Path(args.source).resolve()
    dst = Path(args.target).resolve()
    if not src.is_dir():
        raise SystemExit(f"error: source not a directory: {src}")
    _guard_containment(src, dst)
    cfg = _resolve(args)
    dst.mkdir(parents=True, exist_ok=True)
    ts = _now()

    if args.project:
        proj = Path(args.project).resolve()
        if proj.is_relative_to(src) or proj.is_relative_to(dst):
            raise SystemExit("error: --project vault must not be inside the source or target tree")

    vault = None
    # MED 4: build the provider cfg up-front so the finally block can ALWAYS
    # scrub the key (when --forget-key) regardless of how the run ends —
    # success, LLMError, SystemExit, or any other exception.
    provider_cfg = _build_provider_cfg(cfg, args) if _llm_enabled(cfg, args) else None
    try:
        if args.project:
            vault = Vault(Path(args.project)).open()
            amap = vault.load_map()
            entities_path = Path(args.entities) if args.entities else vault.entities_path
        else:
            amap = AliasMap()
            entities_path = Path(args.entities) if args.entities else None

        entity_dets = _load_entities(amap, entities_path)
        detectors = build_active(disable=cfg.disable, enable=cfg.enable,
                                 custom=cfg.custom, denylist=cfg.denylist) + entity_dets

        # ---- optional LLM second pass -----------------------------------
        post_pass = None
        llm_strict_failed = {"hit": False, "reason": ""}
        if provider_cfg is not None:
            # Fail fast (before touching any file): enforce the cloud gate and
            # confirm the key is available. Nothing is sent here.
            try:
                llm_mod.enforce_cloud_gate(provider_cfg)
                llm_mod.load_key(provider_cfg)   # raises if a needed key is absent
            except llm_mod.LLMError as e:
                # A blocked cloud endpoint / missing key is a hard config error
                # regardless of strict mode — refuse before processing anything.
                raise SystemExit(f"error: {e}")

            def post_pass(rel: str, stripped_text: str) -> tuple[str, int]:
                try:
                    return llm_mod.second_pass(
                        stripped_text, amap, provider_cfg=provider_cfg, file=rel)
                except llm_mod.LLMError as e:
                    if provider_cfg.strict:
                        llm_strict_failed["hit"] = True
                        llm_strict_failed["reason"] = f"{rel}: {e}"
                    sys.stderr.write(f"piiscrub: LLM pass warning ({rel}): {e}\n")
                    # Fail-open: leave the regex-stripped text unchanged.
                    return stripped_text, 0

        progress = make_cli_renderer(enabled=not getattr(args, "no_progress", False))
        stats = process_tree(src, dst, detectors, amap, allowlist_cf=cfg.allowlist_cf,
                             include=cfg.include, exclude=cfg.exclude,
                             max_bytes=cfg.max_bytes, write=True, exclude_dirs={PII_DIRNAME},
                             stream_threshold=cfg.stream_threshold, progress=progress,
                             post_pass=post_pass)

        manifest = manifest_mod.build_manifest(src, dst, stats, timestamp=ts, version=__version__)
        audit = verify_tree(dst, detectors, cfg.allowlist_cf)
        verify_status = "PASS" if audit["clean"] else "FAIL"
        summary = build_summary(mode="strip", src=str(src), dst=str(dst), timestamp=ts,
                                version=__version__, amap=amap, stats=stats,
                                verify_status=verify_status, entities=len(amap.legend()),
                                run_digest=manifest["run_digest_sha256"])

        pii_dir = src / PII_DIRNAME
        pii_dir.mkdir(parents=True, exist_ok=True)
        write_json(summary, pii_dir / "report.json")
        write_html(summary, pii_dir / "report.html")
        manifest_mod.write_manifest(manifest, pii_dir / "manifest.json")

        if vault is not None:
            vault.save_map(amap)
            vault.save_legend(amap)
            run_dir = vault.run_dir(ts)
            write_json(summary, run_dir / "report.json")
            manifest_mod.write_manifest(manifest, run_dir / "manifest.json")
            manifest_mod.append_manifest_log(manifest, vault.root / "manifest_log.jsonl")
            decode_loc = str(vault.map_path)
            lock_warn = _lock_dir(vault.root)
        else:
            # standalone: the decode map lives with the originals
            write_json(amap.decode_table(), pii_dir / "decode.json")
            decode_loc = str(pii_dir / "decode.json")
            lock_warn = _lock_dir(pii_dir)

        if args.emit_entities:
            entities_mod.write_starter_csv(amap, pii_dir / "entities_starter.csv")

        out = {"mode": "strip", "files_processed": stats.files_processed,
               "files_copied_unprocessed": stats.files_copied,
               "replacements": stats.replacements, "entities": len(amap.legend()),
               "decode_map": decode_loc, "report": str(pii_dir / "report.html"),
               "manifest": str(pii_dir / "manifest.json"),
               "run_digest": manifest["run_digest_sha256"], "verify": verify_status}
        if lock_warn:
            out["warning"] = lock_warn
        if llm_strict_failed["hit"]:
            out["llm_strict_failed"] = llm_strict_failed["reason"]
        print(json.dumps(out, indent=2))
        if not audit["clean"]:
            sys.stderr.write(json.dumps({"verify_failed": audit}, indent=2) + "\n")
            return 10
        if llm_strict_failed["hit"]:
            sys.stderr.write(
                json.dumps({"llm_strict_failed": llm_strict_failed["reason"]}, indent=2) + "\n")
            return 11
        return 0
    finally:
        # MED 4: ALWAYS scrub the key (when --forget-key) — even on error /
        # SystemExit — so it never lingers in the environment after the run.
        if provider_cfg is not None:
            _forget_key_now(provider_cfg)
        if vault is not None:
            vault.close()


def cmd_verify(args: argparse.Namespace) -> int:
    dst = Path(args.target).resolve()
    if not dst.is_dir():
        raise SystemExit(f"error: target not a directory: {dst}")
    cfg = _resolve(args)
    detectors = build_active(disable=cfg.disable, enable=cfg.enable,
                             custom=cfg.custom, denylist=cfg.denylist)
    audit = verify_tree(dst, detectors, cfg.allowlist_cf)
    print(json.dumps({"clean": audit["clean"], "leak_count": len(audit["leaks"]),
                      "stray_sidecars": audit["stray_sidecars"],
                      "leaks": audit["leaks"][:50]}, indent=2))
    return 0 if audit["clean"] else 10


def cmd_reverse(args: argparse.Namespace) -> int:
    in_path = Path(args.input).resolve()
    out_path = Path(args.output).resolve()
    map_path = Path(args.map).resolve()
    if not in_path.is_file():
        raise SystemExit(f"error: input not a file: {in_path}")
    if not map_path.is_file():
        raise SystemExit(f"error: decode map not found: {map_path}")
    n = reverse_file(in_path, out_path, map_path)
    print(json.dumps({"restored_tokens": n, "output": str(out_path)}, indent=2))
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    if not input_path.is_dir():
        raise SystemExit(f"error: input not a directory: {input_path}")
    _guard_containment(input_path, output_path)

    # Resolve map source: --map takes priority when both given.
    if not getattr(args, "map", None) and not getattr(args, "project", None):
        raise SystemExit("error: reconcile needs --map or --project")

    if output_path.exists():
        if not output_path.is_dir():
            raise SystemExit(f"error: output exists and is not a directory: {output_path}")
        if any(output_path.iterdir()):
            raise SystemExit(
                f"error: output dir is not empty: {output_path}; reconcile writes a fresh "
                "custody-tracked copy — use a new/empty output dir"
            )

    vault = None
    try:
        if getattr(args, "map", None):
            map_path = Path(args.map).resolve()
        else:
            vault = Vault(Path(args.project)).open()
            map_path = vault.map_path

        if not map_path.is_file():
            raise SystemExit(f"error: map not found: {map_path}")

        try:
            table = reconcile_mod.load_alias_table(map_path)
        except (json.JSONDecodeError, ValueError) as e:
            raise SystemExit(f"error: invalid map file {map_path}: {e}")
        canonical_map = reconcile_mod.build_canonical_map(table)

        output_path.mkdir(parents=True, exist_ok=True)
        ts = _now()

        stats = reconcile_mod.reconcile_tree(
            input_path, output_path, canonical_map,
            exclude_dirs={PII_DIRNAME},
        )

        manifest = manifest_mod.build_manifest(
            input_path, output_path, stats, timestamp=ts, version=__version__,
        )
        summary = reconcile_mod.build_reconcile_summary(
            src=input_path, dst=output_path, timestamp=ts, version=__version__,
            stats=stats, canonical_map=canonical_map,
            run_digest=manifest["run_digest_sha256"],
        )

        pii_dir = output_path / PII_DIRNAME
        pii_dir.mkdir(parents=True, exist_ok=True)
        manifest_mod.write_manifest(manifest, pii_dir / "manifest.json")
        write_json(summary, pii_dir / "reconcile_report.json")
        write_json(canonical_map, pii_dir / "reconcile_map.json")

        if vault is not None:
            run_dir = vault.run_dir(ts)
            manifest_mod.write_manifest(manifest, run_dir / "manifest.json")
            write_json(summary, run_dir / "reconcile_report.json")
            manifest_mod.append_manifest_log(manifest, vault.root / "manifest_log.jsonl")

        out = {
            "mode": "reconcile",
            "files_processed": stats.files_processed,
            "files_copied_unprocessed": stats.files_copied,
            "replacements": stats.replacements,
            "aliases_reconciled": len(canonical_map),
            "manifest": str(pii_dir / "manifest.json"),
            "reconcile_map": str(pii_dir / "reconcile_map.json"),
            "run_digest": manifest["run_digest_sha256"],
        }
        print(json.dumps(out, indent=2))
        return 0
    finally:
        if vault is not None:
            vault.close()


def _selftest() -> int:
    from .engine import AliasMap, reverse_text, tokenize
    detectors = build_active()
    sample = ("User a@Example.com from 10.0.0.5 hit https://host.corp/x and again 10.0.0.5; "
              "mac de:ad:be:ef:00:11 path C:\\Users\\jdoe\\app.log")
    amap = AliasMap()
    stripped, reps = tokenize(sample, detectors, amap)
    if not reps:
        sys.stderr.write("selftest: no detections\n"); return 1
    ip_aliases = {a for a, m in amap.decode_table().items() if m["category"] == "ipv4"}
    if len(ip_aliases) != 1:
        sys.stderr.write(f"selftest: IP consistency broken ({ip_aliases})\n"); return 1
    if reverse_text(stripped, amap.reverse_pairs()) != sample:
        sys.stderr.write("selftest: round-trip mismatch\n"); return 1
    _n, residual = tokenize(stripped, detectors, AliasMap())
    if residual:
        sys.stderr.write("selftest: residual PII after strip\n"); return 1
    print("selftest: OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="piiscrub", description="Reusable PII pseudonymiser (local).")
    p.add_argument("--version", action="version", version=f"piiscrub {__version__}")
    p.add_argument("--selftest", action="store_true", help="run an internal smoke test and exit")
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--config", help="path to piiscrub.toml")
        sp.add_argument("--profile", choices=profile_names(), help="named preset")
        sp.add_argument("--project", help="central vault dir for cross-run correlation")
        sp.add_argument("--entities", help="entity table CSV (default: <project>/entities.csv)")
        sp.add_argument("--enable", action="append", help="enable a detector category (repeatable)")
        sp.add_argument("--disable", action="append", help="disable a detector category (repeatable)")
        sp.add_argument("--include", action="append", help="glob to include (repeatable)")
        sp.add_argument("--exclude", action="append", help="glob to exclude (repeatable)")
        sp.add_argument("--max-bytes", type=int, dest="max_bytes", help="hard skip files larger than N bytes (default: effectively off; huge files are streamed)")
        sp.add_argument("--stream-threshold", type=int, dest="stream_threshold", help="stream files larger than N bytes in chunks (default 50MB)")
        sp.add_argument("--no-progress", action="store_true", help="suppress the stderr progress bar")
        # ---- optional LLM second pass (OFF unless --llm) ----
        sp.add_argument("--llm", action="store_true",
                        help="run an optional LLM second pass over the ALREADY-STRIPPED "
                             "text to flag residual PII the regex missed (off by default)")
        sp.add_argument("--llm-provider", choices=["ollama", "openai", "anthropic"],
                        dest="llm_provider", help="LLM provider (default: ollama, local)")
        sp.add_argument("--llm-endpoint", dest="llm_endpoint",
                        help="LLM endpoint base URL (default: local Ollama at "
                             "http://127.0.0.1:11434)")
        sp.add_argument("--llm-model", dest="llm_model", help="model name")
        sp.add_argument("--llm-key-env", dest="llm_key_env",
                        help="NAME of the env var holding the API key (never the key "
                             "itself; default PIISCRUB_LLM_KEY). Local providers need none.")
        sp.add_argument("--allow-cloud", action="store_true", dest="allow_cloud",
                        help="REQUIRED to send already-stripped text to a non-local "
                             "endpoint; without it a remote endpoint is refused")
        sp.add_argument("--forget-key", action="store_true", dest="forget_key",
                        help="scrub the API key from this process's environment after "
                             "use so nothing persists")
        sp.add_argument("--llm-strict", action="store_true", dest="llm_strict",
                        help="fail-closed: exit non-zero on any LLM error instead of "
                             "warning and continuing")

    s = sub.add_parser("scan", help="dry-run: detect + report, write nothing stripped")
    s.add_argument("source"); common(s)
    s.add_argument("--emit-entities", action="store_true", help="write a starter entity CSV")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("strip", help="write stripped mirror + decode map + report + manifest, then verify")
    s.add_argument("source"); s.add_argument("target"); common(s)
    s.add_argument("--emit-entities", action="store_true", help="write a starter entity CSV")
    s.set_defaults(func=cmd_strip)

    s = sub.add_parser("verify", help="re-scan a stripped tree for residual PII (fail-closed)")
    s.add_argument("target"); common(s); s.set_defaults(func=cmd_verify)

    s = sub.add_parser("reverse", help="rehydrate a stripped file using a decode map or vault")
    s.add_argument("input"); s.add_argument("output")
    s.add_argument("--map", required=True, help="path to decode.json or vault map.json")
    s.set_defaults(func=cmd_reverse)

    s = sub.add_parser(
        "reconcile",
        help="rewrite an already-stripped tree to current canonical aliases (custody-safe new copy)",
    )
    s.add_argument("input", help="path to the already-stripped input tree")
    s.add_argument("output", help="path to write the reconciled output tree (new directory)")
    s.add_argument("--map", help="path to vault map.json or standalone decode.json")
    s.add_argument("--project", help="vault dir — alternative source for the alias map")
    s.set_defaults(func=cmd_reconcile)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.selftest:
        return _selftest()
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except VaultLocked as e:
        sys.stderr.write(f"error: {e}\n")
        return 3
    except (FileNotFoundError, ValueError, KeyError) as e:
        sys.stderr.write(f"error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
