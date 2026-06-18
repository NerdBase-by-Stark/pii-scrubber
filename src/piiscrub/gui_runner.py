"""Programmatic API for scan and strip — no CLI, no argparse, no print, no sys.exit.

Intended for GUI consumers (e.g. a future Qt front-end) that need to drive the
core without duplicating orchestration logic.  The LLM second-pass is never
used here; ``post_pass`` is always None.

The relative imports below (``from . import ...``, ``from .cli import ...``) are
intentional and correct because this is a regular package module; the
absolute-import rule applies only to the PyInstaller entry-point script
``gui.py``, which runs as ``__main__`` with no parent package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from . import entities as entities_mod
from . import manifest as manifest_mod
from .audit import verify_tree
from .cli import (
    PII_DIRNAME,
    _load_entities,
    _lock_dir,
    _now,
)
from .config import resolve_config
from .detectors import build_active
from .engine import AliasMap
from .progress import ProgressCallback
from .projectmap import Vault
from .report import build_summary, write_html, write_json
from .walker import process_tree


@dataclass
class RunOptions:
    source: str
    target: str | None = None           # required for strip; ignored by scan
    config: str | None = None           # path to piiscrub.toml
    profile: str | None = None
    project: str | None = None          # vault dir
    entities: str | None = None         # entity CSV (default <project>/entities.csv)
    enable: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    max_bytes: int | None = None
    stream_threshold: int | None = None
    emit_entities: bool = False


def _guard_containment_v(src: Path, dst: Path) -> None:
    """Like cli._guard_containment but raises ValueError instead of SystemExit."""
    s, d = src.resolve(), dst.resolve()
    if s == d:
        raise ValueError("source and target must differ")
    if d.is_relative_to(s) or s.is_relative_to(d):
        raise ValueError("source and target must not be nested inside each other")


def _apply_opts_to_config(cfg, opts: RunOptions):
    """Mirror _merge_cli_into_config but against RunOptions; raises ValueError instead
    of SystemExit for non-positive numeric values."""
    if opts.enable:
        cfg.enable |= set(opts.enable)
    if opts.disable:
        cfg.disable |= set(opts.disable)
    if opts.include:
        cfg.include += list(opts.include)
    if opts.exclude:
        cfg.exclude += list(opts.exclude)
    if opts.max_bytes is not None:
        if opts.max_bytes <= 0:
            raise ValueError("max_bytes must be > 0")
        cfg.max_bytes = opts.max_bytes
    if opts.stream_threshold is not None:
        if opts.stream_threshold <= 0:
            raise ValueError("stream_threshold must be > 0")
        cfg.stream_threshold = opts.stream_threshold
    return cfg


def run_scan(opts: RunOptions, progress: ProgressCallback | None = None) -> dict:
    """Dry-run: detect PII in *source*, write scan report to ``<source>/_pii``.

    No files are stripped.  Returns a result dict with keys:
      mode, files_total, files_processed, would_replace, report
    and optionally entities_starter, entities_rows when opts.emit_entities is True.

    Raises ValueError on bad arguments.  Other exceptions propagate unchanged.
    """
    src = Path(opts.source).resolve()
    if not src.is_dir():
        raise ValueError(f"source not a directory: {src}")

    cfg = resolve_config(opts.profile, Path(opts.config) if opts.config else None)
    _apply_opts_to_config(cfg, opts)

    if opts.project:
        amap = Vault(Path(opts.project)).load_map()
        entities_path = (
            Path(opts.entities) if opts.entities else Path(opts.project) / "entities.csv"
        )
    else:
        amap = AliasMap()
        entities_path = Path(opts.entities) if opts.entities else None

    entity_dets = _load_entities(amap, entities_path)
    detectors = (
        build_active(
            disable=cfg.disable,
            enable=cfg.enable,
            custom=cfg.custom,
            denylist=cfg.denylist,
        )
        + entity_dets
    )

    stats = process_tree(
        src,
        None,
        detectors,
        amap,
        allowlist_cf=cfg.allowlist_cf,
        include=cfg.include,
        exclude=cfg.exclude,
        max_bytes=cfg.max_bytes,
        write=False,
        exclude_dirs={PII_DIRNAME},
        stream_threshold=cfg.stream_threshold,
        progress=progress,
        post_pass=None,
    )

    pii_dir = src / PII_DIRNAME
    summary = build_summary(
        mode="scan",
        src=str(src),
        dst=None,
        timestamp=_now(),
        version=__version__,
        amap=amap,
        stats=stats,
        entities=len(amap.legend()),
    )
    write_json(summary, pii_dir / "scan_report.json")
    write_html(summary, pii_dir / "scan_report.html")

    out: dict = {
        "mode": "scan",
        "files_total": stats.files_total,
        "files_processed": stats.files_processed,
        "would_replace": stats.replacements,
        "report": str(pii_dir / "scan_report.html"),
    }
    if opts.emit_entities:
        n = entities_mod.write_starter_csv(amap, pii_dir / "entities_starter.csv")
        out["entities_starter"] = str(pii_dir / "entities_starter.csv")
        out["entities_rows"] = n
    return out


def run_strip(opts: RunOptions, progress: ProgressCallback | None = None) -> dict:
    """Strip PII from *source* into *target*, write decode map + report + manifest.

    Returns a result dict with keys:
      mode, files_processed, files_copied_unprocessed, replacements, entities,
      decode_map, report, manifest, run_digest, verify, verify_clean, verify_detail
    and optionally warning (lock warning string), entities_starter, entities_rows.

    Raises ValueError on bad arguments.  Other exceptions propagate unchanged.
    """
    src = Path(opts.source).resolve()
    if opts.target is None:
        raise ValueError("target is required for strip")
    dst = Path(opts.target).resolve()
    if not src.is_dir():
        raise ValueError(f"source not a directory: {src}")

    _guard_containment_v(src, dst)

    cfg = resolve_config(opts.profile, Path(opts.config) if opts.config else None)
    _apply_opts_to_config(cfg, opts)

    dst.mkdir(parents=True, exist_ok=True)
    ts = _now()

    if opts.project:
        proj = Path(opts.project).resolve()
        if proj.is_relative_to(src) or proj.is_relative_to(dst):
            raise ValueError(
                "error: --project vault must not be inside the source or target tree"
            )

    vault = None
    try:
        if opts.project:
            vault = Vault(Path(opts.project)).open()
            amap = vault.load_map()
            entities_path = (
                Path(opts.entities) if opts.entities else vault.entities_path
            )
        else:
            amap = AliasMap()
            entities_path = Path(opts.entities) if opts.entities else None

        entity_dets = _load_entities(amap, entities_path)
        detectors = (
            build_active(
                disable=cfg.disable,
                enable=cfg.enable,
                custom=cfg.custom,
                denylist=cfg.denylist,
            )
            + entity_dets
        )

        stats = process_tree(
            src,
            dst,
            detectors,
            amap,
            allowlist_cf=cfg.allowlist_cf,
            include=cfg.include,
            exclude=cfg.exclude,
            max_bytes=cfg.max_bytes,
            write=True,
            exclude_dirs={PII_DIRNAME},
            stream_threshold=cfg.stream_threshold,
            progress=progress,
            post_pass=None,
        )

        manifest = manifest_mod.build_manifest(
            src, dst, stats, timestamp=ts, version=__version__
        )
        audit = verify_tree(dst, detectors, cfg.allowlist_cf)
        verify_status = "PASS" if audit["clean"] else "FAIL"
        summary = build_summary(
            mode="strip",
            src=str(src),
            dst=str(dst),
            timestamp=ts,
            version=__version__,
            amap=amap,
            stats=stats,
            verify_status=verify_status,
            entities=len(amap.legend()),
            run_digest=manifest["run_digest_sha256"],
        )

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
            write_json(amap.decode_table(), pii_dir / "decode.json")
            decode_loc = str(pii_dir / "decode.json")
            lock_warn = _lock_dir(pii_dir)

        entities_rows = None
        if opts.emit_entities:
            entities_rows = entities_mod.write_starter_csv(
                amap, pii_dir / "entities_starter.csv"
            )

        out: dict = {
            "mode": "strip",
            "files_processed": stats.files_processed,
            "files_copied_unprocessed": stats.files_copied,
            "replacements": stats.replacements,
            "entities": len(amap.legend()),
            "decode_map": decode_loc,
            "report": str(pii_dir / "report.html"),
            "manifest": str(pii_dir / "manifest.json"),
            "run_digest": manifest["run_digest_sha256"],
            "verify": verify_status,
            "verify_clean": audit["clean"],
            "verify_detail": audit,
        }
        if lock_warn:
            out["warning"] = lock_warn
        if opts.emit_entities:
            out["entities_starter"] = str(pii_dir / "entities_starter.csv")
            out["entities_rows"] = entities_rows
        return out
    finally:
        if vault is not None:
            vault.close()
