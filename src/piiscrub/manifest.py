"""Chain-of-custody manifest — for regulated data.

Records SHA-256 of every original and every stripped file, plus encoding,
replacement count, status and timestamp, and a run-level digest over all the
per-file hashes (so the manifest itself is tamper-evident). Written per run;
appended to a project-level manifest log when running in project mode.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .walker import RunStats


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_or_blank(path: Path) -> str:
    try:
        return hash_file(path)
    except OSError:
        return ""


def build_records(src: Path, dst: Path, stats: RunStats, timestamp: str) -> list[dict]:
    records: list[dict] = []
    # processed text files
    for fs in stats.per_file:
        records.append({
            "file": fs.rel, "status": fs.status, "encoding": fs.encoding,
            "replacements": fs.replacements,
            "source_sha256": _hash_or_blank(src / fs.rel),
            "output_sha256": _hash_or_blank(dst / fs.rel),
            "timestamp": timestamp,
        })
    # copied-through files (binary / undecodable / oversize)
    for fs in stats.skipped:
        records.append({
            "file": fs.rel, "status": fs.status, "encoding": "",
            "replacements": 0,
            "source_sha256": _hash_or_blank(src / fs.rel),
            "output_sha256": _hash_or_blank(dst / fs.rel),
            "timestamp": timestamp,
        })
    records.sort(key=lambda r: r["file"])
    return records


def run_digest(records: list[dict]) -> str:
    h = hashlib.sha256()
    for r in records:
        h.update(f"{r['file']}\0{r['source_sha256']}\0{r['output_sha256']}\0".encode())
    return h.hexdigest()


def build_manifest(src: Path, dst: Path, stats: RunStats, *, timestamp: str,
                   version: str) -> dict:
    records = build_records(src, dst, stats, timestamp)
    return {
        "tool": "piiscrub",
        "version": version,
        "timestamp": timestamp,
        "source": str(src),
        "target": str(dst),
        "file_count": len(records),
        "run_digest_sha256": run_digest(records),
        "files": records,
    }


def write_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def append_manifest_log(manifest: dict, log_path: Path) -> None:
    """Append a one-line summary record to a project-level audit log (JSONL)."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {k: manifest[k] for k in
               ("timestamp", "version", "source", "target", "file_count", "run_digest_sha256")}
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(summary, ensure_ascii=False) + "\n")
