"""Reconcile a delivered stripped tree to current canonical aliases.

After a stripped tree has been delivered, the operator may group identifiers
into an entity, making ``<IP_1>`` canonically ``<DEV0001.IP_1>`` in the vault.
``reconcile`` produces a NEW copy of the delivered tree with every superseded
alias rewritten to its current canonical form.

Custody-safe: the input tree is NEVER modified; a brand-new output tree is
written together with its own chain-of-custody manifest.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from .walker import BINARY_EXTS, FileStat, RunStats, decode_bytes, iter_files


def load_alias_table(map_path: Path) -> dict[str, dict]:
    """Load an alias table from a vault map.json or a standalone decode.json.

    A vault ``map.json`` nests the table under the key ``"entries"``; a
    standalone ``decode.json`` is the table directly (``{alias: meta}``).
    """
    with open(map_path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "entries" in data:
        return data["entries"]
    return data


def build_canonical_map(table: dict[str, dict]) -> dict[str, str]:
    """Return ``{old_alias: terminal_canonical}`` for every superseded alias.

    Follows ``meta["superseded_by"]`` chains to the terminal entry. Cycle-safe:
    a visited-set per chain detects cycles and treats the last pointer as
    terminal. Dangling pointers (target not in the table) are also treated as
    terminal. Only aliases whose terminal differs from themselves are included.
    """
    canonical: dict[str, str] = {}

    for start in table:
        if "superseded_by" not in table[start]:
            continue
        visited: set[str] = {start}
        current = start
        while True:
            nxt = table[current].get("superseded_by")
            if nxt is None:
                # current is terminal
                terminal = current
                break
            if nxt in visited or nxt not in table:
                # cycle or dangling — treat nxt as terminal
                terminal = nxt
                break
            visited.add(nxt)
            current = nxt
        if terminal != start:
            canonical[start] = terminal

    return canonical


def reconcile_text(text: str, canonical_map: dict[str, str]) -> tuple[str, int]:
    """Rewrite every superseded alias to its canonical form.

    Uses a single non-overlapping left-to-right pass via ``re.subn`` with
    alternation sorted by DESCENDING key length so longer aliases (e.g.
    ``<IP_10>``) are always tried before shorter prefixes (``<IP_1>``).

    Returns ``(new_text, n_replacements)``.
    """
    if not canonical_map:
        return text, 0
    # Sort longest-first so <IP_10> is tried before <IP_1>.
    keys_sorted = sorted(canonical_map, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(k) for k in keys_sorted))
    new_text, count = pattern.subn(lambda m: canonical_map[m.group(0)], text)
    return new_text, count


def reconcile_tree(
    input_root: Path,
    output_root: Path,
    canonical_map: dict[str, str],
    *,
    exclude_dirs: set[str],
) -> RunStats:
    """Walk ``input_root`` and write a reconciled copy into ``output_root``.

    * Binary extensions (``BINARY_EXTS``) are copied through with
      ``shutil.copy2``.
    * Files that cannot be decoded to text are also copied through.
    * Text files are passed through :func:`reconcile_text`; the result is
      written with the detected encoding using ``open(..., newline="")``.
    """
    stats = RunStats()
    files = iter_files(input_root, exclude_dirs)

    for path in files:
        rel = path.relative_to(input_root).as_posix()
        out = output_root / rel
        stats.files_total += 1

        if path.suffix.lower() in BINARY_EXTS:
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, out)
            stats.skipped.append(FileStat(rel, "copied"))
            stats.files_copied += 1
        else:
            raw = path.read_bytes()
            decoded = decode_bytes(raw)
            if decoded is None:
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, out)
                stats.skipped.append(FileStat(rel, "copied"))
                stats.files_copied += 1
            else:
                text, enc = decoded
                new_text, n = reconcile_text(text, canonical_map)
                out.parent.mkdir(parents=True, exist_ok=True)
                with open(out, "w", encoding=enc, newline="") as fh:
                    fh.write(new_text)
                stats.per_file.append(FileStat(rel, "reconciled", encoding=enc, replacements=n))
                stats.files_processed += 1
                stats.replacements += n

    return stats


def build_reconcile_summary(
    *,
    src: Path,
    dst: Path,
    timestamp: str,
    version: str,
    stats: RunStats,
    canonical_map: dict[str, str],
    run_digest: str,
) -> dict:
    """Return a JSON-serialisable summary dict for the reconcile run."""
    return {
        "mode": "reconcile",
        "tool": "piiscrub",
        "version": version,
        "timestamp": timestamp,
        "source": str(src),
        "target": str(dst),
        "files_total": stats.files_total,
        "files_processed": stats.files_processed,
        "files_copied_unprocessed": stats.files_copied,
        "total_replacements": stats.replacements,
        "aliases_reconciled": len(canonical_map),
        "supersessions": canonical_map,
        "run_digest_sha256": run_digest,
        "warnings": stats.warnings,
    }
