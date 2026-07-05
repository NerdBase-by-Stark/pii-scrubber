"""Verify (residual-PII re-scan of the stripped output — fail-closed) and
reverse (rehydrate aliases back to originals from decode.json)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .detectors import Detector
from .engine import AliasMap, reverse_text, tokenize
from .formats import ExtractLimits, get_handler
from .formats.archives import iter_text_members
from .walker import BINARY_EXTS, decode_bytes, iter_files

if TYPE_CHECKING:      # duck-typed .enabled/.disable/.limits; avoids a config cycle
    from .config import ExtractConfig

# Sidecar names that must NEVER appear inside the stripped output tree.
LEAK_SIDECARS = {"decode.json", "report.json", "report.html", "scan_report.json", "scan_report.html"}


def verify_tree(
    dst: Path,
    detectors: list[Detector],
    allowlist_cf: frozenset[str] = frozenset(),
    *,
    extract: "ExtractConfig | None" = None,
) -> dict:
    """Re-scan the stripped tree for residual PII shapes and stray sidecars.

    Returns {"clean": bool, "leaks": [...], "stray_sidecars": [...]}.

    ``extract`` carries the run's extraction settings (default = extraction on).
    When enabled, verify must ALSO recurse into repacked archives in DST and
    scan their text members (fail-closed guarantee is otherwise hollow), using
    ``archive.zip!member/path`` notation for any leak. ``--no-extract`` (or a
    disabled handler) skips that recursion — a documented weaker guarantee. The
    recursion itself is implemented by the archives-verify agent; this signature
    is the plumbing hook it fills in.
    """
    extract_enabled = True if extract is None else extract.enabled
    extract_disable = frozenset() if extract is None else frozenset(extract.disable)
    extract_limits = ExtractLimits() if extract is None else extract.limits

    leaks: list[dict] = []
    stray: list[str] = []

    for path in iter_files(dst, exclude_dirs=set()):
        rel = path.relative_to(dst).as_posix()
        if path.name in LEAK_SIDECARS:
            stray.append(rel)
        if path.suffix.lower() in BINARY_EXTS:
            # When extraction is on and this is a repacked archive, the
            # fail-closed guarantee requires re-scanning its TEXT members (and
            # nested archives, depth-capped) for residual PII — a scrubbed
            # archive whose members still leak would otherwise pass verify.
            # ``--no-extract`` (or a disabled ``archive`` handler) skips this, a
            # documented weaker guarantee. Binary members copied+flagged into the
            # repack are not re-scanned (they were reported, never claimed clean).
            handler = get_handler(path.suffix) if extract_enabled else None
            if handler is not None and handler.name == "archive" \
                    and handler.name not in extract_disable:
                for member_rel, text in iter_text_members(path, rel, extract_limits):
                    scratch = AliasMap()
                    _new, reps = tokenize(text, detectors, scratch, allowlist_cf)
                    for r in reps:
                        leaks.append({
                            "file": member_rel, "category": r.category,
                            "line": text.count("\n", 0, r.start) + 1,
                        })
            continue
        decoded = decode_bytes(path.read_bytes())
        if decoded is None:
            continue
        text, _enc = decoded
        scratch = AliasMap()
        _new, reps = tokenize(text, detectors, scratch, allowlist_cf)
        for r in reps:
            leaks.append({"file": rel, "category": r.category, "line": text.count("\n", 0, r.start) + 1})

    return {"clean": not leaks and not stray, "leaks": leaks, "stray_sidecars": stray}


def load_decode_pairs(map_path: Path) -> list[tuple[str, str]]:
    """Accept either a standalone decode.json (alias -> {original,...}) or a
    project vault map.json (which nests the table under 'entries')."""
    with open(map_path, encoding="utf-8") as fh:
        data = json.load(fh)
    table = data["entries"] if isinstance(data, dict) and "entries" in data else data
    pairs = [(alias, meta["original"]) for alias, meta in table.items()]
    pairs.sort(key=lambda p: -len(p[0]))
    return pairs


def reverse_file(in_path: Path, out_path: Path, map_path: Path) -> int:
    pairs = load_decode_pairs(map_path)
    text = in_path.read_text(encoding="utf-8", errors="replace")
    restored = reverse_text(text, pairs)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(restored, encoding="utf-8")
    return sum(text.count(a) for a, _ in pairs)
