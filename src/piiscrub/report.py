"""Run report generation. Contains ALIASES AND COUNTS ONLY — never raw
originals (those live solely in decode.json), so the report is safe to glance
at or share."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .engine import AliasMap
from .walker import RunStats


def build_summary(
    *,
    mode: str,
    src: str,
    dst: str | None,
    timestamp: str,
    version: str,
    amap: AliasMap,
    stats: RunStats,
    verify_status: str | None = None,
    entities: int = 0,
    run_digest: str | None = None,
) -> dict:
    by_category: dict[str, dict] = {}
    for meta in amap.decode_table().values():
        c = meta["category"]
        row = by_category.setdefault(c, {"unique": 0, "occurrences": 0})
        row["unique"] += 1
        row["occurrences"] += meta["count"]
    return {
        "mode": mode,
        "tool": "piiscrub",
        "version": version,
        "timestamp": timestamp,
        "source": src,
        "target": dst,
        "files_total": stats.files_total,
        "files_processed": stats.files_processed,
        "files_copied_unprocessed": stats.files_copied,
        "total_replacements": stats.replacements,
        "unique_values": len(amap.decode_table()),
        "entities": entities,
        "run_digest_sha256": run_digest,
        "by_category": dict(sorted(by_category.items())),
        "skipped": [{"file": s.rel, "status": s.status} for s in stats.skipped],
        "warnings": stats.warnings,
        "verify": verify_status,
    }


def write_json(summary: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def _h(s) -> str:
    return html.escape(str(s))


def write_html(summary: dict, path: Path) -> None:
    cat_rows = "".join(
        f"<tr><td>{_h(c)}</td><td class=n>{_h(v['unique'])}</td>"
        f"<td class=n>{_h(v['occurrences'])}</td></tr>"
        for c, v in summary["by_category"].items()
    ) or "<tr><td colspan=3>No PII detected.</td></tr>"

    skip_rows = "".join(
        f"<tr><td>{_h(s['file'])}</td><td>{_h(s['status'])}</td></tr>"
        for s in summary["skipped"]
    ) or "<tr><td colspan=2>None.</td></tr>"

    warn_items = "".join(f"<li>{_h(w)}</li>" for w in summary["warnings"]) \
        or "<li>None.</li>"

    verify = summary.get("verify")
    verify_html = ""
    if verify is not None:
        cls = "ok" if verify == "PASS" else "bad"
        verify_html = f'<p>Verify (residual-PII re-scan): <b class={cls}>{_h(verify)}</b></p>'

    doc = f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<title>piiscrub report — {_h(summary['mode'])}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;max-width:60rem}}
 h1{{font-size:1.3rem}} h2{{font-size:1.05rem;margin-top:1.6rem}}
 table{{border-collapse:collapse;width:100%;margin:.5rem 0}}
 th,td{{border:1px solid #ddd;padding:.35rem .6rem;text-align:left}}
 th{{background:#f4f4f4}} td.n{{text-align:right;font-variant-numeric:tabular-nums}}
 .ok{{color:#157f3b}} .bad{{color:#c0271a}}
 .meta td:first-child{{color:#666;width:14rem}}
 code{{background:#f4f4f4;padding:0 .25rem;border-radius:3px}}
</style></head><body>
<h1>piiscrub report <span style=color:#888>({_h(summary['mode'])})</span></h1>
<p style=color:#666>Aliases &amp; counts only — no raw values. Originals live in
<code>decode.json</code>.</p>
{verify_html}
<table class=meta>
 <tr><td>Tool version</td><td>{_h(summary['version'])}</td></tr>
 <tr><td>Timestamp (UTC)</td><td>{_h(summary['timestamp'])}</td></tr>
 <tr><td>Source</td><td><code>{_h(summary['source'])}</code></td></tr>
 <tr><td>Target</td><td><code>{_h(summary['target'])}</code></td></tr>
 <tr><td>Files total</td><td>{_h(summary['files_total'])}</td></tr>
 <tr><td>Files processed</td><td>{_h(summary['files_processed'])}</td></tr>
 <tr><td>Copied unprocessed</td><td>{_h(summary['files_copied_unprocessed'])}</td></tr>
 <tr><td>Total replacements</td><td>{_h(summary['total_replacements'])}</td></tr>
 <tr><td>Unique values</td><td>{_h(summary['unique_values'])}</td></tr>
 <tr><td>Entities</td><td>{_h(summary.get('entities', 0))}</td></tr>
 <tr><td>Run digest (SHA-256)</td><td><code>{_h(summary.get('run_digest_sha256') or '—')}</code></td></tr>
</table>
<h2>By category</h2>
<table><tr><th>Category</th><th>Unique values</th><th>Occurrences</th></tr>
{cat_rows}</table>
<h2>Files copied unprocessed (may contain PII)</h2>
<table><tr><th>File</th><th>Reason</th></tr>{skip_rows}</table>
<h2>Warnings</h2><ul>{warn_items}</ul>
</body></html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
