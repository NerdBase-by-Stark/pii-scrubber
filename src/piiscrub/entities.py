"""Operator entity table — the "pretty name <-> hostname + relationships" layer.

The operator maintains a CSV grouping the different identifiers of one thing
(a device's IP + hostname + MAC) under a single entity, with a friendly name.
The tool then:
  - force-tokenises every listed identifier (even bare hostnames like SRV-AB12
    that match no built-in shape), and
  - groups them so they share an entity-scoped alias (<DEV0001.IP_1> etc.),
    making the same device visible across every log/vendor/date.

The friendly name is kept in the vault legend (it can itself be sensitive, e.g.
a location) and never written into the shareable stripped output.

CSV columns (header row required):
    id, type, pretty_name, identifiers, notes
where `identifiers` is a semicolon-separated list.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import Detector, classify_identifier
from .engine import AliasMap

ENTITY_PRIORITY = 120  # above custom (100) and denylist (110)
CSV_FIELDS = ["id", "type", "pretty_name", "identifiers", "notes"]


@dataclass
class EntityRow:
    id: str
    type: str = "device"
    pretty_name: str = ""
    identifiers: list[str] = field(default_factory=list)
    notes: str = ""


def load_entities(path: Path) -> list[EntityRow]:
    rows: list[EntityRow] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = {"id", "identifiers"} - set(h.strip() for h in (reader.fieldnames or []))
        if missing:
            raise ValueError(f"entity CSV missing required column(s): {sorted(missing)}")
        for i, raw in enumerate(reader, start=2):
            eid = (raw.get("id") or "").strip()
            if not eid:
                continue
            idents = [s.strip() for s in (raw.get("identifiers") or "").split(";") if s.strip()]
            if not idents:
                continue
            rows.append(EntityRow(
                id=eid,
                type=(raw.get("type") or "device").strip() or "device",
                pretty_name=(raw.get("pretty_name") or "").strip(),
                identifiers=idents,
                notes=(raw.get("notes") or "").strip(),
            ))
    return rows


def register_entities(amap: AliasMap, rows: list[EntityRow]) -> None:
    """Assign each entity its stable label (DEV0001…) in CSV order."""
    for row in rows:
        amap.register_entity(row.id, row.type, row.pretty_name, row.notes)


def link_entities(amap: AliasMap, rows: list[EntityRow]) -> None:
    """Reserve entity-scoped aliases for every declared identifier and link any
    that were already given a plain alias on an earlier run (late-arrival case),
    so the same value never ends up with two unrelated aliases."""
    for row in rows:
        for ident in row.identifiers:
            category, prefix = classify_identifier(ident)
            amap.link_identifier_to_entity(ident, category, prefix, row.id)


def build_entity_detectors(rows: list[EntityRow]) -> list[Detector]:
    """One forced literal detector per identifier, tagged with its entity."""
    dets: list[Detector] = []
    for row in rows:
        for ident in row.identifiers:
            category, prefix = classify_identifier(ident)
            pattern = re.compile(
                r"(?<![\w.-])" + re.escape(ident) + r"(?![\w.-])", re.IGNORECASE
            )
            dets.append(Detector(
                category=category, prefix=prefix, pattern=pattern,
                priority=ENTITY_PRIORITY, on_by_default=True,
                casefold_key=True, entity_id=row.id,
            ))
    return dets


def write_starter_csv(amap: AliasMap, path: Path) -> int:
    """Emit a starter entity CSV of detected identifiers for the operator to
    annotate (group into entities + add pretty names), then re-run. Returns the
    number of identifier rows written."""
    wanted = {"ipv4", "ipv6", "mac", "email", "fqdn", "host"}
    seen: set[str] = set()
    out_rows: list[list[str]] = []
    for meta in amap.decode_table().values():
        if meta.get("entity"):
            continue  # already grouped
        if meta["category"] not in wanted:
            continue
        val = meta["original"]
        if val in seen:
            continue
        seen.add(val)
        # id/type/pretty_name left blank for the operator; identifier prefilled
        out_rows.append(["", "device", "", val, ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_FIELDS)
        writer.writerow(["# fill 'id' (e.g. core-switch-alpha) + group identifiers",
                         "device", "Core Switch Alpha", "10.0.0.5;SRV-AB12", "example row"])
        writer.writerows(sorted(out_rows, key=lambda r: r[3]))
    return len(out_rows)
