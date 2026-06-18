"""The tokenisation engine: single-pass, priority-ordered span replacement
with an AliasMap that guarantees the same real value always maps to the same
opaque alias.

Two alias shapes:
  - plain:  <IP_7>, <EMAIL_3>            (un-grouped values)
  - entity: <DEV0001.IP_1>, <DEV0001.HOST_1>
            (values the operator grouped into one entity via the entity table —
             so a device is visibly the same across every log/vendor/date, and
             you still see whether a line used the IP, the hostname, or the MAC)

The AliasMap is serialisable so it can persist in a central project vault and
be reused across runs (cross-run correlation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .detectors import Detector

VAULT_SCHEMA = "piiscrub-vault/1"


@dataclass
class Replacement:
    start: int
    end: int
    value: str
    alias: str
    category: str


# entity type -> alias label prefix
_ENTITY_PREFIX = {"device": "DEV", "person": "USR", "site": "SITE", "service": "SVC"}


def _entity_prefix(entity_type: str) -> str:
    return _ENTITY_PREFIX.get(entity_type.lower(), re.sub(r"[^A-Z]", "", entity_type.upper())[:4] or "ENT")


class AliasMap:
    """Bijective map real value <-> opaque alias, serialisable for the vault."""

    def __init__(self) -> None:
        self._key_index: dict[str, str] = {}      # composed key -> alias
        self._entries: dict[str, dict] = {}       # alias -> meta
        self._counters: dict[str, int] = {}       # counter name -> int
        self._entities: dict[str, dict] = {}      # entity_id -> {label,type,pretty,notes}
        self._entity_counters: dict[str, int] = {}  # entity prefix -> int

    # ---- entity registration -------------------------------------------
    def register_entity(self, entity_id: str, entity_type: str = "device",
                        pretty: str = "", notes: str = "") -> str:
        ent = self._entities.get(entity_id)
        if ent is None:
            prefix = _entity_prefix(entity_type)
            n = self._entity_counters.get(prefix, 0) + 1
            self._entity_counters[prefix] = n
            ent = {"label": f"{prefix}{n:04d}", "type": entity_type,
                   "pretty": pretty, "notes": notes}
            self._entities[entity_id] = ent
        else:
            if pretty and not ent.get("pretty"):
                ent["pretty"] = pretty
            if notes and not ent.get("notes"):
                ent["notes"] = notes
        return ent["label"]

    # ---- alias assignment ----------------------------------------------
    def _ensure_alias(self, value: str, key: str, category: str, prefix: str,
                     entity_id: str | None = None) -> str:
        """Return the alias for (value, category[, entity]), creating it if new.
        Does NOT bump the occurrence count (used for reservation/linking)."""
        if entity_id is not None:
            label = self._entities[entity_id]["label"]
            ckey = f"E\x00{entity_id}\x00{prefix}\x00{key}"
            counter_name = f"{label}.{prefix}"
            alias_fmt = "<{label}.{prefix}_{n}>"
        else:
            label = ""
            ckey = f"C\x00{category}\x00{key}"
            counter_name = prefix
            alias_fmt = "<{prefix}_{n}>"
        alias = self._key_index.get(ckey)
        if alias is None:
            n = self._counters.get(counter_name, 0) + 1
            self._counters[counter_name] = n
            alias = alias_fmt.format(label=label, prefix=prefix, n=n)
            self._key_index[ckey] = alias
            self._entries[alias] = {
                "original": value, "category": category,
                "count": 0, "files": [], "entity": entity_id,
            }
        return alias

    def alias_for(self, value: str, key: str, category: str, prefix: str,
                 file: str | None = None, entity_id: str | None = None) -> str:
        alias = self._ensure_alias(value, key, category, prefix, entity_id)
        entry = self._entries[alias]
        entry["count"] += 1
        if file and file not in entry["files"]:
            entry["files"].append(file)
        return alias

    def link_identifier_to_entity(self, value: str, category: str, prefix: str,
                                 entity_id: str) -> str:
        """Reserve the entity-scoped alias for ``value`` and, if the value was
        already given a plain alias on an earlier run (before the operator knew
        it belonged to this entity), mark that plain alias as superseded — so
        old outputs still reverse and the equivalence is recorded. Immutable:
        the old alias is never reassigned to a different value."""
        key = value.casefold()
        ent_alias = self._ensure_alias(value, key, category, prefix, entity_id)
        for pk in (f"C\x00{category}\x00{value}", f"C\x00{category}\x00{key}"):
            plain = self._key_index.get(pk)
            if plain and plain != ent_alias:
                self._entries[plain]["superseded_by"] = ent_alias
                sup = self._entries[ent_alias].setdefault("supersedes", [])
                if plain not in sup:
                    sup.append(plain)
                break
        return ent_alias

    # ---- views ----------------------------------------------------------
    def decode_table(self) -> dict[str, dict]:
        return {a: dict(meta) for a, meta in self._entries.items()}

    def reverse_pairs(self) -> list[tuple[str, str]]:
        pairs = [(a, m["original"]) for a, m in self._entries.items()]
        pairs.sort(key=lambda p: -len(p[0]))
        return pairs

    @property
    def categories(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for meta in self._entries.values():
            out[meta["category"]] = out.get(meta["category"], 0) + 1
        return out

    def legend(self) -> dict[str, dict]:
        """entity label -> {pretty, type, notes, aliases, superseded_aliases}."""
        out: dict[str, dict] = {}
        for eid, ent in self._entities.items():
            alias_set = [a for a, m in self._entries.items() if m.get("entity") == eid]
            aset = set(alias_set)
            superseded = [a for a, m in self._entries.items()
                          if m.get("superseded_by") in aset]
            out[ent["label"]] = {
                "entity_id": eid, "pretty": ent.get("pretty", ""),
                "type": ent.get("type", ""), "notes": ent.get("notes", ""),
                "aliases": alias_set, "superseded_aliases": superseded,
            }
        return out

    # ---- serialisation (vault) -----------------------------------------
    def to_dict(self) -> dict:
        return {
            "_schema": VAULT_SCHEMA,
            "key_index": self._key_index,
            "entries": self._entries,
            "counters": self._counters,
            "entities": self._entities,
            "entity_counters": self._entity_counters,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AliasMap":
        m = cls()
        if data.get("_schema") != VAULT_SCHEMA:
            raise ValueError(f"unsupported vault schema: {data.get('_schema')}")
        m._key_index = dict(data.get("key_index", {}))
        m._entries = {a: dict(v) for a, v in data.get("entries", {}).items()}
        m._counters = dict(data.get("counters", {}))
        m._entities = {e: dict(v) for e, v in data.get("entities", {}).items()}
        m._entity_counters = dict(data.get("entity_counters", {}))
        return m


def _overlaps(s: int, e: int, claimed: list[tuple[int, int]]) -> bool:
    return any(not (e <= cs or s >= ce) for cs, ce in claimed)


def find_spans(
    text: str,
    detectors: list[Detector],
    allowlist_cf: frozenset[str] = frozenset(),
) -> list[tuple[int, int, str, Detector]]:
    candidates: list[tuple[int, int, int, int, str, Detector]] = []
    for det in detectors:
        named = "pii" in det.pattern.groupindex
        for m in det.pattern.finditer(text):
            if det.accept is not None and not det.accept(m, text):
                continue
            if named:
                s, e = m.span("pii")
                val = m.group("pii")
            else:
                s, e = m.span(0)
                val = m.group(0)
            if val is None or s == e:
                continue
            if val.casefold() in allowlist_cf:
                continue
            candidates.append((det.priority, -(e - s), s, e, val, det))

    candidates.sort(key=lambda c: (-c[0], c[1], c[2]))

    claimed: list[tuple[int, int]] = []
    chosen: list[tuple[int, int, str, Detector]] = []
    for _prio, _neglen, s, e, val, det in candidates:
        if _overlaps(s, e, claimed):
            continue
        claimed.append((s, e))
        chosen.append((s, e, val, det))

    chosen.sort(key=lambda c: c[0])
    return chosen


def tokenize(
    text: str,
    detectors: list[Detector],
    amap: AliasMap,
    allowlist_cf: frozenset[str] = frozenset(),
    file: str | None = None,
) -> tuple[str, list[Replacement]]:
    chosen = find_spans(text, detectors, allowlist_cf)
    parts: list[str] = []
    reps: list[Replacement] = []
    last = 0
    for s, e, val, det in chosen:
        key = val.casefold() if det.casefold_key else val
        alias = amap.alias_for(val, key, det.category, det.prefix, file, det.entity_id)
        parts.append(text[last:s])
        parts.append(alias)
        last = e
        reps.append(Replacement(s, e, val, alias, det.category))
    parts.append(text[last:])
    return "".join(parts), reps


def tokenize_segment(
    text: str,
    detectors: list[Detector],
    amap: AliasMap,
    allowlist_cf: frozenset[str] = frozenset(),
    file: str | None = None,
    *,
    safe_end: int | None = None,
) -> tuple[str, list[Replacement], int]:
    """Tokenise ``text`` but only commit replacements whose span END is
    <= ``safe_end``; return ``(committed_text, reps, consumed)`` where
    ``consumed`` is the number of leading characters of ``text`` that were
    safely emitted. The caller carries ``text[consumed:]`` into the next chunk.

    This lets a streaming caller process overlapping chunks without ever
    splitting a replacement across a commit boundary. Aliases are assigned
    against the shared ``amap`` exactly as :func:`tokenize` would, in the same
    left-to-right order, so a streamed run is identical to a whole-file run.

    When ``safe_end`` is None, behaves like :func:`tokenize` and consumes the
    whole string.
    """
    if safe_end is None:
        safe_end = len(text)
    chosen = find_spans(text, detectors, allowlist_cf)
    parts: list[str] = []
    reps: list[Replacement] = []
    last = 0
    # cut = how far we may safely emit plain text. Starts at safe_end but is
    # pulled back to the START of the first span that crosses safe_end, so we
    # never emit the leading fragment of a token whose tail is carried over
    # (which would split the token and leak the un-aliased remainder).
    cut = safe_end
    for s, e, val, det in chosen:
        if e > safe_end:
            # This span (and every later one, since chosen is sorted by start)
            # crosses the boundary. Don't emit its leading fragment: pull the
            # cut back to its start and carry the whole span into the next
            # chunk. If the span itself starts past safe_end, keep cut=safe_end.
            if s < cut:
                cut = s
            break
        key = val.casefold() if det.casefold_key else val
        alias = amap.alias_for(val, key, det.category, det.prefix, file, det.entity_id)
        parts.append(text[last:s])
        parts.append(alias)
        last = e
        reps.append(Replacement(s, e, val, alias, det.category))
    # Emit the plain-text gap between the last committed span and the cut.
    if cut > last:
        parts.append(text[last:cut])
    consumed = max(last, cut)
    return "".join(parts), reps, consumed


def reverse_text(text: str, pairs: list[tuple[str, str]]) -> str:
    if not pairs:
        return text
    pattern = re.compile("|".join(re.escape(a) for a, _ in pairs))
    lut = {a: o for a, o in pairs}
    return pattern.sub(lambda m: lut[m.group(0)], text)
