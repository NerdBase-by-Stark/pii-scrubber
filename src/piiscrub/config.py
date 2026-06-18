"""Operator configuration: named profile -> TOML file -> CLI flags, layered.

Zero third-party deps — stdlib ``tomllib`` (Python 3.11+).
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import profiles as _profiles

DEFAULT_MAX_BYTES = 1 << 62  # effectively no hard skip; huge files are streamed
DEFAULT_STREAM_THRESHOLD = 50 * 1024 * 1024  # 50 MB: above this, stream in chunks


@dataclass
class Config:
    disable: set[str] = field(default_factory=set)
    enable: set[str] = field(default_factory=set)
    custom: list[dict] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    max_bytes: int = DEFAULT_MAX_BYTES
    stream_threshold: int = DEFAULT_STREAM_THRESHOLD
    # Optional [llm] table. CLI flags override these. ``enabled`` only takes
    # effect if the operator also passes --llm (the flag is the explicit
    # opt-in); the config can set provider/endpoint/model defaults.
    llm: dict = field(default_factory=dict)

    @property
    def allowlist_cf(self) -> frozenset[str]:
        return frozenset(s.casefold() for s in self.allowlist)


def _validate_custom(entry: dict, idx: int) -> dict:
    if "name" not in entry or "value" not in entry:
        raise ValueError(f"[[custom]] #{idx}: requires 'name' and 'value'")
    kind = entry.get("type", "regex")
    if kind not in ("regex", "literal"):
        raise ValueError(f"[[custom]] '{entry['name']}': type must be 'regex' or 'literal'")
    if kind == "regex":
        try:
            re.compile(entry["value"])
        except re.error as e:
            raise ValueError(f"[[custom]] '{entry['name']}': invalid regex: {e}") from e
    return {"name": entry["name"], "type": kind, "value": entry["value"]}


def _dedupe(seq: list[str]) -> list[str]:
    out: list[str] = []
    for s in seq:
        if s not in out:
            out.append(s)
    return out


def _merge_raw(base: dict, overlay: dict) -> dict:
    """Layer overlay onto base: enable/disable union; lists concat; custom
    concat; max_bytes overrides."""
    out = {k: v for k, v in base.items()}
    bdet = dict(base.get("detectors", {}) or {})
    odet = dict(overlay.get("detectors", {}) or {})
    bdet["disable"] = _dedupe(list(bdet.get("disable", [])) + list(odet.get("disable", [])))
    bdet["enable"] = _dedupe(list(bdet.get("enable", [])) + list(odet.get("enable", [])))
    out["detectors"] = bdet
    for key in ("allowlist", "denylist", "include", "exclude"):
        out[key] = _dedupe(list(base.get(key, [])) + list(overlay.get(key, [])))
    out["custom"] = list(base.get("custom", [])) + list(overlay.get("custom", []))
    if "max_bytes" in overlay:
        out["max_bytes"] = overlay["max_bytes"]
    if "stream_threshold" in overlay:
        out["stream_threshold"] = overlay["stream_threshold"]
    # [llm] table: merge key-by-key, overlay wins (so a project toml can refine
    # a profile's llm defaults without clobbering the rest).
    bllm = dict(base.get("llm", {}) or {})
    bllm.update(dict(overlay.get("llm", {}) or {}))
    if bllm:
        out["llm"] = bllm
    return out


def _config_from_raw(raw: dict) -> Config:
    det = raw.get("detectors", {}) or {}
    custom = [_validate_custom(e, i) for i, e in enumerate(raw.get("custom", []) or [])]
    return Config(
        disable=set(det.get("disable", []) or []),
        enable=set(det.get("enable", []) or []),
        custom=custom,
        allowlist=list(raw.get("allowlist", []) or []),
        denylist=list(raw.get("denylist", []) or []),
        include=list(raw.get("include", []) or []),
        exclude=list(raw.get("exclude", []) or []),
        max_bytes=int(raw.get("max_bytes", DEFAULT_MAX_BYTES)),
        stream_threshold=int(raw.get("stream_threshold", DEFAULT_STREAM_THRESHOLD)),
        llm=dict(raw.get("llm", {}) or {}),
    )


def _load_raw(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"config not found: {path}")
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def load_config(path: Path | None) -> Config:
    """Load a single TOML config (or defaults if path is None)."""
    if path is None:
        return Config()
    return _config_from_raw(_load_raw(path))


def resolve_config(profile: str | None, config_path: Path | None) -> Config:
    """Layer: profile preset -> TOML file. (CLI flags merge on top later.)"""
    raw: dict = {}
    if profile:
        raw = _merge_raw(raw, _profiles.get_profile(profile))
    if config_path is not None:
        raw = _merge_raw(raw, _load_raw(config_path))
    return _config_from_raw(raw)
