# PII Scrubber — Design (v1)

**Date:** 2026-06-18
**Status:** Validated, building v1
**Origin:** Generalised from an internal log-redaction toolset
(`analysis/pseudonymize.py` + `analysis/redactor.py`) into a reusable,
general-purpose tool.

## Purpose

Point the tool at a folder. It walks every file, writes **stripped copies**
into a new folder, and keeps a **decode map** (the only place real PII lives)
in the original folder. Same real value always maps to the same opaque alias,
so analysts keep correlation ("`<IP_7>` appears 40×") without seeing the real
value. The operator can add custom patterns (hostnames, asset tags, etc.).
A report is produced at the end. Reversible via the decode map.

Used across many log types for different jobs → must be accurate, configurable,
and file-type tolerant.

## Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Windows packaging | Standalone `.exe` (PyInstaller, `console=True` CLI) |
| 2 | Default handling | Reversible, consistent per-value tokens + decode map |
| 3 | Location | New standalone repo (`pii-scrubber`) |
| 4 | Safety posture | Mandatory dry-run (`scan`); FP-heavy detectors opt-in |
| 5 | `.exe` build | GitHub Actions `windows-latest` (can't cross-compile from Linux) |

Build pattern reused from an existing internal PyInstaller-on-CI repo
(GH Actions → PyInstaller → artifact + tag-release, with build self-test gates).

## Core insight

The original split into two philosophies — `redactor.py` (destructive: every
IP → the *same* token, kills correlation) and `pseudonymize.py` (reversible,
per-value codes). The reusable tool unifies on **one engine**: a single-pass,
priority-ordered tokenizer producing stable per-value aliases recorded in one
decode map. "Redaction" (irreversible) is just "pseudonymize and discard the
map" — not built in v1 (decision 2), but the design leaves room.

## Architecture

```
piiscrub/
  detectors.py  — Detector dataclass + built-in detector registry
  engine.py     — single-pass span tokenizer + AliasMap (the consistency core)
  config.py     — TOML config: enable/disable, custom patterns, allow/deny
  walker.py     — folder walk, encoding detection, binary handling, mirror I/O
  report.py     — HTML + JSON run report (PII-free; aliases & counts only)
  audit.py      — verify (re-scan output, fail-closed) + reverse (rehydrate)
  cli.py        — scan / strip / verify / reverse / --selftest
```

Zero runtime third-party deps (stdlib only: `re`, `tomllib`, `codecs`,
`fnmatch`, `html`, `json`). Keeps the `.exe` tiny and low-AV-risk.
Dev/build deps only: `pytest`, `pyinstaller`.

### Detector model

```python
@dataclass(frozen=True)
class Detector:
    category: str            # "ipv4", "email", ...
    prefix: str              # alias prefix → <IP_1>, <EMAIL_3>
    pattern: re.Pattern      # may expose a (?P<pii>...) group
    priority: int            # higher claims overlaps first
    on_by_default: bool
    validator: Callable[[str], bool] | None = None   # e.g. Luhn, octet<=255
    casefold_key: bool = False                        # email/host alias key
```

- A match's **sensitive span** = group `pii` if present, else group 0. Only that
  span is tokenized (so `C:\Users\jdoe\` → `C:\Users\<WINUSER_1>\`, prefix kept).
- Alias key = matched value, casefolded for email/host so `A@x`/`a@x` share an
  alias. Stable per run via a per-category counter.

### Single-pass overlap resolution

1. All enabled detectors `finditer` over the text → candidate spans (validated).
2. Sort by (priority desc, span-length desc, start asc).
3. Greedily claim spans that don't overlap an already-claimed range.
4. Replace claimed spans left-to-right via the AliasMap.

So `https://host.corp/x?ip=1.2.3.4` becomes one `<URL_n>` (URL out-prioritises
host + ipv4), never double-substituted.

### AliasMap (consistency + decode)

- `value → alias` and `alias → {original, category, count, files}`.
- Shared across **all files in the run** → cross-file consistency.
- Serialised to `decode.json` (the single PII store).

## Built-in detectors

**On by default (high-confidence):** ipv4 (octet ≤ 255, version-context
exempt), ipv6 (`::` or full-8 w/ hex letter), mac, email, url, fqdn/hostname
(public allowlist; all-numeric skipped), uuid/guid, jwt, aws_access_key,
google_api_key, bearer_token, private_key_block (PEM), credit_card
(Luhn-checked), windows_user_path, windows_sid.

**Opt-in (FP-heavy, off unless enabled):** phone. *(names, national-id,
free-text address → v2; needs lists/NER.)*

## Configuration (`piiscrub.toml`, optional)

```toml
# Top-level keys MUST precede any [table]/[[array]] header (TOML rule).
allowlist = ["pool.ntp.org"]   # never tokenize these literal values
denylist  = ["ProjectCondor"]  # always tokenize (literal, top priority)

[detectors]
disable = ["credit_card"]      # turn built-ins off
enable  = ["phone"]            # turn opt-in detectors on

[[custom]]                     # operator-defined; high priority; keep LAST
name = "asset_tag"
type = "regex"                 # or "literal"
value = "ASSET-[0-9]{6}"
```

Custom regexes are compiled + validated at load (typo fails fast). Custom
detectors get top priority so a specific hostname wins over generic `fqdn`.

## Run model & CLI

- `piiscrub scan SRC [opts]` — **dry-run.** Detect only; write a preview report
  to `SRC/_pii/scan_report.{html,json}`. No stripped files, no decode map.
- `piiscrub strip SRC DST [opts]` — write stripped mirror to `DST`; write
  `decode.json` + `report.{html,json}` to `SRC/_pii/`; then auto-run `verify`.
- `piiscrub verify DST [--map M]` — re-scan `DST` for residual PII shapes and
  confirm no `_pii`/decode files leaked in. **Fail-closed** (exit 10).
- `piiscrub reverse IN OUT --map M` — rehydrate aliases → originals.
- `piiscrub --selftest` — compile all detectors + a tiny round-trip; exit 0.
  (CI uses this to prove the frozen `.exe` actually runs.)

Common opts: `--config`, `--include GLOB` (repeatable), `--exclude GLOB`,
`--enable D`, `--disable D`, `--max-bytes N`.

## Output layout

```
SRC/                         sensitive zone (stays put)
├── ...originals...
└── _pii/                    the one place PII lives; locked to current user
    ├── decode.json          alias → original (+ category, count, files)
    └── report.{html,json}
DST/                         shareable zone — stripped mirror, NEVER any _pii
└── ...stripped files...
```

Guards: refuse if `DST` is inside `SRC` (or vice versa). `verify` enforces that
`DST` contains zero decode/report files. `_pii/` is locked `0700` on POSIX and
via `icacls` (best-effort) on Windows; if locking fails → loud warning (not a
silent false guarantee — the original `chmod 0600` was a no-op on Windows).

## File handling & accuracy

- **Encoding:** BOM detection (utf-8-sig / utf-16 / utf-32) → else try utf-8 →
  else cp1252. Output re-encoded in the detected encoding (utf-16 keeps BOM).
- **Undecodable / known-binary** (`.evtx .pcap .xlsx .docx .zip .png` …):
  copied through **unchanged** and **flagged** in the report as "not processed —
  may contain PII." Never silently half-stripped. (v2: format extractors.)
- **Large files:** above `--max-bytes` (default 200 MB) → skipped + flagged
  (avoids OOM; whole-file read in v1). (v2: streaming.)

## Report (PII-free)

HTML + JSON. Sections: run metadata (src/dst/time/version), per-category counts
(category, unique values, total occurrences, files touched), per-custom-pattern
counts, files skipped/binary/undecodable, warnings, `verify` PASS/FAIL. Contains
**aliases and counts only** — never raw originals (those live solely in
`decode.json`), so the report is safe to glance at or share.

## Testing

- engine: cross-file consistent aliasing; overlap resolution (url>host>ip);
  reverse round-trip; capture-group span (winuser); Luhn accept/reject.
- detectors: each built-in — one positive, one near-miss negative (e.g. version
  string not tokenized).
- walker: utf-16 round-trip; binary passthrough+flag; include/exclude; layout
  (decode in SRC not DST); SRC/DST containment guard.
- cli: scan writes no stripped files; strip→verify clean; verify catches a
  planted leak; reverse; `--selftest` exit 0.

## Packaging & CI (reused from the internal PyInstaller-on-CI build pattern)

- `packaging/piiscrub.spec`: one-file exe, `console=True`, `upx=False`
  (AV/DLL), `runtime_options=["utf8_mode=1"]` (non-ASCII Windows paths safe
  when frozen).
- `.github/workflows/build-windows-exe.yml` on `windows-latest`: setup-python
  3.12 → install → `pyinstaller --noconfirm --clean` → verify exe exists →
  `--selftest` gate → upload artifact → on tag `v*` publish Release w/
  SmartScreen-Unblock note. Tag passed via `env:` (workflow-injection safe).
- **Code signing deferred** (internal tool; SmartScreen-Unblock note suffices).
  Azure Trusted Signing via OIDC is the documented upgrade path.

## Out of scope for v1 (v2 backlog)

Named profile library · field-aware JSON/CSV/XML redaction · `.zip`
extract→strip→rezip · streaming for huge files · cross-run stable map reuse ·
chain-of-custody hashes · optional cross-platform LLM second pass · GUI ·
names/national-id/address detectors · irreversible redact mode.

---

## v2 — decisions confirmed with operator (2026-06-18)

The operator did **not** agree to the v1/v2 split above; the items were
re-reviewed individually. Resulting plan:

| Item | Decision |
|------|----------|
| Field-aware JSON/CSV/XML | **Parked** — ship flat regex, reassess on real data |
| Big files | **Adaptive**: whole-file under threshold (catches multi-line tokens); overlap-chunked streaming above it (overlap ≥ largest token) |
| Zip | **No extraction** (op unzips); keep nested-folder mirroring; add progress bar |
| Cross-run reuse | **Yes** — central project vault (`--project`); same value → same alias across runs/vendors/dates |
| Entity relationships | **Yes** — operator entity CSV groups a thing's identifiers; alias form **`<DEV0001.HOST_1>`** (zero-padded id + type, inline); pretty name kept in vault legend only |
| Chain-of-custody | **Yes** — SHA-256 of every original + stripped file, run digest, audit log (regulated data) |
| LLM second pass | **Yes, optional, off by default** — on already-stripped text only, flag-only; local model default; cloud hard-gated behind `--allow-cloud`; key via env or `--forget-key` to wipe after run |
| GUI | **Yes — both** CLI and PySide6 GUI (two exes, same PyInstaller build pattern) |
| Names/national-id/address (NER) | **Dropped** — this is a logs tool, not a documents tool |
| Named profiles | **Yes** — shipped presets (generic/network-gear/syslog/windows-logs/pcap-text) |
| Irreversible redact mode | Not requested; left out (reversible only) |

### Build phases

- **Phase B (DONE, this build):** central vault (`projectmap.py`), entity
  table + `<DEV0001.TYPE_n>` aliasing (`entities.py`, engine entity support),
  chain-of-custody manifest (`manifest.py`), named profiles (`profiles.py`,
  config layering). 41 tests pass; cross-run entity-linking verified end-to-end.
- **Phase A (DONE):** adaptive streaming for huge files (#3, whole-file under
  `stream_threshold`, overlapping-chunk streaming above, copy-through fallback on
  mid-stream undecodable bytes); progress-event interface + CLI bar (#4). Built
  by agent, audited by reviewer agent, two PII-leak/correctness findings fixed,
  independently re-verified (62 tests; streamed output byte-identical to
  whole-file). Plus late-arriving-identifier supersession (entity equivalence).
- **Phase C (next):** optional LLM second pass (#7) via stdlib HTTP.
- **Phase D (next):** PySide6 GUI + second exe + CI target (#8).

### Vault layout (project mode)

```
<project>/
  map.json            master alias map, cross-run [0600]
  entities.csv        operator entity table (id,type,pretty_name,identifiers,notes)
  legend.json         entity -> aliases + pretty name (generated)
  manifest_log.jsonl  append-only audit trail (one line per run)
  runs/<ts>/          per-run report.json + manifest.json
  .lock               present only while a run is active
```
