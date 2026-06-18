# piiscrub — Usage Guide

This guide walks through the common workflows with concrete, end-to-end
examples. All values below are fictional: organisation **Acme**, device
**Core Switch Alpha**, domain **vendor.example.com**, emails `@example.com`, and
IP addresses from the documentation/private ranges (`192.0.2.0/24`, `10.0.0.0/8`).

Commands are shown as the installed `piiscrub` console script. To run from a
source checkout instead, replace `piiscrub` with `PYTHONPATH=src python -m piiscrub`.

> **Reminder:** the decode map and `_pii/` sidecar contain the real PII and must
> never be committed or shared. See [SECURITY.md](../SECURITY.md).

---

## Example 1 — Dry-run a folder (`scan`)

You have a folder of logs and want to see what *would* be stripped before
touching anything. `scan` detects PII and writes a preview report only — no
stripped files, no decode map.

```bash
piiscrub scan ./acme-logs
```

Sample stdout:

```json
{
  "mode": "scan",
  "files_total": 42,
  "files_processed": 39,
  "would_replace": 1875,
  "report": "/.../acme-logs/_pii/scan_report.html"
}
```

Open the report to review the per-category breakdown (aliases and counts only —
never raw values):

```bash
open ./acme-logs/_pii/scan_report.html      # macOS; use xdg-open on Linux
```

Tune detection before committing to a strip:

```bash
# Turn on the opt-in phone detector and skip credit-card matches for this run
piiscrub scan ./acme-logs --enable phone --disable credit_card

# Limit to specific file types
piiscrub scan ./acme-logs --include '*.log' --include '*.txt'
```

---

## Example 2 — Strip a folder (`strip` + auto-verify)

Produce a shareable, stripped mirror. The decode map, report, and
chain-of-custody manifest are written next to the originals in `_pii/`, and a
fail-closed `verify` pass runs automatically at the end.

```bash
piiscrub strip ./acme-logs ./acme-clean
```

Sample stdout:

```json
{
  "mode": "strip",
  "files_processed": 39,
  "files_copied_unprocessed": 3,
  "replacements": 1875,
  "entities": 0,
  "decode_map": "/.../acme-logs/_pii/decode.json",
  "report": "/.../acme-logs/_pii/report.html",
  "manifest": "/.../acme-logs/_pii/manifest.json",
  "run_digest": "9f86d081...",
  "verify": "PASS"
}
```

Resulting layout:

```
acme-logs/                 sensitive — stays put
├── ...originals...
└── _pii/                  the ONE place PII lives (locked to your user)
    ├── decode.json        alias -> original (+ category, count, files)
    ├── report.{html,json}
    └── manifest.json
acme-clean/                shareable — stripped mirror, no PII
└── ...stripped files...
```

A line that read:

```
2026-06-18T09:12:04 admin a.user@example.com from 10.0.0.5 reached https://vendor.example.com/api
```

comes out as:

```
2026-06-18T09:12:04 admin <EMAIL_1> from <IP_1> reached <URL_1>
```

The same `10.0.0.5` is `<IP_1>` in *every* file of the run, so correlation
survives. If the auto-verify reports `FAIL`, `strip` exits `10` and prints the
residual findings to stderr — do not share the output until it passes.

Apply a profile and a config file together (layering is profile → config → CLI):

```bash
piiscrub strip ./acme-logs ./acme-clean \
  --profile network-gear \
  --config examples/piiscrub.toml \
  --no-progress
```

---

## Example 3 — Cross-run correlation with a project vault and entities

For an investigation spanning several log sources, use a central **project
vault** so the same value gets the same alias across every run, and an **entity
table** so a device's IP, hostname, and MAC are grouped under one identity.

### Step 1 — describe the entities

Create `./case42/entities.csv` (the vault's default entity-table location):

```csv
id,type,pretty_name,identifiers,notes
core-sw,device,Core Switch Alpha,10.0.0.5;SW-CORE-01;de:ad:be:ef:00:11,core switch
admin-jane,person,Jane (admin),jane@example.com;jdoe,primary admin
```

Don't know the identifiers yet? Let the tool propose them:

```bash
piiscrub scan ./syslog --project ./case42 --emit-entities
# writes ./syslog/_pii/entities_starter.csv — annotate it, save as ./case42/entities.csv
```

### Step 2 — strip each source into the same vault

```bash
piiscrub strip ./syslog ./out-syslog --project ./case42 --profile syslog
piiscrub strip ./pcap   ./out-pcap   --project ./case42 --profile pcap-text
```

Because both runs share `./case42`, `10.0.0.5` is the **same alias** in both
outputs. And because that IP, the hostname `SW-CORE-01`, and the MAC are grouped
under the `core-sw` entity, they appear as entity-scoped aliases everywhere:

```
<DEV0001.IP_1>     <DEV0001.HOST_1>     <DEV0001.MAC_1>
```

You can now `grep` across `out-syslog/` and `out-pcap/` to follow one device
through different log types — without ever seeing its real values.

### Step 3 — read the vault

```
case42/
├── map.json            master alias map (cross-run, locked 0600)
├── entities.csv        your entity table
├── legend.json         DEV0001 -> aliases + "Core Switch Alpha" (sensitive!)
├── manifest_log.jsonl  one audit line per run
└── runs/<timestamp>/   per-run report.json + manifest.json
```

The friendly name "Core Switch Alpha" lives **only** in `legend.json` inside the
vault — it is never written into the shareable stripped output.

> **Late-arriving identifiers.** If you strip a source, then later add a value to
> an entity and re-run, the tool keeps the old plain alias working and records
> that it is *superseded by* the new entity-scoped alias. Old stripped outputs
> still reverse correctly; aliases are never re-pointed.

> **Vault lock.** A vault run takes an exclusive `.lock`. If a run crashed and
> left the lock behind, the next run exits `3`; delete `case42/.lock` once you
> are sure nothing is in progress.

---

## Example 4 — Reverse a stripped file (`reverse`)

To rehydrate a stripped file back to its original values, point `reverse` at the
file and the decode map.

Standalone mode (decode map in `_pii/`):

```bash
piiscrub reverse ./acme-clean/app.log ./app.restored.log \
  --map ./acme-logs/_pii/decode.json
```

Project/vault mode (the master map is `map.json`):

```bash
piiscrub reverse ./out-syslog/app.log ./app.restored.log \
  --map ./case42/map.json
```

`--map` accepts either a standalone `decode.json` or a vault `map.json`. Sample
stdout:

```json
{
  "restored_tokens": 312,
  "output": "/.../app.restored.log"
}
```

---

## Example 5 — Reconcile a delivered tree to current canonical aliases (`reconcile`)

**Scenario.** You stripped a set of logs and delivered the output. Later you
grouped `10.0.0.5` into an entity (`core-sw`) so its alias in the vault is now
canonically `<DEV0001.IP_1>`. The delivered tree still says `<IP_1>`. Use
`reconcile` to produce a new, updated copy — without modifying the original
delivered tree.

```bash
# The delivered tree (read-only, never touched by reconcile)
# out-syslog/app.log  contains  … <IP_1> …

piiscrub reconcile ./out-syslog ./out-syslog-v2 --project ./case42
```

Sample stdout:

```json
{
  "mode": "reconcile",
  "files_processed": 12,
  "files_copied_unprocessed": 1,
  "replacements": 48,
  "aliases_reconciled": 2,
  "manifest": "/.../out-syslog-v2/_pii/manifest.json",
  "reconcile_map": "/.../out-syslog-v2/_pii/reconcile_map.json",
  "run_digest": "4e9a12b7..."
}
```

`reconcile` writes three custody files under `out-syslog-v2/_pii/`:

| File | Contents |
|------|----------|
| `manifest.json` | SHA-256 of every source and output file + run digest |
| `reconcile_report.json` | Summary: counts, supersession map, warnings |
| `reconcile_map.json` | `{old_alias: canonical_alias}` applied in this run |

The `_pii/` directory of the **input** tree is never copied into the
reconciled output (the sidecar is excluded by design).

### With a standalone map file

If you do not have a project vault, pass the map directly:

```bash
piiscrub reconcile ./out-syslog ./out-syslog-v2 --map ./decode-or-vault-map.json
```

`--map` accepts either a vault `map.json` or a standalone `decode.json`.

### Reversing a reconciled file

Because the vault map still contains `<IP_1>` (aliases are immutable), a
reconciled file can still be reversed through the vault map:

```bash
piiscrub reverse ./out-syslog-v2/app.log ./app.restored.log \
  --map ./case42/map.json
```

---

## Verifying an existing stripped tree

You can re-run the fail-closed residual-PII check on any stripped tree at any
time:

```bash
piiscrub verify ./acme-clean
```

It exits `0` when the tree is clean, or `10` and prints the findings (residual
PII and any stray decode/report sidecars) when it is not.

---

## Reference: common flags

| Flag | Applies to | Purpose |
|------|------------|---------|
| `--config PATH` | scan, strip, verify | Load a `piiscrub.toml`. |
| `--profile NAME` | scan, strip, verify | Apply a named preset (`generic`, `network-gear`, `syslog`, `windows-logs`, `pcap-text`). |
| `--project DIR` | scan, strip | Use a central cross-run vault. |
| `--entities PATH` | scan, strip | Entity-table CSV (default `<project>/entities.csv`). |
| `--emit-entities` | scan, strip | Write a starter entity CSV of detected identifiers. |
| `--enable D` / `--disable D` | scan, strip, verify | Toggle a detector category (repeatable). |
| `--include GLOB` / `--exclude GLOB` | scan, strip, verify | Filter files (repeatable). |
| `--max-bytes N` | scan, strip, verify | Copy files larger than `N` bytes through unprocessed. |
| `--stream-threshold N` | scan, strip, verify | Stream files larger than `N` bytes (default 50 MB). |
| `--no-progress` | scan, strip, verify | Suppress the stderr progress bar. |
| `--map PATH` | reverse | Decode map (`decode.json`) or vault `map.json`. |
