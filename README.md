# piiscrub

Reusable, **local-only** PII pseudonymiser for log and text trees. Point it at a
folder; it writes stripped copies into a new folder and keeps the decode map with
the originals. The same real value always maps to the same opaque alias
(`<IP_7>`, `<EMAIL_3>`), so analysts keep correlation without ever seeing the
real values. Fully reversible from the decode map.

Generalised from an internal log-redaction toolset into a general-purpose tool
for many log types. **Stdlib-only at runtime** (needs Python 3.11+ for
`tomllib`); no third-party dependencies, so the optional Windows `.exe` stays
small and low-AV-risk.

> **Local-only by design.** This tool never makes network calls. The decode map,
> the `_pii/` sidecar, and any project vault contain the real PII and must
> **never** be committed or shared. See [SECURITY.md](SECURITY.md).

---

## Quick start

```bash
# 1. Dry-run: see what WOULD be stripped (writes a report only, no changes)
piiscrub scan  ./logs

# 2. Strip: stripped mirror -> ./clean; decode map + report + manifest -> ./logs/_pii
#    A residual-PII verify pass runs automatically at the end.
piiscrub strip ./logs ./clean

# 3. Verify: re-scan a stripped tree for residual PII (fail-closed, exit 10)
piiscrub verify ./clean

# 4. Reverse a stripped file back to the original
piiscrub reverse ./clean/app.log ./app.restored.log --map ./logs/_pii/decode.json
```

Run from source without installing:

```bash
PYTHONPATH=src python -m piiscrub scan ./logs
```

---

## Commands

| Command | What it does |
|---------|--------------|
| `scan SRC` | **Dry-run.** Detects PII and writes a preview report to `SRC/_pii/scan_report.{html,json}`. Writes **no** stripped files and **no** decode map. |
| `strip SRC DST` | Writes a stripped mirror into `DST`; writes the decode map + report + chain-of-custody manifest into `SRC/_pii/` (or the project vault); then **auto-runs verify**. |
| `verify DST` | Re-scans a stripped tree for residual PII shapes and stray sidecars. **Fail-closed** — exits `10` on any finding. |
| `reverse IN OUT --map M` | Rehydrates aliases in `IN` back to originals using a decode map, writing `OUT`. |
| `--selftest` | Compiles every detector and runs a tiny tokenise → reverse → re-scan round-trip; exits `0` on success. CI uses this to prove a frozen `.exe` actually runs. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (and, for `verify` / the auto-verify in `strip`, the tree is clean). |
| `10` | `verify` found residual PII or a stray decode/report sidecar (also returned by `strip` if its auto-verify fails). |
| `3` | Project vault is locked by another run (a stale `.lock` can be removed manually). |
| `1` | Other operational error (missing file, bad value, bad config key). |
| `2` | No command given (prints help). |

---

## What it detects

**On by default (high-confidence):**

| Category | Notes |
|----------|-------|
| IPv4 | Octets ≤ 255; dotted-quads in version/firmware context (e.g. `version 2.0.0.0`, `v1.2.3.4`) are **not** treated as IPs. |
| IPv6 | `::`-compressed forms and full 8-group forms (the full form requires a hex letter so pure-decimal time-shaped groups are skipped). |
| MAC | Colon- or hyphen-separated. |
| Email | Casefolded alias key (`A@x` and `a@x` share an alias). |
| URL | `http(s)`/`ftp`. Out-ranks any host/IP inside it, so a URL becomes one `<URL_n>`, never double-tokenised. |
| FQDN / hostname | Curated TLD set chosen to avoid colliding with common file extensions; all-numeric labels skipped. |
| UUID / GUID | Standard 8-4-4-4-12 form. |
| JWT | `eyJ…` three-segment tokens. |
| AWS access key | `AKIA…` / `ASIA…`. |
| Google API key | `AIza…`. |
| Bearer token | The token after `Bearer ` is tokenised; the `Bearer ` prefix is kept. |
| PEM private-key block | Whole `-----BEGIN … PRIVATE KEY-----` … `-----END …-----` block. |
| Credit card | Luhn-validated; 13–19 digits. |
| Windows user path / `/home/<name>` | Only the username is tokenised — `C:\Users\jdoe\` becomes `C:\Users\<WINUSER_1>\`. |
| Windows SID | `S-1-…`. |

**Opt-in (more false positives, off unless enabled):**

| Category | Enable with |
|----------|-------------|
| Phone | `--enable phone` (or `enable = ["phone"]` in config). |

Only the **sensitive span** of a match is tokenised. When a detector defines a
`pii` capture group (e.g. Windows user path, Bearer token) only that group is
replaced and the surrounding literal text is preserved.

---

## How aliasing works

* The same real value always maps to the same alias **across every file in a
  run** (and across every run when using a project vault).
* Aliases are stable per category: `<IP_1>`, `<IP_2>`, `<EMAIL_1>`, …
* Overlaps are resolved by a single-pass, priority-ordered tokenizer:
  1. All enabled detectors scan the text → candidate spans (validated).
  2. Spans are sorted by `(priority desc, length desc, start asc)`.
  3. The longest, highest-priority non-overlapping spans are claimed greedily.
  4. Claimed spans are replaced left-to-right.

So `https://host.vendor.example.com/x?ip=192.0.2.5` becomes a single `<URL_n>`,
never a tangle of nested aliases.

---

## Custom rules — `piiscrub.toml`

```toml
# In TOML, top-level keys MUST come before any [table] / [[array]] header.
include   = []                       # globs to include; [] means "all files"
exclude   = ["*.min.js", "vendor/**"]
allowlist = ["pool.ntp.org"]         # literal values to NEVER tokenise
denylist  = ["ProjectFalcon"]        # literal values to ALWAYS tokenise (case-insensitive)

[detectors]
disable = ["credit_card"]            # turn built-ins off
enable  = ["phone"]                  # turn opt-in detectors on

[[custom]]                           # operator patterns get top priority; keep LAST
name  = "asset_tag"
type  = "regex"                      # "regex" or "literal"
value = "ASSET-[0-9]{6}"
```

* **Custom** patterns get higher priority than the generic built-ins, so a
  specific hostname or asset scheme wins over the generic `fqdn` detector.
  Custom regexes are compiled and validated at load (a typo fails fast).
* **Denylist** literals get the highest priority of all (always tokenised).
* **Allowlist** values are matched case-insensitively and never tokenised.

Pass the file with `--config piiscrub.toml`. A worked example lives in
[`examples/piiscrub.toml`](examples/piiscrub.toml).

Detector toggles and filters can also be given on the CLI and merge **on top of**
the config:

```
--enable D          --disable D         (repeatable detector toggles)
--include GLOB      --exclude GLOB      (repeatable globs)
--max-bytes N       --stream-threshold N
```

---

## Profiles

Named preset bundles for common log types, selected with `--profile`:

```
generic | network-gear | syslog | windows-logs | pcap-text
```

* `generic` — everything on, no extra filtering.
* `network-gear` — disables `credit_card`, `windows_user_path`, `windows_sid`
  (noise on network device logs).
* `syslog` — includes `*.log`, `*.txt`.
* `windows-logs` — includes `*.log`, `*.txt`, `*.csv`.
* `pcap-text` — includes `*.txt`, `*.csv` (packet captures exported to text).

Layering order: **profile → `--config` file → CLI flags** (later layers win or
union, as appropriate).

---

## Cross-run correlation + entities (project vault)

For investigations spanning many vendors, dates, and log types, use a central
**project vault** so the same value gets the same alias everywhere — across
every run:

```bash
piiscrub strip ./syslog ./out-syslog --project ./case42 --profile syslog
piiscrub strip ./pcap   ./out-pcap   --project ./case42 --profile pcap-text
# 10.0.0.5 is <IP_1> in BOTH outputs; grep across them to correlate.
```

The vault is the single place real PII lives in project mode.

```
case42/                      central project vault
├── map.json                 master alias map, cross-run (locked 0600)
├── entities.csv             operator entity table (optional input)
├── legend.json              entity -> aliases + friendly name (generated, sensitive)
├── manifest_log.jsonl       append-only chain-of-custody audit trail
├── runs/<timestamp>/        per-run report.json + manifest.json
└── .lock                    present only while a run is active
```

A vault run takes an exclusive `.lock`. If a previous run crashed and left the
lock behind, the next run exits `3`; delete `.lock` once you are sure no run is
in progress.

### Entity table — grouping a thing's identifiers

To link a device's different identifiers (IP + hostname + MAC) as one logical
thing, give the tool an **entity table** CSV (default location
`<project>/entities.csv`, or `--entities PATH`):

```csv
id,type,pretty_name,identifiers,notes
core-sw,device,Core Switch Alpha,10.0.0.5;SW-CORE-01;de:ad:be:ef:00:11,core switch
```

* Columns: `id, type, pretty_name, identifiers, notes`. `id` and `identifiers`
  are required; `identifiers` is a `;`-separated list. The header row is required.
* Every listed identifier is **force-tokenised** — even bare hostnames like
  `SW-CORE-01` that match no built-in shape.
* Identifiers grouped under one entity share an **entity-scoped alias**, so the
  device is visibly the same across every log/vendor/date and you still see
  which identifier each line used:

  ```
  <DEV0001.IP_1>   <DEV0001.HOST_1>   <DEV0001.MAC_1>
  ```

* The entity label prefix comes from `type`: `device → DEV`, `person → USR`,
  `site → SITE`, `service → SVC` (other types derive a short prefix). The label
  is zero-padded (`DEV0001`).
* The **friendly name** (`pretty_name`, e.g. "Core Switch Alpha") is kept only
  in `legend.json` inside the vault — it can itself be sensitive and is **never**
  written into the shareable stripped output.

**Late-arriving identifiers (supersession).** If a value was already given a
plain alias on an earlier run, and you later add it to an entity, the tool marks
the old plain alias as `superseded_by` the new entity-scoped alias and records
the equivalence (`supersedes`). Aliases are immutable — an old alias is never
re-pointed to a different value — so previously stripped outputs still reverse
correctly.

**Starter CSV.** Run `scan --emit-entities` (or `strip --emit-entities`) to get
a starter `entities_starter.csv` listing every detected IP / host / MAC / email
for you to annotate (assign an `id`, group identifiers, add a friendly name),
then re-run.

A worked example entity table lives in
[`examples/entities.csv`](examples/entities.csv).

---

## Output layout (standalone, no vault)

```
logs/                    sensitive zone (stays put)
├── ...originals...
└── _pii/                the ONE place PII lives (locked to your user)
    ├── decode.json      alias -> original (+ category, count, files)
    ├── report.{html,json}
    └── manifest.json    chain-of-custody hashes for this run
clean/                   shareable zone — stripped mirror, never any decode/PII
└── ...stripped files...
```

* The decode map lives in `SRC/_pii/decode.json` in standalone mode; in project
  mode it lives in the vault's `map.json` instead (no `decode.json` is written
  to `_pii`).
* `_pii/` is locked to the current user (`0700` on POSIX; best-effort `icacls`
  on Windows). If locking fails the tool prints a **loud warning** rather than
  giving a silent false guarantee.
* **Guards:** `SRC` and `DST` must differ and must not be nested inside one
  another; in project mode the vault must not live inside `SRC` or `DST`.
* The report contains **aliases and counts only** — never raw originals — so it
  is safe to glance at or share. Real values live solely in the decode map.

---

## Chain-of-custody (regulated data)

Every `strip` writes a `manifest.json` containing the SHA-256 of each original
**and** each stripped file, the per-file encoding and replacement count,
timestamps, and a run-level digest computed over all the per-file hashes (so the
manifest itself is tamper-evident). In project mode a one-line summary record is
also appended to `case42/manifest_log.jsonl` as an audit trail, and a full copy
is stored under `runs/<timestamp>/`.

---

## File handling

* **Encoding:** BOM detection (UTF-8 / UTF-16 / UTF-32) → else strict UTF-8 →
  else cp1252. Output is re-encoded in the detected encoding (UTF-16/32 keep
  their BOM).
* **Binary / undecodable files** (a NUL byte in the first 4 KB, or a known
  binary extension such as `.pcap .evtx .xlsx .docx .zip .png`) are **copied
  through unchanged and flagged** in the report as "may contain PII" — never
  silently half-stripped.
* **Adaptive streaming for huge files.** Files at or below `stream_threshold`
  (default 50 MB) are processed whole, which preserves multi-line token
  detection (e.g. PEM private-key blocks). Larger files are processed in
  **overlapping streamed chunks** so memory stays flat for multi-GB logs, with
  output **byte-identical** to whole-file processing. If a streamed file turns
  out to contain undecodable bytes mid-stream, any partial output is discarded
  and the original is copied through and flagged, matching whole-file semantics.
* **Hard size ceiling.** `--max-bytes N` copies files larger than `N` through
  unprocessed and flags them. It is effectively **off** by default — large files
  are streamed rather than skipped.
* **Progress bar.** A single-line progress bar is drawn to stderr (so it never
  pollutes the JSON on stdout) and auto-disables when stderr is not a TTY. Use
  `--no-progress` to silence it.

Format extractors for archives/structured binaries (evtx/xlsx/zip) remain on the
backlog — see
[`docs/plans/2026-06-18-pii-scrubber-design.md`](docs/plans/2026-06-18-pii-scrubber-design.md).

---

## Build (Windows `.exe`)

No runtime dependencies — stdlib only (needs Python 3.11+ for `tomllib`). The
Windows `.exe` is **built in CI** on `windows-latest` via GitHub Actions
(PyInstaller, one-file, `console=True`, `upx=False`, UTF-8 mode, with a build
self-test gate):

* Push any branch → builds and uploads the `.exe` artifact.
* Push a tag `v*` → builds and publishes a Release with the `.exe` attached.

Code signing is deferred. On first run, a Windows SmartScreen warning clears via
right-click → **Properties** → **Unblock** → OK.

---

## Documentation

* [`docs/USAGE.md`](docs/USAGE.md) — worked end-to-end examples.
* [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup and tests.
* [`SECURITY.md`](SECURITY.md) — responsible disclosure and the local-only data rules.
* [`docs/plans/2026-06-18-pii-scrubber-design.md`](docs/plans/2026-06-18-pii-scrubber-design.md) — design rationale and roadmap.
