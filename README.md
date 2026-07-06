# piiscrub

![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/NerdBase-by-Stark/pii-scrubber?utm_source=oss&utm_medium=github&utm_campaign=NerdBase-by-Stark%2Fpii-scrubber&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

The north-star job: take messy, multi-source network/AV diagnostic data —
packet captures, device logs, config/CSV exports pulled from dozens of vendors
and devices across different times and clocks — and turn it into something
you can safely hand to a **cloud LLM** for analysis. Every real value (IP,
MAC, hostname, email, credential, …) is replaced by a stable opaque token, the
same real value always mapping to the same token everywhere in a run, so an
LLM (or a person) can still correlate across sources without ever seeing what
a value actually is. The tool keeps **a local map you can use to put the real
values back** once you have the answer — see
[How re-identification works](#how-re-identification-works) below.

The same engine also does the simpler job: a plain, mirror-format stripped
copy of a log tree for sharing with a person or team (the default `generic`
profile). LLM-prep is one flag away (`--profile llm`). One tool, one shared
identity map, two output shapes.

Generalised from an internal log-redaction toolset into a general-purpose tool
for many log types. **Stdlib-only at runtime** (needs Python 3.11+ for
`tomllib`); no third-party dependencies, so the optional Windows `.exe` stays
small and low-AV-risk.

> **Local-only by design.** Core scan/strip make **no network calls.** The only
> exception is the optional, off-by-default `--llm` second pass, which defaults to
> a **local** model and **hard-gates** any non-local endpoint behind `--allow-cloud`
> (without it a remote endpoint is refused and nothing is sent). The decode map,
> the `_pii/` sidecar, and any project vault contain the real PII and must
> **never** be committed or shared — that includes never sending it to an LLM,
> local or cloud; see [How re-identification works](#how-re-identification-works)
> and [SECURITY.md](SECURITY.md).

---

## How re-identification works

1. `piiscrub strip` writes a stripped tree containing only tokens
   (`<IP_NET1_3>`, `<EMAIL_1>`, …) plus a **local decode map**
   (`_pii/decode.json`, or the project vault's `map.json`). The LLM only ever
   sees the stripped tree — never a real IP, MAC, hostname, or credential.
2. The decode map **never leaves your machine.** Don't paste it, upload it, or
   attach it to a prompt — sending it to any LLM (even a local one, if the
   session or logs leave the box) re-uploads exactly the PII you stripped it
   to avoid.
3. Send the stripped tree — or the LLM-prep `.jsonl`/`.csv` records from
   `--profile llm` — to the LLM for analysis. If you want its report to keep
   tokens intact rather than paraphrasing them, tell the LLM the **token
   convention** — e.g. "tokens look like `<IP_NET1_3>` or `<MCAST_1>`; keep
   them verbatim in your answer" — **never the real values behind them.**
4. Run the LLM's response back through `piiscrub reverse` with the same decode
   map (`--map ./logs/_pii/decode.json`, or the vault's `map.json`) to put the
   real values back — entirely on your machine.

---

## Features

- **One shared alias map** — the same real value always maps to the same opaque
  alias (`<IP_7>`, `<EMAIL_3>`) across every file in a run, so analysts (or an
  LLM) keep correlation without seeing real values; the tool keeps a local map
  you can use to put the real values back.
- **16+ built-in detectors** — IPv4/IPv6, MAC, email, URL, FQDN/hostname, UUID, JWT,
  AWS/Google API keys, Bearer tokens, PEM private-key blocks, Luhn-checked credit
  cards, Windows user paths, Windows SIDs (phone opt-in). Single-pass,
  priority-ordered, overlap-safe — a URL never becomes a tangle of nested aliases.
- **Well-known / multicast addresses kept verbatim** — mDNS/LLMNR/PTP multicast
  (e.g. `224.0.1.129`, `224.0.0.251`) and broadcast addresses are **not**
  tokenised by default, so packet dumps stay structurally readable; org-chosen
  multicast groups are still aliased. Config `keep_wellknown = false` restores
  full tokenisation of these too.
- **`--alias-style structured`** — new plain aliases become subnet/role-aware
  (`<IP_NET1_7>` grouped by /24, `<MCAST_1>` for multicast, `<MACMC_1>` for
  multicast MACs) instead of opaque `<IP_7>`, so an LLM can see which addresses
  share a subnet and which are multicast vs unicast without ever seeing a real
  value. Default stays `opaque` (today's behaviour).
- **`--out-format csv|jsonl`** — reshapes scrubbed text output into per-line
  (`{src, n, ts, text}`) or, for pcap derivatives, per-packet (`{src, packet,
  ts, text}`) records — built for feeding straight to an LLM. Default stays
  `text` (today's mirrored files).
- **`--profile llm`** — one flag bundling the LLM-prep defaults
  (`--alias-style structured` + `--out-format jsonl`); well-known addresses are
  already kept verbatim regardless of profile.
- **PTP v1/v2 decode** — the pcap dissector understands PTP (ports 319/320 and
  ethertype `0x88F7`): message type, domain, sequence ID, priorities, and
  grandmaster/clock identities. A MAC-derived clock identity is aliased to the
  *same* `<MAC_n>` as the device's Ethernet MAC, so a PTP grandmaster and its
  NIC correlate as one device; timestamps are preserved verbatim.
- **Field-aware `.csv`/`.json`/`.jsonl` scrubbing** — these are parsed and every
  string value scrubbed individually; keys/columns and document structure stay
  intact, so the output is still a valid CSV / JSON / JSON Lines file.
- **Timestamps are never scrubbed** — they're the correlation key that lets you
  line up events across packet captures, device logs, and exports from
  different sources.
- **Custom rules + profiles** — `piiscrub.toml` (custom regex/literal patterns,
  allow/deny lists, detector toggles, include/exclude globs) and named profiles
  (`generic`, `network-gear`, `syslog`, `windows-logs`, `pcap-text`, `llm`).
- **Cross-run project vault** — one alias map shared across runs, vendors, dates and
  log types, so the same value correlates across an entire investigation.
- **Entity grouping** — link a thing's identifiers (IP + hostname + MAC) into one
  entity-scoped alias (`<DEV0001.IP_1>`); late-arriving identifiers **supersede**
  earlier plain aliases without breaking old outputs.
- **`reconcile`** — converge already-delivered stripped trees onto the current
  canonical aliases, custody-safe (writes a new copy + manifest; original untouched).
- **Chain-of-custody manifest** — SHA-256 of every original and stripped file, a
  tamper-evident run digest, and an append-only project audit log.
- **Fail-closed verify** — every `strip` re-scans its own output for residual PII
  (exit `10`); a standalone `verify` does the same on demand.
- **Optional LLM second pass** — off by default; flags residual PII the regex missed,
  reading only the **already-stripped** text. Local model by default, cloud endpoints
  hard-gated, API key by env-var only. See below.
- **Format extraction (ON by default)** — `.pcap`/`.pcapng`/`.cap`, `.zip`/`.tar[.gz|.bz2|.xz]`/`.tgz`/`.gz`/`.bz2`/`.xz`,
  `.docx`/`.xlsx`/`.pptx`, and `.db`/`.sqlite`/`.sqlite3` are dissected or repacked
  into scrubbed derivatives instead of copied through raw; `--no-extract` restores
  plain copy-through, `--extract-disable NAME` opts out one format at a time.
- **Robust file handling** — encoding/BOM detection, adaptive streaming for
  multi-GB files (output byte-identical to whole-file), progress bar; binary
  formats with no extractor are still copied through and flagged.
- **CLI *and* GUI** — a stdlib-only CLI plus an optional PySide6 folder-picker GUI;
  both ship as portable Windows `.exe`s built in CI.

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
| `verify DST` | Re-scans a stripped tree for residual PII shapes and stray sidecars, recursing into repacked archives when extraction is on. **Fail-closed** — exits `10` on any finding. |
| `reverse IN OUT --map M` | Rehydrates aliases in `IN` back to originals using a decode map, writing `OUT`. |
| `reconcile IN OUT --project P` | Rewrites an already-stripped tree to current canonical aliases (e.g. `<IP_1>` → `<DEV0001.IP_1>`) and writes a **new** output tree. Custody-safe: the input is never modified. |
| `--selftest` | Compiles every detector and runs a tiny tokenise → reverse → re-scan round-trip; exits `0` on success. CI uses this to prove a frozen `.exe` actually runs. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (and, for `verify` / the auto-verify in `strip`, the tree is clean). |
| `10` | `verify` found residual PII or a stray decode/report sidecar (also returned by `strip` if its auto-verify fails). |
| `11` | `strip --llm --llm-strict` — the optional LLM second pass hit an error and strict (fail-closed) mode was on. |
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
alias_style = "opaque"               # "opaque" (default) or "structured" (LLM-prep)
out_format  = "text"                 # "text" (default), "csv", or "jsonl" (LLM-prep)
keep_wellknown = true                # false also tokenises well-known/multicast addresses

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
--no-extract        --extract-disable NAME   (repeatable; format extraction toggles)
--alias-style STYLE --out-format FORMAT      (opaque|structured; text|csv|jsonl — LLM-prep)
```

---

## Profiles

Named preset bundles for common log types, selected with `--profile`:

```
generic | network-gear | syslog | windows-logs | pcap-text | llm
```

* `generic` — everything on, no extra filtering.
* `network-gear` — disables `credit_card`, `windows_user_path`, `windows_sid`
  (noise on network device logs).
* `syslog` — includes `*.log`, `*.txt`.
* `windows-logs` — includes `*.log`, `*.txt`, `*.csv`.
* `pcap-text` — includes `*.txt`, `*.csv` (packet captures exported to text).
* `llm` — the LLM-prep bundle: `--alias-style structured` + `--out-format
  jsonl`. Well-known addresses are kept verbatim regardless of profile (that's
  the default, not something this profile turns on).

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
correctly. To converge those already-delivered outputs onto the new
entity-scoped aliases, run [`reconcile`](#commands) (it writes a fresh,
custody-safe copy and never touches the original).

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
* **Format extraction (ON by default).** Supported binary formats are
  **dissected/repacked into scrubbed output** rather than copied through raw:
  * `.pcap` / `.pcapng` / `.cap` → a scrubbed text dissection `capture.pcap.txt`
    (per-packet fields + printable payload strings, all tokenised);
  * `.docx` / `.pptx` → `report.docx.txt`, `.xlsx` → `book.xlsx.csv` (visible
    text / cells / slide notes / author core-props);
  * `.db` / `.sqlite` / `.sqlite3` → `data.db.txt` (every user table dumped
    CSV-ish, read-only open, BLOBs shown as `<blob N bytes>`, never hex);
  * `.zip` / `.tar[.gz|.bz2|.xz]` / `.tgz` / single-file `.gz` `.bz2` `.xz` →
    **repacked in the same format** with every member scrubbed by this same
    decision tree (text tokenised; supported binary member dissected; unknown
    binary member copied in + flagged).
  * `.csv` / `.json` / `.jsonl` → **field-aware**: parsed, every string value
    scrubbed individually, re-serialised in the **same format and name**
    (keys/columns untouched, output stays valid CSV/JSON/JSON Lines) — this is
    the `structured` extractor, on by default alongside the binary ones above.

  The **original binary is not copied into the output** when a derivative is
  produced (it would carry the very PII we scrubbed); the report's `extracted`
  section records the `src → out` mapping. Anything that cannot be fully and
  safely read (corrupt/encrypted/oversized/too-deeply-nested) **fails open**:
  the original is copied through unchanged and flagged "may contain PII", exactly
  like the pre-extraction behaviour.
* **Turning extraction off / partially off.**
  * `--no-extract` restores the old behaviour: every binary is copied through
    unchanged and flagged (on `verify` it also skips archive recursion — a
    documented weaker guarantee).
  * `--extract-disable NAME` (repeatable) disables one extractor by name
    (`pcap` | `archive` | `office` | `sqlite` | `structured`); its files —
    **including members inside archives** — are copied through unchanged +
    flagged instead of dissected (`structured` files fall back to plain
    regex-on-text scrubbing, not copy-through — they're text, not binary). An
    unknown name is rejected fast rather than silently ignored.
  * The `[extract]` TOML table sets the same options plus the guard rails
    (`disable`, `max_out_bytes`, `max_depth`, `max_members`); see
    [`docs/USAGE.md`](docs/USAGE.md).
* **Still export-to-text first** for formats with **no** built-in extractor —
  `.evtx` / `.etl` (`wevtutil qe … /f:text`) and `.pdf`: these are copied
  through + flagged with the export hint, then re-run on the exported text.
* **Reversing a repacked archive.** A derivative `.txt`/`.csv` reverses directly
  with `piiscrub reverse` (it is text + aliases). For a repacked `.zip`/`.tar`,
  unzip it and run `reverse` on each extracted text member with the same decode
  map / vault.
* **Binary / undecodable files** with no extractor (a NUL byte in the first
  4 KB, or a binary extension such as `.png` `.exe` `.pdf`, or a
  `--no-extract`/disabled format) are **copied through unchanged and flagged** in
  the report as "may contain PII" — never silently half-stripped.
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

`.evtx` binary-XML parsing (and `.pdf` / `.msg`) remain out of scope — see
[`docs/plans/2026-07-05-format-extractors-design.md`](docs/plans/2026-07-05-format-extractors-design.md).

---

## Optional LLM second pass (`--llm`)

A second, **opt-in** pass can flag residual PII the regex detectors missed. It runs
only when you pass `--llm` (a stray config can never start it), and it is built so
nothing leaks:

* **Already-stripped text only** — the model sees the regex-stripped output, never
  the raw input.
* **Local by default, cloud hard-gated** — defaults to a local model (e.g. Ollama at
  `http://127.0.0.1:11434`). A non-loopback endpoint is **refused** unless you pass
  `--allow-cloud`; without it nothing leaves the machine.
* **Flag-only** — the model only returns candidate substrings; the tool validates
  each against the actual text (rejecting ones that aren't really present, or that
  are already aliases) and tokenises the survivors into new `<LLM_n>` aliases with
  the same alias-safe engine. The model's raw output is never trusted as the result.
* **Key from env-var only** — read from the variable named by `--llm-key-env`
  (default `PIISCRUB_LLM_KEY`), never a flag value; `--forget-key` scrubs it from the
  process environment after the run. Local providers need no key.
* **Fail-open, or fail-closed on demand** — on an LLM error the regex result is kept
  and a warning printed; `--llm-strict` instead exits `11`.
* **Stdlib HTTP, TLS, no redirects, temperature 0** — no third-party dependencies.

```bash
# Local model (default provider/endpoint), no key needed:
piiscrub strip ./logs ./clean --llm

# A remote endpoint must be explicitly allowed; the key comes from an env var:
export MY_LLM_KEY=...                       # never passed as a flag
piiscrub strip ./logs ./clean --llm \
    --llm-provider openai --llm-endpoint https://api.example.com/v1 \
    --llm-model some-model --allow-cloud --llm-key-env MY_LLM_KEY --forget-key
```

Streamed huge files (over `--stream-threshold`) skip the LLM pass and stay
regex-only; this is noted in the report. Flags: `--llm-provider {ollama,openai,anthropic}`,
`--llm-endpoint URL`, `--llm-model NAME`, `--llm-key-env VAR`, `--allow-cloud`,
`--forget-key`, `--llm-strict`.

---

## Graphical interface (piiscrub-gui)

A `console=False` Windows exe wraps scan and strip with folder pickers, a
profile dropdown, live progress, and an open-report button. Install the extra
deps locally with:

```bash
pip install -e .[gui]
# or
pip install -r requirements-gui.txt
```

Then launch with:

```bash
piiscrub-gui
```

The GUI exe is built separately by CI (`build-windows-gui-exe.yml`) and attached
to the same release as the CLI exe on tag pushes.

---

## Build (Windows `.exe`)

No runtime dependencies — stdlib only (needs Python 3.11+ for `tomllib`). The
Windows `.exe` is **built in CI** on `windows-latest` via GitHub Actions
(PyInstaller, one-file, `console=True`, `upx=False`, UTF-8 mode, with a build
self-test gate):

* Push any branch → builds and uploads the `.exe` artifact.
* Push a tag `v*` → builds and publishes a Release with the `.exe` attached.

The GUI exe (`piiscrub-gui.exe`, `console=False`) is built by a parallel CI
workflow and attached to the same Release. Both exes are available from the
Artifacts section of each workflow run.

Code signing is deferred. On first run, a Windows SmartScreen warning clears via
right-click → **Properties** → **Unblock** → OK.

---

## Documentation

* [`docs/USAGE.md`](docs/USAGE.md) — worked end-to-end examples.
* [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup and tests.
* [`SECURITY.md`](SECURITY.md) — responsible disclosure and the local-only data rules.
* [`docs/plans/2026-06-18-pii-scrubber-design.md`](docs/plans/2026-06-18-pii-scrubber-design.md) — design rationale and roadmap.
* [`docs/plans/2026-07-05-llm-prep-mode-design.md`](docs/plans/2026-07-05-llm-prep-mode-design.md) — LLM-prep mode: alias styles, out-formats, PTP decode.
