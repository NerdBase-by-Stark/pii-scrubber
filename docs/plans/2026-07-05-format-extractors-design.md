# PII Scrubber — Format Extractors (v3 design)

**Date:** 2026-07-05
**Status:** Approved, building
**Goal:** Close the last big gap in the tool: binary capture/document/archive
formats (`.pcap`, `.zip`, `.docx`, …) are currently copied through **unchanged**
into the shareable output tree and merely flagged "may contain PII". After this
build, supported formats are actually scrubbed.

## Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Runtime deps | **Stdlib only**, unchanged (Python 3.11+). No scapy/dpkt/openpyxl. |
| 2 | pcap output | **Scrubbed text derivative** (`capture.pcap` → `capture.pcap.txt`), not a rewritten pcap. Rewriting packets natively (checksums, length-shifting aliases, seq numbers) is fragile and can silently leak; a dissected text export is what analysts grep anyway and goes through the one proven tokenizer. |
| 3 | Office output | Text derivative too (`report.docx` → `report.docx.txt`, `book.xlsx` → `book.xlsx.csv`). Re-serialising OOXML XML risks corrupt documents and aliases contain `<`/`>` which would need XML-escaping inside documents; a text export is safe and shareable. |
| 4 | Archives | **Recurse + repack same format.** `logs.zip` in SRC → `logs.zip` in DST containing scrubbed members. Members are processed with the same per-file logic as top-level files (text → tokenize; supported binary → derivative; unknown binary → copied in + flagged). |
| 5 | sqlite | Text derivative: dump every table to CSV-ish text (`data.db` → `data.db.txt`), read-only open. |
| 6 | Default | Extraction is **ON by default** (`--no-extract` restores old copy-through behavior; per-format disable via config `[extract] disable = ["pcap", ...]`). Rationale: the old default *copies real PII into the shareable tree*; the new default is strictly safer. |
| 7 | Originals | When a derivative is produced, the original binary is **NOT copied into DST** (it would carry the very PII we scrubbed). The report records the mapping `src rel → out rel`. |
| 8 | evtx / etl / pdf / msg | **Still out of scope** — keep the existing export-to-text hints. evtx binary-XML parsing is a large pure-python lift; wevtutil hint stands. |
| 9 | verify | Must **recurse into archives** in DST (fail-closed guarantee would otherwise be hollow) and scan derivatives like any text. |
| 10 | reverse | Works on text derivatives as-is (they're text + aliases). For repacked archives, operator unzips and reverses members; documented. |

## Architecture

New package `src/piiscrub/formats/`:

```
formats/
  __init__.py    — registry: get_handler(suffix) -> FormatHandler | None,
                   handler_suffixes(), imports the modules below
  base.py        — FormatHandler dataclass/protocol + ExtractOutcome + shared
                   guards (size caps, depth caps) + ExtractError
  pcap.py        — pcap / pcapng / cap dissector -> text
  archives.py    — zip / tar / tar.gz / tgz / gz / bz2 / xz recurse + repack
  office.py      — docx / xlsx / pptx text extraction (zipfile + xml.etree)
  sqlitedb.py    — .db / .sqlite / .sqlite3 dump (stdlib sqlite3, mode=ro)
```

### Handler contract (`base.py`)

```python
@dataclass
class ExtractOutcome:
    kind: str              # "derivative" | "repack"
    out_rel: str           # output path relative to DST (e.g. "x.pcap.txt")
    replacements: int
    members_processed: int = 0    # archives
    members_copied: int = 0       # archives: binary members copied + flagged
    warnings: list[str] = field(default_factory=list)

class FormatHandler(Protocol):
    name: str                     # "pcap", "archive", "office", "sqlite"
    suffixes: tuple[str, ...]     # lowercase, with dot
    def process(self, path: Path, rel: str, out_path: Path | None,
                scrub: ScrubFn, *, write: bool,
                limits: ExtractLimits) -> ExtractOutcome: ...
```

* `scrub(rel: str, text: str) -> tuple[str, int]` is a closure the walker
  provides wrapping `tokenize(...)` with the run's detectors/amap/allowlist —
  **format modules never import the engine** and never see the decode map.
* `ExtractError` (with a human reason) → walker falls back to the *old*
  behavior for that file: copy through unchanged + flag "may contain PII"
  + the reason. Corrupt pcap, encrypted zip, password-protected office file,
  locked/corrupt sqlite all land here. **Fail-open to copy-through+flag,
  never to a silent partial derivative** — a half-written derivative must be
  deleted before falling back.
* `ExtractLimits`: `max_out_bytes` (default 512 MB total expanded text per
  source file), `max_depth` (nested archives, default 3), `max_members`
  (default 50 000). Exceeding a limit raises `ExtractError` (→ copy+flag).
  Configurable via `[extract]` in piiscrub.toml.

### Walker integration (`walker.py`)

In `process_tree`, **before** the `BINARY_EXTS` copy-through branch:

```
if extract_enabled and (h := get_handler(path.suffix)) and h.name not in extract_disabled:
    try:    outcome = h.process(...)
    except ExtractError as e:  -> _copy_through(rel, "binary", old warning + reason)
    else:   record FileStat(rel, "extracted", replacements=..., out_rel=...)
```

* `FileStat` gains `out_rel: str = ""` (empty ⇒ same as `rel`, existing behavior).
* `RunStats` gains `files_extracted: int`.
* scan (write=False) still runs extraction *in memory* so the report/aliases
  reflect what strip would do — but writes nothing.
* Oversize (`max_bytes`) check still applies first, on the source size.
* Streaming: extracted text is scrubbed whole (a pcap's text expansion is
  bounded by `max_out_bytes`); no chunk-streaming inside handlers for v3.
  Members/dissections larger than `max_out_bytes` → `ExtractError`.
  **Known trade-off:** with extraction on by default, a directory of several
  large captures/archives near the 512 MB `max_out_bytes` cap can create real
  memory pressure (whole expanded text held in memory per file, sequentially).
  Operators can lower `max_out_bytes` in `[extract]`; chunk-streaming inside
  handlers is the documented fast-follow if this bites in practice.

### CLI / config

* `--no-extract` on scan/strip/verify (verify: skip archive recursion).
* `[extract]` TOML table: `disable = ["pcap", "archive", "office", "sqlite"]`,
  `max_out_bytes`, `max_depth`, `max_members`. CLI `--extract-disable NAME`
  repeatable, merges on top like detector toggles.
* Profiles: `pcap-text` profile keeps working (text exports); no profile change
  required, but `generic` now handles pcaps natively.

### Report / manifest

* Report: new "extracted" section — src file, out file, kind, replacements,
  member counts. Skipped/flagged unchanged. Still aliases+counts only, no PII.
* Manifest: per-file records already hash original + stripped output; for
  extracted files hash the **original** and the **derivative/repacked** output,
  and record both paths. Verify of manifest digest unchanged.

## Per-format specs

### pcap (`pcap.py`)

Stdlib `struct` parsing. Support:

* **classic pcap**: magics `a1b2c3d4` / `d4c3b2a1` / `a1b23c4d` / `4d3cb2a1`
  (µs + ns variants, both endians). Snaplen respected; `incl_len` bounds-checked.
* **pcapng**: SHB (0x0A0D0D0A, endianness from byte-order magic), IDB, EPB,
  SPB, and skip unknown blocks by length. Multiple sections OK. Per-interface
  `if_tsresol` respected for timestamps (default 1 µs).
* **Link types**: Ethernet (1) incl. 802.1Q VLAN (recursively strip tags),
  Linux SLL (113), Linux SLL2 (276), Raw IPv4/IPv6 (101, 228, 229),
  Null/Loopback (0). Unknown link type → a note line
  (`# link unknown type=N len=L`) plus printable-string extraction of the frame
  — **never** a hex dump of it (see the no-raw-hex invariant below), and not an
  error.
* **Dissection per packet** (text lines, one block per packet):
  * header: `# packet N ts=<ISO8601> caplen=X origlen=Y`
  * L2: `eth <src-mac> -> <dst-mac> type=0xXXXX [vlan N]`
  * ARP: sender/target MAC + IP.
  * IPv4/IPv6: src/dst, proto, ttl/hoplimit (fragments: dissect first fragment,
    note offset for the rest).
  * TCP/UDP: ports, flags (TCP), lengths. ICMP/ICMPv6: type/code.
  * **DNS** (UDP/TCP port 53): decode query/answer names + A/AAAA rdata
    (compression-pointer safe: loop-guard, max 128 jumps).
  * **Payload**: printable-ASCII runs (len ≥ 4) from the remaining bytes,
    emitted as `payload "…"` lines — this is what lets emails/URLs/hostnames
    inside HTTP/SMTP/etc. get tokenized. Cap 4 KB of extracted strings per
    packet (note truncation).
* Truncated final packet / bad block length → stop dissecting, emit a warning
  line in the text, still return what was dissected (a truncated capture is
  normal); *structurally* invalid file (bad magic) → `ExtractError`.
* The dissector NEVER emits raw hex of payloads (hex can encode PII invisibly
  to detectors) — only printable-string runs and decoded fields.

### archives (`archives.py`)

* zip via `zipfile`, tar(+gz/bz2/xz) via `tarfile`, single-file `.gz`/`.bz2`/`.xz`
  via `gzip`/`bz2`/`lzma` (decompress → treat as one member).
* Each member gets the same decision tree as a top-level file, via a shared
  helper: text (decode_bytes) → scrub; supported binary suffix → nested handler
  (depth-capped); unknown binary → copied into the repacked archive **as-is**
  + flagged warning (same contract as today's top-level behavior).
* **Guards**: reject member names that are absolute or contain `..` (flag +
  skip member, do not write); total decompressed bytes across the archive
  capped by `max_out_bytes`; member count by `max_members`; nesting by
  `max_depth`. Encrypted zip members → `ExtractError` (whole archive
  copy+flag; do not partially repack an archive we can't fully read).
* Repack: zip members written with same name + deflate; tar repacked with same
  compression as source. Timestamps preserved from the source member. Do not
  preserve zip external permissions bits beyond defaults (metadata is not PII
  scope). Deterministic member order = source order.
* `.gz`/`.bz2`/`.xz` single files: if inner content is text → scrubbed and
  recompressed same format; binary inner → `ExtractError` unless a nested
  handler claims it (e.g. `x.pcap.gz` → dissect → `x.pcap.gz.txt` derivative).

### office (`office.py`)

* All three are zips of XML; use `zipfile` + `xml.etree.ElementTree`
  (`iterparse` on member streams).
* docx: `word/document.xml` (+ headers/footers/footnotes/endnotes/comments
  `word/*.xml` with `<w:t>` runs) — emit paragraph text lines.
* xlsx: `xl/sharedStrings.xml` + each `xl/worksheets/sheet*.xml`; resolve
  shared-string and inline-string cells; emit one CSV line per row per sheet,
  section header `# sheet: <name>` (names from `xl/workbook.xml`). Numeric
  cells emitted as-is. Output suffix `.csv`.
* pptx: `ppt/slides/slide*.xml` `<a:t>` runs; `# slide N` sections. Also
  `notesSlides`.
* Core/app properties (`docProps/core.xml`: creator, lastModifiedBy) are
  emitted too (`# author: …`) — they routinely hold usernames.
* Malformed XML / encrypted (OLE-wrapped) → `ExtractError`.

### sqlite (`sqlitedb.py`)

* `sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)`.
* Enumerate user tables from `sqlite_master`; per table `# table: <name>`,
  header row of column names, then rows CSV-quoted; BLOB columns rendered as
  `<blob N bytes>` (never hex-dumped). Row cap via `max_members`, byte cap via
  `max_out_bytes`.
* Any `sqlite3.Error` → `ExtractError`.

## verify (`audit.py`)

* For each archive-suffix file in DST: open read-only with the same guards and
  scan text members (and nested archives, depth-capped) for residual PII
  shapes; findings reported with `archive.zip!member/path` notation.
* Derivative `.txt`/`.csv` files scan as normal text (already do).
* `--no-extract` on verify skips archive recursion (documented weaker).
* Binary members inside DST archives that were copied+flagged do NOT fail
  verify (they were flagged in the report) — verify's contract stays "no
  *residual PII shapes in text*, no sidecar leaks", now including text inside
  archives.

## Tests (all fixtures generated programmatically in-test, no binary blobs in git)

* pcap: build classic pcap + pcapng byte-by-byte with `struct` (eth/IPv4/UDP
  DNS query, TCP HTTP payload w/ email + URL, IPv6, VLAN, ARP, SLL, truncated
  file, bad magic, both endians, ns resolution). Assert: IPs/MACs/emails/URLs
  from packets appear aliased in derivative; no raw value survives; bad magic
  → copy+flag.
* archives: zip/tar.gz round-trip (text member scrubbed, binary member
  copied+flagged, nested zip depth, `..` member rejected, encrypted zip →
  copy+flag, bomb caps trip `ExtractError`); repacked archive readable by
  stdlib; verify recursion catches a planted leak *inside* a zip in DST.
* office: build docx/xlsx/pptx via `zipfile` with minimal OOXML; emails/IPs in
  cells/paragraphs/notes/core-props get aliased; encrypted/garbage → copy+flag.
* sqlite: create db via `sqlite3`, PII in rows aliased, blob not hex-dumped,
  corrupt file → copy+flag.
* framework: `--no-extract` restores old behavior; scan writes nothing but
  reports extraction counts; decode-map reverse round-trips a derivative;
  manifest hashes derivative; `--selftest` still exits 0.
* Cross-cutting: same IP in a pcap and a plain log in one run → same alias
  (shared amap); project-vault run over a pcap keeps cross-run aliasing.

## Acceptance criteria

1. `piiscrub strip` of a tree containing `.pcap`, `.pcapng`, `.zip`, `.tar.gz`,
   `.docx`, `.xlsx`, `.pptx`, `.db`, text logs → DST contains **zero raw PII**
   from any of them (auto-verify passes, including archive recursion).
2. All existing 135 tests still pass; new tests cover every bullet above.
3. Stdlib-only: `grep -R "^import\|^from" src/piiscrub/formats` shows stdlib
   modules only.
4. README/USAGE updated; the old "export to text first" hints retained only
   for evtx/etl/pdf.

## Build phases

* **Phase done (2026-07-05):** `pcap`/`archive`/`office`/`sqlite` handlers,
  walker/CLI/config wiring (`--no-extract`, `--extract-disable`, `[extract]`),
  verify archive-recursion, and manifest/report `extracted` section all landed
  and are exercised by the test suite. README.md and docs/USAGE.md updated to
  document the new default behaviour, config table, limits, and a worked
  pcap + zip example. `evtx`/`etl`/`pdf`/`msg` remain out of scope per decision
  #8 above. Full suite: `PYTHONPATH=src python -m pytest tests/ -q` →
  **293 passed**.
