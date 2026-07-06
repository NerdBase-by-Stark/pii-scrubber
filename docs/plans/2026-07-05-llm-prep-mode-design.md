# PII Scrubber — LLM-prep mode + PTP decode (v4 design)

**Date:** 2026-07-05
**Status:** Approved, building
**Goal:** The north-star use case is producing **LLM-ready, leak-proof,
re-identifiable views** of messy multi-source AV-network data (PTP/Dante/
multicast captures + device logs across 100+ devices). Opaque tokens blind an
LLM exactly where sight is needed: multicast vs unicast, same-subnet grouping,
IP-vs-MAC, PTP roles. v4 adds structure-preserving output without weakening
the leak guarantee.

## Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Well-known addresses | **Kept verbatim by default** (all styles). They are identical on every network and identify nothing. Implemented in detector `accept` filters so `verify` inherits the exemption automatically. Config `keep_wellknown = false` restores old behaviour. |
| 2 | Alias style | `--alias-style opaque\|structured` (default `opaque` = today). Structured affects **newly minted plain aliases only**: entity aliases (`<DEV0001.IP_1>`) and aliases already in a vault keep their existing form (consistency beats style). |
| 3 | Structured grammar | IPv4 unicast `<IP_NET<n>_<i>>` grouped by /24; IPv6 unicast `<IPV6_NET<n>_<i>>` grouped by /64; non-well-known multicast `<MCAST_<i>>` / `<MCAST6_<i>>`; link-local v4 (169.254/16) `<IP_LL_<i>>`; multicast MAC `<MACMC_<i>>`; everything else keeps its opaque prefix. Subnet→NET label map persists inside the AliasMap (vault-compatible; unknown keys are ignored by older readers, schema string unchanged). |
| 4 | Out format | `--out-format text\|csv\|jsonl` (default `text` = mirror). csv/jsonl re-shape **scrubbed text outputs** (plain text files and derivatives) into per-line / per-packet records. Repacked archives keep text members (documented limitation — point LLM-prep runs at extracted trees). |
| 5 | Record shape | jsonl: `{"src": rel, "n": lineno, "ts": str\|null, "text": line}`; for pcap derivatives one record per **packet**: `{"src": rel, "packet": N, "ts": str, "text": full block}`. csv: same fields, columns `src,n,ts,text` (packet number goes in `n`). `ts` is extracted best-effort (leading ISO-8601 / syslog date / `ts=` field), else null — never synthesised. |
| 6 | llm profile | `"llm"` profile = `{alias_style: "structured", out_format: "jsonl"}`. Well-knowns already kept by default. |
| 7 | Field-aware input | `.csv` and `.json`/`.jsonl` sources get parse→scrub-values→re-serialise (csv module with sniffed dialect; json re-dump compact — formatting change documented). **XML stays regex-on-text** (re-serialising would entity-escape `<IP_1>` aliases and break `reverse`; same reason v3 rejected OOXML re-serialisation). Field-aware is part of extraction (`[extract] disable = ["structured"]` / `--extract-disable structured` opts out → old regex-on-text path). |
| 8 | PTP decode | pcap dissector decodes PTPv2 (UDP 319/320 **and** ethertype 0x88F7) and PTPv1 (UDP 319/320, Dante). Emits messageType, domain, seqId, priorities, stepsRemoved, timeSource, and identities (below). Malformed PTP → fall back to printable-strings for that payload, never an error. |
| 9 | clockIdentity leak (AUD-3) | PTPv2 clockIdentity/grandmasterIdentity are EUI-64, usually MAC-derived (`aabbcc:FFFE:ddeeff`). MAC-derived → emit the **reconstructed 6-byte MAC in standard colon-hex** (`clockid mac=aa:bb:cc:dd:ee:ff eui64`), so the existing MAC detector aliases it to the *same* `<MAC_n>` as the device's L2 MAC — correlation preserved, leak closed. Non-MAC-derived → emit canonical 8-group colon-hex, tokenised by a new built-in `ptp_clockid` detector (`<CLOCKID_n>`, on by default). PTPv1 sourceUuid *is* a MAC → emit colon-hex, MAC detector handles it. |
| 10 | Timestamps | Sacred — never scrubbed (cross-source correlation key). Pinned by explicit tests (ISO-8601, syslog, epoch secs/millis, pcap `ts=` headers, PTP originTimestamp). Known edge to watch: a Luhn-valid 16-digit epoch-micros integer could trip the credit-card detector — test documents actual behaviour; fix only if it bites. |
| 11 | Version | 0.2.0 (pyproject.toml + `src/piiscrub/__init__.py` — the only two version sites). |

## Well-known address list (detectors.py)

Kept verbatim (exact or prefix/range check inside `accept`):

* IPv4: `0.0.0.0`, `255.255.255.255`, `127.0.0.0/8`, `224.0.0.0/24`
  (local-network control incl. mDNS .251, LLMNR .252), `224.0.1.129–132` (PTP).
* IPv6: `::`, `::1`, `ff02::1`, `ff02::2`, `ff02::fb` (mDNS), `ff02::1:2`
  (DHCPv6), `ff0X::181` (PTP, any scope nibble), `ff02::6b`.
* MAC: `ff:ff:ff:ff:ff:ff`, and multicast group prefixes `01:00:5e`, `33:33`,
  `01:1b:19` (PTP), `01:80:c2` (STP/LLDP/PTP-peer).

Other multicast (e.g. admin-scoped 239/8 Dante audio groups) is **still
aliased** — org-chosen group numbering can be identifying — but structured
style shows it as `<MCAST_n>` so the LLM still sees "multicast".

Escape hatches: operator `denylist`/`custom` (higher priority) force-tokenise
anything; `allowlist` widens exemptions; `keep_wellknown = false` in
`piiscrub.toml` disables the built-in list.

## Alias-style plumbing

* `engine.tokenize` / `tokenize_segment` gain optional `style` (callable
  `(detector, value) -> prefix`; None = `det.prefix`). Only the **prefix**
  varies — composed keys stay category-based, so the same value never gets two
  aliases across styles/runs within one vault.
* The subnet→label registry lives in `AliasMap` (`_nets: dict[str, str]`,
  serialised as `nets`), assigned NET1, NET2… in first-seen order.
* `walker.process_tree` and the `_scrub` closure pass `style` through; cli
  builds it from `--alias-style`/config. `reconcile`, `reverse`, `llm.py`
  untouched (aliases are just strings).

## Out-format plumbing

* Applied in the walker at output-write time for scrubbed **text** results
  (plain files, streaming path, and derivative outputs). Suffix: `x.log` →
  `x.log.jsonl` / `x.log.csv` (derivatives: `cap.pcap.txt` → `cap.pcap.jsonl`).
* `FileStat.out_rel` already records src→out mapping; report/manifest need no
  schema change beyond the existing extracted section.
* verify/reverse: jsonl and csv are text; aliases round-trip as-is. JSON string
  escaping cannot alter alias glyphs (`<`, `>`, `_`, alnum are never escaped).
* scan (write=False) reports as today; out-format only affects strip.

## PTP dissection detail (pcap.py)

* Hook points: `_dissect_udp` (ports 319/320 → `_dissect_ptp`) and
  `_dissect_l3`/ethertype table (0x88F7 → `_dissect_ptp`).
* PTPv2 header (34 B): byte0 low nibble = messageType, byte1 low nibble =
  version(2), messageLength, domainNumber (byte 4), flags, correctionField,
  sourcePortIdentity @20 (8 B clockIdentity + 2 B port), sequenceId @30.
  Announce body @34: originTimestamp(10), utcOffset(2), gmPriority1(1),
  gmClockQuality(4), gmPriority2(1), grandmasterIdentity(8), stepsRemoved(2),
  timeSource(1). Names for types 0,1,2,3,8,9,10,11,12,13.
* EUI-64→MAC: middle bytes `ff:fe` (or `ff:ff`) → strip, join outer 3+3.
* PTPv1 (version nibble = 1): parse control byte for message kind,
  sourceUuid (6 B MAC) @22, sequenceId; emit `ptpv1` lines.
* Emit example:
  `ptp v2 announce dom=0 seq=1234 clockid mac=aa:bb:cc:dd:ee:ff eui64 prio1=128 prio2=128 gm mac=aa:bb:cc:dd:ee:ff eui64 steps=1 tsrc=0xa0`
* Never emit raw hex payload (existing invariant).

## Field-aware structured input (formats/structured.py)

* New handler `structured` for `.csv`, `.json`, `.jsonl` — same
  `FormatHandler` contract; derivative kind, `out_rel` keeps the same suffix
  (csv→csv, json→json) since output stays valid in-format.
* csv: `csv.Sniffer` for dialect (fallback excel), scrub each cell, write with
  the same dialect. Header row scrubbed like any row (hostnames live there).
* json/jsonl: `json.loads` → walk → scrub every string **value** (dict keys
  untouched), `json.dumps(ensure_ascii=False)` compact per line (jsonl) or
  2-space indent (json). Non-UTF-8 / parse error → `ExtractError` → existing
  fallback = plain regex-on-text scrub (NOT copy-through — these are text
  files; the walker's text path is the fallback for the `structured` handler).
* Out-format interaction: field-aware output is already structured; when
  `--out-format csv|jsonl` is set, structured-input files keep their in-format
  output (no double-wrapping).

## Tests

* wellknown: 224.0.1.129 / 224.0.0.251 / ff02::fb / 01:1b:19:00:00:00 /
  broadcast survive strip verbatim; verify passes on output containing them;
  `keep_wellknown=false` restores tokenisation; denylist overrides.
* alias-style: two hosts same /24 share NET label, different /24 differ;
  multicast 239.69.1.2 → `<MCAST_1>`; vault round-trip keeps `nets`; opaque
  default unchanged (existing 293 tests are the regression net).
* out-format: jsonl/csv record shape incl. ts extraction, pcap per-packet
  records, reverse round-trip through a jsonl derivative, verify clean.
* PTP: build PTPv2 announce/sync (UDP mcast + L2 0x88F7) and PTPv1 packets
  byte-by-byte; assert clockIdentity MAC aliases equal the L2 MAC alias;
  non-EUI-64 identity → `<CLOCKID_n>`; no raw identity bytes survive; PTP
  scalar fields + originTimestamp survive verbatim.
* structured: csv/json/jsonl round-trip validity (csv.reader/json.loads on
  output), PII in cells/values aliased, keys untouched, broken json falls back
  to regex-on-text, `--extract-disable structured` restores old path.
* timestamps: pinned shapes per decision #10.

## Acceptance

1. All existing 293 tests pass unchanged (opaque/text defaults intact).
2. `--profile llm` on a tree with pcaps + logs + csv → jsonl outputs,
   structured aliases, well-knowns visible, verify green, reverse restores.
3. Stdlib-only holds (`grep` imports in formats/ + engine/detectors).
4. README/USAGE repositioned per HANDOVER item 1 + new flags documented.
5. Version 0.2.0 in both sites.
