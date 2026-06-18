# Security Policy

## The most important rule: this tool is LOCAL-ONLY

piiscrub is designed to run entirely on your own machine. It makes **no network
calls** and sends nothing anywhere. That design is only safe if the operator
respects one rule:

> ### Decode maps, `_pii/` sidecars, and project vaults contain the real PII. They must NEVER be committed to version control, uploaded, emailed, or shared.

The whole point of the tool is to separate two zones:

* The **stripped mirror** (`DST`) is the *shareable* zone. It contains only
  opaque aliases (`<IP_7>`, `<DEV0001.HOST_1>`) and is safe to hand to analysts
  or attach to a ticket.
* The **decode side** is the *sensitive* zone. It is the only place real values
  live:
  * `SRC/_pii/decode.json` — the alias → original map (standalone mode).
  * `SRC/_pii/report.{html,json}` and `manifest.json` — run artefacts kept next
    to the originals.
  * `<project>/map.json` and `<project>/legend.json` — the cross-run master map
    and the entity friendly-name legend (project/vault mode).

**Anyone who obtains a decode map or vault can fully reverse the stripped output
back to the original PII.** Treat these files with the same care as the raw logs
themselves.

### Operator handling rules

* **Do not commit them.** The repository `.gitignore` already excludes `_pii/`,
  `decode.json`, and `*_decode.json`. Keep your project vault directory outside
  any tracked tree, and never use `git add -f` to override the ignore rules.
* Keep the sensitive zone on the same trust boundary as the original logs. The
  tool locks `_pii/` and the vault to the current user (`0700` / best-effort
  `icacls` on Windows). If you see the "could not lock … protect it manually"
  warning, lock the directory yourself before continuing — do not ignore it.
* Only move the **stripped mirror** (`DST`) across a trust boundary, and only
  after `verify` reports it clean.
* Delete decode maps and vaults when the engagement that needed them is over.

### Verify before you share

`strip` automatically runs a fail-closed `verify` pass over the stripped output,
and you can re-run it any time:

```bash
piiscrub verify ./clean
```

`verify` re-scans the stripped tree for residual PII shapes **and** confirms that
no decode/report sidecar leaked into the shareable zone. It exits `10` on any
finding. Do not share a stripped tree that has not passed verify. Note that
binary and undecodable files are copied through unchanged and flagged in the
report — they are **not** scrubbed and may still contain PII.

## Reporting a vulnerability

If you discover a security issue — for example, a detector that misses an obvious
PII shape, a path that can leak a raw value into the stripped output, or a way to
bypass the verify/containment guards — please report it responsibly:

* **Do not** open a public issue for a vulnerability that could expose PII.
* Report it privately to the maintainers (use the repository's private security
  advisory feature, or the contact listed in the project metadata).
* Please include a minimal, **synthetic** reproduction. Never attach real PII,
  real logs, or a real decode map to a report — construct a fictional example
  instead (e.g. `192.0.2.x` addresses, `@example.com` emails).

We aim to acknowledge reports promptly and will coordinate a fix and disclosure
timeline with you.

## Supported versions

This tool is pre-1.0. Security fixes are made against the latest `main`; please
test against the most recent revision before reporting.
