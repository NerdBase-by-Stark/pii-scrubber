# Contributing to piiscrub

Thanks for your interest in improving piiscrub. This document covers the local
development setup, how to run the tests, and the conventions the project relies
on.

## Ground rules

* **Stdlib-only at runtime.** The runtime code (`src/piiscrub/`) must not import
  any third-party package. This keeps the optional Windows `.exe` small and
  low-AV-risk. Third-party packages are allowed **only** as dev/build tooling
  (`pytest`, `pyinstaller`). If you reach for a dependency, raise it in an issue
  first.
* **Python 3.11+** is required (the config loader uses the stdlib `tomllib`,
  added in 3.11).
* **Never commit real data.** Decode maps, `_pii/` sidecars, and project vaults
  contain real PII. They are git-ignored on purpose — do not force them in. See
  [SECURITY.md](SECURITY.md).

## Development setup

```bash
# Clone, then create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install dev/build tooling (runtime needs nothing)
pip install -r requirements.txt
```

You can run the tool straight from the source tree without installing it:

```bash
PYTHONPATH=src python -m piiscrub scan ./some/logs
```

Or install it as an editable package (this wires up the `piiscrub` console
script):

```bash
pip install -e .
piiscrub --version
```

## Running the tests

The project uses `pytest`. The test configuration in `pyproject.toml` already
puts `src/` on the path, so a bare invocation works:

```bash
python -m pytest
```

For quieter output:

```bash
python -m pytest -q
```

## The self-test

Beyond the unit tests there is a fast, dependency-free self-test that compiles
every detector and runs a tokenise → reverse → re-scan round-trip:

```bash
PYTHONPATH=src python -m piiscrub --selftest
```

It prints `selftest: OK` and exits `0` on success. CI runs this against the
**frozen** Windows `.exe` to prove the packaged binary actually starts and works,
so keep it green.

## Project layout

```
src/piiscrub/
  detectors.py   — Detector dataclass + built-in detector registry
  engine.py      — single-pass span tokenizer + AliasMap (the consistency core)
  config.py      — TOML config + profile/CLI layering
  profiles.py    — named preset bundles per log type
  entities.py    — operator entity table -> entity-scoped aliasing
  projectmap.py  — central cross-run project vault
  manifest.py    — chain-of-custody SHA-256 manifest
  walker.py      — folder walk, encoding detection, binary/stream handling, mirror I/O
  report.py      — HTML + JSON run report (PII-free; aliases & counts only)
  audit.py       — verify (re-scan, fail-closed) + reverse (rehydrate)
  cli.py         — scan / strip / verify / reverse / --selftest
tests/           — pytest suite
packaging/       — PyInstaller spec for the Windows .exe
.github/         — CI workflow that builds the .exe
examples/        — sample piiscrub.toml and entities.csv
docs/            — design notes and usage guide
```

## Pull-request checklist

Before opening a PR:

- [ ] `python -m pytest` passes.
- [ ] `PYTHONPATH=src python -m piiscrub --selftest` prints `selftest: OK`.
- [ ] No new third-party runtime imports in `src/piiscrub/`.
- [ ] New detectors ship with at least one positive and one near-miss negative
      test (e.g. a version string that must **not** be tokenised as an IP).
- [ ] No real PII, decode maps, `_pii/` directories, or vaults are included in
      the diff.
- [ ] Docs (`README.md`, `docs/USAGE.md`) updated if behaviour or flags changed.
