"""Central project vault — the persistent, cross-run store.

Pointed at with ``--project DIR``. Every run loads the master map, extends it,
and saves it back, so the SAME real value gets the SAME alias across all runs,
vendors, dates and log types (cross-view correlation). The vault is the single
place real PII lives when running in project mode.

Layout::

    <project>/
      map.json        master alias map (cross-run)   [0600]
      entities.csv    operator entity table (optional)
      legend.json     entity -> aliases + pretty name (generated)
      runs/<ts>/      per-run report + manifest
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .engine import AliasMap


class VaultLocked(RuntimeError):
    pass


class Vault:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.map_path = self.root / "map.json"
        self.entities_path = self.root / "entities.csv"
        self.legend_path = self.root / "legend.json"
        self.runs_dir = self.root / "runs"
        self._lock_path = self.root / ".lock"
        self._locked = False

    # ---- lifecycle ------------------------------------------------------
    def open(self) -> "Vault":
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as e:
            raise VaultLocked(
                f"vault is locked ({self._lock_path}); another run may be active. "
                f"Delete the .lock file if you're sure no run is in progress."
            ) from e
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        self._locked = True
        return self

    def close(self) -> None:
        if self._locked:
            try:
                self._lock_path.unlink()
            except FileNotFoundError:
                pass
            self._locked = False

    def __enter__(self) -> "Vault":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- map I/O --------------------------------------------------------
    def load_map(self) -> AliasMap:
        if not self.map_path.is_file():
            return AliasMap()
        with open(self.map_path, encoding="utf-8") as fh:
            return AliasMap.from_dict(json.load(fh))

    def save_map(self, amap: AliasMap) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.map_path.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(amap.to_dict(), fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, self.map_path)
        try:
            os.chmod(self.map_path, 0o600)
        except OSError:
            pass

    def save_legend(self, amap: AliasMap) -> None:
        with open(self.legend_path, "w", encoding="utf-8") as fh:
            json.dump(amap.legend(), fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        try:
            os.chmod(self.legend_path, 0o600)
        except OSError:
            pass

    def run_dir(self, timestamp: str) -> Path:
        safe = timestamp.replace(":", "").replace("+", "Z")
        d = self.runs_dir / safe
        d.mkdir(parents=True, exist_ok=True)
        return d
