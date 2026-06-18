"""Headless GUI smoke test — construct the window AND drive a real scan through
the QThread worker offscreen, asserting the done-signal path fires. Run in CI
with QT_QPA_PLATFORM=offscreen. Exits non-zero on any failure."""
from __future__ import annotations
import sys, tempfile, time
from pathlib import Path
from PySide6.QtWidgets import QApplication


def main() -> int:
    app = QApplication([])
    import piiscrub.gui as g
    assert hasattr(g, "MainWindow"), "MainWindow missing"
    w = g.MainWindow()
    assert w is not None
    # Drive a real scan through the worker thread on a temp tree.
    tmp = Path(tempfile.mkdtemp())
    (tmp / "sample.log").write_text("user a@example.com from 10.0.0.5\n", encoding="utf-8")
    w._source_edit.setText(str(tmp))
    w._start_scan()
    deadline = 200  # ~4s at 20ms
    while deadline > 0 and w._report_path is None:
        app.processEvents()
        time.sleep(0.02)
        deadline -= 1
    assert w._report_path is not None, "scan did not complete via the worker thread"
    print("gui smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
