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
    # Poll until the worker thread has FULLY shut down (_on_thread_finished sets
    # _thread = None), not merely until _report_path is set — otherwise we could
    # exit the process while the QThread is still tearing down. Generous timeout
    # for loaded CI runners.
    deadline = 500  # ~10s at 20ms
    while deadline > 0 and w._thread is not None:
        app.processEvents()
        time.sleep(0.02)
        deadline -= 1
    assert w._thread is None, "worker thread did not finish shutting down in time"
    assert w._report_path is not None, "scan did not complete via the worker thread"
    print("gui smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
