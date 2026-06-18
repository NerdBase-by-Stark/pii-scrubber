"""PySide6 GUI front-end for piiscrub — wraps gui_runner.run_scan / run_strip.

Absolute imports throughout: the frozen exe runs this as __main__ with no
parent package, so relative imports crash it.

Threading discipline (production-hardened rules):
  - _Worker is a QObject moved to a QThread via moveToThread BEFORE any
    signals are connected, so AutoConnection resolves to QueuedConnection.
  - The progress callback is a lambda that only emits a Qt signal on the
    worker's owning thread — it never touches any widget directly.
  - All UI updates happen in main-thread slots connected to worker signals.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, QThread, QUrl, Qt, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QMessageBox,
)

from piiscrub import __version__
from piiscrub.gui_runner import RunOptions, run_scan, run_strip
from piiscrub.profiles import profile_names
from piiscrub.progress import ProgressEvent  # noqa: F401 — imported for type clarity


# ---------------------------------------------------------------------------
# Worker — lives on a background QThread; never touches widgets
# ---------------------------------------------------------------------------

class _Worker(QObject):
    progress = Signal(int, int, str)   # files_done, files_total, current_file
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, mode: str, opts: RunOptions) -> None:
        super().__init__()
        self._mode = mode
        self._opts = opts

    @Slot()
    def run(self) -> None:
        try:
            cb = lambda ev: self.progress.emit(  # noqa: E731
                ev.files_done, ev.files_total, ev.current_file
            )
            if self._mode == "scan":
                result = run_scan(self._opts, progress=cb)
            else:
                result = run_strip(self._opts, progress=cb)
            self.done.emit(result)
        except Exception as e:  # ValueError + anything the core raises
            self.failed.emit(f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"piiscrub {__version__}")
        self.setMinimumWidth(620)
        self._report_path: Optional[str] = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[_Worker] = None

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(10)
        root.setContentsMargins(12, 12, 12, 12)

        # ---- Inputs --------------------------------------------------------
        inputs_box = QGroupBox("Inputs")
        inputs_layout = QVBoxLayout(inputs_box)
        inputs_layout.setSpacing(6)

        # Source
        self._source_edit = QLineEdit()
        self._source_edit.setPlaceholderText("Source folder (required for scan and strip)")
        source_btn = QPushButton("Browse…")
        source_btn.clicked.connect(self._pick_source)
        source_row = QHBoxLayout()
        source_row.addWidget(QLabel("Source:"))
        source_row.addWidget(self._source_edit)
        source_row.addWidget(source_btn)
        inputs_layout.addLayout(source_row)

        # Target
        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("Target folder (required for strip, ignored by scan)")
        target_btn = QPushButton("Browse…")
        target_btn.clicked.connect(self._pick_target)
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target:"))
        target_row.addWidget(self._target_edit)
        target_row.addWidget(target_btn)
        inputs_layout.addLayout(target_row)

        # Profile
        self._profile_combo = QComboBox()
        self._profile_combo.addItem("(default / generic)", None)
        for name in profile_names():
            self._profile_combo.addItem(name, name)
        profile_row = QHBoxLayout()
        profile_row.addWidget(QLabel("Profile:"))
        profile_row.addWidget(self._profile_combo)
        profile_row.addStretch()
        inputs_layout.addLayout(profile_row)

        # Project vault (optional)
        self._project_edit = QLineEdit()
        self._project_edit.setPlaceholderText("Project vault dir (optional — for cross-run correlation)")
        project_btn = QPushButton("Browse…")
        project_btn.clicked.connect(self._pick_project)
        project_row = QHBoxLayout()
        project_row.addWidget(QLabel("Vault:"))
        project_row.addWidget(self._project_edit)
        project_row.addWidget(project_btn)
        inputs_layout.addLayout(project_row)

        # Entities CSV (optional)
        self._entities_edit = QLineEdit()
        self._entities_edit.setPlaceholderText("Entities CSV (optional — overrides vault default)")
        entities_btn = QPushButton("Browse…")
        entities_btn.clicked.connect(self._pick_entities)
        entities_row = QHBoxLayout()
        entities_row.addWidget(QLabel("Entities:"))
        entities_row.addWidget(self._entities_edit)
        entities_row.addWidget(entities_btn)
        inputs_layout.addLayout(entities_row)

        root.addWidget(inputs_box)

        # ---- Error label (inline validation feedback) ----------------------
        self._error_label = QLabel("")
        # Explicit color required: per-widget stylesheet breaks color
        # inheritance on Windows dark mode (text becomes white-on-white).
        self._error_label.setStyleSheet(
            "color: #c0271a; font-weight: bold; padding: 2px 0;"
        )
        self._error_label.setVisible(False)
        root.addWidget(self._error_label)

        # ---- Action buttons ------------------------------------------------
        btn_row = QHBoxLayout()
        self._scan_btn = QPushButton("Scan (dry-run)")
        self._scan_btn.setToolTip("Detect PII and write a report — no files are changed")
        self._scan_btn.clicked.connect(self._start_scan)
        self._strip_btn = QPushButton("Strip")
        self._strip_btn.setToolTip("Strip PII and write stripped copies to the target folder")
        self._strip_btn.clicked.connect(self._start_strip)
        btn_row.addWidget(self._scan_btn)
        btn_row.addWidget(self._strip_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # ---- Progress ------------------------------------------------------
        progress_box = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_box)
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # busy-indeterminate until first event
        self._progress_bar.setValue(0)
        self._status_label = QLabel("Ready.")
        # Explicit color: same Windows dark-mode guard
        self._status_label.setStyleSheet("color: palette(text); padding: 2px 0;")
        progress_layout.addWidget(self._progress_bar)
        progress_layout.addWidget(self._status_label)
        root.addWidget(progress_box)

        # ---- Results -------------------------------------------------------
        results_box = QGroupBox("Results")
        results_layout = QVBoxLayout(results_box)
        self._results_area = QTextEdit()
        self._results_area.setReadOnly(True)
        self._results_area.setMinimumHeight(180)
        # Explicit color: background + foreground so dark/light modes both work
        self._results_area.setStyleSheet(
            "color: palette(text); background-color: palette(base);"
            "font-family: monospace; font-size: 11px; padding: 4px;"
        )
        results_layout.addWidget(self._results_area)

        open_report_row = QHBoxLayout()
        self._open_report_btn = QPushButton("Open report")
        self._open_report_btn.setEnabled(False)
        self._open_report_btn.clicked.connect(self._open_report)
        open_report_row.addWidget(self._open_report_btn)
        open_report_row.addStretch()
        results_layout.addLayout(open_report_row)
        root.addWidget(results_box)

        # ---- Input widget list (disabled during run) -----------------------
        self._input_widgets = [
            self._source_edit, source_btn,
            self._target_edit, target_btn,
            self._profile_combo,
            self._project_edit, project_btn,
            self._entities_edit, entities_btn,
            self._scan_btn, self._strip_btn,
        ]

    # ---- Folder / file pickers ---------------------------------------------

    def _pick_source(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select source folder")
        if d:
            self._source_edit.setText(d)

    def _pick_target(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select target folder")
        if d:
            self._target_edit.setText(d)

    def _pick_project(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select project vault dir")
        if d:
            self._project_edit.setText(d)

    def _pick_entities(self) -> None:
        f, _ = QFileDialog.getOpenFileName(
            self, "Select entities CSV", "", "CSV files (*.csv);;All files (*)"
        )
        if f:
            self._entities_edit.setText(f)

    # ---- Validation --------------------------------------------------------

    def _show_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.setVisible(True)

    def _clear_error(self) -> None:
        self._error_label.setVisible(False)
        self._error_label.setText("")

    def _build_opts(self, mode: str) -> Optional[RunOptions]:
        source = self._source_edit.text().strip()
        target = self._target_edit.text().strip()
        project = self._project_edit.text().strip() or None
        entities = self._entities_edit.text().strip() or None
        profile = self._profile_combo.currentData()

        if not source:
            self._show_error("Source folder is required.")
            return None
        if not Path(source).is_dir():
            self._show_error(f"Source folder does not exist: {source}")
            return None
        if mode == "strip":
            if not target:
                self._show_error("Target folder is required for Strip.")
                return None

        self._clear_error()
        return RunOptions(
            source=source,
            target=target or None,
            profile=profile,
            project=project,
            entities=entities,
        )

    # ---- Run lifecycle -----------------------------------------------------

    def _set_inputs_enabled(self, enabled: bool) -> None:
        for w in self._input_widgets:
            w.setEnabled(enabled)

    def _start_run(self, mode: str) -> None:
        opts = self._build_opts(mode)
        if opts is None:
            return

        self._results_area.clear()
        self._results_area.setStyleSheet(
            "color: palette(text); background-color: palette(base);"
            "font-family: monospace; font-size: 11px; padding: 4px;"
        )
        self._open_report_btn.setEnabled(False)
        self._report_path = None
        self._set_inputs_enabled(False)
        self._progress_bar.setRange(0, 0)  # busy-indeterminate
        self._progress_bar.setValue(0)
        self._status_label.setText(f"Starting {mode}…")

        # moveToThread BEFORE connecting signals so AutoConnection resolves to
        # QueuedConnection (worker runs on a different thread than main).
        self._thread = QThread(self)
        self._worker = _Worker(mode, opts)
        self._worker.moveToThread(self._thread)          # move FIRST

        self._thread.started.connect(self._worker.run)   # then connect
        self._worker.progress.connect(self._on_progress)
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.done.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.start()

    def _start_scan(self) -> None:
        self._start_run("scan")

    def _start_strip(self) -> None:
        self._start_run("strip")

    # ---- Worker signal slots (main thread) ---------------------------------

    @Slot(int, int, str)
    def _on_progress(self, files_done: int, files_total: int, current_file: str) -> None:
        if self._progress_bar.maximum() == 0 and files_total > 0:
            # Switch from indeterminate to determinate on first event
            self._progress_bar.setRange(0, files_total)
        if files_total > 0:
            self._progress_bar.setValue(files_done)
        name = current_file
        if len(name) > 60:
            name = "…" + name[-57:]
        self._status_label.setText(f"{files_done}/{files_total}  {name}")

    @Slot(dict)
    def _on_done(self, result: dict) -> None:
        self._set_inputs_enabled(True)
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(1)

        report = result.get("report")
        if report:
            self._report_path = report
            self._open_report_btn.setEnabled(True)

        # Build a tidy human summary (omit bulky verify_detail)
        display = {k: v for k, v in result.items() if k != "verify_detail"}
        summary_text = json.dumps(display, indent=2)

        verify_clean = result.get("verify_clean")
        if verify_clean is False:
            # Residual PII found — show warning in red.
            # Explicit color set to satisfy QSS color firewall rule.
            self._results_area.setStyleSheet(
                "color: #c0271a; background-color: palette(base);"
                "font-family: monospace; font-size: 11px; padding: 4px;"
            )
            self._results_area.setPlainText(
                "WARNING: Residual PII detected in the stripped output "
                "(verify_clean = false). Do not share the output tree.\n\n"
                + summary_text
            )
            self._status_label.setText("Done — RESIDUAL PII FOUND (see results)")
        else:
            self._results_area.setStyleSheet(
                "color: palette(text); background-color: palette(base);"
                "font-family: monospace; font-size: 11px; padding: 4px;"
            )
            self._results_area.setPlainText(summary_text)
            self._status_label.setText("Done.")

    @Slot(str)
    def _on_failed(self, msg: str) -> None:
        self._set_inputs_enabled(True)
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(0)
        # Explicit color: QSS color firewall — must set color when setting any style
        self._results_area.setStyleSheet(
            "color: #c0271a; background-color: palette(base);"
            "font-family: monospace; font-size: 11px; padding: 4px;"
        )
        self._results_area.setPlainText(f"Error: {msg}")
        self._status_label.setText("Failed — see results for details.")

    @Slot()
    def _on_thread_finished(self) -> None:
        self._thread = None
        self._worker = None

    # ---- Open report -------------------------------------------------------

    def _open_report(self) -> None:
        if self._report_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._report_path))

    # ---- Close event -------------------------------------------------------

    def closeEvent(self, event) -> None:  # type: ignore[override]
        # The core has no mid-run cancel hook, so we cannot interrupt a running
        # scan/strip. Give it a short grace period; if it's still running, keep the
        # window open (with a message) rather than freezing the UI or orphaning the
        # worker thread.
        if self._thread is not None and self._thread.isRunning():
            self._thread.quit()
            if not self._thread.wait(3000):
                QMessageBox.information(
                    self, "piiscrub",
                    "A scan or strip is still running. Please wait for it to finish "
                    "before closing.")
                event.ignore()
                return
        event.accept()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("piiscrub")
    app.setApplicationVersion(__version__)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
