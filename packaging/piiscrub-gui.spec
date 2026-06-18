# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for piiscrub-gui (PySide6 windowed GUI). Build on WINDOWS:
#   pyinstaller --noconfirm --clean packaging/piiscrub-gui.spec
# Produces a single portable EXE:  dist\piiscrub-gui.exe
#
# Key differences from piiscrub.spec (CLI):
#   - ENTRY = gui.py (not __main__.py)
#   - name="piiscrub-gui"
#   - console=False  (windowed — no console window on Windows)
#   - hiddenimports=[]  PyInstaller's bundled PySide6 hook covers QtCore/
#     QtGui/QtWidgets; we use only basic widgets so nothing extra is needed.
#   - upx=False, runtime_options utf8, excludes conservative (same as CLI)
#
from pathlib import Path

ROOT  = Path(SPECPATH).parent          # repo root (spec lives in packaging/)
ENTRY = ROOT / "src" / "piiscrub" / "gui.py"

a = Analysis(
    [str(ENTRY)],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # Conservative: only GUI/test modules this app never touches. (Kept
        # narrow on purpose — over-excluding stdlib can break the frozen exe,
        # and we can't test the Windows build from the dev box.)
        "tkinter", "test", "unittest", "pydoc_data",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="piiscrub-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,                     # windowed — no console window
    disable_windowed_traceback=False,
    runtime_options=["utf8_mode=1"],
)
