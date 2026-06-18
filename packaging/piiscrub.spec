# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for piiscrub (CLI). Build on WINDOWS:
#   pyinstaller --noconfirm --clean packaging/piiscrub.spec
# Produces a single portable EXE:  dist\piiscrub.exe
#
# Pattern adapted from the working qsys-plugin-encryptor build:
#   - upx=False              : avoid UPX (AV false positives, DLL issues)
#   - console=True           : this is a CLI tool (qsys app was a GUI → False)
#   - runtime_options utf8   : non-ASCII paths are safe when frozen (Rule 44)
#
from pathlib import Path

ROOT = Path(SPECPATH).parent          # repo root (spec lives in packaging/)
ENTRY = ROOT / "src" / "piiscrub" / "__main__.py"

a = Analysis(
    [str(ENTRY)],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # Conservative: only GUI/test modules this CLI never touches. (Kept
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
    name="piiscrub",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    runtime_options=["utf8_mode=1"],
)
