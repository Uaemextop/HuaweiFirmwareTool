# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for ONT Broadcast Tool.

Build:
  cd ont_tool
  pyinstaller ONTTool.spec

Output: dist/ONTBroadcastTool.exe
"""

import os
import sys

block_cipher = None

# Find customtkinter data files (themes + assets)
try:
    import customtkinter
    ctk_path = os.path.dirname(customtkinter.__file__)
    ctk_datas = [(ctk_path, 'customtkinter')]
except ImportError:
    ctk_datas = []

a = Analysis(
    ['main.py'],
    pathex=[os.path.abspath('.')],
    binaries=[],
    datas=ctk_datas + [
        ('src', 'src'),
    ],
    hiddenimports=[
        'customtkinter',
        'PIL',
        'PIL._tkinter_finder',
        'psutil',
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ONTBroadcastTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # GUI app — no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/icon.ico',  # Uncomment if you add an icon
)
