"""
OBSC Firmware Tool — Main GUI Application

Modern Windows 11 themed GUI for Huawei ONT firmware flashing.
Uses ttkbootstrap (with tkinter/ttk fallback) for a polished look.

The UI is split into mixin classes under ``obsc_tool.gui``, one per tab,
plus shared helpers for theme, adapters, constants, and logging.
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox
import logging

# ttkbootstrap gives us modern themes, meter widgets, icons, and better
# styling.  Fall back to plain ttk if it is not installed.
try:
    import ttkbootstrap as ttkb
    from ttkbootstrap.constants import *  # noqa: F401,F403
    from tkinter import ttk
    HAS_TTKB = True
except ImportError:
    from tkinter import ttk
    HAS_TTKB = False

from obsc_tool import __version__
from obsc_tool.presets import PresetManager
from obsc_tool.terminal import TelnetClient, SerialClient

# Shared constants — re-exported so existing callers still work
from obsc_tool.gui.constants import (  # noqa: F401
    _safe_int, THEMES, IP_MODE_DEFAULTS,
    OBSC_MULTICAST_ADDR, DEVICE_STALE_TIMEOUT,
    TTKB_DARK, TTKB_LIGHT,
)

# Tab / feature mixins
from obsc_tool.gui.upgrade_tab import UpgradeTabMixin
from obsc_tool.gui.presets_tab import PresetsTabMixin
from obsc_tool.gui.verification_tab import VerificationTabMixin
from obsc_tool.gui.crypto_tab import CryptoTabMixin
from obsc_tool.gui.terminal_tab import TerminalTabMixin
from obsc_tool.gui.dump_tab import DumpTabMixin
from obsc_tool.gui.settings_tab import SettingsTabMixin
from obsc_tool.gui.info_tab import InfoTabMixin
from obsc_tool.gui.log_tab import LogTabMixin
from obsc_tool.gui.theme import ThemeMixin
from obsc_tool.gui.adapters import AdaptersMixin

logger = logging.getLogger("obsc_tool")


class OBSCToolApp(
    UpgradeTabMixin,
    PresetsTabMixin,
    VerificationTabMixin,
    CryptoTabMixin,
    TerminalTabMixin,
    DumpTabMixin,
    SettingsTabMixin,
    InfoTabMixin,
    LogTabMixin,
    ThemeMixin,
    AdaptersMixin,
):
    """Main application class."""

    def __init__(self, root):
        self.root = root
        self.root.title(f"OBSC Firmware Tool v{__version__}")
        self.root.geometry("900x720")
        self.root.minsize(800, 600)

        # State
        self.current_theme = 'dark'
        self.firmware = None
        self.firmware_path = ""
        self.adapters = []
        self.worker = None
        self.transport = None
        self.log_entries = []
        self.preset_manager = PresetManager()
        self.telnet_client = TelnetClient()
        self.serial_client = SerialClient()
        self.firmware_dumper = None

        # Setup logging
        self._setup_logging()

        # Build UI
        self._build_ui()

        # Load adapters
        self.root.after(100, self._refresh_adapters)

        # Configure window icon
        self._set_icon()

        # Keyboard shortcuts
        self.root.bind('<F5>', lambda e: self._refresh_adapters())
        self.root.bind('<Control-o>', lambda e: self._browse_firmware())

        # Handle close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_logging(self):
        """Configure logging to capture messages in the log panel."""
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s [%(name)s] %(message)s',
                                      datefmt='%H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    def _set_icon(self):
        """Set window icon if available."""
        try:
            # Try to set a simple icon
            self.root.iconbitmap(default='')
        except tk.TclError:
            pass

    def _build_ui(self):
        """Build the main UI layout."""
        colors = THEMES[self.current_theme]

        # Configure root style
        self.root.configure(bg=colors['bg'])

        # Create style
        self.style = ttk.Style()
        self._apply_theme()

        # Main container with padding
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # ── Header ───────────────────────────────────────────────
        header = ttk.Frame(main)
        header.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(
            header,
            text="OBSC Firmware Tool",
            font=('Segoe UI', 18, 'bold'),
        )
        title_label.pack(side=tk.LEFT)

        # Theme toggle
        self.theme_btn = ttk.Button(
            header, text="🌙 Dark" if self.current_theme == 'dark' else "☀️ Light",
            command=self._toggle_theme, width=10,
        )
        self.theme_btn.pack(side=tk.RIGHT, padx=5)

        version_label = ttk.Label(
            header, text=f"v{__version__}",
            font=('Segoe UI', 9),
        )
        version_label.pack(side=tk.RIGHT, padx=10)

        # ── Notebook (tabs) ──────────────────────────────────────
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Upgrade
        self.tab_upgrade = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_upgrade, text=" 🔄 Upgrade ")
        self._build_upgrade_tab()

        # Tab 2: Presets
        self.tab_presets = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_presets, text=" 📦 Presets ")
        self._build_presets_tab()

        # Tab 3: Verification
        self.tab_verify = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_verify, text=" 🔒 Verification ")
        self._build_verification_tab()

        # Tab 4: Config Crypto
        self.tab_crypto = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_crypto, text=" 🔐 Config Crypto ")
        self._build_crypto_tab()

        # Tab 5: Terminal
        self.tab_terminal = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_terminal, text=" 💻 Terminal ")
        self._build_terminal_tab()

        # Tab 6: Firmware Dump
        self.tab_dump = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_dump, text=" 💾 Firmware Dump ")
        self._build_dump_tab()

        # Tab 7: Settings
        self.tab_settings = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_settings, text=" ⚙️ Settings ")
        self._build_settings_tab()

        # Tab 8: Firmware Info
        self.tab_info = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_info, text=" 📋 Firmware Info ")
        self._build_info_tab()

        # Tab 9: Log
        self.tab_log = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_log, text=" 📝 Log ")
        self._build_log_tab()

    # ── Cleanup ──────────────────────────────────────────────────
    # ── Cleanup ──────────────────────────────────────────────────

    def _on_close(self):
        """Handle window close."""
        if self.worker and self.worker.is_running:
            if not messagebox.askyesno("Confirm Exit",
                                       "An upgrade is in progress. Exit anyway?"):
                return
            self.worker.stop()

        # Close terminal connections
        if self.telnet_client.connected:
            self.telnet_client.disconnect()
        if self.serial_client.connected:
            self.serial_client.disconnect()

        if self.transport:
            self.transport.close()

        self.root.destroy()


def main():
    """Application entry point."""
    # High-DPI awareness for Windows 11
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError, OSError):
        pass

    if HAS_TTKB:
        root = ttkb.Window(themename=TTKB_DARK)
    else:
        root = tk.Tk()

    app = OBSCToolApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
