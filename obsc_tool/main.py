"""
OBSC Firmware Tool — Main GUI Application

Modern professional GUI for Huawei ONT firmware flashing.
Uses ttkbootstrap (with tkinter/ttk fallback) for theming.

Architecture:
  - ``OBSCToolApp`` inherits from tab-mixin classes (one per tab).
  - Tab modules live in ``obsc_tool.gui`` with single-word file names.
  - Shared canvas widgets are in ``obsc_tool.gui.widgets``.
  - The gradient header is drawn on a ``tk.Canvas`` for a polished look.
"""

from __future__ import annotations

import logging
import math
import os
import sys
import tkinter as tk
from tkinter import messagebox

# ttkbootstrap — modern themes, better styling, meter widgets.
try:
    import ttkbootstrap as ttkb  # type: ignore[import]
    from ttkbootstrap.constants import *  # noqa: F401,F403
    from tkinter import ttk
    HAS_TTKB = True
except ImportError:
    from tkinter import ttk  # type: ignore[assignment]
    HAS_TTKB = False

from obsc_tool import __version__
from obsc_tool.presets import PresetManager
from obsc_tool.terminal import TelnetClient, SerialClient

# Shared colour / constant definitions
from obsc_tool.gui.colors import (  # noqa: F401
    _safe_int, THEMES, IP_MODE_DEFAULTS,
    OBSC_MULTICAST_ADDR, DEVICE_STALE_TIMEOUT,
    TTKB_DARK, TTKB_LIGHT,
)

# ── Tab mixin classes (imported from single-word module names) ────────────────
from obsc_tool.gui.upgrade import UpgradeTabMixin
from obsc_tool.gui.preset import PresetsTabMixin
from obsc_tool.gui.verify import VerificationTabMixin
from obsc_tool.gui.encrypt import CryptoTabMixin
from obsc_tool.gui.term import TerminalTabMixin
from obsc_tool.gui.dump import DumpTabMixin
from obsc_tool.gui.settings import SettingsTabMixin
from obsc_tool.gui.info import InfoTabMixin
from obsc_tool.gui.log import LogTabMixin
from obsc_tool.gui.theme import ThemeMixin
from obsc_tool.gui.adapters import AdaptersMixin

logger = logging.getLogger("obsc_tool")

# --------------------------------------------------------------------------- #
#  Palette (subset — full palette is in obsc_tool.gui.colors)
# --------------------------------------------------------------------------- #
_BG_TOP    = (20, 20, 40)    # header gradient start
_BG_MID    = (13, 13, 26)    # header gradient end
_ACCENT    = "#60CDFF"
_ACCENT2   = "#4A9FD4"
_FG_MAIN   = "#FFFFFF"
_FG_DIM    = "#8888AA"


def _rgb_hex(r: int, g: int, b: int) -> str:
    return f"#{r & 0xFF:02x}{g & 0xFF:02x}{b & 0xFF:02x}"


def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


# --------------------------------------------------------------------------- #
#  Gradient header canvas
# --------------------------------------------------------------------------- #

class _HeaderCanvas(tk.Canvas):
    """A canvas that paints a gradient and draws the OBSC mini-logo + title."""

    _H = 68  # header height (px)

    def __init__(self, parent: tk.Widget, version: str, **kw):
        super().__init__(
            parent,
            height=self._H,
            highlightthickness=0,
            **kw,
        )
        self._version = version
        self._pulse = 0.0
        self._job = None
        self.bind("<Configure>", self._draw)
        self.after(10, self._start_pulse)

    # ── Drawing ─────────────────────────────────────────────────────────────

    def _draw(self, _event=None):
        self.delete("all")
        w = max(1, self.winfo_width())
        h = self._H
        r1, g1, b1 = _BG_TOP
        r2, g2, b2 = _BG_MID

        # Horizontal gradient (left = slightly brighter accent band)
        for i in range(h):
            t = i / max(h - 1, 1)
            c = _rgb_hex(
                _lerp(r1, r2, t),
                _lerp(g1, g2, t),
                _lerp(b1, b2, t),
            )
            self.create_line(0, i, w, i, fill=c)

        # Bottom border line with glow
        self.create_line(0, h - 2, w, h - 2, fill=_ACCENT2, width=1)
        self.create_line(0, h - 1, w, h - 1, fill=_ACCENT, width=1)

        # ── Mini logo ────────────────────────────────────────────────────────
        cx, cy = 36, h // 2
        r = 22
        pulse_offset = math.sin(self._pulse) * 3

        # Glow rings
        for gl in range(4, 0, -1):
            gr = r + gl + int(pulse_offset)
            gc = _rgb_hex(
                _lerp(20, 96, gl / 4),
                _lerp(20, 205, gl / 4),
                _lerp(40, 255, gl / 4),
            )
            self.create_oval(cx - gr, cy - gr, cx + gr, cy + gr,
                             outline=gc, width=1)

        # Background circle
        self.create_oval(cx - r, cy - r, cx + r, cy + r,
                         fill=_rgb_hex(13, 27, 42), outline=_ACCENT, width=2)

        # Signal arcs
        for idx, frac in enumerate([0.70, 0.52, 0.34]):
            ar = int(r * frac)
            bright = int(200 - idx * 55)
            col = _rgb_hex(
                int(bright * 96 / 255),
                int(bright * 205 / 255),
                bright,
            )
            self.create_arc(
                cx - ar, cy - ar, cx + ar, cy + ar,
                start=210, extent=120,
                outline=col, style=tk.ARC, width=max(1, 2 - idx),
            )

        # Router body
        rw, rh = 8, 4
        self.create_rectangle(cx - rw, cy - rh, cx + rw, cy + rh,
                               fill=_ACCENT, outline="")

        # ── Title text ───────────────────────────────────────────────────────
        # Shadow
        self.create_text(
            72, cy - 10,
            text="OBSC Firmware Tool",
            anchor="w",
            font=("Segoe UI", 16, "bold"),
            fill="#000000",
        )
        # Main
        self.create_text(
            71, cy - 11,
            text="OBSC Firmware Tool",
            anchor="w",
            font=("Segoe UI", 16, "bold"),
            fill=_FG_MAIN,
        )

        # Subtitle
        self.create_text(
            72, cy + 10,
            text="Open-Source Huawei ONT Firmware Flasher",
            anchor="w",
            font=("Segoe UI", 9),
            fill=_FG_DIM,
        )

        # Version badge (right side)
        badge_x = w - 10
        self.create_text(
            badge_x, cy - 8,
            text=f"v{self._version}",
            anchor="e",
            font=("Segoe UI", 10, "bold"),
            fill=_ACCENT,
        )

    # ── Animation ───────────────────────────────────────────────────────────

    def _start_pulse(self):
        self._pulse = 0.0
        self._tick()

    def _tick(self):
        self._pulse += 0.04
        self._draw()
        self._job = self.after(60, self._tick)


# --------------------------------------------------------------------------- #
#  Main application class
# --------------------------------------------------------------------------- #

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
    """Main application window.

    Inherits one mixin per tab so each tab's code stays in its own module.
    """

    def __init__(self, root):
        self.root = root
        self.root.title(f"OBSC Firmware Tool  v{__version__}")
        self.root.geometry("960x740")
        self.root.minsize(820, 620)

        # ── Application state ────────────────────────────────────────────────
        self.current_theme = "dark"
        self.firmware = None
        self.firmware_path = ""
        self.adapters: list = []
        self.worker = None
        self.transport = None
        self.log_entries: list = []
        self.preset_manager = PresetManager()
        self.telnet_client = TelnetClient()
        self.serial_client = SerialClient()
        self.firmware_dumper = None

        # ── Logging ──────────────────────────────────────────────────────────
        self._setup_logging()

        # ── Build UI ─────────────────────────────────────────────────────────
        self._build_ui()

        # ── Post-init tasks ──────────────────────────────────────────────────
        self.root.after(120, self._refresh_adapters)
        self._set_icon()

        # Keyboard shortcuts
        self.root.bind("<F5>", lambda _e: self._refresh_adapters())
        self.root.bind("<Control-o>", lambda _e: self._browse_firmware())
        self.root.bind("<Control-q>", lambda _e: self._on_close())

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Logging setup ────────────────────────────────────────────────────────

    def _setup_logging(self):
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(name)s] %(message)s",
                                datefmt="%H:%M:%S")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    # ── Window icon ──────────────────────────────────────────────────────────

    def _set_icon(self):
        """Set window icon from the assets package (requires Pillow)."""
        try:
            from obsc_tool.assets import get_logo_photo  # noqa: PLC0415
            photo = get_logo_photo(size=32, root=self.root)
            if photo is not None:
                self.root.iconphoto(True, photo)
        except Exception:
            pass

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        colors = THEMES[self.current_theme]
        self.root.configure(bg=colors["bg"])

        self.style = ttk.Style()
        self._apply_theme()

        # ── Gradient header ──────────────────────────────────────────────────
        self._header = _HeaderCanvas(
            self.root,
            version=__version__,
            bg=colors["bg"],
        )
        self._header.pack(fill=tk.X)

        # ── Theme toggle button ──────────────────────────────────────────────
        btn_row = tk.Frame(self.root, bg=colors["bg"])
        btn_row.pack(fill=tk.X, padx=12, pady=(4, 0))
        self.theme_btn = ttk.Button(
            btn_row,
            text="☀️ Light" if self.current_theme == "dark" else "🌙 Dark",
            command=self._toggle_theme,
            width=11,
        )
        self.theme_btn.pack(side=tk.RIGHT)

        # ── Main content area ────────────────────────────────────────────────
        content = ttk.Frame(self.root, padding=(10, 4, 10, 10))
        content.pack(fill=tk.BOTH, expand=True)

        # ── Notebook (tabs) ──────────────────────────────────────────────────
        self.notebook = ttk.Notebook(content)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab definitions: (attr, label, builder)
        tabs = [
            ("tab_upgrade",   " 🔄  Upgrade ",          self._build_upgrade_tab),
            ("tab_presets",   " 📦  Presets ",           self._build_presets_tab),
            ("tab_verify",    " 🔒  Verify ",            self._build_verification_tab),
            ("tab_crypto",    " 🔐  Config Crypto ",     self._build_crypto_tab),
            ("tab_terminal",  " 💻  Terminal ",          self._build_terminal_tab),
            ("tab_dump",      " 💾  Dump ",              self._build_dump_tab),
            ("tab_settings",  " ⚙️  Settings ",          self._build_settings_tab),
            ("tab_info",      " 📋  Info ",              self._build_info_tab),
            ("tab_log",       " 📝  Log ",               self._build_log_tab),
        ]
        for attr, label, builder in tabs:
            frame = ttk.Frame(self.notebook, padding=10)
            setattr(self, attr, frame)
            self.notebook.add(frame, text=label)
            builder()

        # ── Status bar ───────────────────────────────────────────────────────
        self._build_statusbar(content)

    def _build_statusbar(self, parent):
        """Build the bottom status bar."""
        colors = THEMES[self.current_theme]
        bar = tk.Frame(parent, bg=colors.get("border", "#404040"), height=1)
        bar.pack(fill=tk.X, pady=(6, 0))

        sb = tk.Frame(parent, bg=colors.get("surface", "#2D2D2D"))
        sb.pack(fill=tk.X)

        self._status_bar_var = tk.StringVar(value="Ready")
        tk.Label(
            sb,
            textvariable=self._status_bar_var,
            font=("Segoe UI", 8),
            fg=colors.get("fg", "#FFFFFF"),
            bg=colors.get("surface", "#2D2D2D"),
            anchor="w",
        ).pack(side=tk.LEFT, padx=8, pady=2)

        tk.Label(
            sb,
            text=f"OBSC v{__version__}  |  F5: Refresh Adapters  |  Ctrl+O: Open Firmware",
            font=("Segoe UI", 8),
            fg=colors.get("fg", "#888888"),
            bg=colors.get("surface", "#2D2D2D"),
        ).pack(side=tk.RIGHT, padx=8, pady=2)

    # ── Status bar update helper ─────────────────────────────────────────────

    def _set_status(self, text: str):
        """Update the bottom status bar text."""
        try:
            self._status_bar_var.set(text)
        except tk.TclError:
            pass

    # ── Window close ─────────────────────────────────────────────────────────

    def _on_close(self):
        if self.worker and getattr(self.worker, "is_running", False):
            if not messagebox.askyesno(
                "Confirm Exit",
                "An upgrade is in progress.\nExit anyway and cancel the upgrade?",
            ):
                return
            self.worker.stop()

        if self.telnet_client.connected:
            self.telnet_client.disconnect()
        if self.serial_client.connected:
            self.serial_client.disconnect()
        if self.transport:
            self.transport.close()

        self.root.destroy()


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #

def main():
    """Launch the OBSC Firmware Tool."""
    # High-DPI awareness (Windows 10/11 only)
    try:
        from ctypes import windll  # noqa: PLC0415
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError, OSError):
        pass

    if HAS_TTKB:
        root = ttkb.Window(themename=TTKB_DARK)
    else:
        root = tk.Tk()

    OBSCToolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
