"""
OBSC Firmware Tool — Splash Screen

A modern animated splash window shown at startup while optional pip
packages are checked / installed.  Uses only the stdlib ``tkinter`` so
it works even before any third-party package is available.

Design:
  - 540 × 360 borderless window centred on the primary monitor
  - Canvas-based vertical gradient background (dark navy → near-black)
  - Programmatically drawn animated OBSC logo (arcs + rectangles)
  - Glowing LED-style progress bar
  - Smooth status-text transitions
  - Pulsing accent glow behind the logo
"""

from __future__ import annotations

import math
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import List, Tuple

# --------------------------------------------------------------------------- #
#  Dependency table
# --------------------------------------------------------------------------- #

# (import_name, pip_name, human_description)
DEPENDENCIES: List[Tuple[str, str, str]] = [
    # ── Core UI ──────────────────────────────────────────────────────────────
    ("ttkbootstrap", "ttkbootstrap", "Modern themed widgets"),
    ("PIL", "Pillow", "Image support"),
    ("customtkinter", "customtkinter", "Custom themed widgets"),
    # ── UI Themes ─────────────────────────────────────────────────────────────
    ("darkdetect", "darkdetect", "OS dark-mode detection"),
    ("sv_ttk", "sv-ttk", "Sun Valley theme"),
    ("ttkthemes", "ttkthemes", "Extra ttk themes"),
    # ── UI Widgets ────────────────────────────────────────────────────────────
    ("CTkMessagebox", "CTkMessagebox", "Custom message boxes"),
    ("CTkToolTip", "CTkToolTip", "Custom tooltips"),
    ("tktooltip", "tktooltip", "Tooltip widget"),
    ("tkinterdnd2", "tkinterdnd2", "Drag-and-drop support"),
    ("ttkwidgets", "ttkwidgets", "Extra ttk widgets"),
    # ── System Tray ──────────────────────────────────────────────────────────
    ("pystray", "pystray", "System-tray icon"),
    ("screeninfo", "screeninfo", "Monitor info"),
    # ── Visualisation ─────────────────────────────────────────────────────────
    ("matplotlib", "matplotlib", "Charts and graphs"),
    ("qrcode", "qrcode", "QR-code generation"),
    ("colour", "colour", "Colour utilities"),
    # ── Serial / Network ─────────────────────────────────────────────────────
    ("serial", "pyserial", "Serial terminal"),
    ("psutil", "psutil", "System & process info"),
    ("netifaces", "netifaces", "Network interface details"),
    # ── Clipboard / Notifications ─────────────────────────────────────────────
    ("pyperclip", "pyperclip", "Clipboard support"),
    ("plyer", "plyer", "Desktop notifications"),
    # ── Cryptography ─────────────────────────────────────────────────────────
    ("Crypto", "pycryptodome", "AES encryption"),
    # ── Format Helpers ────────────────────────────────────────────────────────
    ("chardet", "chardet", "Encoding detection"),
    ("defusedxml", "defusedxml", "Safe XML parsing"),
    # ── Logging ───────────────────────────────────────────────────────────────
    ("colorama", "colorama", "Coloured terminal output"),
    ("rich", "rich", "Rich text formatting"),
]

PIP_TIMEOUT = int(os.environ.get("OBSC_PIP_TIMEOUT", "60"))

# --------------------------------------------------------------------------- #
#  Colour palette (consistent with main app dark theme)
# --------------------------------------------------------------------------- #
_BG_TOP    = (16, 16, 36)     # #101024
_BG_BOTTOM = (8, 8, 18)       # #080812
_ACCENT    = "#60CDFF"        # electric blue
_ACCENT2   = "#4A9FD4"        # slightly dimmer blue
_FG_MAIN   = "#FFFFFF"
_FG_DIM    = "#8888AA"
_FG_OK     = "#6CCB5F"
_BAR_BG    = "#1E1E3A"


def _rgb_hex(r: int, g: int, b: int) -> str:
    return f"#{r & 0xFF:02x}{g & 0xFF:02x}{b & 0xFF:02x}"


def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


# --------------------------------------------------------------------------- #
#  Logo renderer (pure tkinter Canvas)
# --------------------------------------------------------------------------- #

class _LogoCanvas(tk.Canvas):
    """Draws the OBSC animated logo using only tkinter primitives."""

    _PULSE_PERIOD = 60  # frames for one pulse cycle

    def __init__(self, parent: tk.Widget, size: int = 120, **kw):
        super().__init__(
            parent,
            width=size, height=size,
            highlightthickness=0,
            bg=_rgb_hex(*_BG_TOP),
            **kw,
        )
        self._sz = size
        self._frame = 0
        self._job = None
        self._running = False

    # ── Drawing ─────────────────────────────────────────────────────────────

    def _draw(self, pulse: float):
        """Redraw logo.  *pulse* is a float in [0, 1] for glow intensity."""
        self.delete("all")
        sz = self._sz
        cx = cy = sz // 2

        # Outer pulsing glow ring
        glow_r = int(sz * 0.48 * (1.0 + 0.04 * math.sin(pulse * 2 * math.pi)))
        glow_alpha = int(40 + 40 * math.sin(pulse * 2 * math.pi))
        for layer in range(5, 0, -1):
            a = max(0, glow_alpha - layer * 6)
            c = _rgb_hex(
                _lerp(0, 96, a / 80),
                _lerp(0, 205, a / 80),
                _lerp(0, 255, a / 80),
            )
            lr = glow_r - layer
            if lr > 0:
                self.create_oval(cx - lr, cy - lr, cx + lr, cy + lr,
                                 outline=c, width=1)

        # Background circle
        r = int(sz * 0.42)
        self.create_oval(cx - r, cy - r, cx + r, cy + r,
                         fill=_rgb_hex(13, 27, 42), outline=_ACCENT, width=2)

        # Signal arcs (WiFi-style, top half)
        for idx, frac in enumerate([0.35, 0.26, 0.17]):
            wr = int(sz * frac)
            bright = int(220 - idx * 50 + 30 * math.sin(pulse * 2 * math.pi))
            bright = max(60, min(255, bright))
            col = _rgb_hex(
                int(bright * 96 / 255),
                int(bright * 205 / 255),
                bright,
            )
            self.create_arc(
                cx - wr, cy - wr, cx + wr, cy + wr,
                start=210, extent=120,
                outline=col, style=tk.ARC, width=max(1, 3 - idx),
            )

        # Router body (horizontal rounded bar)
        rw, rh = int(sz * 0.14), int(sz * 0.06)
        self.create_rectangle(cx - rw + 2, cy - rh, cx + rw - 2, cy + rh,
                               fill=_ACCENT, outline="")
        self.create_oval(cx - rw, cy - rh, cx - rw + rh * 2, cy + rh,
                         fill=_ACCENT, outline="")
        self.create_oval(cx + rw - rh * 2, cy - rh, cx + rw, cy + rh,
                         fill=_ACCENT, outline="")

        # Antenna stubs
        for dx in (-int(rw * 0.6), 0, int(rw * 0.6)):
            self.create_line(cx + dx, cy - rh, cx + dx,
                             cy - rh - int(sz * 0.065),
                             fill=_ACCENT, width=2)

        # "OBSC" label below body
        font_sz = max(9, sz // 10)
        self.create_text(cx + 1, cy + int(r * 0.58) + 1,
                         text="OBSC", font=("Segoe UI", font_sz, "bold"),
                         fill="#000000")
        self.create_text(cx, cy + int(r * 0.58),
                         text="OBSC", font=("Segoe UI", font_sz, "bold"),
                         fill=_FG_MAIN)

    # ── Animation ───────────────────────────────────────────────────────────

    def start(self):
        """Begin the pulsing animation."""
        self._running = True
        self._animate()

    def stop(self):
        self._running = False
        if self._job:
            self.after_cancel(self._job)
            self._job = None

    def _animate(self):
        if not self._running:
            return
        self._frame += 1
        pulse = (self._frame % self._PULSE_PERIOD) / self._PULSE_PERIOD
        self._draw(pulse)
        self._job = self.after(40, self._animate)


# --------------------------------------------------------------------------- #
#  Animated progress bar (canvas-based LED strip)
# --------------------------------------------------------------------------- #

class _ProgressBar(tk.Canvas):
    """Canvas progress bar with a glowing filled segment."""

    def __init__(self, parent, width: int = 420, height: int = 10, **kw):
        super().__init__(parent, width=width, height=height,
                         highlightthickness=0, bg=_rgb_hex(*_BG_TOP), **kw)
        self._w = width
        self._h = height
        self._value = 0.0  # 0.0 – 1.0
        self._frame = 0
        self._job = None
        self._running_anim = False
        self._shimmer = 0.0
        self._draw()

    def set(self, fraction: float):
        self._value = max(0.0, min(1.0, fraction))
        self._draw()

    def set_percent(self, pct: float):
        self.set(pct / 100.0)

    def start_shimmer(self):
        self._running_anim = True
        self._shimmer = 0.0
        self._tick()

    def stop_shimmer(self):
        self._running_anim = False
        if self._job:
            self.after_cancel(self._job)
            self._job = None

    def _tick(self):
        if not self._running_anim:
            return
        self._shimmer = (self._shimmer + 0.03) % 1.0
        self._draw()
        self._job = self.after(50, self._tick)

    def _draw(self):
        self.delete("all")
        w, h = self._w, self._h
        r = h // 2

        # Trough
        self.create_rectangle(r, 0, w - r, h, fill=_BAR_BG, outline="")
        self.create_oval(0, 0, h, h, fill=_BAR_BG, outline="")
        self.create_oval(w - h, 0, w, h, fill=_BAR_BG, outline="")

        # Fill
        fill_w = max(0, int(w * self._value))
        if fill_w > h:
            self.create_rectangle(r, 0, fill_w - r, h, fill=_ACCENT2, outline="")
            self.create_oval(0, 0, h, h, fill=_ACCENT2, outline="")
            self.create_oval(fill_w - h, 0, fill_w, h, fill=_ACCENT2, outline="")

            # Shimmer highlight
            sh_x = int(fill_w * self._shimmer)
            hw = max(4, int(w * 0.06))
            x1 = max(r, sh_x - hw)
            x2 = min(fill_w - r, sh_x + hw)
            if x2 > x1:
                self.create_rectangle(x1, 1, x2, h // 2, fill=_ACCENT, outline="")

        # Glow tip
        if fill_w > h:
            tip_x = fill_w
            glow_r2 = h
            for gl in range(4, 0, -1):
                gc = _rgb_hex(
                    _lerp(16, 96, gl / 4),
                    _lerp(16, 205, gl / 4),
                    _lerp(36, 255, gl / 4),
                )
                self.create_oval(
                    tip_x - glow_r2 - gl * 2, r - gl,
                    tip_x + gl * 2, r + h + gl,
                    fill=gc, outline="",
                )


# --------------------------------------------------------------------------- #
#  Splash screen window
# --------------------------------------------------------------------------- #

class SplashScreen:
    """Animated splash window shown during dependency installation."""

    _W = 540
    _H = 370

    def __init__(self):
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)

        # ── Center on screen ─────────────────────────────────────────────────
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - self._W) // 2
        y = (sh - self._H) // 2
        self.root.geometry(f"{self._W}x{self._H}+{x}+{y}")

        # Rounded corners via transparent background on Windows
        try:
            self.root.attributes("-alpha", 0.97)
        except tk.TclError:
            pass

        # ── Main canvas (gradient background) ────────────────────────────────
        self._canvas = tk.Canvas(
            self.root, width=self._W, height=self._H,
            highlightthickness=0,
        )
        self._canvas.pack(fill="both", expand=True)
        self._draw_background()

        # ── Decorative top border line ────────────────────────────────────────
        self._canvas.create_line(0, 2, self._W, 2, fill=_ACCENT, width=2)

        # ── Logo ─────────────────────────────────────────────────────────────
        self._logo = _LogoCanvas(self._canvas, size=110,
                                  bg=_rgb_hex(*_BG_TOP))
        self._canvas.create_window(self._W // 2, 85, window=self._logo)

        # ── Title ─────────────────────────────────────────────────────────────
        self._canvas.create_text(
            self._W // 2 + 1, 165,
            text="OBSC Firmware Tool",
            font=("Segoe UI", 20, "bold"), fill="#000000",
        )
        self._canvas.create_text(
            self._W // 2, 164,
            text="OBSC Firmware Tool",
            font=("Segoe UI", 20, "bold"), fill=_FG_MAIN,
        )

        # ── Subtitle ──────────────────────────────────────────────────────────
        self._canvas.create_text(
            self._W // 2, 190,
            text="Open-Source Huawei ONT Firmware Flasher",
            font=("Segoe UI", 10), fill=_FG_DIM,
        )

        # ── Status text ───────────────────────────────────────────────────────
        self._status_id = self._canvas.create_text(
            self._W // 2, 230,
            text="Initialising…",
            font=("Segoe UI", 10), fill=_FG_MAIN,
        )

        # ── Progress bar ─────────────────────────────────────────────────────
        self._bar = _ProgressBar(self._canvas, width=430, height=10)
        self._canvas.create_window(self._W // 2, 260, window=self._bar)

        # ── Detail text ───────────────────────────────────────────────────────
        self._detail_id = self._canvas.create_text(
            self._W // 2, 285,
            text="",
            font=("Segoe UI", 9), fill=_FG_DIM,
        )

        # ── Version + copyright ───────────────────────────────────────────────
        try:
            from hwflash._version import __version__ as ver  # noqa: PLC0415
        except Exception:
            ver = "1.0.0"
        self._canvas.create_text(
            self._W // 2, self._H - 22,
            text=f"v{ver}  ·  Open Source  ·  github.com/Uaemextop/HuaweiFirmwareTool",
            font=("Segoe UI", 8), fill=_FG_DIM,
        )

        self._canvas.create_line(0, self._H - 3, self._W, self._H - 3,
                                  fill=_ACCENT2, width=1)

        self.ready = False
        self.failed_deps: list = []

    # ── Background gradient ──────────────────────────────────────────────────

    def _draw_background(self):
        """Draw a smooth vertical gradient on the main canvas."""
        W, H = self._W, self._H
        r1, g1, b1 = _BG_TOP
        r2, g2, b2 = _BG_BOTTOM
        for i in range(H):
            t = i / max(H - 1, 1)
            c = _rgb_hex(
                _lerp(r1, r2, t),
                _lerp(g1, g2, t),
                _lerp(b1, b2, t),
            )
            self._canvas.create_line(0, i, W, i, fill=c)

    # ── Public API ──────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start dependency installation and run the event loop.

        Returns ``True`` if the application should launch.
        """
        self._logo.start()
        self._bar.start_shimmer()
        t = threading.Thread(target=self._install_deps, daemon=True)
        t.start()
        self.root.mainloop()
        return self.ready

    # ── Dependency installation ──────────────────────────────────────────────

    def _install_deps(self):
        total = len(DEPENDENCIES)
        for idx, (import_name, pip_name, desc) in enumerate(DEPENDENCIES):
            self._update(f"Checking {pip_name}…", desc, idx / total)
            try:
                __import__(import_name)
                # Already installed — brief pause so users see progress
                time.sleep(0.02)
            except ImportError:
                self._update(f"Installing {pip_name}…", desc, idx / total)
                ok = self._pip_install(pip_name)
                if not ok:
                    self.failed_deps.append(pip_name)
                    self._update(
                        f"⚠ {pip_name} — optional, skipped", desc,
                        (idx + 1) / total,
                    )
                    time.sleep(0.3)
                    continue
            self._update(f"✓ {pip_name}", desc, (idx + 1) / total)

        self._update("✨ Launching application…", "", 1.0)
        self.ready = True
        self.root.after(700, self._close)

    def _close(self):
        self._logo.stop()
        self._bar.stop_shimmer()
        self.root.destroy()

    @staticmethod
    def _pip_install(package: str) -> bool:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", package],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=PIP_TIMEOUT,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError, OSError):
            return False

    def _update(self, status: str, detail: str, fraction: float):
        """Thread-safe UI update."""
        def _apply():
            self._canvas.itemconfigure(self._status_id, text=status)
            self._canvas.itemconfigure(self._detail_id, text=detail)
            self._bar.set(fraction)
        self.root.after(0, _apply)


# --------------------------------------------------------------------------- #
#  Public helpers
# --------------------------------------------------------------------------- #

def _is_frozen() -> bool:
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def ensure_dependencies_gui() -> bool:
    """Show the splash screen and install missing dependencies.

    Returns ``True`` if the app should launch, ``False`` on critical failure.
    """
    if _is_frozen():
        return True

    # Quick check — skip splash if everything is already present
    all_present = all(
        _try_import(name) for name, _, _ in DEPENDENCIES
    )
    if all_present:
        return True

    try:
        splash = SplashScreen()
        return splash.start()
    except Exception:
        _ensure_dependencies_cli()
        return True


def _try_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _ensure_dependencies_cli():
    """Silent fallback installer (used when no display is available)."""
    for import_name, pip_name, _ in DEPENDENCIES:
        if not _try_import(import_name):
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--quiet", pip_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=PIP_TIMEOUT,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    FileNotFoundError, OSError):
                pass
