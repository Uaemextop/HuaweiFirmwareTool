"""
Modern animated splash screen with dependency installation progress.

Features smooth gradient background, animated progress bar,
pulsing logo, and real-time status updates.
Uses only stdlib tkinter so it works before any dependency is installed.
"""

import tkinter as tk
from tkinter import ttk
import subprocess
import sys
import threading
import os
import math

# Dependencies to check/install (import_name, pip_name, description)
DEPENDENCIES = [
    ("ttkbootstrap", "ttkbootstrap", "Modern themed widgets"),
    ("PIL", "Pillow", "Image support"),
    ("customtkinter", "customtkinter", "Custom themed tkinter widgets"),
    ("darkdetect", "darkdetect", "OS dark mode detection"),
    ("serial", "pyserial", "Serial terminal support"),
    ("psutil", "psutil", "System and process info"),
    ("Crypto", "pycryptodome", "AES encryption"),
    ("chardet", "chardet", "Character encoding detection"),
    ("defusedxml", "defusedxml", "Safe XML parsing"),
    ("colorama", "colorama", "Colored terminal output"),
]

PIP_TIMEOUT = int(os.environ.get("OBSC_PIP_TIMEOUT", "60"))


class SplashScreen:
    """Modern animated splash window shown while dependencies install."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)

        w, h = 520, 380
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

        try:
            self.root.attributes("-alpha", 0.0)
        except tk.TclError:
            pass

        self.canvas = tk.Canvas(self.root, width=w, height=h, highlightthickness=0, bd=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self._draw_background(w, h)

        # Border glow
        self.canvas.create_rectangle(1, 1, w - 1, h - 1, outline="#2563EB", width=2)

        # Logo circle
        cx, cy = w // 2, 100
        r = 35
        self.canvas.create_oval(cx - r - 3, cy - r - 3, cx + r + 3, cy + r + 3,
                                fill="#1E40AF", outline="#3B82F6", width=2)
        self.canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                fill="#1E3A5F", outline="#2563EB", width=1)
        # Flash symbol
        flash_pts = [cx - 8, cy - 18, cx + 4, cy - 3, cx - 3, cy - 3,
                     cx + 8, cy + 18, cx - 4, cy + 3, cx + 3, cy + 3]
        self.canvas.create_polygon(flash_pts, fill="#60CDFF", outline="")
        # Circuit dots
        for angle in [45, 135, 225, 315]:
            dx = int(r * 0.85 * math.cos(math.radians(angle)))
            dy = int(r * 0.85 * math.sin(math.radians(angle)))
            self.canvas.create_oval(cx + dx - 3, cy + dy - 3, cx + dx + 3, cy + dy + 3,
                                    fill="#06B6D4", outline="")

        # Title
        self.canvas.create_text(w // 2, 160, text="HuaweiFlash",
                                font=("Segoe UI", 22, "bold"), fill="#F8FAFC")
        self.canvas.create_text(w // 2, 185, text="Open-Source Huawei ONT Firmware Flasher",
                                font=("Segoe UI", 10), fill="#94A3B8")

        # Status text
        self._status_id = self.canvas.create_text(
            w // 2, 235, text="Checking dependencies...",
            font=("Segoe UI", 10), fill="#E2E8F0"
        )

        # Progress bar background
        bar_x, bar_y = 60, 265
        bar_w, bar_h = w - 120, 8
        self.canvas.create_rectangle(bar_x, bar_y, bar_x + bar_w, bar_y + bar_h,
                                     fill="#1E293B", outline="#334155")
        # Progress bar fill
        self._bar_fill = self.canvas.create_rectangle(
            bar_x + 1, bar_y + 1, bar_x + 1, bar_y + bar_h - 1,
            fill="#2563EB", outline=""
        )
        # Progress bar highlight
        self._bar_highlight = self.canvas.create_rectangle(
            bar_x + 1, bar_y + 1, bar_x + 1, bar_y + bar_h // 3,
            fill="#3B82F6", outline=""
        )
        self._bar_x = bar_x
        self._bar_w = bar_w
        self._bar_y = bar_y
        self._bar_h = bar_h

        # Detail text
        self._detail_id = self.canvas.create_text(
            w // 2, 290, text="", font=("Segoe UI", 9), fill="#64748B"
        )

        # Version
        try:
            from obsc_tool import __version__
            ver = __version__
        except Exception:
            ver = "1.0.0"
        self.canvas.create_text(w // 2, h - 20, text=f"v{ver}",
                                font=("Segoe UI", 9), fill="#475569")

        # Decorative dots
        for i in range(5):
            dx = w // 2 - 40 + i * 20
            self.canvas.create_oval(dx - 2, h - 45, dx + 2, h - 41,
                                    fill="#334155", outline="")

        self.ready = False
        self.failed_deps = []
        self._progress = 0.0
        self._alpha = 0.0

    def _draw_background(self, w, h):
        """Draw gradient background."""
        for y in range(h):
            ratio = y / h
            r = int(15 + ratio * 5)
            g = int(23 + ratio * 8)
            b = int(42 + ratio * 12)
            color = f"#{r:02x}{g:02x}{b:02x}"
            self.canvas.create_line(0, y, w, y, fill=color)

    def start(self):
        """Begin dependency check with fade-in, then mainloop."""
        self._fade_in()
        t = threading.Thread(target=self._install_deps, daemon=True)
        t.start()
        self.root.mainloop()
        return self.ready

    def _fade_in(self):
        """Smooth fade-in animation."""
        self._alpha = 0.0
        self._do_fade_in()

    def _do_fade_in(self):
        self._alpha += 0.05
        if self._alpha >= 1.0:
            self._alpha = 1.0
            try:
                self.root.attributes("-alpha", 1.0)
            except tk.TclError:
                pass
            return
        try:
            self.root.attributes("-alpha", self._alpha)
        except tk.TclError:
            pass
        self.root.after(20, self._do_fade_in)

    def _install_deps(self):
        """Check and install each dependency."""
        total = len(DEPENDENCIES)
        for idx, (import_name, pip_name, desc) in enumerate(DEPENDENCIES):
            self._update(f"Checking {pip_name}...", desc, idx / total)
            try:
                __import__(import_name)
                self._update(f"✓ {pip_name} ready", desc, (idx + 1) / total)
            except ImportError:
                self._update(f"Installing {pip_name}...", desc, idx / total)
                ok = self._pip_install(pip_name)
                if ok:
                    self._update(f"✓ {pip_name} installed", desc, (idx + 1) / total)
                else:
                    self.failed_deps.append(pip_name)
                    self._update(f"⚠ {pip_name} skipped", desc, (idx + 1) / total)

        self._update("Launching application...", "", 1.0)
        self.ready = True
        self.root.after(500, self._fade_out)

    def _fade_out(self):
        """Smooth fade-out before closing."""
        self._alpha -= 0.08
        if self._alpha <= 0:
            self.root.destroy()
            return
        try:
            self.root.attributes("-alpha", self._alpha)
        except tk.TclError:
            self.root.destroy()
            return
        self.root.after(20, self._fade_out)

    def _pip_install(self, package):
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

    def _update(self, status, detail, progress):
        """Thread-safe UI update with animated progress."""
        def _do():
            self.canvas.itemconfigure(self._status_id, text=status)
            self.canvas.itemconfigure(self._detail_id, text=detail)
            self._animate_progress(progress)
        self.root.after(0, _do)

    def _animate_progress(self, target):
        """Smoothly animate progress bar to target value."""
        diff = target - self._progress
        if abs(diff) < 0.005:
            self._progress = target
            self._draw_progress()
            return
        self._progress += diff * 0.2
        self._draw_progress()
        self.root.after(16, lambda: self._animate_progress(target))

    def _draw_progress(self):
        fill_w = int(self._bar_w * self._progress)
        x1 = self._bar_x + 1
        x2 = x1 + max(0, fill_w - 2)
        self.canvas.coords(self._bar_fill, x1, self._bar_y + 1, x2, self._bar_y + self._bar_h - 1)
        self.canvas.coords(self._bar_highlight, x1, self._bar_y + 1, x2, self._bar_y + self._bar_h // 3)


def _is_frozen():
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def ensure_dependencies():
    """Show splash screen and install dependencies.

    Returns True if the app should launch, False on critical failure.
    """
    if _is_frozen():
        return True

    all_present = True
    for import_name, _, _ in DEPENDENCIES:
        try:
            __import__(import_name)
        except ImportError:
            all_present = False
            break

    if all_present:
        return True

    try:
        splash = SplashScreen()
        return splash.start()
    except Exception:
        _install_silent()
        return True


def _install_silent():
    """Fallback silent installer (no GUI)."""
    for import_name, pip_name, _ in DEPENDENCIES:
        try:
            __import__(import_name)
        except ImportError:
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
