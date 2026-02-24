"""
Splash screen with dependency installation progress.

Shows a modern loading screen while optional pip packages are being
installed.  Uses only the stdlib ``tkinter`` so it can run before any
third-party dependency is available.
"""

import tkinter as tk
from tkinter import ttk
import subprocess
import sys
import threading
import os

# Dependencies to check/install  (import_name, pip_name, description)
DEPENDENCIES = [
    ("ttkbootstrap", "ttkbootstrap", "Modern themed widgets"),
    ("PIL", "Pillow", "Image support"),
    ("serial", "pyserial", "Serial terminal support"),
    ("psutil", "psutil", "System & process info"),
    ("netifaces", "netifaces", "Network interface details"),
    ("pyperclip", "pyperclip", "Clipboard support"),
    ("plyer", "plyer", "Desktop notifications"),
    ("Crypto", "pycryptodome", "AES encryption"),
    ("chardet", "chardet", "Character encoding detection"),
    ("defusedxml", "defusedxml", "Safe XML parsing"),
    ("colorama", "colorama", "Colored terminal output"),
    ("rich", "rich", "Rich text formatting"),
]

# Pip install timeout (seconds). Override with OBSC_PIP_TIMEOUT env var.
PIP_TIMEOUT = int(os.environ.get("OBSC_PIP_TIMEOUT", "60"))


class SplashScreen:
    """Lightweight splash window shown while dependencies install."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.overrideredirect(True)  # no window decorations
        self.root.attributes("-topmost", True)

        # Center on screen
        w, h = 480, 320
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

        # Dark background
        self.root.configure(bg="#1a1a2e")

        # ── Title ────────────────────────────────────────────────
        tk.Label(
            self.root, text="OBSC Firmware Tool",
            font=("Segoe UI", 22, "bold"),
            fg="#60CDFF", bg="#1a1a2e",
        ).pack(pady=(40, 5))

        tk.Label(
            self.root, text="Open-Source Huawei ONT Firmware Flasher",
            font=("Segoe UI", 10),
            fg="#aaaaaa", bg="#1a1a2e",
        ).pack()

        # ── Status ───────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Checking dependencies…")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Segoe UI", 10),
            fg="#ffffff", bg="#1a1a2e",
        ).pack(pady=(30, 8))

        # ── Progress bar ─────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Splash.Horizontal.TProgressbar",
            troughcolor="#2d2d44",
            background="#60CDFF",
            thickness=14,
        )
        self.progress = ttk.Progressbar(
            self.root, style="Splash.Horizontal.TProgressbar",
            orient="horizontal", length=380, mode="determinate",
            maximum=len(DEPENDENCIES),
        )
        self.progress.pack(pady=(0, 10))

        # ── Detail label ─────────────────────────────────────────
        self.detail_var = tk.StringVar(value="")
        tk.Label(
            self.root, textvariable=self.detail_var,
            font=("Segoe UI", 9),
            fg="#888888", bg="#1a1a2e",
        ).pack()

        # ── Version label ────────────────────────────────────────
        try:
            from obsc_tool import __version__
            ver = __version__
        except Exception:
            ver = "1.0.0"
        tk.Label(
            self.root, text=f"v{ver}",
            font=("Segoe UI", 9),
            fg="#555555", bg="#1a1a2e",
        ).pack(side=tk.BOTTOM, pady=10)

        self.ready = False
        self.failed_deps = []

    def start(self):
        """Begin dependency check in a background thread, then mainloop."""
        t = threading.Thread(target=self._install_deps, daemon=True)
        t.start()
        self.root.mainloop()
        return self.ready

    def _install_deps(self):
        """Check and install each dependency."""
        for idx, (import_name, pip_name, desc) in enumerate(DEPENDENCIES):
            self._update(f"Checking {pip_name}…", desc, idx)
            try:
                __import__(import_name)
                self._update(f"✓ {pip_name} ready", desc, idx + 1)
            except ImportError:
                self._update(f"Installing {pip_name}…", desc, idx)
                ok = self._pip_install(pip_name)
                if ok:
                    self._update(f"✓ {pip_name} installed", desc, idx + 1)
                else:
                    self.failed_deps.append(pip_name)
                    self._update(f"⚠ {pip_name} — optional, skipped", desc, idx + 1)

        self._update("Launching application…", "", len(DEPENDENCIES))
        self.ready = True
        # Close splash after a short delay so the user sees "Launching"
        self.root.after(600, self.root.destroy)

    def _pip_install(self, package):
        """Install a pip package. Returns True on success."""
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

    def _update(self, status, detail, progress_value):
        """Thread-safe UI update."""
        self.root.after(0, lambda: self.status_var.set(status))
        self.root.after(0, lambda: self.detail_var.set(detail))
        self.root.after(0, lambda: self.progress.configure(value=progress_value))


def _is_frozen():
    """Return True if running from a PyInstaller bundle."""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def ensure_dependencies_gui():
    """Show splash screen and install dependencies.

    Returns True if the app should launch, False on critical failure.
    """
    # When running from a PyInstaller EXE, all dependencies are already
    # bundled — skip the check entirely to avoid blank-screen delays.
    if _is_frozen():
        return True

    # Quick check — if all deps are already present, skip splash
    all_present = True
    for import_name, _, _ in DEPENDENCIES:
        try:
            __import__(import_name)
        except ImportError:
            all_present = False
            break

    if all_present:
        return True

    # Show splash and install
    try:
        splash = SplashScreen()
        return splash.start()
    except Exception:
        # If splash fails (e.g. no display), fall back to silent install
        _ensure_dependencies_cli()
        return True


def _ensure_dependencies_cli():
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
