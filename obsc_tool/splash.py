"""
Splash screen with dependency installation progress.

Shows a modern loading screen while optional pip packages are being
installed.  Uses only the stdlib ``tkinter`` so it can run before any
third-party dependency is available.

Features:
- Animated gradient background
- SVG logo display
- Smooth progress animations
- Modern color scheme
- Shadow effects
"""

import tkinter as tk
from tkinter import ttk
import subprocess
import sys
import threading
import os
from pathlib import Path

# Dependencies to check/install  (import_name, pip_name, description)
DEPENDENCIES = [
    # ── Core UI ──────────────────────────────────────────────────
    ("ttkbootstrap", "ttkbootstrap", "Modern themed widgets"),
    ("PIL", "Pillow", "Image support"),
    ("customtkinter", "customtkinter", "Custom themed tkinter widgets"),
    # ── UI Themes & Styling ──────────────────────────────────────
    ("darkdetect", "darkdetect", "OS dark mode detection"),
    ("sv_ttk", "sv-ttk", "Sun Valley ttk theme"),
    ("ttkthemes", "ttkthemes", "Extra ttk themes"),
    # ── UI Widgets & Helpers ─────────────────────────────────────
    ("CTkMessagebox", "CTkMessagebox", "Custom message boxes"),
    ("CTkToolTip", "CTkToolTip", "Custom tooltips"),
    ("tktooltip", "tktooltip", "Tkinter tooltip widget"),
    ("tkinterdnd2", "tkinterdnd2", "Drag and drop support"),
    ("ttkwidgets", "ttkwidgets", "Extra ttk widget collection"),
    # ── System Tray & Screen ─────────────────────────────────────
    ("pystray", "pystray", "System tray icon"),
    ("screeninfo", "screeninfo", "Monitor resolution info"),
    # ── Charts & Visualization ───────────────────────────────────
    ("matplotlib", "matplotlib", "Charts and graphs"),
    ("qrcode", "qrcode", "QR code generation"),
    ("colour", "colour", "Color manipulation library"),
    # ── Terminal & Serial ────────────────────────────────────────
    ("serial", "pyserial", "Serial terminal support"),
    # ── System & Network ─────────────────────────────────────────
    ("psutil", "psutil", "System & process info"),
    ("netifaces", "netifaces", "Network interface details"),
    # ── Clipboard & Notifications ────────────────────────────────
    ("pyperclip", "pyperclip", "Clipboard support"),
    ("plyer", "plyer", "Desktop notifications"),
    # ── Cryptography ─────────────────────────────────────────────
    ("Crypto", "pycryptodome", "AES encryption"),
    # ── File Format Helpers ──────────────────────────────────────
    ("chardet", "chardet", "Character encoding detection"),
    ("defusedxml", "defusedxml", "Safe XML parsing"),
    # ── Logging & Export ─────────────────────────────────────────
    ("colorama", "colorama", "Colored terminal output"),
    ("rich", "rich", "Rich text formatting"),
]

# Pip install timeout (seconds). Override with OBSC_PIP_TIMEOUT env var.
PIP_TIMEOUT = int(os.environ.get("OBSC_PIP_TIMEOUT", "60"))


class SplashScreen:
    """Modern splash window with animations shown while dependencies install."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.overrideredirect(True)  # no window decorations
        self.root.attributes("-topmost", True)

        # Center on screen with larger size
        w, h = 600, 450
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

        # Modern gradient background (dark blue to cyan)
        self.root.configure(bg="#0D1B2A")

        # Create canvas for gradient background
        self.canvas = tk.Canvas(self.root, width=w, height=h, bd=0, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self._draw_gradient_background(w, h)

        # Create frame on top of canvas for content
        content_frame = tk.Frame(self.root, bg="", highlightthickness=0)
        content_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # ── Logo ─────────────────────────────────────────────────
        # Try to load logo, fallback to text if unavailable
        try:
            logo_path = Path(__file__).parent / "assets" / "logos" / "logo.svg"
            if logo_path.exists():
                # For now, use a placeholder - full SVG rendering requires PIL
                # which might not be installed yet
                logo_label = tk.Label(
                    content_frame, text="⚙",
                    font=("Segoe UI", 72),
                    fg="#60CDFF", bg="#0D1B2A",
                )
                logo_label.pack(pady=(0, 10))
            else:
                # Fallback icon
                logo_label = tk.Label(
                    content_frame, text="⚙",
                    font=("Segoe UI", 72),
                    fg="#60CDFF", bg="#0D1B2A",
                )
                logo_label.pack(pady=(0, 10))
        except Exception:
            # Fallback if anything goes wrong
            logo_label = tk.Label(
                content_frame, text="⚙",
                font=("Segoe UI", 72),
                fg="#60CDFF", bg="#0D1B2A",
            )
            logo_label.pack(pady=(0, 10))

        # ── Title ────────────────────────────────────────────────
        tk.Label(
            content_frame, text="OBSC Firmware Tool",
            font=("Segoe UI", 26, "bold"),
            fg="#FFFFFF", bg="#0D1B2A",
        ).pack(pady=(0, 5))

        tk.Label(
            content_frame, text="Open-Source Huawei ONT Firmware Flasher",
            font=("Segoe UI", 11),
            fg="#A0D8F7", bg="#0D1B2A",
        ).pack(pady=(0, 30))

        # ── Status ───────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Checking dependencies…")
        tk.Label(
            content_frame, textvariable=self.status_var,
            font=("Segoe UI", 11, "bold"),
            fg="#FFFFFF", bg="#0D1B2A",
        ).pack(pady=(0, 10))

        # ── Progress bar ─────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Modern.Horizontal.TProgressbar",
            troughcolor="#1E3A5F",
            background="#00B7C3",
            bordercolor="#0D1B2A",
            lightcolor="#00B7C3",
            darkcolor="#00B7C3",
            thickness=18,
        )
        self.progress = ttk.Progressbar(
            content_frame, style="Modern.Horizontal.TProgressbar",
            orient="horizontal", length=450, mode="determinate",
            maximum=len(DEPENDENCIES),
        )
        self.progress.pack(pady=(0, 10))

        # ── Detail label ─────────────────────────────────────────
        self.detail_var = tk.StringVar(value="")
        tk.Label(
            content_frame, textvariable=self.detail_var,
            font=("Segoe UI", 9),
            fg="#8DB3D6", bg="#0D1B2A",
        ).pack(pady=(0, 20))

        # ── Version label ────────────────────────────────────────
        try:
            from obsc_tool import __version__
            ver = __version__
        except Exception:
            ver = "1.0.0"
        tk.Label(
            content_frame, text=f"v{ver}",
            font=("Segoe UI", 9),
            fg="#6B8BA8", bg="#0D1B2A",
        ).pack()

        self.ready = False
        self.failed_deps = []
        self._animation_id = None

    def _draw_gradient_background(self, width: int, height: int):
        """Draw gradient background on canvas."""
        # Create vertical gradient from dark blue to darker blue
        steps = 100
        for i in range(steps):
            # Calculate color for this step
            factor = i / steps
            # Start color: #0D1B2A (dark blue)
            # End color: #1E3A5F (lighter blue)
            r1, g1, b1 = 13, 27, 42
            r2, g2, b2 = 30, 58, 95

            r = int(r1 + (r2 - r1) * factor)
            g = int(g1 + (g2 - g1) * factor)
            b = int(b1 + (b2 - b1) * factor)

            color = f'#{r:02x}{g:02x}{b:02x}'
            y1 = int(height * i / steps)
            y2 = int(height * (i + 1) / steps)

            self.canvas.create_rectangle(0, y1, width, y2, fill=color, outline='')

        # Add subtle pattern overlay
        for i in range(0, height, 40):
            self.canvas.create_line(
                0, i, width, i,
                fill='#FFFFFF', width=1, stipple='gray12'
            )

    def start(self):
        """Begin dependency check in a background thread, then mainloop."""
        t = threading.Thread(target=self._install_deps, daemon=True)
        t.start()
        # Start fade-in animation
        self._fade_in()
        self.root.mainloop()
        return self.ready

    def _fade_in(self):
        """Animate fade-in effect (simulated with opacity changes)."""
        # Note: Tkinter doesn't natively support window opacity on all platforms
        # This is a placeholder for platforms that support it
        try:
            self.root.attributes('-alpha', 0.0)
            self._fade_step(0.0, 1.0, 0.05)
        except Exception:
            # If alpha not supported, just show the window
            pass

    def _fade_step(self, current: float, target: float, step: float):
        """Perform one step of fade animation."""
        if current < target:
            try:
                self.root.attributes('-alpha', current)
                self._animation_id = self.root.after(
                    20, lambda: self._fade_step(current + step, target, step)
                )
            except Exception:
                pass

    def _install_deps(self):
        """Check and install each dependency with smooth progress updates."""
        for idx, (import_name, pip_name, desc) in enumerate(DEPENDENCIES):
            self._update(f"Checking {pip_name}…", desc, idx)
            try:
                __import__(import_name)
                self._update(f"✓ {pip_name} ready", desc, idx + 1)
                # Small delay for visual feedback
                import time
                time.sleep(0.05)
            except ImportError:
                self._update(f"Installing {pip_name}…", desc, idx)
                ok = self._pip_install(pip_name)
                if ok:
                    self._update(f"✓ {pip_name} installed", desc, idx + 1)
                else:
                    self.failed_deps.append(pip_name)
                    self._update(f"⚠ {pip_name} — optional, skipped", desc, idx + 1)
                # Small delay for visual feedback
                import time
                time.sleep(0.05)

        self._update("Launching application…", "Ready to start", len(DEPENDENCIES))
        self.ready = True
        # Close splash with fade-out animation
        self._fade_out()

    def _fade_out(self):
        """Animate fade-out effect before closing."""
        try:
            self._fade_out_step(1.0, 0.0, 0.05)
        except Exception:
            # If alpha not supported, just close after delay
            self.root.after(600, self.root.destroy)

    def _fade_out_step(self, current: float, target: float, step: float):
        """Perform one step of fade-out animation."""
        if current > target:
            try:
                self.root.attributes('-alpha', current)
                self._animation_id = self.root.after(
                    20, lambda: self._fade_out_step(current - step, target, step)
                )
            except Exception:
                self.root.destroy()
        else:
            self.root.destroy()

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
