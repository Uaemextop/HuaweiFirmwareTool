"""
HuaweiFlash — Modern GUI Application

Sidebar navigation, card-based layout, gradient accents,
animated transitions, and custom window frame.
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox
import logging

try:
    import ttkbootstrap as ttkb
    from ttkbootstrap.constants import *  # noqa: F401,F403
    from tkinter import ttk
    HAS_TTKB = True
except ImportError:
    from tkinter import ttk
    HAS_TTKB = False

from hwflash import __version__
from hwflash.core.presets import PresetManager
from hwflash.core.terminal import TelnetClient, SerialClient
from hwflash.shared.styles import (
    THEMES, get_theme, IP_MODE_DEFAULTS,
    OBSC_MULTICAST_ADDR, DEVICE_STALE_TIMEOUT,
    TTKB_DARK, TTKB_LIGHT, FONT_FAMILY, PRIMARY,
)
from hwflash.shared.helpers import safe_int
from hwflash.shared.icons import generate_logo
from hwflash.ui.components.cards import GradientBar
from hwflash.ui.components.sidebar import SidebarNav

from hwflash.ui.tabs.upgrade import UpgradeTabMixin
from hwflash.ui.tabs.presets import PresetsTabMixin
from hwflash.ui.tabs.verify import VerificationTabMixin
from hwflash.ui.tabs.crypto import CryptoTabMixin
from hwflash.ui.tabs.terminal import TerminalTabMixin
from hwflash.ui.tabs.dump import DumpTabMixin
from hwflash.ui.tabs.settings import SettingsTabMixin
from hwflash.ui.tabs.info import InfoTabMixin
from hwflash.ui.tabs.log import LogTabMixin
from hwflash.ui.tabs.theme import ThemeMixin
from hwflash.ui.tabs.adapters import AdaptersMixin

logger = logging.getLogger("hwflash")

APP_NAME = "HuaweiFlash"


class HuaweiFlashApp(
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
    """Main application class with modern sidebar-based UI."""

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{__version__}")
        self.root.geometry("1050x750")
        self.root.minsize(900, 650)

        # State
        self.current_theme = "dark"
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
        self._build_modern_ui()

        # Load adapters
        self.root.after(100, self._refresh_adapters)

        # Set icon
        self._set_app_icon()

        # Keyboard shortcuts
        self.root.bind("<F5>", lambda e: self._refresh_adapters())
        self.root.bind("<Control-o>", lambda e: self._browse_firmware())

        # Handle close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_logging(self):
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s [%(name)s] %(message)s", datefmt="%H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    def _set_app_icon(self):
        """Set window icon from generated logo."""
        try:
            logo_data = generate_logo(64)
            if logo_data:
                from PIL import Image, ImageTk
                import io
                img = Image.open(io.BytesIO(logo_data))
                self._icon_photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, self._icon_photo)
        except Exception:
            try:
                self.root.iconbitmap(default="")
            except tk.TclError:
                pass

    def _build_modern_ui(self):
        """Build the modern sidebar-based UI layout."""
        colors = get_theme(self.current_theme)

        self.root.configure(bg=colors["bg"])

        self.style = ttk.Style()
        self._apply_theme()

        # Top gradient accent bar
        self._accent_bar = GradientBar(
            self.root, height=3, color_start="#2563EB", color_end="#06B6D4"
        )
        self._accent_bar.pack(fill=tk.X)

        # Main horizontal container
        main_container = tk.Frame(self.root, bg=colors["bg"])
        main_container.pack(fill=tk.BOTH, expand=True)

        # ── Sidebar ──────────────────────────────────────────────
        self._sidebar = SidebarNav(
            main_container, theme=colors, on_select=self._on_nav_select
        )
        self._sidebar.pack(side=tk.LEFT, fill=tk.Y)

        # Sidebar separator
        sep = tk.Frame(main_container, bg=colors["border"], width=1)
        sep.pack(side=tk.LEFT, fill=tk.Y)

        # Sidebar header with logo
        def build_header(parent):
            logo_frame = tk.Frame(parent, bg=colors["sidebar"])
            logo_frame.pack(fill=tk.X, pady=(0, 8))

            # Try to show logo image
            try:
                logo_data = generate_logo(40)
                if logo_data:
                    from PIL import Image, ImageTk
                    import io
                    img = Image.open(io.BytesIO(logo_data))
                    self._sidebar_logo = ImageTk.PhotoImage(img)
                    logo_label = tk.Label(
                        logo_frame, image=self._sidebar_logo,
                        bg=colors["sidebar"]
                    )
                    logo_label.pack(side=tk.LEFT, padx=(0, 8))
            except Exception:
                pass

            title_frame = tk.Frame(logo_frame, bg=colors["sidebar"])
            title_frame.pack(side=tk.LEFT, fill=tk.X)
            tk.Label(
                title_frame, text=APP_NAME,
                font=(FONT_FAMILY, 13, "bold"),
                bg=colors["sidebar"], fg=colors["fg"],
            ).pack(anchor="w")
            tk.Label(
                title_frame, text=f"v{__version__}",
                font=(FONT_FAMILY, 8),
                bg=colors["sidebar"], fg=colors["fg_muted"],
            ).pack(anchor="w")

        self._sidebar.set_header(build_header)

        # Navigation items
        self._sidebar.add_section_label("Main")
        self._sidebar.add_item("Upgrade", "⚡", "upgrade")
        self._sidebar.add_item("Presets", "📦", "presets")
        self._sidebar.add_item("Verify", "🛡", "verify")
        self._sidebar.add_separator()
        self._sidebar.add_section_label("Tools")
        self._sidebar.add_item("Crypto", "🔐", "crypto")
        self._sidebar.add_item("Terminal", "💻", "terminal")
        self._sidebar.add_item("Dump", "💾", "dump")
        self._sidebar.add_separator()
        self._sidebar.add_section_label("Config")
        self._sidebar.add_item("Settings", "⚙", "settings")
        self._sidebar.add_item("Info", "📋", "info")
        self._sidebar.add_item("Log", "📝", "log")

        # Footer with theme toggle
        def build_footer(parent):
            self.theme_btn = tk.Button(
                parent,
                text="🌙 Dark Mode",
                font=(FONT_FAMILY, 9),
                bg=colors["bg_card"],
                fg=colors["fg_secondary"],
                relief="flat",
                cursor="hand2",
                command=self._toggle_theme,
                activebackground=colors["bg_hover"],
                activeforeground=colors["fg"],
            )
            self.theme_btn.pack(fill=tk.X, pady=2)

        self._sidebar.set_footer(build_footer)

        # ── Content area ─────────────────────────────────────────
        self._content_area = tk.Frame(main_container, bg=colors["bg"])
        self._content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Content header
        self._content_header = tk.Frame(self._content_area, bg=colors["bg"], height=50)
        self._content_header.pack(fill=tk.X, padx=20, pady=(16, 8))
        self._content_header.pack_propagate(False)

        self._page_title = tk.Label(
            self._content_header,
            text="⚡ Firmware Upgrade",
            font=(FONT_FAMILY, 16, "bold"),
            bg=colors["bg"],
            fg=colors["fg"],
            anchor="w",
        )
        self._page_title.pack(side=tk.LEFT, fill=tk.X)

        self._page_subtitle = tk.Label(
            self._content_header,
            text="Flash firmware to your Huawei ONT device",
            font=(FONT_FAMILY, 9),
            bg=colors["bg"],
            fg=colors["fg_muted"],
            anchor="e",
        )
        self._page_subtitle.pack(side=tk.RIGHT)

        # Separator under header
        header_sep = tk.Frame(self._content_area, bg=colors["border"], height=1)
        header_sep.pack(fill=tk.X, padx=20)

        # Notebook (hidden tabs - controlled by sidebar)
        self.notebook = ttk.Notebook(self._content_area)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(8, 16))

        # Hide notebook tabs (we use sidebar instead)
        style = ttk.Style()
        style.layout("TNotebook.Tab", [])

        # ── Build all tabs ───────────────────────────────────────
        self.tab_upgrade = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_upgrade, text="Upgrade")
        self._build_upgrade_tab()

        self.tab_presets = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_presets, text="Presets")
        self._build_presets_tab()

        self.tab_verify = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_verify, text="Verify")
        self._build_verification_tab()

        self.tab_crypto = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_crypto, text="Crypto")
        self._build_crypto_tab()

        self.tab_terminal = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_terminal, text="Terminal")
        self._build_terminal_tab()

        self.tab_dump = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_dump, text="Dump")
        self._build_dump_tab()

        self.tab_settings = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_settings, text="Settings")
        self._build_settings_tab()

        self.tab_info = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_info, text="Info")
        self._build_info_tab()

        self.tab_log = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_log, text="Log")
        self._build_log_tab()

        self._sidebar.select(0)

        # Status bar at bottom
        self._build_status_bar(colors)

    def _build_status_bar(self, colors):
        """Build bottom status bar with connection info."""
        status_frame = tk.Frame(self.root, bg=colors["bg_secondary"], height=28)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)

        GradientBar(
            status_frame, height=1,
            color_start="#2563EB", color_end="#06B6D4",
        ).pack(fill=tk.X, side=tk.TOP)

        self._status_label = tk.Label(
            status_frame, text="Ready",
            font=(FONT_FAMILY, 8),
            bg=colors["bg_secondary"], fg=colors["fg_muted"],
            anchor="w", padx=12,
        )
        self._status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._adapter_label = tk.Label(
            status_frame, text="No adapter selected",
            font=(FONT_FAMILY, 8),
            bg=colors["bg_secondary"], fg=colors["fg_muted"],
            anchor="e", padx=12,
        )
        self._adapter_label.pack(side=tk.RIGHT)

    def set_status(self, text: str):
        """Update the status bar text."""
        try:
            self._status_label.configure(text=text)
        except (tk.TclError, AttributeError):
            pass

    # ── Page titles and subtitles for each nav item ──────────────
    _PAGE_INFO = {
        "upgrade": ("⚡ Firmware Upgrade", "Flash firmware to your Huawei ONT device"),
        "presets": ("📦 Router Presets", "Manage device configuration profiles"),
        "verify": ("🛡 Verification", "Configure pre-flash integrity checks"),
        "crypto": ("🔐 Config Crypto", "Encrypt and decrypt device configuration files"),
        "terminal": ("💻 Terminal", "Connect to device via Telnet or Serial"),
        "dump": ("💾 Firmware Dump", "Extract firmware partitions from device"),
        "settings": ("⚙ Settings", "Configure protocol and network parameters"),
        "info": ("📋 Firmware Info", "View detailed firmware structure and metadata"),
        "log": ("📝 Activity Log", "View application events and operation history"),
    }

    _TAB_MAP = {
        "upgrade": 0,
        "presets": 1,
        "verify": 2,
        "crypto": 3,
        "terminal": 4,
        "dump": 5,
        "settings": 6,
        "info": 7,
        "log": 8,
    }

    def _on_nav_select(self, index: int, tag: str):
        """Handle sidebar navigation selection."""
        tab_idx = self._TAB_MAP.get(tag, 0)
        self.notebook.select(tab_idx)

        title, subtitle = self._PAGE_INFO.get(tag, ("", ""))
        colors = get_theme(self.current_theme)
        self._page_title.configure(text=title, fg=colors["fg"])
        self._page_subtitle.configure(text=subtitle, fg=colors["fg_muted"])

    def _on_close(self):
        """Handle window close."""
        if self.worker and self.worker.is_running:
            if not messagebox.askyesno(
                "Confirm Exit", "An upgrade is in progress. Exit anyway?"
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


def main():
    """Application entry point."""
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError, OSError):
        pass

    if HAS_TTKB:
        root = ttkb.Window(themename=TTKB_DARK)
    else:
        root = tk.Tk()

    HuaweiFlashApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
