"""
HuaweiFlash — Main GUI Application

Custom borderless window with sidebar navigation and standalone tab classes.
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, ttk

try:
    import ttkbootstrap as ttkb
    HAS_TTKB = True
except ImportError:
    ttkb = None
    HAS_TTKB = False

from hwflash import __version__
from hwflash.core.presets import PresetManager
from hwflash.core.terminal import TelnetClient, SerialClient
from hwflash.shared.styles import ThemeEngine, TTKB_DARK, FONT_FAMILY
from hwflash.shared.icons import generate_logo
from hwflash.ui.components.cards import GradientBar
from hwflash.ui.components.sidebar import SidebarNav
from hwflash.ui.titlebar import CustomTitlebar
from hwflash.ui.state import AppState, AppController
from hwflash.ui.tabs.adapters import refresh_adapters_async
from hwflash.ui.tabs.upgrade import UpgradeTab
from hwflash.ui.tabs.presets import PresetsTab
from hwflash.ui.tabs.verify import VerifyTab
from hwflash.ui.tabs.crypto import CryptoTab
from hwflash.ui.tabs.terminal import TerminalTab
from hwflash.ui.tabs.dump import DumpTab
from hwflash.ui.tabs.settings import SettingsTab
from hwflash.ui.tabs.info import InfoTab
from hwflash.ui.tabs.log import LogTab

logger = logging.getLogger("hwflash")

APP_NAME = "HuaweiFlash"

NAV_ICONS = {
    "upgrade": "⇪",
    "presets": "▦",
    "verify": "✓",
    "crypto": "⌁",
    "terminal": ">_",
    "dump": "⤓",
    "settings": "⚙",
    "info": "ⓘ",
    "log": "☷",
}


class HuaweiFlashApp:
    """Main application class with custom borderless window."""

    _PAGE_INFO = {
        "upgrade": ("Firmware Upgrade", "Flash firmware to your Huawei ONT device"),
        "presets": ("Router Presets", "Manage device configuration profiles"),
        "verify": ("Verification", "Configure pre-flash integrity checks"),
        "crypto": ("Config Crypto", "Encrypt and decrypt device configuration files"),
        "terminal": ("Terminal", "Connect to device via Telnet or Serial"),
        "dump": ("Firmware Dump", "Extract firmware partitions from device"),
        "settings": ("Settings", "Configure protocol and network parameters"),
        "info": ("Firmware Info", "View detailed firmware structure and metadata"),
        "log": ("Activity Log", "View application events and operation history"),
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

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{__version__}")
        self.root.geometry("1100x780")
        self.root.minsize(950, 680)
        self.root.overrideredirect(True)
        self._center_window(1100, 780)

        self.engine = ThemeEngine(initial="dark")
        self.state = AppState(root)
        self.state.preset_manager = PresetManager()
        self.state.telnet_client = TelnetClient()
        self.state.serial_client = SerialClient()
        self.ctrl = AppController(self.state, self.engine)

        self._setup_logging()
        self._build_ui()

        self.ctrl._refresh_adapters = self._refresh_adapters
        self.ctrl._refresh_fw_info = self._tabs["info"]._refresh_fw_info
        self.ctrl._update_status_bar = self._set_status

        self.root.after(100, self._refresh_adapters)
        self._set_app_icon()

        self.root.bind("<F5>", lambda e: self._refresh_adapters())
        self.root.bind("<Control-o>", lambda e: self._tabs["upgrade"]._browse_firmware())
        self.root.bind("<<AppClose>>", lambda e: self._on_close())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _center_window(self, w: int, h: int):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _setup_logging(self):
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s [%(name)s] %(message)s", datefmt="%H:%M:%S")
        handler.setFormatter(formatter)
        if not logger.handlers:
            logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    def _set_app_icon(self):
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

    def _refresh_adapters(self):
        refresh_adapters_async(self.state, self.ctrl)

    def _build_ui(self):
        colors = self.engine.colors
        self.root.configure(bg=colors["bg"])

        self.style = ttk.Style()
        self._apply_ttkb_theme()

        self._titlebar = CustomTitlebar(
            self.root,
            self.root,
            title=f"{APP_NAME} v{__version__}",
            theme=colors,
            engine=self.engine,
        )
        self._titlebar.pack(fill=tk.X)
        self.engine.register(self._titlebar, updater=self._titlebar.update_theme)

        self._accent_bar = GradientBar(self.root, height=2, color_start="#2563EB", color_end="#06B6D4")
        self._accent_bar.pack(fill=tk.X)

        main_container = tk.Frame(self.root, bg=colors["bg"])
        main_container.pack(fill=tk.BOTH, expand=True)
        self.engine.register(main_container, {"bg": "bg"})

        self._sidebar = SidebarNav(main_container, theme=colors, on_select=self._on_nav_select, engine=self.engine)
        self._sidebar.pack(side=tk.LEFT, fill=tk.Y)

        sep = tk.Frame(main_container, bg=colors["border"], width=1)
        sep.pack(side=tk.LEFT, fill=tk.Y)
        self.engine.register(sep, {"bg": "border"})

        self._build_sidebar_content(colors)

        self._content_area = tk.Frame(main_container, bg=colors["bg"])
        self._content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.engine.register(self._content_area, {"bg": "bg"})

        self._build_content_header(colors)

        self.notebook = ttk.Notebook(self._content_area)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(6, 10))
        self.style.layout("TNotebook.Tab", [])

        self._tabs: dict[str, ttk.Frame] = {}
        self._create_tabs()
        self._sidebar.select(0)

        self._build_status_bar(colors)

    def _build_sidebar_content(self, colors: dict):
        def build_header(parent):
            logo_frame = tk.Frame(parent, bg=colors["sidebar"])
            logo_frame.pack(fill=tk.X, pady=(0, 8))
            try:
                logo_data = generate_logo(40)
                if logo_data:
                    from PIL import Image, ImageTk
                    import io

                    img = Image.open(io.BytesIO(logo_data))
                    self._sidebar_logo = ImageTk.PhotoImage(img)
                    tk.Label(logo_frame, image=self._sidebar_logo, bg=colors["sidebar"]).pack(side=tk.LEFT, padx=(0, 8))
            except Exception:
                pass

            title_frame = tk.Frame(logo_frame, bg=colors["sidebar"])
            title_frame.pack(side=tk.LEFT, fill=tk.X)
            tk.Label(
                title_frame,
                text=APP_NAME,
                font=(FONT_FAMILY, 13, "bold"),
                bg=colors["sidebar"],
                fg=colors["fg"],
            ).pack(anchor="w")
            tk.Label(
                title_frame,
                text=f"v{__version__}",
                font=(FONT_FAMILY, 8),
                bg=colors["sidebar"],
                fg=colors["fg_muted"],
            ).pack(anchor="w")

        self._sidebar.set_header(build_header)

        self._sidebar.add_section_label("Main")
        self._sidebar.add_item("Upgrade", NAV_ICONS["upgrade"], "upgrade")
        self._sidebar.add_item("Presets", NAV_ICONS["presets"], "presets")
        self._sidebar.add_item("Verify", NAV_ICONS["verify"], "verify")
        self._sidebar.add_separator()
        self._sidebar.add_section_label("Tools")
        self._sidebar.add_item("Crypto", NAV_ICONS["crypto"], "crypto")
        self._sidebar.add_item("Terminal", NAV_ICONS["terminal"], "terminal")
        self._sidebar.add_item("Dump", NAV_ICONS["dump"], "dump")
        self._sidebar.add_separator()
        self._sidebar.add_section_label("Config")
        self._sidebar.add_item("Settings", NAV_ICONS["settings"], "settings")
        self._sidebar.add_item("Info", NAV_ICONS["info"], "info")
        self._sidebar.add_item("Log", NAV_ICONS["log"], "log")

        def build_footer(parent):
            self.theme_btn = tk.Button(
                parent,
                text="Light mode",
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
            self.engine.register(
                self.theme_btn,
                {
                    "bg": "bg_card",
                    "fg": "fg_secondary",
                    "activebackground": "bg_hover",
                    "activeforeground": "fg",
                },
            )

        self._sidebar.set_footer(build_footer)

    def _build_content_header(self, colors: dict):
        self._content_header = tk.Frame(self._content_area, bg=colors["bg"], height=44)
        self._content_header.pack(fill=tk.X, padx=16, pady=(10, 4))
        self._content_header.pack_propagate(False)
        self.engine.register(self._content_header, {"bg": "bg"})

        self._page_title = tk.Label(
            self._content_header,
            text="Firmware Upgrade",
            font=(FONT_FAMILY, 14, "bold"),
            bg=colors["bg"],
            fg=colors["fg"],
            anchor="w",
        )
        self._page_title.pack(side=tk.LEFT, fill=tk.X)
        self.engine.register(self._page_title, {"bg": "bg", "fg": "fg"})

        self._page_subtitle = tk.Label(
            self._content_header,
            text="Flash firmware to your Huawei ONT device",
            font=(FONT_FAMILY, 9),
            bg=colors["bg"],
            fg=colors["fg_muted"],
            anchor="e",
        )
        self._page_subtitle.pack(side=tk.RIGHT)
        self.engine.register(self._page_subtitle, {"bg": "bg", "fg": "fg_muted"})

        header_sep = tk.Frame(self._content_area, bg=colors["border"], height=1)
        header_sep.pack(fill=tk.X, padx=16)
        self.engine.register(header_sep, {"bg": "border"})

    def _create_tabs(self):
        tabs = [
            ("upgrade", UpgradeTab, "Upgrade"),
            ("presets", PresetsTab, "Presets"),
            ("verify", VerifyTab, "Verify"),
            ("crypto", CryptoTab, "Crypto"),
            ("terminal", TerminalTab, "Terminal"),
            ("dump", DumpTab, "Dump"),
            ("settings", SettingsTab, "Settings"),
            ("info", InfoTab, "Info"),
            ("log", LogTab, "Log"),
        ]

        for tag, cls, label in tabs:
            tab = cls(self.notebook, self.state, self.ctrl, self.engine)
            self.notebook.add(tab, text=label)
            self._tabs[tag] = tab

    def _build_status_bar(self, colors: dict):
        status_frame = tk.Frame(self.root, bg=colors["bg_secondary"], height=28)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        self.engine.register(status_frame, {"bg": "bg_secondary"})

        GradientBar(status_frame, height=1, color_start="#2563EB", color_end="#06B6D4").pack(fill=tk.X, side=tk.TOP)

        self._status_label = tk.Label(
            status_frame,
            text="Ready",
            font=(FONT_FAMILY, 8),
            bg=colors["bg_secondary"],
            fg=colors["fg_muted"],
            anchor="w",
            padx=12,
        )
        self._status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.engine.register(self._status_label, {"bg": "bg_secondary", "fg": "fg_muted"})

        self._adapter_label = tk.Label(
            status_frame,
            text="No adapter selected",
            font=(FONT_FAMILY, 8),
            bg=colors["bg_secondary"],
            fg=colors["fg_muted"],
            anchor="e",
            padx=12,
        )
        self._adapter_label.pack(side=tk.RIGHT)
        self.engine.register(self._adapter_label, {"bg": "bg_secondary", "fg": "fg_muted"})

    def _set_status(self, text: str):
        try:
            self._status_label.configure(text=text)
        except (tk.TclError, AttributeError):
            pass

    def _apply_ttkb_theme(self):
        if HAS_TTKB:
            try:
                ttkb.Style().theme_use(self.engine.ttkb_theme)
            except Exception:
                pass

        colors = self.engine.colors
        self.style.configure(".", font=(FONT_FAMILY, 10))
        self.style.configure("TFrame", background=colors["bg"])
        self.style.configure("TLabel", background=colors["bg"], foreground=colors["fg"])
        self.style.configure("TLabelframe", background=colors["bg_card"], bordercolor=colors["border"], relief="solid")
        self.style.configure(
            "TLabelframe.Label",
            background=colors["bg_card"],
            foreground=colors["fg"],
            font=(FONT_FAMILY, 10, "bold"),
        )
        self.style.configure("TButton", font=(FONT_FAMILY, 9), padding=(10, 6))
        self.style.configure("TEntry", fieldbackground=colors["bg_input"], foreground=colors["fg"], insertcolor=colors["fg"], padding=6)
        self.style.configure("TCombobox", fieldbackground=colors["bg_input"], foreground=colors["fg"], padding=4)
        self.style.configure("TCheckbutton", background=colors["bg_card"], foreground=colors["fg_secondary"])
        self.style.configure("TRadiobutton", background=colors["bg_card"], foreground=colors["fg_secondary"])
        self.style.configure("Treeview", rowheight=24, fieldbackground=colors["bg_input"], background=colors["bg_input"], foreground=colors["fg"])
        self.style.configure("Treeview.Heading", background=colors["bg_secondary"], foreground=colors["fg"], font=(FONT_FAMILY, 9, "bold"))
        self.style.map("Treeview", background=[("selected", colors["bg_selected"])], foreground=[("selected", colors["fg"])])

    def _toggle_theme(self):
        self.engine.toggle()
        self._apply_ttkb_theme()
        colors = self.engine.colors
        self.root.configure(bg=colors["bg"])
        next_label = "Light mode" if self.engine.is_dark else "Dark mode"
        self.theme_btn.configure(text=next_label)

    def _on_nav_select(self, index: int, tag: str):
        tab_idx = self._TAB_MAP.get(tag, 0)
        self.notebook.select(tab_idx)
        title, subtitle = self._PAGE_INFO.get(tag, ("", ""))
        colors = self.engine.colors
        self._page_title.configure(text=title, fg=colors["fg"])
        self._page_subtitle.configure(text=subtitle, fg=colors["fg_muted"])

    def _on_close(self):
        s = self.state

        if s.worker and s.worker.is_running:
            if not messagebox.askyesno("Confirm Exit", "An upgrade is in progress. Exit anyway?"):
                return
            s.worker.stop()

        if s.telnet_client and s.telnet_client.connected:
            s.telnet_client.disconnect()
        if s.serial_client and s.serial_client.connected:
            s.serial_client.disconnect()
        if s.transport:
            s.transport.close()

        self.root.destroy()


def main():
    """Application entry point."""
    try:
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError, OSError):
        pass

    root = tk.Tk()

    if HAS_TTKB:
        try:
            ttkb.Style(themename=TTKB_DARK, master=root)
        except Exception as exc:
            logger.debug("ttkbootstrap style init failed: %s", exc)

    HuaweiFlashApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
