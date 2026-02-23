"""
Main application window for ONT Broadcast Tool.

Built with customtkinter for a modern Windows 11 look with dark/light mode.
Replicates the functionality of the original OBSCTool (ONT_V100R002C00SPC253.exe)
and adds many new configuration options.
"""

import os
import sys
import logging
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
from typing import Optional, List

try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
except ImportError:
    # Fallback to plain tkinter if customtkinter not installed
    import tkinter as ctk
    ctk.set_appearance_mode = lambda *a: None
    ctk.set_default_color_theme = lambda *a: None
    ctk.CTk = tk.Tk
    ctk.CTkFrame = tk.Frame
    ctk.CTkLabel = tk.Label
    ctk.CTkButton = tk.Button
    ctk.CTkEntry = tk.Entry
    ctk.CTkComboBox = tk.OptionMenu
    ctk.CTkTextbox = scrolledtext.ScrolledText
    ctk.CTkRadioButton = tk.Radiobutton
    ctk.CTkCheckBox = tk.Checkbutton
    ctk.CTkSlider = tk.Scale
    ctk.CTkOptionMenu = tk.OptionMenu
    ctk.CTkScrollableFrame = tk.Frame
    ctk.CTkTabview = tk.Frame
    try:
        from tkinter import ttk as _ttk
        ctk.CTkProgressBar = _ttk.Progressbar
    except ImportError:
        ctk.CTkProgressBar = tk.Frame
    CTK_AVAILABLE = False

# Import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.hwnp import HWNPPackage, load_hwnp_file, describe_package
from src.broadcaster import BroadcastEngine, DeviceSession, DeviceStatus
from src.network import NetworkInterface, get_interfaces
from src.config import AppSettings, load_settings, save_settings

logger = logging.getLogger(__name__)

APP_TITLE   = "ONT Broadcast Tool"
APP_VERSION = "1.0.0"

# Built-in firmware package labels (matching original OBSCTool)
BUILTIN_PACKAGES = [
    "Package 1 — Most V3 firmware devices",
    "Package 2 — Most V5 firmware devices",
    "Package 3 — Newer devices (partial support)",
]


class SettingsDialog(ctk.CTkToplevel):
    """Settings / preferences dialog."""

    def __init__(self, parent, settings: AppSettings):
        super().__init__(parent)
        self.title("Settings")
        self.geometry("480x560")
        self.resizable(False, False)
        self.grab_set()

        self._settings = settings
        self._saved = False

        self._build_ui()

    def _build_ui(self):
        pad = dict(padx=16, pady=8)

        # Network settings
        net_frame = ctk.CTkFrame(self)
        net_frame.pack(fill='x', **pad)
        ctk.CTkLabel(net_frame, text="Network", font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        self._port_var = tk.StringVar(value=str(self._settings.udp_port))
        self._bcast_var = tk.StringVar(value=self._settings.broadcast_address)

        row = ctk.CTkFrame(net_frame, fg_color='transparent')
        row.pack(fill='x', padx=8, pady=4)
        ctk.CTkLabel(row, text="UDP Port:", width=160).pack(side='left')
        ctk.CTkEntry(row, textvariable=self._port_var, width=120).pack(side='left', padx=4)

        row2 = ctk.CTkFrame(net_frame, fg_color='transparent')
        row2.pack(fill='x', padx=8, pady=4)
        ctk.CTkLabel(row2, text="Broadcast Address:", width=160).pack(side='left')
        ctk.CTkEntry(row2, textvariable=self._bcast_var, width=160).pack(side='left', padx=4)

        # Timing settings
        timing_frame = ctk.CTkFrame(self)
        timing_frame.pack(fill='x', **pad)
        ctk.CTkLabel(timing_frame, text="Timing", font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        self._interval_var = tk.StringVar(value=str(self._settings.packet_interval_ms))
        self._timeout_var  = tk.StringVar(value=str(self._settings.operation_timeout_s))
        self._retry_var    = tk.StringVar(value=str(self._settings.retry_count))
        self._chunk_var    = tk.StringVar(value=str(self._settings.chunk_size))

        for label, var, unit in [
            ("Packet Interval:", self._interval_var, "ms"),
            ("Operation Timeout:", self._timeout_var, "s"),
            ("Retry Count:", self._retry_var, ""),
            ("Chunk Size:", self._chunk_var, "bytes"),
        ]:
            row = ctk.CTkFrame(timing_frame, fg_color='transparent')
            row.pack(fill='x', padx=8, pady=4)
            ctk.CTkLabel(row, text=label, width=160).pack(side='left')
            ctk.CTkEntry(row, textvariable=var, width=100).pack(side='left', padx=4)
            if unit:
                ctk.CTkLabel(row, text=unit).pack(side='left')

        # Appearance settings
        app_frame = ctk.CTkFrame(self)
        app_frame.pack(fill='x', **pad)
        ctk.CTkLabel(app_frame, text="Appearance", font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        self._theme_var = tk.StringVar(value=self._settings.theme)
        row = ctk.CTkFrame(app_frame, fg_color='transparent')
        row.pack(fill='x', padx=8, pady=4)
        ctk.CTkLabel(row, text="Theme:", width=160).pack(side='left')
        if CTK_AVAILABLE:
            ctk.CTkOptionMenu(row, variable=self._theme_var,
                              values=['dark', 'light', 'system'],
                              width=120).pack(side='left', padx=4)

        # Advanced
        adv_frame = ctk.CTkFrame(self)
        adv_frame.pack(fill='x', **pad)
        ctk.CTkLabel(adv_frame, text="Advanced", font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        self._raw_mode_var  = tk.BooleanVar(value=self._settings.raw_send_mode)
        self._autolog_var   = tk.BooleanVar(value=self._settings.auto_save_log)
        self._discovery_var = tk.BooleanVar(value=self._settings.discovery_enabled)

        for text, var in [
            ("Raw send mode (skip handshake)", self._raw_mode_var),
            ("Auto-save log on stop",          self._autolog_var),
            ("Enable discovery broadcast",     self._discovery_var),
        ]:
            ctk.CTkCheckBox(adv_frame, text=text, variable=var).pack(anchor='w', padx=8, pady=4)

        # Buttons
        btn_row = ctk.CTkFrame(self, fg_color='transparent')
        btn_row.pack(fill='x', padx=16, pady=16)
        ctk.CTkButton(btn_row, text="Save", command=self._save, width=100).pack(side='right', padx=4)
        ctk.CTkButton(btn_row, text="Cancel", command=self.destroy, width=100,
                      fg_color='gray').pack(side='right', padx=4)

    def _save(self):
        try:
            self._settings.udp_port            = int(self._port_var.get())
            self._settings.broadcast_address   = self._bcast_var.get().strip()
            self._settings.packet_interval_ms  = int(self._interval_var.get())
            self._settings.operation_timeout_s = int(self._timeout_var.get())
            self._settings.retry_count         = int(self._retry_var.get())
            self._settings.chunk_size          = int(self._chunk_var.get())
            self._settings.theme               = self._theme_var.get()
            self._settings.raw_send_mode       = self._raw_mode_var.get()
            self._settings.auto_save_log       = self._autolog_var.get()
            self._settings.discovery_enabled   = self._discovery_var.get()
            self._saved = True
            self.destroy()
        except ValueError as e:
            messagebox.showerror("Invalid value", str(e), parent=self)

    @property
    def saved(self) -> bool:
        return self._saved


class FirmwareInfoDialog(ctk.CTkToplevel):
    """Shows detailed info about a loaded HWNP firmware package."""

    def __init__(self, parent, pkg: HWNPPackage, title: str = "Firmware Package Info"):
        super().__init__(parent)
        self.title(title)
        self.geometry("700x500")
        self.grab_set()

        text_box = ctk.CTkTextbox(self, font=('Consolas', 11))
        text_box.pack(fill='both', expand=True, padx=10, pady=10)
        text_box.insert('end', describe_package(pkg))
        text_box.configure(state='disabled')

        ctk.CTkButton(self, text="Close", command=self.destroy, width=100).pack(pady=8)


class MainWindow:
    """
    Main application window for ONT Broadcast Tool.

    Provides:
    - Network interface selection
    - Firmware package selection (built-in V3/V5/new + custom file)
    - Broadcast settings (port, interval, timeout, retries)
    - Device tracking and progress display
    - Operation log panel with export
    - Settings persistence
    """

    def __init__(self):
        self.settings = load_settings()
        self._apply_theme()

        self._root = ctk.CTk()
        self._root.title(f"{APP_TITLE} v{APP_VERSION}")
        self._root.geometry(
            f"{self.settings.window_width}x{self.settings.window_height}"
        )
        self._root.minsize(800, 600)
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

        # State
        self._interfaces: List[NetworkInterface] = []
        self._selected_iface: Optional[NetworkInterface] = None
        self._custom_firmware_path: Optional[str] = None
        self._custom_pkg: Optional[HWNPPackage]   = None
        self._engine: Optional[BroadcastEngine]   = None
        self._pkg_choice = tk.IntVar(value=0)   # 0=pkg1, 1=pkg2, 2=pkg3, 3=custom
        self._log_lines: List[str] = []

        self._build_ui()
        self._refresh_interfaces()
        self._update_controls()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        if CTK_AVAILABLE:
            theme = self.settings.theme
            ctk.set_appearance_mode(theme if theme != 'system' else 'system')
            ctk.set_default_color_theme("blue")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        root = self._root

        # ── Top bar ──────────────────────────────────────────────────
        top = ctk.CTkFrame(root, corner_radius=0)
        top.pack(fill='x', side='top')

        ctk.CTkLabel(top, text=f"  {APP_TITLE}",
                     font=('', 16, 'bold')).pack(side='left', padx=8, pady=8)

        # Theme toggle (right side)
        self._theme_btn = ctk.CTkButton(
            top, text="🌙", width=40, command=self._toggle_theme
        )
        self._theme_btn.pack(side='right', padx=4, pady=4)

        ctk.CTkButton(top, text="⚙ Settings", width=110,
                      command=self._open_settings).pack(side='right', padx=4, pady=4)
        ctk.CTkButton(top, text="? About", width=90,
                      command=self._show_about).pack(side='right', padx=4, pady=4)

        # ── Network interface row ─────────────────────────────────────
        net_row = ctk.CTkFrame(root, fg_color='transparent')
        net_row.pack(fill='x', padx=12, pady=(8, 0))

        ctk.CTkLabel(net_row, text="Network Interface:", width=140).pack(side='left')
        self._iface_cb = ctk.CTkComboBox(
            net_row, width=320, command=self._on_iface_select,
            state='readonly'
        )
        self._iface_cb.pack(side='left', padx=6)
        ctk.CTkButton(net_row, text="⟳ Refresh", width=90,
                      command=self._refresh_interfaces).pack(side='left', padx=4)

        self._status_lbl = ctk.CTkLabel(net_row, text="● Ready",
                                        text_color='green')
        self._status_lbl.pack(side='left', padx=12)

        # ── Main content (left + right) ───────────────────────────────
        content = ctk.CTkFrame(root, fg_color='transparent')
        content.pack(fill='both', expand=True, padx=12, pady=8)

        # Left panel: firmware selection + settings
        left = ctk.CTkFrame(content)
        left.pack(side='left', fill='both', expand=False, padx=(0, 6))
        left.configure(width=340)

        self._build_firmware_panel(left)
        self._build_quick_settings_panel(left)

        # Right panel: device list
        right = ctk.CTkFrame(content)
        right.pack(side='left', fill='both', expand=True)

        self._build_device_panel(right)

        # ── Log panel ─────────────────────────────────────────────────
        log_frame = ctk.CTkFrame(root)
        log_frame.pack(fill='both', expand=True, padx=12, pady=(0, 4))

        log_header = ctk.CTkFrame(log_frame, fg_color='transparent')
        log_header.pack(fill='x', padx=4, pady=(4, 0))
        ctk.CTkLabel(log_header, text="Operation Log",
                     font=('', 12, 'bold')).pack(side='left', padx=4)
        ctk.CTkButton(log_header, text="Clear", width=70,
                      command=self._clear_log).pack(side='right', padx=4)
        ctk.CTkButton(log_header, text="Export…", width=80,
                      command=self._export_log).pack(side='right', padx=4)

        self._log_box = ctk.CTkTextbox(log_frame, height=150,
                                       font=('Consolas', 11))
        self._log_box.pack(fill='both', expand=True, padx=4, pady=4)

        # ── Bottom action bar ─────────────────────────────────────────
        btn_bar = ctk.CTkFrame(root, corner_radius=0)
        btn_bar.pack(fill='x', side='bottom')

        self._start_btn = ctk.CTkButton(
            btn_bar, text="▶  Start", width=130, height=40,
            font=('', 13, 'bold'), fg_color='green', hover_color='#1a7a1a',
            command=self._start_broadcast
        )
        self._start_btn.pack(side='left', padx=12, pady=8)

        self._stop_btn = ctk.CTkButton(
            btn_bar, text="■  Stop", width=130, height=40,
            font=('', 13, 'bold'), fg_color='red', hover_color='#7a1a1a',
            command=self._stop_broadcast, state='disabled'
        )
        self._stop_btn.pack(side='left', padx=4, pady=8)

        self._inspect_btn = ctk.CTkButton(
            btn_bar, text="🔍 Inspect Package", width=160,
            command=self._inspect_package
        )
        self._inspect_btn.pack(side='left', padx=16, pady=8)

        # Progress bar
        self._progress = ctk.CTkProgressBar(btn_bar, width=200)
        self._progress.pack(side='right', padx=12, pady=12)
        self._progress.set(0)

        self._progress_lbl = ctk.CTkLabel(btn_bar, text="0%", width=40)
        self._progress_lbl.pack(side='right', padx=4)

    def _build_firmware_panel(self, parent):
        frame = ctk.CTkFrame(parent)
        frame.pack(fill='x', padx=8, pady=8)

        ctk.CTkLabel(frame, text="Firmware Package",
                     font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        for i, label in enumerate(BUILTIN_PACKAGES):
            ctk.CTkRadioButton(
                frame,
                text=label,
                variable=self._pkg_choice,
                value=i,
                command=self._on_pkg_choice
            ).pack(anchor='w', padx=16, pady=3)

        # Custom file option
        ctk.CTkRadioButton(
            frame,
            text="Custom firmware file…",
            variable=self._pkg_choice,
            value=3,
            command=self._on_pkg_choice
        ).pack(anchor='w', padx=16, pady=3)

        # Custom file path row
        cust_row = ctk.CTkFrame(frame, fg_color='transparent')
        cust_row.pack(fill='x', padx=8, pady=(0, 8))

        self._custom_path_var = tk.StringVar(value='')
        self._custom_entry = ctk.CTkEntry(
            cust_row, textvariable=self._custom_path_var,
            placeholder_text="Select .bin firmware file…",
            state='disabled', width=200
        )
        self._custom_entry.pack(side='left', padx=(8, 4), fill='x', expand=True)

        self._browse_btn = ctk.CTkButton(
            cust_row, text="Browse…", width=80,
            command=self._browse_firmware, state='disabled'
        )
        self._browse_btn.pack(side='right', padx=4)

        # Package info label
        self._pkg_info_lbl = ctk.CTkLabel(
            frame, text="Built-in package (V3 devices)",
            text_color='gray', wraplength=280
        )
        self._pkg_info_lbl.pack(anchor='w', padx=12, pady=(0, 8))

    def _build_quick_settings_panel(self, parent):
        frame = ctk.CTkFrame(parent)
        frame.pack(fill='x', padx=8, pady=8)

        ctk.CTkLabel(frame, text="Quick Settings",
                     font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        self._port_var      = tk.StringVar(value=str(self.settings.udp_port))
        self._interval_var  = tk.StringVar(value=str(self.settings.packet_interval_ms))
        self._timeout_var   = tk.StringVar(value=str(self.settings.operation_timeout_s))
        self._retries_var   = tk.StringVar(value=str(self.settings.retry_count))

        for label, var, unit, tip in [
            ("UDP Port:", self._port_var, "", "1400 (default)"),
            ("Packet Interval:", self._interval_var, "ms", "5 ms (default)"),
            ("Operation Timeout:", self._timeout_var, "s", "60 s"),
            ("Retry Count:", self._retries_var, "", "3"),
        ]:
            row = ctk.CTkFrame(frame, fg_color='transparent')
            row.pack(fill='x', padx=8, pady=4)
            ctk.CTkLabel(row, text=label, width=140).pack(side='left')
            ctk.CTkEntry(row, textvariable=var, width=80,
                         placeholder_text=tip).pack(side='left', padx=4)
            if unit:
                ctk.CTkLabel(row, text=unit).pack(side='left')

        ctk.CTkLabel(frame, text="Tip: Original tool uses 1400 port, 5 ms interval",
                     text_color='gray', font=('', 10),
                     wraplength=300).pack(anchor='w', padx=8, pady=(0, 8))

    def _build_device_panel(self, parent):
        ctk.CTkLabel(parent, text="Active Devices / Sessions",
                     font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        # Header row
        hdr = ctk.CTkFrame(parent)
        hdr.pack(fill='x', padx=4)
        for col, w in [("ONT Serial", 160), ("Status", 100), ("Progress", 120), ("Duration", 80)]:
            ctk.CTkLabel(hdr, text=col, width=w,
                         font=('', 11, 'bold')).pack(side='left', padx=4)

        # Scrollable device list
        self._device_frame = ctk.CTkScrollableFrame(parent, height=220)
        self._device_frame.pack(fill='both', expand=True, padx=4, pady=4)

        self._device_rows: dict = {}

    # ------------------------------------------------------------------
    # Interface helpers
    # ------------------------------------------------------------------

    def _refresh_interfaces(self):
        self._interfaces = get_interfaces()
        names = [str(i) for i in self._interfaces]
        self._iface_cb.configure(values=names)
        if names:
            self._iface_cb.set(names[0])
            self._selected_iface = self._interfaces[0]
        else:
            self._iface_cb.set('No interfaces found')

    def _on_iface_select(self, choice: str):
        for iface in self._interfaces:
            if str(iface) == choice:
                self._selected_iface = iface
                self._log(f"Interface: {iface} → broadcast {iface.broadcast}")
                break

    def _get_broadcast_addr(self) -> str:
        if self._selected_iface:
            return self._selected_iface.broadcast
        return self.settings.broadcast_address

    # ------------------------------------------------------------------
    # Firmware selection helpers
    # ------------------------------------------------------------------

    def _on_pkg_choice(self):
        choice = self._pkg_choice.get()
        is_custom = (choice == 3)
        state = 'normal' if is_custom else 'disabled'
        self._custom_entry.configure(state=state)
        self._browse_btn.configure(state=state)

        labels = [
            "Built-in HWNP package for most V3 firmware devices",
            "Built-in HWNP package for most V5 firmware devices",
            "Built-in HWNP package for newer devices (partial)",
            "Custom firmware file (must be a valid .bin / HWNP file)",
        ]
        self._pkg_info_lbl.configure(text=labels[choice])
        self._update_controls()

    def _browse_firmware(self):
        path = filedialog.askopenfilename(
            title="Select HWNP firmware file",
            initialdir=self.settings.last_firmware_dir or os.path.expanduser('~'),
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            pkg = load_hwnp_file(path)
            self._custom_pkg = pkg
            self._custom_firmware_path = path
            self._custom_path_var.set(os.path.basename(path))
            self.settings.last_firmware_dir  = os.path.dirname(path)
            self.settings.last_firmware_path = path
            self._log(f"Loaded: {os.path.basename(path)} "
                      f"({pkg.size_kb:.1f} KB, {pkg.item_counts} items)")
            self._pkg_info_lbl.configure(
                text=f"{pkg.size_kb:.1f} KB · {pkg.item_counts} items"
                     f" · products: {pkg.product_list[:30] or 'all'}"
            )
        except Exception as e:
            messagebox.showerror("Load Error",
                                 f"Could not load firmware:\n{e}", parent=self._root)

    def _inspect_package(self):
        pkg = self._get_selected_package()
        if pkg is None:
            messagebox.showinfo("No package",
                                "Select or load an HWNP firmware file first.",
                                parent=self._root)
            return
        FirmwareInfoDialog(self._root, pkg)

    def _get_selected_package(self) -> Optional[HWNPPackage]:
        """Return the currently selected HWNPPackage, or None for built-ins."""
        choice = self._pkg_choice.get()
        if choice == 3:
            return self._custom_pkg
        # Built-in packages: return None (they are embedded in the original exe)
        # In this open-source version, they must be provided as external files.
        # Here we return None to signal "built-in" – callers handle this.
        return None

    def _get_firmware_for_broadcast(self) -> Optional[HWNPPackage]:
        """
        Return the HWNPPackage to broadcast.
        For built-in slots, the user should place the corresponding .bin files
        in the same directory as the tool (e.g. pkg1.bin, pkg2.bin, pkg3.bin).
        """
        choice = self._pkg_choice.get()
        if choice == 3:
            if not self._custom_pkg:
                messagebox.showwarning("No file",
                                       "Please browse and select a firmware file.",
                                       parent=self._root)
                return None
            return self._custom_pkg

        # Try to auto-load built-in package from files
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        pkg_filename = f"pkg{choice + 1}.bin"
        pkg_path = os.path.join(base_dir, pkg_filename)

        if not os.path.isfile(pkg_path):
            # Ask user to locate the file
            answer = messagebox.askyesno(
                "Package file not found",
                f"Built-in firmware file '{pkg_filename}' not found.\n\n"
                f"Package {choice+1} corresponds to:\n"
                f"{BUILTIN_PACKAGES[choice]}\n\n"
                f"Would you like to browse for the firmware file?\n"
                f"(Place it as '{pkg_filename}' to avoid this message.)",
                parent=self._root
            )
            if not answer:
                return None
            pkg_path = filedialog.askopenfilename(
                title=f"Select firmware for Package {choice+1}",
                filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")]
            )
            if not pkg_path:
                return None

        try:
            pkg = load_hwnp_file(pkg_path)
            self._log(f"Using: {os.path.basename(pkg_path)} "
                      f"({pkg.size_kb:.1f} KB)")
            return pkg
        except Exception as e:
            messagebox.showerror("Load Error", str(e), parent=self._root)
            return None

    # ------------------------------------------------------------------
    # Broadcast control
    # ------------------------------------------------------------------

    def _read_quick_settings(self):
        """Sync quick-settings panel values back to settings object."""
        try:
            self.settings.udp_port           = int(self._port_var.get())
        except ValueError:
            pass
        try:
            self.settings.packet_interval_ms = int(self._interval_var.get())
        except ValueError:
            pass
        try:
            self.settings.operation_timeout_s = int(self._timeout_var.get())
        except ValueError:
            pass
        try:
            self.settings.retry_count = int(self._retries_var.get())
        except ValueError:
            pass

    def _start_broadcast(self):
        self._read_quick_settings()
        pkg = self._get_firmware_for_broadcast()
        if pkg is None:
            return

        bcast = self._get_broadcast_addr()
        iface_ip = self._selected_iface.ip if self._selected_iface else ''

        self._engine = BroadcastEngine(
            broadcast_addr=bcast,
            port=self.settings.udp_port,
            interface_ip=iface_ip,
            packet_interval_ms=self.settings.packet_interval_ms,
            operation_timeout_s=self.settings.operation_timeout_s,
            retry_count=self.settings.retry_count,
            chunk_size=self.settings.chunk_size,
        )
        self._engine.on_log    = self._on_engine_log
        self._engine.on_device = self._on_engine_device
        self._engine.on_status = self._on_engine_status

        self._progress.set(0)
        self._progress_lbl.configure(text="0%")
        self._set_running(True)
        self._engine.start(pkg)

    def _stop_broadcast(self):
        if self._engine:
            self._engine.stop()
        self._set_running(False)

    def _set_running(self, running: bool):
        if running:
            self._start_btn.configure(state='disabled')
            self._stop_btn.configure(state='normal')
            self._status_lbl.configure(text="● Broadcasting…", text_color='orange')
        else:
            self._start_btn.configure(state='normal')
            self._stop_btn.configure(state='disabled')
            self._status_lbl.configure(text="● Ready", text_color='green')
            self._progress.set(0)
            self._progress_lbl.configure(text="0%")

    # ------------------------------------------------------------------
    # Engine callbacks (called from worker thread → schedule to main thread)
    # ------------------------------------------------------------------

    def _on_engine_log(self, msg: str):
        self._root.after(0, self._append_log, msg)

    def _on_engine_status(self, msg: str):
        self._root.after(0, self._status_lbl.configure,
                         {'text': f'● {msg}'})

    def _on_engine_device(self, session: DeviceSession):
        self._root.after(0, self._update_device_row, session)
        if session.total_bytes > 0:
            pct = session.bytes_sent / session.total_bytes
            self._root.after(0, self._progress.set, pct)
            self._root.after(0, self._progress_lbl.configure,
                             {'text': f'{int(pct*100)}%'})
        if session.status in (DeviceStatus.SUCCESS, DeviceStatus.FAILED):
            self._root.after(0, self._set_running, False)

    def _update_device_row(self, session: DeviceSession):
        key = session.ont_sn
        if key not in self._device_rows:
            row = ctk.CTkFrame(self._device_frame)
            row.pack(fill='x', pady=2)
            sn_lbl   = ctk.CTkLabel(row, text=session.ont_sn, width=160)
            st_lbl   = ctk.CTkLabel(row, text="—", width=100)
            prog_bar = ctk.CTkProgressBar(row, width=120)
            prog_bar.set(0)
            dur_lbl  = ctk.CTkLabel(row, text="—", width=80)
            sn_lbl.pack(side='left', padx=4)
            st_lbl.pack(side='left', padx=4)
            prog_bar.pack(side='left', padx=4)
            dur_lbl.pack(side='left', padx=4)
            self._device_rows[key] = (st_lbl, prog_bar, dur_lbl)

        st_lbl, prog_bar, dur_lbl = self._device_rows[key]
        status_map = {
            DeviceStatus.DISCOVERED: ("Discovered", 'blue'),
            DeviceStatus.UPGRADING:  ("Upgrading…", 'orange'),
            DeviceStatus.SUCCESS:    ("✓ Done",     'green'),
            DeviceStatus.FAILED:     ("✗ Failed",   'red'),
            DeviceStatus.TIMEOUT:    ("Timeout",    'red'),
        }
        text, color = status_map.get(session.status, ("—", 'gray'))
        st_lbl.configure(text=text, text_color=color)
        if session.total_bytes > 0:
            prog_bar.set(session.bytes_sent / session.total_bytes)
        if session.end_time and session.start_time:
            dur_lbl.configure(text=f"{session.duration_s:.1f}s")

    # ------------------------------------------------------------------
    # Log helpers
    # ------------------------------------------------------------------

    def _append_log(self, msg: str):
        self._log_lines.append(msg)
        self._log_box.configure(state='normal')
        self._log_box.insert('end', msg + '\n')
        self._log_box.configure(state='disabled')
        self._log_box.see('end')

    def _log(self, msg: str):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._append_log(f"{ts} {msg}")

    def _clear_log(self):
        self._log_lines.clear()
        self._log_box.configure(state='normal')
        self._log_box.delete('1.0', 'end')
        self._log_box.configure(state='disabled')

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            title="Export log",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
            initialfile=f"ONT_LOG_{datetime.now().strftime('%Y-%m-%d_%H')}.log"
        )
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self._log_lines))
            self._log(f"Log exported: {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e), parent=self._root)

    # ------------------------------------------------------------------
    # Settings dialog
    # ------------------------------------------------------------------

    def _open_settings(self):
        dlg = SettingsDialog(self._root, self.settings)
        self._root.wait_window(dlg)
        if dlg.saved:
            save_settings(self.settings)
            self._apply_theme()
            # Sync quick-settings panel
            self._port_var.set(str(self.settings.udp_port))
            self._interval_var.set(str(self.settings.packet_interval_ms))
            self._timeout_var.set(str(self.settings.operation_timeout_s))
            self._retries_var.set(str(self.settings.retry_count))
            self._log("Settings saved")

    def _toggle_theme(self):
        if CTK_AVAILABLE:
            current = ctk.get_appearance_mode().lower()
            new = 'light' if current == 'dark' else 'dark'
            ctk.set_appearance_mode(new)
            self.settings.theme = new
            self._theme_btn.configure(text='☀' if new == 'light' else '🌙')

    # ------------------------------------------------------------------
    # About dialog
    # ------------------------------------------------------------------

    def _show_about(self):
        text = (
            f"{APP_TITLE} v{APP_VERSION}\n\n"
            "Open-source reimplementation of OBSCTool\n"
            "(Huawei ONT Broadband Service Console Tool)\n\n"
            "Broadcasts HWNP firmware packages to Huawei\n"
            "ONT devices over UDP for upgrade and unlock.\n\n"
            "Based on analysis of ONT_V100R002C00SPC253.exe\n"
            "and DESBLOQUEIO.R22.HG8145V5.E.HG8145V5V2.rar\n\n"
            "HWNP format: huawei_header.h (this repository)\n\n"
            "Protocol: UDP broadcast → ONT upgrade daemon\n"
            "Default port: 1400 | Interval: 5 ms"
        )
        messagebox.showinfo(f"About {APP_TITLE}", text, parent=self._root)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _update_controls(self):
        """Enable/disable controls based on current state."""
        pass

    def _on_close(self):
        if self._engine and self._engine.is_running:
            if not messagebox.askyesno(
                "Exit", "Broadcast is running. Stop and exit?",
                parent=self._root
            ):
                return
            self._engine.stop()

        # Save window size
        try:
            self.settings.window_width  = self._root.winfo_width()
            self.settings.window_height = self._root.winfo_height()
        except Exception:
            pass

        if self.settings.auto_save_log and self._log_lines:
            self._auto_save_log()

        save_settings(self.settings)
        self._root.destroy()

    def _auto_save_log(self):
        """Auto-save log to configured log directory."""
        try:
            log_dir = self.settings.log_dir or os.path.dirname(
                os.path.dirname(os.path.dirname(__file__)))
            os.makedirs(log_dir, exist_ok=True)
            fname = f"ONT_LOG_{datetime.now().strftime('%Y-%m-%d_%H')}.log"
            path = os.path.join(log_dir, fname)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self._log_lines))
        except Exception as e:
            logger.warning("Auto-save log failed: %s", e)

    def run(self):
        """Start the application main loop."""
        self._root.mainloop()
