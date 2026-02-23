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

"""
Main application window for ONT Broadcast Tool.

Built with customtkinter for a modern Windows 11 look with dark/light mode.
Replicates the functionality of the original OBSCTool (ONT_V100R002C00SPC253.exe)
and adds many new configuration options including:
  - Router preset manager (create/edit/delete/duplicate)
  - Signature verification settings
  - Dry-run mode
  - Repeat broadcast, inter-repeat delay
  - Configurable socket TTL, send buffer
  - Extended log settings
"""

import os
import sys
import ast
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
from src.hwnp import HWNPPackage, load_hwnp_file, describe_package, verify_package
from src.broadcaster import BroadcastEngine, DeviceSession, DeviceStatus
from src.network import NetworkInterface, get_interfaces
from src.config import (
    AppSettings, load_settings, save_settings,
    RouterPreset, load_presets, save_presets,
    get_all_presets, duplicate_preset, BUILTIN_PRESETS,
)

logger = logging.getLogger(__name__)

APP_TITLE   = "ONT Broadcast Tool"
APP_VERSION = "1.1.0"

# Built-in firmware package labels (matching original OBSCTool)
BUILTIN_PACKAGES = [
    "Package 1 — Most V3 firmware devices",
    "Package 2 — Most V5 firmware devices",
    "Package 3 — Newer devices (partial support)",
]


# ===========================================================================
# Helper: uniform row builder
# ===========================================================================

def _labeled_entry(parent, label: str, var: tk.Variable, unit: str = '',
                   width: int = 100, label_width: int = 180) -> ctk.CTkEntry:
    row = ctk.CTkFrame(parent, fg_color='transparent')
    row.pack(fill='x', padx=8, pady=3)
    ctk.CTkLabel(row, text=label, width=label_width).pack(side='left')
    e = ctk.CTkEntry(row, textvariable=var, width=width)
    e.pack(side='left', padx=4)
    if unit:
        ctk.CTkLabel(row, text=unit).pack(side='left')
    return e


def _labeled_checkbox(parent, label: str, var: tk.BooleanVar) -> ctk.CTkCheckBox:
    cb = ctk.CTkCheckBox(parent, text=label, variable=var)
    cb.pack(anchor='w', padx=12, pady=3)
    return cb


# ===========================================================================
# PresetsDialog
# ===========================================================================

class PresetsDialog(ctk.CTkToplevel):
    """
    Router Preset Manager — create, edit, duplicate and delete presets.
    Built-in presets are shown read-only; user presets are fully editable.
    """

    def __init__(self, parent, user_presets: List[RouterPreset]):
        super().__init__(parent)
        self.title("Router Preset Manager")
        self.geometry("860x620")
        self.minsize(760, 500)
        self.grab_set()

        from dataclasses import replace
        # Work on copies so Cancel discards all changes
        self._user_presets: List[RouterPreset] = [replace(p) for p in user_presets]
        self._all_presets: List[RouterPreset] = get_all_presets(self._user_presets)
        self._selected_idx: int = 0
        self._saved = False

        self._build_ui()
        self._refresh_list()
        if self._all_presets:
            self._select_preset(0)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        main = ctk.CTkFrame(self, fg_color='transparent')
        main.pack(fill='both', expand=True, padx=8, pady=8)

        # Left: preset list
        left = ctk.CTkFrame(main)
        left.pack(side='left', fill='y', padx=(0, 6))
        left.configure(width=240)

        ctk.CTkLabel(left, text="Presets",
                     font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        self._list_frame = ctk.CTkScrollableFrame(left, width=220, height=400)
        self._list_frame.pack(fill='both', expand=True, padx=4)

        self._list_btns: List[ctk.CTkButton] = []

        # Buttons below list
        btn_row = ctk.CTkFrame(left, fg_color='transparent')
        btn_row.pack(fill='x', padx=4, pady=8)
        ctk.CTkButton(btn_row, text="+ New",    width=70,
                      command=self._new_preset).pack(side='left', padx=2)
        ctk.CTkButton(btn_row, text="⧉ Copy",   width=70,
                      command=self._duplicate_preset).pack(side='left', padx=2)
        self._del_btn = ctk.CTkButton(btn_row, text="✕ Delete", width=70,
                                       fg_color='#8b0000', hover_color='#5a0000',
                                       command=self._delete_preset)
        self._del_btn.pack(side='left', padx=2)

        # Right: edit form
        right = ctk.CTkScrollableFrame(main)
        right.pack(side='left', fill='both', expand=True)

        ctk.CTkLabel(right, text="Preset Details",
                     font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        # Identity
        id_frame = ctk.CTkFrame(right)
        id_frame.pack(fill='x', padx=4, pady=4)
        ctk.CTkLabel(id_frame, text="Identity",
                     font=('', 11, 'bold')).pack(anchor='w', padx=8, pady=(6, 2))

        self._v_name        = tk.StringVar()
        self._v_router      = tk.StringVar()
        self._v_description = tk.StringVar()
        self._v_notes       = tk.StringVar()

        _labeled_entry(id_frame, "Name:",          self._v_name,        label_width=160)
        _labeled_entry(id_frame, "Router Model:",  self._v_router,      label_width=160)
        _labeled_entry(id_frame, "Description:",   self._v_description, label_width=160, width=280)
        _labeled_entry(id_frame, "Notes:",         self._v_notes,       label_width=160, width=280)

        # Network
        net_frame = ctk.CTkFrame(right)
        net_frame.pack(fill='x', padx=4, pady=4)
        ctk.CTkLabel(net_frame, text="Network",
                     font=('', 11, 'bold')).pack(anchor='w', padx=8, pady=(6, 2))

        self._v_bcast  = tk.StringVar()
        self._v_port   = tk.StringVar()

        _labeled_entry(net_frame, "Broadcast Address:", self._v_bcast, label_width=160)
        _labeled_entry(net_frame, "UDP Port:",           self._v_port,  label_width=160, width=80)

        # Timing
        timing_frame = ctk.CTkFrame(right)
        timing_frame.pack(fill='x', padx=4, pady=4)
        ctk.CTkLabel(timing_frame, text="Timing",
                     font=('', 11, 'bold')).pack(anchor='w', padx=8, pady=(6, 2))

        self._v_interval    = tk.StringVar()
        self._v_timeout     = tk.StringVar()
        self._v_retries     = tk.StringVar()
        self._v_chunk       = tk.StringVar()
        self._v_repeat      = tk.StringVar()
        self._v_rep_delay   = tk.StringVar()

        _labeled_entry(timing_frame, "Packet Interval:",       self._v_interval,  unit='ms', label_width=160, width=80)
        _labeled_entry(timing_frame, "Operation Timeout:",     self._v_timeout,   unit='s',  label_width=160, width=80)
        _labeled_entry(timing_frame, "Retry Count:",           self._v_retries,              label_width=160, width=60)
        _labeled_entry(timing_frame, "Chunk Size:",            self._v_chunk,     unit='B',  label_width=160, width=80)
        _labeled_entry(timing_frame, "Send Repeat Count:",     self._v_repeat,               label_width=160, width=60)
        _labeled_entry(timing_frame, "Inter-Repeat Delay:",    self._v_rep_delay, unit='s',  label_width=160, width=80)

        # Firmware
        fw_frame = ctk.CTkFrame(right)
        fw_frame.pack(fill='x', padx=4, pady=4)
        ctk.CTkLabel(fw_frame, text="Firmware",
                     font=('', 11, 'bold')).pack(anchor='w', padx=8, pady=(6, 2))

        self._v_fw_path  = tk.StringVar()
        self._v_fw_label = tk.StringVar()

        fw_row = ctk.CTkFrame(fw_frame, fg_color='transparent')
        fw_row.pack(fill='x', padx=8, pady=3)
        ctk.CTkLabel(fw_row, text="Firmware File:", width=160).pack(side='left')
        self._fw_entry = ctk.CTkEntry(fw_row, textvariable=self._v_fw_path, width=200)
        self._fw_entry.pack(side='left', padx=4)
        self._fw_browse_btn = ctk.CTkButton(fw_row, text="Browse…", width=80,
                                             command=self._browse_fw)
        self._fw_browse_btn.pack(side='left', padx=4)

        _labeled_entry(fw_frame, "Display Label:", self._v_fw_label, label_width=160, width=180)

        # Verification
        ver_frame = ctk.CTkFrame(right)
        ver_frame.pack(fill='x', padx=4, pady=4)
        ctk.CTkLabel(ver_frame, text="Signature & Verification",
                     font=('', 11, 'bold')).pack(anchor='w', padx=8, pady=(6, 2))

        self._v_verify_crc  = tk.BooleanVar()
        self._v_verify_sig  = tk.BooleanVar()
        self._v_sig_key     = tk.StringVar()
        self._v_discovery   = tk.BooleanVar()

        _labeled_checkbox(ver_frame, "Verify CRC32 checksum before broadcast", self._v_verify_crc)
        _labeled_checkbox(ver_frame, "Verify RSA signature (requires public key file)", self._v_verify_sig)

        sig_row = ctk.CTkFrame(ver_frame, fg_color='transparent')
        sig_row.pack(fill='x', padx=8, pady=3)
        ctk.CTkLabel(sig_row, text="Public Key (.pem):", width=160).pack(side='left')
        ctk.CTkEntry(sig_row, textvariable=self._v_sig_key, width=200).pack(side='left', padx=4)
        ctk.CTkButton(sig_row, text="Browse…", width=80,
                      command=self._browse_key).pack(side='left', padx=4)

        _labeled_checkbox(ver_frame, "Enable discovery broadcast before firmware", self._v_discovery)

        # Buttons
        btn_row2 = ctk.CTkFrame(self, fg_color='transparent')
        btn_row2.pack(fill='x', padx=12, pady=8)
        self._save_btn = ctk.CTkButton(btn_row2, text="Save Preset", width=120,
                                        command=self._save_current)
        self._save_btn.pack(side='left', padx=4)
        ctk.CTkButton(btn_row2, text="Close & Apply", width=130,
                      command=self._close_apply).pack(side='right', padx=4)
        ctk.CTkButton(btn_row2, text="Cancel", width=90, fg_color='gray',
                      command=self.destroy).pack(side='right', padx=4)

    # ------------------------------------------------------------------
    # List helpers
    # ------------------------------------------------------------------

    def _refresh_list(self):
        for btn in self._list_btns:
            btn.destroy()
        self._list_btns.clear()

        self._all_presets = get_all_presets(self._user_presets)
        for idx, p in enumerate(self._all_presets):
            is_builtin = p.id.startswith('builtin-')
            label = f"{'🔒 ' if is_builtin else ''}{p.name}"
            btn = ctk.CTkButton(
                self._list_frame,
                text=label,
                anchor='w',
                fg_color='transparent',
                hover_color=('#3a7ebf', '#1e5a8a'),
                command=lambda i=idx: self._select_preset(i),
            )
            btn.pack(fill='x', pady=1)
            self._list_btns.append(btn)

    def _select_preset(self, idx: int):
        self._selected_idx = idx
        p = self._all_presets[idx]
        is_builtin = p.id.startswith('builtin-')

        # Populate form
        self._v_name.set(p.name)
        self._v_router.set(p.router_model)
        self._v_description.set(p.description)
        self._v_notes.set(p.notes)
        self._v_bcast.set(p.broadcast_address)
        self._v_port.set(str(p.udp_port))
        self._v_interval.set(str(p.packet_interval_ms))
        self._v_timeout.set(str(p.operation_timeout_s))
        self._v_retries.set(str(p.retry_count))
        self._v_chunk.set(str(p.chunk_size))
        self._v_repeat.set(str(p.send_repeat_count))
        self._v_rep_delay.set(str(p.inter_repeat_delay_s))
        self._v_fw_path.set(p.firmware_path)
        self._v_fw_label.set(p.firmware_label)
        self._v_verify_crc.set(p.verify_crc32)
        self._v_verify_sig.set(p.verify_signature)
        self._v_sig_key.set(p.signature_key_path)
        self._v_discovery.set(p.discovery_enabled)

        # Lock form for built-ins
        state = 'disabled' if is_builtin else 'normal'
        for attr in ('_fw_entry', '_fw_browse_btn', '_save_btn'):
            try:
                getattr(self, attr).configure(state=state)
            except Exception:
                pass
        self._del_btn.configure(state=state)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _new_preset(self):
        p = RouterPreset(name="New Preset")
        self._user_presets.append(p)
        self._refresh_list()
        self._select_preset(len(self._all_presets) - 1)

    def _duplicate_preset(self):
        if not self._all_presets:
            return
        p = duplicate_preset(self._all_presets[self._selected_idx])
        self._user_presets.append(p)
        self._refresh_list()
        self._select_preset(len(self._all_presets) - 1)

    def _delete_preset(self):
        if not self._all_presets:
            return
        p = self._all_presets[self._selected_idx]
        if p.id.startswith('builtin-'):
            messagebox.showinfo("Read-only", "Built-in presets cannot be deleted.",
                                parent=self)
            return
        if not messagebox.askyesno("Delete", f"Delete preset '{p.name}'?", parent=self):
            return
        self._user_presets = [x for x in self._user_presets if x.id != p.id]
        self._refresh_list()
        if self._all_presets:
            self._select_preset(max(0, self._selected_idx - 1))

    def _browse_fw(self):
        path = filedialog.askopenfilename(
            title="Select firmware file",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
            parent=self,
        )
        if path:
            self._v_fw_path.set(path)

    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select RSA public key (PEM)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            parent=self,
        )
        if path:
            self._v_sig_key.set(path)

    def _save_current(self):
        if not self._all_presets:
            return
        p = self._all_presets[self._selected_idx]
        if p.id.startswith('builtin-'):
            messagebox.showinfo("Read-only", "Use ⧉ Copy to create an editable copy.",
                                parent=self)
            return
        try:
            p.name              = self._v_name.get().strip() or 'Preset'
            p.router_model      = self._v_router.get().strip()
            p.description       = self._v_description.get().strip()
            p.notes             = self._v_notes.get().strip()
            p.broadcast_address = self._v_bcast.get().strip()
            p.udp_port          = int(self._v_port.get())
            p.packet_interval_ms    = int(self._v_interval.get())
            p.operation_timeout_s   = int(self._v_timeout.get())
            p.retry_count       = int(self._v_retries.get())
            p.chunk_size        = int(self._v_chunk.get())
            p.send_repeat_count     = int(self._v_repeat.get())
            p.inter_repeat_delay_s  = float(self._v_rep_delay.get())
            p.firmware_path     = self._v_fw_path.get().strip()
            p.firmware_label    = self._v_fw_label.get().strip()
            p.verify_crc32      = self._v_verify_crc.get()
            p.verify_signature  = self._v_verify_sig.get()
            p.signature_key_path    = self._v_sig_key.get().strip()
            p.discovery_enabled = self._v_discovery.get()
            self._refresh_list()
            # Re-select to update button label
            for i, x in enumerate(self._all_presets):
                if x.id == p.id:
                    self._select_preset(i)
                    break
        except ValueError as e:
            messagebox.showerror("Invalid value", str(e), parent=self)

    def _close_apply(self):
        self._saved = True
        self.destroy()

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------

    @property
    def saved(self) -> bool:
        return self._saved

    @property
    def result_user_presets(self) -> List[RouterPreset]:
        return self._user_presets


# ===========================================================================
# SettingsDialog  (extended with tabs)
# ===========================================================================

class SettingsDialog(ctk.CTkToplevel):
    """Settings / preferences dialog — tabbed layout."""

    def __init__(self, parent, settings: AppSettings):
        super().__init__(parent)
        self.title("Settings")
        self.geometry("520x640")
        self.minsize(480, 560)
        self.grab_set()

        self._settings = settings
        self._saved = False

        self._build_ui()

    def _build_ui(self):
        if CTK_AVAILABLE:
            tabs = ctk.CTkTabview(self)
            tabs.pack(fill='both', expand=True, padx=8, pady=8)
            t_net    = tabs.add("Network")
            t_timing = tabs.add("Timing")
            t_verify = tabs.add("Verification")
            t_adv    = tabs.add("Advanced")
            t_ui     = tabs.add("Appearance")
        else:
            # Plain tkinter fallback: stack everything vertically
            t_net = t_timing = t_verify = t_adv = t_ui = ctk.CTkScrollableFrame(self)
            t_net.pack(fill='both', expand=True)

        self._build_network_tab(t_net)
        self._build_timing_tab(t_timing)
        self._build_verification_tab(t_verify)
        self._build_advanced_tab(t_adv)
        self._build_ui_tab(t_ui)

        btn_row = ctk.CTkFrame(self, fg_color='transparent')
        btn_row.pack(fill='x', padx=12, pady=8)
        ctk.CTkButton(btn_row, text="Save", command=self._save,
                      width=100).pack(side='right', padx=4)
        ctk.CTkButton(btn_row, text="Cancel", command=self.destroy,
                      width=100, fg_color='gray').pack(side='right', padx=4)
        ctk.CTkButton(btn_row, text="Restore Defaults", command=self._restore_defaults,
                      width=140, fg_color='#555555').pack(side='left', padx=4)

    # ------------------------------------------------------------------
    # Tab: Network
    # ------------------------------------------------------------------

    def _build_network_tab(self, parent):
        self._port_var  = tk.StringVar(value=str(self._settings.udp_port))
        self._bcast_var = tk.StringVar(value=self._settings.broadcast_address)

        _labeled_entry(parent, "UDP Port:", self._port_var, width=100)
        _labeled_entry(parent, "Broadcast Address:", self._bcast_var, width=160)

        ctk.CTkLabel(parent,
                     text="Tip: Use 255.255.255.255 for all-subnet broadcast.\n"
                          "Set a specific subnet broadcast (e.g. 192.168.1.255)\n"
                          "to target a particular network segment.",
                     text_color='gray', font=('', 10), justify='left',
                     wraplength=360).pack(anchor='w', padx=12, pady=6)

    # ------------------------------------------------------------------
    # Tab: Timing
    # ------------------------------------------------------------------

    def _build_timing_tab(self, parent):
        self._interval_var    = tk.StringVar(value=str(self._settings.packet_interval_ms))
        self._timeout_var     = tk.StringVar(value=str(self._settings.operation_timeout_s))
        self._retry_var       = tk.StringVar(value=str(self._settings.retry_count))
        self._chunk_var       = tk.StringVar(value=str(self._settings.chunk_size))
        self._repeat_var      = tk.StringVar(value=str(self._settings.send_repeat_count))
        self._rep_delay_var   = tk.StringVar(value=str(self._settings.inter_repeat_delay_s))

        _labeled_entry(parent, "Packet Interval:",      self._interval_var,  unit='ms')
        _labeled_entry(parent, "Operation Timeout:",    self._timeout_var,   unit='s')
        _labeled_entry(parent, "Retry Count:",          self._retry_var,     width=60)
        _labeled_entry(parent, "Chunk Size:",           self._chunk_var,     unit='bytes')
        _labeled_entry(parent, "Send Repeat Count:",    self._repeat_var,    width=60)
        _labeled_entry(parent, "Inter-Repeat Delay:",   self._rep_delay_var, unit='s')

        ctk.CTkLabel(parent,
                     text="Send Repeat Count > 1 sends the whole package multiple times\n"
                          "(useful for unreliable networks).\n\n"
                          "Original tool defaults: 1400 port · 5 ms interval.",
                     text_color='gray', font=('', 10), justify='left',
                     wraplength=360).pack(anchor='w', padx=12, pady=6)

    # ------------------------------------------------------------------
    # Tab: Verification
    # ------------------------------------------------------------------

    def _build_verification_tab(self, parent):
        self._v_crc32_var    = tk.BooleanVar(value=self._settings.verify_crc32)
        self._v_sig_var      = tk.BooleanVar(value=self._settings.verify_signature)
        self._v_sig_key_var  = tk.StringVar(value=self._settings.signature_key_path)
        self._skip_upchk_var = tk.BooleanVar(value=self._settings.skip_upgrade_check)

        _labeled_checkbox(parent, "Verify CRC32 checksum before broadcast",
                          self._v_crc32_var)
        ctk.CTkLabel(parent,
                     text="Computes the HWNP CRC32 and confirms it matches the\n"
                          "value stored in the package header.",
                     text_color='gray', font=('', 10), justify='left',
                     wraplength=380).pack(anchor='w', padx=28, pady=(0, 6))

        _labeled_checkbox(parent,
                          "Verify RSA signature (requires public key file)",
                          self._v_sig_var)
        ctk.CTkLabel(parent,
                     text="Checks the RSA-2048/SHA-256 signature in the SIGNINFO\n"
                          "or SIGNATURE item against the supplied PEM public key.",
                     text_color='gray', font=('', 10), justify='left',
                     wraplength=380).pack(anchor='w', padx=28, pady=(0, 6))

        key_row = ctk.CTkFrame(parent, fg_color='transparent')
        key_row.pack(fill='x', padx=8, pady=4)
        ctk.CTkLabel(key_row, text="Public Key File (.pem):", width=180).pack(side='left')
        ctk.CTkEntry(key_row, textvariable=self._v_sig_key_var,
                     width=180).pack(side='left', padx=4)
        ctk.CTkButton(key_row, text="Browse…", width=80,
                      command=self._browse_sig_key).pack(side='left', padx=4)

        _labeled_checkbox(parent,
                          "Skip UpgradeCheck.xml hardware compatibility gates",
                          self._skip_upchk_var)
        ctk.CTkLabel(parent,
                     text="When enabled, the device's hardware-gate XML is not\n"
                          "checked. Use with caution on unknown hardware.",
                     text_color='gray', font=('', 10), justify='left',
                     wraplength=380).pack(anchor='w', padx=28, pady=(0, 6))

    def _browse_sig_key(self):
        path = filedialog.askopenfilename(
            title="Select RSA public key (PEM)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            parent=self,
        )
        if path:
            self._v_sig_key_var.set(path)

    # ------------------------------------------------------------------
    # Tab: Advanced
    # ------------------------------------------------------------------

    def _build_advanced_tab(self, parent):
        self._raw_mode_var   = tk.BooleanVar(value=self._settings.raw_send_mode)
        self._autolog_var    = tk.BooleanVar(value=self._settings.auto_save_log)
        self._discovery_var  = tk.BooleanVar(value=self._settings.discovery_enabled)
        self._dry_run_var    = tk.BooleanVar(value=self._settings.dry_run_mode)
        self._ttl_var        = tk.StringVar(value=str(self._settings.socket_ttl))
        self._buf_var        = tk.StringVar(value=str(self._settings.socket_buf_size))
        self._log_dir_var    = tk.StringVar(value=self._settings.log_dir)
        self._log_level_var  = tk.StringVar(value=self._settings.log_level)
        self._ts_fmt_var     = tk.StringVar(value=self._settings.log_timestamp_format)

        _labeled_checkbox(parent, "Dry-run mode (simulate broadcast, no packets sent)",
                          self._dry_run_var)
        _labeled_checkbox(parent, "Raw send mode (skip handshake, send pure HWNP)",
                          self._raw_mode_var)
        _labeled_checkbox(parent, "Send discovery broadcast before firmware",
                          self._discovery_var)
        _labeled_checkbox(parent, "Auto-save log on exit",
                          self._autolog_var)

        ctk.CTkLabel(parent, text="Socket", font=('', 11, 'bold')).pack(
            anchor='w', padx=8, pady=(8, 2))
        _labeled_entry(parent, "IP TTL:", self._ttl_var, width=60,
                       label_width=180)
        _labeled_entry(parent, "Send Buffer Size:", self._buf_var, unit='bytes',
                       label_width=180)

        ctk.CTkLabel(parent, text="Logging", font=('', 11, 'bold')).pack(
            anchor='w', padx=8, pady=(8, 2))

        log_dir_row = ctk.CTkFrame(parent, fg_color='transparent')
        log_dir_row.pack(fill='x', padx=8, pady=3)
        ctk.CTkLabel(log_dir_row, text="Log Directory:", width=180).pack(side='left')
        ctk.CTkEntry(log_dir_row, textvariable=self._log_dir_var,
                     width=160).pack(side='left', padx=4)
        ctk.CTkButton(log_dir_row, text="Browse…", width=80,
                      command=self._browse_log_dir).pack(side='left', padx=4)

        if CTK_AVAILABLE:
            level_row = ctk.CTkFrame(parent, fg_color='transparent')
            level_row.pack(fill='x', padx=8, pady=3)
            ctk.CTkLabel(level_row, text="Log Level:", width=180).pack(side='left')
            ctk.CTkOptionMenu(level_row, variable=self._log_level_var,
                              values=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                              width=120).pack(side='left', padx=4)

        _labeled_entry(parent, "Timestamp Format:", self._ts_fmt_var,
                       width=180, label_width=180)
        ctk.CTkLabel(parent,
                     text="strftime format, e.g. %Y-%m-%d %H:%M:%S",
                     text_color='gray', font=('', 10)).pack(anchor='w', padx=28)

    def _browse_log_dir(self):
        path = filedialog.askdirectory(title="Select log directory", parent=self)
        if path:
            self._log_dir_var.set(path)

    # ------------------------------------------------------------------
    # Tab: Appearance
    # ------------------------------------------------------------------

    def _build_ui_tab(self, parent):
        self._theme_var = tk.StringVar(value=self._settings.theme)

        ctk.CTkLabel(parent, text="Theme:", width=180).pack(anchor='w', padx=8, pady=(12, 2))
        if CTK_AVAILABLE:
            ctk.CTkOptionMenu(parent, variable=self._theme_var,
                              values=['dark', 'light', 'system'],
                              width=140).pack(anchor='w', padx=12)

        ctk.CTkLabel(parent,
                     text="Changes take effect immediately after saving.",
                     text_color='gray', font=('', 10)).pack(anchor='w', padx=12, pady=4)

    # ------------------------------------------------------------------
    # Save / defaults
    # ------------------------------------------------------------------

    def _restore_defaults(self):
        if not messagebox.askyesno("Restore Defaults",
                                   "Reset all settings to factory defaults?",
                                   parent=self):
            return
        d = AppSettings()
        self._port_var.set(str(d.udp_port))
        self._bcast_var.set(d.broadcast_address)
        self._interval_var.set(str(d.packet_interval_ms))
        self._timeout_var.set(str(d.operation_timeout_s))
        self._retry_var.set(str(d.retry_count))
        self._chunk_var.set(str(d.chunk_size))
        self._repeat_var.set(str(d.send_repeat_count))
        self._rep_delay_var.set(str(d.inter_repeat_delay_s))
        self._v_crc32_var.set(d.verify_crc32)
        self._v_sig_var.set(d.verify_signature)
        self._v_sig_key_var.set(d.signature_key_path)
        self._skip_upchk_var.set(d.skip_upgrade_check)
        self._raw_mode_var.set(d.raw_send_mode)
        self._autolog_var.set(d.auto_save_log)
        self._discovery_var.set(d.discovery_enabled)
        self._dry_run_var.set(d.dry_run_mode)
        self._ttl_var.set(str(d.socket_ttl))
        self._buf_var.set(str(d.socket_buf_size))
        self._log_dir_var.set(d.log_dir)
        self._log_level_var.set(d.log_level)
        self._ts_fmt_var.set(d.log_timestamp_format)
        self._theme_var.set(d.theme)

    def _save(self):
        try:
            self._settings.udp_port              = int(self._port_var.get())
            self._settings.broadcast_address     = self._bcast_var.get().strip()
            self._settings.packet_interval_ms    = int(self._interval_var.get())
            self._settings.operation_timeout_s   = int(self._timeout_var.get())
            self._settings.retry_count           = int(self._retry_var.get())
            self._settings.chunk_size            = int(self._chunk_var.get())
            self._settings.send_repeat_count     = int(self._repeat_var.get())
            self._settings.inter_repeat_delay_s  = float(self._rep_delay_var.get())
            self._settings.verify_crc32          = self._v_crc32_var.get()
            self._settings.verify_signature      = self._v_sig_var.get()
            self._settings.signature_key_path    = self._v_sig_key_var.get().strip()
            self._settings.skip_upgrade_check    = self._skip_upchk_var.get()
            self._settings.raw_send_mode         = self._raw_mode_var.get()
            self._settings.auto_save_log         = self._autolog_var.get()
            self._settings.discovery_enabled     = self._discovery_var.get()
            self._settings.dry_run_mode          = self._dry_run_var.get()
            self._settings.socket_ttl            = int(self._ttl_var.get())
            self._settings.socket_buf_size       = int(self._buf_var.get())
            self._settings.log_dir               = self._log_dir_var.get().strip()
            self._settings.log_level             = self._log_level_var.get()
            self._settings.log_timestamp_format  = self._ts_fmt_var.get().strip()
            self._settings.theme                 = self._theme_var.get()
            self._saved = True
            self.destroy()
        except ValueError as e:
            messagebox.showerror("Invalid value", str(e), parent=self)

    @property
    def saved(self) -> bool:
        return self._saved


# ===========================================================================
# FirmwareInfoDialog
# ===========================================================================

class FirmwareInfoDialog(ctk.CTkToplevel):
    """Shows detailed info about a loaded HWNP firmware package."""

    def __init__(self, parent, pkg: HWNPPackage,
                 title: str = "Firmware Package Info",
                 verify_crc32: bool = True,
                 verify_signature: bool = False,
                 sig_key: str = ''):
        super().__init__(parent)
        self.title(title)
        self.geometry("700x560")
        self.grab_set()

        text_box = ctk.CTkTextbox(self, font=('Consolas', 11))
        text_box.pack(fill='both', expand=True, padx=10, pady=10)

        info = describe_package(pkg) + "\n"

        # Run verification if requested
        if verify_crc32 or verify_signature:
            ok, msgs = verify_package(pkg, verify_crc32, verify_signature, sig_key)
            info += "\n── Verification ──\n"
            for m in msgs:
                info += f"  {m}\n"
            info += f"\n  Overall: {'✓ PASS' if ok else '✗ FAIL'}\n"

        text_box.insert('end', info)
        text_box.configure(state='disabled')

        ctk.CTkButton(self, text="Close", command=self.destroy, width=100).pack(pady=8)


# ===========================================================================
# Main window
# ===========================================================================

class MainWindow:
    """
    Main application window for ONT Broadcast Tool v1.1.

    New in v1.1:
    - Router Preset Manager (create/edit/delete/duplicate presets)
    - Apply preset → fills all settings at once
    - Signature verification UI (CRC32 + RSA)
    - Dry-run mode indicator
    - Repeat broadcast count
    - Extended Settings dialog (tabbed: Network / Timing / Verification / Advanced / Appearance)
    - "Restore Defaults" in settings
    """

    def __init__(self):
        self.settings     = load_settings()
        self._user_presets: List[RouterPreset] = load_presets()
        self._apply_theme()

        self._root = ctk.CTk()
        self._root.title(f"{APP_TITLE} v{APP_VERSION}")
        self._root.geometry(
            f"{self.settings.window_width}x{self.settings.window_height}"
        )
        self._root.minsize(820, 620)
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
        ctk.CTkButton(top, text="📋 Presets", width=100,
                      command=self._open_presets).pack(side='right', padx=4, pady=4)
        ctk.CTkButton(top, text="? About", width=90,
                      command=self._show_about).pack(side='right', padx=4, pady=4)

        # ── Network interface row ─────────────────────────────────────
        net_row = ctk.CTkFrame(root, fg_color='transparent')
        net_row.pack(fill='x', padx=12, pady=(8, 0))

        ctk.CTkLabel(net_row, text="Network Interface:", width=140).pack(side='left')
        self._iface_cb = ctk.CTkComboBox(
            net_row, width=300, command=self._on_iface_select,
            state='readonly'
        )
        self._iface_cb.pack(side='left', padx=6)
        ctk.CTkButton(net_row, text="⟳ Refresh", width=80,
                      command=self._refresh_interfaces).pack(side='left', padx=2)

        self._status_lbl = ctk.CTkLabel(net_row, text="● Ready",
                                        text_color='green')
        self._status_lbl.pack(side='left', padx=12)

        # Dry-run badge
        self._dryrun_lbl = ctk.CTkLabel(net_row, text="",
                                         text_color='orange', font=('', 11, 'bold'))
        self._dryrun_lbl.pack(side='left', padx=4)
        self._refresh_dryrun_badge()

        # ── Main content (left + right) ───────────────────────────────
        content = ctk.CTkFrame(root, fg_color='transparent')
        content.pack(fill='both', expand=True, padx=12, pady=8)

        left = ctk.CTkFrame(content)
        left.pack(side='left', fill='both', expand=False, padx=(0, 6))
        left.configure(width=360)

        self._build_preset_bar(left)
        self._build_firmware_panel(left)
        self._build_quick_settings_panel(left)

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
            btn_bar, text="🔍 Inspect", width=110,
            command=self._inspect_package
        )
        self._inspect_btn.pack(side='left', padx=8, pady=8)

        self._verify_btn = ctk.CTkButton(
            btn_bar, text="✓ Verify Package", width=130,
            command=self._verify_package
        )
        self._verify_btn.pack(side='left', padx=4, pady=8)

        # Progress
        self._progress = ctk.CTkProgressBar(btn_bar, width=200)
        self._progress.pack(side='right', padx=12, pady=12)
        self._progress.set(0)

        self._progress_lbl = ctk.CTkLabel(btn_bar, text="0%", width=40)
        self._progress_lbl.pack(side='right', padx=4)

    def _build_preset_bar(self, parent):
        """Compact preset selector at top of left panel."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill='x', padx=8, pady=(8, 0))

        ctk.CTkLabel(frame, text="Router Preset:",
                     font=('', 12, 'bold')).pack(anchor='w', padx=8, pady=(6, 2))

        row = ctk.CTkFrame(frame, fg_color='transparent')
        row.pack(fill='x', padx=8, pady=(0, 6))

        all_presets = get_all_presets(self._user_presets)
        names = [p.name for p in all_presets]

        self._preset_cb = ctk.CTkComboBox(
            row, values=names, width=210, state='readonly',
            command=self._on_preset_select
        )
        self._preset_cb.pack(side='left', padx=(0, 4))
        if names:
            self._preset_cb.set(names[0])

        ctk.CTkButton(row, text="Apply", width=60,
                      command=self._apply_selected_preset).pack(side='left', padx=2)
        ctk.CTkButton(row, text="Manage", width=70,
                      command=self._open_presets).pack(side='left', padx=2)

    def _build_firmware_panel(self, parent):
        frame = ctk.CTkFrame(parent)
        frame.pack(fill='x', padx=8, pady=8)

        ctk.CTkLabel(frame, text="Firmware Package",
                     font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        for i, label in enumerate(BUILTIN_PACKAGES):
            ctk.CTkRadioButton(
                frame, text=label,
                variable=self._pkg_choice, value=i,
                command=self._on_pkg_choice
            ).pack(anchor='w', padx=16, pady=3)

        ctk.CTkRadioButton(
            frame, text="Custom firmware file…",
            variable=self._pkg_choice, value=3,
            command=self._on_pkg_choice
        ).pack(anchor='w', padx=16, pady=3)

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

        self._pkg_info_lbl = ctk.CTkLabel(
            frame, text="Built-in package (V3 devices)",
            text_color='gray', wraplength=300
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
        self._repeat_var    = tk.StringVar(value=str(self.settings.send_repeat_count))

        for label, var, unit in [
            ("UDP Port:",           self._port_var,     ""),
            ("Packet Interval:",    self._interval_var, "ms"),
            ("Operation Timeout:",  self._timeout_var,  "s"),
            ("Retry Count:",        self._retries_var,  ""),
            ("Send Repeat Count:",  self._repeat_var,   "×"),
        ]:
            row = ctk.CTkFrame(frame, fg_color='transparent')
            row.pack(fill='x', padx=8, pady=3)
            ctk.CTkLabel(row, text=label, width=150).pack(side='left')
            ctk.CTkEntry(row, textvariable=var, width=72).pack(side='left', padx=4)
            if unit:
                ctk.CTkLabel(row, text=unit).pack(side='left')

        ctk.CTkLabel(frame,
                     text="Original defaults: 1400 port · 5 ms · 60 s · 3 retries",
                     text_color='gray', font=('', 10),
                     wraplength=320).pack(anchor='w', padx=8, pady=(0, 8))

    def _build_device_panel(self, parent):
        ctk.CTkLabel(parent, text="Active Devices / Sessions",
                     font=('', 13, 'bold')).pack(anchor='w', padx=8, pady=(8, 4))

        hdr = ctk.CTkFrame(parent)
        hdr.pack(fill='x', padx=4)
        for col, w in [("ONT Serial", 160), ("Status", 100),
                       ("Progress", 120), ("Duration", 80)]:
            ctk.CTkLabel(hdr, text=col, width=w,
                         font=('', 11, 'bold')).pack(side='left', padx=4)

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
    # Preset helpers
    # ------------------------------------------------------------------

    def _refresh_preset_cb(self):
        all_p = get_all_presets(self._user_presets)
        names = [p.name for p in all_p]
        self._preset_cb.configure(values=names)
        if names and not self._preset_cb.get():
            self._preset_cb.set(names[0])

    def _on_preset_select(self, choice: str):
        pass  # preview only; user clicks Apply to commit

    def _apply_selected_preset(self):
        name = self._preset_cb.get()
        all_p = get_all_presets(self._user_presets)
        preset = next((p for p in all_p if p.name == name), None)
        if preset is None:
            return
        self.settings.udp_port           = preset.udp_port
        self.settings.broadcast_address  = preset.broadcast_address
        self.settings.packet_interval_ms = preset.packet_interval_ms
        self.settings.operation_timeout_s = preset.operation_timeout_s
        self.settings.retry_count        = preset.retry_count
        self.settings.chunk_size         = preset.chunk_size
        self.settings.send_repeat_count  = preset.send_repeat_count
        self.settings.inter_repeat_delay_s = preset.inter_repeat_delay_s
        self.settings.verify_crc32       = preset.verify_crc32
        self.settings.verify_signature   = preset.verify_signature
        self.settings.signature_key_path = preset.signature_key_path
        self.settings.discovery_enabled  = preset.discovery_enabled
        self.settings.active_preset_id   = preset.id

        # Sync quick-settings panel
        self._port_var.set(str(preset.udp_port))
        self._interval_var.set(str(preset.packet_interval_ms))
        self._timeout_var.set(str(preset.operation_timeout_s))
        self._retries_var.set(str(preset.retry_count))
        self._repeat_var.set(str(preset.send_repeat_count))

        # Auto-load firmware if preset has a path
        if preset.firmware_path and os.path.isfile(preset.firmware_path):
            try:
                pkg = load_hwnp_file(preset.firmware_path)
                self._custom_pkg = pkg
                self._custom_firmware_path = preset.firmware_path
                self._custom_path_var.set(os.path.basename(preset.firmware_path))
                self._pkg_choice.set(3)
                self._on_pkg_choice()
                self._pkg_info_lbl.configure(
                    text=f"{pkg.size_kb:.1f} KB · {pkg.item_counts} items"
                )
            except Exception as e:
                self._log(f"Warning: could not load preset firmware: {e}")

        self._log(f"Preset applied: {preset.name} "
                  f"(port={preset.udp_port}, interval={preset.packet_interval_ms}ms)")

    def _open_presets(self):
        dlg = PresetsDialog(self._root, self._user_presets)
        self._root.wait_window(dlg)
        if dlg.saved:
            self._user_presets = dlg.result_user_presets
            save_presets(self._user_presets)
            self._refresh_preset_cb()
            self._log(f"Presets saved ({len(self._user_presets)} user preset(s))")

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

    def _get_custom_package(self) -> Optional[HWNPPackage]:
        if self._pkg_choice.get() == 3:
            return self._custom_pkg
        return None

    def _inspect_package(self):
        pkg = self._get_custom_package()
        if pkg is None:
            messagebox.showinfo("No custom package",
                                "Load a custom firmware file first (select option 4).",
                                parent=self._root)
            return
        FirmwareInfoDialog(self._root, pkg,
                           verify_crc32=False,
                           verify_signature=False)

    def _verify_package(self):
        pkg = self._get_custom_package()
        if pkg is None:
            messagebox.showinfo("No custom package",
                                "Load a custom firmware file first (select option 4).",
                                parent=self._root)
            return
        FirmwareInfoDialog(
            self._root, pkg,
            title="Firmware Verification",
            verify_crc32=self.settings.verify_crc32,
            verify_signature=self.settings.verify_signature,
            sig_key=self.settings.signature_key_path,
        )

    def _get_firmware_for_broadcast(self) -> Optional[HWNPPackage]:
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
            answer = messagebox.askyesno(
                "Package file not found",
                f"Built-in firmware file '{pkg_filename}' not found.\n\n"
                f"Package {choice+1} corresponds to:\n"
                f"{BUILTIN_PACKAGES[choice]}\n\n"
                f"Would you like to browse for the firmware file?\n"
                f"(Place it as '{pkg_filename}' next to the tool to avoid this.)",
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
            self._log(f"Using: {os.path.basename(pkg_path)} ({pkg.size_kb:.1f} KB)")
            return pkg
        except Exception as e:
            messagebox.showerror("Load Error", str(e), parent=self._root)
            return None

    # ------------------------------------------------------------------
    # Broadcast control
    # ------------------------------------------------------------------

    def _read_quick_settings(self):
        """Sync quick-settings panel values back to settings object."""
        for attr, var in [
            ('udp_port',            self._port_var),
            ('packet_interval_ms',  self._interval_var),
            ('operation_timeout_s', self._timeout_var),
            ('retry_count',         self._retries_var),
            ('send_repeat_count',   self._repeat_var),
        ]:
            try:
                setattr(self.settings, attr, int(var.get()))
            except ValueError:
                pass

    def _start_broadcast(self):
        self._read_quick_settings()
        pkg = self._get_firmware_for_broadcast()
        if pkg is None:
            return

        bcast    = self._get_broadcast_addr()
        iface_ip = self._selected_iface.ip if self._selected_iface else ''

        self._engine = BroadcastEngine(
            broadcast_addr=bcast,
            port=self.settings.udp_port,
            interface_ip=iface_ip,
            packet_interval_ms=self.settings.packet_interval_ms,
            operation_timeout_s=self.settings.operation_timeout_s,
            retry_count=self.settings.retry_count,
            chunk_size=self.settings.chunk_size,
            dry_run=self.settings.dry_run_mode,
            send_repeat_count=self.settings.send_repeat_count,
            inter_repeat_delay_s=self.settings.inter_repeat_delay_s,
            verify_crc32=self.settings.verify_crc32,
            verify_signature=self.settings.verify_signature,
            signature_key_path=self.settings.signature_key_path,
            socket_ttl=self.settings.socket_ttl,
            socket_buf_size=self.settings.socket_buf_size,
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
            label = "● [DRY RUN] Broadcasting…" if self.settings.dry_run_mode else "● Broadcasting…"
            self._status_lbl.configure(text=label, text_color='orange')
        else:
            self._start_btn.configure(state='normal')
            self._stop_btn.configure(state='disabled')
            self._status_lbl.configure(text="● Ready", text_color='green')
            self._progress.set(0)
            self._progress_lbl.configure(text="0%")

    def _refresh_dryrun_badge(self):
        if self.settings.dry_run_mode:
            self._dryrun_lbl.configure(text="[DRY RUN]")
        else:
            self._dryrun_lbl.configure(text="")

    # ------------------------------------------------------------------
    # Engine callbacks
    # ------------------------------------------------------------------

    def _on_engine_log(self, msg: str):
        self._root.after(0, self._append_log, msg)

    def _on_engine_status(self, msg: str):
        self._root.after(0, self._status_lbl.configure, {'text': f'● {msg}'})

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
        fmt = self.settings.log_timestamp_format or '%Y-%m-%d %H:%M:%S'
        ts  = datetime.now().strftime(fmt)
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
            self._repeat_var.set(str(self.settings.send_repeat_count))
            self._refresh_dryrun_badge()
            self._log("Settings saved")

    def _toggle_theme(self):
        if CTK_AVAILABLE:
            current = ctk.get_appearance_mode().lower()
            new = 'light' if current == 'dark' else 'dark'
            ctk.set_appearance_mode(new)
            self.settings.theme = new
            self._theme_btn.configure(text='☀' if new == 'light' else '🌙')

    # ------------------------------------------------------------------
    # About
    # ------------------------------------------------------------------

    def _show_about(self):
        text = (
            f"{APP_TITLE} v{APP_VERSION}\n\n"
            "Open-source reimplementation of OBSCTool\n"
            "(Huawei ONT Broadband Service Console Tool)\n\n"
            "New in v1.1:\n"
            "  • Router Preset Manager\n"
            "  • Signature / CRC32 verification\n"
            "  • Dry-run mode\n"
            "  • Repeat broadcast\n"
            "  • Extended settings (tabbed)\n\n"
            "Broadcasts HWNP firmware packages to Huawei\n"
            "ONT devices over UDP for upgrade and unlock.\n\n"
            "HWNP format: huawei_header.h (this repository)\n"
            "Default: port 1400 | interval 5 ms"
        )
        messagebox.showinfo(f"About {APP_TITLE}", text, parent=self._root)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _update_controls(self):
        pass

    def _on_close(self):
        if self._engine and self._engine.is_running:
            if not messagebox.askyesno(
                "Exit", "Broadcast is running. Stop and exit?",
                parent=self._root
            ):
                return
            self._engine.stop()

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
