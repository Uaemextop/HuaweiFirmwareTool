"""
OBSC Firmware Tool — Main GUI Application

Modern Windows 11 themed GUI for Huawei ONT firmware flashing.
Uses ttkbootstrap (with tkinter/ttk fallback) for a polished look.

Features:
  - Network adapter selection with auto-detection
  - Firmware file browser with HWNP validation
  - Configurable transfer parameters (frame size, interval, flash mode)
  - Real-time progress with speed and ETA
  - Device discovery list
  - Audit log with export (OBSC_LOG format)
  - Dark / Light theme toggle
  - IP Mode: Automatic / Manual / DHCP
"""

import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import time
import datetime
import logging
import zlib

# ttkbootstrap gives us modern themes, meter widgets, icons, and better
# styling.  Fall back to plain ttk if it is not installed.
try:
    import ttkbootstrap as ttkb
    from ttkbootstrap.constants import *
    from ttkbootstrap import Style as TtkbStyle
    from tkinter import ttk  # still needed for some sub-widgets
    HAS_TTKB = True
except ImportError:
    from tkinter import ttk
    HAS_TTKB = False

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obsc_tool import __version__
from obsc_tool.firmware import HWNPFirmware
from obsc_tool.network import (
    discover_adapters, UDPTransport,
    configure_adapter_ip, set_adapter_dhcp, test_socket_bind,
    list_serial_ports,
)
from obsc_tool.protocol import (
    OBSCWorker, FlashMode, UpgradeType,
    OBSC_SEND_PORT, OBSC_RECV_PORT
)
from obsc_tool.presets import PresetManager, PRESET_TEMPLATE
from obsc_tool.config_crypto import (
    encrypt_config, decrypt_config, try_decrypt_all_keys,
    CfgFileParser, KNOWN_CHIP_IDS, derive_key
)
from obsc_tool.terminal import (
    TelnetClient, SerialClient, FirmwareDumper, ONT_COMMANDS
)

logger = logging.getLogger("obsc_tool")


# ── Theme Colors ─────────────────────────────────────────────────

THEMES = {
    'light': {
        'bg': '#F3F3F3',
        'fg': '#1A1A1A',
        'accent': '#0078D4',
        'accent_hover': '#106EBE',
        'surface': '#FFFFFF',
        'surface_alt': '#F9F9F9',
        'border': '#D1D1D1',
        'success': '#0F7B0F',
        'error': '#C42B1C',
        'warning': '#9D5D00',
        'log_bg': '#FFFFFF',
        'log_fg': '#1A1A1A',
        'progress_bg': '#E0E0E0',
        'progress_fg': '#0078D4',
    },
    'dark': {
        'bg': '#202020',
        'fg': '#FFFFFF',
        'accent': '#60CDFF',
        'accent_hover': '#429CE3',
        'surface': '#2D2D2D',
        'surface_alt': '#383838',
        'border': '#404040',
        'success': '#6CCB5F',
        'error': '#FF99A4',
        'warning': '#FCE100',
        'log_bg': '#1A1A1A',
        'log_fg': '#D4D4D4',
        'progress_bg': '#404040',
        'progress_fg': '#60CDFF',
    },
}

# ── IP Mode defaults (extracted from ONT_V100R002C00SPC253.exe) ──
# Binary analysis of the dialog resource at 0x877500 confirms:
#   - "本地网卡" (Local Network Card) = Ethernet adapter selector
#   - "组播服务器IP" (Multicast Server IP) = ONT IP (SysIPAddress32 control)
#   - Default FRSIZE options: 800, 1000, 1200, 1400 (default 1200)
#   - Default FRINTERV options: 10, 20 (default 10 ms)
#   - Send port 50000, receive port 50001
#   - The PC Ethernet adapter must be on the same subnet as the ONT.
# The ONT default LAN IP is 192.168.1.1; PC uses 192.168.1.100/24.
# The DESBLOQUEIO unlock method changes to FRSIZE=1400, FRINTERV=5ms.
IP_MODE_DEFAULTS = {
    'ip': '192.168.1.100',
    'netmask': '255.255.255.0',
    'gateway': '192.168.1.1',
    'dns1': '8.8.8.8',
    'dns2': '8.8.4.4',
}

# ttkbootstrap theme names
TTKB_DARK = "darkly"
TTKB_LIGHT = "cosmo"


class OBSCToolApp:
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

    def _build_upgrade_tab(self):
        """Build the main upgrade tab."""
        tab = self.tab_upgrade

        # ── Network Adapter ──────────────────────────────────────
        adapter_frame = ttk.LabelFrame(
            tab, text="Ethernet Adapter (connect ONT via LAN cable)", padding=8)
        adapter_frame.pack(fill=tk.X, pady=(0, 8))

        adapter_row = ttk.Frame(adapter_frame)
        adapter_row.pack(fill=tk.X)

        self.adapter_var = tk.StringVar()
        self.adapter_combo = ttk.Combobox(
            adapter_row, textvariable=self.adapter_var,
            state='readonly', width=60,
        )
        self.adapter_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        refresh_btn = ttk.Button(
            adapter_row, text="🔃 Refresh",
            command=self._refresh_adapters, width=12,
        )
        refresh_btn.pack(side=tk.RIGHT)

        # Adapter details panel
        self.adapter_detail_var = tk.StringVar(value="")
        adapter_detail_label = ttk.Label(
            adapter_frame, textvariable=self.adapter_detail_var,
            font=('Consolas', 8), justify=tk.LEFT,
        )
        adapter_detail_label.pack(fill=tk.X, pady=(5, 0))

        # Update details when adapter selection changes
        self.adapter_combo.bind('<<ComboboxSelected>>', self._on_adapter_selected)

        # ── IP Mode ──────────────────────────────────────────────
        ip_frame = ttk.LabelFrame(
            tab, text="IP Mode (Ethernet adapter configuration)", padding=8)
        ip_frame.pack(fill=tk.X, pady=(0, 8))

        mode_row = ttk.Frame(ip_frame)
        mode_row.pack(fill=tk.X)

        self.ip_mode_var = tk.StringVar(value="automatic")
        ttk.Radiobutton(
            mode_row,
            text="🔄 Automatic (192.168.1.100/24 → gw 192.168.1.1)",
            variable=self.ip_mode_var, value="automatic",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(
            mode_row, text="✏️ Manual",
            variable=self.ip_mode_var, value="manual",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(
            mode_row, text="🌐 DHCP",
            variable=self.ip_mode_var, value="dhcp",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT)

        # Manual IP fields (shown/hidden depending on mode)
        self.ip_manual_frame = ttk.Frame(ip_frame)
        self.ip_manual_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Label(self.ip_manual_frame, text="IP:", width=5).pack(side=tk.LEFT)
        self.ip_mode_ip_var = tk.StringVar(value=IP_MODE_DEFAULTS['ip'])
        self.ip_mode_ip_entry = ttk.Entry(
            self.ip_manual_frame, textvariable=self.ip_mode_ip_var, width=15)
        self.ip_mode_ip_entry.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(self.ip_manual_frame, text="Mask:", width=5).pack(side=tk.LEFT)
        self.ip_mode_mask_var = tk.StringVar(value=IP_MODE_DEFAULTS['netmask'])
        self.ip_mode_mask_entry = ttk.Entry(
            self.ip_manual_frame, textvariable=self.ip_mode_mask_var, width=15)
        self.ip_mode_mask_entry.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(self.ip_manual_frame, text="Gateway:", width=8).pack(side=tk.LEFT)
        self.ip_mode_gw_var = tk.StringVar(value=IP_MODE_DEFAULTS['gateway'])
        self.ip_mode_gw_entry = ttk.Entry(
            self.ip_manual_frame, textvariable=self.ip_mode_gw_var, width=15)
        self.ip_mode_gw_entry.pack(side=tk.LEFT, padx=(0, 8))

        # Apply button lives in its own row so it's always visible
        apply_row = ttk.Frame(ip_frame)
        apply_row.pack(fill=tk.X, pady=(5, 0))
        self.ip_mode_apply_btn = ttk.Button(
            apply_row, text="⚡ Apply IP Mode",
            command=self._apply_ip_mode, width=18)
        self.ip_mode_apply_btn.pack(side=tk.LEFT)

        # Status line
        self.ip_mode_status_var = tk.StringVar(value="")
        ttk.Label(ip_frame, textvariable=self.ip_mode_status_var,
                  font=('Segoe UI', 9)).pack(fill=tk.X, pady=(3, 0))

        # Initial state — Automatic hides manual fields
        self._on_ip_mode_changed()

        # ── Firmware File ────────────────────────────────────────
        fw_frame = ttk.LabelFrame(tab, text="Firmware File", padding=8)
        fw_frame.pack(fill=tk.X, pady=(0, 8))

        fw_row = ttk.Frame(fw_frame)
        fw_row.pack(fill=tk.X)

        self.fw_path_var = tk.StringVar(value="No file selected")
        fw_entry = ttk.Entry(
            fw_row, textvariable=self.fw_path_var,
            state='readonly', width=60,
        )
        fw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        browse_btn = ttk.Button(
            fw_row, text="📂 Browse",
            command=self._browse_firmware, width=12,
        )
        browse_btn.pack(side=tk.RIGHT)

        # Firmware info line
        self.fw_info_var = tk.StringVar(value="")
        fw_info_label = ttk.Label(fw_frame, textvariable=self.fw_info_var,
                                  font=('Segoe UI', 9))
        fw_info_label.pack(fill=tk.X, pady=(5, 0))

        # ── Quick Config ─────────────────────────────────────────
        config_frame = ttk.LabelFrame(tab, text="Transfer Configuration", padding=8)
        config_frame.pack(fill=tk.X, pady=(0, 8))

        config_grid = ttk.Frame(config_frame)
        config_grid.pack(fill=tk.X)

        # Frame Size
        ttk.Label(config_grid, text="Frame Size:").grid(row=0, column=0, sticky='w', padx=(0, 5))
        self.frame_size_var = tk.StringVar(value="1400")
        frame_size_combo = ttk.Combobox(
            config_grid, textvariable=self.frame_size_var,
            values=["1200", "1400", "1472", "4096", "8192"],
            width=10,
        )
        frame_size_combo.grid(row=0, column=1, padx=(0, 15))
        ttk.Label(config_grid, text="bytes").grid(row=0, column=2, sticky='w', padx=(0, 20))

        # Frame Interval
        ttk.Label(config_grid, text="Frame Interval:").grid(row=0, column=3, sticky='w', padx=(0, 5))
        self.frame_interval_var = tk.StringVar(value="5")
        interval_combo = ttk.Combobox(
            config_grid, textvariable=self.frame_interval_var,
            values=["1", "2", "5", "10", "20", "50"],
            width=10,
        )
        interval_combo.grid(row=0, column=4, padx=(0, 15))
        ttk.Label(config_grid, text="ms").grid(row=0, column=5, sticky='w')

        # Flash Mode
        ttk.Label(config_grid, text="Flash Mode:").grid(row=1, column=0, sticky='w', padx=(0, 5), pady=(5, 0))
        self.flash_mode_var = tk.StringVar(value="Normal")
        flash_combo = ttk.Combobox(
            config_grid, textvariable=self.flash_mode_var,
            values=["Normal", "Forced"],
            state='readonly', width=10,
        )
        flash_combo.grid(row=1, column=1, padx=(0, 15), pady=(5, 0))

        # Delete Config
        self.delete_cfg_var = tk.BooleanVar(value=False)
        delete_chk = ttk.Checkbutton(
            config_grid, text="Delete existing configuration",
            variable=self.delete_cfg_var,
        )
        delete_chk.grid(row=1, column=3, columnspan=3, sticky='w', pady=(5, 0))

        # ── Progress ─────────────────────────────────────────────
        progress_frame = ttk.LabelFrame(tab, text="Progress", padding=8)
        progress_frame.pack(fill=tk.X, pady=(0, 8))

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            progress_frame, variable=self.progress_var,
            maximum=100, mode='determinate', length=400,
        )
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(
            progress_frame, textvariable=self.status_var,
            font=('Segoe UI', 10),
        )
        status_label.pack(fill=tk.X)

        self.progress_detail_var = tk.StringVar(value="")
        detail_label = ttk.Label(
            progress_frame, textvariable=self.progress_detail_var,
            font=('Segoe UI', 9),
        )
        detail_label.pack(fill=tk.X)

        # ── Action Buttons ───────────────────────────────────────
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, pady=(5, 0))

        self.discover_btn = ttk.Button(
            btn_frame, text="🔍 Discover Devices",
            command=self._discover_devices, width=20,
        )
        self.discover_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.start_btn = ttk.Button(
            btn_frame, text="▶ Start Upgrade",
            command=self._start_upgrade, width=20,
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_btn = ttk.Button(
            btn_frame, text="⏹ Stop",
            command=self._stop_upgrade, width=12,
            state='disabled',
        )
        self.stop_btn.pack(side=tk.LEFT)

    def _build_settings_tab(self):
        """Build the settings tab with advanced configuration."""
        tab = self.tab_settings

        # ── Protocol Settings ────────────────────────────────────
        proto_frame = ttk.LabelFrame(tab, text="Protocol Settings", padding=10)
        proto_frame.pack(fill=tk.X, pady=(0, 10))

        # Send Port
        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Send Port:", width=20).pack(side=tk.LEFT)
        self.send_port_var = tk.StringVar(value=str(OBSC_SEND_PORT))
        ttk.Entry(row, textvariable=self.send_port_var, width=10).pack(side=tk.LEFT)

        # Receive Port
        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Receive Port:", width=20).pack(side=tk.LEFT)
        self.recv_port_var = tk.StringVar(value=str(OBSC_RECV_PORT))
        ttk.Entry(row, textvariable=self.recv_port_var, width=10).pack(side=tk.LEFT)

        # Broadcast Address override
        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Broadcast Address:", width=20).pack(side=tk.LEFT)
        self.broadcast_var = tk.StringVar(value="auto")
        ttk.Entry(row, textvariable=self.broadcast_var, width=20).pack(side=tk.LEFT)
        ttk.Label(row, text="(auto = calculated from adapter)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # Timeout
        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Upgrade Timeout:", width=20).pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value="600")
        ttk.Entry(row, textvariable=self.timeout_var, width=10).pack(side=tk.LEFT)
        ttk.Label(row, text="seconds").pack(side=tk.LEFT, padx=5)

        # ── Upgrade Options ──────────────────────────────────────
        upgrade_frame = ttk.LabelFrame(tab, text="Upgrade Options", padding=10)
        upgrade_frame.pack(fill=tk.X, pady=(0, 10))

        # Upgrade Type
        row = ttk.Frame(upgrade_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Upgrade Type:", width=20).pack(side=tk.LEFT)
        self.upgrade_type_var = tk.StringVar(value="Standard")
        ttk.Combobox(
            row, textvariable=self.upgrade_type_var,
            values=["Standard", "Equipment", "Equipment WC"],
            state='readonly', width=18,
        ).pack(side=tk.LEFT)

        # Machine Filter
        row = ttk.Frame(upgrade_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Machine Filter (SN):", width=20).pack(side=tk.LEFT)
        self.machine_filter_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.machine_filter_var, width=30).pack(side=tk.LEFT)
        ttk.Label(row, text="(empty = all devices)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # ── Advanced Transfer ────────────────────────────────────
        adv_frame = ttk.LabelFrame(tab, text="Advanced Transfer", padding=10)
        adv_frame.pack(fill=tk.X, pady=(0, 10))

        # Discovery Duration
        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Discovery Duration:", width=20).pack(side=tk.LEFT)
        self.discovery_duration_var = tk.StringVar(value="10")
        ttk.Combobox(
            row, textvariable=self.discovery_duration_var,
            values=["5", "10", "15", "20", "30", "60"],
            width=8,
        ).pack(side=tk.LEFT)
        ttk.Label(row, text="seconds").pack(side=tk.LEFT, padx=5)

        # Control Retries
        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Control Retries:", width=20).pack(side=tk.LEFT)
        self.ctrl_retries_var = tk.StringVar(value="3")
        ttk.Combobox(
            row, textvariable=self.ctrl_retries_var,
            values=["1", "2", "3", "5", "10"],
            width=8,
        ).pack(side=tk.LEFT)
        ttk.Label(row, text="attempts", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # Data Retries
        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Data Frame Retries:", width=20).pack(side=tk.LEFT)
        self.data_retries_var = tk.StringVar(value="0")
        ttk.Combobox(
            row, textvariable=self.data_retries_var,
            values=["0", "1", "2", "3"],
            width=8,
        ).pack(side=tk.LEFT)
        ttk.Label(row, text="(0 = no retry)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # Check Policy
        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Check Policy:", width=20).pack(side=tk.LEFT)
        self.check_policy_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.check_policy_var, width=20).pack(side=tk.LEFT)
        ttk.Label(row, text="(empty = default)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # BOM Code
        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="BOM Code:", width=20).pack(side=tk.LEFT)
        self.bom_code_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.bom_code_var, width=20).pack(side=tk.LEFT)
        ttk.Label(row, text="(empty = default)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # ── Logging Options ──────────────────────────────────────
        log_frame = ttk.LabelFrame(tab, text="Logging", padding=10)
        log_frame.pack(fill=tk.X, pady=(0, 10))

        row = ttk.Frame(log_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Log Directory:", width=20).pack(side=tk.LEFT)
        self.log_dir_var = tk.StringVar(value=os.path.join(os.getcwd(), "logs"))
        ttk.Entry(row, textvariable=self.log_dir_var, width=40).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="Browse", command=self._browse_log_dir, width=8).pack(side=tk.LEFT)

        self.auto_log_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            log_frame, text="Auto-save log after each upgrade",
            variable=self.auto_log_var,
        ).pack(fill=tk.X, pady=2)

        # ── Network Configuration ────────────────────────────────
        net_frame = ttk.LabelFrame(tab, text="Network Configuration", padding=10)
        net_frame.pack(fill=tk.X, pady=(0, 10))

        # Adapter selector for configuration
        row = ttk.Frame(net_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Configure Adapter:", width=20).pack(side=tk.LEFT)
        self.cfg_adapter_var = tk.StringVar()
        self.cfg_adapter_combo = ttk.Combobox(
            row, textvariable=self.cfg_adapter_var,
            state='readonly', width=30,
        )
        self.cfg_adapter_combo.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="🔃", command=self._refresh_cfg_adapters, width=3).pack(side=tk.LEFT)

        # IP Address
        row = ttk.Frame(net_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="IP Address:", width=20).pack(side=tk.LEFT)
        self.cfg_ip_var = tk.StringVar(value="192.168.1.100")
        ttk.Entry(row, textvariable=self.cfg_ip_var, width=18).pack(side=tk.LEFT)

        # Subnet Mask
        ttk.Label(row, text="  Subnet:", width=8).pack(side=tk.LEFT)
        self.cfg_mask_var = tk.StringVar(value="255.255.255.0")
        ttk.Entry(row, textvariable=self.cfg_mask_var, width=18).pack(side=tk.LEFT)

        # Gateway
        row = ttk.Frame(net_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Gateway:", width=20).pack(side=tk.LEFT)
        self.cfg_gw_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.cfg_gw_var, width=18).pack(side=tk.LEFT)
        ttk.Label(row, text="(optional)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # Buttons
        btn_row = ttk.Frame(net_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(
            btn_row, text="📝 Apply Static IP",
            command=self._apply_static_ip, width=18,
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            btn_row, text="🔄 Set DHCP",
            command=self._apply_dhcp, width=14,
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            btn_row, text="🔌 Test Socket",
            command=self._test_socket, width=14,
        ).pack(side=tk.LEFT)

        self.net_status_var = tk.StringVar(value="")
        ttk.Label(net_frame, textvariable=self.net_status_var,
                  font=('Segoe UI', 9)).pack(fill=tk.X, pady=(5, 0))

    def _build_presets_tab(self):
        """Build the router presets management tab."""
        tab = self.tab_presets

        # ── Preset Selection ─────────────────────────────────────
        select_frame = ttk.LabelFrame(tab, text="Router Presets", padding=10)
        select_frame.pack(fill=tk.X, pady=(0, 10))

        row = ttk.Frame(select_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Select Preset:", width=16).pack(side=tk.LEFT)
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(
            row, textvariable=self.preset_var,
            state='readonly', width=35,
        )
        self.preset_combo.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="Load", command=self._load_preset, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(row, text="Delete", command=self._delete_preset, width=8).pack(side=tk.LEFT, padx=2)

        # Preset description (must be created before _refresh_preset_list)
        self.preset_desc_var = tk.StringVar(value="Select a preset to see its description")
        ttk.Label(select_frame, textvariable=self.preset_desc_var,
                  font=('Segoe UI', 9), wraplength=600).pack(fill=tk.X, pady=(5, 0))

        self.preset_combo.bind('<<ComboboxSelected>>', self._on_preset_selected)

        # ── Save Current as Preset ───────────────────────────────
        save_frame = ttk.LabelFrame(tab, text="Save Current Settings as Preset", padding=10)
        save_frame.pack(fill=tk.X, pady=(0, 10))

        row = ttk.Frame(save_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Preset Name:", width=16).pack(side=tk.LEFT)
        self.new_preset_name_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.new_preset_name_var, width=30).pack(side=tk.LEFT, padx=(0, 5))

        row = ttk.Frame(save_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Router Model:", width=16).pack(side=tk.LEFT)
        self.new_preset_model_var = tk.StringVar()
        ttk.Combobox(
            row, textvariable=self.new_preset_model_var,
            values=["HG8145V5", "HG8245H", "HG8546M", "HG8245Q2",
                     "HG8045Q", "EG8145V5", "HN8245Q", "Custom"],
            width=18,
        ).pack(side=tk.LEFT, padx=(0, 5))

        row = ttk.Frame(save_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Description:", width=16).pack(side=tk.LEFT)
        self.new_preset_desc_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.new_preset_desc_var, width=50).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(save_frame, text="💾 Save Preset",
                   command=self._save_preset, width=20).pack(pady=(5, 0))

        # ── Preset Details ───────────────────────────────────────
        details_frame = ttk.LabelFrame(tab, text="Preset Details", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self.preset_details_text = scrolledtext.ScrolledText(
            details_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled', height=10,
        )
        self.preset_details_text.pack(fill=tk.BOTH, expand=True)

        # Populate preset list (must be after all widgets are created)
        self._refresh_preset_list()

    def _build_verification_tab(self):
        """Build the signature and verification configuration tab."""
        tab = self.tab_verify

        # ── CRC32 Verification ───────────────────────────────────
        crc_frame = ttk.LabelFrame(tab, text="CRC32 Integrity Verification", padding=10)
        crc_frame.pack(fill=tk.X, pady=(0, 10))

        self.verify_crc32_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            crc_frame, text="Verify CRC32 checksums before flashing",
            variable=self.verify_crc32_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(crc_frame,
                  text="When enabled, the tool validates the HWNP header and data CRC32\n"
                       "checksums before starting the transfer. Disable only if you are\n"
                       "working with modified/custom firmware packages.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
                  ).pack(fill=tk.X, pady=(2, 0))

        # ── HWNP Signature Verification ──────────────────────────
        sig_frame = ttk.LabelFrame(tab, text="HWNP Signature Verification", padding=10)
        sig_frame.pack(fill=tk.X, pady=(0, 10))

        self.verify_signature_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sig_frame, text="Verify RSA signature before flashing",
            variable=self.verify_signature_var,
        ).pack(fill=tk.X, pady=2)

        row = ttk.Frame(sig_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Public Key File:", width=16).pack(side=tk.LEFT)
        self.pubkey_path_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.pubkey_path_var, width=40).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="Browse", command=self._browse_pubkey, width=8).pack(side=tk.LEFT)

        ttk.Label(sig_frame,
                  text="Huawei HWNP firmware packages may include an RSA signature\n"
                       "(SIGNINFO section). If you have the public key, enable this to\n"
                       "verify the firmware authenticity before flashing.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
                  ).pack(fill=tk.X, pady=(2, 0))

        # ── Product Compatibility Check ──────────────────────────
        prod_frame = ttk.LabelFrame(tab, text="Product Compatibility Check", padding=10)
        prod_frame.pack(fill=tk.X, pady=(0, 10))

        self.skip_product_check_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            prod_frame, text="Skip product compatibility check (dangerous)",
            variable=self.skip_product_check_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(prod_frame,
                  text="HWNP firmware includes a product list specifying compatible\n"
                       "hardware. Skipping this check allows flashing firmware to\n"
                       "potentially incompatible devices. Use with extreme caution.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
                  ).pack(fill=tk.X, pady=(2, 0))

        # ── Pre-Flash Verification ───────────────────────────────
        preflash_frame = ttk.LabelFrame(tab, text="Pre-Flash Verification", padding=10)
        preflash_frame.pack(fill=tk.X, pady=(0, 10))

        self.verify_item_crc_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            preflash_frame, text="Verify individual item CRC32 checksums",
            variable=self.verify_item_crc_var,
        ).pack(fill=tk.X, pady=2)

        self.verify_size_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            preflash_frame, text="Verify firmware file size matches header",
            variable=self.verify_size_var,
        ).pack(fill=tk.X, pady=2)

        self.dry_run_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            preflash_frame, text="Dry run mode (validate only, do not flash)",
            variable=self.dry_run_var,
        ).pack(fill=tk.X, pady=2)

        ttk.Label(preflash_frame,
                  text="These options run additional checks on the firmware before\n"
                       "starting the transfer. Dry run mode performs all steps except\n"
                       "actually sending data, useful for testing configuration.",
                  font=('Segoe UI', 8), justify=tk.LEFT,
                  ).pack(fill=tk.X, pady=(2, 0))

    def _build_crypto_tab(self):
        """Build the config file encryption/decryption tab."""
        tab = self.tab_crypto

        # ── Encrypt / Decrypt ────────────────────────────────────
        op_frame = ttk.LabelFrame(tab, text="Config File Encryption (aescrypt2)", padding=10)
        op_frame.pack(fill=tk.X, pady=(0, 10))

        # Input file
        row = ttk.Frame(op_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Input File:", width=14).pack(side=tk.LEFT)
        self.crypto_input_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.crypto_input_var, width=45).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="Browse", command=self._browse_crypto_input, width=8).pack(side=tk.LEFT)

        # Output file
        row = ttk.Frame(op_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Output File:", width=14).pack(side=tk.LEFT)
        self.crypto_output_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.crypto_output_var, width=45).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="Browse", command=self._browse_crypto_output, width=8).pack(side=tk.LEFT)

        # Chip ID
        row = ttk.Frame(op_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Chip ID:", width=14).pack(side=tk.LEFT)
        self.crypto_chip_var = tk.StringVar(value="SD5116H")
        ttk.Combobox(
            row, textvariable=self.crypto_chip_var,
            values=KNOWN_CHIP_IDS + ["Custom"],
            width=15,
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(row, text="Key template: Df7!ui%s9(lmV1L8", font=('Segoe UI', 8)).pack(side=tk.LEFT)

        # Custom chip ID
        row = ttk.Frame(op_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Custom Chip:", width=14).pack(side=tk.LEFT)
        self.crypto_custom_chip_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.crypto_custom_chip_var, width=20).pack(side=tk.LEFT)
        ttk.Label(row, text="(only if Chip ID = Custom)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # Buttons
        btn_row = ttk.Frame(op_frame)
        btn_row.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btn_row, text="🔓 Decrypt", command=self._crypto_decrypt, width=15).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="🔒 Encrypt", command=self._crypto_encrypt, width=15).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="🔍 Auto-Detect Key", command=self._crypto_auto_detect, width=18).pack(side=tk.LEFT)

        # ── Config Editor (cfgtool) ──────────────────────────────
        edit_frame = ttk.LabelFrame(tab, text="Config Editor (cfgtool)", padding=10)
        edit_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Search
        search_row = ttk.Frame(edit_frame)
        search_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(search_row, text="Search:").pack(side=tk.LEFT)
        self.cfg_search_var = tk.StringVar()
        ttk.Entry(search_row, textvariable=self.cfg_search_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_row, text="Search", command=self._cfg_search, width=8).pack(side=tk.LEFT)
        ttk.Button(search_row, text="Load File", command=self._cfg_load, width=10).pack(side=tk.LEFT, padx=5)

        # Config text viewer
        self.cfg_text = scrolledtext.ScrolledText(
            edit_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            height=12,
        )
        self.cfg_text.pack(fill=tk.BOTH, expand=True)

    def _build_terminal_tab(self):
        """Build the serial/telnet terminal tab."""
        tab = self.tab_terminal

        # ── Connection ───────────────────────────────────────────
        conn_frame = ttk.LabelFrame(tab, text="Connection", padding=8)
        conn_frame.pack(fill=tk.X, pady=(0, 8))

        # Connection type
        type_row = ttk.Frame(conn_frame)
        type_row.pack(fill=tk.X, pady=2)
        ttk.Label(type_row, text="Type:", width=12).pack(side=tk.LEFT)
        self.term_type_var = tk.StringVar(value="Telnet")
        ttk.Combobox(
            type_row, textvariable=self.term_type_var,
            values=["Telnet", "Serial"],
            state='readonly', width=10,
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(type_row, text="Host/Port:", width=10).pack(side=tk.LEFT)
        self.term_host_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(type_row, textvariable=self.term_host_var, width=18).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Label(type_row, text="Port:").pack(side=tk.LEFT)
        self.term_port_var = tk.StringVar(value="23")
        ttk.Entry(type_row, textvariable=self.term_port_var, width=6).pack(side=tk.LEFT, padx=(0, 5))

        # Serial settings row
        serial_row = ttk.Frame(conn_frame)
        serial_row.pack(fill=tk.X, pady=2)
        ttk.Label(serial_row, text="COM Port:", width=12).pack(side=tk.LEFT)
        self.term_com_var = tk.StringVar()
        self.term_com_combo = ttk.Combobox(
            serial_row, textvariable=self.term_com_var,
            width=15,
        )
        self.term_com_combo.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(serial_row, text="🔃", command=self._refresh_com_ports, width=3).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(serial_row, text="Baud:").pack(side=tk.LEFT)
        self.term_baud_var = tk.StringVar(value="115200")
        ttk.Combobox(
            serial_row, textvariable=self.term_baud_var,
            values=["9600", "19200", "38400", "57600", "115200"],
            width=8,
        ).pack(side=tk.LEFT, padx=(0, 10))

        # Connect/disconnect buttons
        btn_row = ttk.Frame(conn_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))
        self.term_connect_btn = ttk.Button(
            btn_row, text="🔌 Connect", command=self._term_connect, width=14)
        self.term_connect_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.term_disconnect_btn = ttk.Button(
            btn_row, text="❌ Disconnect", command=self._term_disconnect,
            width=14, state='disabled')
        self.term_disconnect_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.term_status_var = tk.StringVar(value="Disconnected")
        ttk.Label(btn_row, textvariable=self.term_status_var,
                  font=('Segoe UI', 9)).pack(side=tk.LEFT)

        # ── Quick Commands ───────────────────────────────────────
        cmd_frame = ttk.LabelFrame(tab, text="Quick Commands (WAP CLI)", padding=5)
        cmd_frame.pack(fill=tk.X, pady=(0, 8))

        cmd_grid = ttk.Frame(cmd_frame)
        cmd_grid.pack(fill=tk.X)
        quick_cmds = [
            ("System Info", "display sysinfo"),
            ("Version", "display version"),
            ("SN", "display sn"),
            ("MAC", "display mac"),
            ("WAN Config", "display wan config"),
            ("Optical", "display optic 0"),
            ("CPU", "display cpu"),
            ("Memory", "display memory"),
            ("Flash", "display flash"),
            ("Partitions", "cat /proc/mtd"),
            ("Processes", "ps"),
            ("Config", "display current-config"),
        ]
        for i, (label, cmd) in enumerate(quick_cmds):
            r, c = divmod(i, 6)
            ttk.Button(
                cmd_grid, text=label, width=14,
                command=lambda c=cmd: self._term_send_command(c),
            ).grid(row=r, column=c, padx=1, pady=1)

        # ── Terminal Output ──────────────────────────────────────
        term_frame = ttk.Frame(tab)
        term_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self.term_output = scrolledtext.ScrolledText(
            term_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled',
            bg='#0C0C0C', fg='#CCCCCC',
            insertbackground='#CCCCCC',
        )
        self.term_output.pack(fill=tk.BOTH, expand=True)

        # ── Input ────────────────────────────────────────────────
        input_row = ttk.Frame(tab)
        input_row.pack(fill=tk.X)
        ttk.Label(input_row, text="Command:").pack(side=tk.LEFT)
        self.term_input_var = tk.StringVar()
        self.term_input_entry = ttk.Entry(
            input_row, textvariable=self.term_input_var, width=60)
        self.term_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.term_input_entry.bind('<Return>', lambda e: self._term_send_input())
        ttk.Button(input_row, text="Send", command=self._term_send_input, width=8).pack(side=tk.LEFT)

    def _build_dump_tab(self):
        """Build the firmware dump tab."""
        tab = self.tab_dump

        # ── Info ─────────────────────────────────────────────────
        info_frame = ttk.LabelFrame(tab, text="Firmware Dump (via Telnet)", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(info_frame,
                  text="Firmware dump requires an active Telnet connection to the ONT device.\n"
                       "The device must have Telnet enabled (flash 1-TELNET.bin first).\n"
                       "Connect via the Terminal tab, then use the controls below to dump partitions.",
                  font=('Segoe UI', 9), justify=tk.LEFT,
                  ).pack(fill=tk.X)

        # ── Partition List ───────────────────────────────────────
        part_frame = ttk.LabelFrame(tab, text="MTD Partitions", padding=10)
        part_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        btn_row = ttk.Frame(part_frame)
        btn_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(btn_row, text="🔍 Read Partitions",
                   command=self._dump_read_partitions, width=18).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="💾 Dump Selected",
                   command=self._dump_selected, width=15).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="💾 Dump All",
                   command=self._dump_all, width=12).pack(side=tk.LEFT)

        self.dump_status_var = tk.StringVar(value="Connect via Terminal tab first")
        ttk.Label(btn_row, textvariable=self.dump_status_var,
                  font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=10)

        # Partition table
        columns = ('id', 'name', 'size', 'erasesize')
        self.dump_tree = ttk.Treeview(
            part_frame, columns=columns, show='headings', height=8)
        self.dump_tree.heading('id', text='MTD #')
        self.dump_tree.heading('name', text='Partition Name')
        self.dump_tree.heading('size', text='Size')
        self.dump_tree.heading('erasesize', text='Erase Size')
        self.dump_tree.column('id', width=60)
        self.dump_tree.column('name', width=200)
        self.dump_tree.column('size', width=120)
        self.dump_tree.column('erasesize', width=120)
        self.dump_tree.pack(fill=tk.BOTH, expand=True)

        # ── Dump Output ──────────────────────────────────────────
        out_frame = ttk.LabelFrame(tab, text="Dump Output", padding=5)
        out_frame.pack(fill=tk.X, pady=(0, 5))

        self.dump_output = scrolledtext.ScrolledText(
            out_frame, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled', height=6,
        )
        self.dump_output.pack(fill=tk.BOTH, expand=True)

    def _build_info_tab(self):
        """Build the firmware information tab."""
        tab = self.tab_info

        self.info_text = scrolledtext.ScrolledText(
            tab, wrap=tk.WORD,
            font=('Consolas', 10),
            state='disabled',
        )
        self.info_text.pack(fill=tk.BOTH, expand=True)

    def _build_log_tab(self):
        """Build the log viewer tab."""
        tab = self.tab_log

        # Log controls
        controls = ttk.Frame(tab)
        controls.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(controls, text="Clear Log", command=self._clear_log, width=12).pack(side=tk.LEFT)
        ttk.Button(controls, text="Export Log", command=self._export_log, width=12).pack(side=tk.LEFT, padx=5)

        # Log text
        self.log_text = scrolledtext.ScrolledText(
            tab, wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled',
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ── Preset Management ────────────────────────────────────────

    def _refresh_preset_list(self):
        """Refresh the preset combobox values."""
        names = self.preset_manager.list_presets()
        self.preset_combo['values'] = names
        if names:
            self.preset_combo.current(0)
            self._on_preset_selected(None)

    def _on_preset_selected(self, event):
        """Handle preset selection change."""
        name = self.preset_var.get()
        preset = self.preset_manager.get_preset(name)
        if preset:
            self.preset_desc_var.set(preset.get('description', 'No description'))
            # Show details
            lines = []
            for key, val in sorted(preset.items()):
                if key.startswith('_'):
                    continue
                lines.append(f"  {key:25s} = {val}")
            self.preset_details_text.configure(state='normal')
            self.preset_details_text.delete('1.0', tk.END)
            self.preset_details_text.insert('1.0', f"Preset: {name}\n{'=' * 50}\n" + '\n'.join(lines))
            self.preset_details_text.configure(state='disabled')

    def _load_preset(self):
        """Load the selected preset into the current settings."""
        name = self.preset_var.get()
        if not name:
            messagebox.showwarning("No Preset", "Please select a preset first.")
            return

        preset = self.preset_manager.get_preset(name)
        if not preset:
            return

        # Apply preset to all settings
        self.frame_size_var.set(str(preset.get('frame_size', 1400)))
        self.frame_interval_var.set(str(preset.get('frame_interval_ms', 5)))
        self.flash_mode_var.set(preset.get('flash_mode', 'Normal'))
        self.delete_cfg_var.set(preset.get('delete_cfg', False))
        self.upgrade_type_var.set(preset.get('upgrade_type', 'Standard'))
        self.send_port_var.set(str(preset.get('send_port', OBSC_SEND_PORT)))
        self.recv_port_var.set(str(preset.get('recv_port', OBSC_RECV_PORT)))
        self.timeout_var.set(str(preset.get('timeout', 600)))
        self.machine_filter_var.set(preset.get('machine_filter', ''))
        self.broadcast_var.set(preset.get('broadcast_address', 'auto'))
        self.verify_crc32_var.set(preset.get('verify_crc32', True))
        self.verify_signature_var.set(preset.get('verify_signature', False))
        self.skip_product_check_var.set(preset.get('skip_product_check', False))
        self.discovery_duration_var.set(str(preset.get('discovery_duration', 10)))
        self.ctrl_retries_var.set(str(preset.get('ctrl_retries', 3)))
        self.data_retries_var.set(str(preset.get('data_retries', 0)))
        self.check_policy_var.set(preset.get('check_policy', ''))
        self.bom_code_var.set(preset.get('bom_code', ''))

        self._log(f"Loaded preset: {name}")
        messagebox.showinfo("Preset Loaded", f"Loaded preset: {name}")

    def _save_preset(self):
        """Save current settings as a new preset."""
        name = self.new_preset_name_var.get().strip()
        if not name:
            messagebox.showwarning("No Name", "Please enter a preset name.")
            return

        if self.preset_manager.is_builtin(name):
            messagebox.showwarning("Built-in Preset",
                                   "Cannot overwrite a built-in preset. Choose a different name.")
            return

        preset_data = self._gather_current_settings()
        preset_data['model'] = self.new_preset_model_var.get() or "Custom"
        preset_data['description'] = self.new_preset_desc_var.get() or f"Custom preset for {preset_data['model']}"

        self.preset_manager.save_preset(name, preset_data)
        self._refresh_preset_list()
        self._log(f"Saved preset: {name}")
        messagebox.showinfo("Preset Saved", f"Preset '{name}' saved successfully.")

    def _delete_preset(self):
        """Delete the selected preset."""
        name = self.preset_var.get()
        if not name:
            return

        if self.preset_manager.is_builtin(name):
            messagebox.showwarning("Built-in Preset",
                                   "Cannot delete built-in presets.")
            return

        if messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
            if self.preset_manager.delete_preset(name):
                self._refresh_preset_list()
                self._log(f"Deleted preset: {name}")

    def _gather_current_settings(self):
        """Gather all current settings into a dict."""
        return {
            'frame_size': int(self.frame_size_var.get()),
            'frame_interval_ms': int(self.frame_interval_var.get()),
            'flash_mode': self.flash_mode_var.get(),
            'delete_cfg': self.delete_cfg_var.get(),
            'upgrade_type': self.upgrade_type_var.get(),
            'send_port': int(self.send_port_var.get()),
            'recv_port': int(self.recv_port_var.get()),
            'timeout': int(self.timeout_var.get()),
            'machine_filter': self.machine_filter_var.get(),
            'broadcast_address': self.broadcast_var.get(),
            'verify_crc32': self.verify_crc32_var.get(),
            'verify_signature': self.verify_signature_var.get(),
            'skip_product_check': self.skip_product_check_var.get(),
            'discovery_duration': int(self.discovery_duration_var.get()),
            'ctrl_retries': int(self.ctrl_retries_var.get()),
            'data_retries': int(self.data_retries_var.get()),
            'check_policy': self.check_policy_var.get(),
            'bom_code': self.bom_code_var.get(),
        }

    # ── Verification Helpers ─────────────────────────────────────

    def _browse_pubkey(self):
        """Browse for RSA public key file."""
        path = filedialog.askopenfilename(
            title="Select Public Key File",
            filetypes=[
                ("PEM files", "*.pem"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.pubkey_path_var.set(path)

    # ── Config Crypto Handlers ───────────────────────────────────

    def _get_chip_id(self):
        """Get the selected chip ID."""
        chip = self.crypto_chip_var.get()
        if chip == "Custom":
            custom = self.crypto_custom_chip_var.get().strip()
            if not custom:
                messagebox.showwarning("No Chip ID", "Enter a custom chip ID.")
                return None
            return custom
        return chip

    def _browse_crypto_input(self):
        """Browse for config file input."""
        path = filedialog.askopenfilename(
            title="Select Config File",
            filetypes=[
                ("XML files", "*.xml"),
                ("Binary files", "*.bin"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.crypto_input_var.set(path)
            # Auto-set output
            base, ext = os.path.splitext(path)
            self.crypto_output_var.set(base + "_out" + ext)

    def _browse_crypto_output(self):
        """Browse for config file output."""
        path = filedialog.asksaveasfilename(
            title="Save Decrypted/Encrypted File",
            filetypes=[
                ("XML files", "*.xml"),
                ("Binary files", "*.bin"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.crypto_output_var.set(path)

    def _crypto_decrypt(self):
        """Decrypt a config file."""
        in_path = self.crypto_input_var.get().strip()
        out_path = self.crypto_output_var.get().strip()
        if not in_path or not out_path:
            messagebox.showwarning("Missing Path", "Select input and output files.")
            return
        chip_id = self._get_chip_id()
        if not chip_id:
            return
        try:
            with open(in_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted = decrypt_config(encrypted_data, chip_id)
            with open(out_path, 'wb') as f:
                f.write(decrypted)
            # Show in editor
            try:
                text = decrypted.decode('utf-8', errors='replace')
                self.cfg_text.delete('1.0', tk.END)
                self.cfg_text.insert('1.0', text)
            except Exception:
                pass
            self._log(f"Decrypted {in_path} -> {out_path} (chip: {chip_id})")
            messagebox.showinfo("Success",
                                f"Decrypted successfully.\n"
                                f"Key: Df7!ui{chip_id}9(lmV1L8\n"
                                f"Output: {out_path}")
        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))
            self._log(f"Decrypt error: {e}")

    def _crypto_encrypt(self):
        """Encrypt a config file."""
        in_path = self.crypto_input_var.get().strip()
        out_path = self.crypto_output_var.get().strip()
        if not in_path or not out_path:
            messagebox.showwarning("Missing Path", "Select input and output files.")
            return
        chip_id = self._get_chip_id()
        if not chip_id:
            return
        try:
            with open(in_path, 'rb') as f:
                plain_data = f.read()
            encrypted = encrypt_config(plain_data, chip_id)
            with open(out_path, 'wb') as f:
                f.write(encrypted)
            self._log(f"Encrypted {in_path} -> {out_path} (chip: {chip_id})")
            messagebox.showinfo("Success",
                                f"Encrypted successfully.\n"
                                f"Key: Df7!ui{chip_id}9(lmV1L8\n"
                                f"Output: {out_path}")
        except Exception as e:
            messagebox.showerror("Encrypt Error", str(e))
            self._log(f"Encrypt error: {e}")

    def _crypto_auto_detect(self):
        """Try decrypting with all known chip IDs."""
        in_path = self.crypto_input_var.get().strip()
        if not in_path:
            messagebox.showwarning("No File", "Select an encrypted config file first.")
            return
        try:
            with open(in_path, 'rb') as f:
                data = f.read()
            results = try_decrypt_all_keys(data)
            if results:
                chip_id, decrypted = results[0]
                self.crypto_chip_var.set(chip_id)
                text = decrypted.decode('utf-8', errors='replace')
                self.cfg_text.delete('1.0', tk.END)
                self.cfg_text.insert('1.0', text)
                self._log(f"Auto-detected key: {chip_id} for {in_path}")
                messagebox.showinfo("Key Detected",
                                    f"Detected chip ID: {chip_id}\n"
                                    f"Key: Df7!ui{chip_id}9(lmV1L8\n"
                                    f"Config loaded in editor.")
            else:
                messagebox.showwarning("No Match",
                                       "Could not decrypt with any known chip ID.\n"
                                       "Try entering a custom chip ID.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _cfg_load(self):
        """Load a config file into the editor."""
        path = filedialog.askopenfilename(
            title="Load Config File",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            parser = CfgFileParser()
            chip_id = self._get_chip_id()
            parser.load(path, chip_id=chip_id)
            self.cfg_text.delete('1.0', tk.END)
            self.cfg_text.insert('1.0', parser.text_content)
            if parser.is_encrypted:
                self.crypto_chip_var.set(parser.chip_id)
                self._log(f"Loaded encrypted config: {path} (chip: {parser.chip_id})")
            else:
                self._log(f"Loaded plaintext config: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def _cfg_search(self):
        """Search for a value in the config editor."""
        query = self.cfg_search_var.get().strip()
        if not query:
            return
        content = self.cfg_text.get('1.0', tk.END)
        # Clear previous highlights
        self.cfg_text.tag_remove('search', '1.0', tk.END)
        # Find and highlight
        start = '1.0'
        count = 0
        while True:
            pos = self.cfg_text.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.cfg_text.tag_add('search', pos, end)
            start = end
            count += 1
        self.cfg_text.tag_configure('search', background='yellow', foreground='black')
        if count > 0:
            self.cfg_text.see(self.cfg_text.tag_ranges('search')[0])
        self._log(f"Config search '{query}': {count} match(es)")

    # ── Terminal Handlers ────────────────────────────────────────

    def _refresh_com_ports(self):
        """Refresh serial port list."""
        ports = SerialClient.list_ports()
        self.term_com_combo['values'] = [f"{p[0]} - {p[1]}" for p in ports]
        if ports:
            self.term_com_combo.current(0)

    def _term_connect(self):
        """Connect via telnet or serial."""
        conn_type = self.term_type_var.get()
        try:
            if conn_type == "Telnet":
                host = self.term_host_var.get().strip()
                port = int(self.term_port_var.get().strip())
                if not host:
                    messagebox.showwarning("No Host", "Enter the ONT IP address.")
                    return

                self.telnet_client = TelnetClient()
                self.telnet_client.on_data = self._term_on_data
                self.telnet_client.on_connect = lambda h, p: self._term_on_connect(f"Telnet {h}:{p}")
                self.telnet_client.on_disconnect = self._term_on_disconnect
                self.telnet_client.on_error = lambda msg: self._term_append(f"\n*** Error: {msg}\n")
                self.telnet_client.connect(host, port)

            else:  # Serial
                com = self.term_com_var.get().strip()
                if not com:
                    messagebox.showwarning("No Port", "Select a COM port.")
                    return
                port_name = com.split(' - ')[0].strip()
                baud = int(self.term_baud_var.get())

                self.serial_client = SerialClient()
                self.serial_client.on_data = self._term_on_data
                self.serial_client.on_connect = lambda p, b: self._term_on_connect(f"Serial {p} @ {b}")
                self.serial_client.on_disconnect = self._term_on_disconnect
                self.serial_client.on_error = lambda msg: self._term_append(f"\n*** Error: {msg}\n")
                self.serial_client.connect(port_name, baud)

        except ImportError as e:
            messagebox.showerror("Missing Library", str(e))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self._log(f"Terminal connect error: {e}")

    def _term_disconnect(self):
        """Disconnect terminal."""
        if self.telnet_client.connected:
            self.telnet_client.disconnect()
        if self.serial_client.connected:
            self.serial_client.disconnect()

    def _term_on_connect(self, info):
        """Handle terminal connection."""
        self.term_status_var.set(f"Connected: {info}")
        self.term_connect_btn.configure(state='disabled')
        self.term_disconnect_btn.configure(state='normal')
        self._term_append(f"*** Connected to {info}\n")
        self._log(f"Terminal connected: {info}")
        # Set up firmware dumper with the active client
        if self.telnet_client.connected:
            client = self.telnet_client
        elif self.serial_client.connected:
            client = self.serial_client
        else:
            client = None
        if client:
            self.firmware_dumper = FirmwareDumper(client)
            self.dump_status_var.set("Connected — Ready to read partitions")

    def _term_on_disconnect(self):
        """Handle terminal disconnection."""
        def _update():
            self.term_status_var.set("Disconnected")
            self.term_connect_btn.configure(state='normal')
            self.term_disconnect_btn.configure(state='disabled')
            self._term_append("\n*** Disconnected\n")
            self._log("Terminal disconnected")
            self.firmware_dumper = None
            self.dump_status_var.set("Connect via Terminal tab first")
        self.root.after(0, _update)

    def _term_on_data(self, text):
        """Handle incoming terminal data."""
        self.root.after(0, lambda: self._term_append(text))

    def _term_append(self, text):
        """Append text to terminal output."""
        self.term_output.configure(state='normal')
        self.term_output.insert(tk.END, text)
        self.term_output.see(tk.END)
        self.term_output.configure(state='disabled')

    def _term_send_input(self):
        """Send user input from the command entry."""
        text = self.term_input_var.get()
        self.term_input_var.set("")
        self._term_send_command(text)

    def _term_send_command(self, command):
        """Send a command to the connected device."""
        if self.telnet_client.connected:
            self.telnet_client.send_command(command)
            self._term_append(f"{command}\n")
        elif self.serial_client.connected:
            self.serial_client.send_command(command)
            self._term_append(f"{command}\n")
        else:
            self._term_append("*** Not connected. Use Connect button first.\n")

    # ── Firmware Dump Handlers ───────────────────────────────────

    def _dump_read_partitions(self):
        """Read MTD partition table from connected device."""
        if not self.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        self.dump_status_var.set("Reading partitions...")
        self._dump_log("Sending: cat /proc/mtd\n")
        self.firmware_dumper.get_mtd_partitions(callback=self._dump_partitions_loaded)

    def _dump_partitions_loaded(self, partitions):
        """Callback when partitions have been read."""
        def _update():
            # Clear existing items
            for item in self.dump_tree.get_children():
                self.dump_tree.delete(item)
            # Add partitions
            for p in partitions:
                size_str = f"{p['size']:,} bytes ({p['size'] / 1024 / 1024:.1f} MB)"
                erase_str = f"{p['erasesize']:,} bytes"
                self.dump_tree.insert('', tk.END, values=(
                    f"mtd{p['id']}", p['name'], size_str, erase_str))
            self.dump_status_var.set(f"Found {len(partitions)} partition(s)")
            self._dump_log(f"Found {len(partitions)} MTD partitions\n")
        self.root.after(0, _update)

    def _dump_selected(self):
        """Dump the selected partition."""
        if not self.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        selected = self.dump_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select a partition to dump.")
            return
        for item in selected:
            values = self.dump_tree.item(item, 'values')
            mtd_id = int(values[0].replace('mtd', ''))
            name = values[1]
            self._dump_log(f"Dumping mtd{mtd_id} ({name}) to /tmp/mtd{mtd_id}.bin...\n")
            self.firmware_dumper.dump_partition(mtd_id)
            self._log(f"Firmware dump: mtd{mtd_id} ({name})")

    def _dump_all(self):
        """Dump all partitions."""
        if not self.firmware_dumper:
            messagebox.showwarning("Not Connected",
                                   "Connect to the device via the Terminal tab first.")
            return
        if not self.firmware_dumper.partitions:
            messagebox.showwarning("No Partitions",
                                   "Read partitions first.")
            return
        if not messagebox.askyesno("Dump All",
                                    f"Dump all {len(self.firmware_dumper.partitions)} "
                                    f"partitions to /tmp on the device?"):
            return
        self._dump_log(f"Dumping all {len(self.firmware_dumper.partitions)} partitions...\n")
        self.firmware_dumper.dump_all_partitions()
        self._log("Firmware dump: all partitions")

    def _dump_log(self, text):
        """Append text to dump output."""
        self.dump_output.configure(state='normal')
        self.dump_output.insert(tk.END, text)
        self.dump_output.see(tk.END)
        self.dump_output.configure(state='disabled')

    # ── Theme ────────────────────────────────────────────────────

    def _apply_theme(self):
        """Apply the current theme to all widgets."""
        colors = THEMES[self.current_theme]

        if HAS_TTKB:
            # ttkbootstrap handles theming — just switch the theme name
            theme = TTKB_DARK if self.current_theme == 'dark' else TTKB_LIGHT
            try:
                ttkb.Style().theme_use(theme)
            except Exception:
                pass
            return

        try:
            self.style.theme_use('clam')
        except tk.TclError:
            pass

        self.style.configure('.',
                             background=colors['bg'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'],
                             focuscolor=colors['accent'],
                             )

        self.style.configure('TFrame', background=colors['bg'])
        self.style.configure('TLabel', background=colors['bg'], foreground=colors['fg'])
        self.style.configure('TLabelframe', background=colors['bg'],
                             foreground=colors['fg'])
        self.style.configure('TLabelframe.Label', background=colors['bg'],
                             foreground=colors['accent'],
                             font=('Segoe UI', 10, 'bold'))

        self.style.configure('TButton',
                             background=colors['surface_alt'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'],
                             padding=(8, 4))
        self.style.map('TButton',
                        background=[('active', colors['accent']),
                                    ('pressed', colors['accent_hover'])],
                        foreground=[('active', '#FFFFFF'),
                                    ('pressed', '#FFFFFF')])

        self.style.configure('TEntry',
                             fieldbackground=colors['surface'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'])

        self.style.configure('TCombobox',
                             fieldbackground=colors['surface'],
                             foreground=colors['fg'],
                             bordercolor=colors['border'])

        self.style.configure('TCheckbutton',
                             background=colors['bg'],
                             foreground=colors['fg'])

        self.style.configure('TNotebook',
                             background=colors['bg'],
                             bordercolor=colors['border'])
        self.style.configure('TNotebook.Tab',
                             background=colors['surface_alt'],
                             foreground=colors['fg'],
                             padding=(12, 6))
        self.style.map('TNotebook.Tab',
                        background=[('selected', colors['surface'])],
                        foreground=[('selected', colors['accent'])])

        self.style.configure('Horizontal.TProgressbar',
                             background=colors['progress_fg'],
                             troughcolor=colors['progress_bg'],
                             bordercolor=colors['border'])

    def _toggle_theme(self):
        """Toggle between light and dark themes."""
        self.current_theme = 'light' if self.current_theme == 'dark' else 'dark'
        self.theme_btn.configure(
            text="🌙 Dark" if self.current_theme == 'dark' else "☀️ Light"
        )
        self._apply_theme()

        if not HAS_TTKB:
            self.root.configure(bg=THEMES[self.current_theme]['bg'])

        # Update text widgets
        colors = THEMES[self.current_theme]
        for text_widget in [self.log_text, self.info_text, self.preset_details_text,
                            self.cfg_text, self.dump_output]:
            text_widget.configure(
                bg=colors['log_bg'],
                fg=colors['log_fg'],
                insertbackground=colors['fg'],
            )

    # ── Adapter Management ───────────────────────────────────────

    def _refresh_adapters(self):
        """Refresh the list of network adapters.

        Ethernet adapters are sorted first because the OBSC protocol
        requires a wired LAN connection to the ONT device.
        """
        self.adapters = discover_adapters()
        # Sort: Ethernet adapters first (match original tool: "本地网卡")
        def _eth_sort_key(a):
            name_lower = (a.name + " " + a.description).lower()
            if 'ethernet' in name_lower or 'eth' in name_lower or 'lan' in name_lower:
                return 0
            if 'wi-fi' in name_lower or 'wireless' in name_lower or 'wlan' in name_lower:
                return 2
            return 1
        self.adapters.sort(key=_eth_sort_key)
        names = [a.display_name() for a in self.adapters]
        self.adapter_combo['values'] = names
        if names:
            self.adapter_combo.current(0)
            self._on_adapter_selected(None)
        self._log(f"Found {len(self.adapters)} network adapter(s)")
        # Also refresh the config adapter combo in Settings tab
        self._refresh_cfg_adapters()

    def _on_adapter_selected(self, event):
        """Update adapter detail display when selection changes."""
        adapter = self._get_selected_adapter()
        if adapter:
            details = adapter.details_dict()
            text = "  |  ".join(f"{k}: {v}" for k, v in details.items()
                                if v and v != "N/A" and k not in ("Name",))
            self.adapter_detail_var.set(text)
        else:
            self.adapter_detail_var.set("")

    def _get_selected_adapter(self):
        """Get the currently selected NetworkAdapter."""
        idx = self.adapter_combo.current()
        if idx >= 0 and idx < len(self.adapters):
            return self.adapters[idx]
        return None

    def _refresh_cfg_adapters(self):
        """Refresh the adapter list in the Network Configuration section."""
        if hasattr(self, 'cfg_adapter_combo'):
            names = [a.name for a in self.adapters]
            self.cfg_adapter_combo['values'] = names
            if names:
                self.cfg_adapter_combo.current(0)

    def _apply_static_ip(self):
        """Apply static IP configuration to the selected adapter."""
        adapter_name = self.cfg_adapter_var.get()
        if not adapter_name:
            messagebox.showwarning("No Adapter", "Select an adapter to configure.")
            return

        ip = self.cfg_ip_var.get().strip()
        mask = self.cfg_mask_var.get().strip()
        gw = self.cfg_gw_var.get().strip()

        if not ip or not mask:
            messagebox.showwarning("Missing Info", "IP address and subnet mask are required.")
            return

        if not messagebox.askyesno(
            "Confirm Network Change",
            f"Set {adapter_name} to:\n\n"
            f"  IP: {ip}\n  Mask: {mask}\n  GW: {gw or 'none'}\n\n"
            "⚠️ Requires administrator privileges.\n"
            "This may temporarily disconnect the adapter."
        ):
            return

        self.net_status_var.set("Applying...")
        self.root.update_idletasks()

        ok, msg = configure_adapter_ip(adapter_name, ip, mask, gw)
        self.net_status_var.set(("✅ " if ok else "❌ ") + msg)
        self._log(f"Network config: {msg}")
        if ok:
            self.root.after(2000, self._refresh_adapters)

    def _apply_dhcp(self):
        """Set the selected adapter to DHCP mode."""
        adapter_name = self.cfg_adapter_var.get()
        if not adapter_name:
            messagebox.showwarning("No Adapter", "Select an adapter to configure.")
            return

        if not messagebox.askyesno(
            "Confirm DHCP",
            f"Set {adapter_name} to DHCP?\n\n"
            "⚠️ Requires administrator privileges."
        ):
            return

        self.net_status_var.set("Applying DHCP...")
        self.root.update_idletasks()

        ok, msg = set_adapter_dhcp(adapter_name)
        self.net_status_var.set(("✅ " if ok else "❌ ") + msg)
        self._log(f"Network config: {msg}")
        if ok:
            self.root.after(3000, self._refresh_adapters)

    def _test_socket(self):
        """Test socket binding to verify network is ready."""
        adapter = self._get_selected_adapter()
        bind_ip = adapter.ip if adapter else "0.0.0.0"
        bind_port = int(self.recv_port_var.get())

        ok, msg = test_socket_bind(bind_ip, bind_port, broadcast=True)
        self.net_status_var.set(("✅ " if ok else "❌ ") + msg)
        self._log(f"Socket test: {msg}")

    # ── IP Mode Management ──────────────────────────────────────

    def _on_ip_mode_changed(self):
        """Handle IP Mode radio button change."""
        mode = self.ip_mode_var.get()
        if mode == "manual":
            # Show manual fields, enable editing
            self.ip_manual_frame.pack(fill=tk.X, pady=(5, 0))
            self.ip_mode_ip_entry.configure(state='normal')
            self.ip_mode_mask_entry.configure(state='normal')
            self.ip_mode_gw_entry.configure(state='normal')
            self.ip_mode_status_var.set(
                "Enter Ethernet adapter IP settings and click Apply")
        elif mode == "automatic":
            # Show fields with defaults (read-only)
            self.ip_manual_frame.pack(fill=tk.X, pady=(5, 0))
            self.ip_mode_ip_var.set(IP_MODE_DEFAULTS['ip'])
            self.ip_mode_mask_var.set(IP_MODE_DEFAULTS['netmask'])
            self.ip_mode_gw_var.set(IP_MODE_DEFAULTS['gateway'])
            self.ip_mode_ip_entry.configure(state='readonly')
            self.ip_mode_mask_entry.configure(state='readonly')
            self.ip_mode_gw_entry.configure(state='readonly')
            self.ip_mode_status_var.set(
                f"Automatic: IP {IP_MODE_DEFAULTS['ip']}  "
                f"Mask {IP_MODE_DEFAULTS['netmask']}  "
                f"Gateway {IP_MODE_DEFAULTS['gateway']} (ONT default)"
            )
        else:  # dhcp
            self.ip_manual_frame.pack_forget()
            self.ip_mode_status_var.set(
                "DHCP: Ethernet adapter will obtain IP automatically")

    def _apply_ip_mode(self):
        """Apply the selected IP mode to the currently selected adapter."""
        adapter = self._get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter",
                                   "Select a network adapter first (above).")
            return

        mode = self.ip_mode_var.get()
        adapter_name = adapter.name

        if mode == "dhcp":
            if not messagebox.askyesno(
                "Confirm DHCP",
                f"Set '{adapter_name}' to DHCP?\n\n"
                "⚠️ Requires administrator privileges."
            ):
                return
            self.ip_mode_status_var.set("Applying DHCP…")
            self.root.update_idletasks()
            ok, msg = set_adapter_dhcp(adapter_name)
        else:
            ip = self.ip_mode_ip_var.get().strip()
            mask = self.ip_mode_mask_var.get().strip()
            gw = self.ip_mode_gw_var.get().strip()
            if not ip or not mask:
                messagebox.showwarning("Missing Info",
                                       "IP and subnet mask are required.")
                return
            label = "Automatic (ONT default)" if mode == "automatic" else "Manual"
            if not messagebox.askyesno(
                f"Confirm {label} IP",
                f"Configure '{adapter_name}' with:\n\n"
                f"  IP: {ip}\n  Mask: {mask}\n  Gateway: {gw or 'none'}\n\n"
                "⚠️ Requires administrator privileges.\n"
                "The adapter may briefly disconnect."
            ):
                return
            self.ip_mode_status_var.set("Applying…")
            self.root.update_idletasks()
            ok, msg = configure_adapter_ip(adapter_name, ip, mask, gw)

        self.ip_mode_status_var.set(("✅ " if ok else "❌ ") + msg)
        self._log(f"IP Mode ({mode}): {msg}")
        if ok:
            self.root.after(2000, self._refresh_adapters)

    # ── Firmware Management ──────────────────────────────────────

    def _browse_firmware(self):
        """Open file dialog to select firmware file."""
        path = filedialog.askopenfilename(
            title="Select Firmware File",
            filetypes=[
                ("Firmware files", "*.bin"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        self.fw_path_var.set(path)
        self._load_firmware(path)

    def _load_firmware(self, path):
        """Load and validate an HWNP firmware file."""
        try:
            fw = HWNPFirmware()
            fw.load(path)

            # Validate CRC
            hdr_ok, data_ok = fw.validate_crc32()
            crc_status = "✅" if (hdr_ok and data_ok) else "⚠️"

            self.firmware = fw
            self.firmware_path = path

            size_mb = len(fw.raw_data) / (1024 * 1024)
            self.fw_info_var.set(
                f"{crc_status} HWNP | {fw.item_count} items | "
                f"{size_mb:.2f} MB | Products: {fw.product_list[:50]}"
            )

            # Update info tab
            self._update_firmware_info()
            self._log(f"Loaded firmware: {os.path.basename(path)} ({size_mb:.2f} MB, {fw.item_count} items)")

        except (ValueError, FileNotFoundError) as e:
            self.firmware = None
            self.fw_info_var.set(f"❌ Error: {e}")
            self._log(f"Failed to load firmware: {e}")
            messagebox.showerror("Firmware Error", str(e))

    def _update_firmware_info(self):
        """Update the firmware info tab with details."""
        if not self.firmware:
            return

        info = self.firmware.get_info()
        hdr_ok, data_ok = self.firmware.validate_crc32()

        lines = [
            f"File: {info['file']}",
            f"Size: {info['size']:,} bytes ({info['size']/1024/1024:.2f} MB)",
            f"Items: {info['items']}",
            f"Products: {info['products']}",
            f"Header CRC32: {'VALID ✅' if hdr_ok else 'INVALID ❌'}",
            f"Data CRC32: {'VALID ✅' if data_ok else 'INVALID ❌'}",
            "",
            "=" * 60,
            "Items:",
            "=" * 60,
        ]

        for item in info['items_detail']:
            lines.append(f"")
            lines.append(f"  [{item['index']}] {item['path']}")
            lines.append(f"      Section: {item['section']}")
            lines.append(f"      Version: {item['version']}")
            lines.append(f"      Size: {item['size']:,} bytes")
            lines.append(f"      CRC32: {item['crc32']}")
            lines.append(f"      Policy: {item['policy']}")

        self.info_text.configure(state='normal')
        self.info_text.delete('1.0', tk.END)
        self.info_text.insert('1.0', '\n'.join(lines))
        self.info_text.configure(state='disabled')

    # ── Discovery ────────────────────────────────────────────────

    def _discover_devices(self):
        """Start device discovery."""
        adapter = self._get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first.")
            return

        self._log(f"Starting discovery on {adapter.ip}...")
        self.discover_btn.configure(state='disabled')

        try:
            if self.transport:
                self.transport.close()

            self.transport = UDPTransport(
                bind_ip=adapter.ip,
                bind_port=int(self.recv_port_var.get()),
                dest_port=int(self.send_port_var.get()),
                broadcast=True,
            )
            self.transport.open()

            self.worker = OBSCWorker(self.transport, adapter)
            self.worker.on_device_found = self._on_device_found
            self.worker.on_status = self._on_status
            self.worker.on_log = self._on_worker_log
            self.worker.on_error = self._on_error

            self.worker.start_discovery(duration=int(self.discovery_duration_var.get()))

            # Re-enable button after discovery
            duration_ms = int(self.discovery_duration_var.get()) * 1000 + 1000
            self.root.after(duration_ms, lambda: self.discover_btn.configure(state='normal'))

        except Exception as e:
            self._log(f"Discovery error: {e}")
            messagebox.showerror("Discovery Error", str(e))
            self.discover_btn.configure(state='normal')
            if self.transport:
                self.transport.close()

    def _on_device_found(self, device):
        """Callback when a device is discovered."""
        self.root.after(0, lambda: self._log(
            f"📡 Device: {device.ip} | SN: {device.board_sn} | MAC: {device.mac}"
        ))

    # ── Upgrade ──────────────────────────────────────────────────

    def _start_upgrade(self):
        """Start the firmware upgrade process."""
        adapter = self._get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first.")
            return

        if not self.firmware:
            messagebox.showwarning("No Firmware", "Please select a firmware file first.")
            return

        # Pre-flash verification
        if self.verify_crc32_var.get():
            hdr_ok, data_ok = self.firmware.validate_crc32()
            if not hdr_ok or not data_ok:
                if not messagebox.askyesno(
                    "CRC32 Warning",
                    "Firmware CRC32 verification failed!\n\n"
                    f"Header CRC32: {'VALID' if hdr_ok else 'INVALID'}\n"
                    f"Data CRC32: {'VALID' if data_ok else 'INVALID'}\n\n"
                    "Continue anyway?"
                ):
                    return

        if self.verify_item_crc_var.get():
            self._log("Verifying individual item CRC32 checksums...")
            for item in self.firmware.items:
                if item.data and item.crc32:
                    calc_crc = zlib.crc32(item.data) & 0xFFFFFFFF
                    if calc_crc != item.crc32:
                        self._log(f"⚠️ Item CRC32 mismatch: {item.item_path} "
                                  f"(expected 0x{item.crc32:08X}, got 0x{calc_crc:08X})")
                        if not messagebox.askyesno(
                            "Item CRC32 Warning",
                            f"Item CRC32 mismatch for:\n{item.item_path}\n\n"
                            f"Expected: 0x{item.crc32:08X}\n"
                            f"Calculated: 0x{calc_crc:08X}\n\n"
                            "Continue anyway?"
                        ):
                            return

        # Dry run check
        if self.dry_run_var.get():
            self._log("✅ Dry run complete — all pre-flash checks passed")
            messagebox.showinfo("Dry Run", "All pre-flash verification checks passed.\n"
                                "No data was sent (dry run mode).")
            return

        # Confirm
        size_mb = len(self.firmware.raw_data) / (1024 * 1024)
        if not messagebox.askyesno(
            "Confirm Upgrade",
            f"Flash firmware to all ONT devices on the network?\n\n"
            f"File: {os.path.basename(self.firmware_path)}\n"
            f"Size: {size_mb:.2f} MB\n"
            f"Frame Size: {self.frame_size_var.get()} bytes\n"
            f"Frame Interval: {self.frame_interval_var.get()} ms\n"
            f"Flash Mode: {self.flash_mode_var.get()}\n"
            f"Delete Config: {'Yes' if self.delete_cfg_var.get() else 'No'}\n\n"
            f"⚠️ Do not disconnect power during the upgrade!"
        ):
            return

        self._set_upgrading(True)

        try:
            if self.transport:
                self.transport.close()

            self.transport = UDPTransport(
                bind_ip=adapter.ip,
                bind_port=int(self.recv_port_var.get()),
                dest_port=int(self.send_port_var.get()),
                broadcast=True,
            )
            self.transport.open()

            self.worker = OBSCWorker(self.transport, adapter)
            self.worker.frame_size = int(self.frame_size_var.get())
            self.worker.frame_interval_ms = int(self.frame_interval_var.get())
            self.worker.flash_mode = FlashMode.FORCED if self.flash_mode_var.get() == "Forced" else FlashMode.NORMAL
            self.worker.delete_cfg = self.delete_cfg_var.get()
            self.worker.timeout = int(self.timeout_var.get())
            self.worker.machine_filter = self.machine_filter_var.get()
            self.worker.ctrl_retries = int(self.ctrl_retries_var.get())
            self.worker.data_retries = int(self.data_retries_var.get())

            # Map upgrade type
            ut_map = {"Standard": UpgradeType.STANDARD,
                      "Equipment": UpgradeType.EQUIPMENT,
                      "Equipment WC": UpgradeType.EQUIPMENT_WC}
            self.worker.upgrade_type = ut_map.get(self.upgrade_type_var.get(), UpgradeType.STANDARD)

            # Set callbacks
            self.worker.on_progress = self._on_progress
            self.worker.on_status = self._on_status
            self.worker.on_log = self._on_worker_log
            self.worker.on_complete = self._on_complete
            self.worker.on_error = self._on_error

            # Start upgrade
            self.worker.start_upgrade(self.firmware.raw_data)

        except Exception as e:
            self._log(f"Upgrade start error: {e}")
            messagebox.showerror("Error", str(e))
            self._set_upgrading(False)
            if self.transport:
                self.transport.close()

    def _stop_upgrade(self):
        """Stop the current upgrade."""
        if self.worker:
            self.worker.stop()
        self._set_upgrading(False)
        if self.transport:
            self.transport.close()
            self.transport = None
        self._log("Upgrade stopped by user")

    def _set_upgrading(self, active):
        """Toggle UI state for upgrade in progress."""
        if active:
            self.start_btn.configure(state='disabled')
            self.stop_btn.configure(state='normal')
            self.discover_btn.configure(state='disabled')
            self.progress_var.set(0)
        else:
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')
            self.discover_btn.configure(state='normal')

    # ── Callbacks (thread-safe) ──────────────────────────────────

    def _on_progress(self, percent, detail_text):
        """Progress callback from worker thread."""
        self.root.after(0, lambda: self.progress_var.set(percent))
        self.root.after(0, lambda: self.progress_detail_var.set(detail_text))

    def _on_status(self, text):
        """Status callback from worker thread."""
        self.root.after(0, lambda: self.status_var.set(text))

    def _on_worker_log(self, text):
        """Log callback from worker thread."""
        self.root.after(0, lambda: self._log(text))

    def _on_complete(self, success, message):
        """Completion callback from worker thread."""
        self.root.after(0, lambda: self._set_upgrading(False))
        self.root.after(0, lambda: self._log(
            f"{'✅' if success else '❌'} Upgrade {'complete' if success else 'failed'}: {message}"
        ))

        if self.auto_log_var.get():
            self.root.after(100, self._auto_save_log)

        if self.transport:
            self.root.after(0, lambda: self.transport.close())

    def _on_error(self, text):
        """Error callback from worker thread."""
        self.root.after(0, lambda: self._log(f"❌ ERROR: {text}"))
        self.root.after(0, lambda: self._set_upgrading(False))
        self.root.after(0, lambda: messagebox.showerror("Error", text))

    # ── Logging ──────────────────────────────────────────────────

    def _log(self, message):
        """Add a timestamped message to the log."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log_entries.append(entry)

        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, entry + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def _clear_log(self):
        """Clear the log panel."""
        self.log_entries.clear()
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.configure(state='disabled')

    def _export_log(self):
        """Export log to file."""
        # Log filename matches original Huawei tool format (OSBC_LOG_*)
        path = filedialog.asksaveasfilename(
            title="Export Log",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
            initialfile=f"OBSC_LOG_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log",
        )
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.log_entries))
            self._log(f"Log exported to {path}")

    def _auto_save_log(self):
        """Auto-save log after upgrade."""
        try:
            log_dir = self.log_dir_var.get()
            os.makedirs(log_dir, exist_ok=True)
            filename = f"OBSC_LOG_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log"
            path = os.path.join(log_dir, filename)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.log_entries))
            self._log(f"Log auto-saved to {path}")
        except OSError as e:
            self._log(f"Failed to auto-save log: {e}")

    def _browse_log_dir(self):
        """Browse for log directory."""
        path = filedialog.askdirectory(title="Select Log Directory")
        if path:
            self.log_dir_var.set(path)

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
