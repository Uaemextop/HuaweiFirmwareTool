"""
OBSC Firmware Tool — Main GUI Application

Modern Windows 11 themed GUI for Huawei ONT firmware flashing.
Uses tkinter with ttk for a native look and feel.

Features:
  - Network adapter selection with auto-detection
  - Firmware file browser with HWNP validation
  - Configurable transfer parameters (frame size, interval, flash mode)
  - Real-time progress with speed and ETA
  - Device discovery list
  - Audit log with export
  - Dark / Light theme toggle
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import datetime
import logging
import zlib

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obsc_tool import __version__
from obsc_tool.firmware import HWNPFirmware
from obsc_tool.network import discover_adapters, UDPTransport
from obsc_tool.protocol import (
    OBSCWorker, FlashMode, UpgradeType,
    OBSC_SEND_PORT, OBSC_RECV_PORT
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

        # Tab 2: Settings
        self.tab_settings = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_settings, text=" ⚙️ Settings ")
        self._build_settings_tab()

        # Tab 3: Firmware Info
        self.tab_info = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_info, text=" 📋 Firmware Info ")
        self._build_info_tab()

        # Tab 4: Log
        self.tab_log = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_log, text=" 📝 Log ")
        self._build_log_tab()

    def _build_upgrade_tab(self):
        """Build the main upgrade tab."""
        tab = self.tab_upgrade

        # ── Network Adapter ──────────────────────────────────────
        adapter_frame = ttk.LabelFrame(tab, text="Network Adapter", padding=8)
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

    # ── Theme ────────────────────────────────────────────────────

    def _apply_theme(self):
        """Apply the current theme to all widgets."""
        colors = THEMES[self.current_theme]

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
        self.root.configure(bg=THEMES[self.current_theme]['bg'])

        # Update text widgets
        colors = THEMES[self.current_theme]
        for text_widget in [self.log_text, self.info_text]:
            text_widget.configure(
                bg=colors['log_bg'],
                fg=colors['log_fg'],
                insertbackground=colors['fg'],
            )

    # ── Adapter Management ───────────────────────────────────────

    def _refresh_adapters(self):
        """Refresh the list of network adapters."""
        self.adapters = discover_adapters()
        names = [a.display_name() for a in self.adapters]
        self.adapter_combo['values'] = names
        if names:
            self.adapter_combo.current(0)
        self._log(f"Found {len(self.adapters)} network adapter(s)")

    def _get_selected_adapter(self):
        """Get the currently selected NetworkAdapter."""
        idx = self.adapter_combo.current()
        if idx >= 0 and idx < len(self.adapters):
            return self.adapters[idx]
        return None

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

            self.worker.start_discovery(duration=10)

            # Re-enable button after discovery
            self.root.after(11000, lambda: self.discover_btn.configure(state='normal'))

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
        path = filedialog.asksaveasfilename(
            title="Export Log",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")],
            initialfile=f"OSBC_LOG_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log",
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
            filename = f"OSBC_LOG_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log"
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

        if self.transport:
            self.transport.close()

        self.root.destroy()


def main():
    """Application entry point."""
    root = tk.Tk()

    # High-DPI awareness for Windows 11
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError, OSError):
        pass

    app = OBSCToolApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
