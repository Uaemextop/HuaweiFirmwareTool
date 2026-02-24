"""Upgrade tab mixin for HuaweiFlash."""

import os
import time
import zlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from hwflash.shared.helpers import safe_int as _safe_int
from hwflash.shared.styles import LEGACY_IP_DEFAULTS as IP_MODE_DEFAULTS
from hwflash.shared.styles import OBSC_MULTICAST_ADDR, DEVICE_STALE_TIMEOUT
from hwflash.core.firmware import HWNPFirmware
from hwflash.core.network import UDPTransport
from hwflash.core.protocol import (
    OBSCWorker, FlashMode, UpgradeType,
    OBSC_SEND_PORT, OBSC_RECV_PORT,
)


class UpgradeTabMixin:
    """Mixin providing the Upgrade tab and related methods."""

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
            text="🔄 Automatic (DHCP + Multicast 224.0.0.9)",
            variable=self.ip_mode_var, value="automatic",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(
            mode_row, text="✏️ Manual",
            variable=self.ip_mode_var, value="manual",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(
            mode_row, text="🌐 DHCP Only",
            variable=self.ip_mode_var, value="dhcp",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT)

        # Manual IP fields (shown/hidden depending on mode)
        self.ip_manual_frame = ttk.Frame(ip_frame)

        # Row 1: IP + Mask
        ip_row1 = ttk.Frame(self.ip_manual_frame)
        ip_row1.pack(fill=tk.X, pady=2)
        ttk.Label(ip_row1, text="IP Address:", width=12).pack(side=tk.LEFT)
        self.ip_mode_ip_var = tk.StringVar(value=IP_MODE_DEFAULTS['ip'])
        self.ip_mode_ip_entry = ttk.Entry(
            ip_row1, textvariable=self.ip_mode_ip_var, width=16)
        self.ip_mode_ip_entry.pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(ip_row1, text="Subnet Mask:", width=12).pack(side=tk.LEFT)
        self.ip_mode_mask_var = tk.StringVar(value=IP_MODE_DEFAULTS['netmask'])
        self.ip_mode_mask_entry = ttk.Entry(
            ip_row1, textvariable=self.ip_mode_mask_var, width=16)
        self.ip_mode_mask_entry.pack(side=tk.LEFT)

        # Row 2: Gateway + DNS
        ip_row2 = ttk.Frame(self.ip_manual_frame)
        ip_row2.pack(fill=tk.X, pady=2)
        ttk.Label(ip_row2, text="Gateway:", width=12).pack(side=tk.LEFT)
        self.ip_mode_gw_var = tk.StringVar(value=IP_MODE_DEFAULTS['gateway'])
        self.ip_mode_gw_entry = ttk.Entry(
            ip_row2, textvariable=self.ip_mode_gw_var, width=16)
        self.ip_mode_gw_entry.pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(ip_row2, text="DNS:", width=12).pack(side=tk.LEFT)
        self.ip_mode_dns_var = tk.StringVar(value=IP_MODE_DEFAULTS.get('dns1', '8.8.8.8'))
        self.ip_mode_dns_entry = ttk.Entry(
            ip_row2, textvariable=self.ip_mode_dns_var, width=16)
        self.ip_mode_dns_entry.pack(side=tk.LEFT)

        # Apply button row (always visible when a mode is active)
        self.ip_apply_frame = ttk.Frame(ip_frame)
        self.ip_apply_frame.pack(fill=tk.X, pady=(5, 0))
        self.ip_mode_apply_btn = ttk.Button(
            self.ip_apply_frame, text="⚡ Apply IP Mode",
            command=self._apply_ip_mode, width=18)
        self.ip_mode_apply_btn.pack(side=tk.LEFT)

        # Status line
        self.ip_mode_status_var = tk.StringVar(value="")
        ttk.Label(ip_frame, textvariable=self.ip_mode_status_var,
                  font=('Segoe UI', 9)).pack(fill=tk.X, pady=(3, 0))

        # Initial state
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

        # ── Device Table ─────────────────────────────────────────
        dev_frame = ttk.LabelFrame(
            tab, text="Detected Devices (auto-updates during discovery & flash)",
            padding=8)
        dev_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        dev_columns = ('ip', 'mac', 'sn', 'model', 'status', 'progress')
        self.device_tree = ttk.Treeview(
            dev_frame, columns=dev_columns, show='headings', height=5)
        self.device_tree.heading('ip', text='IP Address')
        self.device_tree.heading('mac', text='MAC')
        self.device_tree.heading('sn', text='Serial Number')
        self.device_tree.heading('model', text='Model')
        self.device_tree.heading('status', text='Status')
        self.device_tree.heading('progress', text='Progress')
        self.device_tree.column('ip', width=130)
        self.device_tree.column('mac', width=140)
        self.device_tree.column('sn', width=140)
        self.device_tree.column('model', width=100)
        self.device_tree.column('status', width=120)
        self.device_tree.column('progress', width=100)

        dev_scroll = ttk.Scrollbar(dev_frame, orient=tk.VERTICAL,
                                   command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=dev_scroll.set)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dev_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Tracked devices: {ip: {item_id, device, last_seen}}
        self._tracked_devices = {}

        # Start stale-device checker
        self._check_stale_devices()

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

        except Exception as e:
            self.firmware = None
            self.fw_info_var.set(f"❌ Error: {e}")
            self._log(f"Failed to load firmware: {e}")
            messagebox.showerror("Firmware Error", str(e))

    def _update_firmware_info(self):
        """Update the firmware info tab with details."""
        if not self.firmware:
            return

        # Refresh the new tree-based view
        self._refresh_fw_info()

    # ── Discovery ────────────────────────────────────────────────

    def _validate_adapter_ip(self, adapter):
        """Check that the adapter has a valid IP. Shows warning if not. Returns True if valid."""
        if not adapter.ip or adapter.ip == "0.0.0.0":
            messagebox.showwarning("No IP Address",
                                   "The selected adapter has no IP address.\n"
                                   "Configure an IP address first (IP Mode section).")
            return False
        return True

    def _discover_devices(self):
        """Start device discovery."""
        adapter = self._get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first.")
            return

        if not self._validate_adapter_ip(adapter):
            return

        use_multicast = (self.ip_mode_var.get() == "automatic")
        mc_label = f" + multicast {OBSC_MULTICAST_ADDR}" if use_multicast else ""
        self._log(f"Starting discovery on {adapter.ip}{mc_label}...")
        self.discover_btn.configure(state='disabled')

        try:
            if self.transport:
                self.transport.close()

            self.transport = UDPTransport(
                bind_ip=adapter.ip,
                bind_port=_safe_int(self.recv_port_var.get(), OBSC_RECV_PORT),
                dest_port=_safe_int(self.send_port_var.get(), OBSC_SEND_PORT),
                broadcast=True,
                multicast_group=OBSC_MULTICAST_ADDR if use_multicast else None,
            )
            self.transport.open()

            self.worker = OBSCWorker(self.transport, adapter)
            self.worker.on_device_found = self._on_device_found
            self.worker.on_status = self._on_status
            self.worker.on_log = self._on_worker_log
            self.worker.on_error = self._on_error
            if use_multicast:
                self.worker.multicast_addr = OBSC_MULTICAST_ADDR

            self.worker.start_discovery(duration=_safe_int(self.discovery_duration_var.get(), 10))

            # Re-enable button after discovery
            duration_ms = _safe_int(self.discovery_duration_var.get(), 10) * 1000 + 1000
            self.root.after(duration_ms, lambda: self.discover_btn.configure(state='normal'))

        except Exception as e:
            self._log(f"Discovery error: {e}")
            messagebox.showerror("Discovery Error", str(e))
            self.discover_btn.configure(state='normal')
            if self.transport:
                self.transport.close()

    def _on_device_found(self, device):
        """Callback when a device is discovered — add/update the device table."""
        self.root.after(0, lambda: self._update_device_table(device))

    def _update_device_table(self, device):
        """Add or update a device row in the table."""
        ip = device.ip
        now = time.time()
        if ip in self._tracked_devices:
            # Update existing
            item_id = self._tracked_devices[ip]['item_id']
            self._tracked_devices[ip]['last_seen'] = now
            self._tracked_devices[ip]['device'] = device
            self.device_tree.item(item_id, values=(
                ip, device.mac or "—", device.board_sn or "—",
                device.model or "—", device.status, "—"))
        else:
            # Insert new
            item_id = self.device_tree.insert('', tk.END, values=(
                ip, device.mac or "—", device.board_sn or "—",
                device.model or "—", device.status, "—"))
            self._tracked_devices[ip] = {
                'item_id': item_id,
                'device': device,
                'last_seen': now,
            }
        self._log(f"📡 Device: {ip} | SN: {device.board_sn} | MAC: {device.mac}")

    def _update_device_progress(self, ip, status, progress_text):
        """Update flash progress for a device in the table."""
        if ip in self._tracked_devices:
            item_id = self._tracked_devices[ip]['item_id']
            dev = self._tracked_devices[ip]['device']
            self.device_tree.item(item_id, values=(
                ip, dev.mac or "—", dev.board_sn or "—",
                dev.model or "—", status, progress_text))
            self._tracked_devices[ip]['last_seen'] = time.time()

    def _check_stale_devices(self):
        """Remove devices that haven't been seen for DEVICE_STALE_TIMEOUT seconds."""
        now = time.time()
        stale = [ip for ip, info in self._tracked_devices.items()
                 if now - info['last_seen'] > DEVICE_STALE_TIMEOUT]
        for ip in stale:
            item_id = self._tracked_devices[ip]['item_id']
            try:
                self.device_tree.delete(item_id)
            except tk.TclError:
                pass
            del self._tracked_devices[ip]
            self._log(f"📡 Device lost: {ip}")
        # Schedule next check
        self.root.after(5000, self._check_stale_devices)

    # ── Upgrade ──────────────────────────────────────────────────

    def _start_upgrade(self):
        """Start the firmware upgrade process."""
        adapter = self._get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first.")
            return

        if not self._validate_adapter_ip(adapter):
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
                bind_port=_safe_int(self.recv_port_var.get(), OBSC_RECV_PORT),
                dest_port=_safe_int(self.send_port_var.get(), OBSC_SEND_PORT),
                broadcast=True,
            )
            self.transport.open()

            self.worker = OBSCWorker(self.transport, adapter)
            self.worker.frame_size = _safe_int(self.frame_size_var.get(), 1400)
            self.worker.frame_interval_ms = _safe_int(self.frame_interval_var.get(), 5)
            self.worker.flash_mode = FlashMode.FORCED if self.flash_mode_var.get() == "Forced" else FlashMode.NORMAL
            self.worker.delete_cfg = self.delete_cfg_var.get()
            self.worker.timeout = _safe_int(self.timeout_var.get(), 600)
            self.worker.machine_filter = self.machine_filter_var.get()
            self.worker.ctrl_retries = _safe_int(self.ctrl_retries_var.get(), 3)
            self.worker.data_retries = _safe_int(self.data_retries_var.get(), 0)

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
