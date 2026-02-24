"""Upgrade tab — firmware flashing UI."""

from __future__ import annotations

import os
import time
import zlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import TYPE_CHECKING

from hwflash.shared.helpers import safe_int as _safe_int
from hwflash.shared.constants import OBSC_MULTICAST_ADDR, DEVICE_STALE_TIMEOUT
from hwflash.core.firmware import HWNPFirmware
from hwflash.core.network import UDPTransport
from hwflash.core.protocol import (
    OBSCWorker, FlashMode, UpgradeType,
    OBSC_SEND_PORT, OBSC_RECV_PORT,
)
from hwflash.shared.styles import FONT_FAMILY

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


class UpgradeTab(ttk.Frame):
    """Firmware upgrade tab."""

    def __init__(self, parent, state: AppState, ctrl: AppController,
                 engine: ThemeEngine, **kwargs):
        super().__init__(parent, padding=10, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self._tracked_devices: dict = {}
        self._build()
        self._check_stale_devices()

    # ── Build ────────────────────────────────────────────────────

    def _build(self):
        s = self.s

        # Adapter
        adapter_frame = ttk.LabelFrame(self, text="Ethernet Adapter", padding=8)
        adapter_frame.pack(fill=tk.X, pady=(0, 6))

        adapter_row = ttk.Frame(adapter_frame)
        adapter_row.pack(fill=tk.X)

        self.adapter_combo = ttk.Combobox(
            adapter_row, textvariable=s.adapter_var,
            state='readonly', width=55,
        )
        self.adapter_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.ctrl.bind_adapter_combo(self.adapter_combo)

        ttk.Button(
            adapter_row, text="Refresh",
            command=self.ctrl.refresh_adapters, width=11,
        ).pack(side=tk.RIGHT)

        ttk.Label(adapter_frame, textvariable=s.adapter_detail_var,
                  font=("Consolas", 8), justify=tk.LEFT).pack(fill=tk.X, pady=(3, 0))

        self.adapter_combo.bind('<<ComboboxSelected>>', self._on_adapter_selected)

        # Firmware
        fw_frame = ttk.LabelFrame(self, text="Firmware File", padding=8)
        fw_frame.pack(fill=tk.X, pady=(0, 6))

        fw_row = ttk.Frame(fw_frame)
        fw_row.pack(fill=tk.X)

        ttk.Entry(fw_row, textvariable=s.fw_path_var, state='readonly', width=55).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        ttk.Button(fw_row, text="Browse", command=self._browse_firmware, width=11).pack(side=tk.RIGHT)

        ttk.Label(fw_frame, textvariable=s.fw_info_var, font=(FONT_FAMILY, 9)).pack(fill=tk.X, pady=(3, 0))

        # Transfer config
        config_frame = ttk.LabelFrame(self, text="Transfer Configuration", padding=8)
        config_frame.pack(fill=tk.X, pady=(0, 6))

        g = ttk.Frame(config_frame)
        g.pack(fill=tk.X)

        ttk.Label(g, text="Frame Size:").grid(row=0, column=0, sticky='w', padx=(0, 4))
        ttk.Combobox(g, textvariable=s.frame_size_var,
                     values=["1200", "1400", "1472", "4096", "8192"],
                     state='readonly', width=8).grid(row=0, column=1, padx=(0, 12))

        ttk.Label(g, text="Interval:").grid(row=0, column=2, sticky='w', padx=(0, 4))
        ttk.Combobox(g, textvariable=s.frame_interval_var,
                     values=["1", "2", "5", "10", "20", "50"],
                     state='readonly', width=6).grid(row=0, column=3, padx=(0, 4))
        ttk.Label(g, text="ms").grid(row=0, column=4, sticky='w', padx=(0, 12))

        ttk.Label(g, text="Flash Mode:").grid(row=0, column=5, sticky='w', padx=(0, 4))
        ttk.Combobox(g, textvariable=s.flash_mode_var,
                     values=["Normal", "Forced"],
                     state='readonly', width=8).grid(row=0, column=6, padx=(0, 12))

        ttk.Checkbutton(g, text="Delete config",
                        variable=s.delete_cfg_var).grid(row=0, column=7, sticky='w')

        # Progress
        progress_frame = ttk.LabelFrame(self, text="Progress", padding=8)
        progress_frame.pack(fill=tk.X, pady=(0, 6))

        self.progress_bar = ttk.Progressbar(
            progress_frame, variable=s.progress_var,
            maximum=100, mode='determinate',
        )
        self.progress_bar.pack(fill=tk.X, pady=(0, 3))

        ttk.Label(progress_frame, textvariable=s.status_var, font=(FONT_FAMILY, 10)).pack(fill=tk.X)
        ttk.Label(progress_frame, textvariable=s.progress_detail_var, font=(FONT_FAMILY, 9)).pack(fill=tk.X)

        # Action buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=(4, 6))

        self.discover_btn = ttk.Button(
            btn_frame, text="Discover",
            command=self._discover_devices, width=14,
        )
        self.discover_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.start_btn = ttk.Button(
            btn_frame, text="Start Upgrade",
            command=self._start_upgrade, width=16,
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.stop_btn = ttk.Button(
            btn_frame, text="Stop",
            command=self._stop_upgrade, width=10,
            state='disabled',
        )
        self.stop_btn.pack(side=tk.LEFT)

        # Device table
        dev_frame = ttk.LabelFrame(self, text="Detected Devices", padding=8)
        dev_frame.pack(fill=tk.BOTH, expand=True)

        dev_columns = ('ip', 'mac', 'sn', 'model', 'status', 'progress')
        self.device_tree = ttk.Treeview(
            dev_frame, columns=dev_columns, show='headings', height=4)
        self.device_tree.heading('ip', text='IP Address')
        self.device_tree.heading('mac', text='MAC')
        self.device_tree.heading('sn', text='Serial Number')
        self.device_tree.heading('model', text='Model')
        self.device_tree.heading('status', text='Status')
        self.device_tree.heading('progress', text='Progress')
        self.device_tree.column('ip', width=120)
        self.device_tree.column('mac', width=130)
        self.device_tree.column('sn', width=130)
        self.device_tree.column('model', width=90)
        self.device_tree.column('status', width=100)
        self.device_tree.column('progress', width=80)

        dev_scroll = ttk.Scrollbar(dev_frame, orient=tk.VERTICAL,
                                   command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=dev_scroll.set)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dev_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # ── Adapter ──────────────────────────────────────────────────

    def _on_adapter_selected(self, event):
        adapter = self.ctrl.get_selected_adapter()
        if adapter:
            try:
                self.s.term_nic_var.set(adapter.display_name())
            except Exception:
                pass
            details = adapter.details_dict()
            text = "  |  ".join(f"{k}: {v}" for k, v in details.items()
                                if v and v != "N/A" and k not in ("Name",))
            self.s.adapter_detail_var.set(text)
            if adapter.ip:
                self.s.ip_mode_ip_var.set(adapter.ip)
            if adapter.netmask:
                self.s.ip_mode_mask_var.set(adapter.netmask)
            has_gateway = adapter.gateway and adapter.gateway != "N/A"
            if has_gateway:
                self.s.ip_mode_gw_var.set(adapter.gateway)
                self.s.term_host_var.set(adapter.gateway)
        else:
            self.s.adapter_detail_var.set("")

    # ── Firmware Management ──────────────────────────────────────

    def _browse_firmware(self):
        path = filedialog.askopenfilename(
            title="Select Firmware File",
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")],
        )
        if not path:
            return
        self.s.fw_path_var.set(path)
        self._load_firmware(path)

    def _load_firmware(self, path):
        try:
            fw = HWNPFirmware()
            fw.load(path)
            hdr_ok, data_ok = fw.validate_crc32()
            crc_status = "✅" if (hdr_ok and data_ok) else "⚠️"

            self.s.firmware = fw
            self.s.firmware_path = path

            size_mb = len(fw.raw_data) / (1024 * 1024)
            self.s.fw_info_var.set(
                f"{crc_status} HWNP | {fw.item_count} items | "
                f"{size_mb:.2f} MB | Products: {fw.product_list[:50]}"
            )
            self.ctrl.refresh_fw_info()
            self.ctrl.log(f"Loaded firmware: {os.path.basename(path)} ({size_mb:.2f} MB, {fw.item_count} items)")
        except Exception as e:
            self.s.firmware = None
            self.s.fw_info_var.set(f"❌ Error: {e}")
            self.ctrl.log(f"Failed to load firmware: {e}")
            messagebox.showerror("Firmware Error", str(e))

    # ── Discovery ────────────────────────────────────────────────

    def _validate_adapter_ip(self, adapter):
        if not adapter.ip or adapter.ip == "0.0.0.0":
            messagebox.showwarning("No IP Address",
                                   "The selected adapter has no IP address.\n"
                                   "Configure an IP address first (IP Mode section).")
            return False
        return True

    def _discover_devices(self):
        adapter = self.ctrl.get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first.")
            return
        if not self._validate_adapter_ip(adapter):
            return

        use_multicast = (self.s.ip_mode_var.get() == "automatic")
        mc_label = f" + multicast {OBSC_MULTICAST_ADDR}" if use_multicast else ""
        self.ctrl.log(f"Starting discovery on {adapter.ip}{mc_label}...")
        self.discover_btn.configure(state='disabled')

        try:
            if self.s.transport:
                self.s.transport.close()

            self.s.transport = UDPTransport(
                bind_ip=adapter.ip,
                bind_port=_safe_int(self.s.recv_port_var.get(), OBSC_RECV_PORT),
                dest_port=_safe_int(self.s.send_port_var.get(), OBSC_SEND_PORT),
                broadcast=True,
                multicast_group=OBSC_MULTICAST_ADDR if use_multicast else None,
            )
            self.s.transport.open()

            self.s.worker = OBSCWorker(self.s.transport, adapter)
            self.s.worker.on_device_found = self._on_device_found
            self.s.worker.on_status = self._on_status
            self.s.worker.on_log = self._on_worker_log
            self.s.worker.on_error = self._on_error
            if use_multicast:
                self.s.worker.multicast_addr = OBSC_MULTICAST_ADDR

            self.s.worker.start_discovery(duration=_safe_int(self.s.discovery_duration_var.get(), 10))
            duration_ms = _safe_int(self.s.discovery_duration_var.get(), 10) * 1000 + 1000
            self.s.root.after(duration_ms, lambda: self.discover_btn.configure(state='normal'))

        except Exception as e:
            self.ctrl.log(f"Discovery error: {e}")
            messagebox.showerror("Discovery Error", str(e))
            self.discover_btn.configure(state='normal')
            if self.s.transport:
                self.s.transport.close()

    def _on_device_found(self, device):
        self.s.root.after(0, lambda: self._update_device_table(device))

    def _update_device_table(self, device):
        ip = device.ip
        now = time.time()
        if ip in self._tracked_devices:
            item_id = self._tracked_devices[ip]['item_id']
            self._tracked_devices[ip]['last_seen'] = now
            self._tracked_devices[ip]['device'] = device
            self.device_tree.item(item_id, values=(
                ip, device.mac or "—", device.board_sn or "—",
                device.model or "—", device.status, "—"))
        else:
            item_id = self.device_tree.insert('', tk.END, values=(
                ip, device.mac or "—", device.board_sn or "—",
                device.model or "—", device.status, "—"))
            self._tracked_devices[ip] = {
                'item_id': item_id, 'device': device, 'last_seen': now,
            }
        self.ctrl.log(f"📡 Device: {ip} | SN: {device.board_sn} | MAC: {device.mac}")

    def _update_device_progress(self, ip, status, progress_text):
        if ip in self._tracked_devices:
            item_id = self._tracked_devices[ip]['item_id']
            dev = self._tracked_devices[ip]['device']
            self.device_tree.item(item_id, values=(
                ip, dev.mac or "—", dev.board_sn or "—",
                dev.model or "—", status, progress_text))
            self._tracked_devices[ip]['last_seen'] = time.time()

    def _check_stale_devices(self):
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
            self.ctrl.log(f"📡 Device lost: {ip}")
        self.s.root.after(5000, self._check_stale_devices)

    # ── Upgrade ──────────────────────────────────────────────────

    def _start_upgrade(self):
        adapter = self.ctrl.get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first.")
            return
        if not self._validate_adapter_ip(adapter):
            return
        if not self.s.firmware:
            messagebox.showwarning("No Firmware", "Please select a firmware file first.")
            return

        # Pre-flash CRC32
        if self.s.verify_crc32_var.get():
            hdr_ok, data_ok = self.s.firmware.validate_crc32()
            if not hdr_ok or not data_ok:
                if not messagebox.askyesno(
                    "CRC32 Warning",
                    "Firmware CRC32 verification failed!\n\n"
                    f"Header CRC32: {'VALID' if hdr_ok else 'INVALID'}\n"
                    f"Data CRC32: {'VALID' if data_ok else 'INVALID'}\n\n"
                    "Continue anyway?"
                ):
                    return

        # Item CRC
        if self.s.verify_item_crc_var.get():
            self.ctrl.log("Verifying individual item CRC32 checksums...")
            for item in self.s.firmware.items:
                if item.data and item.crc32:
                    calc_crc = zlib.crc32(item.data) & 0xFFFFFFFF
                    if calc_crc != item.crc32:
                        self.ctrl.log(f"⚠️ Item CRC32 mismatch: {item.item_path} "
                                      f"(expected 0x{item.crc32:08X}, got 0x{calc_crc:08X})")
                        if not messagebox.askyesno(
                            "Item CRC32 Warning",
                            f"Item CRC32 mismatch for:\n{item.item_path}\n\n"
                            f"Expected: 0x{item.crc32:08X}\nCalculated: 0x{calc_crc:08X}\n\n"
                            "Continue anyway?"
                        ):
                            return

        # Dry run
        if self.s.dry_run_var.get():
            self.ctrl.log("✅ Dry run complete — all pre-flash checks passed")
            messagebox.showinfo("Dry Run", "All pre-flash verification checks passed.\n"
                                "No data was sent (dry run mode).")
            return

        # Confirm
        size_mb = len(self.s.firmware.raw_data) / (1024 * 1024)
        if not messagebox.askyesno(
            "Confirm Upgrade",
            f"Flash firmware to all ONT devices on the network?\n\n"
            f"File: {os.path.basename(self.s.firmware_path)}\n"
            f"Size: {size_mb:.2f} MB\n"
            f"Frame Size: {self.s.frame_size_var.get()} bytes\n"
            f"Frame Interval: {self.s.frame_interval_var.get()} ms\n"
            f"Flash Mode: {self.s.flash_mode_var.get()}\n"
            f"Delete Config: {'Yes' if self.s.delete_cfg_var.get() else 'No'}\n\n"
            f"⚠️ Do not disconnect power during the upgrade!"
        ):
            return

        self._set_upgrading(True)

        try:
            if self.s.transport:
                self.s.transport.close()

            self.s.transport = UDPTransport(
                bind_ip=adapter.ip,
                bind_port=_safe_int(self.s.recv_port_var.get(), OBSC_RECV_PORT),
                dest_port=_safe_int(self.s.send_port_var.get(), OBSC_SEND_PORT),
                broadcast=True,
            )
            self.s.transport.open()

            self.s.worker = OBSCWorker(self.s.transport, adapter)
            self.s.worker.frame_size = _safe_int(self.s.frame_size_var.get(), 1400)
            self.s.worker.frame_interval_ms = _safe_int(self.s.frame_interval_var.get(), 5)
            self.s.worker.flash_mode = FlashMode.FORCED if self.s.flash_mode_var.get() == "Forced" else FlashMode.NORMAL
            self.s.worker.delete_cfg = self.s.delete_cfg_var.get()
            self.s.worker.timeout = _safe_int(self.s.timeout_var.get(), 600)
            self.s.worker.machine_filter = self.s.machine_filter_var.get()
            self.s.worker.ctrl_retries = _safe_int(self.s.ctrl_retries_var.get(), 3)
            self.s.worker.data_retries = _safe_int(self.s.data_retries_var.get(), 0)

            ut_map = {"Standard": UpgradeType.STANDARD,
                      "Equipment": UpgradeType.EQUIPMENT,
                      "Equipment WC": UpgradeType.EQUIPMENT_WC}
            self.s.worker.upgrade_type = ut_map.get(self.s.upgrade_type_var.get(), UpgradeType.STANDARD)

            self.s.worker.on_progress = self._on_progress
            self.s.worker.on_status = self._on_status
            self.s.worker.on_log = self._on_worker_log
            self.s.worker.on_complete = self._on_complete
            self.s.worker.on_error = self._on_error

            transfer_data = self.s.firmware.get_transfer_data()
            transfer_crc32 = self.s.firmware.get_transfer_crc32()
            self.s.worker.start_upgrade(
                transfer_data,
                firmware_size=len(transfer_data),
                firmware_crc32=transfer_crc32,
            )

        except Exception as e:
            self.ctrl.log(f"Upgrade start error: {e}")
            messagebox.showerror("Error", str(e))
            self._set_upgrading(False)
            if self.s.transport:
                self.s.transport.close()

    def _stop_upgrade(self):
        if self.s.worker:
            self.s.worker.stop()
        self._set_upgrading(False)
        if self.s.transport:
            self.s.transport.close()
            self.s.transport = None
        self.ctrl.log("Upgrade stopped by user")

    def _set_upgrading(self, active):
        if active:
            self.start_btn.configure(state='disabled')
            self.stop_btn.configure(state='normal')
            self.discover_btn.configure(state='disabled')
            self.s.progress_var.set(0)
        else:
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')
            self.discover_btn.configure(state='normal')

    # ── Callbacks (thread-safe) ──────────────────────────────────

    def _on_progress(self, percent, detail_text):
        self.s.root.after(0, lambda: self.s.progress_var.set(percent))
        self.s.root.after(0, lambda: self.s.progress_detail_var.set(detail_text))

    def _on_status(self, text):
        self.s.root.after(0, lambda: self.s.status_var.set(text))

    def _on_worker_log(self, text):
        self.s.root.after(0, lambda: self.ctrl.log(text))

    def _on_complete(self, success, message):
        self.s.root.after(0, lambda: self._set_upgrading(False))
        self.s.root.after(0, lambda: self.ctrl.log(
            f"{'✅' if success else '❌'} Upgrade {'complete' if success else 'failed'}: {message}"
        ))
        if self.s.auto_log_var.get():
            self.s.root.after(100, self.ctrl.auto_save_log)
        transport = self.s.transport
        if transport:
            self.s.root.after(0, lambda t=transport: t.close())

    def _on_error(self, text):
        self.s.root.after(0, lambda: self.ctrl.log(f"❌ ERROR: {text}"))
        self.s.root.after(0, lambda: self._set_upgrading(False))
        self.s.root.after(0, lambda: messagebox.showerror("Error", text))
