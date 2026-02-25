"""Settings tab — protocol, network, and upgrade configuration."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import TYPE_CHECKING

from hwflash.shared.helpers import safe_int as _safe_int
from hwflash.shared.constants import DEFAULT_IP_CONFIG, OBSC_MULTICAST_ADDR
from hwflash.core.network import (
    configure_adapter_ip, set_adapter_dhcp, test_socket_bind,
)
from hwflash.core.protocol import OBSC_SEND_PORT, OBSC_RECV_PORT
from hwflash.shared.styles import FONT_FAMILY
from hwflash.ui.components.factory import ActionSpec

if TYPE_CHECKING:
    from hwflash.ui.state import AppState, AppController
    from hwflash.shared.styles import ThemeEngine


class SettingsTab(ttk.Frame):
    """Settings and configuration tab with scrollable content."""

    def __init__(self, parent, state: "AppState", ctrl: "AppController",
                 engine: "ThemeEngine", **kwargs):
        super().__init__(parent, padding=0, **kwargs)
        self.s = state
        self.ctrl = ctrl
        self.engine = engine
        self.widgets = ctrl.get_engine("widgets")
        self.command_engine = ctrl.get_engine("commands")
        self._build_scrollable()

    # ── Scrollable container ──────────────────────────────────────────

    def _build_scrollable(self):
        """Wrap content in a scrollable canvas for long settings pages."""
        canvas = tk.Canvas(self, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview)
        self._inner = ttk.Frame(canvas, padding=10)

        self._inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=self._inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Mouse-wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self._canvas = canvas
        self._build()

    # ── Build ─────────────────────────────────────────────────────────

    def _build(self):
        s = self.s
        parent = self._inner   # all widgets go inside the scrollable inner frame

        fw_meta_frame = ttk.LabelFrame(parent, text="Loaded Firmware Metadata", padding=8)
        fw_meta_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(fw_meta_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Product ID:", width=16).pack(side=tk.LEFT)
        ttk.Label(row, textvariable=s.fw_product_id_var).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(row, text="SOC ID:", width=10).pack(side=tk.LEFT)
        ttk.Label(row, textvariable=s.fw_soc_id_var).pack(side=tk.LEFT)

        row = ttk.Frame(fw_meta_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Board ID:", width=16).pack(side=tk.LEFT)
        ttk.Label(row, textvariable=s.fw_board_id_var).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(row, text="HW/SW:", width=10).pack(side=tk.LEFT)
        ttk.Label(row, textvariable=s.fw_hw_ver_var).pack(side=tk.LEFT)
        ttk.Label(row, text=" / ").pack(side=tk.LEFT)
        ttk.Label(row, textvariable=s.fw_sw_ver_var).pack(side=tk.LEFT)

        row = ttk.Frame(fw_meta_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Build Date:", width=16).pack(side=tk.LEFT)
        ttk.Label(row, textvariable=s.fw_build_date_var).pack(side=tk.LEFT)

        auto_row = ttk.Frame(parent)
        auto_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(
            auto_row, text="Reset all to defaults",
            command=self._reset_settings_to_auto, width=24,
        ).pack(side=tk.LEFT)
        ttk.Label(auto_row, text="  Restores recommended values",
                  font=(FONT_FAMILY, 8)).pack(side=tk.LEFT)

        # IP Mode
        ip_frame = ttk.LabelFrame(parent, text="IP Mode (adapter config)", padding=8)
        ip_frame.pack(fill=tk.X, pady=(0, 8))

        mode_row = ttk.Frame(ip_frame)
        mode_row.pack(fill=tk.X)

        ttk.Radiobutton(
            mode_row, text="Automatic (DHCP + Multicast)",
            variable=s.ip_mode_var, value="automatic",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(
            mode_row, text="Manual",
            variable=s.ip_mode_var, value="manual",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(
            mode_row, text="DHCP Only",
            variable=s.ip_mode_var, value="dhcp",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT)

        self.ip_manual_frame = ttk.Frame(ip_frame)

        ip_row1 = ttk.Frame(self.ip_manual_frame)
        ip_row1.pack(fill=tk.X, pady=2)
        ttk.Label(ip_row1, text="IP Address:", width=12).pack(side=tk.LEFT)
        self.ip_mode_ip_entry = ttk.Entry(ip_row1, textvariable=s.ip_mode_ip_var, width=16)
        self.ip_mode_ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(ip_row1, text="Subnet Mask:", width=12).pack(side=tk.LEFT)
        self.ip_mode_mask_entry = ttk.Entry(ip_row1, textvariable=s.ip_mode_mask_var, width=16)
        self.ip_mode_mask_entry.pack(side=tk.LEFT)

        ip_row2 = ttk.Frame(self.ip_manual_frame)
        ip_row2.pack(fill=tk.X, pady=2)
        ttk.Label(ip_row2, text="Gateway:", width=12).pack(side=tk.LEFT)
        self.ip_mode_gw_entry = ttk.Entry(ip_row2, textvariable=s.ip_mode_gw_var, width=16)
        self.ip_mode_gw_entry.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(ip_row2, text="DNS:", width=12).pack(side=tk.LEFT)
        self.ip_mode_dns_entry = ttk.Entry(ip_row2, textvariable=s.ip_mode_dns_var, width=16)
        self.ip_mode_dns_entry.pack(side=tk.LEFT)

        self.ip_apply_frame = ttk.Frame(ip_frame)
        self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
        if self.widgets:
            self.widgets.actions(
                self.ip_apply_frame,
                [ActionSpec("Apply IP Mode", self._apply_ip_mode, width=16)],
                pady=(0, 0),
            )
        else:
            ttk.Button(self.ip_apply_frame, text="Apply IP Mode",
                       command=self._apply_ip_mode, width=16).pack(side=tk.LEFT)

        ttk.Label(ip_frame, textvariable=s.ip_mode_status_var,
                  font=(FONT_FAMILY, 9)).pack(fill=tk.X, pady=(3, 0))

        self._on_ip_mode_changed()

        # Protocol settings
        proto_frame = ttk.LabelFrame(parent, text="Protocol Settings", padding=8)
        proto_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(proto_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Send Port:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.send_port_var,
                     values=["50000", "50002", "50010"], width=8).pack(side=tk.LEFT)

        row = ttk.Frame(proto_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Receive Port:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.recv_port_var,
                     values=["50001", "50003", "50011"], width=8).pack(side=tk.LEFT)

        row = ttk.Frame(proto_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Broadcast Address:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.broadcast_var,
                     values=["auto", "255.255.255.255", "192.168.100.255"],
                     width=18).pack(side=tk.LEFT)
        ttk.Label(row, text="(auto = from adapter)", font=(FONT_FAMILY, 8)).pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(proto_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Upgrade Timeout:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.timeout_var,
                     values=["300", "600", "900", "1200", "1800"],
                     width=8).pack(side=tk.LEFT)
        ttk.Label(row, text="seconds").pack(side=tk.LEFT, padx=5)

        # Upgrade options
        upgrade_frame = ttk.LabelFrame(parent, text="Upgrade Options", padding=8)
        upgrade_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(upgrade_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Upgrade Type:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.upgrade_type_var,
                     values=["Standard", "Equipment", "Equipment WC"],
                     state='readonly', width=16).pack(side=tk.LEFT)

        row = ttk.Frame(upgrade_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Machine Filter (SN):", width=18).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.machine_filter_var, width=28).pack(side=tk.LEFT)
        ttk.Label(row, text="(empty = all)", font=(FONT_FAMILY, 8)).pack(side=tk.LEFT, padx=5)

        # Advanced transfer
        adv_frame = ttk.LabelFrame(parent, text="Advanced Transfer", padding=8)
        adv_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(adv_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Discovery Duration:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.discovery_duration_var,
                     values=["5", "10", "15", "20", "30", "60"],
                     state='readonly', width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="seconds").pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(adv_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Control Retries:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.ctrl_retries_var,
                     values=["1", "2", "3", "5", "10"],
                     state='readonly', width=6).pack(side=tk.LEFT)

        row = ttk.Frame(adv_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Data Frame Retries:", width=18).pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=s.data_retries_var,
                     values=["0", "1", "2", "3"],
                     state='readonly', width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="(0 = no retry)", font=(FONT_FAMILY, 8)).pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(adv_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Check Policy:", width=18).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.check_policy_var, width=18).pack(side=tk.LEFT)
        ttk.Label(row, text="(empty = default)", font=(FONT_FAMILY, 8)).pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(adv_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="BOM Code:", width=18).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.bom_code_var, width=18).pack(side=tk.LEFT)

        # Logging
        log_frame = ttk.LabelFrame(parent, text="Logging", padding=8)
        log_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(log_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Log Directory:", width=18).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.log_dir_var, width=36).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="Browse", command=self._browse_log_dir, width=8).pack(side=tk.LEFT)

        ttk.Checkbutton(log_frame, text="Auto-save log after each upgrade",
                        variable=s.auto_log_var).pack(fill=tk.X, pady=2)

        # Network config
        net_frame = ttk.LabelFrame(parent, text="Network Configuration", padding=8)
        net_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(net_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Configure Adapter:", width=18).pack(side=tk.LEFT)
        self.cfg_adapter_combo = ttk.Combobox(
            row, textvariable=s.cfg_adapter_var, state='readonly', width=28)
        self.cfg_adapter_combo.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="Refresh", command=self._refresh_cfg_adapters, width=8).pack(side=tk.LEFT)

        row = ttk.Frame(net_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="IP Address:", width=18).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.cfg_ip_var, width=16).pack(side=tk.LEFT)
        ttk.Label(row, text="  Subnet:", width=8).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.cfg_mask_var, width=16).pack(side=tk.LEFT)

        row = ttk.Frame(net_frame); row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Gateway:", width=18).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=s.cfg_gw_var, width=16).pack(side=tk.LEFT)
        ttk.Label(row, text="(optional)", font=(FONT_FAMILY, 8)).pack(side=tk.LEFT, padx=5)

        btn_row = ttk.Frame(net_frame)
        btn_row.pack(fill=tk.X, pady=(4, 0))
        if self.widgets:
            self.widgets.actions(
                btn_row,
                [
                    ActionSpec("Apply Static IP", self._apply_static_ip, width=16),
                    ActionSpec("Set DHCP", self._apply_dhcp, width=12),
                    ActionSpec("Test Socket", self._test_socket, width=12, padx=(0, 0)),
                ],
                pady=(0, 0),
            )
        else:
            ttk.Button(btn_row, text="Apply Static IP",
                       command=self._apply_static_ip, width=16).pack(side=tk.LEFT, padx=(0, 4))
            ttk.Button(btn_row, text="Set DHCP",
                       command=self._apply_dhcp, width=12).pack(side=tk.LEFT, padx=(0, 4))
            ttk.Button(btn_row, text="Test Socket",
                       command=self._test_socket, width=12).pack(side=tk.LEFT)

        ttk.Label(net_frame, textvariable=s.net_status_var,
                  font=(FONT_FAMILY, 9)).pack(fill=tk.X, pady=(4, 0))

    # ── Handlers ───────────────────────────────────────────────────────

    def _browse_log_dir(self):
        path = filedialog.askdirectory(title="Select Log Directory")
        if path:
            self.s.log_dir_var.set(path)

    def _refresh_cfg_adapters(self):
        names = [a.name for a in self.s.adapters]
        self.cfg_adapter_combo['values'] = names
        if names:
            self.cfg_adapter_combo.current(0)

    def _apply_static_ip(self):
        adapter_name = self.s.cfg_adapter_var.get()
        if not adapter_name:
            messagebox.showwarning("No Adapter", "Select an adapter to configure.")
            return
        ip = self.s.cfg_ip_var.get().strip()
        mask = self.s.cfg_mask_var.get().strip()
        gw = self.s.cfg_gw_var.get().strip()
        if not ip or not mask:
            messagebox.showwarning("Missing Info", "IP address and subnet mask are required.")
            return
        if not messagebox.askyesno(
            "Confirm Network Change",
            f"Set {adapter_name} to:\n\n"
            f"  IP: {ip}\n  Mask: {mask}\n  GW: {gw or 'none'}\n\n"
            "\u26a0\ufe0f Requires administrator privileges."
        ):
            return
        self.s.net_status_var.set("Applying...")
        self.s.root.update_idletasks()
        if self.command_engine and self.command_engine.can_run("network.configure_static_ip"):
            result = self.command_engine.run(
                "network.configure_static_ip",
                adapter_name=adapter_name,
                ip=ip,
                netmask=mask,
                gateway=gw,
            )
            ok, msg = result.ok, result.message
        else:
            ok, msg = configure_adapter_ip(adapter_name, ip, mask, gw)
        self.s.net_status_var.set(("\u2705 " if ok else "\u274c ") + msg)
        self.ctrl.log(f"Network config: {msg}")
        if ok:
            self.s.root.after(2000, self.ctrl.refresh_adapters)

    def _apply_dhcp(self):
        adapter_name = self.s.cfg_adapter_var.get()
        if not adapter_name:
            messagebox.showwarning("No Adapter", "Select an adapter to configure.")
            return
        if not messagebox.askyesno(
            "Confirm DHCP",
            f"Set {adapter_name} to DHCP?\n\n"
            "\u26a0\ufe0f Requires administrator privileges."
        ):
            return
        self.s.net_status_var.set("Applying DHCP...")
        self.s.root.update_idletasks()
        if self.command_engine and self.command_engine.can_run("network.set_dhcp"):
            result = self.command_engine.run("network.set_dhcp", adapter_name=adapter_name)
            ok, msg = result.ok, result.message
        else:
            ok, msg = set_adapter_dhcp(adapter_name)
        self.s.net_status_var.set(("\u2705 " if ok else "\u274c ") + msg)
        self.ctrl.log(f"Network config: {msg}")
        if ok:
            self.s.root.after(3000, self.ctrl.refresh_adapters)

    def _test_socket(self):
        adapter = self.ctrl.get_selected_adapter()
        bind_ip = adapter.ip if adapter else "0.0.0.0"
        bind_port = _safe_int(self.s.recv_port_var.get(), OBSC_RECV_PORT)
        if self.command_engine and self.command_engine.can_run("network.test_socket"):
            result = self.command_engine.run(
                "network.test_socket",
                bind_ip=bind_ip,
                bind_port=bind_port,
                broadcast=True,
            )
            ok, msg = result.ok, result.message
        else:
            ok, msg = test_socket_bind(bind_ip, bind_port, broadcast=True)
        self.s.net_status_var.set(("\u2705 " if ok else "\u274c ") + msg)
        self.ctrl.log(f"Socket test: {msg}")

    def _reset_settings_to_auto(self):
        s = self.s
        s.send_port_var.set(str(OBSC_SEND_PORT))
        s.recv_port_var.set(str(OBSC_RECV_PORT))
        s.broadcast_var.set("auto")
        s.timeout_var.set("600")
        s.upgrade_type_var.set("Standard")
        s.machine_filter_var.set("")
        s.discovery_duration_var.set("10")
        s.ctrl_retries_var.set("3")
        s.data_retries_var.set("0")
        s.check_policy_var.set("")
        s.bom_code_var.set("")
        s.auto_log_var.set(True)
        s.frame_size_var.set("1400")
        s.frame_interval_var.set("5")
        s.flash_mode_var.set("Normal")
        s.delete_cfg_var.set(False)
        s.ip_mode_var.set("automatic")
        self._on_ip_mode_changed()
        self.ctrl.log("All settings reset to defaults")

    def _on_ip_mode_changed(self):
        mode = self.s.ip_mode_var.get()
        if mode == "manual":
            self.ip_manual_frame.pack(fill=tk.X, pady=(4, 0))
            self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
            self.ip_mode_ip_entry.configure(state='normal')
            self.ip_mode_mask_entry.configure(state='normal')
            self.ip_mode_gw_entry.configure(state='normal')
            self.ip_mode_dns_entry.configure(state='normal')
            self.s.ip_mode_status_var.set(
                "\u270f\ufe0f Manual: Edit fields, then click Apply")
        elif mode == "automatic":
            self.ip_manual_frame.pack_forget()
            self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
            self.s.ip_mode_status_var.set(
                f"🔄 Automatic: DHCP + Multicast {OBSC_MULTICAST_ADDR}")
        else:
            self.ip_manual_frame.pack_forget()
            self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
            self.s.ip_mode_status_var.set(
                "🌐 DHCP Only: adapter obtains IP automatically")

    def _apply_ip_mode(self):
        adapter = self.ctrl.get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Select a network adapter first.")
            return
        mode = self.s.ip_mode_var.get()
        adapter_name = adapter.name

        if mode in ("dhcp", "automatic"):
            label = "Automatic (DHCP + Multicast)" if mode == "automatic" else "DHCP Only"
            extra = f"Multicast: {OBSC_MULTICAST_ADDR}\n\n" if mode == "automatic" else ""
            if not messagebox.askyesno(
                f"Confirm {label}",
                f"Set '{adapter_name}' to DHCP?\n\n"
                + extra
                + "\u26a0\ufe0f Requires administrator privileges."
            ):
                return
            self.s.ip_mode_status_var.set("Applying DHCP\u2026")
            self.s.root.update_idletasks()
            if self.command_engine and self.command_engine.can_run("network.set_dhcp"):
                result = self.command_engine.run("network.set_dhcp", adapter_name=adapter_name)
                ok, msg = result.ok, result.message
            else:
                ok, msg = set_adapter_dhcp(adapter_name)
            if ok and mode == "automatic":
                msg += f" | Multicast: {OBSC_MULTICAST_ADDR}"
        else:
            ip = self.s.ip_mode_ip_var.get().strip()
            mask = self.s.ip_mode_mask_var.get().strip()
            gw = self.s.ip_mode_gw_var.get().strip()
            if not ip or not mask:
                messagebox.showwarning("Missing Info", "IP and subnet mask are required.")
                return
            if not messagebox.askyesno(
                "Confirm Manual IP",
                f"Configure '{adapter_name}' with:\n\n"
                f"  IP: {ip}\n  Mask: {mask}\n  Gateway: {gw or 'none'}\n\n"
                "\u26a0\ufe0f Requires administrator privileges."
            ):
                return
            self.s.ip_mode_status_var.set("Applying\u2026")
            self.s.root.update_idletasks()
            if self.command_engine and self.command_engine.can_run("network.configure_static_ip"):
                result = self.command_engine.run(
                    "network.configure_static_ip",
                    adapter_name=adapter_name,
                    ip=ip,
                    netmask=mask,
                    gateway=gw,
                )
                ok, msg = result.ok, result.message
            else:
                ok, msg = configure_adapter_ip(adapter_name, ip, mask, gw)

        self.s.ip_mode_status_var.set(("\u2705 " if ok else "\u274c ") + msg)
        self.ctrl.log(f"IP Mode ({mode}): {msg}")
        if ok:
            self.s.root.after(2000, self.ctrl.refresh_adapters)
