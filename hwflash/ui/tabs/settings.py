"""Settings tab mixin for HuaweiFlash."""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from hwflash.shared.helpers import safe_int as _safe_int
from hwflash.shared.styles import DEFAULT_IP_CONFIG, OBSC_MULTICAST_ADDR
from hwflash.core.network import (
    configure_adapter_ip, set_adapter_dhcp, test_socket_bind,
)
from hwflash.core.protocol import OBSC_SEND_PORT, OBSC_RECV_PORT


class SettingsTabMixin:
    """Mixin providing the Settings tab and related methods."""

    def _build_settings_tab(self):
        tab = self.tab_settings

        auto_row = ttk.Frame(tab)
        auto_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(
            auto_row, text="🔄 Reset All to Defaults",
            command=self._reset_settings_to_auto, width=24,
        ).pack(side=tk.LEFT)
        ttk.Label(auto_row, text="  Restores recommended values",
                  font=('Segoe UI', 8)).pack(side=tk.LEFT)

        # IP Mode (moved from Upgrade tab)
        ip_frame = ttk.LabelFrame(tab, text="IP Mode (adapter config)", padding=8)
        ip_frame.pack(fill=tk.X, pady=(0, 8))

        mode_row = ttk.Frame(ip_frame)
        mode_row.pack(fill=tk.X)

        self.ip_mode_var = tk.StringVar(value="automatic")
        ttk.Radiobutton(
            mode_row, text="🔄 Automatic (DHCP + Multicast)",
            variable=self.ip_mode_var, value="automatic",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(
            mode_row, text="✏️ Manual",
            variable=self.ip_mode_var, value="manual",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(
            mode_row, text="🌐 DHCP Only",
            variable=self.ip_mode_var, value="dhcp",
            command=self._on_ip_mode_changed,
        ).pack(side=tk.LEFT)

        self.ip_manual_frame = ttk.Frame(ip_frame)

        ip_row1 = ttk.Frame(self.ip_manual_frame)
        ip_row1.pack(fill=tk.X, pady=2)
        ttk.Label(ip_row1, text="IP Address:", width=12).pack(side=tk.LEFT)
        self.ip_mode_ip_var = tk.StringVar(value=DEFAULT_IP_CONFIG['ip'])
        self.ip_mode_ip_entry = ttk.Entry(ip_row1, textvariable=self.ip_mode_ip_var, width=16)
        self.ip_mode_ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(ip_row1, text="Subnet Mask:", width=12).pack(side=tk.LEFT)
        self.ip_mode_mask_var = tk.StringVar(value=DEFAULT_IP_CONFIG['netmask'])
        self.ip_mode_mask_entry = ttk.Entry(ip_row1, textvariable=self.ip_mode_mask_var, width=16)
        self.ip_mode_mask_entry.pack(side=tk.LEFT)

        ip_row2 = ttk.Frame(self.ip_manual_frame)
        ip_row2.pack(fill=tk.X, pady=2)
        ttk.Label(ip_row2, text="Gateway:", width=12).pack(side=tk.LEFT)
        self.ip_mode_gw_var = tk.StringVar(value=DEFAULT_IP_CONFIG['gateway'])
        self.ip_mode_gw_entry = ttk.Entry(ip_row2, textvariable=self.ip_mode_gw_var, width=16)
        self.ip_mode_gw_entry.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(ip_row2, text="DNS:", width=12).pack(side=tk.LEFT)
        self.ip_mode_dns_var = tk.StringVar(value=DEFAULT_IP_CONFIG.get('dns1', '8.8.8.8'))
        self.ip_mode_dns_entry = ttk.Entry(ip_row2, textvariable=self.ip_mode_dns_var, width=16)
        self.ip_mode_dns_entry.pack(side=tk.LEFT)

        self.ip_apply_frame = ttk.Frame(ip_frame)
        self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(self.ip_apply_frame, text="⚡ Apply IP Mode",
                   command=self._apply_ip_mode, width=16).pack(side=tk.LEFT)

        self.ip_mode_status_var = tk.StringVar(value="")
        ttk.Label(ip_frame, textvariable=self.ip_mode_status_var,
                  font=('Segoe UI', 9)).pack(fill=tk.X, pady=(3, 0))

        self._on_ip_mode_changed()

        # Protocol settings (ports as comboboxes)
        proto_frame = ttk.LabelFrame(tab, text="Protocol Settings", padding=8)
        proto_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Send Port:", width=18).pack(side=tk.LEFT)
        self.send_port_var = tk.StringVar(value=str(OBSC_SEND_PORT))
        ttk.Combobox(row, textvariable=self.send_port_var,
                     values=["50000", "50002", "50010"],
                     width=8).pack(side=tk.LEFT)

        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Receive Port:", width=18).pack(side=tk.LEFT)
        self.recv_port_var = tk.StringVar(value=str(OBSC_RECV_PORT))
        ttk.Combobox(row, textvariable=self.recv_port_var,
                     values=["50001", "50003", "50011"],
                     width=8).pack(side=tk.LEFT)

        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Broadcast Address:", width=18).pack(side=tk.LEFT)
        self.broadcast_var = tk.StringVar(value="auto")
        ttk.Combobox(row, textvariable=self.broadcast_var,
                     values=["auto", "255.255.255.255", "192.168.100.255"],
                     width=18).pack(side=tk.LEFT)
        ttk.Label(row, text="(auto = from adapter)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(proto_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Upgrade Timeout:", width=18).pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value="600")
        ttk.Combobox(row, textvariable=self.timeout_var,
                     values=["300", "600", "900", "1200", "1800"],
                     width=8).pack(side=tk.LEFT)
        ttk.Label(row, text="seconds").pack(side=tk.LEFT, padx=5)

        # Upgrade options
        upgrade_frame = ttk.LabelFrame(tab, text="Upgrade Options", padding=8)
        upgrade_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(upgrade_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Upgrade Type:", width=18).pack(side=tk.LEFT)
        self.upgrade_type_var = tk.StringVar(value="Standard")
        ttk.Combobox(row, textvariable=self.upgrade_type_var,
                     values=["Standard", "Equipment", "Equipment WC"],
                     state='readonly', width=16).pack(side=tk.LEFT)

        row = ttk.Frame(upgrade_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Machine Filter (SN):", width=18).pack(side=tk.LEFT)
        self.machine_filter_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.machine_filter_var, width=28).pack(side=tk.LEFT)
        ttk.Label(row, text="(empty = all)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        # Advanced transfer
        adv_frame = ttk.LabelFrame(tab, text="Advanced Transfer", padding=8)
        adv_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Discovery Duration:", width=18).pack(side=tk.LEFT)
        self.discovery_duration_var = tk.StringVar(value="10")
        ttk.Combobox(row, textvariable=self.discovery_duration_var,
                     values=["5", "10", "15", "20", "30", "60"],
                     state='readonly', width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="seconds").pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Control Retries:", width=18).pack(side=tk.LEFT)
        self.ctrl_retries_var = tk.StringVar(value="3")
        ttk.Combobox(row, textvariable=self.ctrl_retries_var,
                     values=["1", "2", "3", "5", "10"],
                     state='readonly', width=6).pack(side=tk.LEFT)

        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Data Frame Retries:", width=18).pack(side=tk.LEFT)
        self.data_retries_var = tk.StringVar(value="0")
        ttk.Combobox(row, textvariable=self.data_retries_var,
                     values=["0", "1", "2", "3"],
                     state='readonly', width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="(0 = no retry)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Check Policy:", width=18).pack(side=tk.LEFT)
        self.check_policy_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.check_policy_var, width=18).pack(side=tk.LEFT)
        ttk.Label(row, text="(empty = default)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        row = ttk.Frame(adv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="BOM Code:", width=18).pack(side=tk.LEFT)
        self.bom_code_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.bom_code_var, width=18).pack(side=tk.LEFT)

        # Logging
        log_frame = ttk.LabelFrame(tab, text="Logging", padding=8)
        log_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(log_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Log Directory:", width=18).pack(side=tk.LEFT)
        self.log_dir_var = tk.StringVar(value=os.path.join(os.getcwd(), "logs"))
        ttk.Entry(row, textvariable=self.log_dir_var, width=36).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="Browse", command=self._browse_log_dir, width=8).pack(side=tk.LEFT)

        self.auto_log_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_frame, text="Auto-save log after each upgrade",
                        variable=self.auto_log_var).pack(fill=tk.X, pady=2)

        # Network config
        net_frame = ttk.LabelFrame(tab, text="Network Configuration", padding=8)
        net_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(net_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Configure Adapter:", width=18).pack(side=tk.LEFT)
        self.cfg_adapter_var = tk.StringVar()
        self.cfg_adapter_combo = ttk.Combobox(
            row, textvariable=self.cfg_adapter_var, state='readonly', width=28)
        self.cfg_adapter_combo.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row, text="🔃", command=self._refresh_cfg_adapters, width=3).pack(side=tk.LEFT)

        row = ttk.Frame(net_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="IP Address:", width=18).pack(side=tk.LEFT)
        self.cfg_ip_var = tk.StringVar(value="192.168.100.100")
        ttk.Entry(row, textvariable=self.cfg_ip_var, width=16).pack(side=tk.LEFT)
        ttk.Label(row, text="  Subnet:", width=8).pack(side=tk.LEFT)
        self.cfg_mask_var = tk.StringVar(value="255.255.255.0")
        ttk.Entry(row, textvariable=self.cfg_mask_var, width=16).pack(side=tk.LEFT)

        row = ttk.Frame(net_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Gateway:", width=18).pack(side=tk.LEFT)
        self.cfg_gw_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.cfg_gw_var, width=16).pack(side=tk.LEFT)
        ttk.Label(row, text="(optional)", font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=5)

        btn_row = ttk.Frame(net_frame)
        btn_row.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(btn_row, text="📝 Apply Static IP",
                   command=self._apply_static_ip, width=16).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="🔄 Set DHCP",
                   command=self._apply_dhcp, width=12).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="🔌 Test Socket",
                   command=self._test_socket, width=12).pack(side=tk.LEFT)

        self.net_status_var = tk.StringVar(value="")
        ttk.Label(net_frame, textvariable=self.net_status_var,
                  font=('Segoe UI', 9)).pack(fill=tk.X, pady=(4, 0))

    def _apply_static_ip(self):
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
            "⚠️ Requires administrator privileges."
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
        adapter = self._get_selected_adapter()
        bind_ip = adapter.ip if adapter else "0.0.0.0"
        bind_port = _safe_int(self.recv_port_var.get(), OBSC_RECV_PORT)

        ok, msg = test_socket_bind(bind_ip, bind_port, broadcast=True)
        self.net_status_var.set(("✅ " if ok else "❌ ") + msg)
        self._log(f"Socket test: {msg}")

    def _reset_settings_to_auto(self):
        self.send_port_var.set(str(OBSC_SEND_PORT))
        self.recv_port_var.set(str(OBSC_RECV_PORT))
        self.broadcast_var.set("auto")
        self.timeout_var.set("600")
        self.upgrade_type_var.set("Standard")
        self.machine_filter_var.set("")
        self.discovery_duration_var.set("10")
        self.ctrl_retries_var.set("3")
        self.data_retries_var.set("0")
        self.check_policy_var.set("")
        self.bom_code_var.set("")
        self.auto_log_var.set(True)
        self.frame_size_var.set("1400")
        self.frame_interval_var.set("5")
        self.flash_mode_var.set("Normal")
        self.delete_cfg_var.set(False)
        self.ip_mode_var.set("automatic")
        self._on_ip_mode_changed()
        self._log("All settings reset to defaults")

    def _on_ip_mode_changed(self):
        mode = self.ip_mode_var.get()
        if mode == "manual":
            self.ip_manual_frame.pack(fill=tk.X, pady=(4, 0))
            self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
            self.ip_mode_ip_entry.configure(state='normal')
            self.ip_mode_mask_entry.configure(state='normal')
            self.ip_mode_gw_entry.configure(state='normal')
            self.ip_mode_dns_entry.configure(state='normal')
            self.ip_mode_status_var.set(
                "✏️ Manual: Edit fields, then click Apply")
        elif mode == "automatic":
            self.ip_manual_frame.pack_forget()
            self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
            self.ip_mode_status_var.set(
                f"🔄 Automatic: DHCP + Multicast {OBSC_MULTICAST_ADDR}")
        else:
            self.ip_manual_frame.pack_forget()
            self.ip_apply_frame.pack(fill=tk.X, pady=(4, 0))
            self.ip_mode_status_var.set(
                "🌐 DHCP Only: adapter obtains IP automatically")

    def _apply_ip_mode(self):
        adapter = self._get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter", "Select a network adapter first.")
            return

        mode = self.ip_mode_var.get()
        adapter_name = adapter.name

        if mode in ("dhcp", "automatic"):
            label = "Automatic (DHCP + Multicast)" if mode == "automatic" else "DHCP Only"
            if not messagebox.askyesno(
                f"Confirm {label}",
                f"Set '{adapter_name}' to DHCP?\n\n"
                + (f"Multicast: {OBSC_MULTICAST_ADDR}\n\n"
                   if mode == "automatic" else "")
                + "⚠️ Requires administrator privileges."
            ):
                return
            self.ip_mode_status_var.set("Applying DHCP…")
            self.root.update_idletasks()
            ok, msg = set_adapter_dhcp(adapter_name)
            if ok and mode == "automatic":
                msg += f" | Multicast: {OBSC_MULTICAST_ADDR}"
        else:
            ip = self.ip_mode_ip_var.get().strip()
            mask = self.ip_mode_mask_var.get().strip()
            gw = self.ip_mode_gw_var.get().strip()
            if not ip or not mask:
                messagebox.showwarning("Missing Info", "IP and subnet mask are required.")
                return
            if not messagebox.askyesno(
                "Confirm Manual IP",
                f"Configure '{adapter_name}' with:\n\n"
                f"  IP: {ip}\n  Mask: {mask}\n  Gateway: {gw or 'none'}\n\n"
                "⚠️ Requires administrator privileges."
            ):
                return
            self.ip_mode_status_var.set("Applying…")
            self.root.update_idletasks()
            ok, msg = configure_adapter_ip(adapter_name, ip, mask, gw)

        self.ip_mode_status_var.set(("✅ " if ok else "❌ ") + msg)
        self._log(f"IP Mode ({mode}): {msg}")
        if ok:
            self.root.after(2000, self._refresh_adapters)
