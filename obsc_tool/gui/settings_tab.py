"""Settings tab mixin for OBSC Firmware Tool."""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from obsc_tool.gui.constants import (
    _safe_int, IP_MODE_DEFAULTS, OBSC_MULTICAST_ADDR,
)
from obsc_tool.network import (
    configure_adapter_ip, set_adapter_dhcp, test_socket_bind,
)
from obsc_tool.protocol import OBSC_SEND_PORT, OBSC_RECV_PORT


class SettingsTabMixin:
    """Mixin providing the Settings tab and related methods."""

    def _build_settings_tab(self):
        """Build the settings tab with advanced configuration."""
        tab = self.tab_settings

        # ── Auto Defaults Button ─────────────────────────────────
        auto_row = ttk.Frame(tab)
        auto_row.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(
            auto_row, text="🔄 Reset All to Auto/Defaults",
            command=self._reset_settings_to_auto, width=28,
        ).pack(side=tk.LEFT)
        ttk.Label(auto_row,
                  text="  Restores recommended values for all settings",
                  font=('Segoe UI', 8)).pack(side=tk.LEFT)

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
        self.cfg_ip_var = tk.StringVar(value="192.168.100.100")
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
        bind_port = _safe_int(self.recv_port_var.get(), OBSC_RECV_PORT)

        ok, msg = test_socket_bind(bind_ip, bind_port, broadcast=True)
        self.net_status_var.set(("✅ " if ok else "❌ ") + msg)
        self._log(f"Socket test: {msg}")

    # ── IP Mode Management ──────────────────────────────────────

    def _reset_settings_to_auto(self):
        """Reset all settings to auto/recommended defaults."""
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
        self._log("All settings reset to auto/defaults")

    def _on_ip_mode_changed(self):
        """Handle IP Mode radio button change.

        Automatic — hides manual fields, uses DHCP + multicast.
        Manual    — shows editable IP/Mask/Gateway/DNS fields.
        DHCP      — hides manual fields, DHCP without multicast.
        """
        mode = self.ip_mode_var.get()
        if mode == "manual":
            self.ip_manual_frame.pack(fill=tk.X, pady=(5, 0))
            self.ip_apply_frame.pack(fill=tk.X, pady=(5, 0))
            self.ip_mode_ip_entry.configure(state='normal')
            self.ip_mode_mask_entry.configure(state='normal')
            self.ip_mode_gw_entry.configure(state='normal')
            self.ip_mode_dns_entry.configure(state='normal')
            self.ip_mode_status_var.set(
                "✏️ Manual: Edit IP/Mask/Gateway/DNS, then click Apply")
        elif mode == "automatic":
            self.ip_manual_frame.pack_forget()
            self.ip_apply_frame.pack(fill=tk.X, pady=(5, 0))
            self.ip_mode_status_var.set(
                f"🔄 Automatic: DHCP + Multicast {OBSC_MULTICAST_ADDR}  "
                f"(default: {IP_MODE_DEFAULTS['ip']} / {IP_MODE_DEFAULTS['gateway']})")
        else:  # dhcp
            self.ip_manual_frame.pack_forget()
            self.ip_apply_frame.pack(fill=tk.X, pady=(5, 0))
            self.ip_mode_status_var.set(
                "🌐 DHCP Only: adapter obtains IP automatically (no multicast)")

    def _apply_ip_mode(self):
        """Apply the selected IP mode to the currently selected adapter."""
        adapter = self._get_selected_adapter()
        if not adapter:
            messagebox.showwarning("No Adapter",
                                   "Select a network adapter first (above).")
            return

        mode = self.ip_mode_var.get()
        adapter_name = adapter.name

        if mode in ("dhcp", "automatic"):
            # Both automatic and dhcp-only start with DHCP
            label = "Automatic (DHCP + Multicast)" if mode == "automatic" else "DHCP Only"
            if not messagebox.askyesno(
                f"Confirm {label}",
                f"Set '{adapter_name}' to DHCP?\n\n"
                + (f"Multicast discovery will use {OBSC_MULTICAST_ADDR}\n\n"
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
                messagebox.showwarning("Missing Info",
                                       "IP and subnet mask are required.")
                return
            if not messagebox.askyesno(
                "Confirm Manual IP",
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
