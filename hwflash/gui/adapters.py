"""Adapter management mixin for OBSC Firmware Tool."""

import threading
import tkinter as tk
from tkinter import ttk

from hwflash.net import discover_adapters


class AdaptersMixin:
    """Mixin providing network adapter management methods."""

    def _refresh_adapters(self):
        """Refresh the list of network adapters in a background thread.

        Ethernet adapters are sorted first because the OBSC protocol
        requires a wired LAN connection to the ONT device.
        The actual discovery runs off the main thread so the GUI stays
        responsive during the PowerShell/ipconfig calls on Windows.
        """
        # Show a loading state while discovering
        self.adapter_combo['values'] = ["Detecting adapters..."]
        self.adapter_combo.current(0)
        self.adapter_detail_var.set("")

        def _discover():
            adapters = discover_adapters()
            # Sort: Ethernet adapters first (match original tool: "本地网卡")
            def _eth_sort_key(a):
                name_lower = (a.name + " " + (a.description or "")).lower()
                if 'ethernet' in name_lower or 'eth' in name_lower or 'lan' in name_lower:
                    return 0
                if 'wi-fi' in name_lower or 'wireless' in name_lower or 'wlan' in name_lower:
                    return 2
                return 1
            adapters.sort(key=_eth_sort_key)
            # Schedule UI update on the main thread
            self.root.after(0, lambda: self._finish_refresh_adapters(adapters))

        threading.Thread(target=_discover, daemon=True).start()

    def _finish_refresh_adapters(self, adapters):
        """Update UI with discovered adapters (called on main thread)."""
        self.adapters = adapters
        names = [a.display_name() for a in self.adapters]
        self.adapter_combo['values'] = names
        if names:
            self.adapter_combo.current(0)
            self._on_adapter_selected(None)
        self._log(f"Found {len(self.adapters)} network adapter(s)")
        # Also refresh the config adapter combo in Settings tab
        self._refresh_cfg_adapters()
        # Also refresh terminal NIC selector
        self._refresh_term_nic()

    def _on_adapter_selected(self, event):
        """Update adapter detail display and auto-populate IP fields."""
        adapter = self._get_selected_adapter()
        if adapter:
            details = adapter.details_dict()
            text = "  |  ".join(f"{k}: {v}" for k, v in details.items()
                                if v and v != "N/A" and k not in ("Name",))
            self.adapter_detail_var.set(text)
            # Auto-populate manual IP fields from detected adapter
            if adapter.ip:
                self.ip_mode_ip_var.set(adapter.ip)
            if adapter.netmask:
                self.ip_mode_mask_var.set(adapter.netmask)
            # Check if gateway is valid (not empty or "N/A")
            has_gateway = adapter.gateway and adapter.gateway != "N/A"
            if has_gateway:
                self.ip_mode_gw_var.set(adapter.gateway)
                # Auto-populate terminal host with adapter gateway
                if hasattr(self, 'term_host_var'):
                    self.term_host_var.set(adapter.gateway)
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

    def _refresh_term_nic(self):
        """Refresh the terminal NIC selector, auto-selecting the first Ethernet adapter."""
        if not hasattr(self, 'term_nic_combo'):
            return
        names = [a.display_name() for a in self.adapters]
        self.term_nic_combo['values'] = names
        # Auto-select the first Ethernet adapter (already sorted Ethernet-first)
        if names:
            self.term_nic_combo.current(0)
            # If an Ethernet adapter is detected, set the terminal host to its gateway
            adapter = self.adapters[0]
            name_lower = (adapter.name + " " + (adapter.description or "")).lower()
            if any(kw in name_lower for kw in ('ethernet', 'eth', 'lan')):
                if adapter.gateway and adapter.gateway != "N/A":
                    self.term_host_var.set(adapter.gateway)
                    self._log(f"Terminal: auto-selected {adapter.name} → gateway {adapter.gateway}")
