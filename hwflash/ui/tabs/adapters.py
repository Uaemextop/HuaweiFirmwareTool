"""Adapter management — background discovery, sorting, UI update.

This is NOT a tab; it provides the shared adapter-refresh logic
used by AppController.  It is imported by state.py.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, List

from hwflash.core.network import discover_adapters

if TYPE_CHECKING:
    from hwflash.core.network import NetworkAdapter


def _eth_sort_key(adapter: NetworkAdapter) -> int:
    name_lower = (adapter.name + " " + (adapter.description or "")).lower()
    if 'ethernet' in name_lower or 'eth' in name_lower or 'lan' in name_lower:
        return 0
    if 'wi-fi' in name_lower or 'wireless' in name_lower or 'wlan' in name_lower:
        return 2
    return 1


def refresh_adapters_async(state, ctrl, extra_combos=None):
    """Discover adapters in a background thread and update state.

    *extra_combos* is an optional list of (combo, name_func) tuples
    that should be refreshed with the adapter list.
    """
    # Show loading in all bound combos
    for combo in state.adapter_combos:
        combo['values'] = ["Detecting adapters..."]
        combo.current(0)
    state.adapter_detail_var.set("")

    def _discover():
        adapters = discover_adapters()
        adapters.sort(key=_eth_sort_key)
        state.root.after(0, lambda: _finish(adapters))

    def _finish(adapters: List):
        state.adapters = adapters
        display_names = [a.display_name() for a in adapters]
        short_names = [a.name for a in adapters]

        for combo in state.adapter_combos:
            combo['values'] = display_names
            if display_names:
                combo.current(0)

        if extra_combos:
            for combo, name_fn in extra_combos:
                combo['values'] = [name_fn(a) for a in adapters]
                if adapters:
                    combo.current(0)

        ctrl.log(f"Found {len(adapters)} network adapter(s)")

        # Auto-populate IP fields from first adapter
        if adapters:
            a = adapters[0]
            if a.ip:
                state.ip_mode_ip_var.set(a.ip)
            if a.netmask:
                state.ip_mode_mask_var.set(a.netmask)
            if a.gateway and a.gateway != "N/A":
                state.ip_mode_gw_var.set(a.gateway)
                state.term_host_var.set(a.gateway)

    threading.Thread(target=_discover, daemon=True).start()
