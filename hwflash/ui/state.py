"""
Shared application state and cross-tab controller.

``AppState`` centralises every ``tk.StringVar`` / ``tk.BooleanVar`` that
was previously scattered across the 11 tab classes.  ``AppController``
exposes cross-tab operations (logging, adapter refresh, firmware
loading, etc.) so that standalone tab classes never reference each
other directly.
"""

from __future__ import annotations

import datetime
import logging
import os
import tkinter as tk
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from hwflash.shared.constants import DEFAULT_IP_CONFIG
from hwflash.core.protocol import OBSC_SEND_PORT, OBSC_RECV_PORT

if TYPE_CHECKING:
    from hwflash.core.firmware import HWNPFirmware
    from hwflash.core.network import NetworkAdapter, UDPTransport
    from hwflash.core.presets import PresetManager
    from hwflash.core.terminal import TelnetClient, SerialClient, FirmwareDumper
    from hwflash.core.protocol import OBSCWorker
    from hwflash.shared.styles import ThemeEngine

logger = logging.getLogger("hwflash")


class AppState:
    """Centralised application state — all shared tk variables live here.

    Created once in ``app.py``, passed to every tab constructor by
    reference.  Tabs read/write variables directly off this object.
    """

    def __init__(self, root: tk.Tk):
        self.root = root

        # ── Firmware ─────────────────────────────────────────────
        self.firmware: Optional[HWNPFirmware] = None
        self.firmware_path: str = ""
        self.firmware_dirty: bool = False
        self.firmware_signature_dirty: bool = False
        self.fw_path_var = tk.StringVar(value="No file selected")
        self.fw_info_var = tk.StringVar(value="")

        # ── Adapter ──────────────────────────────────────────────
        self.adapters: List = []
        self.adapter_var = tk.StringVar()
        self.adapter_detail_var = tk.StringVar(value="")

        # ── Transfer (Upgrade tab) ───────────────────────────────
        self.frame_size_var = tk.StringVar(value="1400")
        self.frame_interval_var = tk.StringVar(value="5")
        self.flash_mode_var = tk.StringVar(value="Normal")
        self.delete_cfg_var = tk.BooleanVar(value=False)

        # ── Progress ─────────────────────────────────────────────
        self.progress_var = tk.DoubleVar(value=0)
        self.status_var = tk.StringVar(value="Ready")
        self.progress_detail_var = tk.StringVar(value="")

        # ── Protocol (Settings tab) ──────────────────────────────
        self.send_port_var = tk.StringVar(value=str(OBSC_SEND_PORT))
        self.recv_port_var = tk.StringVar(value=str(OBSC_RECV_PORT))
        self.broadcast_var = tk.StringVar(value="auto")
        self.timeout_var = tk.StringVar(value="600")
        self.upgrade_type_var = tk.StringVar(value="Standard")
        self.machine_filter_var = tk.StringVar(value="")
        self.discovery_duration_var = tk.StringVar(value="10")
        self.ctrl_retries_var = tk.StringVar(value="3")
        self.data_retries_var = tk.StringVar(value="0")
        self.check_policy_var = tk.StringVar(value="")
        self.bom_code_var = tk.StringVar(value="")

        # ── IP Mode (Settings tab) ───────────────────────────────
        self.ip_mode_var = tk.StringVar(value="automatic")
        self.ip_mode_ip_var = tk.StringVar(value=DEFAULT_IP_CONFIG["ip"])
        self.ip_mode_mask_var = tk.StringVar(value=DEFAULT_IP_CONFIG["netmask"])
        self.ip_mode_gw_var = tk.StringVar(value=DEFAULT_IP_CONFIG["gateway"])
        self.ip_mode_dns_var = tk.StringVar(
            value=DEFAULT_IP_CONFIG.get("dns1", "8.8.8.8")
        )
        self.ip_mode_status_var = tk.StringVar(value="")

        # ── Logging (Settings tab) ───────────────────────────────
        self.log_dir_var = tk.StringVar(
            value=os.path.join(os.getcwd(), "logs")
        )
        self.auto_log_var = tk.BooleanVar(value=True)

        # ── Verification (Verify tab) ────────────────────────────
        self.verify_crc32_var = tk.BooleanVar(value=True)
        self.verify_signature_var = tk.BooleanVar(value=False)
        self.skip_product_check_var = tk.BooleanVar(value=False)
        self.verify_item_crc_var = tk.BooleanVar(value=False)
        self.verify_size_var = tk.BooleanVar(value=True)
        self.dry_run_var = tk.BooleanVar(value=False)
        self.pubkey_path_var = tk.StringVar(value="")

        # ── Crypto (Crypto tab) ──────────────────────────────────
        self.crypto_input_var = tk.StringVar()
        self.crypto_output_var = tk.StringVar()
        self.crypto_chip_var = tk.StringVar(value="Auto")
        self.crypto_custom_chip_var = tk.StringVar()
        self.cfg_search_var = tk.StringVar()

        # ── Terminal (Terminal tab) ───────────────────────────────
        self.term_type_var = tk.StringVar(value="Telnet")
        self.term_host_var = tk.StringVar(value="192.168.100.1")
        self.term_port_var = tk.StringVar(value="23")
        self.term_com_var = tk.StringVar()
        self.term_baud_var = tk.StringVar(value="115200")
        self.term_nic_var = tk.StringVar()
        self.term_status_var = tk.StringVar(value="Disconnected")
        self.term_input_var = tk.StringVar()

        # ── Dump (Dump tab) ──────────────────────────────────────
        self.dump_status_var = tk.StringVar(
            value="Connect via Terminal tab first"
        )

        # ── Network config (Settings tab) ────────────────────────
        self.cfg_adapter_var = tk.StringVar()
        self.cfg_ip_var = tk.StringVar(value="192.168.100.100")
        self.cfg_mask_var = tk.StringVar(value="255.255.255.0")
        self.cfg_gw_var = tk.StringVar(value="")
        self.net_status_var = tk.StringVar(value="")

        # ── Presets ──────────────────────────────────────────────
        self.preset_var = tk.StringVar()
        self.preset_desc_var = tk.StringVar(
            value="Select a preset to see its description"
        )

        # ── Firmware Info ────────────────────────────────────────
        self.fw_info_status_var = tk.StringVar(value="Load a firmware file first")

        # ── Runtime objects (not tk vars) ────────────────────────
        self.worker: Optional[OBSCWorker] = None
        self.transport: Optional[UDPTransport] = None
        self.telnet_client = None  # set in app.py
        self.serial_client = None  # set in app.py
        self.firmware_dumper: Optional[FirmwareDumper] = None
        self.preset_manager: Optional[PresetManager] = None
        self.log_entries: List[str] = []
        self.adapter_combos: List = []  # combos to refresh on adapter discovery


class AppController:
    """Cross-tab operations invoked by any tab.

    Keeps tabs decoupled — they call ``ctrl.log()``, ``ctrl.refresh_adapters()``,
    etc. without knowing about sibling tab classes.
    """

    def __init__(self, state: AppState, theme_engine: ThemeEngine):
        self.state = state
        self.theme_engine = theme_engine

        # Callback hooks set by the orchestrator (app.py) after
        # all tabs are created.
        self._refresh_adapters: Optional[Callable] = None
        self._refresh_fw_info: Optional[Callable] = None
        self._update_status_bar: Optional[Callable[[str], None]] = None

    # ── Logging ──────────────────────────────────────────────────

    def log(self, message: str) -> None:
        """Append a timestamped message to the shared log."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.state.log_entries.append(entry)
        logger.debug(message)

        # Also push to the log text widget (if bound)
        if self._on_log:
            try:
                self.state.root.after(0, lambda: self._on_log(entry))
            except Exception:
                pass

    _on_log: Optional[Callable[[str], None]] = None

    def bind_log_widget(self, callback: Callable[[str], None]) -> None:
        """Called by LogTab to register its append-text callback."""
        self._on_log = callback

    # ── Adapter refresh ──────────────────────────────────────────

    def refresh_adapters(self) -> None:
        if self._refresh_adapters:
            self._refresh_adapters()

    # ── Firmware info refresh ────────────────────────────────────

    def refresh_fw_info(self) -> None:
        if self._refresh_fw_info:
            self._refresh_fw_info()

    # ── Status bar ───────────────────────────────────────────────

    def set_status(self, text: str) -> None:
        if self._update_status_bar:
            self._update_status_bar(text)

    # ── Selected adapter ─────────────────────────────────────────

    def get_selected_adapter(self):
        """Return the currently selected ``NetworkAdapter`` or ``None``."""
        try:
            from hwflash.core.network import NetworkAdapter  # noqa: F811
        except ImportError:
            pass
        # Find widget – adapter_combo is stored on the UpgradeTab
        # but the state holds the list.  Use combo index from state.
        if hasattr(self, "_adapter_combo"):
            idx = self._adapter_combo.current()
            if 0 <= idx < len(self.state.adapters):
                return self.state.adapters[idx]
        return None

    _adapter_combo = None

    def bind_adapter_combo(self, combo) -> None:
        self._adapter_combo = combo

    # ── Auto-save log ────────────────────────────────────────────

    def auto_save_log(self) -> None:
        """Auto-save log to the configured log directory."""
        try:
            log_dir = self.state.log_dir_var.get()
            os.makedirs(log_dir, exist_ok=True)
            filename = f"hwflash_{datetime.datetime.now().strftime('%Y-%m-%d_%H')}.log"
            path = os.path.join(log_dir, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.state.log_entries))
            self.log(f"Log auto-saved to {path}")
        except OSError as e:
            self.log(f"Failed to auto-save log: {e}")
