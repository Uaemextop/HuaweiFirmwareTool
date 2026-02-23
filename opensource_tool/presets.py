"""
presets.py — Router preset management for Open OBSC Tool.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

PRESETS_FILE = "router_presets.json"

@dataclass
class RouterPreset:
    """Configuration preset for a specific router model."""
    name: str = ""
    model: str = ""
    description: str = ""
    # Network settings
    broadcast_port: int = 1200
    chunk_size: int = 1400
    retry_interval_ms: int = 10
    max_retries: int = 3
    timeout_ms: int = 5000
    # Board filter
    board_list: str = ""
    # Verification
    verify_crc32: bool = True
    verify_signature: bool = False
    rsa_public_key_path: str = ""
    # UpgradeCheck.xml settings
    bypass_upgrade_checks: bool = True
    hard_ver_check: bool = False
    lsw_chip_check: bool = False
    wifi_chip_check: bool = False
    voice_chip_check: bool = False
    usb_chip_check: bool = False
    optical_check: bool = False
    other_chip_check: bool = False
    product_check: bool = False
    program_check: bool = False
    cfg_check: bool = False
    # Encryption
    aes_key_template: str = "Df7!ui%s9(lmV1L8"
    chip_id: str = "SD5116H"
    # Flash options
    dry_run: bool = False
    auto_reboot: bool = True
    enable_telnet: bool = False
    enable_ssh: bool = False
    # Custom firmware version string
    firmware_version: str = ""


# Built-in presets for common Huawei ONT models
BUILTIN_PRESETS = {
    "HG8145V5 (Default)": RouterPreset(
        name="HG8145V5 (Default)",
        model="HG8145V5",
        description="Huawei HG8145V5 GPON ONT — default settings",
        broadcast_port=1200,
        chunk_size=1400,
        retry_interval_ms=10,
        board_list="120|130|140|141|150|160|170|171|180|190|1B1|1A1|1A0|1B0|1D0|1F1|201|211|221|230|240|260|261|270|271|280|281|291|2A1|431|",
        bypass_upgrade_checks=True,
        auto_reboot=True,
        chip_id="SD5116H",
    ),
    "HG8145V5 (Unlock R22)": RouterPreset(
        name="HG8145V5 (Unlock R22)",
        model="HG8145V5",
        description="HG8145V5 unlock preset — downgrade R22→R20, enable telnet, unlock",
        broadcast_port=1400,
        chunk_size=1400,
        retry_interval_ms=5,
        board_list="120|130|140|141|150|160|170|171|180|190|1B1|1A1|1A0|1B0|1D0|1F1|201|211|221|230|240|260|261|270|271|280|281|291|2A1|431|2D7|2D7D|2D7D.A|",
        bypass_upgrade_checks=True,
        auto_reboot=True,
        enable_telnet=True,
        enable_ssh=True,
        chip_id="SD5116H",
    ),
    "HG8245H": RouterPreset(
        name="HG8245H",
        model="HG8245H",
        description="Huawei HG8245H GPON ONT",
        broadcast_port=1200,
        chunk_size=1400,
        retry_interval_ms=10,
        board_list="",
        bypass_upgrade_checks=True,
        chip_id="SD5115",
    ),
    "HG8546M": RouterPreset(
        name="HG8546M",
        model="HG8546M",
        description="Huawei HG8546M GPON ONT",
        broadcast_port=1200,
        chunk_size=1400,
        retry_interval_ms=10,
        board_list="",
        bypass_upgrade_checks=True,
        chip_id="SD5116H",
    ),
    "EG8145V5": RouterPreset(
        name="EG8145V5",
        model="EG8145V5",
        description="Huawei EG8145V5 GPON ONT (EchoLife)",
        broadcast_port=1200,
        chunk_size=1400,
        retry_interval_ms=10,
        board_list="",
        bypass_upgrade_checks=True,
        chip_id="SD5116H",
    ),
    "Custom": RouterPreset(
        name="Custom",
        model="Custom",
        description="Empty custom preset — configure all settings manually",
    ),
}


class PresetManager:
    """Manages router presets — loading, saving, creating, deleting."""

    def __init__(self, config_dir: str = ""):
        self.config_dir = config_dir or os.path.dirname(os.path.abspath(__file__))
        self.presets: Dict[str, RouterPreset] = {}
        self._load_builtins()
        self._load_user_presets()

    def _load_builtins(self):
        """Load built-in presets."""
        for name, preset in BUILTIN_PRESETS.items():
            self.presets[name] = RouterPreset(**asdict(preset))

    def _load_user_presets(self):
        """Load user-saved presets from file."""
        path = os.path.join(self.config_dir, PRESETS_FILE)
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for name, preset_dict in data.items():
                self.presets[name] = RouterPreset(**preset_dict)
        except Exception:
            pass

    def save_user_presets(self):
        """Save user presets to file (excluding built-ins)."""
        user_presets = {}
        for name, preset in self.presets.items():
            if name not in BUILTIN_PRESETS:
                user_presets[name] = asdict(preset)
        path = os.path.join(self.config_dir, PRESETS_FILE)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(user_presets, f, indent=2)
        except Exception:
            pass

    def get_preset(self, name: str) -> Optional[RouterPreset]:
        return self.presets.get(name)

    def add_preset(self, preset: RouterPreset):
        self.presets[preset.name] = preset
        self.save_user_presets()

    def delete_preset(self, name: str) -> bool:
        if name in BUILTIN_PRESETS:
            return False  # Cannot delete built-in presets
        if name in self.presets:
            del self.presets[name]
            self.save_user_presets()
            return True
        return False

    def list_presets(self) -> List[str]:
        return list(self.presets.keys())

    def is_builtin(self, name: str) -> bool:
        return name in BUILTIN_PRESETS
