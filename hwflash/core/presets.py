"""
Router preset management for the HuaweiFlash.

Allows creating, saving, loading, and deleting configuration presets
for different router models (e.g., HG8145V5, HG8245H, etc.).
Presets are stored as JSON files in a user-configurable directory.
"""

import json
import os
import copy

# Packaged presets directory (read-only in many installs)
DEFAULT_PRESETS_DIR = os.path.join(os.path.dirname(__file__), "presets")


def _default_user_presets_dir():
    """Return a user-writable presets directory."""
    appdata = os.environ.get('APPDATA')
    if appdata:
        return os.path.join(appdata, 'HuaweiFirmwareTool', 'presets')
    return os.path.join(os.path.expanduser('~'), '.huawei-firmware-tool', 'presets')


DEFAULT_USER_PRESETS_DIR = _default_user_presets_dir()

# Built-in presets for common Huawei ONT models
BUILTIN_PRESETS = {
    "HG8145V5 (Default)": {
        "description": "Huawei HG8145V5 — Default settings for standard upgrade",
        "model": "HG8145V5",
        "frame_size": 1400,
        "frame_interval_ms": 5,
        "flash_mode": "Normal",
        "delete_cfg": False,
        "upgrade_type": "Standard",
        "send_port": 50000,
        "recv_port": 50001,
        "timeout": 600,
        "machine_filter": "",
        "broadcast_address": "auto",
        "verify_crc32": True,
        "verify_signature": False,
        "skip_product_check": False,
        "discovery_duration": 10,
        "ctrl_retries": 3,
        "data_retries": 0,
        "check_policy": "",
        "bom_code": "",
    },
    "HG8145V5 (Unlock)": {
        "description": "Huawei HG8145V5 — Optimized for unlock/downgrade flashing",
        "model": "HG8145V5",
        "frame_size": 1400,
        "frame_interval_ms": 5,
        "flash_mode": "Forced",
        "delete_cfg": False,
        "upgrade_type": "Standard",
        "send_port": 50000,
        "recv_port": 50001,
        "timeout": 600,
        "machine_filter": "",
        "broadcast_address": "auto",
        "verify_crc32": True,
        "verify_signature": False,
        "skip_product_check": True,
        "discovery_duration": 10,
        "ctrl_retries": 5,
        "data_retries": 1,
        "check_policy": "",
        "bom_code": "",
    },
    "HG8245H": {
        "description": "Huawei HG8245H — Standard ONT settings",
        "model": "HG8245H",
        "frame_size": 1200,
        "frame_interval_ms": 10,
        "flash_mode": "Normal",
        "delete_cfg": False,
        "upgrade_type": "Standard",
        "send_port": 50000,
        "recv_port": 50001,
        "timeout": 600,
        "machine_filter": "",
        "broadcast_address": "auto",
        "verify_crc32": True,
        "verify_signature": False,
        "skip_product_check": False,
        "discovery_duration": 10,
        "ctrl_retries": 3,
        "data_retries": 0,
        "check_policy": "",
        "bom_code": "",
    },
    "HG8546M": {
        "description": "Huawei HG8546M — Standard ONT settings",
        "model": "HG8546M",
        "frame_size": 1400,
        "frame_interval_ms": 5,
        "flash_mode": "Normal",
        "delete_cfg": False,
        "upgrade_type": "Standard",
        "send_port": 50000,
        "recv_port": 50001,
        "timeout": 600,
        "machine_filter": "",
        "broadcast_address": "auto",
        "verify_crc32": True,
        "verify_signature": False,
        "skip_product_check": False,
        "discovery_duration": 10,
        "ctrl_retries": 3,
        "data_retries": 0,
        "check_policy": "",
        "bom_code": "",
    },
    "Generic ONT (Safe)": {
        "description": "Generic — Conservative settings for unknown devices",
        "model": "Generic",
        "frame_size": 1200,
        "frame_interval_ms": 10,
        "flash_mode": "Normal",
        "delete_cfg": False,
        "upgrade_type": "Standard",
        "send_port": 50000,
        "recv_port": 50001,
        "timeout": 900,
        "machine_filter": "",
        "broadcast_address": "auto",
        "verify_crc32": True,
        "verify_signature": False,
        "skip_product_check": False,
        "discovery_duration": 15,
        "ctrl_retries": 5,
        "data_retries": 1,
        "check_policy": "",
        "bom_code": "",
    },
    "Generic ONT (Fast)": {
        "description": "Generic — Aggressive settings for fast transfer",
        "model": "Generic",
        "frame_size": 4096,
        "frame_interval_ms": 1,
        "flash_mode": "Normal",
        "delete_cfg": False,
        "upgrade_type": "Standard",
        "send_port": 50000,
        "recv_port": 50001,
        "timeout": 300,
        "machine_filter": "",
        "broadcast_address": "auto",
        "verify_crc32": True,
        "verify_signature": False,
        "skip_product_check": False,
        "discovery_duration": 5,
        "ctrl_retries": 3,
        "data_retries": 0,
        "check_policy": "",
        "bom_code": "",
    },
}

# Template for new presets
PRESET_TEMPLATE = {
    "description": "",
    "model": "",
    "frame_size": 1400,
    "frame_interval_ms": 5,
    "flash_mode": "Normal",
    "delete_cfg": False,
    "upgrade_type": "Standard",
    "send_port": 50000,
    "recv_port": 50001,
    "timeout": 600,
    "machine_filter": "",
    "broadcast_address": "auto",
    "verify_crc32": True,
    "verify_signature": False,
    "skip_product_check": False,
    "discovery_duration": 10,
    "ctrl_retries": 3,
    "data_retries": 0,
    "check_policy": "",
    "bom_code": "",
}


class PresetManager:
    """Manages router configuration presets."""

    def __init__(self, presets_dir=None):
        # Presets created by the user are stored in a user-writable directory.
        # Packaged presets are still loaded from DEFAULT_PRESETS_DIR.
        self.presets_dir = presets_dir or DEFAULT_USER_PRESETS_DIR
        self._builtin_presets_dir = DEFAULT_PRESETS_DIR
        self._presets = {}
        self._load_builtins()
        self._load_json_presets_from_dir(self._builtin_presets_dir)
        self._load_json_presets_from_dir(self.presets_dir)

    def _load_builtins(self):
        """Load built-in presets."""
        for name, preset in BUILTIN_PRESETS.items():
            self._presets[name] = copy.deepcopy(preset)

    def _load_json_presets_from_dir(self, directory):
        """Load presets from JSON files in *directory* (best-effort)."""
        if not directory or not os.path.isdir(directory):
            return

        for filename in os.listdir(directory):
            if not filename.lower().endswith('.json'):
                continue
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                name = data.get('_name', filename[:-5])
                preset = copy.deepcopy(PRESET_TEMPLATE)
                preset.update({k: v for k, v in data.items() if k != '_name'})
                self._presets[name] = preset
            except (json.JSONDecodeError, OSError, KeyError):
                pass

    def list_presets(self):
        """Return sorted list of preset names."""
        return sorted(self._presets.keys())

    def get_preset(self, name):
        """Get a preset by name. Returns a copy."""
        if name in self._presets:
            return copy.deepcopy(self._presets[name])
        return None

    @staticmethod
    def _safe_preset_name(name):
        """Convert a preset display name to a safe filename stem."""
        return "".join(c if c.isalnum() or c in ' _-' else '_' for c in name)

    def save_preset(self, name, preset_data):
        """Save a preset (creates/overwrites).

        Args:
            name: Preset display name.
            preset_data: Dict with preset configuration.
        """
        # Merge with template
        preset = copy.deepcopy(PRESET_TEMPLATE)
        preset.update(preset_data)
        self._presets[name] = preset

        # Save to disk
        os.makedirs(self.presets_dir, exist_ok=True)
        filepath = os.path.join(self.presets_dir,
                                f"{self._safe_preset_name(name)}.json")
        save_data = copy.deepcopy(preset)
        save_data['_name'] = name
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, indent=2, ensure_ascii=False)

    def delete_preset(self, name):
        """Delete a user preset.

        Built-in presets cannot be deleted.

        Returns:
            True if deleted, False if not found or built-in.
        """
        if name in BUILTIN_PRESETS:
            return False
        if name not in self._presets:
            return False

        del self._presets[name]

        # Remove from disk
        filepath = os.path.join(self.presets_dir,
                                f"{self._safe_preset_name(name)}.json")
        if os.path.isfile(filepath):
            os.remove(filepath)

        return True

    def is_builtin(self, name):
        """Check if a preset is built-in (not user-created)."""
        return name in BUILTIN_PRESETS

    @staticmethod
    def new_preset_template():
        """Return a blank preset template for creating new presets."""
        return copy.deepcopy(PRESET_TEMPLATE)
