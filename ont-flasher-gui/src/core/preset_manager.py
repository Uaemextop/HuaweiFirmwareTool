"""
Preset Manager - Handle device presets and configurations
"""

import json
import os
from utils.logger import get_logger

class PresetManager:
    """Manages device configuration presets"""

    def __init__(self):
        self.logger = get_logger()
        self.presets_file = os.path.join(
            os.path.dirname(__file__), '..', '..', 'config', 'presets.json'
        )
        self.presets = self.load_presets()

    def load_presets(self):
        """Load presets from file"""
        # Default presets
        defaults = {
            "HG8145V5_Unlock": {
                "name": "HG8145V5 Unlock",
                "description": "Optimized for HG8145V5 unlock operations",
                "baudrate": 115200,
                "timeout": 1400,
                "delay": 5,
                "chunk_size": 1024,
                "retry_count": 3,
                "verify": True,
                "reboot": True,
                "signature_check": False,
                "custom": False
            },
            "HG8245_Standard": {
                "name": "HG8245 Standard",
                "description": "Standard settings for HG8245 devices",
                "baudrate": 115200,
                "timeout": 1200,
                "delay": 10,
                "chunk_size": 1024,
                "retry_count": 3,
                "verify": True,
                "reboot": True,
                "signature_check": False,
                "custom": False
            },
            "Safe_Mode": {
                "name": "Safe Mode",
                "description": "Conservative settings for maximum compatibility",
                "baudrate": 57600,
                "timeout": 2000,
                "delay": 20,
                "chunk_size": 512,
                "retry_count": 5,
                "verify": True,
                "reboot": True,
                "signature_check": True,
                "custom": False
            },
            "Fast_Mode": {
                "name": "Fast Mode",
                "description": "Optimized for speed (may be less reliable)",
                "baudrate": 115200,
                "timeout": 1000,
                "delay": 2,
                "chunk_size": 2048,
                "retry_count": 2,
                "verify": False,
                "reboot": True,
                "signature_check": False,
                "custom": False
            }
        }

        # Try to load from file
        if os.path.exists(self.presets_file):
            try:
                with open(self.presets_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    # Merge with defaults
                    defaults.update(loaded)
                    self.logger.info(f"Loaded {len(loaded)} custom presets")
            except Exception as e:
                self.logger.error(f"Error loading presets: {e}")

        return defaults

    def save_presets(self):
        """Save custom presets to file"""
        try:
            # Only save custom presets
            custom_presets = {
                k: v for k, v in self.presets.items()
                if v.get('custom', False)
            }

            # Ensure directory exists
            os.makedirs(os.path.dirname(self.presets_file), exist_ok=True)

            with open(self.presets_file, 'w', encoding='utf-8') as f:
                json.dump(custom_presets, f, indent=2)

            self.logger.info(f"Saved {len(custom_presets)} custom presets")
            return True

        except Exception as e:
            self.logger.error(f"Error saving presets: {e}")
            return False

    def get_preset(self, preset_id):
        """Get preset by ID"""
        return self.presets.get(preset_id)

    def get_all_presets(self):
        """Get all presets"""
        return self.presets

    def get_preset_list(self):
        """Get list of preset names and IDs"""
        return [
            (preset_id, preset['name'])
            for preset_id, preset in self.presets.items()
        ]

    def add_preset(self, preset_id, preset_data):
        """Add or update a preset"""
        preset_data['custom'] = True
        self.presets[preset_id] = preset_data
        return self.save_presets()

    def delete_preset(self, preset_id):
        """Delete a custom preset"""
        if preset_id in self.presets:
            preset = self.presets[preset_id]
            if preset.get('custom', False):
                del self.presets[preset_id]
                return self.save_presets()
            else:
                self.logger.warning(f"Cannot delete built-in preset: {preset_id}")
                return False
        return False

    def is_custom_preset(self, preset_id):
        """Check if preset is custom"""
        preset = self.presets.get(preset_id)
        return preset.get('custom', False) if preset else False
