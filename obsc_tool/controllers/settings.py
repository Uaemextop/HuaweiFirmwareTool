"""Settings and configuration controller."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from .base import BaseController


class SettingsController(BaseController):
    """
    Controller for application settings.

    Handles:
    - Settings persistence
    - Configuration management
    - Theme settings
    - User preferences
    """

    DEFAULT_SETTINGS = {
        'theme': 'light',
        'language': 'en',
        'auto_save': True,
        'recent_files': [],
        'window_geometry': '',
        'default_ip': '192.168.1.1',
        'default_port': 5555,
        'connection_timeout': 10,
        'chunk_size': 4096,
        'log_level': 'INFO',
        'save_logs': True,
    }

    def __init__(self, settings_file: Optional[Path] = None):
        """
        Initialize settings controller.

        Args:
            settings_file: Path to settings file
        """
        super().__init__()
        self._settings_file = settings_file or Path.home() / '.obsc_tool' / 'settings.json'
        self._settings: Dict[str, Any] = self.DEFAULT_SETTINGS.copy()
        self.load_settings()

    def load_settings(self) -> bool:
        """
        Load settings from file.

        Returns:
            True if loaded successfully

        Emits:
            - settings_loaded: (settings_dict)
            - settings_load_failed: (error)
        """
        try:
            if self._settings_file.exists():
                with open(self._settings_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    self._settings.update(loaded)

                self.emit_event('settings_loaded', self._settings.copy())
                self.logger.info(f"Settings loaded from {self._settings_file}")
                return True
            else:
                self.logger.info("No settings file found, using defaults")
                return False

        except Exception as e:
            self.handle_error(e, "Failed to load settings")
            self.emit_event('settings_load_failed', str(e))
            return False

    def save_settings(self) -> bool:
        """
        Save settings to file.

        Returns:
            True if saved successfully

        Emits:
            - settings_saved: (settings_file)
            - settings_save_failed: (error)
        """
        try:
            # Ensure directory exists
            self._settings_file.parent.mkdir(parents=True, exist_ok=True)

            with open(self._settings_file, 'w', encoding='utf-8') as f:
                json.dump(self._settings, f, indent=2)

            self.emit_event('settings_saved', str(self._settings_file))
            self.logger.info(f"Settings saved to {self._settings_file}")
            return True

        except Exception as e:
            self.handle_error(e, "Failed to save settings")
            self.emit_event('settings_save_failed', str(e))
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get setting value.

        Args:
            key: Setting key
            default: Default value if key not found

        Returns:
            Setting value or default
        """
        return self._settings.get(key, default)

    def set(self, key: str, value: Any, save: bool = True) -> bool:
        """
        Set setting value.

        Args:
            key: Setting key
            value: Value to set
            save: Whether to save immediately

        Returns:
            True if set successfully

        Emits:
            - setting_changed: (key, value)
        """
        old_value = self._settings.get(key)
        self._settings[key] = value

        self.emit_event('setting_changed', key, value)
        self.logger.debug(f"Setting changed: {key} = {value}")

        if save:
            return self.save_settings()
        return True

    def update(self, settings: Dict[str, Any], save: bool = True) -> bool:
        """
        Update multiple settings.

        Args:
            settings: Dictionary of settings to update
            save: Whether to save immediately

        Returns:
            True if updated successfully

        Emits:
            - settings_updated: (updated_dict)
        """
        self._settings.update(settings)
        self.emit_event('settings_updated', settings.copy())

        if save:
            return self.save_settings()
        return True

    def reset_to_defaults(self, save: bool = True) -> bool:
        """
        Reset all settings to defaults.

        Args:
            save: Whether to save immediately

        Returns:
            True if reset successfully

        Emits:
            - settings_reset
        """
        self._settings = self.DEFAULT_SETTINGS.copy()
        self.emit_event('settings_reset')
        self.logger.info("Settings reset to defaults")

        if save:
            return self.save_settings()
        return True

    def get_all(self) -> Dict[str, Any]:
        """
        Get all settings.

        Returns:
            Copy of all settings
        """
        return self._settings.copy()

    def add_recent_file(self, file_path: str, max_recent: int = 10):
        """
        Add file to recent files list.

        Args:
            file_path: Path to file
            max_recent: Maximum number of recent files to keep
        """
        recent = self.get('recent_files', [])

        # Remove if already exists
        if file_path in recent:
            recent.remove(file_path)

        # Add to front
        recent.insert(0, file_path)

        # Trim to max
        recent = recent[:max_recent]

        self.set('recent_files', recent)

    def get_recent_files(self) -> list:
        """
        Get recent files list.

        Returns:
            List of recent file paths
        """
        return self.get('recent_files', [])

    def clear_recent_files(self):
        """Clear recent files list."""
        self.set('recent_files', [])

    def export_settings(self, export_path: Path) -> bool:
        """
        Export settings to file.

        Args:
            export_path: Path to export file

        Returns:
            True if exported successfully
        """
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(self._settings, f, indent=2)
            self.logger.info(f"Settings exported to {export_path}")
            return True
        except Exception as e:
            self.handle_error(e, "Failed to export settings")
            return False

    def import_settings(self, import_path: Path, save: bool = True) -> bool:
        """
        Import settings from file.

        Args:
            import_path: Path to import file
            save: Whether to save after import

        Returns:
            True if imported successfully
        """
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported = json.load(f)
                self._settings.update(imported)

            self.emit_event('settings_imported', str(import_path))
            self.logger.info(f"Settings imported from {import_path}")

            if save:
                return self.save_settings()
            return True

        except Exception as e:
            self.handle_error(e, "Failed to import settings")
            return False
