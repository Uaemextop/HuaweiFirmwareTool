"""Tests for the presets module."""

import os
import json
import tempfile
import shutil
import pytest

from hwflash.core.presets import (
    PresetManager,
    BUILTIN_PRESETS,
    PRESET_TEMPLATE,
)


class TestPresetManager:
    """Test preset management."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.manager = PresetManager(presets_dir=self.tmpdir)

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_builtins_loaded(self):
        names = self.manager.list_presets()
        for name in BUILTIN_PRESETS:
            assert name in names

    def test_get_builtin_preset(self):
        preset = self.manager.get_preset("HG8145V5 (Default)")
        assert preset is not None
        assert preset['model'] == "HG8145V5"
        assert preset['frame_size'] == 1400

    def test_get_returns_copy(self):
        p1 = self.manager.get_preset("HG8145V5 (Default)")
        p2 = self.manager.get_preset("HG8145V5 (Default)")
        assert p1 == p2
        p1['frame_size'] = 9999
        p2_again = self.manager.get_preset("HG8145V5 (Default)")
        assert p2_again['frame_size'] == 1400

    def test_get_nonexistent(self):
        assert self.manager.get_preset("Nonexistent") is None

    def test_save_and_load_preset(self):
        preset = PresetManager.new_preset_template()
        preset['model'] = "CustomDevice"
        preset['frame_size'] = 2048
        self.manager.save_preset("My Custom", preset)

        loaded = self.manager.get_preset("My Custom")
        assert loaded is not None
        assert loaded['model'] == "CustomDevice"
        assert loaded['frame_size'] == 2048

    def test_save_creates_json_file(self):
        preset = PresetManager.new_preset_template()
        self.manager.save_preset("Test Preset", preset)
        files = os.listdir(self.tmpdir)
        assert any(f.endswith('.json') for f in files)

    def test_delete_user_preset(self):
        preset = PresetManager.new_preset_template()
        self.manager.save_preset("ToDelete", preset)
        assert self.manager.get_preset("ToDelete") is not None

        assert self.manager.delete_preset("ToDelete") is True
        assert self.manager.get_preset("ToDelete") is None

    def test_delete_builtin_fails(self):
        assert self.manager.delete_preset("HG8145V5 (Default)") is False

    def test_delete_nonexistent_fails(self):
        assert self.manager.delete_preset("Nonexistent") is False

    def test_is_builtin(self):
        assert self.manager.is_builtin("HG8145V5 (Default)") is True
        assert self.manager.is_builtin("CustomPreset") is False

    def test_new_template_has_all_keys(self):
        template = PresetManager.new_preset_template()
        for key in PRESET_TEMPLATE:
            assert key in template

    def test_preset_persistence(self):
        """Test that presets survive manager recreation."""
        preset = PresetManager.new_preset_template()
        preset['model'] = "Persistent"
        self.manager.save_preset("Persistent Preset", preset)

        # Create a new manager pointing to same directory
        new_manager = PresetManager(presets_dir=self.tmpdir)
        loaded = new_manager.get_preset("Persistent Preset")
        assert loaded is not None
        assert loaded['model'] == "Persistent"

    def test_save_merges_with_template(self):
        """Saving partial data fills in missing keys from template."""
        self.manager.save_preset("Partial", {"model": "Test"})
        loaded = self.manager.get_preset("Partial")
        assert loaded['frame_size'] == PRESET_TEMPLATE['frame_size']


class TestPresetTemplate:
    """Test preset template values."""

    def test_template_has_required_keys(self):
        required = [
            'frame_size', 'frame_interval_ms', 'flash_mode',
            'send_port', 'recv_port', 'timeout',
            'ctrl_retries', 'data_retries',
        ]
        for key in required:
            assert key in PRESET_TEMPLATE, f"Missing key: {key}"

    def test_template_defaults_are_sensible(self):
        assert 100 <= PRESET_TEMPLATE['frame_size'] <= 65500
        assert PRESET_TEMPLATE['frame_interval_ms'] >= 0
        assert PRESET_TEMPLATE['timeout'] > 0
        assert PRESET_TEMPLATE['ctrl_retries'] >= 0


class TestBuiltinPresets:
    """Test built-in presets."""

    def test_all_builtins_have_required_keys(self):
        for name, preset in BUILTIN_PRESETS.items():
            for key in PRESET_TEMPLATE:
                assert key in preset, f"Preset '{name}' missing key '{key}'"

    def test_builtin_preset_names_unique(self):
        names = list(BUILTIN_PRESETS.keys())
        assert len(names) == len(set(names))
