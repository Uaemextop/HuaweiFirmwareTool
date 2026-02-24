"""
Tests for obsc_tool.presets (PresetManager).
"""

import os
import json
import tempfile

import pytest

from obsc_tool.presets import PresetManager, BUILTIN_PRESETS, PRESET_TEMPLATE


class TestPresetManagerBuiltins:
    def test_builtin_presets_available(self):
        pm = PresetManager()
        names = pm.list_presets()
        assert len(names) > 0

    def test_builtin_presets_match_expected(self):
        pm = PresetManager()
        for name in BUILTIN_PRESETS:
            assert name in pm.list_presets()

    def test_get_builtin_preset_returns_copy(self):
        pm = PresetManager()
        names = pm.list_presets()
        preset = pm.get_preset(names[0])
        assert preset is not None
        # Modifying the returned copy must not affect stored preset
        preset['frame_size'] = 9999
        preset2 = pm.get_preset(names[0])
        assert preset2['frame_size'] != 9999

    def test_cannot_delete_builtin(self):
        pm = PresetManager()
        for name in BUILTIN_PRESETS:
            result = pm.delete_preset(name)
            assert result is False
            assert name in pm.list_presets()

    def test_is_builtin_returns_true(self):
        pm = PresetManager()
        for name in BUILTIN_PRESETS:
            assert pm.is_builtin(name) is True

    def test_get_nonexistent_preset_returns_none(self):
        pm = PresetManager()
        assert pm.get_preset('__does_not_exist__') is None


class TestPresetManagerUserPresets:
    def test_save_and_retrieve_preset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            preset_data = {'frame_size': 1400, 'frame_interval_ms': 5}
            pm.save_preset('MyPreset', preset_data)
            assert 'MyPreset' in pm.list_presets()
            retrieved = pm.get_preset('MyPreset')
            assert retrieved['frame_size'] == 1400
            assert retrieved['frame_interval_ms'] == 5

    def test_saved_preset_persists_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            pm.save_preset('PersistTest', {'frame_size': 800})

            # Load a fresh manager from the same directory
            pm2 = PresetManager(presets_dir=tmpdir)
            assert 'PersistTest' in pm2.list_presets()
            assert pm2.get_preset('PersistTest')['frame_size'] == 800

    def test_delete_user_preset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            pm.save_preset('ToDelete', {'frame_size': 1200})
            assert 'ToDelete' in pm.list_presets()
            result = pm.delete_preset('ToDelete')
            assert result is True
            assert 'ToDelete' not in pm.list_presets()

    def test_delete_nonexistent_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            assert pm.delete_preset('ghost_preset') is False

    def test_is_builtin_false_for_user_preset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            pm.save_preset('UserOne', {})
            assert pm.is_builtin('UserOne') is False

    def test_list_presets_sorted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            pm.save_preset('Zebra', {})
            pm.save_preset('Alpha', {})
            names = pm.list_presets()
            assert names == sorted(names)

    def test_save_overwrites_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            pm.save_preset('EditMe', {'frame_size': 1000})
            pm.save_preset('EditMe', {'frame_size': 1400})
            assert pm.get_preset('EditMe')['frame_size'] == 1400

    def test_preset_template_provides_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pm = PresetManager(presets_dir=tmpdir)
            pm.save_preset('Minimal', {})
            preset = pm.get_preset('Minimal')
            # All template keys should be present
            for key in PRESET_TEMPLATE:
                assert key in preset

    def test_new_preset_template(self):
        tmpl = PresetManager.new_preset_template()
        assert isinstance(tmpl, dict)
        for key in PRESET_TEMPLATE:
            assert key in tmpl
