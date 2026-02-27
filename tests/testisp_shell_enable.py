"""Tests for tools/isp_shell_enable.py and the --name flag in download_firmwares.py."""

import sys
import os
import pytest

# Allow importing tools/ from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.isp_shell_enable import (
    resolve_isp,
    firmware_url,
    build_guide,
    ISP_ALIASES,
    ISP_DEFAULT_MODEL,
    ISP_FIRMWARE,
    RELEASE_BASE,
)


# ── resolve_isp ───────────────────────────────────────────────────────────────

class TestResolveIsp:
    """resolve_isp() maps all known aliases to their canonical key."""

    @pytest.mark.parametrize("alias", ["megacable", "mega", "megacable2"])
    def test_megacable_aliases(self, alias):
        assert resolve_isp(alias) == "megacable"

    @pytest.mark.parametrize("alias", ["MEGACABLE", "Mega", "MEGACABLE2"])
    def test_megacable_aliases_case_insensitive(self, alias):
        assert resolve_isp(alias) == "megacable"

    @pytest.mark.parametrize("alias", ["telmex", "infinitum"])
    def test_telmex_aliases(self, alias):
        assert resolve_isp(alias) == "telmex"

    def test_izzi(self):
        assert resolve_isp("izzi") == "izzi"

    @pytest.mark.parametrize("alias", ["generic", "any"])
    def test_generic_aliases(self, alias):
        assert resolve_isp(alias) == "generic"

    def test_unknown_returns_none(self):
        assert resolve_isp("unknownISP") is None

    def test_whitespace_stripped(self):
        assert resolve_isp("  mega  ") == "megacable"


# ── firmware_url ──────────────────────────────────────────────────────────────

class TestFirmwareUrl:
    def test_megacable_url_contains_eg8145v5(self):
        url = firmware_url("megacable")
        assert "EG8145V5" in url
        assert url.startswith(RELEASE_BASE)

    def test_telmex_url_contains_hg8145v5(self):
        url = firmware_url("telmex")
        assert "HG8145V5" in url or "5611" in url

    def test_unknown_isp_falls_back_to_generic(self):
        url = firmware_url("nonexistent")
        assert url == firmware_url("generic")

    def test_all_known_isps_return_url(self):
        for isp in ISP_ALIASES:
            url = firmware_url(isp)
            assert url.startswith("https://")


# ── build_guide ───────────────────────────────────────────────────────────────

class TestBuildGuide:
    def test_megacable_guide_contains_model(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "EG8145V5" in guide

    def test_megacable_guide_mentions_isp(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "Megacable" in guide

    def test_guide_contains_telnet_instructions(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "TelnetEnable" in guide
        assert "SSHEnable" in guide

    def test_guide_contains_cfgtool(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "cfgtool" in guide

    def test_guide_contains_obsc_method(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "OBSC" in guide or "Enable Package" in guide

    def test_guide_contains_disasm_section(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "arm_disasm.py" in guide or "radare2" in guide or "r2" in guide

    def test_download_section_included_when_requested(self):
        guide = build_guide("megacable", "EG8145V5", include_download=True)
        assert "download_firmwares.py" in guide

    def test_download_section_excluded_by_default(self):
        guide = build_guide("megacable", "EG8145V5", include_download=False)
        assert "download_firmwares.py" not in guide

    def test_guide_contains_download_firmwares_script_reference(self):
        guide = build_guide("megacable", "EG8145V5", include_download=True)
        assert "tools/download_firmwares.py" in guide

    def test_v5_device_labelled_v5_package(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "V5" in guide

    def test_note_appears_in_guide(self):
        guide = build_guide("megacable", "EG8145V5")
        assert "Note" in guide or "note" in guide.lower()


# ── ISP → model mapping ───────────────────────────────────────────────────────

class TestIspModelMapping:
    def test_megacable_maps_to_eg8145v5(self):
        assert ISP_DEFAULT_MODEL["megacable"] == "EG8145V5"

    def test_telmex_maps_to_hg8145v5(self):
        assert ISP_DEFAULT_MODEL["telmex"] == "HG8145V5"

    def test_all_isps_have_model(self):
        for isp in ISP_ALIASES:
            assert isp in ISP_DEFAULT_MODEL

    def test_all_isps_have_firmware(self):
        for isp in ISP_ALIASES:
            assert isp in ISP_FIRMWARE
            assert ISP_FIRMWARE[isp].endswith(".bin")


# ── download_firmwares --name flag ────────────────────────────────────────────

class TestDownloadFirmaresNameFilter:
    """Tests for the --name filter added to download_firmwares.py."""

    def test_name_filter_matches_eg8145v5(self):
        from tools.download_firmwares import FIRMWARES
        matches = [fw for fw in FIRMWARES if fw["name"].lower() == "eg8145v5"]
        assert len(matches) == 1
        assert "EG8145V5" in matches[0]["filename"]

    def test_name_filter_matches_hg8145v5(self):
        from tools.download_firmwares import FIRMWARES
        matches = [fw for fw in FIRMWARES if fw["name"].lower() == "hg8145v5"]
        assert len(matches) == 1

    def test_all_firmwares_have_name_field(self):
        from tools.download_firmwares import FIRMWARES
        for fw in FIRMWARES:
            assert "name" in fw
            assert fw["name"]

    def test_main_returns_1_on_unknown_name(self, monkeypatch, capsys):
        import tools.download_firmwares as dl
        monkeypatch.setattr(
            sys, "argv",
            ["download_firmwares.py", "--name", "NONEXISTENT_ISP",
             "--output-dir", "/tmp/fw_test_dir"],
        )
        ret = dl.main()
        assert ret == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.err


# ── Presets ───────────────────────────────────────────────────────────────────

class TestMegacablePreset:
    """The Megacable preset is available in the PresetManager."""

    def test_megacable_preset_exists(self):
        from hwflash.core.presets import PresetManager
        pm = PresetManager()
        names = pm.list_presets()
        assert any("Megacable" in n for n in names)

    def test_megacable_preset_model_is_eg8145v5(self):
        from hwflash.core.presets import PresetManager
        pm = PresetManager()
        preset = pm.get_preset("EG8145V5 (Megacable)")
        assert preset is not None
        assert preset["model"] == "EG8145V5"

    def test_megacable_preset_flash_mode_forced(self):
        from hwflash.core.presets import PresetManager
        pm = PresetManager()
        preset = pm.get_preset("EG8145V5 (Megacable)")
        assert preset["flash_mode"] == "Forced"

    def test_telmex_preset_exists(self):
        from hwflash.core.presets import PresetManager
        pm = PresetManager()
        preset = pm.get_preset("HG8145V5 (Telmex)")
        assert preset is not None
        assert preset["model"] == "HG8145V5"
