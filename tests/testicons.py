"""Tests for shared.icons module."""

from hwflash.shared.icons import (
    generate_logo,
    generate_icon,
    logo_to_base64,
    BRAND_BLUE,
    BRAND_CYAN,
    BRAND_DARK,
    BRAND_LIGHT,
)


class TestGenerateLogo:
    """Tests for logo generation."""

    def test_generates_png_bytes(self):
        data = generate_logo(64)
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_png_header(self):
        data = generate_logo(64)
        # PNG magic bytes
        assert data[:4] == b'\x89PNG'

    def test_different_sizes(self):
        small = generate_logo(32)
        large = generate_logo(128)
        assert len(small) < len(large)

    def test_default_size(self):
        data = generate_logo()
        assert len(data) > 0


class TestGenerateIcon:
    """Tests for icon generation."""

    def test_flash_icon(self):
        data = generate_icon("flash", 20)
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_folder_icon(self):
        data = generate_icon("folder", 20)
        assert len(data) > 0

    def test_unknown_icon(self):
        data = generate_icon("unknown_icon", 20)
        assert len(data) > 0  # Falls back to default circle

    def test_custom_color(self):
        data = generate_icon("flash", 20, "#FF0000")
        assert len(data) > 0

    def test_icon_names(self):
        for name in ["flash", "folder", "play", "stop", "settings",
                     "terminal", "shield", "info", "refresh",
                     "connect", "disconnect", "check", "warning",
                     "save", "log", "trash", "copy", "x",
                     "upload", "download", "key", "lock", "unlock", "search"]:
            data = generate_icon(name, 16)
            assert len(data) > 0, f"Icon {name} failed to generate"

    def test_new_icons_produce_png(self):
        for name in ["save", "log", "trash", "copy", "x",
                     "upload", "download", "key", "lock", "unlock", "search"]:
            data = generate_icon(name, 20)
            assert data[:4] == b'\x89PNG', f"Icon {name} is not PNG"


class TestLogoToBase64:
    """Tests for base64 logo encoding."""

    def test_returns_string(self):
        result = logo_to_base64(32)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_is_valid_base64(self):
        import base64
        result = logo_to_base64(32)
        decoded = base64.b64decode(result)
        assert decoded[:4] == b'\x89PNG'


class TestBrandColors:
    """Tests for brand color constants."""

    def test_colors_are_hex(self):
        for color in [BRAND_BLUE, BRAND_CYAN, BRAND_DARK, BRAND_LIGHT]:
            assert color.startswith("#")
            assert len(color) == 7
