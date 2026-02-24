"""
Tests for obsc_tool.assets (logo generation).
"""

import io

import pytest

from obsc_tool.assets import get_logo_png, get_logo_photo


class TestLogoGeneration:
    def test_get_logo_png_returns_bytes(self):
        data = get_logo_png(64)
        assert data is not None
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_get_logo_png_is_valid_png(self):
        data = get_logo_png(64)
        assert data is not None
        # PNG magic bytes: 0x89 PNG \r \n \x1a \n
        assert data[:8] == b"\x89PNG\r\n\x1a\n"

    def test_get_logo_png_different_sizes(self):
        """Different sizes should produce different (valid) PNGs."""
        small = get_logo_png(32)
        large = get_logo_png(256)
        assert small is not None
        assert large is not None
        assert len(large) > len(small), "Larger image should produce bigger PNG"

    def test_get_logo_png_minimum_size(self):
        """Logo generation should work for small sizes without crashing."""
        data = get_logo_png(16)
        assert data is not None

    def test_get_logo_png_content_can_be_opened(self):
        """Generated PNG bytes should be loadable by PIL."""
        try:
            from PIL import Image

            data = get_logo_png(128)
            assert data is not None
            img = Image.open(io.BytesIO(data))
            assert img.size == (128, 128)
            assert img.mode == "RGBA"
        except ImportError:
            pytest.skip("PIL not installed")

    def test_get_logo_photo_without_display(self):
        """get_logo_photo should return None gracefully when no display is available."""
        # In CI without a display, both PIL and tk will fail; result is None
        result = get_logo_photo(size=32)
        # We just verify it doesn't raise an exception
        assert result is None or hasattr(result, "width") or hasattr(result, "get")
