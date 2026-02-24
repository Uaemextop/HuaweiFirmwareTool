"""Tests for shared.styles module."""

from hwflash.shared.styles import (
    THEMES,
    DARK,
    LIGHT,
    get_theme,
    get_gradient,
    PRIMARY,
    SECONDARY,
    SUCCESS,
    DANGER,
    FONT_FAMILY,
    FONT_SIZES,
    PADDING,
    RADIUS,
    ANIMATION,
)


class TestThemes:
    """Tests for theme system."""

    def test_dark_theme_exists(self):
        assert "dark" in THEMES

    def test_light_theme_exists(self):
        assert "light" in THEMES

    def test_dark_has_all_keys(self):
        required_keys = ["bg", "fg", "accent", "border", "success", "danger"]
        for key in required_keys:
            assert key in DARK, f"Missing key: {key}"

    def test_light_has_all_keys(self):
        required_keys = ["bg", "fg", "accent", "border", "success", "danger"]
        for key in required_keys:
            assert key in LIGHT, f"Missing key: {key}"

    def test_get_theme_dark(self):
        theme = get_theme("dark")
        assert theme == DARK

    def test_get_theme_light(self):
        theme = get_theme("light")
        assert theme == LIGHT

    def test_get_theme_fallback(self):
        theme = get_theme("nonexistent")
        assert theme == DARK

    def test_get_gradient(self):
        start, end = get_gradient(DARK)
        assert start.startswith("#")
        assert end.startswith("#")

    def test_color_format(self):
        for name, theme in THEMES.items():
            for key, value in theme.items():
                assert value.startswith("#"), f"{name}.{key} = {value} is not a hex color"


class TestConstants:
    """Tests for style constants."""

    def test_primary_color(self):
        assert PRIMARY.startswith("#")

    def test_secondary_color(self):
        assert SECONDARY.startswith("#")

    def test_font_family(self):
        assert isinstance(FONT_FAMILY, str)

    def test_font_sizes(self):
        assert "body" in FONT_SIZES
        assert "title" in FONT_SIZES
        assert FONT_SIZES["title"] > FONT_SIZES["body"]

    def test_padding(self):
        assert PADDING["xs"] < PADDING["sm"] < PADDING["md"] < PADDING["lg"]

    def test_radius(self):
        assert RADIUS["sm"] < RADIUS["md"] < RADIUS["lg"]

    def test_animation(self):
        assert "fade_duration" in ANIMATION
        assert ANIMATION["fade_duration"] > 0
