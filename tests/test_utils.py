"""
Tests for obsc_tool.utils (shared utility functions).
"""

import pytest

from obsc_tool.utils import (
    safe_int,
    safe_float,
    clamp,
    format_size,
    format_duration,
    log_line,
    is_valid_ip,
    is_valid_netmask,
    broadcast_address,
    crc32_of,
    hex32,
    safe_filename,
    lerp_color,
    rgb_hex,
)


class TestSafeConversions:
    def test_safe_int_valid(self):
        assert safe_int("42") == 42
        assert safe_int(3.7) == 3
        assert safe_int("0") == 0

    def test_safe_int_invalid(self):
        assert safe_int("abc") == 0
        assert safe_int(None) == 0
        assert safe_int("abc", default=99) == 99

    def test_safe_float_valid(self):
        assert safe_float("3.14") == pytest.approx(3.14)
        assert safe_float("0") == 0.0

    def test_safe_float_invalid(self):
        assert safe_float("nope", default=1.5) == 1.5

    def test_clamp(self):
        assert clamp(5.0, 0.0, 10.0) == 5.0
        assert clamp(-1.0, 0.0, 10.0) == 0.0
        assert clamp(11.0, 0.0, 10.0) == 10.0
        assert clamp(0.0, 0.0, 0.0) == 0.0


class TestFormatHelpers:
    def test_format_size_bytes(self):
        assert format_size(512) == "512 B"

    def test_format_size_kb(self):
        result = format_size(2048)
        assert "KB" in result

    def test_format_size_mb(self):
        result = format_size(5 * 1024 * 1024)
        assert "MB" in result

    def test_format_duration_seconds(self):
        assert format_duration(45) == "45s"

    def test_format_duration_minutes(self):
        result = format_duration(125)
        assert "m" in result and "s" in result

    def test_format_duration_hours(self):
        result = format_duration(3700)
        assert "h" in result

    def test_log_line_format(self):
        line = log_line("test message")
        assert "test message" in line
        assert "[" in line and "]" in line


class TestNetworkHelpers:
    def test_valid_ip(self):
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("0.0.0.0") is True
        assert is_valid_ip("255.255.255.255") is True

    def test_invalid_ip(self):
        assert is_valid_ip("999.0.0.1") is False
        assert is_valid_ip("not_an_ip") is False
        assert is_valid_ip("") is False

    def test_valid_netmask(self):
        assert is_valid_netmask("255.255.255.0") is True
        assert is_valid_netmask("255.255.0.0") is True
        assert is_valid_netmask("255.0.0.0") is True
        assert is_valid_netmask("0.0.0.0") is True

    def test_invalid_netmask(self):
        assert is_valid_netmask("255.255.255.1") is False
        assert is_valid_netmask("abc") is False

    def test_broadcast_address(self):
        result = broadcast_address("192.168.100.100", "255.255.255.0")
        assert result == "192.168.100.255"

    def test_broadcast_address_fallback(self):
        result = broadcast_address("invalid", "invalid")
        assert result == "255.255.255.255"


class TestChecksumHelpers:
    def test_crc32_empty(self):
        assert isinstance(crc32_of(b""), int)

    def test_crc32_deterministic(self):
        assert crc32_of(b"hello") == crc32_of(b"hello")

    def test_crc32_differs(self):
        assert crc32_of(b"hello") != crc32_of(b"world")

    def test_crc32_unsigned(self):
        assert 0 <= crc32_of(b"\xFF" * 100) <= 0xFFFFFFFF

    def test_hex32_format(self):
        assert hex32(0) == "0x00000000"
        assert hex32(0xABCDEF01) == "0xABCDEF01"
        assert hex32(-1) == "0xFFFFFFFF"  # unsigned masking


class TestPathHelpers:
    def test_safe_filename_strips_invalid(self):
        result = safe_filename("file<>:name.txt")
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_safe_filename_keeps_normal(self):
        assert safe_filename("firmware.bin") == "firmware.bin"

    def test_safe_filename_null_bytes(self):
        result = safe_filename("name\x00\x01test")
        assert "\x00" not in result


class TestColourHelpers:
    def test_lerp_color_zero(self):
        assert lerp_color((0, 0, 0), (255, 255, 255), 0.0) == (0, 0, 0)

    def test_lerp_color_one(self):
        assert lerp_color((0, 0, 0), (255, 255, 255), 1.0) == (255, 255, 255)

    def test_lerp_color_mid(self):
        result = lerp_color((0, 0, 0), (100, 200, 50), 0.5)
        assert result == (50, 100, 25)

    def test_lerp_color_with_alpha(self):
        result = lerp_color((0, 0, 0, 0), (100, 100, 100, 255), 0.5)
        assert len(result) == 4

    def test_rgb_hex_format(self):
        assert rgb_hex(255, 0, 0) == "#ff0000"
        assert rgb_hex(0, 255, 0) == "#00ff00"
        assert rgb_hex(0, 0, 255) == "#0000ff"
        assert rgb_hex(0, 0, 0) == "#000000"

    def test_rgb_hex_clamped(self):
        # Values > 255 should wrap to 8-bit
        result = rgb_hex(256, 0, 0)
        assert isinstance(result, str)
        assert result.startswith("#")
