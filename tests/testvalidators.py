"""Tests for shared.validators module."""

import pytest

from hwflash.shared.validators import (
    is_valid_ip,
    is_valid_port,
    validate_range,
    validate_not_empty,
    validate_max_size,
    sanitize_string,
    parse_ip_port,
)


class TestIsValidIp:

    def test_valid(self):
        assert is_valid_ip("192.168.1.1") is True

    def test_broadcast(self):
        assert is_valid_ip("255.255.255.255") is True

    def test_zeros(self):
        assert is_valid_ip("0.0.0.0") is True

    def test_invalid_octet(self):
        assert is_valid_ip("256.1.1.1") is False

    def test_incomplete(self):
        assert is_valid_ip("192.168.1") is False

    def test_empty(self):
        assert is_valid_ip("") is False

    def test_letters(self):
        assert is_valid_ip("abc.def.ghi.jkl") is False


class TestIsValidPort:

    def test_valid(self):
        assert is_valid_port(80) is True

    def test_min(self):
        assert is_valid_port(1) is True

    def test_max(self):
        assert is_valid_port(65535) is True

    def test_zero(self):
        assert is_valid_port(0) is False

    def test_negative(self):
        assert is_valid_port(-1) is False

    def test_too_large(self):
        assert is_valid_port(65536) is False


class TestValidateRange:

    def test_in_range(self):
        assert validate_range(50, 0, 100) == 50

    def test_at_min(self):
        assert validate_range(0, 0, 100) == 0

    def test_at_max(self):
        assert validate_range(100, 0, 100) == 100

    def test_below_raises(self):
        with pytest.raises(ValueError, match="outside valid range"):
            validate_range(-1, 0, 100, "test")

    def test_above_raises(self):
        with pytest.raises(ValueError, match="outside valid range"):
            validate_range(101, 0, 100)


class TestValidateNotEmpty:

    def test_valid(self):
        assert validate_not_empty(b"\x00") == b"\x00"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="No .* provided"):
            validate_not_empty(b"", "firmware")


class TestValidateMaxSize:

    def test_within(self):
        data = b"\x00" * 100
        assert validate_max_size(data, 200) == data

    def test_exceeds(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_max_size(b"\x00" * 200, 100, "file")


class TestSanitizeString:

    def test_strips(self):
        assert sanitize_string("  hello  ") == "hello"

    def test_truncates(self):
        assert len(sanitize_string("a" * 500, 10)) == 10


class TestParseIpPort:

    def test_with_port(self):
        assert parse_ip_port("192.168.1.1:8080") == ("192.168.1.1", 8080)

    def test_without_port(self):
        assert parse_ip_port("192.168.1.1") == ("192.168.1.1", 0)

    def test_default_port(self):
        assert parse_ip_port("192.168.1.1", 443) == ("192.168.1.1", 443)

    def test_invalid_port(self):
        assert parse_ip_port("192.168.1.1:abc", 80) == ("192.168.1.1", 80)
