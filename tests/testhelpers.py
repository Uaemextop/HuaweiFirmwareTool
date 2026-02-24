"""Tests for shared.helpers module."""

import os
import tempfile
import pytest

from hwflash.shared.helpers import (
    safe_int,
    safe_float,
    format_size,
    format_hex,
    clamp,
    ensure_dir,
    truncate,
)


class TestSafeInt:
    """Tests for safe_int conversion."""

    def test_valid_int(self):
        assert safe_int("42") == 42

    def test_valid_float_string(self):
        assert safe_int("3.7") == 0  # not convertible directly

    def test_invalid_string(self):
        assert safe_int("abc") == 0

    def test_none(self):
        assert safe_int(None) == 0

    def test_custom_default(self):
        assert safe_int("bad", 99) == 99

    def test_int_passthrough(self):
        assert safe_int(100) == 100

    def test_negative(self):
        assert safe_int("-5") == -5


class TestSafeFloat:
    """Tests for safe_float conversion."""

    def test_valid_float(self):
        assert safe_float("3.14") == pytest.approx(3.14)

    def test_invalid(self):
        assert safe_float("xyz") == 0.0

    def test_none(self):
        assert safe_float(None, 1.0) == 1.0


class TestFormatSize:
    """Tests for format_size function."""

    def test_bytes(self):
        assert format_size(500) == "500 B"

    def test_kilobytes(self):
        assert "KB" in format_size(2048)

    def test_megabytes(self):
        assert "MB" in format_size(1048576)

    def test_gigabytes(self):
        assert "GB" in format_size(2 * 1024 * 1024 * 1024)

    def test_zero(self):
        assert format_size(0) == "0 B"


class TestFormatHex:
    """Tests for format_hex function."""

    def test_basic(self):
        assert format_hex(255) == "0x000000FF"

    def test_wide(self):
        assert format_hex(0xDEAD, 4) == "0xDEAD"

    def test_zero(self):
        assert format_hex(0) == "0x00000000"


class TestClamp:
    """Tests for clamp function."""

    def test_in_range(self):
        assert clamp(50, 0, 100) == 50

    def test_below_min(self):
        assert clamp(-10, 0, 100) == 0

    def test_above_max(self):
        assert clamp(150, 0, 100) == 100

    def test_at_boundary(self):
        assert clamp(0, 0, 100) == 0
        assert clamp(100, 0, 100) == 100


class TestEnsureDir:
    """Tests for ensure_dir function."""

    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "subdir", "nested")
            result = ensure_dir(new_dir)
            assert os.path.isdir(new_dir)
            assert result == new_dir

    def test_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = ensure_dir(tmpdir)
            assert result == tmpdir


class TestTruncate:
    """Tests for truncate function."""

    def test_short_text(self):
        assert truncate("hello", 10) == "hello"

    def test_long_text(self):
        result = truncate("a" * 100, 20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_custom_suffix(self):
        result = truncate("a" * 100, 10, "…")
        assert result.endswith("…")

    def test_exact_length(self):
        assert truncate("12345", 5) == "12345"
