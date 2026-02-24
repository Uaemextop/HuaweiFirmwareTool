"""
Unit tests for HWNP firmware parser.

Tests the firmware.py module functionality including:
- HWNP file parsing
- Header validation
- Item extraction
- CRC32 validation
"""

import os
import struct
import tempfile
import pytest
from obsc_tool.firmware import HWNPFirmware, HWNPItem, HWNP_MAGIC, HWNP_HEADER_SIZE


class TestHWNPItem:
    """Test HWNPItem class."""

    def test_init(self):
        """Test HWNPItem initialization."""
        item = HWNPItem()
        assert item.index == 0
        assert item.crc32 == 0
        assert item.data_offset == 0
        assert item.data_size == 0
        assert item.item_path == ""
        assert item.section == ""
        assert item.version == ""
        assert item.policy == 0
        assert item.data == b""

    def test_repr(self):
        """Test HWNPItem string representation."""
        item = HWNPItem()
        item.index = 1
        item.item_path = "test.bin"
        item.section = "kernel"
        item.data_size = 1024
        item.policy = 0

        repr_str = repr(item)
        assert "HWNPItem" in repr_str
        assert "index=1" in repr_str
        assert "path='test.bin'" in repr_str
        assert "section='kernel'" in repr_str
        assert "size=1024" in repr_str


class TestHWNPFirmware:
    """Test HWNPFirmware class."""

    def test_init(self):
        """Test HWNPFirmware initialization."""
        fw = HWNPFirmware()
        assert fw.magic == 0
        assert fw.raw_size == 0
        assert fw.raw_crc32 == 0
        assert fw.header_size == 0
        assert fw.header_crc32 == 0
        assert fw.item_count == 0
        assert fw.prod_list_size == 0
        assert fw.item_header_size == 0
        assert fw.product_list == ""
        assert fw.items == []
        assert fw.raw_data == b""
        assert fw.file_path == ""

    def test_load_nonexistent_file(self):
        """Test loading a non-existent file raises FileNotFoundError."""
        fw = HWNPFirmware()
        with pytest.raises(FileNotFoundError):
            fw.load("/nonexistent/path/firmware.bin")

    def test_load_too_small_file(self):
        """Test loading a file that's too small raises ValueError."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"SMALL")
            temp_path = f.name

        try:
            fw = HWNPFirmware()
            with pytest.raises(ValueError, match="File too small"):
                fw.load(temp_path)
        finally:
            os.unlink(temp_path)

    def test_load_invalid_magic(self):
        """Test loading a file with invalid magic raises ValueError."""
        # Create a file with wrong magic but correct size
        data = struct.pack('<IIIIIIBBHII',
            0xDEADBEEF,  # Wrong magic
            0, 0, 0, 0, 0, 0, 0, 0, 360, 0
        )

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            fw = HWNPFirmware()
            with pytest.raises(ValueError, match="Invalid HWNP magic"):
                fw.load(temp_path)
        finally:
            os.unlink(temp_path)

    def test_parse_minimal_valid_firmware(self):
        """Test parsing a minimal valid HWNP firmware."""
        # Create a minimal valid HWNP file
        header = struct.pack('<IIIIIIBBHII',
            HWNP_MAGIC,      # magic
            100,             # raw_size
            0x12345678,      # raw_crc32
            HWNP_HEADER_SIZE, # hdr_sz
            0x87654321,      # hdr_crc32
            0,               # item_counts (no items)
            0, 0,            # unknown
            0,               # prod_list_sz (no product list)
            360,             # item_sz
            0                # reserved
        )

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(header)
            temp_path = f.name

        try:
            fw = HWNPFirmware()
            fw.load(temp_path)

            assert fw.magic == HWNP_MAGIC
            assert fw.raw_size == 100
            assert fw.raw_crc32 == 0x12345678
            assert fw.header_size == HWNP_HEADER_SIZE
            assert fw.header_crc32 == 0x87654321
            assert fw.item_count == 0
            assert fw.prod_list_size == 0
            assert fw.item_header_size == 360
            assert fw.product_list == ""
            assert len(fw.items) == 0
        finally:
            os.unlink(temp_path)

    def test_parse_firmware_with_product_list(self):
        """Test parsing firmware with product list."""
        product_str = b"HG8310M;HG8240H;HG8245H\x00"
        prod_list_size = len(product_str)

        header = struct.pack('<IIIIIIBBHII',
            HWNP_MAGIC,
            100, 0, HWNP_HEADER_SIZE, 0,
            0,  # No items
            0, 0,
            prod_list_size,
            360, 0
        )

        data = header + product_str

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            fw = HWNPFirmware()
            fw.load(temp_path)

            assert fw.product_list == "HG8310M;HG8240H;HG8245H"
            assert fw.prod_list_size == prod_list_size
        finally:
            os.unlink(temp_path)

    def test_get_info(self):
        """Test get_info returns correct dictionary."""
        header = struct.pack('<IIIIIIBBHII',
            HWNP_MAGIC, 100, 0, HWNP_HEADER_SIZE, 0, 0, 0, 0, 0, 360, 0
        )

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(header)
            temp_path = f.name

        try:
            fw = HWNPFirmware()
            fw.load(temp_path)

            info = fw.get_info()
            assert 'file' in info
            assert 'size' in info
            assert 'items' in info
            assert 'products' in info
            assert 'items_detail' in info

            assert info['size'] == len(header)
            assert info['items'] == 0
            assert isinstance(info['items_detail'], list)
        finally:
            os.unlink(temp_path)

    def test_get_total_data_size_empty(self):
        """Test get_total_data_size with no items."""
        header = struct.pack('<IIIIIIBBHII',
            HWNP_MAGIC, 100, 0, HWNP_HEADER_SIZE, 0, 0, 0, 0, 0, 360, 0
        )

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(header)
            temp_path = f.name

        try:
            fw = HWNPFirmware()
            fw.load(temp_path)

            assert fw.get_total_data_size() == 0
        finally:
            os.unlink(temp_path)


class TestHWNPFirmwareItemParsing:
    """Test firmware item parsing."""

    def create_firmware_with_item(self, item_path="test.bin", section="kernel",
                                   version="1.0.0", data_size=1024):
        """Helper to create a firmware file with one item."""
        # Header with 1 item
        header = struct.pack('<IIIIIIBBHII',
            HWNP_MAGIC,
            100 + 360 + data_size,  # Total size
            0, HWNP_HEADER_SIZE, 0,
            1,  # 1 item
            0, 0, 0, 360, 0
        )

        # Item header (360 bytes)
        data_offset = HWNP_HEADER_SIZE + 360
        item_header = struct.pack('<IIII',
            0,            # index
            0x11223344,   # crc32
            data_offset,  # data_offset
            data_size     # data_size
        )

        # Item strings (256 + 16 + 64 = 336 bytes)
        path_bytes = item_path.encode('ascii') + b'\x00' * (256 - len(item_path))
        section_bytes = section.encode('ascii') + b'\x00' * (16 - len(section))
        version_bytes = version.encode('ascii') + b'\x00' * (64 - len(version))

        # Policy and reserved (8 bytes)
        policy_data = struct.pack('<II', 1, 0)

        item_data = item_header + path_bytes + section_bytes + version_bytes + policy_data

        # Pad to 360 bytes
        item_data += b'\x00' * (360 - len(item_data))

        # Actual data
        actual_data = b'\xAA' * data_size

        full_data = header + item_data + actual_data

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(full_data)
            return f.name

    def test_parse_single_item(self):
        """Test parsing firmware with a single item."""
        temp_path = self.create_firmware_with_item(
            item_path="kernel.bin",
            section="kernel",
            version="2.6.36",
            data_size=2048
        )

        try:
            fw = HWNPFirmware()
            fw.load(temp_path)

            assert fw.item_count == 1
            assert len(fw.items) == 1

            item = fw.items[0]
            assert item.index == 0
            assert item.crc32 == 0x11223344
            assert item.item_path == "kernel.bin"
            assert item.section == "kernel"
            assert item.version == "2.6.36"
            assert item.data_size == 2048
            assert item.policy == 1
            assert len(item.data) == 2048
            assert item.data == b'\xAA' * 2048
        finally:
            os.unlink(temp_path)

    def test_get_total_data_size_with_items(self):
        """Test get_total_data_size with items."""
        temp_path = self.create_firmware_with_item(data_size=5000)

        try:
            fw = HWNPFirmware()
            fw.load(temp_path)

            assert fw.get_total_data_size() == 5000
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
