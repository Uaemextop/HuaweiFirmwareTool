"""Tests for the firmware module (HWNP parser)."""

import struct
import zlib
import os
import tempfile
import pytest

from hwflash.core.firmware import (
    HWNPFirmware,
    HWNPItem,
    HWNP_MAGIC,
    HWNP_HEADER_SIZE,
    HWNP_ITEM_SIZE,
)


def _build_hwnp_firmware(items=None, product_list=b"COMMON"):
    """Build a minimal valid HWNP firmware binary for testing.

    Args:
        items: List of (path, section, version, data) tuples.
        product_list: Product list bytes.

    Returns:
        Raw firmware bytes.
    """
    if items is None:
        items = [("file:/var/test.xml", "TEST", "V1.0", b"testdata1234")]

    prod_list = product_list + b'\x00' * (256 - len(product_list))
    prod_list_size = len(prod_list)

    # Calculate header area
    item_headers = bytearray()
    item_data_parts = []
    data_offset_start = HWNP_HEADER_SIZE + prod_list_size + len(items) * HWNP_ITEM_SIZE

    current_data_offset = data_offset_start
    for idx, (path, section, version, data) in enumerate(items):
        item_hdr = bytearray(HWNP_ITEM_SIZE)
        # index(4) + crc32(4) + data_offset(4) + data_size(4) = 16 bytes
        item_crc = zlib.crc32(data) & 0xFFFFFFFF
        struct.pack_into('<IIII', item_hdr, 0, idx, item_crc, current_data_offset, len(data))
        # path at offset 16, max 256 bytes
        path_bytes = path.encode('ascii')[:255]
        item_hdr[16:16 + len(path_bytes)] = path_bytes
        # section at offset 16+256=272, max 16 bytes
        sec_bytes = section.encode('ascii')[:15]
        item_hdr[272:272 + len(sec_bytes)] = sec_bytes
        # version at offset 16+256+16=288, max 64 bytes
        ver_bytes = version.encode('ascii')[:63]
        item_hdr[288:288 + len(ver_bytes)] = ver_bytes
        # policy at offset 16+256+16+64=352
        struct.pack_into('<I', item_hdr, 352, 0)

        item_headers.extend(item_hdr)
        item_data_parts.append(data)
        current_data_offset += len(data)

    # Build full binary (without CRCs first)
    all_data = b''.join(item_data_parts)
    raw_size = HWNP_HEADER_SIZE + prod_list_size + len(item_headers) + len(all_data)

    header = bytearray(HWNP_HEADER_SIZE)
    struct.pack_into('<I', header, 0, HWNP_MAGIC)
    struct.pack_into('<I', header, 4, raw_size)
    # raw_crc32 at offset 8 — set later
    struct.pack_into('<I', header, 12, HWNP_HEADER_SIZE + prod_list_size + len(item_headers))
    # hdr_crc32 at offset 16 — set later
    struct.pack_into('<I', header, 20, len(items))
    struct.pack_into('<H', header, 26, prod_list_size)
    struct.pack_into('<I', header, 28, HWNP_ITEM_SIZE)

    firmware = bytearray(header + prod_list + item_headers + all_data)

    # Compute header CRC32 (over header + prod_list + item_headers, with CRC fields zeroed)
    hdr_area = bytearray(firmware[:HWNP_HEADER_SIZE + prod_list_size + len(item_headers)])
    struct.pack_into('<I', hdr_area, 8, 0)
    struct.pack_into('<I', hdr_area, 16, 0)
    hdr_crc = zlib.crc32(bytes(hdr_area)) & 0xFFFFFFFF
    struct.pack_into('<I', firmware, 16, hdr_crc)

    # Compute raw CRC32 (over full file, with raw_crc32 zeroed)
    raw_copy = bytearray(firmware)
    struct.pack_into('<I', raw_copy, 8, 0)
    raw_crc = zlib.crc32(bytes(raw_copy)) & 0xFFFFFFFF
    struct.pack_into('<I', firmware, 8, raw_crc)

    return bytes(firmware)


class TestHWNPFirmwareParser:
    """Test HWNP firmware parsing."""

    def test_load_valid_firmware(self):
        data = _build_hwnp_firmware()
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(data)
            f.flush()
            fw = HWNPFirmware()
            fw.load(f.name)
        os.unlink(f.name)

        assert fw.magic == HWNP_MAGIC
        assert fw.item_count == 1
        assert len(fw.items) == 1
        assert fw.items[0].item_path == "file:/var/test.xml"
        assert fw.items[0].section == "TEST"
        assert fw.items[0].version == "V1.0"

    def test_load_nonexistent_raises(self):
        fw = HWNPFirmware()
        with pytest.raises(FileNotFoundError):
            fw.load("/nonexistent/file.bin")

    def test_load_too_small_raises(self):
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b'\x00' * 10)
            f.flush()
        with pytest.raises(ValueError, match="too small"):
            fw = HWNPFirmware()
            fw.load(f.name)
        os.unlink(f.name)

    def test_load_bad_magic_raises(self):
        data = _build_hwnp_firmware()
        bad_data = b'\x00\x00\x00\x00' + data[4:]
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(bad_data)
            f.flush()
        with pytest.raises(ValueError, match="Invalid HWNP magic"):
            fw = HWNPFirmware()
            fw.load(f.name)
        os.unlink(f.name)

    def test_multiple_items(self):
        items = [
            ("file:/var/a.xml", "A", "V1", b"aaaa"),
            ("flash:kernel", "KERN", "V2", b"kernel_data_here"),
            ("file:/var/b.bin", "B", "V3", b"bbbbbbbbbbbbbbbb"),
        ]
        data = _build_hwnp_firmware(items=items)
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(data)
            f.flush()
            fw = HWNPFirmware()
            fw.load(f.name)
        os.unlink(f.name)

        assert fw.item_count == 3
        assert fw.items[0].item_path == "file:/var/a.xml"
        assert fw.items[1].item_path == "flash:kernel"
        assert fw.items[2].item_path == "file:/var/b.bin"

    def test_validate_crc32(self):
        data = _build_hwnp_firmware()
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(data)
            f.flush()
            fw = HWNPFirmware()
            fw.load(f.name)
        os.unlink(f.name)

        hdr_valid, raw_valid = fw.validate_crc32()
        assert hdr_valid is True
        assert raw_valid is True

    def test_get_info(self):
        data = _build_hwnp_firmware()
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(data)
            f.flush()
            fw = HWNPFirmware()
            fw.load(f.name)
        os.unlink(f.name)

        info = fw.get_info()
        assert info['items'] == 1
        assert 'COMMON' in info['products']
        assert len(info['items_detail']) == 1

    def test_get_total_data_size(self):
        items = [
            ("file:a", "A", "V1", b"1234"),
            ("file:b", "B", "V2", b"123456"),
        ]
        data = _build_hwnp_firmware(items=items)
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(data)
            f.flush()
            fw = HWNPFirmware()
            fw.load(f.name)
        os.unlink(f.name)

        assert fw.get_total_data_size() == 10  # 4 + 6


class TestHWNPItem:
    """Test HWNPItem structure."""

    def test_default_values(self):
        item = HWNPItem()
        assert item.index == 0
        assert item.crc32 == 0
        assert item.data == b""
        assert item.item_path == ""

    def test_repr(self):
        item = HWNPItem()
        item.index = 1
        item.item_path = "test/path"
        r = repr(item)
        assert "HWNPItem" in r
        assert "test/path" in r
