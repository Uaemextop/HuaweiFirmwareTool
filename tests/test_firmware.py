"""
Tests for obsc_tool.firmware (HWNPFirmware parser and CRC32 validation).
"""

import os
import struct
import tempfile
import zlib

import pytest

from obsc_tool.firmware import (
    HWNP_HEADER_SIZE,
    HWNP_ITEM_SIZE,
    HWNP_MAGIC,
    HWNPFirmware,
)


# ---------------------------------------------------------------------------
# Helpers for building synthetic HWNP firmware blobs
# ---------------------------------------------------------------------------

def _pack_item_header(index: int, item_crc32: int, data_offset: int,
                      data_size: int, item_path: str = "/update/kernel",
                      section: str = "kernel", version: str = "V100R001",
                      policy: int = 0) -> bytes:
    """Return a 360-byte HWNP item header."""
    hdr = struct.pack('<IIII', index, item_crc32, data_offset, data_size)
    hdr += item_path.encode('ascii', errors='replace')[:255].ljust(256, b'\x00')
    hdr += section.encode('ascii', errors='replace')[:15].ljust(16, b'\x00')
    hdr += version.encode('ascii', errors='replace')[:63].ljust(64, b'\x00')
    hdr += struct.pack('<II', policy, 0)  # policy + reserved
    assert len(hdr) == HWNP_ITEM_SIZE
    return hdr


def _build_firmware(items: list | None = None,
                    product_list: bytes = b'') -> bytes:
    """Build a syntactically valid HWNP firmware binary with correct CRCs.

    Args:
        items: List of ``bytes`` objects, one per firmware item's data payload.
        product_list: Raw product-list bytes (null-terminated string).

    Returns:
        Complete firmware binary with correct ``hdr_crc32`` and ``raw_crc32``.
    """
    if items is None:
        items = []

    prod_list_sz = len(product_list)
    item_count = len(items)
    header_area_size = HWNP_HEADER_SIZE + prod_list_sz + item_count * HWNP_ITEM_SIZE

    # Compute item data offsets and item CRCs
    item_headers = b''
    item_data_blobs = b''
    current_offset = header_area_size
    for idx, data in enumerate(items):
        item_crc32 = zlib.crc32(data) & 0xFFFFFFFF
        item_headers += _pack_item_header(
            index=idx + 1,
            item_crc32=item_crc32,
            data_offset=current_offset,
            data_size=len(data),
        )
        item_data_blobs += data
        current_offset += len(data)

    raw_sz = header_area_size + len(item_data_blobs)

    # Build header with placeholder CRCs
    header = struct.pack(
        '<IIIIIIBBHII',
        HWNP_MAGIC,          # magic
        raw_sz,              # raw_sz
        0,                   # raw_crc32 (placeholder)
        header_area_size,    # hdr_sz
        0,                   # hdr_crc32 (placeholder)
        item_count,          # item_counts
        0,                   # _unknown_data_1
        0,                   # _unknown_data_2
        prod_list_sz,        # prod_list_sz
        HWNP_ITEM_SIZE,      # item_sz
        0,                   # reserved
    )

    # Compute hdr_crc32: header[0x14:] + product_list + item_headers
    header_area = header + product_list + item_headers
    hdr_crc32 = zlib.crc32(header_area[0x14:]) & 0xFFFFFFFF
    header = header[:16] + struct.pack('<I', hdr_crc32) + header[20:]

    # Compute raw_crc32: header[0x0C:] + product_list + item_headers + item_data
    header_area = header + product_list + item_headers
    raw_crc32 = zlib.crc32(header_area[0x0C:] + item_data_blobs) & 0xFFFFFFFF
    header = header[:8] + struct.pack('<I', raw_crc32) + header[12:]

    return header + product_list + item_headers + item_data_blobs


def _write_firmware(data: bytes) -> str:
    """Write firmware bytes to a temporary file and return its path."""
    fd, path = tempfile.mkstemp(suffix='.bin')
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Tests: loading
# ---------------------------------------------------------------------------

class TestHWNPFirmwareLoad:
    def test_load_empty_firmware(self):
        """Minimal valid firmware with no items loads without error."""
        data = _build_firmware()
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            assert fw.magic == HWNP_MAGIC
            assert fw.item_count == 0
            assert fw.items == []
        finally:
            os.unlink(path)

    def test_load_firmware_with_product_list(self):
        product_list = b'HG8145V5\x00'
        data = _build_firmware(product_list=product_list)
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            assert 'HG8145V5' in fw.product_list
        finally:
            os.unlink(path)

    def test_load_firmware_with_one_item(self):
        item_payload = b'KERNEL_DATA_' * 10
        data = _build_firmware(items=[item_payload])
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            assert fw.item_count == 1
            assert len(fw.items) == 1
            assert fw.items[0].data == item_payload
            assert fw.items[0].data_size == len(item_payload)
        finally:
            os.unlink(path)

    def test_load_firmware_with_multiple_items(self):
        payloads = [b'ITEM_A' * 8, b'ITEM_B' * 16, b'ITEM_C' * 4]
        data = _build_firmware(items=payloads)
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            assert fw.item_count == 3
            assert len(fw.items) == 3
            for i, payload in enumerate(payloads):
                assert fw.items[i].data == payload
        finally:
            os.unlink(path)

    def test_load_nonexistent_file_raises(self):
        fw = HWNPFirmware()
        with pytest.raises(FileNotFoundError):
            fw.load('/nonexistent/path/firmware.bin')

    def test_load_invalid_magic_raises(self):
        data = bytearray(_build_firmware())
        data[0:4] = b'BAAD'  # corrupt magic
        path = _write_firmware(bytes(data))
        try:
            fw = HWNPFirmware()
            with pytest.raises(ValueError, match="Invalid HWNP magic"):
                fw.load(path)
        finally:
            os.unlink(path)

    def test_load_too_small_raises(self):
        path = _write_firmware(b'\x00' * 10)
        try:
            fw = HWNPFirmware()
            with pytest.raises(ValueError):
                fw.load(path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: CRC32 validation
# ---------------------------------------------------------------------------

class TestValidateCRC32:
    def test_validate_empty_firmware(self):
        data = _build_firmware()
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            hdr_ok, raw_ok = fw.validate_crc32()
            assert hdr_ok, "Header CRC32 should be valid"
            assert raw_ok, "Raw CRC32 should be valid"
        finally:
            os.unlink(path)

    def test_validate_firmware_with_items(self):
        payloads = [b'DATA_CHUNK_A' * 5, b'DATA_CHUNK_B' * 3]
        data = _build_firmware(items=payloads)
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            hdr_ok, raw_ok = fw.validate_crc32()
            assert hdr_ok, "Header CRC32 should be valid"
            assert raw_ok, "Raw CRC32 should be valid"
        finally:
            os.unlink(path)

    def test_validate_firmware_with_product_list(self):
        data = _build_firmware(
            items=[b'FIRMWARE_CONTENT'],
            product_list=b'HG8145V5\x00',
        )
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            hdr_ok, raw_ok = fw.validate_crc32()
            assert hdr_ok, "Header CRC32 should be valid"
            assert raw_ok, "Raw CRC32 should be valid"
        finally:
            os.unlink(path)

    def test_corrupted_item_data_fails_raw_crc(self):
        """Corrupting item data should fail the raw CRC check."""
        data = bytearray(_build_firmware(items=[b'ORIGINAL_DATA' * 4]))
        # Corrupt the last byte of item data
        data[-1] ^= 0xFF
        path = _write_firmware(bytes(data))
        try:
            fw = HWNPFirmware()
            fw.load(path)
            _hdr_ok, raw_ok = fw.validate_crc32()
            assert not raw_ok, "Corrupted data should fail raw CRC32"
        finally:
            os.unlink(path)

    def test_corrupted_item_header_fails_both_crcs(self):
        """Corrupting an item header byte should fail the header CRC."""
        data = bytearray(_build_firmware(items=[b'SOME_DATA']))
        # Corrupt a byte inside the item header area (after main HWNP header)
        corrupt_pos = HWNP_HEADER_SIZE + 8  # inside item header
        data[corrupt_pos] ^= 0xFF
        path = _write_firmware(bytes(data))
        try:
            fw = HWNPFirmware()
            fw.load(path)
            hdr_ok, _raw_ok = fw.validate_crc32()
            assert not hdr_ok, "Corrupted item header should fail header CRC32"
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: get_info / get_total_data_size
# ---------------------------------------------------------------------------

class TestFirmwareInfo:
    def test_get_info_keys(self):
        data = _build_firmware(items=[b'X' * 100], product_list=b'HG8145V5\x00')
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            info = fw.get_info()
            assert 'file' in info
            assert 'size' in info
            assert 'items' in info
            assert 'products' in info
            assert 'items_detail' in info
            assert info['items'] == 1
        finally:
            os.unlink(path)

    def test_get_total_data_size(self):
        payloads = [b'A' * 50, b'B' * 75]
        data = _build_firmware(items=payloads)
        path = _write_firmware(data)
        try:
            fw = HWNPFirmware()
            fw.load(path)
            assert fw.get_total_data_size() == 125
        finally:
            os.unlink(path)
