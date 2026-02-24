"""
HWNP firmware format parser.

Parses Huawei HWNP firmware packages, validates CRC32 checksums,
and extracts firmware items for transfer via the OBSC protocol.
"""

import os
import struct
import zlib
from typing import Tuple

from ..models.firmware import FirmwareItem, FirmwarePackage


# HWNP magic: "HWNP" = 0x504E5748 (little-endian)
HWNP_MAGIC = 0x504E5748

# Header size: sizeof(huawei_header) = 36 bytes
HWNP_HEADER_SIZE = 36

# Item header size: sizeof(huawei_item) = 360 bytes
HWNP_ITEM_SIZE = 360


class HWNPParser:
    """Parser for HWNP firmware format."""

    @staticmethod
    def parse(file_path: str) -> FirmwarePackage:
        """
        Parse an HWNP firmware file.

        Args:
            file_path: Path to the .bin firmware file

        Returns:
            Parsed FirmwarePackage

        Raises:
            ValueError: If the file is not a valid HWNP firmware
            FileNotFoundError: If the file does not exist
        """
        package = FirmwarePackage()
        package.file_path = file_path

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Firmware file not found: {file_path}")

        with open(file_path, 'rb') as f:
            package.raw_data = f.read()

        if len(package.raw_data) < HWNP_HEADER_SIZE:
            raise ValueError("File too small to be an HWNP firmware")

        HWNPParser._parse_header(package)
        HWNPParser._parse_product_list(package)
        HWNPParser._parse_items(package)

        return package

    @staticmethod
    def _parse_header(package: FirmwarePackage) -> None:
        """Parse the HWNP main header (36 bytes)."""
        # struct huawei_header {
        #   uint32_t magic_huawei;     // offset 0
        #   uint32_t raw_sz;           // offset 4
        #   uint32_t raw_crc32;        // offset 8
        #   uint32_t hdr_sz;           // offset 12
        #   uint32_t hdr_crc32;        // offset 16
        #   uint32_t item_counts;      // offset 20
        #   uint8_t  _unknow_data_1;   // offset 24
        #   uint8_t  _unknow_data_2;   // offset 25
        #   uint16_t prod_list_sz;     // offset 26
        #   uint32_t item_sz;          // offset 28
        #   uint32_t reserved;         // offset 32
        # };
        fmt = '<IIIIIIBBHII'
        fields = struct.unpack_from(fmt, package.raw_data, 0)

        package.magic = fields[0]
        package.raw_size = fields[1]
        package.raw_crc32 = fields[2]
        package.header_size = fields[3]
        package.header_crc32 = fields[4]
        package.item_count = fields[5]
        # fields[6] = _unknow_data_1
        # fields[7] = _unknow_data_2
        package.prod_list_size = fields[8]
        package.item_header_size = fields[9]
        # fields[10] = reserved

        if package.magic != HWNP_MAGIC:
            raise ValueError(
                f"Invalid HWNP magic: 0x{package.magic:08X} "
                f"(expected 0x{HWNP_MAGIC:08X})"
            )

    @staticmethod
    def _parse_product_list(package: FirmwarePackage) -> None:
        """Parse the product compatibility list."""
        offset = HWNP_HEADER_SIZE
        if package.prod_list_size > 0:
            raw = package.raw_data[offset:offset + package.prod_list_size]
            package.product_list = raw.split(b'\x00')[0].decode('ascii', errors='replace')

    @staticmethod
    def _parse_items(package: FirmwarePackage) -> None:
        """Parse all firmware items."""
        package.items = []
        items_offset = HWNP_HEADER_SIZE + package.prod_list_size
        # Use item size from header if available, otherwise default
        item_size = package.item_header_size if package.item_header_size > 0 else HWNP_ITEM_SIZE

        for i in range(package.item_count):
            item_offset = items_offset + i * item_size
            if item_offset + item_size > len(package.raw_data):
                break

            item = FirmwareItem()

            fields = struct.unpack_from('<IIII', package.raw_data, item_offset)
            item.index = fields[0]
            item.crc32 = fields[1]
            item.data_offset = fields[2]
            item.data_size = fields[3]

            # Parse strings (null-terminated within fixed-size fields)
            str_offset = item_offset + 16
            item.item_path = HWNPParser._read_string(package.raw_data, str_offset, 256)
            item.section = HWNPParser._read_string(package.raw_data, str_offset + 256, 16)
            item.version = HWNPParser._read_string(package.raw_data, str_offset + 272, 64)

            # Policy and reserved
            policy_offset = item_offset + 16 + 256 + 16 + 64
            item.policy = struct.unpack_from('<I', package.raw_data, policy_offset)[0]

            # Extract item data
            if item.data_offset > 0 and item.data_size > 0:
                end = item.data_offset + item.data_size
                if end <= len(package.raw_data):
                    item.data = package.raw_data[item.data_offset:end]

            package.items.append(item)

    @staticmethod
    def _read_string(data: bytes, offset: int, max_len: int) -> str:
        """Read a null-terminated string from binary data."""
        raw = data[offset:offset + max_len]
        null_pos = raw.find(b'\x00')
        if null_pos >= 0:
            raw = raw[:null_pos]
        return raw.decode('ascii', errors='replace')

    @staticmethod
    def validate_crc32(package: FirmwarePackage) -> Tuple[bool, bool]:
        """
        Validate CRC32 checksums of the firmware.

        Note: The original C++ code uses crc32_combine for a chained
        calculation across header, product list, items, and data.
        This simplified validator zeros CRC fields and recomputes over
        the full data, which may not match the original algorithm.

        Args:
            package: Firmware package to validate

        Returns:
            Tuple of (header_valid, data_valid) booleans
        """
        # Header CRC32: calculated over the header area
        item_size = package.item_header_size if package.item_header_size > 0 else HWNP_ITEM_SIZE
        header_end = HWNP_HEADER_SIZE + package.prod_list_size + \
            package.item_count * item_size
        header_data = bytearray(package.raw_data[:header_end])
        # Zero out the CRC fields for recalculation
        # raw_crc32 is at offset 8, hdr_crc32 is at offset 16
        struct.pack_into('<I', header_data, 0x08, 0)  # raw_crc32
        struct.pack_into('<I', header_data, 0x10, 0)  # hdr_crc32
        calc_hdr_crc = zlib.crc32(bytes(header_data[:header_end])) & 0xFFFFFFFF
        header_valid = (calc_hdr_crc == package.header_crc32)

        # Raw CRC32: calculated over the entire file
        raw_copy = bytearray(package.raw_data)
        struct.pack_into('<I', raw_copy, 0x08, 0)  # zero raw_crc32
        calc_raw_crc = zlib.crc32(bytes(raw_copy)) & 0xFFFFFFFF
        data_valid = (calc_raw_crc == package.raw_crc32)

        return header_valid, data_valid
