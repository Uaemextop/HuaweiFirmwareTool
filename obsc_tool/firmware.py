"""
HWNP firmware file parser and validator.

Parses Huawei HWNP firmware packages, validates CRC32 checksums,
and extracts firmware items for transfer via the OBSC protocol.
"""

import struct
import zlib
import os


# HWNP magic: "HWNP" = 0x504E5748 (little-endian)
HWNP_MAGIC = 0x504E5748

# Header size: sizeof(huawei_header) = 36 bytes
HWNP_HEADER_SIZE = 36

# Item header size: sizeof(huawei_item) = 360 bytes
HWNP_ITEM_SIZE = 360


class HWNPItem:
    """Represents a single firmware item within an HWNP package."""

    __slots__ = ('index', 'crc32', 'data_offset', 'data_size',
                 'item_path', 'section', 'version', 'policy', 'data')

    def __init__(self):
        self.index = 0
        self.crc32 = 0
        self.data_offset = 0
        self.data_size = 0
        self.item_path = ""
        self.section = ""
        self.version = ""
        self.policy = 0
        self.data = b""

    def __repr__(self):
        return (f"HWNPItem(index={self.index}, path='{self.item_path}', "
                f"section='{self.section}', size={self.data_size}, "
                f"policy={self.policy})")


class HWNPFirmware:
    """Parser and validator for HWNP firmware packages."""

    def __init__(self):
        self.magic = 0
        self.raw_size = 0
        self.raw_crc32 = 0
        self.header_size = 0
        self.header_crc32 = 0
        self.item_count = 0
        self.prod_list_size = 0
        self.item_header_size = 0
        self.product_list = ""
        self.items = []
        self.raw_data = b""
        self.file_path = ""

    def load(self, file_path):
        """Load and parse an HWNP firmware file.

        Args:
            file_path: Path to the .bin firmware file.

        Raises:
            ValueError: If the file is not a valid HWNP firmware.
            FileNotFoundError: If the file does not exist.
        """
        self.file_path = file_path

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Firmware file not found: {file_path}")

        with open(file_path, 'rb') as f:
            self.raw_data = f.read()

        if len(self.raw_data) < HWNP_HEADER_SIZE:
            raise ValueError("File too small to be an HWNP firmware")

        self._parse_header()
        self._parse_product_list()
        self._parse_items()

    def _parse_header(self):
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
        fields = struct.unpack_from(fmt, self.raw_data, 0)

        self.magic = fields[0]
        self.raw_size = fields[1]
        self.raw_crc32 = fields[2]
        self.header_size = fields[3]
        self.header_crc32 = fields[4]
        self.item_count = fields[5]
        # fields[6] = _unknow_data_1
        # fields[7] = _unknow_data_2
        self.prod_list_size = fields[8]
        self.item_header_size = fields[9]
        # fields[10] = reserved

        if self.magic != HWNP_MAGIC:
            raise ValueError(
                f"Invalid HWNP magic: 0x{self.magic:08X} "
                f"(expected 0x{HWNP_MAGIC:08X})"
            )

    def _parse_product_list(self):
        """Parse the product compatibility list."""
        offset = HWNP_HEADER_SIZE
        if self.prod_list_size > 0:
            raw = self.raw_data[offset:offset + self.prod_list_size]
            self.product_list = raw.split(b'\x00')[0].decode('ascii', errors='replace')

    def _parse_items(self):
        """Parse all firmware items."""
        self.items = []
        items_offset = HWNP_HEADER_SIZE + self.prod_list_size
        # Use item size from header if available, otherwise default
        item_size = self.item_header_size if self.item_header_size > 0 else HWNP_ITEM_SIZE

        for i in range(self.item_count):
            item_offset = items_offset + i * item_size
            if item_offset + item_size > len(self.raw_data):
                break

            item = HWNPItem()

            fields = struct.unpack_from('<IIII', self.raw_data, item_offset)
            item.index = fields[0]
            item.crc32 = fields[1]
            item.data_offset = fields[2]
            item.data_size = fields[3]

            # Parse strings (null-terminated within fixed-size fields)
            str_offset = item_offset + 16
            item.item_path = self._read_string(str_offset, 256)
            item.section = self._read_string(str_offset + 256, 16)
            item.version = self._read_string(str_offset + 272, 64)

            # Policy and reserved
            policy_offset = item_offset + 16 + 256 + 16 + 64
            item.policy = struct.unpack_from('<I', self.raw_data, policy_offset)[0]

            # Extract item data
            if item.data_offset > 0 and item.data_size > 0:
                end = item.data_offset + item.data_size
                if end <= len(self.raw_data):
                    item.data = self.raw_data[item.data_offset:end]

            self.items.append(item)

    def _read_string(self, offset, max_len):
        """Read a null-terminated string from the firmware data."""
        raw = self.raw_data[offset:offset + max_len]
        null_pos = raw.find(b'\x00')
        if null_pos >= 0:
            raw = raw[:null_pos]
        return raw.decode('ascii', errors='replace')

    def validate_crc32(self):
        """Validate CRC32 checksums of the firmware.

        Returns:
            Tuple of (header_valid, data_valid) booleans.
        """
        # Header CRC32: calculated over the header area
        header_end = HWNP_HEADER_SIZE + self.prod_list_size + \
            self.item_count * HWNP_ITEM_SIZE
        header_data = bytearray(self.raw_data[:header_end])
        # Zero out the CRC fields for recalculation
        struct.pack_into('<I', header_data, 0x0C, 0)  # raw_crc32
        struct.pack_into('<I', header_data, 0x14, 0)  # header_crc32
        calc_hdr_crc = zlib.crc32(bytes(header_data[:header_end])) & 0xFFFFFFFF
        header_valid = (calc_hdr_crc == self.header_crc32)

        # Raw CRC32: calculated over the entire file
        raw_copy = bytearray(self.raw_data)
        struct.pack_into('<I', raw_copy, 0x0C, 0)  # zero raw_crc32
        calc_raw_crc = zlib.crc32(bytes(raw_copy)) & 0xFFFFFFFF
        data_valid = (calc_raw_crc == self.raw_crc32)

        return header_valid, data_valid

    def get_info(self):
        """Get a summary dict of the firmware info."""
        return {
            'file': os.path.basename(self.file_path),
            'size': len(self.raw_data),
            'items': self.item_count,
            'products': self.product_list,
            'items_detail': [
                {
                    'index': item.index,
                    'path': item.item_path,
                    'section': item.section,
                    'version': item.version,
                    'size': item.data_size,
                    'crc32': f"0x{item.crc32:08X}",
                    'policy': item.policy,
                }
                for item in self.items
            ],
        }

    def get_total_data_size(self):
        """Get total size of all firmware item data."""
        return sum(item.data_size for item in self.items)
