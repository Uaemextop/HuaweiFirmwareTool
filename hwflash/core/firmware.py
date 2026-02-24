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
        self.header_offset = 0
        self.endian = '<'
        self.header_layout = 'legacy'
        self._raw_crc32_alt = None
        self._header_crc32_alt = None
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

        self.header_offset = self._find_header_offset()
        self._parse_header(self.header_offset)
        self._parse_product_list()
        self._parse_items()

    def _find_header_offset(self):
        """Find the HWNP header offset inside the file.

        Some vendor firmwares prepend wrapper metadata before the HWNP block,
        so the magic is not always located at offset 0.
        """
        signature = struct.pack('<I', HWNP_MAGIC)
        offset = self.raw_data.find(signature)
        if offset < 0:
            raise ValueError(
                f"Invalid HWNP magic: not found "
                f"(expected 0x{HWNP_MAGIC:08X})"
            )
        return offset

    def _parse_header(self, offset=0):
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
        if self.raw_data[offset:offset + 4] != b'HWNP':
            raise ValueError(
                f"Invalid HWNP magic at offset {offset}: expected bytes 'HWNP'"
            )

        file_rem = len(self.raw_data) - offset

        # Layout 1 (legacy, used by our tests / older tools): little-endian struct
        # < magic,u32 raw_sz,u32 raw_crc32,u32 hdr_sz,u32 hdr_crc32,u32 item_counts,u8,u8,u16 prod_list_sz,u32 item_sz,u32 reserved
        legacy_fmt = '<IIIIIIBBHII'

        # Layout 2 (seen in real BINs): mixed-endian
        # 0x00 'HWNP'
        # 0x04 raw_sz (BE u32)
        # 0x08 raw_crc32 (BE u32)
        # 0x0C hdr_sz (LE u32)
        # 0x10 hdr_crc32 (LE u32)
        # 0x14 item_counts (LE u32)
        # 0x18 unknown/reserved (LE u32)
        # 0x1C prod_list_sz (LE u32)
        # 0x20 item_sz/reserved (LE u32; sometimes 0/1)

        def _score_common(raw_sz: int, hdr_sz: int, item_counts: int, prod_sz: int, item_sz: int) -> int:
            score = 0
            if HWNP_HEADER_SIZE <= raw_sz <= file_rem:
                score += 5
                if abs(raw_sz - file_rem) < 256:
                    score += 2
                elif abs(raw_sz - file_rem) < 4096:
                    score += 1
            if HWNP_HEADER_SIZE <= hdr_sz <= raw_sz:
                score += 3
            if 0 <= item_counts <= 4096:
                score += 2
                if item_counts > 0:
                    score += 1
            if 0 <= prod_sz <= 65535:
                score += 1
            if 128 <= item_sz <= 2048:
                score += 2
                if item_sz == HWNP_ITEM_SIZE:
                    score += 1

            if item_sz <= 0:
                item_sz = HWNP_ITEM_SIZE
            computed = HWNP_HEADER_SIZE + prod_sz + item_counts * item_sz
            if computed <= raw_sz and (hdr_sz == 0 or computed <= hdr_sz or abs(computed - hdr_sz) < 4096):
                score += 2
            return score

        legacy = struct.unpack_from(legacy_fmt, self.raw_data, offset)
        legacy_raw_sz = int(legacy[1])
        legacy_hdr_sz = int(legacy[3])
        legacy_item_counts = int(legacy[5])
        legacy_prod_sz = int(legacy[8])
        legacy_item_sz = int(legacy[9]) if int(legacy[9]) > 0 else HWNP_ITEM_SIZE
        score_legacy = _score_common(legacy_raw_sz, legacy_hdr_sz, legacy_item_counts, legacy_prod_sz, legacy_item_sz)

        mixed_raw_sz = struct.unpack_from('>I', self.raw_data, offset + 0x04)[0]
        mixed_raw_crc_be = struct.unpack_from('>I', self.raw_data, offset + 0x08)[0]
        mixed_raw_crc_le = struct.unpack_from('<I', self.raw_data, offset + 0x08)[0]
        mixed_hdr_sz = struct.unpack_from('<I', self.raw_data, offset + 0x0C)[0]
        mixed_hdr_crc_le = struct.unpack_from('<I', self.raw_data, offset + 0x10)[0]
        mixed_hdr_crc_be = struct.unpack_from('>I', self.raw_data, offset + 0x10)[0]
        mixed_item_counts = struct.unpack_from('<I', self.raw_data, offset + 0x14)[0]
        mixed_prod_sz = struct.unpack_from('<I', self.raw_data, offset + 0x1C)[0]
        mixed_item_sz = struct.unpack_from('<I', self.raw_data, offset + 0x20)[0]
        if mixed_item_sz < 128:
            mixed_item_sz = HWNP_ITEM_SIZE
        score_mixed = _score_common(int(mixed_raw_sz), int(mixed_hdr_sz), int(mixed_item_counts), int(mixed_prod_sz), int(mixed_item_sz))

        if score_mixed > score_legacy:
            self.header_layout = 'mixed'
            self.endian = '<'  # item table fields appear little-endian in this layout
            self.magic = HWNP_MAGIC
            self.raw_size = int(mixed_raw_sz)
            self.raw_crc32 = int(mixed_raw_crc_be)
            self._raw_crc32_alt = int(mixed_raw_crc_le)
            self.header_size = int(mixed_hdr_sz)
            self.header_crc32 = int(mixed_hdr_crc_le)
            self._header_crc32_alt = int(mixed_hdr_crc_be)
            self.item_count = int(mixed_item_counts)
            self.prod_list_size = int(mixed_prod_sz)
            self.item_header_size = int(mixed_item_sz)
        else:
            self.header_layout = 'legacy'
            self.endian = '<'
            self.magic = legacy[0]
            self.raw_size = int(legacy[1])
            self.raw_crc32 = int(legacy[2])
            self._raw_crc32_alt = None
            self.header_size = int(legacy[3])
            self.header_crc32 = int(legacy[4])
            self._header_crc32_alt = None
            self.item_count = int(legacy[5])
            self.prod_list_size = int(legacy[8])
            self.item_header_size = int(legacy[9])

    def _resolve_offset(self, value):
        """Resolve a potentially relative offset to an absolute file offset."""
        if value < 0:
            return None
        if value < len(self.raw_data):
            return value
        shifted = self.header_offset + value
        if shifted < len(self.raw_data):
            return shifted
        return None

    def _parse_product_list(self):
        """Parse the product compatibility list."""
        offset = self.header_offset + HWNP_HEADER_SIZE
        if self.prod_list_size > 0:
            raw = self.raw_data[offset:offset + self.prod_list_size]
            self.product_list = raw.split(b'\x00')[0].decode('ascii', errors='replace')

    def _parse_items(self):
        """Parse all firmware items."""
        self.items = []
        items_offset = self.header_offset + HWNP_HEADER_SIZE + self.prod_list_size
        # Use item size from header if available, otherwise default
        item_size = self.item_header_size if self.item_header_size > 0 else HWNP_ITEM_SIZE

        for i in range(self.item_count):
            item_offset = items_offset + i * item_size
            if item_offset + item_size > len(self.raw_data):
                break

            item = HWNPItem()

            fields = struct.unpack_from(self.endian + 'IIII', self.raw_data, item_offset)
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
            item.policy = struct.unpack_from(self.endian + 'I', self.raw_data, policy_offset)[0]

            # Extract item data
            if item.data_offset > 0 and item.data_size > 0:
                candidates = []
                abs_direct = item.data_offset
                abs_shifted = self.header_offset + item.data_offset

                if abs_direct + item.data_size <= len(self.raw_data):
                    candidates.append(abs_direct)
                if abs_shifted + item.data_size <= len(self.raw_data) and abs_shifted != abs_direct:
                    candidates.append(abs_shifted)

                for abs_data_offset in candidates:
                    chunk = self.raw_data[abs_data_offset:abs_data_offset + item.data_size]
                    calc_crc = zlib.crc32(chunk) & 0xFFFFFFFF
                    if calc_crc == item.crc32:
                        item.data = chunk
                        break

                if not item.data and candidates:
                    abs_data_offset = candidates[0]
                    item.data = self.raw_data[abs_data_offset:abs_data_offset + item.data_size]

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

        Note: The original C++ code uses crc32_combine for a chained
        calculation across header, product list, items, and data.
        This simplified validator zeros CRC fields and recomputes over
        the full data, which may not match the original algorithm.

        Returns:
            Tuple of (header_valid, data_valid) booleans.
        """
        # Header CRC32: calculated over the header area
        item_size = self.item_header_size if self.item_header_size > 0 else HWNP_ITEM_SIZE
        header_start = self.header_offset
        computed_len = HWNP_HEADER_SIZE + self.prod_list_size + self.item_count * item_size
        hdr_len = computed_len
        if self.header_size and self.header_size > 0:
            # In HWNP, hdr_sz is typically a *length* from the HWNP header start.
            # Some firmwares may set it larger/smaller than the computed item table length.
            candidate_len = int(self.header_size)
            if HWNP_HEADER_SIZE <= candidate_len <= (len(self.raw_data) - header_start):
                hdr_len = max(candidate_len, computed_len)

        header_end = header_start + hdr_len
        if header_end > len(self.raw_data):
            header_end = min(len(self.raw_data), header_start + computed_len)

        hdr_copy = bytearray(self.raw_data)
        struct.pack_into('<I', hdr_copy, self.header_offset + 0x08, 0)
        struct.pack_into('<I', hdr_copy, self.header_offset + 0x10, 0)
        calc_hdr_crc = zlib.crc32(bytes(hdr_copy[header_start:header_end])) & 0xFFFFFFFF
        header_valid = (calc_hdr_crc == self.header_crc32)
        if not header_valid and self._header_crc32_alt is not None:
            header_valid = (calc_hdr_crc == self._header_crc32_alt)

        # Raw CRC32: calculated over the HWNP transfer region.
        raw_copy = bytearray(self.raw_data)
        struct.pack_into('<I', raw_copy, self.header_offset + 0x08, 0)  # zero raw_crc32
        t_start, t_end = self.get_transfer_range()
        calc_raw_crc = zlib.crc32(bytes(raw_copy[t_start:t_end])) & 0xFFFFFFFF
        data_valid = (calc_raw_crc == self.raw_crc32)
        if not data_valid and self._raw_crc32_alt is not None:
            data_valid = (calc_raw_crc == self._raw_crc32_alt)

        return header_valid, data_valid

    def get_transfer_range(self):
        """Return (start, end) slice for bytes to transfer/validate.

        Prefer the HWNP header's raw_size when it is sane; otherwise use
        the remainder of the file from the detected header offset.
        """
        start = self.header_offset
        if start < 0:
            start = 0

        if self.raw_size and self.raw_size > 0:
            end = start + self.raw_size
            if start <= end <= len(self.raw_data):
                return start, end

        return start, len(self.raw_data)

    def get_transfer_data(self):
        """Get the exact bytes that should be sent to the device."""
        start, end = self.get_transfer_range()
        return self.raw_data[start:end]

    def get_transfer_crc32(self):
        """Compute firmware CRC32 in the same style as validate_crc32().

        This matches the common convention where the raw_crc32 field is
        zeroed before calculating the CRC.
        """
        if not self.raw_data:
            return 0

        start, end = self.get_transfer_range()
        raw_copy = bytearray(self.raw_data)
        # raw_crc32 is at offset 8 from the HWNP header start
        if self.header_offset + 0x0C <= len(raw_copy):
            struct.pack_into('<I', raw_copy, self.header_offset + 0x08, 0)
        return zlib.crc32(bytes(raw_copy[start:end])) & 0xFFFFFFFF

    def get_item_text_preview(self, item, max_bytes=262144, max_chars=8192):
        """Return a textual preview for shell/text/xml-like firmware items."""
        if not item or not item.data:
            return {'is_text': False, 'reason': 'Item has no data'}

        path = (item.item_path or '').lower()
        is_text_ext = path.endswith('.sh') or path.endswith('.txt') or path.endswith('.xml')
        sample = item.data[:max_bytes]

        if b'\x00' in sample and not is_text_ext:
            return {'is_text': False, 'reason': 'Binary payload (NUL bytes detected)'}

        encodings = ('utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'latin-1')
        decoded = None
        used_encoding = None

        for enc in encodings:
            try:
                text = sample.decode(enc)
            except UnicodeDecodeError:
                continue

            printable = sum(ch.isprintable() or ch in '\r\n\t' for ch in text)
            ratio = (printable / len(text)) if text else 0.0
            if is_text_ext or ratio >= 0.80 or text.lstrip().startswith('<?xml'):
                decoded = text
                used_encoding = enc
                break

        if decoded is None:
            return {'is_text': False, 'reason': 'Unable to decode as text'}

        truncated = len(decoded) > max_chars
        if truncated:
            decoded = decoded[:max_chars]

        return {
            'is_text': True,
            'encoding': used_encoding,
            'truncated': truncated,
            'text': decoded,
        }

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
