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
        # The struct layout is identical to legacy for fields at 0x0C+,
        # but raw_sz (0x04) and raw_crc32 (0x08) are big-endian.
        # 0x00 'HWNP'
        # 0x04 raw_sz (BE u32)
        # 0x08 raw_crc32 (BE u32)
        # 0x0C hdr_sz (LE u32)
        # 0x10 hdr_crc32 (LE u32)
        # 0x14 item_counts (LE u32)
        # 0x18 unkn1 (u8), unkn2 (u8), prod_list_sz (LE u16)
        # 0x1C item_sz (LE u32)
        # 0x20 reserved (LE u32)

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
        # prod_list_sz is u16 at offset 0x1A (same position as legacy struct)
        mixed_prod_sz = struct.unpack_from('<H', self.raw_data, offset + 0x1A)[0]
        # item_sz is u32 at offset 0x1C (same position as legacy struct)
        mixed_item_sz = struct.unpack_from('<I', self.raw_data, offset + 0x1C)[0]
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

        # Some real-world firmwares include padding/extra metadata between the product
        # list and the item headers. If the default offset yields empty headers, scan.
        if self.header_layout == 'mixed':
            detected = self._detect_items_offset(items_offset, item_size)
            if detected is not None:
                items_offset = detected

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

    def _detect_items_offset(self, initial_offset, item_size):
        """Best-effort item table offset detection for mixed-layout files."""
        if self.item_count <= 0:
            return None

        max_scan = self.header_offset + max(self.header_size, HWNP_HEADER_SIZE + self.prod_list_size) + 8192
        max_scan = min(max_scan, len(self.raw_data) - item_size)
        start = self.header_offset + HWNP_HEADER_SIZE
        start = min(start, max_scan)

        def _is_printable_path(buf: bytes) -> bool:
            head = buf.split(b'\x00', 1)[0]
            if len(head) < 5:
                return False
            if b':' not in head[:32]:
                return False
            # allow common characters
            for b in head[:64]:
                if b < 0x20 or b > 0x7E:
                    return False
            return True

        def _candidate_ok(off: int) -> bool:
            try:
                idx, crc, data_off, data_sz = struct.unpack_from(self.endian + 'IIII', self.raw_data, off)
            except struct.error:
                return False

            if idx > max(4096, self.item_count + 32):
                return False
            if data_sz == 0 or data_sz > len(self.raw_data):
                return False
            # path field sanity
            if not _is_printable_path(self.raw_data[off + 16:off + 16 + 128]):
                return False

            # offset should point into file, either absolute or relative to header_offset
            abs1 = data_off
            abs2 = self.header_offset + data_off
            ok_off = False
            for a in (abs1, abs2):
                if 0 <= a <= len(self.raw_data) and a + data_sz <= len(self.raw_data):
                    ok_off = True
                    break
            if not ok_off:
                return False

            return True

        # Quick check: if initial offset already looks good, keep it.
        if 0 <= initial_offset <= max_scan and _candidate_ok(initial_offset):
            return initial_offset

        # Scan for the first offset that looks like a table start and has a few
        # consecutive valid headers.
        probe_n = min(3, self.item_count)
        for off in range(start, max_scan, 4):
            if not _candidate_ok(off):
                continue
            ok = True
            for i in range(1, probe_n):
                if not _candidate_ok(off + i * item_size):
                    ok = False
                    break
            if ok:
                return off

        return None

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

        # For mixed-layout firmwares, some vendors use non-standard checksums in
        # the container fields. In that case, fall back to structural + per-item CRC.
        if self.header_layout == 'mixed' and (not header_valid or not data_valid):
            # Structural sanity
            start, end = self.get_transfer_range()
            size_ok = (self.raw_size > 0 and (end - start) == self.raw_size)
            hdr_ok = (HWNP_HEADER_SIZE <= self.header_size <= self.raw_size)

            # Per-item CRC: require that we can extract at least one item with data,
            # and that all extracted items match their advertised CRC.
            extracted = [it for it in self.items if it.data and it.data_size]
            item_ok = False
            if extracted:
                bad = 0
                for it in extracted:
                    calc = zlib.crc32(it.data) & 0xFFFFFFFF
                    if it.crc32 and calc != it.crc32:
                        bad += 1
                item_ok = (bad == 0)

            if size_ok and hdr_ok and item_ok:
                return True, True

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
            ascii_like = sum((32 <= ord(ch) <= 126) or ch in '\r\n\t' for ch in text)
            ascii_ratio = (ascii_like / len(text)) if text else 0.0
            looks_structured = any(token in text for token in ('\n', '\r', '=', ':', '</', '/>', '{', '}', '[', ']'))

            if is_text_ext or text.lstrip().startswith('<?xml'):
                decoded = text
                used_encoding = enc
                break

            if enc.startswith('utf-16'):
                if ratio >= 0.80 and (ascii_ratio >= 0.25 or looks_structured):
                    decoded = text
                    used_encoding = enc
                    break
            elif ratio >= 0.80 and ascii_ratio >= 0.35:
                decoded = text
                used_encoding = enc
                break

        if decoded is None:
            if b'\x00' in sample:
                return {'is_text': False, 'reason': 'Binary payload (NUL bytes detected)'}
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

    def get_firmware_summary(self) -> dict:
        """Extract a comprehensive metadata summary from the actual firmware.

        Analyses header fields, item table, product list tags, per-item
        version strings, and any UpgradeCheck.xml content to produce the
        most complete picture possible — regardless of whether the
        product list contains KEY=VALUE pairs.
        """
        summary: dict = {}

        # ── Header info ─────────────────────────────────────────
        summary['layout'] = self.header_layout
        summary['raw_size'] = self.raw_size
        summary['header_size'] = self.header_size
        summary['item_count'] = self.item_count
        summary['prod_list_size'] = self.prod_list_size
        summary['item_header_size'] = self.item_header_size
        summary['file_size'] = len(self.raw_data)
        summary['header_offset'] = self.header_offset

        # CRC
        try:
            hdr_ok, data_ok = self.validate_crc32()
        except Exception:
            hdr_ok, data_ok = False, False
        summary['header_crc_valid'] = hdr_ok
        summary['data_crc_valid'] = data_ok
        summary['header_crc'] = f"0x{self.header_crc32:08X}"
        summary['raw_crc'] = f"0x{self.raw_crc32:08X}"

        # ── Product list ────────────────────────────────────────
        raw_pl = self.product_list.strip()
        summary['product_list_raw'] = raw_pl

        # Try KEY=VALUE parsing
        kv: dict[str, str] = {}
        for line in raw_pl.replace('\r\n', '\n').split('\n'):
            line = line.strip()
            if '=' in line:
                k, v = line.split('=', 1)
                kv[k.strip().upper()] = v.strip()
        summary['product_kv'] = kv

        # Parse pipe/semicolon-delimited tags (common format)
        tags: list[str] = []
        if not kv and raw_pl:
            for tag in raw_pl.replace(';', '|').split('|'):
                tag = tag.strip()
                if tag:
                    tags.append(tag)
        summary['product_tags'] = tags

        # ── Version from items ──────────────────────────────────
        versions = list({it.version for it in self.items if it.version})
        summary['versions'] = versions
        summary['firmware_version'] = versions[0] if len(versions) == 1 else (
            ', '.join(sorted(versions)) if versions else ''
        )

        # ── Sections ────────────────────────────────────────────
        sections = list(dict.fromkeys(it.section for it in self.items if it.section))
        summary['sections'] = sections

        # ── UpgradeCheck.xml extraction ─────────────────────────
        board_ids: list[str] = []
        chip_info: dict[str, list[str]] = {}
        for it in self.items:
            if (it.item_path or '').lower().endswith('upgradecheck.xml') and it.data:
                try:
                    xml_text = it.data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                import re
                for m in re.finditer(r'BoardId="(\d+)"', xml_text):
                    bid = m.group(1)
                    if bid and bid not in board_ids:
                        board_ids.append(bid)
                for m in re.finditer(r'<(\w+ChipCheckIns)\s+name="([^"]+)"', xml_text):
                    chip_type = m.group(1)
                    names = [n.strip() for n in m.group(2).split(',') if n.strip()]
                    chip_info[chip_type] = names
        summary['board_ids'] = board_ids
        summary['chip_info'] = chip_info

        return summary

    # ── Firmware editing / repackaging ───────────────────────────

    def replace_item_data(self, index: int, new_data: bytes):
        """Replace the raw data of a firmware item by index.

        Updates the item's data, size, and CRC32 but does NOT
        recompute the global header CRCs — call ``repack()`` for that.
        """
        item = next((it for it in self.items if it.index == index), None)
        if item is None:
            raise ValueError(f"No item with index {index}")
        item.data = new_data
        item.data_size = len(new_data)
        item.crc32 = zlib.crc32(new_data) & 0xFFFFFFFF

    def remove_item(self, index: int):
        """Remove an item from the firmware by index."""
        item = next((it for it in self.items if it.index == index), None)
        if item is None:
            raise ValueError(f"No item with index {index}")
        self.items.remove(item)
        self.item_count = len(self.items)
        # Re-index
        for i, it in enumerate(self.items):
            it.index = i

    def add_item(self, item_path: str, section: str, version: str,
                 data: bytes, policy: int = 0):
        """Add a new item to the firmware.

        Args:
            item_path: Item path string (e.g. ``file:/var/test.xml``).
            section: Section name.
            version: Version string.
            data: Raw item data bytes.
            policy: Policy flags (default 0).
        """
        item = HWNPItem()
        item.index = len(self.items)
        item.item_path = item_path
        item.section = section
        item.version = version
        item.data = data
        item.data_size = len(data)
        item.crc32 = zlib.crc32(data) & 0xFFFFFFFF
        item.policy = policy
        self.items.append(item)
        self.item_count = len(self.items)

    def repack(self) -> bytes:
        """Re-assemble the firmware binary from current items.

        Recomputes all offsets, CRC32 values, and builds a complete
        HWNP firmware binary identical in structure to the C++ packer.

        Returns:
            Complete firmware binary as bytes.
        """
        self.item_count = len(self.items)
        prod_bytes = self.product_list.encode('ascii', errors='replace')
        if len(prod_bytes) < self.prod_list_size:
            prod_bytes = prod_bytes + b'\x00' * (self.prod_list_size - len(prod_bytes))
        else:
            prod_bytes = prod_bytes[:self.prod_list_size]

        item_size = HWNP_ITEM_SIZE

        # Calculate data offsets
        header_area_size = (HWNP_HEADER_SIZE + len(prod_bytes) +
                            self.item_count * item_size)
        current_offset = header_area_size
        for item in self.items:
            item.data_offset = current_offset
            item.data_size = len(item.data)
            item.crc32 = zlib.crc32(item.data) & 0xFFFFFFFF
            current_offset += item.data_size

        raw_size = current_offset

        # Build item headers
        item_headers = bytearray()
        for item in self.items:
            ih = bytearray(item_size)
            struct.pack_into('<IIII', ih, 0,
                             item.index, item.crc32,
                             item.data_offset, item.data_size)
            # path at +16, max 256
            path_b = item.item_path.encode('ascii', errors='replace')[:255]
            ih[16:16 + len(path_b)] = path_b
            # section at +272, max 16
            sec_b = item.section.encode('ascii', errors='replace')[:15]
            ih[272:272 + len(sec_b)] = sec_b
            # version at +288, max 64
            ver_b = item.version.encode('ascii', errors='replace')[:63]
            ih[288:288 + len(ver_b)] = ver_b
            # policy at +352
            struct.pack_into('<I', ih, 352, item.policy)
            item_headers.extend(ih)

        # Build main header (CRC fields zeroed for now)
        header = bytearray(HWNP_HEADER_SIZE)
        struct.pack_into('<I', header, 0, self.magic if self.magic else HWNP_MAGIC)
        struct.pack_into('<I', header, 4, raw_size)          # raw_sz
        # offset 8: raw_crc32 → set later
        struct.pack_into('<I', header, 12, header_area_size)  # hdr_sz
        # offset 16: hdr_crc32 → set later
        struct.pack_into('<I', header, 20, self.item_count)
        struct.pack_into('<BB', header, 24, 0, 0)
        struct.pack_into('<H', header, 26, len(prod_bytes))
        struct.pack_into('<I', header, 28, item_size)
        struct.pack_into('<I', header, 32, 0)  # reserved

        # Assemble full binary
        all_data = b''.join(item.data for item in self.items)
        firmware = bytearray(header + prod_bytes + item_headers + all_data)

        # ── CRC32 calculation (matches C++ CalculateCRC32 logic) ──
        # Header CRC32: from offset 0x14 (20) of header through
        # header + prod_list + item_headers, with both CRC fields zeroed.
        hdr_area = bytearray(firmware[:header_area_size])
        struct.pack_into('<I', hdr_area, 8, 0)   # zero raw_crc32
        struct.pack_into('<I', hdr_area, 16, 0)   # zero hdr_crc32
        hdr_crc = zlib.crc32(bytes(hdr_area)) & 0xFFFFFFFF
        struct.pack_into('<I', firmware, 16, hdr_crc)

        # Raw CRC32: over full file with raw_crc32 zeroed
        raw_copy = bytearray(firmware)
        struct.pack_into('<I', raw_copy, 8, 0)
        raw_crc = zlib.crc32(bytes(raw_copy)) & 0xFFFFFFFF
        struct.pack_into('<I', firmware, 8, raw_crc)

        # Update internal state
        self.raw_data = bytes(firmware)
        self.raw_size = raw_size
        self.header_size = header_area_size
        self.raw_crc32 = raw_crc
        self.header_crc32 = hdr_crc
        self.item_header_size = item_size
        self.prod_list_size = len(prod_bytes)
        self.header_offset = 0
        self.header_layout = 'legacy'
        self.endian = '<'
        self._raw_crc32_alt = None
        self._header_crc32_alt = None

        return bytes(firmware)

    def unpack_to_dir(self, output_dir: str):
        """Unpack all firmware items to a directory.

        Creates ``item_list.txt`` (metadata) and ``sig_item_list.txt``
        (signing manifest) exactly like the C++ ``UnpackToFS``.

        Args:
            output_dir: Destination directory.
        """
        os.makedirs(output_dir, exist_ok=True)
        meta_path = os.path.join(output_dir, "item_list.txt")
        sig_path = os.path.join(output_dir, "sig_item_list.txt")

        with open(meta_path, 'w') as meta, open(sig_path, 'w') as sig:
            meta.write(f"0x{self.magic:08X}\n")
            meta.write(f"{self.prod_list_size} {self.product_list}\n")

            for item in self.items:
                # Extract item path after ':'
                colon_pos = item.item_path.find(':')
                if colon_pos >= 0 and colon_pos + 1 < len(item.item_path):
                    fs_path = item.item_path[colon_pos + 1:]
                else:
                    fs_path = item.item_path

                full_path = os.path.join(output_dir, fs_path.lstrip('/'))
                os.makedirs(os.path.dirname(full_path), exist_ok=True)

                with open(full_path, 'wb') as f:
                    f.write(item.data if item.data else b'')

                ver = item.version if item.version else "NULL"
                meta.write(f"+ {item.index} {item.item_path} "
                           f"{item.section} {ver} {item.policy}\n")
                sig.write(f"+ {item.item_path}\n")

    def pack_from_dir(self, input_dir: str):
        """Rebuild firmware from a previously unpacked directory.

        Reads ``item_list.txt`` and re-assembles the firmware. This is
        the Python equivalent of the C++ packer (``hw_fmw -p``).

        Args:
            input_dir: Directory containing unpacked items and metadata.

        Returns:
            Complete firmware binary bytes.
        """
        meta_path = os.path.join(input_dir, "item_list.txt")
        if not os.path.isfile(meta_path):
            raise FileNotFoundError(f"Metadata file not found: {meta_path}")

        with open(meta_path, 'r') as f:
            lines = f.readlines()

        if len(lines) < 2:
            raise ValueError("Metadata file too short")

        # Line 1: magic
        magic_str = lines[0].strip()
        self.magic = int(magic_str, 16) if magic_str.startswith('0x') else int(magic_str)

        # Line 2: prod_list_size + product_list
        parts = lines[1].strip().split(' ', 1)
        self.prod_list_size = int(parts[0])
        self.product_list = parts[1] if len(parts) > 1 else ""

        self.items = []
        for line in lines[2:]:
            line = line.strip()
            if len(line) <= 2 or not line.startswith('+'):
                continue
            line = line[2:]  # strip "+ "
            tokens = line.split()
            if len(tokens) < 5:
                continue

            idx = int(tokens[0])
            item_path = tokens[1]
            section = tokens[2]
            version = tokens[3]
            policy = int(tokens[4])

            # Resolve filesystem path
            colon_pos = item_path.find(':')
            if colon_pos >= 0 and colon_pos + 1 < len(item_path):
                fs_path = item_path[colon_pos + 1:]
            else:
                fs_path = item_path
            full_path = os.path.join(input_dir, fs_path.lstrip('/'))

            with open(full_path, 'rb') as f:
                data = f.read()

            item = HWNPItem()
            item.index = idx
            item.item_path = item_path
            item.section = section
            item.version = version if version != "NULL" else ""
            item.data = data
            item.data_size = len(data)
            item.crc32 = zlib.crc32(data) & 0xFFFFFFFF
            item.policy = policy
            self.items.append(item)

        self.item_count = len(self.items)
        if self.item_count == 0:
            raise ValueError("No items found in metadata")

        return self.repack()

    # ── Signature verification & signing ─────────────────────────

    def verify_signature(self, sig_path: str, pubkey_path: str) -> dict:
        """Verify firmware RSA signature (adapted from C++ hw_verify).

        The signature file format:
          Line 1: item count
          Lines 2..N+1: ``sha256_hex item_path``
          Remaining bytes: RSA signature (256 bytes)

        Args:
            sig_path: Path to the signature file.
            pubkey_path: Path to the PEM public key file.

        Returns:
            dict with keys 'sha256_results' (list of dicts) and
            'signature_valid' (bool).
        """
        import hashlib

        with open(sig_path, 'rb') as f:
            sig_raw = f.read()

        with open(pubkey_path, 'r') as f:
            pubkey_pem = f.read()

        # Parse signature file: text portion + 256-byte RSA signature
        SIG_SIZE = 256
        if len(sig_raw) <= SIG_SIZE:
            raise ValueError("Signature file too small")

        text_part = sig_raw[:-SIG_SIZE]
        rsa_sig = sig_raw[-SIG_SIZE:]

        lines = text_part.decode('utf-8', errors='replace').splitlines()
        if not lines:
            raise ValueError("Empty signature file")

        item_count = int(lines[0].strip())
        sha256_results = []

        for i in range(1, item_count + 1):
            if i >= len(lines):
                break
            parts = lines[i].strip().split(' ', 1)
            if len(parts) < 2:
                continue
            expected_sha256 = parts[0]
            item_path_sig = parts[1]

            # Find matching item
            actual_sha256 = None
            for item in self.items:
                if not item.data:
                    continue
                # Match by path suffix
                colon_pos = item.item_path.find(':')
                if colon_pos >= 0:
                    fs_path = item.item_path[colon_pos + 1:]
                else:
                    fs_path = item.item_path

                if item_path_sig.endswith(fs_path) or fs_path.endswith(item_path_sig.lstrip('/')):
                    actual_sha256 = hashlib.sha256(item.data).hexdigest()
                    break

            match = (actual_sha256 == expected_sha256) if actual_sha256 else False
            sha256_results.append({
                'path': item_path_sig,
                'expected': expected_sha256,
                'actual': actual_sha256 or 'NOT_FOUND',
                'match': match,
            })

        # Verify RSA signature over text portion
        sig_valid = _rsa_verify(text_part, rsa_sig, pubkey_pem)

        return {
            'sha256_results': sha256_results,
            'signature_valid': sig_valid,
        }

    def sign_firmware(self, privkey_path: str, output_sig_path: str,
                      sig_items: list | None = None):
        """Sign firmware items with RSA private key (adapted from C++ hw_sign).

        Generates a signature file containing SHA256 hashes of each item
        and an RSA signature over the hash manifest.

        Args:
            privkey_path: Path to PEM private key (no password).
            output_sig_path: Where to write the signature file.
            sig_items: Optional list of item indices to sign.
                       If None, signs all items.

        Returns:
            Path to the generated signature file.
        """
        import hashlib

        with open(privkey_path, 'r') as f:
            privkey_pem = f.read()

        items_to_sign = self.items
        if sig_items is not None:
            items_to_sign = [it for it in self.items if it.index in sig_items]

        if not items_to_sign:
            raise ValueError("No items to sign")

        # Build signature data: count + sha256 lines
        sig_lines = [str(len(items_to_sign))]
        for item in items_to_sign:
            if not item.data:
                raise ValueError(f"Item {item.index} ({item.item_path}) has no data")

            colon_pos = item.item_path.find(':')
            if colon_pos >= 0 and colon_pos + 1 < len(item.item_path):
                path_on_fmw = item.item_path[colon_pos + 1:]
            else:
                path_on_fmw = item.item_path

            sha256_hex = hashlib.sha256(item.data).hexdigest()
            sig_lines.append(f"{sha256_hex} {path_on_fmw}")

        text_data = '\n'.join(sig_lines) + '\n'
        text_bytes = text_data.encode('utf-8')

        # RSA sign
        rsa_signature = _rsa_sign(text_bytes, privkey_pem)

        with open(output_sig_path, 'wb') as f:
            f.write(text_bytes)
            f.write(rsa_signature)

        return output_sig_path


def _rsa_verify(data: bytes, signature: bytes, pubkey_pem: str) -> bool:
    """Verify RSA-SHA256 signature using the cryptography library."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        import hashlib

        pubkey = serialization.load_pem_public_key(pubkey_pem.encode('utf-8'))
        digest = hashlib.sha256(data).digest()

        try:
            pubkey.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
            return True
        except Exception:
            return False
    except ImportError:
        # Fallback: try with rsa library
        try:
            import rsa as _rsa
            import hashlib

            pubkey = _rsa.PublicKey.load_pkcs1_openssl_pem(pubkey_pem.encode('utf-8'))
            digest = hashlib.sha256(data).digest()
            try:
                _rsa.verify({'sha256': digest}, signature, pubkey)
                return True
            except _rsa.VerificationError:
                return False
        except ImportError:
            raise ImportError(
                "RSA verification requires 'cryptography' or 'rsa' package. "
                "Install with: pip install cryptography"
            )


def _rsa_sign(data: bytes, privkey_pem: str) -> bytes:
    """Sign data with RSA-SHA256 using the cryptography library."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        import hashlib

        privkey = serialization.load_pem_private_key(
            privkey_pem.encode('utf-8'), password=None
        )
        digest = hashlib.sha256(data).digest()

        signature = privkey.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
        return signature
    except ImportError:
        try:
            import rsa as _rsa
            import hashlib

            privkey = _rsa.PrivateKey.load_pkcs1(privkey_pem.encode('utf-8'))
            signature = _rsa.sign_hash(
                hashlib.sha256(data).digest(), privkey, 'SHA-256'
            )
            return signature
        except ImportError:
            raise ImportError(
                "RSA signing requires 'cryptography' or 'rsa' package. "
                "Install with: pip install cryptography"
            )
