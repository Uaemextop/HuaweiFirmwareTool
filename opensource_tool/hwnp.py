"""
hwnp.py — Huawei HWNP firmware format parser and builder.

Implements reading, writing, and manipulation of Huawei HWNP firmware
packages used by ONT (Optical Network Terminal) devices.

Based on the huawei_header.h definitions from the HuaweiFirmwareTool project.
"""

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

HWNP_MAGIC = 0x504E5748  # "HWNP" in little-endian

# Offsets for CRC32 calculation (from huawei_header.h)
CRC32_HDR = 0x14
CRC32_ALL = 0x0C
SZ_BIN = 0x4C

HEADER_SIZE = 36  # sizeof(huawei_header)
ITEM_SIZE = 360   # sizeof(huawei_item)


@dataclass
class HwnpItem:
    """Represents a single item in a HWNP firmware package."""
    iter: int = 0
    item_crc32: int = 0
    data_off: int = 0
    data_sz: int = 0
    item: str = ""        # Target path (e.g., "file:/var/run.sh")
    section: str = ""     # Section type (e.g., "UPGRDCHECK", "ROOTFS")
    version: str = ""     # Version string
    policy: int = 0       # 0=normal, 2=auto-execute script
    reserved: int = 0
    data: bytes = field(default=b"", repr=False)

    def pack_header(self) -> bytes:
        """Pack item header to binary (360 bytes)."""
        item_bytes = self.item.encode("ascii", errors="replace")[:256].ljust(256, b"\x00")
        section_bytes = self.section.encode("ascii", errors="replace")[:16].ljust(16, b"\x00")
        version_bytes = self.version.encode("ascii", errors="replace")[:64].ljust(64, b"\x00")

        return struct.pack(
            "<II II 256s 16s 64s II",
            self.iter,
            self.item_crc32,
            self.data_off,
            self.data_sz,
            item_bytes,
            section_bytes,
            version_bytes,
            self.policy,
            self.reserved,
        )

    @classmethod
    def unpack_header(cls, data: bytes, offset: int = 0) -> "HwnpItem":
        """Unpack item header from binary data."""
        fields = struct.unpack_from("<II II 256s 16s 64s II", data, offset)
        return cls(
            iter=fields[0],
            item_crc32=fields[1],
            data_off=fields[2],
            data_sz=fields[3],
            item=fields[4].split(b"\x00")[0].decode("ascii", errors="replace"),
            section=fields[5].split(b"\x00")[0].decode("ascii", errors="replace"),
            version=fields[6].split(b"\x00")[0].decode("ascii", errors="replace"),
            policy=fields[7],
            reserved=fields[8],
        )


@dataclass
class HwnpFirmware:
    """Represents a complete HWNP firmware package."""
    magic: int = HWNP_MAGIC
    raw_sz: int = 0
    raw_crc32: int = 0
    hdr_sz: int = 0
    hdr_crc32: int = 0
    item_counts: int = 0
    unknow_data_1: int = 0
    unknow_data_2: int = 0
    prod_list_sz: int = 0
    item_sz: int = ITEM_SIZE
    reserved: int = 0
    prod_list: str = ""
    items: List[HwnpItem] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str) -> "HwnpFirmware":
        """Read a HWNP firmware from a file."""
        with open(path, "rb") as f:
            data = f.read()
        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "HwnpFirmware":
        """Parse a HWNP firmware from raw bytes."""
        if len(data) < HEADER_SIZE:
            raise ValueError("Data too short for HWNP header")

        fields = struct.unpack_from("<I II II I BB H I I", data, 0)
        fw = cls(
            magic=fields[0],
            raw_sz=fields[1],
            raw_crc32=fields[2],
            hdr_sz=fields[3],
            hdr_crc32=fields[4],
            item_counts=fields[5],
            unknow_data_1=fields[6],
            unknow_data_2=fields[7],
            prod_list_sz=fields[8],
            item_sz=fields[9],
            reserved=fields[10],
        )

        if fw.magic != HWNP_MAGIC:
            raise ValueError(f"Invalid HWNP magic: 0x{fw.magic:08X}")

        # Read product list
        offset = HEADER_SIZE
        if fw.prod_list_sz > 0:
            fw.prod_list = data[offset : offset + fw.prod_list_sz].split(b"\x00")[0].decode(
                "ascii", errors="replace"
            )
            offset += fw.prod_list_sz

        # Read items
        for i in range(fw.item_counts):
            item = HwnpItem.unpack_header(data, offset)
            offset += ITEM_SIZE

            # Read item data
            if item.data_off + item.data_sz <= len(data):
                item.data = data[item.data_off : item.data_off + item.data_sz]

            fw.items.append(item)

        return fw

    def to_bytes(self) -> bytes:
        """Serialize the firmware to bytes, recalculating offsets and CRC32."""
        self.item_counts = len(self.items)
        prod_list_bytes = self.prod_list.encode("ascii", errors="replace")
        self.prod_list_sz = len(prod_list_bytes)
        self.item_sz = ITEM_SIZE

        # Calculate header size and data offsets
        header_total = HEADER_SIZE + self.prod_list_sz + self.item_counts * ITEM_SIZE
        self.hdr_sz = header_total

        offset = header_total
        for item in self.items:
            item.data_off = offset
            item.data_sz = len(item.data)
            offset += item.data_sz

        total_size = offset
        self.raw_sz = total_size

        # Calculate CRC32 for each item
        for item in self.items:
            item.item_crc32 = zlib.crc32(item.data) & 0xFFFFFFFF

        # Pack header
        hdr_bytes = struct.pack(
            "<I II II I BB H I I",
            self.magic,
            self.raw_sz,
            0,  # raw_crc32 placeholder
            self.hdr_sz,
            0,  # hdr_crc32 placeholder
            self.item_counts,
            self.unknow_data_1,
            self.unknow_data_2,
            self.prod_list_sz,
            self.item_sz,
            self.reserved,
        )

        # Pack items headers
        items_hdr_bytes = b""
        for item in self.items:
            items_hdr_bytes += item.pack_header()

        # Calculate header CRC32 (from offset CRC32_HDR)
        hdr_for_crc = hdr_bytes[CRC32_HDR:] + prod_list_bytes + items_hdr_bytes
        hdr_crc32 = zlib.crc32(hdr_for_crc) & 0xFFFFFFFF
        self.hdr_crc32 = hdr_crc32

        # Re-pack header with hdr_crc32
        hdr_bytes = struct.pack(
            "<I II II I BB H I I",
            self.magic,
            self.raw_sz,
            0,  # raw_crc32 placeholder
            self.hdr_sz,
            self.hdr_crc32,
            self.item_counts,
            self.unknow_data_1,
            self.unknow_data_2,
            self.prod_list_sz,
            self.item_sz,
            self.reserved,
        )

        # Calculate full CRC32 (from offset CRC32_ALL)
        all_data = hdr_bytes + prod_list_bytes + items_hdr_bytes
        for item in self.items:
            all_data += item.data
        raw_crc32 = zlib.crc32(all_data[CRC32_ALL:]) & 0xFFFFFFFF
        self.raw_crc32 = raw_crc32

        # Final pack
        hdr_bytes = struct.pack(
            "<I II II I BB H I I",
            self.magic,
            self.raw_sz,
            self.raw_crc32,
            self.hdr_sz,
            self.hdr_crc32,
            self.item_counts,
            self.unknow_data_1,
            self.unknow_data_2,
            self.prod_list_sz,
            self.item_sz,
            self.reserved,
        )

        result = hdr_bytes + prod_list_bytes + items_hdr_bytes
        for item in self.items:
            result += item.data
        return result

    def save(self, path: str) -> None:
        """Save firmware to file."""
        with open(path, "wb") as f:
            f.write(self.to_bytes())

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"HWNP Firmware Package",
            f"  Magic:       0x{self.magic:08X}",
            f"  Items:       {self.item_counts}",
            f"  Board list:  {self.prod_list or '(universal)'}",
            f"  Items:",
        ]
        for i, item in enumerate(self.items):
            policy_str = " [AUTO-EXEC]" if item.policy == 2 else ""
            lines.append(
                f"    [{i}] {item.item} ({item.section}) "
                f"{len(item.data)} bytes{policy_str}"
            )
        return "\n".join(lines)


def create_upgrade_check_xml(
    hard_ver_check: bool = False,
    lsw_chip_check: bool = False,
    wifi_chip_check: bool = False,
    voice_chip_check: bool = False,
    usb_chip_check: bool = False,
    optical_check: bool = False,
    other_chip_check: bool = False,
    product_check: bool = False,
    program_check: bool = False,
    cfg_check: bool = False,
) -> bytes:
    """Generate an UpgradeCheck.xml with configurable validation checks."""
    def check_entry(name: str, enabled: bool) -> str:
        enable_val = "1" if enabled else "0"
        return (
            f'<{name} CheckEnable="{enable_val}">\n'
            f'<IncludeList Enable="1"/>\n'
            f'<ExcludeList Enable="0"/>\n'
            f'</{name}>'
        )

    xml = "<upgradecheck>\n"
    xml += check_entry("HardVerCheck", hard_ver_check) + "\n"
    xml += check_entry("LswChipCheck", lsw_chip_check) + "\n"
    xml += check_entry("WifiChipCheck", wifi_chip_check) + "\n"
    xml += check_entry("VoiceChipCheck", voice_chip_check) + "\n"
    xml += check_entry("UsbChipCheck", usb_chip_check) + "\n"
    xml += check_entry("OpticalCheck", optical_check) + "\n"
    xml += check_entry("OtherChipCheck", other_chip_check) + "\n"
    xml += check_entry("ProductCheck", product_check) + "\n"
    xml += check_entry("ProgramCheck", program_check) + "\n"
    xml += check_entry("CfgCheck", cfg_check) + "\n"
    xml += "</upgradecheck>\n"
    return xml.encode("utf-8")
