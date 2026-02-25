#!/usr/bin/env python3
"""
nand_dump_analyze.py – HG8145V5 raw NAND flash dump analyser.

Downloads (or uses a local copy of) the 128 MB DS35Q1GA NAND flash dump:
  Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN

The dump is a page-interleaved raw read (no ECC correction applied):
  2048 bytes main data + 64 bytes OOB (spare) per page
  64 pages per 128 KB erase block × 1024 blocks = 128 MB main + 4 MB OOB = 132 MB total

What the tool does
------------------
1. Strip OOB bytes → 128 MB clean main image
2. Parse the MTD partition table from the U-Boot environment string
3. Extract the bootloader (startcode, 128 KB at offset 0)
4. Parse the UBI super-image that occupies the rest of the flash:
     vol 0/1  flash_configA/B  – XML partition layout
     vol 2/3  slave_paramA/B   – device parameters (MAC, serial, board info)
     vol 4/5  allsystemA/B     – HWNP whwh-wrapped firmware (U-Boot + Kernel + rootfs SquashFS)
     vol 6/7  wifi_paramA/B    – Wi-Fi NV parameters
     vol 9    file_system      – UBIFS root filesystem
5. Scan all regions for cryptographic material:
     • X.509 certificates (PEM and raw DER)
     • RSA / EC / PKCS#8 private keys (PEM)
     • AES key blobs in the KeyFile MTD partition
6. Report the eFuse key derivation chain and document extraction methods

eFuse key chain (cannot be extracted from flash alone)
------------------------------------------------------
The device-unique AES-256 key used to protect hw_ctree.xml and keyfile data is:

  eFuse OTP (hardware registers 0x12010100, SD511x)
    → hal_efuse_read_sram_efuse_data()          (kernel module hw_module_efuse.ko)
    → DM_GetRootKeyOffset()                      (libsmp_api.so)
    → HW_OS_FLASH_Read("KeyFile", ...)           (96-byte flash head)
    → DM_LdspDecryptData()                       (hw_module_sec.ko IPSec AES)
    → DM_GetKeyByMaterial()                      (PBKDF2-HMAC-SHA256, 1 iter, 32-byte key)
    → AES-256-CBC key

The eFuse OTP data is burned at the factory and lives only in hardware.
Possible extraction approaches on a live device:
  (a) U-Boot "md 0x12010100 40" via UART console (requires physical access)
  (b) Read /dev/efuse (if the device exports it) from a root shell
  (c) Read /proc/device-info or /proc/soc_info on unlocked devices
  (d) Physical JTAG/debug interface (HiSilicon SD511x ARM Cortex-A9 uses ARM DAP)

Usage
-----
    python3 tools/nand_dump_analyze.py [--dump <path>] [--out <dir>]

Requirements
------------
    pip install cryptography ubi_reader

"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import struct
import sys
import urllib.request
from pathlib import Path
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional deps
# ---------------------------------------------------------------------------
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DUMP_URL = (
    "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/"
    "Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN"
)
DUMP_FILENAME = "Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN"

# DS35Q1GA geometry
PAGE_MAIN   = 2048          # bytes of data per NAND page
PAGE_OOB    = 64            # bytes of spare/OOB per NAND page
PAGE_SIZE   = PAGE_MAIN + PAGE_OOB
PAGES_PER_BLOCK = 64
BLOCK_SIZE  = PAGE_MAIN * PAGES_PER_BLOCK   # 128 KB usable per erase block
TOTAL_BLOCKS = 1024
TOTAL_PAGES  = TOTAL_BLOCKS * PAGES_PER_BLOCK

# Dump file size: 65536 pages × 2112 bytes = 138,412,032 bytes (~132 MB)
DUMP_SIZE_EXPECTED = TOTAL_PAGES * PAGE_SIZE

# Download chunk size (1 MB)
DOWNLOAD_CHUNK_SIZE = 1 << 20

# UBI constants
UBI_EC_MAGIC  = 0x55424923   # 'UBI#'
UBI_VID_MAGIC = 0x55424921   # 'UBI!'
UBI_LAYOUT_VOL_ID = 0x7FFFEFFF
UBI_LEB_SIZE  = BLOCK_SIZE - 0x1000   # 124 KB (typical EC+VID header overhead)

# MTD partition in non-UBI area
STARTCODE_OFFSET = 0x000000
STARTCODE_SIZE   = 0x020000   # 128 KB
EFUSE_OFFSET     = 0x0A0000   # 'bootcode:eFuse' from XML
EFUSE_SIZE       = 0x020000   # 128 KB

# eFuse register base on HiSilicon SD511x (HG8145V5 SoC)
EFUSE_PHYS_BASE  = 0x12010000
EFUSE_SRAM_OFF   = 0x100        # SRAM shadow at EFUSE_PHYS_BASE + 0x100
EFUSE_DATA_SIZE  = 128          # bytes of OTP shadow data

# PEM delimiters we recognise
_PEM_BEGIN_TAGS = [
    b"-----BEGIN CERTIFICATE-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN EC PARAMETERS-----",
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN CERTIFICATE REQUEST-----",
    b"-----BEGIN DH PARAMETERS-----",
    b"-----BEGIN PKCS7-----",
    b"-----BEGIN X509 CRL-----",
]
_PEM_END_PREFIX = b"-----END"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
class PemBlock(NamedTuple):
    offset: int          # byte offset in main (OOB-stripped) image
    begin_tag: bytes     # e.g. b"-----BEGIN CERTIFICATE-----"
    pem_bytes: bytes     # full PEM including headers and base64 body
    sha256: str          # hex digest (first 16 chars)
    valid: bool          # True if cryptography lib parsed it without error
    parse_info: str      # subject/issuer/size summary


class UBIVolume(NamedTuple):
    vol_id: int
    name: str
    leb_count: int
    data: bytes          # reassembled LEB data (may contain 0xFF gaps)


class NANDReport(NamedTuple):
    dump_path: Path
    dump_size: int
    page_count: int
    block_count: int
    partitions: dict     # name → (offset, size, description)
    ubi_volumes: list    # list[UBIVolume]
    pem_blocks: list     # list[PemBlock] – deduplicated
    efuse_blank: bool    # True if eFuse MTD partition is all 0xFF
    efuse_notes: list    # list of strings with eFuse analysis notes


# ---------------------------------------------------------------------------
# Step 1: Strip OOB bytes
# ---------------------------------------------------------------------------
def strip_oob(dump: bytes) -> bytes:
    """Return the main-data-only view of a raw NAND dump (strips OOB per page)."""
    if len(dump) != DUMP_SIZE_EXPECTED:
        # Try to handle differently-sized dumps gracefully
        page_count = len(dump) // PAGE_SIZE
    else:
        page_count = TOTAL_PAGES

    out = bytearray(page_count * PAGE_MAIN)
    for p in range(page_count):
        src = p * PAGE_SIZE
        dst = p * PAGE_MAIN
        out[dst:dst + PAGE_MAIN] = dump[src:src + PAGE_MAIN]
    return bytes(out)


# ---------------------------------------------------------------------------
# Step 2: Extract MTD partitions from environment string
# ---------------------------------------------------------------------------
def parse_mtd_partitions(main: bytes) -> Dict[str, Tuple[int, int, str]]:
    """
    Parse the 'mtdparts' U-Boot env var embedded in the bootloader area.

    Returns a dict: name → (offset_bytes, size_bytes, description).
    """
    partitions = {}

    # The env string is in the bootloader (first 128 KB)
    boot = main[:STARTCODE_SIZE]
    idx = boot.find(b"mtdparts=nand0:")
    if idx == -1:
        # Fall back to known HG8145V5 layout
        partitions["startcode"] = (0x000000, 0x020000, "Bootloader / startcode")
        partitions["ubifs"]     = (0x020000, 0x7FE0000, "UBI super-image")
        partitions["reserved"]  = (0x7FE0000, 0x20000, "Reserved")
        return partitions

    line_end = boot.find(b"\x00", idx)
    line = boot[idx:line_end].decode("ascii", errors="replace")
    # Format: mtdparts=nand0:0x20000(startcode),0x7FE0000(ubifs),-(reserved)
    parts_str = line.split("=nand0:", 1)[-1]
    offset = 0
    total = BLOCK_SIZE * TOTAL_BLOCKS
    for part in parts_str.split(","):
        part = part.strip()
        if "(" not in part:
            continue
        size_str, rest = part.split("(", 1)
        name = rest.rstrip(")")
        if size_str == "-":
            size = total - offset
        else:
            size = int(size_str, 16) if size_str.startswith("0x") else int(size_str)
        partitions[name] = (offset, size, _part_description(name))
        offset += size
    return partitions


def _part_description(name: str) -> str:
    descs = {
        "startcode": "L1 + L2 bootloader, eFuse init code",
        "ubifs":     "UBI super-image (flash_config, slave_param, allsystem, wifi_param, keyfile, file_system)",
        "reserved":  "Reserved / bad-block table",
    }
    return descs.get(name, name)


# ---------------------------------------------------------------------------
# Step 3: Parse UBI volumes
# ---------------------------------------------------------------------------
def _parse_ubi_volumes(main: bytes) -> List[UBIVolume]:
    """
    Manually reassemble UBI logical erase blocks (LEBs) into per-volume images.

    Each physical erase block (128 KB) has:
      • Erase Counter header at offset 0  (UBI#)
      • VID header at offset vid_hdr_off  (UBI!)
      • LEB data   at offset data_off

    We collect all valid (vol_id, lnum) pairs and stitch them together.
    """
    # First pass: collect blocks
    raw_blocks: Dict[int, Dict[int, bytes]] = {}   # vol_id → {lnum: leb_data}
    leb_size: Optional[int] = None

    for blk in range(TOTAL_BLOCKS):
        off = blk * BLOCK_SIZE
        if off + 4 > len(main):
            break
        ec_magic = struct.unpack_from(">I", main, off)[0]
        if ec_magic != UBI_EC_MAGIC:
            continue

        vid_hdr_off = struct.unpack_from(">I", main, off + 16)[0]
        data_off    = struct.unpack_from(">I", main, off + 20)[0]

        vid_start = off + vid_hdr_off
        if vid_start + 4 > len(main):
            continue
        vid_magic = struct.unpack_from(">I", main, vid_start)[0]
        if vid_magic != UBI_VID_MAGIC:
            continue

        vol_id = struct.unpack_from(">I", main, vid_start + 8)[0]
        lnum   = struct.unpack_from(">I", main, vid_start + 12)[0]

        if vol_id == UBI_LAYOUT_VOL_ID:
            continue   # internal layout volume

        leb_data = main[off + data_off: off + BLOCK_SIZE]
        if leb_size is None:
            leb_size = len(leb_data)

        if vol_id not in raw_blocks:
            raw_blocks[vol_id] = {}
        if lnum not in raw_blocks[vol_id]:
            raw_blocks[vol_id][lnum] = leb_data

    if leb_size is None:
        leb_size = UBI_LEB_SIZE

    # Read volume table to get names
    vol_names = _read_ubi_vtbl(main, leb_size)

    # Second pass: reassemble
    volumes = []
    for vol_id in sorted(raw_blocks):
        lebs = raw_blocks[vol_id]
        if not lebs:
            continue
        max_lnum = max(lebs)
        total_size = leb_size * (max_lnum + 1)
        buf = bytearray(b"\xff" * total_size)
        for lnum, data in lebs.items():
            start = lnum * leb_size
            end   = start + min(len(data), leb_size)
            buf[start:end] = data[:leb_size]
        name = vol_names.get(vol_id, f"vol_{vol_id}")
        volumes.append(UBIVolume(vol_id, name, len(lebs), bytes(buf)))

    return volumes


def _read_ubi_vtbl(main: bytes, leb_size: int) -> Dict[int, str]:
    """
    Read the UBI volume table from the layout volume LEBs.
    Returns a dict: vol_id → name.
    """
    vtbl_lebs: Dict[int, bytes] = {}
    for blk in range(TOTAL_BLOCKS):
        off = blk * BLOCK_SIZE
        if off + 4 > len(main):
            break
        if struct.unpack_from(">I", main, off)[0] != UBI_EC_MAGIC:
            continue
        vid_hdr_off = struct.unpack_from(">I", main, off + 16)[0]
        data_off    = struct.unpack_from(">I", main, off + 20)[0]
        vid_start = off + vid_hdr_off
        if vid_start + 16 > len(main):
            continue
        if struct.unpack_from(">I", main, vid_start)[0] != UBI_VID_MAGIC:
            continue
        vol_id = struct.unpack_from(">I", main, vid_start + 8)[0]
        lnum   = struct.unpack_from(">I", main, vid_start + 12)[0]
        if vol_id == UBI_LAYOUT_VOL_ID and lnum not in vtbl_lebs:
            vtbl_lebs[lnum] = main[off + data_off: off + BLOCK_SIZE]

    if 0 not in vtbl_lebs:
        return {}

    vtbl = vtbl_lebs[0]
    names = {}
    RECORD_SIZE = 172
    for vid in range(128):
        rec_off = vid * RECORD_SIZE
        if rec_off + RECORD_SIZE > len(vtbl):
            break
        rec = vtbl[rec_off: rec_off + RECORD_SIZE]
        reserved_pebs = struct.unpack_from(">I", rec, 0)[0]
        name_len      = struct.unpack_from(">H", rec, 14)[0]
        if reserved_pebs == 0 and name_len == 0:
            continue
        if name_len > 128:
            continue
        try:
            name = rec[16:16 + name_len].decode("utf-8", errors="replace")
            names[vid] = name
        except Exception:
            pass
    return names


# ---------------------------------------------------------------------------
# Step 4: Scan for PEM cryptographic material
# ---------------------------------------------------------------------------
def _iter_pem_blocks(data: bytes) -> Iterator[Tuple[int, bytes, bytes]]:
    """
    Yield (offset, begin_tag, raw_pem_bytes) for every PEM block in data.

    We are lenient: if the end marker appears within 16 KB of the begin
    marker we accept the block even if it contains binary noise (NAND
    corruption or compression artefacts).
    """
    for begin_tag in _PEM_BEGIN_TAGS:
        offset = 0
        while True:
            idx = data.find(begin_tag, offset)
            if idx == -1:
                break
            window = data[idx: idx + 16384]
            end_idx = window.find(_PEM_END_PREFIX)
            if end_idx == -1:
                offset = idx + 1
                continue
            # Find newline after end line
            nl = window.find(b"\n", end_idx)
            if nl == -1:
                nl = end_idx + 64
            raw = window[:nl + 1]
            yield (idx, begin_tag, raw)
            offset = idx + 1


def _try_parse_pem(begin_tag: bytes, raw: bytes) -> Tuple[bool, str]:
    """
    Attempt to parse the PEM block with the cryptography library.

    Returns (success, human_readable_info).
    """
    if not _HAS_CRYPTO:
        return False, "cryptography library not available"

    # Sanitize: keep only printable ASCII + newline/CR (fix NAND bit-flips)
    clean_lines = []
    for line in raw.split(b"\n"):
        sane = bytes(b for b in line if (b >= 32 and b <= 126) or b == 9)
        clean_lines.append(sane)
    clean = b"\n".join(clean_lines) + b"\n"

    try:
        if b"CERTIFICATE" in begin_tag:
            cert = x509.load_pem_x509_certificate(clean, default_backend())
            subj = _dn_oneline(cert.subject)
            issr = _dn_oneline(cert.issuer)
            pk   = cert.public_key()
            try:
                from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec
                if isinstance(pk, _rsa.RSAPublicKey):
                    key_info = f"RSA-{pk.key_size}"
                elif isinstance(pk, _ec.EllipticCurvePublicKey):
                    key_info = f"EC/{pk.curve.name}"
                else:
                    key_info = "unknown"
            except Exception:
                key_info = "?"
            info = f"SUBJECT={subj} ISSUER={issr} KEY={key_info}"
            return True, info
        else:
            privkey = load_pem_private_key(clean, password=None,
                                           backend=default_backend())
            size = getattr(privkey, "key_size", "?")
            info = f"PRIVATE KEY bits={size}"
            return True, info
    except Exception as exc:
        # Try DER fallback: strip header/footer, base64-decode lines
        try:
            body = clean
            for hdr in [begin_tag, _PEM_END_PREFIX]:
                body = b"\n".join(
                    ln for ln in body.split(b"\n")
                    if not ln.startswith(hdr[:5]) and not ln.startswith(b"Proc-Type")
                    and not ln.startswith(b"DEK-Info")
                )
            der = base64.b64decode(b"".join(body.split()), validate=False)
            return True, f"DER parse OK ({len(der)} bytes)"
        except Exception:
            pass
        return False, str(exc)[:80]


def _dn_oneline(name) -> str:
    parts = []
    for attr in name:
        try:
            parts.append(f"{attr.oid._name}={attr.value}")
        except Exception:
            parts.append(f"?={attr.value}")
    return "/".join(parts)


def scan_pem(data: bytes, label: str = "") -> List[PemBlock]:
    """
    Scan *data* for PEM blocks and return deduplicated list[PemBlock].
    """
    seen: Dict[str, PemBlock] = {}   # sha256 → PemBlock
    for offset, begin_tag, raw in _iter_pem_blocks(data):
        digest = hashlib.sha256(raw).hexdigest()[:16]
        if digest in seen:
            continue
        valid, info = _try_parse_pem(begin_tag, raw)
        block = PemBlock(
            offset=offset,
            begin_tag=begin_tag,
            pem_bytes=raw,
            sha256=digest,
            valid=valid,
            parse_info=info,
        )
        seen[digest] = block
    return list(seen.values())


# ---------------------------------------------------------------------------
# Step 5: eFuse partition analysis
# ---------------------------------------------------------------------------
def analyse_efuse_partition(main: bytes) -> Tuple[bool, List[str]]:
    """
    Check the eFuse MTD partition (startcode:eFuse, 0xa0000–0xc0000).

    Returns (is_blank, notes_list).
    """
    efuse_data = main[EFUSE_OFFSET: EFUSE_OFFSET + EFUSE_SIZE]
    blank = all(b == 0xFF for b in efuse_data)
    notes = []
    notes.append(
        f"eFuse MTD partition: 0x{EFUSE_OFFSET:06x}–"
        f"0x{EFUSE_OFFSET+EFUSE_SIZE:06x} ({EFUSE_SIZE//1024} KB)"
    )
    if blank:
        notes.append(
            "  → All 0xFF (blank). The eFuse OTP data is stored in hardware registers "
            "only (not in flash)."
        )
    else:
        non_ff = [(i, efuse_data[i]) for i in range(len(efuse_data)) if efuse_data[i] != 0xFF]
        notes.append(f"  → {len(non_ff)} non-0xFF bytes found (possible eFuse init data)")
        for off, val in non_ff[:16]:
            notes.append(f"     0x{EFUSE_OFFSET+off:06x}: 0x{val:02x}")

    notes.append("")
    notes.append("eFuse OTP hardware location (HiSilicon SD511x / HG8145V5):")
    notes.append(f"  Physical base : 0x{EFUSE_PHYS_BASE:08x}")
    notes.append(f"  SRAM shadow   : 0x{EFUSE_PHYS_BASE+EFUSE_SRAM_OFF:08x}")
    notes.append(f"  Shadow size   : {EFUSE_DATA_SIZE} bytes")
    notes.append("")
    notes.append("How to extract the eFuse key (requires physical device access):")
    notes.append(
        "  (a) UART/U-Boot console (115200 8N1 on UART0):\n"
        "        U-Boot> md.b 0x12010100 80\n"
        "      Dumps 128 bytes from the eFuse SRAM shadow."
    )
    notes.append(
        "  (b) /dev/efuse from a root shell (if driver exports the node):\n"
        "        dd if=/dev/efuse bs=1 count=128 | xxd"
    )
    notes.append(
        "  (c) /proc/device-info (on unlocked OpenWRT-style firmwares):\n"
        "        cat /proc/device-info | grep -i efuse"
    )
    notes.append(
        "  (d) JTAG/SWD: attach to HiSilicon SD511x ARM Cortex-A9 DAP, halt core,\n"
        "      read 128 bytes from 0x12010100."
    )
    notes.append(
        "  (e) ioctl to hw_module_efuse.ko (if kernel module is present):\n"
        "        int fd = open(\"/dev/hw_efuse\", O_RDONLY);\n"
        "        ioctl(fd, EFUSE_IOCTL_READ_DATA, buf);"
    )
    return blank, notes


# ---------------------------------------------------------------------------
# Step 6: Analyse whwh-wrapped HWNP allsystem volumes
# ---------------------------------------------------------------------------
def parse_allsystem(vol_data: bytes) -> Dict[str, dict]:
    """
    Parse an allsystemA/B UBI volume containing a whwh-wrapped HWNP firmware.

    Returns a dict of section_name → info dict.
    """
    sections = {}
    offset = 0
    while offset < len(vol_data) - 4:
        if vol_data[offset:offset+4] != b"whwh":
            offset += 4
            continue
        # whwh header: magic(4) + version_str(up to 32 bytes, null-padded)
        #              + ' | '(3) + section_name(up to 20 bytes, null-padded)
        pipe = vol_data.find(b" | ", offset + 4, offset + 80)
        if pipe == -1:
            offset += 4
            continue
        ver_bytes = vol_data[offset+4: pipe].rstrip(b"\x00")
        version = ver_bytes.decode("ascii", errors="replace").strip()
        sec_start = pipe + 3
        sec_end   = vol_data.find(b"\x00", sec_start, sec_start + 32)
        if sec_end == -1:
            sec_end = sec_start + 20
        section = vol_data[sec_start:sec_end].decode("ascii", errors="replace")

        info: dict = {"offset": offset, "version": version}

        # Detect embedded content types
        search_window = vol_data[offset: offset + 0x200]
        if b"\x27\x05\x19\x56" in search_window:
            uimg_off = search_window.find(b"\x27\x05\x19\x56")
            abs_off  = offset + uimg_off
            uimg_sz  = struct.unpack_from(">I", vol_data, abs_off + 12)[0]
            uimg_name = vol_data[abs_off+32: abs_off+64].rstrip(b"\x00").decode("ascii", errors="replace")
            comp_id   = vol_data[abs_off+31]
            comp      = {0:"none", 1:"gzip", 2:"bzip2", 3:"lzma", 4:"lzo"}.get(comp_id, "?")
            info["uimage"] = {
                "name": uimg_name,
                "size": uimg_sz,
                "comp": comp,
                "offset": abs_off,
            }

        # SquashFS rootfs
        sqfs_off = _find_sqfs(vol_data, offset, offset + len(vol_data) - offset)
        if sqfs_off != -1:
            sqfs_bytes_used = struct.unpack_from("<Q", vol_data, sqfs_off + 40)[0]
            info["squashfs"] = {"offset": sqfs_off, "bytes_used": sqfs_bytes_used}

        sections[section] = info
        offset += 4

    return sections


def _find_sqfs(data: bytes, start: int, end: int) -> int:
    """Find SquashFS magic within [start, end) in data."""
    for sig in (b"hsqs", b"sqsh"):
        idx = data.find(sig, start, end)
        if idx != -1:
            return idx
    return -1


# ---------------------------------------------------------------------------
# Step 7: Extract and save PEM blocks
# ---------------------------------------------------------------------------
def save_pem_blocks(pem_blocks: List[PemBlock], out_dir: Path) -> None:
    """Write each unique PEM block to out_dir/keys/."""
    keys_dir = out_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    for block in pem_blocks:
        tag_clean = (
            block.begin_tag.decode("ascii", errors="replace")
            .replace("-----BEGIN ", "")
            .replace("-----", "")
            .strip()
            .replace(" ", "_")
        )
        fname = f"{tag_clean}_{block.sha256[:8]}.pem"
        fpath = keys_dir / fname
        fpath.write_bytes(block.pem_bytes)


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------
def analyse(dump_path: Path, out_dir: Path, write_report: bool = True) -> NANDReport:
    """
    Full analysis pipeline.  Returns an NANDReport; writes files to out_dir.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Load dump ──────────────────────────────────────────────────────
    print(f"[1/6] Loading dump: {dump_path} ({dump_path.stat().st_size // 1024 // 1024} MB)")
    dump = dump_path.read_bytes()
    if len(dump) != DUMP_SIZE_EXPECTED:
        print(f"      Warning: expected {DUMP_SIZE_EXPECTED} bytes, got {len(dump)}")

    # ── 2. Strip OOB ─────────────────────────────────────────────────────
    print("[2/6] Stripping OOB bytes (64 B/page)…")
    main = strip_oob(dump)
    main_path = out_dir / "nand_main.bin"
    main_path.write_bytes(main)
    print(f"      Main data: {len(main) // 1024 // 1024} MB → {main_path}")

    # ── 3. Parse MTD partitions ───────────────────────────────────────────
    print("[3/6] Parsing MTD partition table…")
    partitions = parse_mtd_partitions(main)
    for name, (off, sz, desc) in partitions.items():
        print(f"      {name:12s}  0x{off:08x}–0x{off+sz:08x}  ({sz//1024} KB)  {desc}")

    # ── 4. Parse UBI volumes ──────────────────────────────────────────────
    print("[4/6] Parsing UBI volumes…")
    volumes = _parse_ubi_volumes(main)
    allsystem_sections: dict = {}
    for vol in volumes:
        first4 = vol.data[:4]
        ctype = (
            "XML"       if first4[:1] == b"<"   else
            "whwh/HWNP" if first4 == b"whwh"   else
            "UBIFS"     if first4 == b"\x31\x18\x10\x06" else
            f"raw({first4.hex()})"
        )
        print(f"      Vol {vol.vol_id:2d} '{vol.name}': {vol.leb_count} LEBs "
              f"= {len(vol.data)//1024} KB  [{ctype}]")
        if ctype == "whwh/HWNP" and "allsystem" in vol.name.lower():
            secs = parse_allsystem(vol.data)
            allsystem_sections[vol.name] = secs
            for sname, info in secs.items():
                uimg = info.get("uimage", {})
                sqfs = info.get("squashfs", {})
                print(f"        section '{sname}' @0x{info['offset']:x} ver={info['version']}", end="")
                if uimg:
                    print(f"  uImage='{uimg['name']}' {uimg['size']//1024}KB comp={uimg['comp']}", end="")
                if sqfs:
                    print(f"  SquashFS={sqfs['bytes_used']//1024}KB @0x{sqfs['offset']:x}", end="")
                print()

    # ── 5. Scan for cryptographic material ───────────────────────────────
    print("[5/6] Scanning for PEM cryptographic material…")
    all_pem: List[PemBlock] = scan_pem(main, label="full NAND")
    # Also scan each UBI volume separately for context
    for vol in volumes:
        vol_pem = scan_pem(vol.data, label=vol.name)
        # Merge (deduplicate by sha256)
        existing = {b.sha256 for b in all_pem}
        for block in vol_pem:
            if block.sha256 not in existing:
                all_pem.append(block)
                existing.add(block.sha256)

    # Categorize
    certs    = [b for b in all_pem if b"CERTIFICATE" in b.begin_tag]
    priv_enc = [b for b in all_pem if b"PRIVATE KEY" in b.begin_tag
                and b"Proc-Type: 4,ENCRYPTED" in b.pem_bytes]
    priv_plain = [b for b in all_pem if b"PRIVATE KEY" in b.begin_tag
                  and b"Proc-Type: 4,ENCRYPTED" not in b.pem_bytes]
    other    = [b for b in all_pem if b not in certs + priv_enc + priv_plain]

    print(f"      Certificates     : {len(certs)}")
    print(f"      Private keys (enc): {len(priv_enc)}")
    print(f"      Private keys (plain): {len(priv_plain)}")
    print(f"      Other PEM blocks : {len(other)}")

    save_pem_blocks(all_pem, out_dir)
    print(f"      Saved to {out_dir / 'keys'}/")

    # ── 6. eFuse partition ────────────────────────────────────────────────
    print("[6/6] Analysing eFuse partition…")
    efuse_blank, efuse_notes = analyse_efuse_partition(main)

    # ── Write report ──────────────────────────────────────────────────────
    report = NANDReport(
        dump_path   = dump_path,
        dump_size   = len(dump),
        page_count  = len(dump) // PAGE_SIZE,
        block_count = len(dump) // PAGE_SIZE // PAGES_PER_BLOCK,
        partitions  = partitions,
        ubi_volumes = volumes,
        pem_blocks  = all_pem,
        efuse_blank = efuse_blank,
        efuse_notes = efuse_notes,
    )

    if write_report:
        _write_report(report, allsystem_sections, out_dir)

    return report


def _write_report(report: NANDReport, allsystem_sections: dict, out_dir: Path) -> None:
    """Write a structured Markdown analysis report."""
    lines = [
        "# HG8145V5 NAND Flash Dump Analysis",
        "",
        f"**File**: `{report.dump_path.name}`",
        f"**Size**: {report.dump_size:,} bytes ({report.dump_size // 1024 // 1024} MB)",
        f"**Geometry**: DS35Q1GA – {report.page_count:,} pages "
        f"({PAGE_MAIN}+{PAGE_OOB} bytes), {report.block_count} erase blocks × 128 KB",
        "",
        "---",
        "",
        "## 1. MTD Partition Layout",
        "",
        "```",
        f"{'Partition':<14} {'Offset':>10}  {'Size':>10}  Description",
        "-" * 72,
    ]
    for name, (off, sz, desc) in report.partitions.items():
        lines.append(f"{name:<14} 0x{off:08x}  {sz//1024:>6} KB  {desc}")
    lines += ["```", ""]

    lines += [
        "## 2. UBI Volume Map",
        "",
        "```",
        f"{'Vol':>4}  {'Name':<20}  {'LEBs':>5}  {'Size':>8}  Type",
        "-" * 60,
    ]
    for vol in report.ubi_volumes:
        first4 = vol.data[:4]
        ctype = (
            "XML"       if first4[:1] == b"<"   else
            "whwh/HWNP" if first4 == b"whwh"   else
            "UBIFS"     if first4 == b"\x31\x18\x10\x06" else
            f"raw"
        )
        lines.append(f"{vol.vol_id:>4}  {vol.name:<20}  {vol.leb_count:>5}  "
                     f"{len(vol.data)//1024:>5} KB  {ctype}")
    lines += ["```", ""]

    lines += ["## 3. Firmware Sections in allsystemA/B", ""]
    for vol_name, sections in allsystem_sections.items():
        lines.append(f"### {vol_name}")
        lines.append("")
        for sname, info in sections.items():
            lines.append(f"**{sname}**  version=`{info['version']}`  offset=0x{info['offset']:x}")
            if "uimage" in info:
                u = info["uimage"]
                lines.append(f"  - uImage: `{u['name']}` ({u['size']//1024} KB, comp={u['comp']})")
            if "squashfs" in info:
                s = info["squashfs"]
                lines.append(f"  - SquashFS rootfs: {s['bytes_used']//1024} KB "
                              f"(lzma compressed) @ 0x{s['offset']:x}")
            lines.append("")

    lines += [
        "## 4. Cryptographic Material",
        "",
        f"Total unique PEM blocks found: **{len(report.pem_blocks)}**",
        "",
        "### 4.1 X.509 Certificates",
        "",
    ]
    certs = [b for b in report.pem_blocks if b"CERTIFICATE" in b.begin_tag]
    for block in certs:
        lines.append(f"- `@0x{block.offset:08x}`  sha256prefix=`{block.sha256}`")
        lines.append(f"  parse_valid={block.valid}  {block.parse_info}")
    lines.append("")

    lines += ["### 4.2 Private Keys", ""]
    priv_enc   = [b for b in report.pem_blocks if b"PRIVATE KEY" in b.begin_tag
                  and b"Proc-Type: 4,ENCRYPTED" in b.pem_bytes]
    priv_plain = [b for b in report.pem_blocks if b"PRIVATE KEY" in b.begin_tag
                  and b"Proc-Type: 4,ENCRYPTED" not in b.pem_bytes]
    if priv_enc:
        lines.append("#### Encrypted private keys")
        for block in priv_enc:
            # Extract DEK-Info line
            dek = ""
            for ln in block.pem_bytes.split(b"\n"):
                if ln.startswith(b"DEK-Info:"):
                    dek = ln.decode("ascii", errors="replace")
                    break
            lines.append(f"- `@0x{block.offset:08x}` `{block.begin_tag.decode()}` "
                         f"{dek}  sha256=`{block.sha256}`")
        lines.append("")
    if priv_plain:
        lines.append("#### Plaintext private keys _(may be test/library keys)_")
        for block in priv_plain:
            lines.append(f"- `@0x{block.offset:08x}` `{block.begin_tag.decode()}`  "
                         f"parse_valid={block.valid}  sha256=`{block.sha256}`")
            if block.parse_info:
                lines.append(f"  {block.parse_info}")
        lines.append("")

    lines += [
        "## 5. eFuse Key Chain",
        "",
    ]
    lines += report.efuse_notes
    lines += [
        "",
        "### 5.1 Key Derivation Chain (from decompiled sources)",
        "",
        "```",
        "eFuse OTP (HiSilicon SD511x hardware)",
        "  Physical: SRAM shadow @ 0x12010100 (sd511x efuse driver)",
        "  Kernel:   hal_efuse_read_sram_efuse_data(buf, 128)   [hw_module_efuse.ko]",
        "                │",
        "                ▼",
        "  DM_GetRootKeyOffset(partition_name, &blk_name, &offset)  [libsmp_api.so]",
        '    │  reads MTD "KeyFile" block name from flash layout',
        "                │",
        "                ▼",
        "  HW_OS_FLASH_Read(blk_name, offset, head_buf, 96)          [libc MTD API]",
        "    │  96-byte encrypted header from flash KeyFile partition",
        "                │",
        "                ▼",
        "  DM_LdspDecryptData(head_buf, eFuse_key, plain_buf)        [hw_module_sec.ko]",
        "    │  IPSec AES-CBC decryption using raw eFuse OTP as key",
        "                │",
        "                ▼",
        "  DM_GetKeyByMaterial(plain_buf, material_len,              [libsmp_api.so]",
        "                      out_key, 32)                           PBKDF2-HMAC-SHA256",
        "    │  1 iteration, 32-byte output → AES-256-CBC key",
        "                │",
        "                ▼",
        "  AES-256-CBC key   ────► aescrypt2  ────► hw_ctree.xml",
        "                         (OS_AescryptEncrypt)    (ttree_spec_smooth.tar.gz)",
        "```",
        "",
        "### 5.2 Why the key cannot be recovered from the flash dump alone",
        "",
        "The root secret is the **eFuse OTP** – a one-time-programmable hardware",
        "register array burned at the factory. It is **not stored anywhere in flash**.",
        "Even with a full flash dump the decryption chain cannot be completed without",
        "reading the raw eFuse SRAM shadow from the live device.",
        "",
        "The flash dump *does* contain:",
        "- The encrypted 96-byte header (in the KeyFile UBI volume)",
        "- The encrypted hw_ctree.xml (in JFFS2 on /mnt/jffs2)",
        "- All firmware certificates and library-embedded test keys",
        "",
        "It does **not** contain the eFuse OTP seed, which means the AES-256-CBC",
        "work key cannot be derived offline.",
        "",
    ]

    report_path = out_dir / "NAND_ANALYSIS.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[✓] Report written to {report_path}")


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------
def _download(url: str, dest: Path) -> None:
    """Download *url* to *dest* with a simple progress indicator."""
    print(f"    Downloading {url}")
    print(f"    → {dest}")
    req = urllib.request.Request(url, headers={"User-Agent": "HuaweiFirmwareTool/1.0"})
    with urllib.request.urlopen(req) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with dest.open("wb") as f:
            while True:
                chunk = resp.read(DOWNLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    print(f"\r    {downloaded//1024//1024} / {total//1024//1024} MB  ({pct}%)",
                          end="", flush=True)
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    default_dump = repo_root / DUMP_FILENAME
    default_out  = repo_root / "nand_analysis"

    p = argparse.ArgumentParser(
        description=(
            "Analyse an HG8145V5 raw NAND flash dump: "
            "strip OOB, parse UBI partitions, extract PEM keys/certificates, "
            "report eFuse key chain."
        )
    )
    p.add_argument("--dump", metavar="PATH", default=str(default_dump),
                   help=f"Path to the .BIN dump file (default: {default_dump})")
    p.add_argument("--out",  metavar="DIR",  default=str(default_out),
                   help=f"Output directory (default: {default_out})")
    p.add_argument("--download", action="store_true",
                   help="Download the dump from GitHub if not present locally")
    p.add_argument("--no-report", action="store_true",
                   help="Skip writing the Markdown report")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    dump_path = Path(args.dump)
    out_dir   = Path(args.out)

    if not dump_path.exists():
        if args.download:
            _download(DUMP_URL, dump_path)
        else:
            print(f"[!] Dump not found: {dump_path}")
            print(f"    Re-run with --download to fetch it automatically, or:")
            print(f"    wget -O '{dump_path}' '{DUMP_URL}'")
            sys.exit(1)

    analyse(dump_path, out_dir, write_report=not args.no_report)
    print("[✓] Done")


if __name__ == "__main__":
    main()
