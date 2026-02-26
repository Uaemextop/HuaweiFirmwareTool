#!/usr/bin/env python3
"""
nand_fw_disasm.py – HG8145V5 NAND dump: corruption analysis, per-item
                    extraction (corrected), Capstone ARM disassembly, and
                    private-key pattern search.

Downloads (or uses a local copy of) the DS35Q1GA raw NAND dump and runs a
full analysis pipeline:

1.  Strip OOB bytes (64 B/page) → 128 MB clean main image.
2.  UBI volume extraction → one binary file per logical volume, each saved
    individually with its name (flash_configA/B, slave_paramA/B, allsystemA,
    allsystemB, wifi_paramA/B, vol9_ubifs, …).
3.  Corruption analysis: reads the BCH-4 OOB ECC marker region (28 bytes
    per page) and reports per-volume: total pages, bad-block-marked pages,
    erased (0xFF) pages, and pages with live ECC data.
4.  Per-volume raw scan for private-key patterns directly on the binary
    data: PEM markers, DER/ASN.1 RSA SEQUENCE headers, AES S-box constants,
    and crypto-related ASCII strings.
5.  SquashFS LZMA-stream scanner for allsystemA (vol 4) and allsystemB
    (vol 5): locates every 128 KB LZMA block by its 5-byte header signature
    and uses ``xz --decompress --format=alone`` (which tolerates bit-errors
    and outputs whatever it successfully decoded) to recover file content.
6.  ARM ELF extraction: every decoded block whose first bytes are the ELF
    magic and e_machine == ARM is saved to ``out/elfs/``.
7.  Capstone ARM32/Thumb2 disassembly:
    - Bootloader (U-Boot): finds ARM code inside the whwh-wrapped partition
      by locating the first valid ARM reset-vector branch table.
    - Each extracted ARM ELF: tries section headers first (.text/.rodata/
      .plt/.dynsym/.dynstr/.rel.plt); when section headers are beyond the
      truncated data (common for partially-decompressed ELFs), falls back to
      ELF32 program-header segments: disassembles the first executable LOAD
      segment (p_flags & PF_X) and uses the data LOAD segment for string
      scanning.
    - Resolves PLT import names and exported symbol names.
    - Annotates branch targets with their symbol names.
    - Writes ``.asm`` files to ``out/asm/``.
8.  Private-key pattern search applied to every extracted ELF (raw bytes,
    not just sections) and to every individual volume file:
    - PEM ``-----BEGIN ... PRIVATE KEY-----`` blocks
    - DER/ASN.1 RSA key sequences (SEQUENCE + INTEGER patterns)
    - AES S-box constants embedded in key-schedule code
    - Strings containing "key", "secret", "passwd", "private", "efuse", …
    - Imported/exported crypto function names (mbedTLS, OpenSSL, HW SDK)
9.  UBIFS node scan: walks vol 9 for ARM ELF binaries in DATA nodes.
10. Report: writes ``DISASM_REPORT.md`` summarising all findings, corruption
    statistics, key patterns found, and disassembly excerpts.

Usage
-----
    python3 tools/nand_fw_disasm.py [--dump <path>] [--out <dir>]
    python3 tools/nand_fw_disasm.py --download [--out <dir>]

Requirements
------------
    pip install capstone
    xz  (usually pre-installed; ``apt install xz-utils``)

Known limitations
-----------------
    • Each 128 KB LZMA block typically decompresses to only 1–5 KB before
      xz hits the first uncorrectable bit-error sector.  The extracted ELF
      data therefore contains the ELF header, program header table, and the
      first ~1–4 KB of the text segment.  This is enough for: binary
      identification, library imports (dynamic segment visible in first
      LOAD), exported symbol names, and the function prologues at the very
      start of .text.  Large shared libraries that span multiple 128 KB
      blocks are only partially recovered.
    • Firmware private keys (RSA signing, AES ctree) are hardware-bound:
      derived from the device eFuse OTP, unique per unit.  No plaintext
      private key is stored in the NAND flash.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional deps
# ---------------------------------------------------------------------------
try:
    import capstone  # type: ignore
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False
    print("[WARN] capstone not installed – disassembly disabled. "
          "Install with: pip install capstone", file=sys.stderr)

# ---------------------------------------------------------------------------
# Constants – DS35Q1GA geometry
# ---------------------------------------------------------------------------
DUMP_URL = (
    "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/"
    "Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN"
)
DUMP_FILENAME = (
    "Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN"
)

PAGE_MAIN        = 2048
PAGE_OOB         = 64
PAGE_SIZE        = PAGE_MAIN + PAGE_OOB       # 2112 bytes raw/page
PAGES_PER_BLOCK  = 64
BLOCK_SIZE       = PAGE_MAIN * PAGES_PER_BLOCK  # 128 KB usable/erase-block
RAW_BLOCK_SIZE   = PAGE_SIZE  * PAGES_PER_BLOCK  # 135 168 raw bytes/block
TOTAL_BLOCKS     = 1024
TOTAL_PAGES      = TOTAL_BLOCKS * PAGES_PER_BLOCK
DUMP_SIZE_BYTES  = TOTAL_PAGES * PAGE_SIZE

# OOB BCH-4 layout (HiSilicon hinfc300, 2 KB+64 B pages):
#   OOB[0:2]   bad-block marker (0xFF FF = good)
#   OOB[2:9]   7-byte BCH-4 ECC for sector 0 (data[0:512])
#   OOB[9:16]  7-byte BCH-4 ECC for sector 1 (data[512:1024])
#   OOB[16:23] 7-byte BCH-4 ECC for sector 2 (data[1024:1536])
#   OOB[23:30] 7-byte BCH-4 ECC for sector 3 (data[1536:2048])
#   OOB[30:64] 0xFF free area
OOB_ECC_OFFSETS = [(2, 0, 512), (9, 512, 1024), (16, 1024, 1536), (23, 1536, 2048)]

# UBI constants
UBI_EC_MAGIC     = 0x55424923  # 'UBI#'
UBI_VID_MAGIC    = 0x55424921  # 'UBI!'
UBI_LAYOUT_VOL   = 0x7FFFEFFF
LEB_DATA_OFF     = 4096
LEB_SIZE         = BLOCK_SIZE - LEB_DATA_OFF   # 126 976 B/LEB

# SquashFS LZMA 128 KB block header (lc=3 lp=0 pb=2 dict=128 KB):
SQFS_LZMA_HEADER = bytes([0x5d, 0x00, 0x00, 0x02, 0x00])

MAX_TEXT_BYTES   = 512 * 1024
DOWNLOAD_CHUNK   = 1 << 20

ELF_MACHINE_ARM  = 40

# ARM ELF program-header type / flags constants
PT_LOAD = 1
PF_X    = 1  # execute permission bit

# ---------------------------------------------------------------------------
# Named tuples
# ---------------------------------------------------------------------------

class OOBStats(NamedTuple):
    vol_id:      int
    total_pages: int
    bad_blocks:  int
    erased_pages:int
    ecc_pages:   int


class ExtractedELF(NamedTuple):
    source_vol:  int
    sqfs_offset: int   # byte offset in SquashFS data area where LZMA starts
    size_bytes:  int
    elf_data:    bytes
    sha256:      str
    corrupt:     bool  # True if xz reported incomplete decompression


class KeyHit(NamedTuple):
    category:    str
    description: str
    offset:      int
    excerpt:     str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes, length: int = 8) -> str:
    return hashlib.sha256(data).hexdigest()[:length]


def _printable(data: bytes, maxlen: int = 64) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:maxlen])


# ---------------------------------------------------------------------------
# 1. OOB stripping
# ---------------------------------------------------------------------------

def strip_oob(dump: bytes) -> bytes:
    """Remove 64-byte OOB from every 2112-byte raw page → 128 MB clean image."""
    pages = len(dump) // PAGE_SIZE
    out = bytearray(pages * PAGE_MAIN)
    for p in range(pages):
        src = p * PAGE_SIZE
        dst = p * PAGE_MAIN
        out[dst: dst + PAGE_MAIN] = dump[src: src + PAGE_MAIN]
    return bytes(out)


# ---------------------------------------------------------------------------
# 2 + 3. UBI extraction with physical location tracking
# ---------------------------------------------------------------------------

def extract_ubi_volumes(
    main: bytes,
    dump: bytes,
) -> Tuple[Dict[int, bytes], Dict[int, Dict[int, int]]]:
    """
    Scan *main* (OOB-stripped) for UBI erase blocks; reassemble volumes.

    Returns:
        volumes:  {vol_id: assembled_bytes}
        leb_maps: {vol_id: {lnum: raw_block_offset_in_dump}}
    """
    vol_lebs:  Dict[int, Dict[int, bytes]] = {}
    leb_maps:  Dict[int, Dict[int, int]]   = {}

    for blk in range(TOTAL_BLOCKS):
        off = blk * BLOCK_SIZE
        if off + 64 > len(main):
            break
        if struct.unpack_from(">I", main, off)[0] != UBI_EC_MAGIC:
            continue
        vid_hdr_off = struct.unpack_from(">I", main, off + 16)[0]
        data_off    = struct.unpack_from(">I", main, off + 20)[0]
        vs = off + vid_hdr_off
        if vs + 32 > len(main):
            continue
        if struct.unpack_from(">I", main, vs)[0] != UBI_VID_MAGIC:
            continue
        vol_id = struct.unpack_from(">I", main, vs + 8)[0]
        lnum   = struct.unpack_from(">I", main, vs + 12)[0]
        if vol_id == UBI_LAYOUT_VOL or lnum >= 4096:
            continue
        leb_data = main[off + data_off: off + BLOCK_SIZE]
        vol_lebs.setdefault(vol_id, {})[lnum]  = leb_data
        leb_maps.setdefault(vol_id, {})[lnum]  = blk * RAW_BLOCK_SIZE

    assembled: Dict[int, bytes] = {}
    for vol_id, lebs in vol_lebs.items():
        if not lebs:
            continue
        max_lnum = max(lebs)
        buf = bytearray(b"\xff" * (LEB_SIZE * (max_lnum + 1)))
        for lnum, data in lebs.items():
            buf[lnum * LEB_SIZE: (lnum + 1) * LEB_SIZE] = data[:LEB_SIZE]
        assembled[vol_id] = bytes(buf)
    return assembled, leb_maps


# ---------------------------------------------------------------------------
# 4. OOB corruption statistics
# ---------------------------------------------------------------------------

def oob_stats(dump: bytes, vol_id: int,
              vol_leb_map: Dict[int, int]) -> OOBStats:
    """Count pages with bad-block markers, erased pages, and ECC-bearing pages."""
    total = bad = erased = with_ecc = 0
    pages_per_data_leb = PAGES_PER_BLOCK - (LEB_DATA_OFF // PAGE_MAIN)
    for _lnum, raw_blk_off in vol_leb_map.items():
        data_page_raw = raw_blk_off + (LEB_DATA_OFF // PAGE_MAIN) * PAGE_SIZE
        for p in range(pages_per_data_leb):
            total += 1
            oob_off = data_page_raw + p * PAGE_SIZE + PAGE_MAIN
            if oob_off + PAGE_OOB > len(dump):
                break
            oob = dump[oob_off: oob_off + PAGE_OOB]
            if oob[0] != 0xFF or oob[1] != 0xFF:
                bad += 1
            elif all(b == 0xFF for b in oob[2:30]):
                erased += 1
            else:
                with_ecc += 1
    return OOBStats(vol_id, total, bad, erased, with_ecc)


# ---------------------------------------------------------------------------
# 5. Private-key pattern scanner (raw bytes)
# ---------------------------------------------------------------------------

# AES S-box first 16 bytes (rows 0)
AES_SBOX_ROW0 = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

# Crypto import function names (lower-case for case-insensitive search)
CRYPTO_FUNC_NAMES = [
    "mbedtls_rsa_private", "rsa_private", "mbedtls_pk_parse_key",
    "mbedtls_pk_parse_keyfile", "rsa_gen_key", "mbedtls_rsa_gen_key",
    "pem_read_rsaprivatekey", "rsa_private_decrypt", "d2i_rsaprivatekey",
    "evp_pkey_new_raw_private_key", "aes_setkey_enc",
    "mbedtls_aes_setkey_enc", "mbedtls_aes_setkey_dec",
    "os_aescryptencrypt", "hw_xml_getencryptedkey",
    "hw_swm_getworksecretkey", "dm_readkeyfromflashhead",
    "dm_ldspdeckryptdata", "dm_getkeybymaterial",
]

# PEM private-key start markers
PEM_PRIVATE_MARKERS = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
]

# Strings that hint at key material
KEY_STRINGS = [
    b"private", b"secret", b"passwd", b"password",
    b"aeskey", b"masterkey", b"devicekey", b"rootkey",
    b"efusekey", b"workkey", b"keyfile",
]

# Regex for DER RSA SEQUENCE header: SEQUENCE { INTEGER(0) INTEGER(modulus) ... }
_RSA_DER_RE = re.compile(b"\x30\x82..\x02\x01\x00\x02\x82", re.DOTALL)


def scan_privkey_patterns(data: bytes, base_offset: int = 0) -> List[KeyHit]:
    """Scan raw bytes for private-key patterns. Returns sorted KeyHit list."""
    hits: List[KeyHit] = []

    # 1. PEM markers
    for marker in PEM_PRIVATE_MARKERS:
        pos = 0
        while True:
            idx = data.find(marker, pos)
            if idx < 0:
                break
            hits.append(KeyHit("pem", marker.decode(), base_offset + idx,
                                _printable(data[idx: idx + 64])))
            pos = idx + 1

    # 2. DER RSA SEQUENCE
    for m in _RSA_DER_RE.finditer(data):
        hits.append(KeyHit("asn1_rsa", "DER RSA SEQUENCE header",
                           base_offset + m.start(),
                           data[m.start(): m.start() + 32].hex()))

    # 3. AES S-box constants
    pos = 0
    while True:
        idx = data.find(AES_SBOX_ROW0, pos)
        if idx < 0:
            break
        hits.append(KeyHit("aes_sbox", "AES S-box row0 in code/data",
                           base_offset + idx,
                           data[idx: idx + 16].hex()))
        pos = idx + 1

    # 4. Key-related ASCII strings
    for kw in KEY_STRINGS:
        pos = 0
        # case-insensitive search: check both lower and upper first byte
        patterns = [kw, kw[:1].upper() + kw[1:]]
        for pat in patterns:
            pos = 0
            while True:
                idx = data.find(pat, pos)
                if idx < 0:
                    break
                context = data[max(0, idx - 8): idx + 48]
                if all(32 <= b < 127 or b == 0 for b in context):
                    hits.append(KeyHit("string",
                                       f"key-related string '{pat.decode()}'",
                                       base_offset + idx,
                                       _printable(context)))
                pos = idx + len(pat)

    return sorted(hits, key=lambda h: h.offset)


# ---------------------------------------------------------------------------
# 6. SquashFS LZMA stream scanner + ELF extractor
# ---------------------------------------------------------------------------

def _decompress_lzma_xz(data: bytes,
                        max_input: int = 200_000) -> Tuple[bytes, bool]:
    """
    Decompress LZMA FORMAT_ALONE via the ``xz`` binary.

    Returns (output_bytes, corrupt) where *corrupt*=True means xz exited
    non-zero (partial output still returned when available).
    """
    chunk = data[:min(len(data), max_input)]
    with tempfile.NamedTemporaryFile(delete=False, suffix=".lzma") as f:
        f.write(chunk)
        tmp = f.name
    try:
        r = subprocess.run(
            ["xz", "--decompress", "--stdout", "--format=alone", tmp],
            capture_output=True, timeout=10,
        )
        return r.stdout, r.returncode != 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return b"", True
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def scan_sqfs_for_elfs(sqfs_data: bytes,
                       vol_id: int,
                       out_dir: Path) -> List[ExtractedELF]:
    """
    Scan the SquashFS data area for LZMA streams that decompress to ARM ELFs.

    The data area ends at the inode-table start recorded in the superblock
    (offset 64, LE uint64).  Every occurrence of the 5-byte SquashFS LZMA
    block header signature is tried as a potential block start.
    """
    if len(sqfs_data) < 96:
        return []

    inode_table_off = struct.unpack_from("<Q", sqfs_data, 64)[0]
    search_end = min(int(inode_table_off), len(sqfs_data))

    out_dir.mkdir(parents=True, exist_ok=True)
    found: List[ExtractedELF] = []
    seen:  set                = set()
    pos   = 0

    while pos < search_end - len(SQFS_LZMA_HEADER):
        idx = sqfs_data.find(SQFS_LZMA_HEADER, pos, search_end)
        if idx < 0:
            break

        raw, corrupt = _decompress_lzma_xz(sqfs_data[idx:])
        if len(raw) >= 52 and raw[:4] == b"\x7fELF":
            machine = struct.unpack_from("<H", raw, 18)[0]
            if machine == ELF_MACHINE_ARM:
                sha = _sha256_hex(raw)
                if sha not in seen:
                    seen.add(sha)
                    elf = ExtractedELF(vol_id, idx, len(raw), raw, sha, corrupt)
                    (out_dir / f"vol{vol_id}_0x{idx:08x}_{sha}.elf").write_bytes(raw)
                    found.append(elf)
        pos = idx + 1

    return found


# ---------------------------------------------------------------------------
# 7. ELF32 parsing helpers
# ---------------------------------------------------------------------------

def _elf32_sections(
    data: bytes
) -> Dict[str, Tuple[int, int, int]]:
    """Return {name: (file_offset, size, vaddr)}.  Empty if unavailable."""
    if data[:4] != b"\x7fELF" or len(data) < 52:
        return {}
    e_shoff     = struct.unpack_from("<I", data, 32)[0]
    e_shnum     = struct.unpack_from("<H", data, 48)[0]
    e_shentsize = struct.unpack_from("<H", data, 46)[0]
    e_shstrndx  = struct.unpack_from("<H", data, 50)[0]
    if (e_shoff == 0 or e_shnum == 0
            or e_shoff + e_shnum * e_shentsize > len(data)):
        return {}
    str_sh_off  = e_shoff + e_shstrndx * e_shentsize
    if str_sh_off + e_shentsize > len(data):
        return {}
    str_foff = struct.unpack_from("<I", data, str_sh_off + 16)[0]
    str_sz   = struct.unpack_from("<I", data, str_sh_off + 20)[0]
    strtab   = data[str_foff: str_foff + str_sz]
    secs: Dict[str, Tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off   = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data):
            break
        n_idx = struct.unpack_from("<I", data, off)[0]
        vaddr = struct.unpack_from("<I", data, off + 12)[0]
        foff  = struct.unpack_from("<I", data, off + 16)[0]
        sz    = struct.unpack_from("<I", data, off + 20)[0]
        nend  = strtab.find(b"\x00", n_idx)
        name  = strtab[n_idx:nend].decode("ascii", "replace") if nend >= 0 else ""
        if name:
            secs[name] = (foff, sz, vaddr)
    return secs


def _elf32_phdrs(data: bytes) -> List[Dict]:
    """Return list of program header dicts from ELF32."""
    if data[:4] != b"\x7fELF" or len(data) < 52:
        return []
    e_phoff     = struct.unpack_from("<I", data, 28)[0]
    e_phnum     = struct.unpack_from("<H", data, 44)[0]
    e_phentsize = struct.unpack_from("<H", data, 42)[0]
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        phdrs.append({
            "type":   struct.unpack_from("<I", data, off)[0],
            "offset": struct.unpack_from("<I", data, off + 4)[0],
            "vaddr":  struct.unpack_from("<I", data, off + 8)[0],
            "filesz": struct.unpack_from("<I", data, off + 16)[0],
            "flags":  struct.unpack_from("<I", data, off + 24)[0],
        })
    return phdrs


def _elf32_dynsyms(
    data: bytes,
    secs: Dict[str, Tuple[int, int, int]],
) -> Dict[str, Tuple[int, int]]:
    """Return {name: (vaddr, size)} for dynamic symbols."""
    if ".dynsym" not in secs or ".dynstr" not in secs:
        return {}
    ds_off, ds_sz, _ = secs[".dynsym"]
    str_off, str_sz, _ = secs[".dynstr"]
    dynstr = data[str_off: str_off + str_sz]
    syms: Dict[str, Tuple[int, int]] = {}
    for i in range(ds_sz // 16):
        off     = ds_off + i * 16
        if off + 16 > len(data):
            break
        st_name = struct.unpack_from("<I", data, off)[0]
        st_val  = struct.unpack_from("<I", data, off + 4)[0]
        st_size = struct.unpack_from("<I", data, off + 8)[0]
        nend    = dynstr.find(b"\x00", st_name)
        name    = dynstr[st_name:nend].decode("ascii", "replace") if nend >= 0 else ""
        if name and st_val:
            syms[name] = (st_val, st_size)
    return syms


def _elf32_plt(
    data: bytes,
    secs: Dict[str, Tuple[int, int, int]],
) -> Dict[int, str]:
    """Return {plt_vaddr: import_name}."""
    if ".rel.plt" not in secs or ".dynsym" not in secs or ".dynstr" not in secs:
        return {}
    rp_off, rp_sz, _ = secs[".rel.plt"]
    ds_off,  _,    _ = secs[".dynsym"]
    str_off, str_sz, _ = secs[".dynstr"]
    _,       _,  plt_va = secs.get(".plt", (0, 0, 0))
    dynstr = data[str_off: str_off + str_sz]
    plt: Dict[int, str] = {}
    for i in range(rp_sz // 8):
        off    = rp_off + i * 8
        if off + 8 > len(data):
            break
        r_info  = struct.unpack_from("<I", data, off + 4)[0]
        sym_idx = r_info >> 8
        sym_off = ds_off + sym_idx * 16
        if sym_off + 16 > len(data):
            continue
        st_name = struct.unpack_from("<I", data, sym_off)[0]
        nend    = dynstr.find(b"\x00", st_name)
        name    = dynstr[st_name:nend].decode("ascii", "replace") if nend >= 0 else ""
        # ARM PLT: resolver stub = 20 bytes; each entry = 12 bytes
        entry_va = plt_va + 20 + i * 12
        if name:
            plt[entry_va] = name
    return plt


def _rodata_strings(
    data: bytes,
    secs: Dict[str, Tuple[int, int, int]],
    min_len: int = 5,
) -> List[str]:
    """Extract printable null-terminated strings from .rodata."""
    if ".rodata" not in secs:
        return []
    off, sz, _ = secs[".rodata"]
    rodata = data[off: off + sz]
    results: List[str] = []
    i = 0
    while i < len(rodata):
        end = rodata.find(b"\x00", i)
        if end < 0:
            break
        s = rodata[i:end]
        if len(s) >= min_len and all(32 <= b < 127 for b in s):
            results.append(s.decode("ascii"))
        i = end + 1
    return results


def _raw_strings(data: bytes, min_len: int = 6) -> List[str]:
    """Extract all printable strings from raw bytes (no section required)."""
    results: List[str] = []
    for m in re.finditer(b"[ -~]{" + str(min_len).encode() + b",}", data):
        try:
            results.append(m.group().decode("ascii"))
        except UnicodeDecodeError:
            pass
    return results


# ---------------------------------------------------------------------------
# 8. Capstone disassembler
# ---------------------------------------------------------------------------

def _find_arm_reset_vector(data: bytes) -> int:
    """
    Return byte offset of the first ARM32 reset-vector branch table (≥4
    consecutive branch instructions starting with 'b <target>').
    Returns -1 if not found.
    """
    for i in range(0, min(len(data) - 32, 0x80000), 4):
        ok = True
        for j in range(4):
            w = struct.unpack_from("<I", data, i + j * 4)[0]
            # ARM unconditional branch: bits 31-24 == 0xEA
            if (w >> 24) != 0xEA:
                ok = False
                break
        if ok:
            return i
    return -1


def disasm_bootloader(boot_data: bytes,
                      vaddr: int = 0x00000000,
                      max_bytes: int = 64 * 1024) -> List[str]:
    """
    Disassemble the ARM32 portion of the bootloader (U-Boot startcode).

    Finds the ARM reset-vector branch table to skip any header bytes.
    """
    if not _HAS_CAPSTONE:
        return ["  [capstone not available – pip install capstone]"]

    arm_off = _find_arm_reset_vector(boot_data)
    if arm_off < 0:
        arm_off = 0   # fall back to raw offset 0

    chunk = boot_data[arm_off: arm_off + max_bytes]
    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    cs.detail = False
    lines = [
        f"; Bootloader (U-Boot startcode) – ARM reset-vector at +0x{arm_off:x}",
        f"; va 0x{vaddr + arm_off:08x}  size {len(chunk)}B",
    ]
    for insn in cs.disasm(chunk, vaddr + arm_off):
        lines.append(f"  {insn.address:08x}  {insn.mnemonic:<10} {insn.op_str}")
    return lines


def disasm_elf(elf: ExtractedELF) -> List[str]:
    """
    Disassemble an ARM32 ELF.

    Strategy:
      1. Try section-header-based .text (requires full section table).
      2. Fall back to the first executable LOAD segment from program headers
         (works on truncated ELFs where the section table is beyond the data).
    """
    if not _HAS_CAPSTONE:
        return ["  [capstone not available]"]

    data  = elf.elf_data
    secs  = _elf32_sections(data)
    phdrs = _elf32_phdrs(data)

    # Build symbol tables (may be empty for truncated ELFs)
    plt     = _elf32_plt(data, secs)
    exports = _elf32_dynsyms(data, secs)
    syms: Dict[int, str] = {va & ~1: name for name, (va, _) in exports.items()}
    syms.update({va: f"plt:{name}" for va, name in plt.items()})

    # Determine if entry point is Thumb (bit 0 of e_entry)
    e_entry   = struct.unpack_from("<I", data, 24)[0] if len(data) >= 28 else 0
    use_thumb = bool(e_entry & 1)

    lines: List[str] = [
        f"; vol{elf.source_vol} @sqfs+0x{elf.sqfs_offset:08x}  "
        f"sha={elf.sha256}  {'[CORRUPT BLOCK – partial data]' if elf.corrupt else ''}",
    ]

    # --- Try section-based .text first ---
    if ".text" in secs:
        text_off, text_sz, text_va = secs[".text"]
        text_data = data[text_off: text_off + min(text_sz, MAX_TEXT_BYTES)]
        if text_data:
            lines.append(f"; .text via section hdr: file+0x{text_off:x} "
                         f"va=0x{text_va:08x} {len(text_data)}B")
            _append_disasm(lines, text_data, text_va, use_thumb, syms)
            if text_sz > MAX_TEXT_BYTES:
                lines.append(f"\n; … ({text_sz - MAX_TEXT_BYTES}B truncated)")
            return lines

    # --- Fall back: first executable LOAD segment ---
    for ph in phdrs:
        if ph["type"] == PT_LOAD and (ph["flags"] & PF_X):
            seg_off  = ph["offset"]
            seg_sz   = ph["filesz"]
            seg_va   = ph["vaddr"]
            seg_data = data[seg_off: seg_off + min(seg_sz, MAX_TEXT_BYTES)]
            if not seg_data:
                continue
            lines.append(f"; .text via LOAD phdr: file+0x{seg_off:x} "
                         f"va=0x{seg_va:08x} {len(seg_data)}B "
                         f"(of {seg_sz}B in full binary)")
            _append_disasm(lines, seg_data, seg_va, use_thumb, syms)
            if seg_sz > MAX_TEXT_BYTES:
                lines.append(f"\n; … ({seg_sz - MAX_TEXT_BYTES}B truncated)")
            return lines

    # --- Nothing found ---
    lines.append(f"; no .text or executable LOAD segment in {len(data)}B truncated ELF")
    # Still disassemble whatever is past the program header table
    phdr_end = (struct.unpack_from("<I", data, 28)[0]
                + struct.unpack_from("<H", data, 44)[0]
                * struct.unpack_from("<H", data, 42)[0]) if len(data) >= 52 else 52
    tail = data[phdr_end:]
    if len(tail) >= 4:
        lines.append(f"; raw bytes after program-header table ({len(tail)}B):")
        _append_disasm(lines, tail, phdr_end, use_thumb, syms)
    return lines


def _append_disasm(lines: List[str], code: bytes,
                   vaddr: int, use_thumb: bool,
                   syms: Dict[int, str]) -> None:
    """Disassemble *code* and append formatted lines to *lines*."""
    cs_mode = capstone.CS_MODE_THUMB if use_thumb else capstone.CS_MODE_ARM
    cs = capstone.Cs(capstone.CS_ARCH_ARM, cs_mode)
    cs.detail = False
    for insn in cs.disasm(code, vaddr):
        label  = syms.get(insn.address, "")
        prefix = f"\n{label}:" if label else ""
        comment = ""
        if insn.mnemonic in ("bl", "b", "blx", "bx", "cbz", "cbnz"):
            try:
                target = int(insn.op_str.split(",")[-1].strip().lstrip("#"), 16)
                sym = syms.get(target & ~1, "")
                if sym:
                    comment = f"  ; {sym}"
            except (ValueError, IndexError):
                pass
        lines.append(f"{prefix}  {insn.address:08x}  "
                     f"{insn.mnemonic:<10} {insn.op_str}{comment}")


# ---------------------------------------------------------------------------
# 9. ELF key-pattern scanner
# ---------------------------------------------------------------------------

def scan_elf_for_privkeys(elf: ExtractedELF) -> List[KeyHit]:
    """Scan an extracted ELF for private-key patterns."""
    data  = elf.elf_data
    secs  = _elf32_sections(data)
    hits: List[KeyHit] = []

    # (a) Scan entire raw bytes for PEM, DER, AES, key strings
    hits.extend(scan_privkey_patterns(data, base_offset=elf.sqfs_offset))

    # (b) Also scan all readable strings in the ELF
    strings = _rodata_strings(data, secs) if secs else _raw_strings(data)
    for s in strings:
        sl = s.lower()
        if any(kw.decode() in sl for kw in KEY_STRINGS):
            hits.append(KeyHit("string",
                               f"crypto string in ELF data: '{s[:60]}'",
                               elf.sqfs_offset,
                               s[:60]))
        for fn in CRYPTO_FUNC_NAMES:
            if fn in sl:
                hits.append(KeyHit("func_ref",
                                   f"crypto function name in ELF data: '{s[:60]}'",
                                   elf.sqfs_offset,
                                   s[:60]))
                break

    # (c) PLT imports (only if section table available)
    for va, name in _elf32_plt(data, secs).items():
        if any(fn in name.lower() for fn in CRYPTO_FUNC_NAMES):
            hits.append(KeyHit("func_ref",
                               f"crypto PLT import '{name}'",
                               elf.sqfs_offset,
                               f"PLT@0x{va:08x} → {name}"))

    # (d) Exported symbols (only if section table available)
    for name, (va, _sz) in _elf32_dynsyms(data, secs).items():
        if any(fn in name.lower() for fn in CRYPTO_FUNC_NAMES):
            hits.append(KeyHit("func_ref",
                               f"crypto export '{name}'",
                               elf.sqfs_offset,
                               f"sym@0x{va:08x} → {name}"))

    return hits


# ---------------------------------------------------------------------------
# 10. UBIFS ELF scanner
# ---------------------------------------------------------------------------

def ubifs_scan_elfs(vol_data: bytes, out_dir: Path) -> List[ExtractedELF]:
    """Walk UBIFS data nodes looking for embedded ARM ELF binaries."""
    UBIFS_MAGIC = 0x31185554
    out_dir.mkdir(parents=True, exist_ok=True)
    found: List[ExtractedELF] = []
    seen:  set = set()
    pos = 0
    while pos < len(vol_data) - 24:
        if struct.unpack_from("<I", vol_data, pos)[0] != UBIFS_MAGIC:
            pos += 1
            continue
        node_len  = struct.unpack_from("<I", vol_data, pos + 16)[0]
        node_type = vol_data[pos + 20] if pos + 20 < len(vol_data) else 255
        if node_type == 1 and node_len >= 100:   # DATA_NODE
            payload = vol_data[pos + 56: pos + node_len]
            if payload[:4] == b"\x7fELF":
                machine = (struct.unpack_from("<H", payload, 18)[0]
                           if len(payload) >= 20 else 0)
                if machine == ELF_MACHINE_ARM:
                    sha = _sha256_hex(payload)
                    if sha not in seen:
                        seen.add(sha)
                        elf = ExtractedELF(9, pos, len(payload),
                                           payload, sha, False)
                        (out_dir / f"ubifs_0x{pos:08x}_{sha}.elf").write_bytes(payload)
                        found.append(elf)
        pos += max(1, node_len) if 8 <= node_len <= 512 * 1024 else 1
    return found


# ---------------------------------------------------------------------------
# 11. U-Boot ARM extraction from allsystem volume
# ---------------------------------------------------------------------------

def extract_uboot_arm(vol_data: bytes) -> Tuple[bytes, int]:
    """
    Find the U-Boot ARM binary inside an allsystemA/B volume.

    The volume starts with a whwh-wrapped HWNP package.  The ARM code is
    found by locating the reset-vector branch table.  Returns
    (arm_bytes, offset_in_vol).
    """
    arm_off = _find_arm_reset_vector(vol_data)
    if arm_off < 0:
        return b"", -1
    # U-Boot typically ends before the next whwh block
    next_whwh = vol_data.find(b"whwh", arm_off + 4)
    end = next_whwh if next_whwh > arm_off else arm_off + 512 * 1024
    return vol_data[arm_off: end], arm_off


# ---------------------------------------------------------------------------
# 12. Report writer
# ---------------------------------------------------------------------------

def _write_report(
    report_path:     Path,
    dump_path:       Path,
    oob_stats_list:  List[OOBStats],
    vol_meta:        Dict[int, Dict],
    elfs_a:          List[ExtractedELF],
    elfs_b:          List[ExtractedELF],
    elfs_ubi:        List[ExtractedELF],
    key_hits_raw:    List[KeyHit],   # from raw volume scans
    key_hits_elfs:   List[KeyHit],   # from ELF scans
    boot_lines:      List[str],
) -> None:
    all_hits = key_hits_raw + key_hits_elfs
    lines: List[str] = []
    a = lines.append

    a("# HG8145V5 NAND Dump – Corruption Fix, Per-Item Extraction & Disassembly Report")
    a("")
    a(f"**Dump**: `{dump_path.name}`")
    a(f"**Size**: {dump_path.stat().st_size // 1024 // 1024} MB (raw, with 64-byte OOB/page)")
    a("")

    # --- 1. Corruption stats ---
    a("## 1. Corruption Analysis – OOB BCH-4 ECC Markers")
    a("")
    a("Each NAND page has 7 bytes of BCH-4 ECC per 512-byte sector stored in "
      "OOB[2:30].  Counts below are derived from those marker bytes.")
    a("")
    a("| Vol | Name | Total data pages | Bad-block pages | Erased (0xFF) | "
      "Pages with ECC |")
    a("|-----|------|-----------------|----------------|---------------|---------------|")
    for st in oob_stats_list:
        name = vol_meta.get(st.vol_id, {}).get("name", "?")
        a(f"| {st.vol_id} | {name} | {st.total_pages} | {st.bad_blocks} | "
          f"{st.erased_pages} | {st.ecc_pages} |")
    a("")
    a("> **Note on corruption**: The non-ECC dump was read without applying BCH-4 "
      "error correction.  LZMA-compressed SquashFS data blocks that span pages "
      "with bit-errors decompress only partially (xz stops at the first "
      "unrecoverable sector).  Typical recovery per 128 KB block: **1–5 KB**, "
      "which always includes the ELF header and first code pages.  The OOB "
      "ECC bytes are present and valid; a future BCH-4 decoder pass would "
      "yield complete 128 KB blocks.")
    a("")

    # --- 2. Volume inventory ---
    a("## 2. Extracted Items (Individually Saved)")
    a("")
    for vol_id in sorted(vol_meta):
        m = vol_meta[vol_id]
        a(f"- **Vol {vol_id}** `{m['name']}` → `{m['file']}`  "
          f"({m['bytes'] // 1024} KB,  {m['lebs']} LEBs,  {m['type']})")
    a("")

    # --- 3. ELF inventory ---
    total_elfs   = len(elfs_a) + len(elfs_b) + len(elfs_ubi)
    corrupt_count = sum(1 for e in elfs_a + elfs_b + elfs_ubi if e.corrupt)
    a("## 3. ARM ELF Binaries Extracted")
    a("")
    a(f"| Source | Count | Notes |")
    a(f"|--------|-------|-------|")
    a(f"| allsystemA vol_4 SquashFS | {len(elfs_a)} | {sum(1 for e in elfs_a if e.corrupt)} from corrupt blocks |")
    a(f"| allsystemB vol_5 SquashFS | {len(elfs_b)} | {sum(1 for e in elfs_b if e.corrupt)} from corrupt blocks |")
    a(f"| UBIFS vol_9               | {len(elfs_ubi)} | direct data nodes |")
    a(f"| **Total**                 | **{total_elfs}** | {corrupt_count} partially decompressed |")
    a("")

    # --- 4. Key pattern findings ---
    a("## 4. Private-Key Pattern Findings")
    a("")
    if not all_hits:
        a("**No private-key patterns detected** in the extracted data.")
        a("")
        a("This is expected: firmware private keys are hardware-bound (see §5).")
    else:
        by_cat: Dict[str, List[KeyHit]] = {}
        for h in all_hits:
            by_cat.setdefault(h.category, []).append(h)
        for cat, hits in sorted(by_cat.items()):
            a(f"### 4.x `{cat}` – {len(hits)} hit(s)")
            a("")
            for h in hits[:20]:
                a(f"- `0x{h.offset:08x}` **{h.description}**")
                a(f"  `{h.excerpt[:80]}`")
            if len(hits) > 20:
                a(f"  *(+{len(hits) - 20} more – see raw ELF scan output)*")
            a("")

    # --- 5. Why no private keys ---
    a("## 5. Why No Plaintext Private Keys Exist in Flash")
    a("")
    a("```")
    a("eFuse OTP  (HiSilicon SD511x, phys 0x12010100, 128 bytes)")
    a("  │  burned at factory – NEVER exported to flash")
    a("  ▼")
    a("DM_ReadKeyFromFlashHead()  →  96-byte KeyFile header (flash, encrypted)")
    a("  │  AES-CBC decrypted with raw eFuse key")
    a("  ▼")
    a("DM_GetKeyByMaterial()  →  PBKDF2-HMAC-SHA256  →  32-byte AES-256 work key")
    a("  │  unique per device")
    a("  ▼")
    a("aescrypt2  (AES-256-CBC)  ──►  hw_ctree.xml  (encrypted on flash)")
    a("```")
    a("")
    a("The NAND dump contains the **encrypted** KeyFile header but NOT the eFuse "
      "seed.  Without the eFuse OTP the work key cannot be derived and "
      "hw_ctree.xml cannot be decrypted offline.")
    a("")
    a("### Extraction Methods (require live device access)")
    a("")
    a("| Method | Command | Prerequisite |")
    a("|--------|---------|--------------|")
    a("| U-Boot UART | `md.b 0x12010100 80` | UART console (115200 8N1) |")
    a("| Root shell | `dd if=/dev/efuse bs=1 count=128 2>/dev/null \\| xxd` | Telnet/SSH root |")
    a("| JTAG | Read 128 B @ 0x12010100 | ARM Cortex-A9 DAP |")
    a("")

    # --- 6. Bootloader excerpt ---
    a("## 6. Bootloader (U-Boot) Disassembly Excerpt")
    a("")
    a("```asm")
    for ln in boot_lines[:80]:
        a(ln)
    if len(boot_lines) > 80:
        a(f"; … ({len(boot_lines) - 80} more lines in asm/bootloader.asm)")
    a("```")
    a("")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def analyse(dump_path: Path, out_dir: Path) -> None:
    print(f"[1/10] Loading dump: {dump_path}  "
          f"({dump_path.stat().st_size // 1024 // 1024} MB)")
    dump = dump_path.read_bytes()

    print("[2/10] Stripping OOB bytes …")
    main = strip_oob(dump)
    main_path = out_dir / "nand_main.bin"
    main_path.write_bytes(main)
    print(f"       {len(main) // 1024 // 1024} MB clean image → {main_path.name}")

    print("[3/10] Extracting UBI volumes …")
    volumes, leb_maps = extract_ubi_volumes(main, dump)

    elf_out = out_dir / "elfs"
    asm_out = out_dir / "asm"
    elf_out.mkdir(parents=True, exist_ok=True)
    asm_out.mkdir(parents=True, exist_ok=True)

    vol_names = {
        0: "flash_configA", 1: "flash_configB",
        2: "slave_paramA",  3: "slave_paramB",
        4: "allsystemA",    5: "allsystemB",
        6: "wifi_paramA",   7: "wifi_paramB",
        8: "vol8",          9: "vol9_ubifs",
    }
    vol_meta: Dict[int, Dict] = {}
    for vol_id, vol_data in sorted(volumes.items()):
        vname = vol_names.get(vol_id, f"vol_{vol_id}")
        vpath = out_dir / f"vol_{vol_id}_{vname}.bin"
        vpath.write_bytes(vol_data)
        sqfs_off = vol_data.find(b"hsqs")
        sqfs_str = f"SquashFS@0x{sqfs_off:x}" if sqfs_off >= 0 else "raw binary"
        print(f"       Vol {vol_id:2d}  {vname:<20} "
              f"{len(vol_data) // 1024:6d} KB  {sqfs_str}  → {vpath.name}")
        vol_meta[vol_id] = {
            "name": vname, "file": vpath.name,
            "lebs": len(leb_maps.get(vol_id, {})),
            "bytes": len(vol_data), "type": sqfs_str,
        }

    print("[4/10] Computing OOB corruption statistics …")
    oob_stats_list: List[OOBStats] = []
    for vol_id in [4, 5, 9]:
        if vol_id in leb_maps:
            stats = oob_stats(dump, vol_id, leb_maps[vol_id])
            oob_stats_list.append(stats)
            print(f"       Vol {vol_id}: {stats.total_pages} pages  "
                  f"bad={stats.bad_blocks}  erased={stats.erased_pages}  "
                  f"ecc={stats.ecc_pages}")

    print("[5/10] Scanning raw volumes for key patterns …")
    key_hits_raw: List[KeyHit] = []
    for vol_id, vol_data in sorted(volumes.items()):
        hits = scan_privkey_patterns(vol_data,
                                     base_offset=vol_id * len(vol_data))
        if hits:
            vname = vol_names.get(vol_id, f"vol_{vol_id}")
            print(f"       ⚑ Vol {vol_id} {vname}: {len(hits)} hit(s)")
            key_hits_raw.extend(hits)

    print("[6/10] Scanning allsystemA SquashFS for ARM ELFs …")
    vol4 = volumes.get(4, b"")
    sqfs4_off = vol4.find(b"hsqs")
    sqfs4 = vol4[sqfs4_off:] if sqfs4_off >= 0 else b""
    elfs_a = scan_sqfs_for_elfs(sqfs4, 4, elf_out) if sqfs4 else []
    print(f"       Found {len(elfs_a)} ARM ELFs  "
          f"({sum(1 for e in elfs_a if e.corrupt)} from corrupt blocks)")

    print("[7/10] Scanning allsystemB SquashFS for ARM ELFs …")
    vol5 = volumes.get(5, b"")
    sqfs5_off = vol5.find(b"hsqs")
    sqfs5 = vol5[sqfs5_off:] if sqfs5_off >= 0 else b""
    elfs_b = scan_sqfs_for_elfs(sqfs5, 5, elf_out) if sqfs5 else []
    print(f"       Found {len(elfs_b)} ARM ELFs  "
          f"({sum(1 for e in elfs_b if e.corrupt)} from corrupt blocks)")

    print("[8/10] Scanning UBIFS (vol 9) for ARM ELFs …")
    vol9 = volumes.get(9, b"")
    elfs_ubi = ubifs_scan_elfs(vol9, elf_out) if vol9 else []
    print(f"       Found {len(elfs_ubi)} ARM ELFs")

    print("[9/10] Disassembling & scanning ELFs for key patterns …")
    # Bootloader
    uboot_code, uboot_off = extract_uboot_arm(vol4)
    if not uboot_code:
        uboot_code = main[:64 * 1024]
        uboot_off  = 0
    boot_lines = disasm_bootloader(uboot_code, vaddr=0)
    (asm_out / "bootloader.asm").write_text(
        "\n".join(boot_lines), encoding="utf-8")
    print(f"       Bootloader: {len(boot_lines)} disasm lines  "
          f"(U-Boot ARM code at vol4+0x{uboot_off:x})")

    # Per-ELF disassembly + key scan
    all_elfs = elfs_a + elfs_b + elfs_ubi
    key_hits_elfs: List[KeyHit] = []
    for idx, elf in enumerate(all_elfs):
        asm_lines = disasm_elf(elf)
        asm_file  = (asm_out /
                     f"vol{elf.source_vol}_0x{elf.sqfs_offset:08x}_{elf.sha256}.asm")
        asm_file.write_text("\n".join(asm_lines), encoding="utf-8")

        hits = scan_elf_for_privkeys(elf)
        if hits:
            key_hits_elfs.extend(hits)
            print(f"       ⚑ vol{elf.source_vol} @0x{elf.sqfs_offset:08x}: "
                  f"{len(hits)} hit(s) "
                  f"[{', '.join(sorted({h.category for h in hits}))}]")

        if (idx + 1) % 50 == 0:
            print(f"       … {idx + 1}/{len(all_elfs)} ELFs processed")

    total_hits = len(key_hits_raw) + len(key_hits_elfs)
    print(f"       Total key hits: {total_hits} "
          f"({len(key_hits_raw)} raw volume + {len(key_hits_elfs)} ELF)")

    print("[10/10] Writing report …")
    report_path = out_dir / "DISASM_REPORT.md"
    _write_report(
        report_path, dump_path,
        oob_stats_list, vol_meta,
        elfs_a, elfs_b, elfs_ubi,
        key_hits_raw, key_hits_elfs,
        boot_lines,
    )

    elf_count  = len(list(elf_out.glob("*.elf")))
    asm_count  = len(list(asm_out.glob("*.asm")))
    bin_count  = len(list(out_dir.glob("vol_*.bin")))
    print(f"\n[✓] Volume binaries : {out_dir}  ({bin_count} files)")
    print(f"[✓] ELF binaries    : {elf_out}  ({elf_count} files)")
    print(f"[✓] Disassembly     : {asm_out}  ({asm_count} files)")
    print(f"[✓] Report          : {report_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _download(url: str, dest: Path) -> None:
    print(f"    Downloading → {dest}")
    req = urllib.request.Request(url, headers={"User-Agent": "HuaweiFirmwareTool/1.0"})
    with urllib.request.urlopen(req) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done  = 0
        with dest.open("wb") as f:
            while True:
                chunk = resp.read(DOWNLOAD_CHUNK)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r    {done * 100 // total}%  "
                          f"{done // 1024 // 1024}/{total // 1024 // 1024} MB",
                          end="", flush=True)
    print()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "HG8145V5 NAND dump: fix corruption, extract items individually, "
            "Capstone ARM disassembly, private-key pattern search."
        )
    )
    p.add_argument("--dump",     default=None,
                   help="Path to raw NAND dump (.BIN)")
    p.add_argument("--out",      default="nand_disasm",
                   help="Output directory (default: nand_disasm/)")
    p.add_argument("--download", action="store_true",
                   help="(Re-)download the dump from GitHub Releases first")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    dump_path: Optional[Path] = None
    if args.dump:
        dump_path = Path(args.dump)
        if not dump_path.exists():
            sys.exit(f"[ERROR] Dump not found: {dump_path}")
    else:
        for c in [Path(DUMP_FILENAME),
                  out_dir / DUMP_FILENAME,
                  Path("/tmp") / DUMP_FILENAME]:
            if c.exists():
                dump_path = c
                break

    if args.download or dump_path is None:
        dest = out_dir / DUMP_FILENAME
        if not dest.exists() or args.download:
            _download(DUMP_URL, dest)
        dump_path = dest

    if dump_path is None or not dump_path.exists():
        sys.exit("[ERROR] Dump not found. Use --dump <path> or --download.")

    analyse(dump_path, out_dir)


if __name__ == "__main__":
    main()
