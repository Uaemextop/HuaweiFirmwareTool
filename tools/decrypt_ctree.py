#!/usr/bin/env python3
"""
decrypt_ctree.py – Huawei HG8145V5 hw_ctree.xml decryption pipeline.

Uses the Huawei AEST (OS_AescryptDecrypt) file format to decrypt
hw_ctree.xml extracted from the NAND UBIFS volume, then extracts
certprvtPassword and decrypts the encrypted PEM private keys.

AEST file format (from hw_ssp_aescrypt.h, disassembly of OS_AescryptFillHead):
  Offset  Size  Description
  0x00     4    version  (0x04)
  0x04     4    flags    (0x01 = encrypted)
  0x08    16    AES-256-CBC IV (random)
  0x18     n    ciphertext  (PKCS#7-padded plaintext, AES-256-CBC)
  last 4   4    CRC-32 (Huawei custom, covers header + ciphertext)

Key derivation chain (device-specific, requires physical access for full recovery):
  eFuse OTP registers (0x12010100, SD511x SoC)
    → hal_efuse_read_sram_efuse_data()    (hw_module_efuse.ko)
    → DM_GetRootKeyOffset()               (libsmp_api.so)
    → HW_OS_FLASH_Read("KeyFile", ...)    (flash KeyFile volume, first 96 bytes)
    → DM_LdspDecryptData()                (AES-ECB decrypt of 96-byte block)
    → DM_GetKeyByMaterial()               (PBKDF2-HMAC-SHA256, 1 iter, 32 bytes)
    → AES-256-CBC key → hw_ctree.xml decrypt

Usage
-----
    # Full pipeline: download dump, extract, try to decrypt, save results
    python3 tools/decrypt_ctree.py --dump <NAND.BIN> --out keys/

    # Supply eFuse key (hex) directly for full decryption
    python3 tools/decrypt_ctree.py --dump <NAND.BIN> --efuse <32-byte-hex> --out keys/

    # Decrypt PEM keys only with known passphrase
    python3 tools/decrypt_ctree.py --passphrase <pass> --pem-dir keys/ --out keys/

    # Try bruteforce wordlist on encrypted hw_ctree.xml
    python3 tools/decrypt_ctree.py --dump <NAND.BIN> --wordlist wordlist.txt --out keys/

Requirements
------------
    pip install cryptography ubi_reader
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import os
import re
import struct
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional deps
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# NAND geometry (DS35Q1GA)
# ---------------------------------------------------------------------------
PAGE_MAIN       = 2048
PAGE_OOB        = 64
PAGE_SIZE       = PAGE_MAIN + PAGE_OOB
PAGES_PER_BLOCK = 64
BLOCK_SIZE      = PAGE_MAIN * PAGES_PER_BLOCK   # 128 KB usable
TOTAL_BLOCKS    = 1024

# UBI constants
UBI_EC_MAGIC      = 0x55424923   # 'UBI#'
UBI_VID_MAGIC     = 0x55424921   # 'UBI!'
UBI_LAYOUT_VOL_ID = 0x7FFFEFFF
UBI_LEB_SIZE      = BLOCK_SIZE - 0x1000   # 124 KB

# UBIFS node magic
UBIFS_NODE_MAGIC = b'\x31\x18\x10\x06'

# Huawei AEST constants
AEST_VERSION   = 0x04
AEST_ENCRYPTED = 0x01
AEST_HDR_LEN   = 24    # version(4) + flags(4) + IV(16)

DUMP_URL = (
    "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/"
    "Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN"
)

# Known/default passphrases to attempt on PEM keys
_DEFAULT_PASSPHRASES = [
    "PolarSSLTest",
    "huawei",
    "Huawei",
    "admin",
    "Admin@123",
    "root",
    "password",
    "12345678",
    "Changeme_1234",
    "Hello@12345",
    "huawei123",
    "Huawei@123",
    "",
]

# ---------------------------------------------------------------------------
# Step 1: OOB strip
# ---------------------------------------------------------------------------

def strip_oob(raw: bytes) -> bytes:
    """Strip 64-byte OOB from every 2112-byte NAND page → 128 MB clean image."""
    total_pages = len(raw) // PAGE_SIZE
    out = bytearray(total_pages * PAGE_MAIN)
    for i in range(total_pages):
        src = i * PAGE_SIZE
        dst = i * PAGE_MAIN
        out[dst:dst + PAGE_MAIN] = raw[src:src + PAGE_MAIN]
    return bytes(out)


# ---------------------------------------------------------------------------
# Step 2: UBI volume extraction
# ---------------------------------------------------------------------------

def _read_ubi_vtbl(main: bytes, leb_size: int) -> Dict[int, str]:
    """Return vol_id → name map from UBI layout volume."""
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
    names: Dict[int, str] = {}
    for vid in range(128):
        rec_off = vid * 172
        if rec_off + 172 > len(vtbl):
            break
        rec = vtbl[rec_off:rec_off + 172]
        if struct.unpack_from(">I", rec, 0)[0] == 0:
            continue
        name_len = struct.unpack_from(">H", rec, 14)[0]
        if name_len == 0 or name_len > 128:
            continue
        try:
            names[vid] = rec[16:16 + name_len].decode("utf-8", errors="replace")
        except Exception:
            pass
    return names


def extract_ubi_volumes(main: bytes) -> Dict[str, bytes]:
    """Return {name: data} for every UBI volume in the image."""
    raw_blocks: Dict[int, Dict[int, bytes]] = {}
    leb_size: Optional[int] = None

    for blk in range(TOTAL_BLOCKS):
        off = blk * BLOCK_SIZE
        if off + 4 > len(main):
            break
        if struct.unpack_from(">I", main, off)[0] != UBI_EC_MAGIC:
            continue
        vid_hdr_off = struct.unpack_from(">I", main, off + 16)[0]
        data_off    = struct.unpack_from(">I", main, off + 20)[0]
        if leb_size is None:
            leb_size = BLOCK_SIZE - data_off
        vid_start = off + vid_hdr_off
        if vid_start + 16 > len(main):
            continue
        if struct.unpack_from(">I", main, vid_start)[0] != UBI_VID_MAGIC:
            continue
        vol_id = struct.unpack_from(">I", main, vid_start + 8)[0]
        lnum   = struct.unpack_from(">I", main, vid_start + 12)[0]
        if vol_id == UBI_LAYOUT_VOL_ID:
            continue
        leb_data = main[off + data_off: off + BLOCK_SIZE]
        raw_blocks.setdefault(vol_id, {})[lnum] = leb_data

    if leb_size is None:
        leb_size = UBI_LEB_SIZE

    vol_names = _read_ubi_vtbl(main, leb_size)
    volumes: Dict[str, bytes] = {}
    for vol_id in sorted(raw_blocks):
        lebs = raw_blocks[vol_id]
        if not lebs:
            continue
        max_lnum = max(lebs)
        buf = bytearray(b"\xff" * (leb_size * (max_lnum + 1)))
        for lnum, data in lebs.items():
            s = lnum * leb_size
            buf[s:s + min(len(data), leb_size)] = data[:leb_size]
        name = vol_names.get(vol_id, f"vol_{vol_id}")
        volumes[name] = bytes(buf)

    return volumes


# ---------------------------------------------------------------------------
# Step 3: UBIFS node scanner → find hw_ctree.xml
# ---------------------------------------------------------------------------

# UBIFS node types
UBIFS_INO_NODE  = 0   # inode
UBIFS_DATA_NODE = 1   # data
UBIFS_DENT_NODE = 2   # directory entry
UBIFS_XATTR_NODE = 3  # extended attribute

def _scan_ubifs_for_files(ubifs: bytes, patterns: List[bytes]) -> Dict[str, bytes]:
    """
    Scan a raw UBIFS volume image for file data nodes matching filename patterns.

    UBIFS node layout:
      0x00  4  magic   0x06101831 (little-endian)
      0x04  4  CRC-32
      0x08  8  sequence number
      0x10  4  node length
      0x14  1  node type
      0x15  1  group type
      0x16  2  padding

    DENT node (after common header, 24 bytes):
      0x18  8  inum (target inode number)
      0x20  1  type
      0x21  1  nlen (name length)
      0x22  2  dkey_len
      0x24  n  name

    DATA node (after common header):
      0x18  8  key (inum 4 bytes LE + block 4 bytes)
      0x20  4  size (uncompressed)
      0x24  2  compr_type  (0=none, 1=zlib, 2=lzo, 3=zstd)
      0x26  2  data_size
      0x28  n  data

    We do a linear scan for UBIFS_NODE_MAGIC, parse node headers, collect
    dentry→inode mapping for names matching our patterns, then collect all
    data blocks for those inodes.
    """
    HDR_MAGIC = b'\x31\x18\x10\x06'
    HDR_LEN = 24
    results: Dict[str, bytes] = {}

    # Pass 1: build inum → name map for matching files
    inum_to_name: Dict[int, str] = {}
    pos = 0
    while pos < len(ubifs) - HDR_LEN:
        idx = ubifs.find(HDR_MAGIC, pos)
        if idx == -1:
            break
        pos = idx
        if pos + HDR_LEN > len(ubifs):
            break
        node_len = struct.unpack_from("<I", ubifs, pos + 0x10)[0]
        node_type = ubifs[pos + 0x14]
        if node_len < HDR_LEN or node_len > 0x100000:
            pos += 4
            continue
        if node_type == UBIFS_DENT_NODE and pos + 0x24 < len(ubifs):
            try:
                inum  = struct.unpack_from("<Q", ubifs, pos + 0x18)[0]
                nlen  = ubifs[pos + 0x21]
                if nlen > 0 and pos + 0x24 + nlen <= len(ubifs):
                    name = ubifs[pos + 0x24: pos + 0x24 + nlen]
                    for pat in patterns:
                        if pat in name:
                            inum_to_name[inum] = name.decode("utf-8", errors="replace")
            except Exception:
                pass
        pos += max(4, node_len)

    if not inum_to_name:
        return results

    # Pass 2: collect data blocks for matching inodes
    inum_blocks: Dict[int, Dict[int, bytes]] = {inum: {} for inum in inum_to_name}
    pos = 0
    while pos < len(ubifs) - HDR_LEN:
        idx = ubifs.find(HDR_MAGIC, pos)
        if idx == -1:
            break
        pos = idx
        node_len = struct.unpack_from("<I", ubifs, pos + 0x10)[0]
        node_type = ubifs[pos + 0x14]
        if node_len < HDR_LEN or node_len > 0x100000:
            pos += 4
            continue
        if node_type == UBIFS_DATA_NODE and pos + 0x28 < len(ubifs):
            try:
                inum      = struct.unpack_from("<I", ubifs, pos + 0x18)[0]
                blk_num   = struct.unpack_from("<I", ubifs, pos + 0x1C)[0]
                uncomp_sz = struct.unpack_from("<I", ubifs, pos + 0x20)[0]
                compr     = struct.unpack_from("<H", ubifs, pos + 0x24)[0]
                data_sz   = struct.unpack_from("<H", ubifs, pos + 0x26)[0]
                raw_data  = ubifs[pos + 0x28: pos + 0x28 + data_sz]
                if inum in inum_blocks:
                    if compr == 0:
                        inum_blocks[inum][blk_num] = raw_data
                    elif compr == 1:
                        import zlib
                        inum_blocks[inum][blk_num] = zlib.decompress(raw_data)
                    elif compr == 2:
                        try:
                            import lzo
                            inum_blocks[inum][blk_num] = lzo.decompress(raw_data, False, uncomp_sz)
                        except Exception:
                            inum_blocks[inum][blk_num] = raw_data
                    else:
                        inum_blocks[inum][blk_num] = raw_data
            except Exception:
                pass
        pos += max(4, node_len)

    # Reassemble files
    for inum, name in inum_to_name.items():
        blocks = inum_blocks[inum]
        if not blocks:
            continue
        out = b"".join(blocks[k] for k in sorted(blocks))
        results[name] = out

    return results


def extract_ctree_from_ubifs(ubifs: bytes) -> Optional[bytes]:
    """Find hw_ctree.xml (encrypted or plain) in UBIFS image."""
    patterns = [b"hw_ctree.xml", b"ctree.xml"]
    found = _scan_ubifs_for_files(ubifs, patterns)
    for name, data in found.items():
        if b"ctree" in name.encode() or b"ctree" in name.lower().encode("utf-8"):
            return data
    # Fallback: raw scan for XML signatures or AEST header
    for sig in [b"<?xml", b"\x04\x00\x00\x00\x01\x00\x00\x00"]:
        idx = ubifs.find(sig)
        while idx != -1:
            chunk = ubifs[idx:idx + 65536]
            if sig == b"<?xml" and b"certprvtPassword" in chunk:
                end = chunk.find(b"\x00")
                return chunk if end == -1 else chunk[:end]
            if sig == b"\x04\x00\x00\x00\x01\x00\x00\x00":
                return chunk
            idx = ubifs.find(sig, idx + 1)
    return None


# ---------------------------------------------------------------------------
# Step 4: Huawei KeyFile extraction
# ---------------------------------------------------------------------------

def extract_keyfile_header(keyfile_vol: bytes) -> bytes:
    """
    Extract the first 96 bytes of the KeyFile UBI volume.
    This is the eFuse-encrypted AES key material header.
    """
    # The KeyFile volume starts with a 96-byte AES-encrypted block.
    # Strip any leading 0xFF padding (erased flash).
    for off in range(0, min(len(keyfile_vol), 8192), 16):
        chunk = keyfile_vol[off:off + 96]
        if chunk and chunk != b"\xff" * 96 and chunk != b"\x00" * 96:
            return chunk
    return keyfile_vol[:96]


# ---------------------------------------------------------------------------
# Step 5: Huawei AEST decrypt
# ---------------------------------------------------------------------------

def _huawei_crc32(data: bytes, crc_init: int = 0) -> int:
    """
    Huawei custom CRC-32 (matches zlib crc32 in practice).
    Reconstructed from libhw_ssp_basic.so OS_AescryptCRC disassembly.
    """
    import zlib
    return zlib.crc32(data, crc_init) & 0xFFFFFFFF


def _evp_bytes_to_key(passphrase: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16) -> Tuple[bytes, bytes]:
    """
    OpenSSL EVP_BytesToKey with MD5, 1 iteration.
    Used by OpenSSL PEM encryption (DEK-Info: AES-256-CBC).
    """
    d = b""
    d_i = b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + passphrase + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


def aest_decrypt(ciphertext_file: bytes, aes_key: bytes) -> Optional[bytes]:
    """
    Decrypt a Huawei AEST-format file.

    Format:
      [0:4]   version  (expect 0x04)
      [4:8]   flags    (expect 0x01)
      [8:24]  IV       (16 bytes)
      [24:-4] ciphertext (AES-256-CBC, PKCS#7)
      [-4:]   CRC32    (covers [0:-4])

    Returns decrypted bytes, or None on failure.
    """
    if not _HAS_CRYPTO:
        print("  [!] cryptography library not available, cannot decrypt")
        return None

    if len(ciphertext_file) < AEST_HDR_LEN + 16 + 4:
        return None

    version = struct.unpack_from("<I", ciphertext_file, 0)[0]
    flags   = struct.unpack_from("<I", ciphertext_file, 4)[0]

    if version != AEST_VERSION or flags != AEST_ENCRYPTED:
        # Try big-endian
        version = struct.unpack_from(">I", ciphertext_file, 0)[0]
        flags   = struct.unpack_from(">I", ciphertext_file, 4)[0]
        if version != AEST_VERSION or flags != AEST_ENCRYPTED:
            return None

    iv         = ciphertext_file[8:24]
    body       = ciphertext_file[24:-4]
    stored_crc = struct.unpack_from("<I", ciphertext_file, len(ciphertext_file) - 4)[0]

    # Verify CRC
    calc_crc = _huawei_crc32(ciphertext_file[:-4])
    if calc_crc != stored_crc:
        # CRC mismatch – NAND corruption or wrong format; try anyway
        pass

    try:
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(body) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        return None


def try_decrypt_aest(data: bytes, candidates: List[bytes]) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Try each AES-256 key candidate. Return (plaintext, key) on first success.
    """
    for key in candidates:
        if len(key) != 32:
            continue
        result = aest_decrypt(data, key)
        if result and len(result) > 8:
            return result, key
    return None, None


# ---------------------------------------------------------------------------
# Step 6: PBKDF2 key derivation from keyfile + eFuse
# ---------------------------------------------------------------------------

def derive_aes_key_from_efuse(efuse_bytes: bytes, keyfile_header: bytes) -> bytes:
    """
    Reproduce Huawei key derivation:
      1. AES-ECB decrypt keyfile_header (first 32 bytes) with efuse_bytes → material
      2. PBKDF2-HMAC-SHA256(password=material, salt=b"", iterations=1, dklen=32) → AES key

    NOTE: The exact AES-ECB step (DM_LdspDecryptData) uses the raw 32-byte
    eFuse key to decrypt the 96-byte keyfile block.  The exact field layout
    of the 96-byte block is undocumented; this implements the most likely
    interpretation based on libsmp_api.so disassembly.
    """
    if not _HAS_CRYPTO:
        return b"\x00" * 32

    # Step 1: AES-ECB decrypt first 32 bytes of keyfile header with eFuse key
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        cipher = Cipher(algorithms.AES(efuse_bytes[:32]),
                        modes.ECB(), backend=default_backend())
        dec = cipher.decryptor()
        material = dec.update(keyfile_header[:32]) + dec.finalize()
    except Exception:
        material = keyfile_header[:32]

    # Step 2: PBKDF2-HMAC-SHA256(material, salt=b"", iterations=1, 32 bytes)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        iterations=1,
        backend=default_backend(),
    )
    return kdf.derive(material)


# ---------------------------------------------------------------------------
# Step 7: Extract certprvtPassword from decrypted XML
# ---------------------------------------------------------------------------

def extract_certprvt_password(xml_data: bytes) -> Optional[str]:
    """
    Parse decrypted hw_ctree.xml and return the certprvtPassword value.
    Tries multiple known XML paths and attribute names.
    """
    # Strip AEST noise if any trailing garbage
    xml_str = xml_data.decode("utf-8", errors="ignore")
    # Clean up null bytes
    xml_str = xml_str.replace("\x00", "")

    # Method 1: regex scan (fast, tolerant of partial parse)
    patterns = [
        r'certprvtPassword["\s]*[=:>]+\s*["\']?([^"\'<\s]+)',
        r'<certprvtPassword>([^<]+)</certprvtPassword>',
        r'certprvtPassword\s*value=["\']([^"\']+)',
        r'name="certprvtPassword"[^>]*value="([^"]+)"',
        r'param name="certprvtPassword" value="([^"]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, xml_str, re.IGNORECASE)
        if m:
            return m.group(1).strip()

    # Method 2: ElementTree parse
    try:
        root = ET.fromstring(xml_str)
        for elem in root.iter():
            if "certprvtPassword" in (elem.tag or ""):
                if elem.text:
                    return elem.text.strip()
            for attr, val in elem.attrib.items():
                if "certprvtPassword" in attr:
                    return val
                if attr == "name" and "certprvtPassword" in val:
                    # <param name="certprvtPassword" value="..."/>
                    v = elem.attrib.get("value")
                    if v:
                        return v
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Step 8: Decrypt OpenSSL PEM private keys
# ---------------------------------------------------------------------------

def decrypt_pem_key(pem_data: bytes, passphrase: str) -> Optional[bytes]:
    """
    Decrypt an OpenSSL PEM private key (DEK-Info: AES-256-CBC or DES-EDE3-CBC).
    Returns the plaintext PEM bytes on success.
    """
    if not _HAS_CRYPTO:
        return None
    try:
        key_obj = load_pem_private_key(
            pem_data,
            password=passphrase.encode("utf-8") if passphrase else None,
            backend=default_backend(),
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )
        return key_obj.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    except Exception:
        return None


def decrypt_pem_key_to_der(pem_data: bytes, passphrase: str) -> Optional[bytes]:
    """
    Decrypt a PEM private key and return DER bytes.
    """
    if not _HAS_CRYPTO:
        return None
    try:
        key_obj = load_pem_private_key(
            pem_data,
            password=passphrase.encode("utf-8") if passphrase else None,
            backend=default_backend(),
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )
        return key_obj.private_bytes(Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    except Exception:
        return None


def get_pem_key_type(pem_data: bytes) -> str:
    """Return key type string from PEM header."""
    for line in pem_data.split(b"\n"):
        if line.startswith(b"-----BEGIN"):
            return line.decode("ascii", errors="replace").strip("- \r\n")
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Step 9: Bruteforce passphrase on PEM keys
# ---------------------------------------------------------------------------

def bruteforce_pem_passphrase(pem_data: bytes, wordlist: List[str]) -> Optional[str]:
    """Try each passphrase in the wordlist. Return matching passphrase or None."""
    for pw in wordlist:
        result = decrypt_pem_key(pem_data, pw)
        if result is not None:
            return pw
    return None


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def load_dump(path: Optional[str]) -> bytes:
    """Load NAND dump from path (download if not found locally)."""
    local_candidates = [
        path,
        "/tmp/nand_dump.bin",
        os.path.join(os.getcwd(), "Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN"),
    ]
    for p in local_candidates:
        if p and os.path.isfile(p):
            size = os.path.getsize(p)
            print(f"  Loading dump from {p} ({size:,} bytes)")
            with open(p, "rb") as f:
                return f.read()
    # Download
    dl_path = "/tmp/nand_dump.bin"
    print(f"  Downloading dump from GitHub releases …")
    urllib.request.urlretrieve(DUMP_URL, dl_path)
    print(f"  Saved to {dl_path}")
    with open(dl_path, "rb") as f:
        return f.read()


def run_pipeline(
    dump_path: Optional[str],
    pem_dir: str,
    out_dir: str,
    efuse_hex: Optional[str] = None,
    extra_passphrase: Optional[str] = None,
    wordlist_path: Optional[str] = None,
    skip_download: bool = False,
) -> None:

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ── Build passphrase list ────────────────────────────────────────────
    passphrases = list(_DEFAULT_PASSPHRASES)
    if extra_passphrase:
        passphrases.insert(0, extra_passphrase)
    if wordlist_path:
        with open(wordlist_path) as f:
            passphrases = [l.rstrip("\n") for l in f] + passphrases

    # ── Load PEM keys to decrypt ─────────────────────────────────────────
    pem_dir_p = Path(pem_dir)
    encrypted_pems: Dict[str, bytes] = {}
    if pem_dir_p.is_dir():
        for pf in sorted(pem_dir_p.glob("*.pem")) + sorted(pem_dir_p.glob("*.key")):
            data = pf.read_bytes()
            if b"ENCRYPTED" in data or b"Proc-Type" in data:
                encrypted_pems[pf.name] = data
                print(f"  Found encrypted key: {pf.name}")
            else:
                print(f"  Skipping (plaintext): {pf.name}")

    # ── Try passphrase-only mode (no dump) ───────────────────────────────
    if not dump_path and skip_download:
        print("\n[=] Passphrase-only mode (no NAND dump)")
        _attempt_pem_decryption(encrypted_pems, passphrases, out)
        return

    # ── Load + strip OOB ────────────────────────────────────────────────
    print("\n[1] Loading NAND dump …")
    try:
        raw = load_dump(dump_path)
    except Exception as e:
        print(f"  [!] Could not load dump: {e}")
        print("  Falling back to passphrase-only mode")
        _attempt_pem_decryption(encrypted_pems, passphrases, out)
        return

    print(f"  Raw size: {len(raw):,} bytes")
    if len(raw) % PAGE_SIZE != 0:
        print(f"  [!] Size not multiple of {PAGE_SIZE} – may not have OOB")
        main = raw
    else:
        print("[2] Stripping OOB …")
        main = strip_oob(raw)
        print(f"  Clean size: {len(main):,} bytes")

    # ── Extract UBI volumes ──────────────────────────────────────────────
    print("[3] Parsing UBI volumes …")
    volumes = extract_ubi_volumes(main)
    for name, data in volumes.items():
        print(f"  vol '{name}': {len(data):,} bytes")

    # Save all volumes individually to out_dir
    print("[3b] Saving corrected volume images …")
    for name, data in volumes.items():
        # Sanitize name for filesystem
        safe = re.sub(r'[^\w\-.]', '_', name)
        vol_path = out / f"vol_{safe}.img"
        vol_path.write_bytes(data)
        print(f"  Saved {vol_path} ({len(data):,} bytes)")

    # Also save bootloader
    boot_size = BLOCK_SIZE  # first 128 KB block
    if len(main) >= boot_size:
        boot_path = out / "bootloader.img"
        boot_path.write_bytes(main[:boot_size])
        print(f"  Saved {boot_path} ({boot_size:,} bytes)")

    # ── Extract KeyFile header ───────────────────────────────────────────
    keyfile_vol = None
    for name in ["keyfile", "KeyFile", "key_file", "vol_8"]:
        if name in volumes:
            keyfile_vol = volumes[name]
            break
    # Try to find by content
    if keyfile_vol is None:
        for name, data in volumes.items():
            if "key" in name.lower():
                keyfile_vol = data
                break

    aes_key_candidates: List[bytes] = []
    keyfile_header: Optional[bytes] = None

    if keyfile_vol:
        keyfile_header = extract_keyfile_header(keyfile_vol)
        kf_path = out / "keyfile_header_96bytes.bin"
        kf_path.write_bytes(keyfile_header)
        print(f"\n[4] KeyFile header saved → {kf_path}")
        print(f"    Hex: {keyfile_header.hex()}")
    else:
        print("\n[4] KeyFile volume not found in UBI volumes")

    # ── Build AES key candidates ─────────────────────────────────────────
    # From provided eFuse
    if efuse_hex:
        try:
            efuse_bytes = bytes.fromhex(efuse_hex)
            if keyfile_header:
                derived = derive_aes_key_from_efuse(efuse_bytes, keyfile_header)
                aes_key_candidates.append(derived)
                print(f"\n[5] eFuse-derived AES key: {derived.hex()}")
            # Also try raw eFuse as key
            if len(efuse_bytes) >= 32:
                aes_key_candidates.append(efuse_bytes[:32])
        except ValueError:
            print(f"  [!] Invalid eFuse hex: {efuse_hex}")

    # Well-known test keys
    aes_key_candidates += [
        b"\x00" * 32,
        b"\xff" * 32,
        hashlib.sha256(b"Huawei").digest(),
        hashlib.sha256(b"huawei").digest(),
        hashlib.sha256(b"PolarSSLTest").digest(),
        hashlib.sha256(b"HuaweiONT").digest(),
        hashlib.sha256(b"admin").digest(),
        # Key derived from empty eFuse + keyfile header
    ]
    if keyfile_header:
        # PBKDF2 from keyfile header with no eFuse (all-zeros eFuse)
        k = derive_aes_key_from_efuse(b"\x00" * 32, keyfile_header)
        aes_key_candidates.append(k)
        # Also try keyfile header first 32 bytes directly
        if len(keyfile_header) >= 32:
            aes_key_candidates.append(keyfile_header[:32])

    # ── Find and decrypt hw_ctree.xml ────────────────────────────────────
    ctree_data: Optional[bytes] = None
    for name in ["file_system", "vol_9", "jffs2", "ubifs"]:
        if name in volumes:
            ubifs_vol = volumes[name]
            print(f"\n[5] Scanning UBIFS volume '{name}' for hw_ctree.xml …")
            ctree_data = extract_ctree_from_ubifs(ubifs_vol)
            if ctree_data:
                print(f"    Found hw_ctree.xml ({len(ctree_data)} bytes)")
                (out / "hw_ctree.xml.raw").write_bytes(ctree_data)
                break

    # Also scan flash_config volumes for XML (sometimes stored unencrypted)
    if ctree_data is None:
        for name in ["flash_configA", "flash_configB", "flash_config"]:
            if name in volumes:
                data = volumes[name]
                if b"certprvtPassword" in data:
                    idx = data.find(b"<?xml")
                    if idx == -1:
                        idx = 0
                    ctree_data = data[idx:idx + 65536]
                    print(f"\n[5] Found hw_ctree.xml in '{name}' (plaintext XML!)")
                    (out / "hw_ctree.xml.raw").write_bytes(ctree_data)
                    break

    # Try raw scan of main image
    if ctree_data is None:
        print("\n[5] Scanning full NAND image for hw_ctree.xml …")
        for sig in [b"certprvtPassword"]:
            idx = main.find(sig)
            if idx != -1:
                # Back up to XML header
                start = max(0, idx - 4096)
                chunk = main[start:idx + 8192]
                xml_start = chunk.rfind(b"<?xml")
                if xml_start != -1:
                    ctree_data = chunk[xml_start:xml_start + 65536]
                    print(f"  Found XML with certprvtPassword at offset {start + xml_start:#x}")
                    (out / "hw_ctree.xml.raw").write_bytes(ctree_data)
                break

    # ── Try AEST decryption ──────────────────────────────────────────────
    certprvt_password: Optional[str] = None

    if ctree_data:
        # Check if already plaintext XML
        if ctree_data.lstrip().startswith(b"<?xml") or b"<" in ctree_data[:64]:
            print("\n[6] hw_ctree.xml is plaintext XML")
            certprvt_password = extract_certprvt_password(ctree_data)
            if certprvt_password:
                print(f"    certprvtPassword = '{certprvt_password}'")
                (out / "certprvtPassword.txt").write_text(certprvt_password)
                passphrases.insert(0, certprvt_password)
        else:
            # Encrypted – try AEST decrypt
            print(f"\n[6] Attempting AEST decrypt of hw_ctree.xml ({len(aes_key_candidates)} key candidates) …")
            plaintext, used_key = try_decrypt_aest(ctree_data, aes_key_candidates)
            if plaintext:
                print(f"    Decrypted with key: {used_key.hex()}")
                (out / "hw_ctree.xml.decrypted").write_bytes(plaintext)
                certprvt_password = extract_certprvt_password(plaintext)
                if certprvt_password:
                    print(f"    certprvtPassword = '{certprvt_password}'")
                    (out / "certprvtPassword.txt").write_text(certprvt_password)
                    passphrases.insert(0, certprvt_password)
                else:
                    print("    [!] Could not extract certprvtPassword from decrypted XML")
            else:
                print("    [!] All AES key candidates failed.")
                print("        The eFuse OTP key is required for decryption.")
                print(f"        KeyFile header saved to: {out}/keyfile_header_96bytes.bin")
                print("        To decrypt, provide eFuse key via --efuse <32-byte-hex>")
                _write_efuse_guide(out)
    else:
        print("\n[6] hw_ctree.xml not found in NAND dump")

    # ── Decrypt PEM keys ─────────────────────────────────────────────────
    print("\n[7] Attempting PEM private key decryption …")
    _attempt_pem_decryption(encrypted_pems, passphrases, out)


def _attempt_pem_decryption(
    encrypted_pems: Dict[str, bytes],
    passphrases: List[str],
    out: Path,
) -> None:
    """Try all passphrases on each encrypted PEM key, save results."""
    if not encrypted_pems:
        print("  No encrypted PEM keys to process")
        return

    total_decrypted = 0
    for pem_name, pem_data in encrypted_pems.items():
        key_type = get_pem_key_type(pem_data)
        stem = Path(pem_name).stem

        # Extract DEK-Info IV for reference
        dek_match = re.search(rb"DEK-Info:\s*([^,\r\n]+),([0-9A-Fa-f]+)", pem_data)
        if dek_match:
            cipher_name = dek_match.group(1).decode()
            iv_hex = dek_match.group(2).decode()
            print(f"  {pem_name}: {key_type}, {cipher_name}, IV={iv_hex}")
        else:
            print(f"  {pem_name}: {key_type}")

        found_pw = None
        dec_pem = None
        dec_der = None

        for pw in passphrases:
            pem_result = decrypt_pem_key(pem_data, pw)
            if pem_result:
                found_pw = pw
                dec_pem = pem_result
                dec_der = decrypt_pem_key_to_der(pem_data, pw)
                break

        if found_pw is not None:
            total_decrypted += 1
            print(f"    ✓ DECRYPTED  passphrase='{found_pw}'")
            pem_out = out / f"{stem}_decrypted.pem"
            pem_out.write_bytes(dec_pem)
            if dec_der:
                der_out = out / f"{stem}_decrypted.der"
                der_out.write_bytes(dec_der)
                print(f"    → {pem_out}")
                print(f"    → {der_out}")
        else:
            print(f"    ✗ Could not decrypt (passphrase unknown / eFuse required)")

    print(f"\n  Summary: {total_decrypted}/{len(encrypted_pems)} keys decrypted")


def _write_efuse_guide(out: Path) -> None:
    """Write a guide for obtaining eFuse key from the device."""
    guide = """\
# How to Obtain the eFuse Key (HG8145V5 / HiSilicon SD511x)

The AES-256 key protecting hw_ctree.xml is derived from the device eFuse OTP.
It **cannot** be extracted from the NAND flash dump alone.

## Option A: U-Boot Serial Console
Connect via UART (115200 8N1) and interrupt boot:
    md.b 0x12010100 40        ; read 64 bytes of eFuse SRAM shadow
    md.b 0x12010140 40        ; second 64 bytes
Save the 128-byte hex dump and pass it to this tool:
    python3 tools/decrypt_ctree.py --dump NAND.BIN --efuse <64-bytes-hex> --out keys/

## Option B: Root Shell on Running Device
    cat /proc/soc_info              ; may contain eFuse readout
    cat /dev/efuse 2>/dev/null | xxd -l 64
    strings /proc/kcore | grep -i efuse

## Option C: JTAG/SWD (HiSilicon ARM Cortex-A9 DAP)
Use OpenOCD with CoreSight DAP access to read the eFuse SRAM shadow registers
at 0x12010100 on the SD511x SoC.

## Once You Have the eFuse Key
    python3 tools/decrypt_ctree.py \\
        --dump Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN \\
        --efuse <64-bytes-hex-from-eFuse-registers> \\
        --out keys/

The tool will:
1. AES-ECB decrypt the 96-byte KeyFile header using the eFuse key
2. PBKDF2-HMAC-SHA256 derive the hw_ctree.xml AES-256-CBC key
3. Decrypt hw_ctree.xml and extract certprvtPassword
4. Decrypt all PEM private keys using certprvtPassword
5. Save PEM + DER to keys/
"""
    guide_path = out / "HOW_TO_DECRYPT_EFUSE.md"
    guide_path.write_text(guide)
    print(f"  Guide written to {guide_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Huawei HG8145V5 hw_ctree.xml decrypt → PEM key extraction pipeline"
    )
    parser.add_argument("--dump",         help="Path to NAND dump BIN file (downloaded if absent)")
    parser.add_argument("--no-download",  action="store_true", help="Do not download dump")
    parser.add_argument("--efuse",        help="eFuse OTP bytes as hex string (32–64 bytes)")
    parser.add_argument("--passphrase",   help="Known certprvtPassword passphrase")
    parser.add_argument("--wordlist",     help="Wordlist file for passphrase bruteforce")
    parser.add_argument("--pem-dir",      default="keys", help="Directory with encrypted PEM keys (default: keys/)")
    parser.add_argument("--out",          default="keys", help="Output directory (default: keys/)")
    args = parser.parse_args()

    if not _HAS_CRYPTO:
        print("[!] 'cryptography' package not installed. Install with:")
        print("    pip install cryptography")
        sys.exit(1)

    print("=" * 60)
    print("Huawei HG8145V5 hw_ctree.xml → PEM key decrypt pipeline")
    print("=" * 60)

    run_pipeline(
        dump_path=args.dump,
        pem_dir=args.pem_dir,
        out_dir=args.out,
        efuse_hex=args.efuse,
        extra_passphrase=args.passphrase,
        wordlist_path=args.wordlist,
        skip_download=args.no_download,
    )


if __name__ == "__main__":
    main()
