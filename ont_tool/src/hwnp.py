"""
HWNP Firmware Package Parser
=============================
Python port of the Huawei HWNP format as defined in huawei_header.h.

Magic: 0x504e5748 ("HWNP")

Header layout (36 bytes, little-endian):
  uint32  magic_huawei
  uint32  raw_sz
  uint32  raw_crc32
  uint32  hdr_sz
  uint32  hdr_crc32
  uint32  item_counts
  uint8   _unknown_1
  uint8   _unknown_2
  uint16  prod_list_sz
  uint32  item_sz
  uint32  reserved

Item layout (360 bytes):
  uint32  iter
  uint32  item_crc32
  uint32  data_off
  uint32  data_sz
  char[256] item       (file path, e.g. "file:/var/run.sh")
  char[16]  section    (e.g. "UNKNOWN", "MODULE", "UPGRDCHECK")
  char[64]  version
  uint32  policy
  uint32  reserved
"""

import struct
import zlib
from dataclasses import dataclass, field
from typing import List, Optional
import os

# Constants
HWNP_MAGIC = b'HWNP'
HEADER_STRUCT = '<4sIIIIIBBHII'  # 36 bytes
HEADER_SIZE = struct.calcsize(HEADER_STRUCT)  # == 36

ITEM_STRUCT = '<IIII256s16s64sII'  # 360 bytes
ITEM_SIZE = struct.calcsize(ITEM_STRUCT)  # == 360

# Section constants
SECTION_UPGRDCHECK = 'UPGRDCHECK'
SECTION_SIGNINFO   = 'SIGNINFO'
SECTION_SIGNATURE  = 'SIGNATURE'
SECTION_MODULE     = 'MODULE'
SECTION_EFS        = 'EFS'
SECTION_UPDATEFLAG = 'UPDATEFLAG'
SECTION_UNKNOWN    = 'UNKNOWN'


@dataclass
class HWNPItem:
    """Represents a single item in an HWNP firmware package."""
    iter: int = 0
    item_crc32: int = 0
    data_off: int = 0
    data_sz: int = 0
    item: str = ''       # file path on target FS, e.g. "file:/var/run.sh"
    section: str = ''
    version: str = ''
    policy: int = 0
    reserved: int = 0
    data: bytes = field(default_factory=bytes)

    @property
    def target_path(self) -> str:
        """Return the target filesystem path (strips 'file:' prefix)."""
        if ':' in self.item:
            return self.item.split(':', 1)[1]
        return self.item

    @property
    def name(self) -> str:
        """Short filename for display."""
        return os.path.basename(self.target_path)

    @property
    def is_script(self) -> bool:
        return self.item.endswith('.sh')

    @property
    def is_archive(self) -> bool:
        return self.item.endswith(('.tar.gz', '.tgz', '.gz'))

    @property
    def is_xml(self) -> bool:
        return self.item.endswith('.xml')


@dataclass
class HWNPPackage:
    """Parsed HWNP firmware package."""
    magic: bytes = HWNP_MAGIC
    raw_sz: int = 0
    raw_crc32: int = 0
    hdr_sz: int = 0
    hdr_crc32: int = 0
    item_counts: int = 0
    unknown1: int = 0
    unknown2: int = 0
    prod_list_sz: int = 0
    item_sz: int = ITEM_SIZE
    reserved: int = 0
    product_list: str = ''
    items: List[HWNPItem] = field(default_factory=list)

    # Raw bytes of the full package (for sending over network)
    raw_bytes: bytes = field(default_factory=bytes, repr=False)

    @property
    def is_valid(self) -> bool:
        return self.magic == HWNP_MAGIC

    @property
    def product_ids(self) -> List[str]:
        """Return list of supported product IDs."""
        if not self.product_list:
            return []
        return [p for p in self.product_list.split('|') if p]

    @property
    def size_bytes(self) -> int:
        return len(self.raw_bytes)

    @property
    def size_kb(self) -> float:
        return self.size_bytes / 1024

    def crc32_verify(self) -> bool:
        """Verify the CRC32 of the full package."""
        if not self.raw_bytes or len(self.raw_bytes) < HEADER_SIZE:
            return False
        # raw_crc32 covers from offset 12 onwards
        data_to_check = self.raw_bytes[12:]
        calculated = zlib.crc32(data_to_check) & 0xFFFFFFFF
        return calculated == self.raw_crc32

    def get_item_by_section(self, section: str) -> Optional[HWNPItem]:
        for item in self.items:
            if item.section == section:
                return item
        return None

    def get_scripts(self) -> List[HWNPItem]:
        return [i for i in self.items if i.is_script]

    def get_upgrade_check(self) -> Optional[HWNPItem]:
        return self.get_item_by_section(SECTION_UPGRDCHECK)


def _decode_cstr(data: bytes) -> str:
    """Decode a null-terminated C string from bytes."""
    null_pos = data.find(b'\x00')
    if null_pos >= 0:
        data = data[:null_pos]
    return data.decode('utf-8', errors='replace')


def parse_hwnp(data: bytes) -> HWNPPackage:
    """
    Parse an HWNP firmware package from raw bytes.

    Args:
        data: Raw bytes of the HWNP package.

    Returns:
        Parsed HWNPPackage object.

    Raises:
        ValueError: If the data is not a valid HWNP package.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Data too short: {len(data)} < {HEADER_SIZE}")

    # Parse header
    magic, raw_sz, raw_crc32, hdr_sz, hdr_crc32, item_counts, \
        unk1, unk2, prod_list_sz, item_sz, reserved = struct.unpack_from(
            HEADER_STRUCT, data, 0)

    if magic != HWNP_MAGIC:
        raise ValueError(f"Invalid magic: {magic!r}, expected {HWNP_MAGIC!r}")

    pkg = HWNPPackage(
        magic=magic,
        raw_sz=raw_sz,
        raw_crc32=raw_crc32,
        hdr_sz=hdr_sz,
        hdr_crc32=hdr_crc32,
        item_counts=item_counts,
        unknown1=unk1,
        unknown2=unk2,
        prod_list_sz=prod_list_sz,
        item_sz=item_sz,
        reserved=reserved,
        raw_bytes=data,
    )

    # Parse product list
    prod_off = HEADER_SIZE
    if prod_list_sz > 0 and prod_off + prod_list_sz <= len(data):
        raw_prod = data[prod_off:prod_off + prod_list_sz]
        pkg.product_list = _decode_cstr(raw_prod)

    # Items start after header + product list.
    # Align to 4-byte boundary to match the C struct layout.
    items_off = HEADER_SIZE + prod_list_sz
    items_off = (items_off + 3) & ~3  # round up to nearest multiple of 4

    for i in range(item_counts):
        item_off = items_off + i * ITEM_SIZE
        if item_off + ITEM_SIZE > len(data):
            break

        fields = struct.unpack_from(ITEM_STRUCT, data, item_off)
        iter_n, i_crc, d_off, d_sz, item_path_b, section_b, version_b, policy, res = fields

        # Stop on null entry
        if iter_n == 0 and i_crc == 0:
            break

        item_path = _decode_cstr(item_path_b)
        section   = _decode_cstr(section_b)
        version   = _decode_cstr(version_b)

        # Read item data
        item_data = b''
        if d_sz > 0 and d_off + d_sz <= len(data):
            item_data = data[d_off:d_off + d_sz]

        hwnp_item = HWNPItem(
            iter=iter_n,
            item_crc32=i_crc,
            data_off=d_off,
            data_sz=d_sz,
            item=item_path,
            section=section,
            version=version,
            policy=policy,
            reserved=res,
            data=item_data,
        )
        pkg.items.append(hwnp_item)

    pkg.item_counts = len(pkg.items)
    return pkg


def load_hwnp_file(path: str) -> HWNPPackage:
    """Load and parse an HWNP firmware file from disk."""
    with open(path, 'rb') as f:
        data = f.read()
    return parse_hwnp(data)


def verify_package(
    pkg: HWNPPackage,
    verify_crc32: bool = True,
    verify_signature: bool = False,
    signature_key_path: str = '',
) -> tuple:
    """
    Verify an HWNP package's integrity.

    Args:
        pkg: Parsed HWNP package.
        verify_crc32: Check the CRC32 checksum in the header.
        verify_signature: Verify the RSA signature in the SIGNINFO item
                          (requires OpenSSL + a public key PEM file).
        signature_key_path: Path to a PEM-encoded RSA public key file.

    Returns:
        (ok: bool, messages: list[str])
        ok is True only when all enabled checks pass.
    """
    messages: List[str] = []
    ok = True

    if not pkg.is_valid:
        messages.append("FAIL: Not a valid HWNP package (bad magic)")
        return False, messages

    if verify_crc32:
        if pkg.crc32_verify():
            messages.append("OK:   CRC32 checksum valid")
        else:
            messages.append("FAIL: CRC32 checksum mismatch — package may be corrupt")
            ok = False

    if verify_signature:
        if not signature_key_path:
            messages.append("WARN: Signature verification requested but no key file provided")
        elif not os.path.isfile(signature_key_path):
            messages.append(f"WARN: Key file not found: {signature_key_path}")
        else:
            sig_item = pkg.get_item_by_section(SECTION_SIGNINFO)
            if sig_item is None:
                sig_item = pkg.get_item_by_section(SECTION_SIGNATURE)

            if sig_item is None or not sig_item.data:
                messages.append("FAIL: No SIGNINFO/SIGNATURE item found in package")
                ok = False
            else:
                try:
                    result = _rsa_verify(sig_item.data, signature_key_path)
                    if result:
                        messages.append("OK:   RSA signature valid")
                    else:
                        messages.append("FAIL: RSA signature invalid")
                        ok = False
                except Exception as e:
                    messages.append(f"FAIL: RSA verification error: {e}")
                    ok = False

    return ok, messages


def _rsa_verify(sig_data: bytes, key_path: str) -> bool:
    """
    Verify RSA signature using OpenSSL (via the cryptography library or subprocess).
    Returns True if signature is valid.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend

        with open(key_path, 'rb') as f:
            pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        # Huawei signature format: last 256 bytes = RSA-2048 signature,
        # everything before = signed data
        if len(sig_data) <= 256:
            return False

        signed_data = sig_data[:-256]
        signature   = sig_data[-256:]

        pub_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        return True

    except ImportError:
        # cryptography not available – try OpenSSL subprocess
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tf:
            tf.write(sig_data[:-256])
            data_file = tf.name

        with tempfile.NamedTemporaryFile(delete=False, suffix='.sig') as tf:
            tf.write(sig_data[-256:])
            sig_file = tf.name

        try:
            result = subprocess.run(
                ['openssl', 'dgst', '-sha256', '-verify', key_path,
                 '-signature', sig_file, data_file],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        finally:
            os.unlink(data_file)
            os.unlink(sig_file)

    except Exception:
        return False


def describe_package(pkg: HWNPPackage) -> str:
    """Return a human-readable description of an HWNP package."""
    lines = [
        f"HWNP Package: {pkg.size_kb:.1f} KB",
        f"  Items:        {pkg.item_counts}",
        f"  Products:     {pkg.product_list[:60] or '(all)'}",
        f"  CRC32 valid:  {pkg.crc32_verify()}",
        "",
        "  Items:",
    ]
    for item in pkg.items:
        lines.append(
            f"    [{item.section:12s}]  {item.item:45s}  "
            f"{item.data_sz // 1024:5d} KB"
        )
    return '\n'.join(lines)
