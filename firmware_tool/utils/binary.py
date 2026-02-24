"""Binary data operations utilities."""

import struct
import zlib
from typing import Optional


def calculate_crc32(data: bytes, initial: int = 0) -> int:
    """
    Calculate CRC32 checksum for binary data.

    Args:
        data: Binary data to checksum
        initial: Initial CRC value

    Returns:
        CRC32 checksum as 32-bit integer
    """
    return zlib.crc32(data, initial) & 0xFFFFFFFF


def read_cstring(data: bytes, offset: int, max_len: int) -> str:
    """
    Read a null-terminated C-style string from binary data.

    Args:
        data: Binary data buffer
        offset: Starting offset
        max_len: Maximum length to read

    Returns:
        Decoded string (ASCII with replacement for invalid chars)
    """
    raw = data[offset:offset + max_len]
    null_pos = raw.find(b'\x00')
    if null_pos >= 0:
        raw = raw[:null_pos]
    return raw.decode('ascii', errors='replace')


def pack_uint32(value: int) -> bytes:
    """
    Pack unsigned 32-bit integer to little-endian bytes.

    Args:
        value: Integer value (0 to 0xFFFFFFFF)

    Returns:
        4-byte little-endian representation
    """
    return struct.pack('<I', value & 0xFFFFFFFF)


def unpack_uint32(data: bytes, offset: int = 0) -> int:
    """
    Unpack unsigned 32-bit integer from little-endian bytes.

    Args:
        data: Binary data
        offset: Offset to read from

    Returns:
        Unsigned 32-bit integer
    """
    return struct.unpack_from('<I', data, offset)[0]


def pack_uint16(value: int) -> bytes:
    """
    Pack unsigned 16-bit integer to little-endian bytes.

    Args:
        value: Integer value (0 to 0xFFFF)

    Returns:
        2-byte little-endian representation
    """
    return struct.pack('<H', value & 0xFFFF)


def unpack_uint16(data: bytes, offset: int = 0) -> int:
    """
    Unpack unsigned 16-bit integer from little-endian bytes.

    Args:
        data: Binary data
        offset: Offset to read from

    Returns:
        Unsigned 16-bit integer
    """
    return struct.unpack_from('<H', data, offset)[0]


def pack_uint8(value: int) -> bytes:
    """
    Pack unsigned 8-bit integer to bytes.

    Args:
        value: Integer value (0 to 0xFF)

    Returns:
        Single byte
    """
    return struct.pack('B', value & 0xFF)


def unpack_uint8(data: bytes, offset: int = 0) -> int:
    """
    Unpack unsigned 8-bit integer from bytes.

    Args:
        data: Binary data
        offset: Offset to read from

    Returns:
        Unsigned 8-bit integer
    """
    return struct.unpack_from('B', data, offset)[0]


def hex_dump(data: bytes, offset: int = 0, length: Optional[int] = None,
             bytes_per_line: int = 16) -> str:
    """
    Create a hex dump string of binary data.

    Args:
        data: Binary data to dump
        offset: Starting offset
        length: Number of bytes to dump (None for all)
        bytes_per_line: Number of bytes per output line

    Returns:
        Formatted hex dump string
    """
    if length is None:
        length = len(data) - offset
    else:
        length = min(length, len(data) - offset)

    lines = []
    for i in range(0, length, bytes_per_line):
        chunk = data[offset + i:offset + i + bytes_per_line]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{offset + i:08X}  {hex_str:<{bytes_per_line * 3}}  {ascii_str}')

    return '\n'.join(lines)
