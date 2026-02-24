"""
Shared utility functions for OBSC Firmware Tool.

Provides helpers used across multiple modules so they are not duplicated.
All functions here are pure (no side effects, no global state) and are
safe to import from any layer (core, GUI, tests).
"""

from __future__ import annotations

import datetime
import ipaddress
import math
import os
import re
import socket
import struct
import zlib
from typing import Optional, Tuple


# --------------------------------------------------------------------------- #
#  Type / value coercion
# --------------------------------------------------------------------------- #

def safe_int(value, default: int = 0) -> int:
    """Convert *value* to ``int``, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default: float = 0.0) -> float:
    """Convert *value* to ``float``, returning *default* on failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def clamp(value: float, lo: float, hi: float) -> float:
    """Return *value* clamped to the closed interval [*lo*, *hi*]."""
    return max(lo, min(hi, value))


# --------------------------------------------------------------------------- #
#  Formatting helpers
# --------------------------------------------------------------------------- #

def format_size(nbytes: int) -> str:
    """Return a human-readable byte count string (e.g. ``"12.4 MB"``).

    Args:
        nbytes: Number of bytes.

    Returns:
        Human-readable string.
    """
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{nbytes} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} TB"


def format_duration(seconds: float) -> str:
    """Return a human-readable duration string (e.g. ``"2m 34s"``).

    Args:
        seconds: Duration in seconds.

    Returns:
        Human-readable string.
    """
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m {s:02d}s"


def log_line(message: str) -> str:
    """Format *message* with an ISO timestamp prefix suitable for log files.

    Args:
        message: Plain text message.

    Returns:
        Formatted log line, e.g. ``"[2025-01-15 14:32:01] message"``.
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"[{ts}] {message}"


# --------------------------------------------------------------------------- #
#  Network / IP helpers
# --------------------------------------------------------------------------- #

def is_valid_ip(address: str) -> bool:
    """Return ``True`` if *address* is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(address)
        return True
    except ValueError:
        return False


def is_valid_netmask(mask: str) -> bool:
    """Return ``True`` if *mask* is a valid IPv4 subnet mask."""
    try:
        parts = list(map(int, mask.split(".")))
        if len(parts) != 4:
            return False
        n = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        # Valid netmask: consecutive 1-bits followed by 0-bits
        inv = (~n) & 0xFFFFFFFF
        return (inv & (inv + 1)) == 0
    except (ValueError, AttributeError):
        return False


def broadcast_address(ip: str, netmask: str) -> str:
    """Compute the broadcast address for a given IP and subnet mask.

    Args:
        ip: Host IPv4 address string.
        netmask: Subnet mask string.

    Returns:
        Broadcast address string, or ``"255.255.255.255"`` on error.
    """
    try:
        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(net.broadcast_address)
    except ValueError:
        return "255.255.255.255"


def test_udp_bind(ip: str, port: int) -> Tuple[bool, str]:
    """Try to bind a UDP socket on *ip*:*port* and return (ok, message).

    Args:
        ip: Local IP to bind.
        port: UDP port number.

    Returns:
        ``(True, "OK")`` on success or ``(False, error_message)`` on failure.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, port))
        return True, f"Bind {ip}:{port} OK"
    except OSError as exc:
        return False, str(exc)
    finally:
        if sock is not None:
            sock.close()


# --------------------------------------------------------------------------- #
#  CRC32 / checksum helpers
# --------------------------------------------------------------------------- #

def crc32_of(data: bytes) -> int:
    """Return the CRC32 of *data* as an unsigned 32-bit integer."""
    return zlib.crc32(data) & 0xFFFFFFFF


def hex32(value: int) -> str:
    """Format *value* as a zero-padded 8-digit hex string (``"0x…"`` prefix).

    Args:
        value: Integer value.

    Returns:
        String like ``"0x0078D4F1"``.
    """
    return f"0x{value & 0xFFFFFFFF:08X}"


# --------------------------------------------------------------------------- #
#  Path helpers
# --------------------------------------------------------------------------- #

def ensure_dir(path: str) -> None:
    """Create *path* (and all parents) if it does not already exist."""
    os.makedirs(path, exist_ok=True)


def safe_filename(name: str) -> str:
    """Strip characters that are invalid in file names on common operating systems.

    Args:
        name: Proposed file name.

    Returns:
        Sanitised file name (spaces replaced with ``_``).
    """
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "", name).strip()


# --------------------------------------------------------------------------- #
#  Colour interpolation (for gradient drawing)
# --------------------------------------------------------------------------- #

def lerp_color(c1: tuple, c2: tuple, t: float) -> tuple:
    """Linearly interpolate between two RGB(A) tuples.

    Args:
        c1: Start colour as ``(r, g, b)`` or ``(r, g, b, a)``.
        c2: End colour with the same number of channels.
        t: Blend factor in [0, 1].

    Returns:
        Interpolated colour tuple (same channel count as inputs).
    """
    return tuple(int(a + (b - a) * t) for a, b in zip(c1, c2))


def rgb_hex(r: int, g: int, b: int) -> str:
    """Return a ``'#RRGGBB'`` Tk colour string."""
    return f"#{r & 0xFF:02x}{g & 0xFF:02x}{b & 0xFF:02x}"
