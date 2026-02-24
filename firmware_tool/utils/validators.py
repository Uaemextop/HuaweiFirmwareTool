"""Input validation utilities."""

import re
import socket
from typing import Any, Optional, Union


def safe_int(value: Any, default: int = 0, min_val: Optional[int] = None,
             max_val: Optional[int] = None) -> int:
    """
    Safely convert value to integer with optional range validation.

    Args:
        value: Value to convert
        default: Default value if conversion fails
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        Converted integer value or default
    """
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return default
        return result
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert value to boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'yes', 'on')
    try:
        return bool(int(value))
    except (ValueError, TypeError):
        return default


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip_str)
        parts = ip_str.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (socket.error, ValueError, AttributeError):
        return False


def is_valid_netmask(mask_str: str) -> bool:
    """Check if string is a valid netmask."""
    if not is_valid_ip(mask_str):
        return False
    try:
        mask_int = int.from_bytes(socket.inet_aton(mask_str), 'big')
        # Valid netmask has contiguous 1s followed by contiguous 0s
        mask_bin = bin(mask_int)[2:].zfill(32)
        return re.match(r'^1*0*$', mask_bin) is not None
    except Exception:
        return False


def is_valid_port(port: Union[str, int]) -> bool:
    """Check if port number is valid (1-65535)."""
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_mac(mac_str: str) -> bool:
    """Check if string is a valid MAC address."""
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return pattern.match(mac_str) is not None
