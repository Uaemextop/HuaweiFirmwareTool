"""
Shared validation functions used across core modules.

Extracts common validation patterns for IP addresses, port numbers,
file sizes, and protocol parameters.
"""

import re
from typing import Optional


IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    return bool(IP_PATTERN.match(ip))


def is_valid_port(port: int) -> bool:
    """Check if a port number is in valid range (1-65535)."""
    return isinstance(port, int) and 1 <= port <= 65535


def validate_range(value: int, min_val: int, max_val: int,
                   name: str = "value") -> int:
    """Validate that value is within range, raise ValueError if not."""
    if not (min_val <= value <= max_val):
        raise ValueError(f"{name} {value} outside valid range [{min_val}, {max_val}]")
    return value


def validate_not_empty(data: bytes, name: str = "data") -> bytes:
    """Validate that data is not empty, raise ValueError if it is."""
    if not data:
        raise ValueError(f"No {name} provided")
    return data


def validate_max_size(data: bytes, max_size: int,
                      name: str = "data") -> bytes:
    """Validate that data doesn't exceed max size."""
    if len(data) > max_size:
        raise ValueError(
            f"{name} size {len(data):,} exceeds maximum {max_size:,}"
        )
    return data


def sanitize_string(text: str, max_length: int = 255) -> str:
    """Sanitize a string: strip whitespace, limit length."""
    return text.strip()[:max_length]


def parse_ip_port(address: str, default_port: int = 0) -> tuple:
    """Parse 'ip:port' string into (ip, port) tuple."""
    if ":" in address:
        parts = address.rsplit(":", 1)
        ip = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = default_port
    else:
        ip = address
        port = default_port
    return ip, port
