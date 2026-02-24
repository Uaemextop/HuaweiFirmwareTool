"""String and data formatting utilities."""

from typing import Union


def format_bytes(bytes_val: Union[int, float], precision: int = 2) -> str:
    """
    Format bytes into human-readable string.

    Args:
        bytes_val: Number of bytes
        precision: Decimal precision

    Returns:
        Formatted string (e.g., "1.23 MB")
    """
    if bytes_val < 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(bytes_val)

    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.{precision}f} {units[unit_index]}"


def format_duration(seconds: Union[int, float]) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "1h 23m 45s")
    """
    if seconds < 0:
        return "0s"

    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def format_speed(bytes_per_sec: Union[int, float]) -> str:
    """
    Format transfer speed.

    Args:
        bytes_per_sec: Speed in bytes per second

    Returns:
        Formatted string (e.g., "1.23 MB/s")
    """
    return f"{format_bytes(bytes_per_sec)}/s"


def format_hex(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Format binary data as hex dump.

    Args:
        data: Binary data
        bytes_per_line: Number of bytes per line

    Returns:
        Formatted hex dump string
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{bytes_per_line*3}}  {ascii_part}")
    return '\n'.join(lines)


def truncate_middle(text: str, max_length: int = 50) -> str:
    """
    Truncate text in the middle with ellipsis.

    Args:
        text: Text to truncate
        max_length: Maximum length

    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text

    if max_length < 3:
        return text[:max_length]

    side_length = (max_length - 3) // 2
    return f"{text[:side_length]}...{text[-side_length:]}"
