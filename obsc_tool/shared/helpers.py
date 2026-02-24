"""
Shared helper functions used across multiple modules.

Consolidates common operations: safe type conversion, string formatting,
file operations, and threading utilities.
"""

import os
import threading
import logging
from typing import Any, Optional, Callable


logger = logging.getLogger("obsc_tool")


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to int, returning default on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float, returning default on failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def format_size(size_bytes: int) -> str:
    """Format byte size to human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def format_hex(value: int, width: int = 8) -> str:
    """Format integer as hex string with 0x prefix."""
    return f"0x{value:0{width}X}"


def clamp(value: float, min_val: float, max_val: float) -> float:
    """Clamp a value between min and max."""
    return max(min_val, min(value, max_val))


def ensure_dir(path: str) -> str:
    """Create directory if it doesn't exist, return path."""
    os.makedirs(path, exist_ok=True)
    return path


def run_in_thread(func: Callable, *args, daemon: bool = True, name: str = "") -> threading.Thread:
    """Run a function in a background thread."""
    thread = threading.Thread(target=func, args=args, daemon=daemon, name=name)
    thread.start()
    return thread


def truncate(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate text to max length with suffix."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix
