"""File operation utilities."""

import os
import tempfile
from pathlib import Path
from typing import Union, Optional


def read_binary(file_path: Union[str, Path]) -> bytes:
    """
    Read binary file safely.

    Args:
        file_path: Path to file

    Returns:
        File contents as bytes

    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file can't be read
    """
    with open(file_path, 'rb') as f:
        return f.read()


def write_binary(file_path: Union[str, Path], data: bytes) -> None:
    """
    Write binary data to file safely.

    Args:
        file_path: Path to file
        data: Binary data to write

    Raises:
        IOError: If file can't be written
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'wb') as f:
        f.write(data)


def ensure_directory(dir_path: Union[str, Path]) -> Path:
    """
    Ensure directory exists, create if necessary.

    Args:
        dir_path: Directory path

    Returns:
        Path object
    """
    path = Path(dir_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_temp_path(prefix: str = 'obsc_', suffix: str = '') -> str:
    """
    Get temporary file path.

    Args:
        prefix: Filename prefix
        suffix: Filename suffix

    Returns:
        Temporary file path
    """
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.close(fd)
    return path


def get_safe_filename(filename: str) -> str:
    """
    Convert filename to safe version (remove invalid characters).

    Args:
        filename: Original filename

    Returns:
        Safe filename
    """
    invalid_chars = '<>:"/\\|?*'
    safe_name = ''.join(c if c not in invalid_chars else '_' for c in filename)
    return safe_name.strip()


def get_file_extension(file_path: Union[str, Path]) -> str:
    """
    Get file extension (without dot).

    Args:
        file_path: File path

    Returns:
        Extension string (lowercase)
    """
    return Path(file_path).suffix.lstrip('.').lower()


def get_file_size(file_path: Union[str, Path]) -> int:
    """
    Get file size in bytes.

    Args:
        file_path: File path

    Returns:
        File size in bytes
    """
    return Path(file_path).stat().st_size
