"""
HWNP firmware file parser and validator.

This module provides backward compatibility while the new modular
architecture is in place. New code should use:
- obsc_tool.models.firmware for data models
- obsc_tool.parsers.hwnp for parsing logic
"""

from .models.firmware import FirmwareItem as HWNPItem
from .models.firmware import FirmwarePackage
from .parsers.hwnp import HWNPParser, HWNP_MAGIC, HWNP_HEADER_SIZE, HWNP_ITEM_SIZE
from typing import Dict, Any, Tuple


class HWNPFirmware:
    """
    Parser and validator for HWNP firmware packages.

    This class provides backward compatibility with the original interface.
    It wraps the new modular parser and model classes.
    """

    def __init__(self) -> None:
        """Initialize firmware parser."""
        self._package: FirmwarePackage = FirmwarePackage()

    def load(self, file_path: str) -> None:
        """
        Load and parse an HWNP firmware file.

        Args:
            file_path: Path to the .bin firmware file

        Raises:
            ValueError: If the file is not a valid HWNP firmware
            FileNotFoundError: If the file does not exist
        """
        self._package = HWNPParser.parse(file_path)

    def validate_crc32(self) -> Tuple[bool, bool]:
        """
        Validate CRC32 checksums of the firmware.

        Returns:
            Tuple of (header_valid, data_valid) booleans
        """
        return HWNPParser.validate_crc32(self._package)

    def get_info(self) -> Dict[str, Any]:
        """Get a summary dict of the firmware info."""
        return self._package.to_dict()

    def get_total_data_size(self) -> int:
        """Get total size of all firmware item data."""
        return self._package.get_total_data_size()

    # Properties for backward compatibility
    @property
    def magic(self) -> int:
        """Firmware magic number."""
        return self._package.magic

    @property
    def raw_size(self) -> int:
        """Raw data size."""
        return self._package.raw_size

    @property
    def raw_crc32(self) -> int:
        """Raw CRC32 checksum."""
        return self._package.raw_crc32

    @property
    def header_size(self) -> int:
        """Header size."""
        return self._package.header_size

    @property
    def header_crc32(self) -> int:
        """Header CRC32 checksum."""
        return self._package.header_crc32

    @property
    def item_count(self) -> int:
        """Number of firmware items."""
        return self._package.item_count

    @property
    def prod_list_size(self) -> int:
        """Product list size."""
        return self._package.prod_list_size

    @property
    def item_header_size(self) -> int:
        """Item header size."""
        return self._package.item_header_size

    @property
    def product_list(self) -> str:
        """Product compatibility list."""
        return self._package.product_list

    @property
    def items(self):
        """Firmware items list."""
        return self._package.items

    @property
    def raw_data(self) -> bytes:
        """Raw firmware data."""
        return self._package.raw_data

    @property
    def file_path(self) -> str:
        """Firmware file path."""
        return self._package.file_path


# Re-export for backward compatibility
__all__ = ['HWNPItem', 'HWNPFirmware', 'HWNP_MAGIC', 'HWNP_HEADER_SIZE', 'HWNP_ITEM_SIZE']
