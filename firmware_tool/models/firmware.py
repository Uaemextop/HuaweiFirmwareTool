"""Firmware data models."""

from typing import List, Dict, Any


class FirmwareItem:
    """Represents a single firmware item within a package."""

    __slots__ = ('index', 'crc32', 'data_offset', 'data_size',
                 'item_path', 'section', 'version', 'policy', 'data')

    def __init__(self) -> None:
        """Initialize firmware item."""
        self.index: int = 0
        self.crc32: int = 0
        self.data_offset: int = 0
        self.data_size: int = 0
        self.item_path: str = ""
        self.section: str = ""
        self.version: str = ""
        self.policy: int = 0
        self.data: bytes = b""

    def __repr__(self) -> str:
        """String representation of firmware item."""
        return (f"FirmwareItem(index={self.index}, path='{self.item_path}', "
                f"section='{self.section}', size={self.data_size}, "
                f"policy={self.policy})")

    def to_dict(self) -> Dict[str, Any]:
        """Convert item to dictionary."""
        return {
            'index': self.index,
            'path': self.item_path,
            'section': self.section,
            'version': self.version,
            'size': self.data_size,
            'crc32': f"0x{self.crc32:08X}",
            'policy': self.policy,
        }


class FirmwarePackage:
    """Container for firmware package data."""

    __slots__ = ('magic', 'raw_size', 'raw_crc32', 'header_size', 'header_crc32',
                 'item_count', 'prod_list_size', 'item_header_size', 'product_list',
                 'items', 'raw_data', 'file_path')

    def __init__(self) -> None:
        """Initialize firmware package."""
        self.magic: int = 0
        self.raw_size: int = 0
        self.raw_crc32: int = 0
        self.header_size: int = 0
        self.header_crc32: int = 0
        self.item_count: int = 0
        self.prod_list_size: int = 0
        self.item_header_size: int = 0
        self.product_list: str = ""
        self.items: List[FirmwareItem] = []
        self.raw_data: bytes = b""
        self.file_path: str = ""

    def get_total_data_size(self) -> int:
        """Get total size of all firmware item data."""
        return sum(item.data_size for item in self.items)

    def to_dict(self) -> Dict[str, Any]:
        """Convert package to dictionary."""
        import os
        return {
            'file': os.path.basename(self.file_path),
            'size': len(self.raw_data),
            'items': self.item_count,
            'products': self.product_list,
            'items_detail': [item.to_dict() for item in self.items],
        }
