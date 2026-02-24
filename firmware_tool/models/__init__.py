"""
Data models for the firmware tool.

This package contains data model classes and structures.
"""

from .firmware import FirmwareItem, FirmwarePackage
from .network import NetworkAdapter, NetworkDevice

__all__ = ['FirmwareItem', 'FirmwarePackage', 'NetworkAdapter', 'NetworkDevice']
