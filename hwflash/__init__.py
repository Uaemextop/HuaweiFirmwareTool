"""
hwflash — Open-Source Huawei ONT Firmware Flasher

An open-source reimplementation of the Huawei OBSCTool for flashing
firmware to ONT (Optical Network Terminal) devices via UDP broadcast.

Features:
  - Network adapter selection
  - HWNP firmware file loading and validation
  - OBSC UDP protocol for firmware transfer
  - Configurable frame size, interval, flash mode
  - Device discovery and status display
  - Audit logging
  - Modern themed GUI with animated splash

Usage:
    python -m hwflash.main

Requirements:
    Python 3.10+
"""

from hwflash._version import __version__  # noqa: F401

__author__ = "HuaweiFirmwareTool Contributors"
