"""
OBSC Firmware Tool - Open Source Huawei ONT Firmware Flasher

An open-source reimplementation of the Huawei OBSCTool for flashing
firmware to ONT (Optical Network Terminal) devices via UDP broadcast.

Features:
  - Network adapter selection
  - HWNP firmware file loading and validation
  - OBSC UDP protocol for firmware transfer
  - Configurable frame size, interval, flash mode
  - Device discovery and status display
  - Audit logging
  - Modern Windows 11 themed GUI

Usage:
    python obsc_tool/main.py

Requirements:
    Python 3.10+ (Windows 11)
    No external dependencies (uses tkinter)
"""

__version__ = "1.0.0"
__author__ = "HuaweiFirmwareTool Contributors"
