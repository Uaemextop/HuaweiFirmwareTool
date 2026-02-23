#!/usr/bin/env python3
"""
ONT Firmware Flasher - Open Source GUI Tool
Windows 11 compatible application for flashing Huawei ONT firmware

Copyright (c) 2026 - Licensed under MIT License
"""

import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import MainWindow
from utils.logger import setup_logger

def main():
    """Main entry point for the application"""
    # Setup logging
    logger = setup_logger()
    logger.info("Starting ONT Firmware Flasher")

    # Enable High DPI scaling for Windows 11
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("ONT Firmware Flasher")
    app.setOrganizationName("HuaweiFirmwareTool")
    app.setApplicationVersion("1.0.0")

    # Apply Windows 11 style
    app.setStyle("Fusion")

    # Create and show main window
    window = MainWindow()
    window.show()

    # Run application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
