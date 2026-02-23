"""
ONT Broadcast Tool – Open-source replacement for OBSCTool
(Huawei ONT_V100R002C00SPC253.exe / OntSoftwareBroadcaster 1211.exe)

Usage:
  python main.py
"""

import sys
import os
import logging

# Put the tool's own directory on the path so imports work whether
# run directly or via PyInstaller bundle.
_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
)


def main():
    from src.gui.main_window import MainWindow
    app = MainWindow()
    app.run()


if __name__ == '__main__':
    main()
