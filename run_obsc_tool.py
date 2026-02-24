#!/usr/bin/env python3
"""Entry point for OBSC Firmware Tool (hwflash)."""

if __name__ == '__main__':
    from hwflash.splash import ensure_dependencies_gui
    if ensure_dependencies_gui():
        from hwflash.main import main
        main()
