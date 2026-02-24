#!/usr/bin/env python3
"""Entry point for OBSC Firmware Tool.

Shows a splash screen with progress while checking / installing
optional dependencies, then launches the main application.
"""

if __name__ == '__main__':
    from obsc_tool.splash import ensure_dependencies_gui

    if ensure_dependencies_gui():
        from obsc_tool.main import main
        main()
