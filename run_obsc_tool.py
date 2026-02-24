#!/usr/bin/env python3
"""Entry point for OBSC Firmware Tool.

Shows a modern animated splash screen with progress while checking
and installing optional dependencies, then launches the main application.
"""

if __name__ == '__main__':
    from obsc_tool.ui.splash import ensure_dependencies

    if ensure_dependencies():
        from obsc_tool.main import main
        main()
