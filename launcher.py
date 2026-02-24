#!/usr/bin/env python3
"""Entry point for HuaweiFlash.

Shows a modern animated splash screen with progress while checking
and installing optional dependencies, then launches the main application.
"""

if __name__ == '__main__':
    from hwflash.ui.splash import ensure_dependencies

    if ensure_dependencies():
        from hwflash.main import main
        main()
