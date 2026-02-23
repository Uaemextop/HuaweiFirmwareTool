#!/usr/bin/env python3
"""Entry point for OBSC Firmware Tool.

Automatically checks and installs optional dependencies before launching.
"""

import sys
import subprocess


def _ensure_dependencies():
    """Install optional dependencies if not already present."""
    optional_deps = [
        ("serial", "pyserial"),  # Serial terminal support
    ]
    for import_name, pip_name in optional_deps:
        try:
            __import__(import_name)
        except ImportError:
            print(f"Installing optional dependency: {pip_name}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pip_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                print(f"  ✓ {pip_name} installed successfully")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"  ⚠ Could not install {pip_name} — serial terminal "
                      "will not be available. Install manually with: "
                      f"pip install {pip_name}")


if __name__ == '__main__':
    _ensure_dependencies()
    from obsc_tool.main import main
    main()
