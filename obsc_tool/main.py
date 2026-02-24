"""
OBSC Firmware Tool — Main GUI Application

Modern UI with sidebar navigation, gradient accents, and animated
transitions. Uses ttkbootstrap with tkinter/ttk fallback.

The UI is split into mixin classes under ``obsc_tool.gui``, with
shared utilities in ``obsc_tool.shared``, and the modern layout
in ``obsc_tool.ui``.
"""

# Import from the new UI module
from obsc_tool.ui.app import OBSCToolApp, main  # noqa: F401


if __name__ == '__main__':
    main()
