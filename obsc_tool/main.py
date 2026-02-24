"""
HuaweiFlash — Main GUI Application

Modern UI with sidebar navigation, gradient accents, and animated
transitions. Uses ttkbootstrap with tkinter/ttk fallback.

The UI is split into mixin classes under ``obsc_tool.ui.tabs``, with
shared utilities in ``obsc_tool.shared``, and the modern layout
in ``obsc_tool.ui``.
"""

from obsc_tool.ui.app import HuaweiFlashApp, main  # noqa: F401

OBSCToolApp = HuaweiFlashApp


if __name__ == '__main__':
    main()
