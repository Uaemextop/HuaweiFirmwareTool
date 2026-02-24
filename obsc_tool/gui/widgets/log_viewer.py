"""Log viewer widget with search and auto-scroll."""

import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime
from typing import Optional


class LogViewer(ttk.Frame):
    """
    Reusable log viewer widget.

    Features:
    - Scrolled text area
    - Auto-scroll option
    - Clear functionality
    - Timestamp support
    - Search/filter
    """

    def __init__(self, parent, height: int = 10, width: int = 80,
                 auto_scroll: bool = True, show_timestamps: bool = True):
        """
        Initialize log viewer.

        Args:
            parent: Parent widget
            height: Widget height in lines
            width: Widget width in characters
            auto_scroll: Auto-scroll to bottom on new entries
            show_timestamps: Prepend timestamps to entries
        """
        super().__init__(parent)

        self.auto_scroll = auto_scroll
        self.show_timestamps = show_timestamps

        # Create widgets
        self._create_widgets(height, width)

    def _create_widgets(self, height: int, width: int):
        """Create the UI components."""
        # Text widget with scrollbar
        self._text = scrolledtext.ScrolledText(
            self,
            height=height,
            width=width,
            wrap=tk.WORD,
            state='disabled'
        )
        self._text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for different log levels
        self._text.tag_config('info', foreground='black')
        self._text.tag_config('success', foreground='green')
        self._text.tag_config('warning', foreground='orange')
        self._text.tag_config('error', foreground='red')
        self._text.tag_config('debug', foreground='gray')

    def add_log(self, message: str, level: str = 'info'):
        """
        Add log entry.

        Args:
            message: Log message
            level: Log level ('info', 'success', 'warning', 'error', 'debug')
        """
        self._text.config(state='normal')

        if self.show_timestamps:
            timestamp = datetime.now().strftime('%H:%M:%S')
            entry = f"[{timestamp}] {message}\n"
        else:
            entry = f"{message}\n"

        self._text.insert(tk.END, entry, level)

        if self.auto_scroll:
            self._text.see(tk.END)

        self._text.config(state='disabled')

    def clear(self):
        """Clear all log entries."""
        self._text.config(state='normal')
        self._text.delete('1.0', tk.END)
        self._text.config(state='disabled')

    def get_text(self) -> str:
        """Get all log text."""
        return self._text.get('1.0', tk.END)

    def search(self, term: str):
        """
        Search for term in logs.

        Args:
            term: Search term
        """
        self._text.tag_remove('search', '1.0', tk.END)

        if not term:
            return

        start = '1.0'
        while True:
            pos = self._text.search(term, start, stopindex=tk.END)
            if not pos:
                break
            end = f"{pos}+{len(term)}c"
            self._text.tag_add('search', pos, end)
            start = end

        self._text.tag_config('search', background='yellow')

    def enable_editing(self):
        """Enable text editing."""
        self._text.config(state='normal')

    def disable_editing(self):
        """Disable text editing."""
        self._text.config(state='disabled')
