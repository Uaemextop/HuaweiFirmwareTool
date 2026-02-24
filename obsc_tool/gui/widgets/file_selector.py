"""File selector widget with browse button and validation."""

import tkinter as tk
from tkinter import ttk, filedialog
from pathlib import Path
from typing import Optional, Callable, List, Tuple


class FileSelector(ttk.Frame):
    """
    Reusable file selector widget with browse button.

    Features:
    - Entry field for file path
    - Browse button
    - File validation
    - Support for open/save modes
    - File type filtering
    """

    def __init__(self, parent, label: str = "File:", mode: str = "open",
                 filetypes: Optional[List[Tuple[str, str]]] = None,
                 on_change: Optional[Callable] = None, width: int = 40):
        """
        Initialize file selector.

        Args:
            parent: Parent widget
            label: Label text
            mode: 'open' or 'save'
            filetypes: List of (description, pattern) tuples
            on_change: Callback when file changes
            width: Entry width
        """
        super().__init__(parent)

        self.mode = mode
        self.filetypes = filetypes or [("All Files", "*.*")]
        self.on_change = on_change
        self._path_var = tk.StringVar()
        self._path_var.trace_add('write', self._on_path_changed)

        # Create widgets
        self._create_widgets(label, width)

    def _create_widgets(self, label: str, width: int):
        """Create the UI components."""
        # Label
        if label:
            ttk.Label(self, text=label).pack(side=tk.LEFT, padx=(0, 5))

        # Entry field
        self._entry = ttk.Entry(self, textvariable=self._path_var, width=width)
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Browse button
        self._browse_btn = ttk.Button(self, text="Browse...", command=self._browse)
        self._browse_btn.pack(side=tk.LEFT)

    def _browse(self):
        """Open file dialog."""
        initial_dir = None
        current_path = self.get_path()
        if current_path and Path(current_path).exists():
            initial_dir = str(Path(current_path).parent)

        if self.mode == "save":
            path = filedialog.asksaveasfilename(
                parent=self,
                filetypes=self.filetypes,
                initialdir=initial_dir
            )
        else:
            path = filedialog.askopenfilename(
                parent=self,
                filetypes=self.filetypes,
                initialdir=initial_dir
            )

        if path:
            self.set_path(path)

    def _on_path_changed(self, *args):
        """Handle path change."""
        if self.on_change:
            self.on_change(self.get_path())

    def get_path(self) -> str:
        """Get current file path."""
        return self._path_var.get().strip()

    def set_path(self, path: str):
        """Set file path."""
        self._path_var.set(path)

    def clear(self):
        """Clear the path."""
        self._path_var.set("")

    def is_valid(self) -> bool:
        """Check if current path is valid."""
        path = self.get_path()
        if not path:
            return False
        return Path(path).exists() if self.mode == "open" else True

    def enable(self):
        """Enable the widget."""
        self._entry.configure(state='normal')
        self._browse_btn.configure(state='normal')

    def disable(self):
        """Disable the widget."""
        self._entry.configure(state='disabled')
        self._browse_btn.configure(state='disabled')
