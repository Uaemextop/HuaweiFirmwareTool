"""Progress widget with bar, status, and details."""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable


class ProgressWidget(ttk.Frame):
    """
    Reusable progress display widget.

    Features:
    - Progress bar with percentage
    - Status text
    - Detail text
    - Cancel button (optional)
    - Time estimation
    """

    def __init__(self, parent, show_cancel: bool = False,
                 on_cancel: Optional[Callable] = None):
        """
        Initialize progress widget.

        Args:
            parent: Parent widget
            show_cancel: Show cancel button
            on_cancel: Cancel callback
        """
        super().__init__(parent)

        self.on_cancel = on_cancel
        self._progress_var = tk.DoubleVar(value=0)
        self._status_var = tk.StringVar(value="Ready")
        self._detail_var = tk.StringVar(value="")

        # Create widgets
        self._create_widgets(show_cancel)

    def _create_widgets(self, show_cancel: bool):
        """Create the UI components."""
        # Progress bar frame
        progress_frame = ttk.Frame(self)
        progress_frame.pack(fill=tk.X, pady=5)

        # Progress bar
        self._progressbar = ttk.Progressbar(
            progress_frame,
            variable=self._progress_var,
            maximum=100,
            mode='determinate'
        )
        self._progressbar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # Percentage label
        self._percent_label = ttk.Label(progress_frame, text="0%", width=6)
        self._percent_label.pack(side=tk.LEFT)

        # Status label
        self._status_label = ttk.Label(
            self,
            textvariable=self._status_var,
            font=('', 9, 'bold')
        )
        self._status_label.pack(fill=tk.X, pady=2)

        # Detail label
        self._detail_label = ttk.Label(
            self,
            textvariable=self._detail_var,
            font=('', 8),
            foreground='gray'
        )
        self._detail_label.pack(fill=tk.X, pady=2)

        # Cancel button
        if show_cancel:
            self._cancel_btn = ttk.Button(
                self,
                text="Cancel",
                command=self._on_cancel
            )
            self._cancel_btn.pack(pady=5)

    def _on_cancel(self):
        """Handle cancel button."""
        if self.on_cancel:
            self.on_cancel()

    def set_progress(self, percent: float):
        """
        Set progress percentage.

        Args:
            percent: Progress (0-100)
        """
        self._progress_var.set(min(100, max(0, percent)))
        self._percent_label.config(text=f"{int(percent)}%")

    def set_status(self, status: str):
        """
        Set status text.

        Args:
            status: Status message
        """
        self._status_var.set(status)

    def set_detail(self, detail: str):
        """
        Set detail text.

        Args:
            detail: Detail message
        """
        self._detail_var.set(detail)

    def update_all(self, percent: float, status: str, detail: str = ""):
        """
        Update all fields at once.

        Args:
            percent: Progress percentage
            status: Status message
            detail: Detail message
        """
        self.set_progress(percent)
        self.set_status(status)
        if detail:
            self.set_detail(detail)

    def reset(self):
        """Reset to initial state."""
        self.set_progress(0)
        self.set_status("Ready")
        self.set_detail("")

    def set_indeterminate(self, active: bool = True):
        """
        Set indeterminate mode (pulsing).

        Args:
            active: True for indeterminate, False for determinate
        """
        if active:
            self._progressbar.config(mode='indeterminate')
            self._progressbar.start(10)
        else:
            self._progressbar.stop()
            self._progressbar.config(mode='determinate')
