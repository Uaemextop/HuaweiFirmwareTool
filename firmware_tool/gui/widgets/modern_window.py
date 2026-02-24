"""Modern custom window frame with title bar."""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable


class ModernWindow(tk.Tk):
    """
    Custom window with modern title bar.

    Features:
    - Custom title bar with minimize/maximize/close buttons
    - Draggable window
    - Modern styling
    - Optional window controls
    """

    def __init__(self, title: str = "", geometry: str = "900x720"):
        """
        Initialize modern window.

        Args:
            title: Window title
            geometry: Window geometry (e.g., "900x720")
        """
        super().__init__()

        # Window configuration
        self.title(title)
        self.geometry(geometry)

        # Remove default title bar
        self.overrideredirect(True)

        # State variables
        self._dragging = False
        self._offset_x = 0
        self._offset_y = 0
        self._maximized = False
        self._normal_geometry = geometry

        # Background color
        self.configure(bg="#0D1B2A")

        # Build custom window frame
        self._build_frame()

    def _build_frame(self):
        """Build the custom window frame."""
        # Main container
        self.container = tk.Frame(self, bg="#0D1B2A", highlightthickness=1,
                                 highlightbackground="#2C4A6B", highlightcolor="#2C4A6B")
        self.container.pack(fill=tk.BOTH, expand=True)

        # Title bar
        self.title_bar = tk.Frame(self.container, bg="#1E3A5F", height=40)
        self.title_bar.pack(side=tk.TOP, fill=tk.X)
        self.title_bar.pack_propagate(False)

        # Title bar content
        self._build_title_bar()

        # Content area
        self.content_frame = tk.Frame(self.container, bg="#0D1B2A")
        self.content_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def _build_title_bar(self):
        """Build title bar with controls."""
        # Window icon / logo placeholder
        self.icon_label = tk.Label(
            self.title_bar, text="⚙",
            font=("Segoe UI", 14),
            fg="#60CDFF", bg="#1E3A5F"
        )
        self.icon_label.pack(side=tk.LEFT, padx=(10, 5))

        # Window title
        self.title_label = tk.Label(
            self.title_bar, text=self.title(),
            font=("Segoe UI", 10, "bold"),
            fg="#FFFFFF", bg="#1E3A5F"
        )
        self.title_label.pack(side=tk.LEFT, padx=5)

        # Make title bar draggable
        self.title_bar.bind('<Button-1>', self._start_drag)
        self.title_bar.bind('<B1-Motion>', self._on_drag)
        self.title_bar.bind('<ButtonRelease-1>', self._stop_drag)
        self.title_label.bind('<Button-1>', self._start_drag)
        self.title_label.bind('<B1-Motion>', self._on_drag)
        self.icon_label.bind('<Button-1>', self._start_drag)
        self.icon_label.bind('<B1-Motion>', self._on_drag)

        # Double-click to maximize/restore
        self.title_bar.bind('<Double-Button-1>', lambda e: self._toggle_maximize())
        self.title_label.bind('<Double-Button-1>', lambda e: self._toggle_maximize())

        # Window control buttons
        self._build_window_controls()

    def _build_window_controls(self):
        """Build minimize/maximize/close buttons."""
        # Close button
        self.close_btn = tk.Button(
            self.title_bar, text="✕",
            font=("Segoe UI", 12, "bold"),
            fg="#FFFFFF", bg="#1E3A5F",
            activebackground="#E81123", activeforeground="#FFFFFF",
            relief=tk.FLAT, bd=0, padx=15, pady=0,
            command=self._on_close,
            cursor="hand2"
        )
        self.close_btn.pack(side=tk.RIGHT)
        self.close_btn.bind('<Enter>', lambda e: self.close_btn.config(bg="#E81123"))
        self.close_btn.bind('<Leave>', lambda e: self.close_btn.config(bg="#1E3A5F"))

        # Maximize button
        self.maximize_btn = tk.Button(
            self.title_bar, text="□",
            font=("Segoe UI", 12),
            fg="#FFFFFF", bg="#1E3A5F",
            activebackground="#2C4A6B", activeforeground="#FFFFFF",
            relief=tk.FLAT, bd=0, padx=15, pady=0,
            command=self._toggle_maximize,
            cursor="hand2"
        )
        self.maximize_btn.pack(side=tk.RIGHT)
        self.maximize_btn.bind('<Enter>', lambda e: self.maximize_btn.config(bg="#2C4A6B"))
        self.maximize_btn.bind('<Leave>', lambda e: self.maximize_btn.config(bg="#1E3A5F"))

        # Minimize button
        self.minimize_btn = tk.Button(
            self.title_bar, text="─",
            font=("Segoe UI", 12),
            fg="#FFFFFF", bg="#1E3A5F",
            activebackground="#2C4A6B", activeforeground="#FFFFFF",
            relief=tk.FLAT, bd=0, padx=15, pady=0,
            command=self._minimize,
            cursor="hand2"
        )
        self.minimize_btn.pack(side=tk.RIGHT)
        self.minimize_btn.bind('<Enter>', lambda e: self.minimize_btn.config(bg="#2C4A6B"))
        self.minimize_btn.bind('<Leave>', lambda e: self.minimize_btn.config(bg="#1E3A5F"))

    def _start_drag(self, event):
        """Start window drag."""
        if not self._maximized:
            self._dragging = True
            self._offset_x = event.x_root - self.winfo_x()
            self._offset_y = event.y_root - self.winfo_y()

    def _on_drag(self, event):
        """Handle window drag."""
        if self._dragging and not self._maximized:
            x = event.x_root - self._offset_x
            y = event.y_root - self._offset_y
            self.geometry(f'+{x}+{y}')

    def _stop_drag(self, event):
        """Stop window drag."""
        self._dragging = False

    def _minimize(self):
        """Minimize window."""
        self.iconify()

    def _toggle_maximize(self):
        """Toggle maximize/restore window."""
        if self._maximized:
            # Restore
            self.geometry(self._normal_geometry)
            self.maximize_btn.config(text="□")
            self._maximized = False
        else:
            # Maximize
            self._normal_geometry = self.geometry()
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            self.geometry(f"{screen_w}x{screen_h}+0+0")
            self.maximize_btn.config(text="❐")
            self._maximized = True

    def _on_close(self):
        """Handle window close."""
        # This can be overridden by subclasses
        self.destroy()

    def set_title(self, title: str):
        """
        Set window title.

        Args:
            title: New title text
        """
        self.title(title)
        self.title_label.config(text=title)

    def get_content_frame(self) -> tk.Frame:
        """
        Get content frame for adding widgets.

        Returns:
            Content frame widget
        """
        return self.content_frame

    def add_title_bar_widget(self, widget: tk.Widget, side: str = tk.RIGHT, **pack_kwargs):
        """
        Add custom widget to title bar.

        Args:
            widget: Widget to add
            side: Pack side (tk.LEFT or tk.RIGHT)
            **pack_kwargs: Additional pack options
        """
        widget.pack(side=side, **pack_kwargs)


class ModernToplevel(tk.Toplevel):
    """
    Custom toplevel window with modern title bar.

    Similar to ModernWindow but as a Toplevel widget.
    """

    def __init__(self, parent, title: str = "", geometry: str = "600x400"):
        """
        Initialize modern toplevel window.

        Args:
            parent: Parent window
            title: Window title
            geometry: Window geometry
        """
        super().__init__(parent)

        # Window configuration
        self.title(title)
        self.geometry(geometry)

        # Remove default title bar
        self.overrideredirect(True)

        # State variables
        self._dragging = False
        self._offset_x = 0
        self._offset_y = 0

        # Background color
        self.configure(bg="#0D1B2A")

        # Build custom window frame
        self._build_frame()

    def _build_frame(self):
        """Build the custom window frame."""
        # Main container
        self.container = tk.Frame(self, bg="#0D1B2A", highlightthickness=1,
                                 highlightbackground="#2C4A6B", highlightcolor="#2C4A6B")
        self.container.pack(fill=tk.BOTH, expand=True)

        # Title bar
        self.title_bar = tk.Frame(self.container, bg="#1E3A5F", height=35)
        self.title_bar.pack(side=tk.TOP, fill=tk.X)
        self.title_bar.pack_propagate(False)

        # Title bar content
        self._build_title_bar()

        # Content area
        self.content_frame = tk.Frame(self.container, bg="#0D1B2A")
        self.content_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def _build_title_bar(self):
        """Build title bar with controls."""
        # Window title
        self.title_label = tk.Label(
            self.title_bar, text=self.title(),
            font=("Segoe UI", 9, "bold"),
            fg="#FFFFFF", bg="#1E3A5F"
        )
        self.title_label.pack(side=tk.LEFT, padx=10)

        # Make title bar draggable
        self.title_bar.bind('<Button-1>', self._start_drag)
        self.title_bar.bind('<B1-Motion>', self._on_drag)
        self.title_bar.bind('<ButtonRelease-1>', self._stop_drag)
        self.title_label.bind('<Button-1>', self._start_drag)
        self.title_label.bind('<B1-Motion>', self._on_drag)

        # Close button
        self.close_btn = tk.Button(
            self.title_bar, text="✕",
            font=("Segoe UI", 11, "bold"),
            fg="#FFFFFF", bg="#1E3A5F",
            activebackground="#E81123", activeforeground="#FFFFFF",
            relief=tk.FLAT, bd=0, padx=12, pady=0,
            command=self.destroy,
            cursor="hand2"
        )
        self.close_btn.pack(side=tk.RIGHT)
        self.close_btn.bind('<Enter>', lambda e: self.close_btn.config(bg="#E81123"))
        self.close_btn.bind('<Leave>', lambda e: self.close_btn.config(bg="#1E3A5F"))

    def _start_drag(self, event):
        """Start window drag."""
        self._dragging = True
        self._offset_x = event.x_root - self.winfo_x()
        self._offset_y = event.y_root - self.winfo_y()

    def _on_drag(self, event):
        """Handle window drag."""
        if self._dragging:
            x = event.x_root - self._offset_x
            y = event.y_root - self._offset_y
            self.geometry(f'+{x}+{y}')

    def _stop_drag(self, event):
        """Stop window drag."""
        self._dragging = False

    def get_content_frame(self) -> tk.Frame:
        """
        Get content frame for adding widgets.

        Returns:
            Content frame widget
        """
        return self.content_frame
