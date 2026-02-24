"""
Modern sidebar navigation component.

Replaces notebook tabs with a sleek vertical navigation panel
featuring icons, hover effects, and active state indicators.
"""

import tkinter as tk
from typing import List, Callable, Optional, Dict

from hwflash.shared.styles import PADDING, FONT_FAMILY


class SidebarNav(tk.Frame):
    """Vertical sidebar navigation with animated selection."""

    def __init__(self, parent, theme: dict, on_select: Optional[Callable] = None, **kwargs):
        super().__init__(parent, bg=theme["sidebar"], width=200, **kwargs)
        self._theme = theme
        self._on_select = on_select
        self._items: List[Dict] = []
        self._buttons: List[tk.Frame] = []
        self._active_index = 0

        self.pack_propagate(False)

        # Header area
        self._header = tk.Frame(self, bg=theme["sidebar"])
        self._header.pack(fill=tk.X, padx=8, pady=(16, 8))

        # Navigation items container
        self._nav_frame = tk.Frame(self, bg=theme["sidebar"])
        self._nav_frame.pack(fill=tk.BOTH, expand=True, padx=8)

        # Bottom section
        self._footer = tk.Frame(self, bg=theme["sidebar"])
        self._footer.pack(fill=tk.X, padx=8, pady=8)

    def set_header(self, widget_func: Callable):
        """Set header content using a builder function."""
        widget_func(self._header)

    def set_footer(self, widget_func: Callable):
        """Set footer content using a builder function."""
        widget_func(self._footer)

    def add_item(self, text: str, icon: str = "●", tag: str = ""):
        """Add a navigation item."""
        index = len(self._items)
        item = {"text": text, "icon": icon, "tag": tag or text.lower()}
        self._items.append(item)

        btn_frame = tk.Frame(
            self._nav_frame,
            bg=self._theme["sidebar"],
            cursor="hand2",
            pady=2,
        )
        btn_frame.pack(fill=tk.X, pady=1)

        # Active indicator bar
        indicator = tk.Frame(btn_frame, bg=self._theme["sidebar"], width=3)
        indicator.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))

        # Icon
        icon_label = tk.Label(
            btn_frame,
            text=icon,
            font=(FONT_FAMILY, 12),
            bg=self._theme["sidebar"],
            fg=self._theme["fg_muted"],
            width=2,
        )
        icon_label.pack(side=tk.LEFT, padx=(4, 4))

        # Text
        text_label = tk.Label(
            btn_frame,
            text=text,
            font=(FONT_FAMILY, 10),
            bg=self._theme["sidebar"],
            fg=self._theme["fg_secondary"],
            anchor="w",
        )
        text_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self._buttons.append({
            "frame": btn_frame,
            "indicator": indicator,
            "icon": icon_label,
            "text": text_label,
        })

        # Bind click events
        for widget in [btn_frame, icon_label, text_label]:
            widget.bind("<Button-1>", lambda e, i=index: self.select(i))
            widget.bind("<Enter>", lambda e, i=index: self._on_hover(i, True))
            widget.bind("<Leave>", lambda e, i=index: self._on_hover(i, False))

    def add_separator(self):
        """Add a visual separator."""
        sep = tk.Frame(self._nav_frame, bg=self._theme["border"], height=1)
        sep.pack(fill=tk.X, pady=8)

    def add_section_label(self, text: str):
        """Add a section label."""
        label = tk.Label(
            self._nav_frame,
            text=text.upper(),
            font=(FONT_FAMILY, 8, "bold"),
            bg=self._theme["sidebar"],
            fg=self._theme["fg_muted"],
            anchor="w",
        )
        label.pack(fill=tk.X, pady=(12, 4), padx=8)

    def select(self, index: int):
        """Select a navigation item."""
        if 0 <= index < len(self._buttons):
            self._active_index = index
            self._update_styles()
            if self._on_select:
                self._on_select(index, self._items[index]["tag"])

    def _on_hover(self, index: int, entering: bool):
        """Handle hover effect."""
        if index == self._active_index:
            return
        btn = self._buttons[index]
        if entering:
            bg = self._theme["bg_hover"]
        else:
            bg = self._theme["sidebar"]
        btn["frame"].configure(bg=bg)
        btn["icon"].configure(bg=bg)
        btn["text"].configure(bg=bg)

    def _update_styles(self):
        """Update all button styles based on active state."""
        for i, btn in enumerate(self._buttons):
            is_active = i == self._active_index
            if is_active:
                bg = self._theme["bg_selected"]
                fg = self._theme["fg"]
                ind_color = self._theme["accent"]
            else:
                bg = self._theme["sidebar"]
                fg = self._theme["fg_secondary"]
                ind_color = self._theme["sidebar"]

            btn["frame"].configure(bg=bg)
            btn["indicator"].configure(bg=ind_color)
            btn["icon"].configure(bg=bg, fg=fg if is_active else self._theme["fg_muted"])
            btn["text"].configure(bg=bg, fg=fg)

    def update_theme(self, theme: dict):
        """Update sidebar theme."""
        self._theme = theme
        self.configure(bg=theme["sidebar"])
        self._header.configure(bg=theme["sidebar"])
        self._nav_frame.configure(bg=theme["sidebar"])
        self._footer.configure(bg=theme["sidebar"])
        self._update_styles()
