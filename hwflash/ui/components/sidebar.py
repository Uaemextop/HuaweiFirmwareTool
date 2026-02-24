"""
Modern sidebar navigation component.

Replaces notebook tabs with a sleek vertical navigation panel
featuring icons, hover effects, and active state indicators.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Dict, List, Optional, TYPE_CHECKING

from hwflash.shared.styles import FONT_FAMILY

if TYPE_CHECKING:
    from hwflash.shared.styles import ThemeEngine


class SidebarNav(tk.Frame):
    """Vertical sidebar navigation with animated selection."""

    def __init__(self, parent, theme: dict, on_select: Optional[Callable] = None,
                 engine: Optional[ThemeEngine] = None, **kwargs):
        super().__init__(parent, bg=theme["sidebar"], width=220, **kwargs)
        self._theme = theme
        self._on_select = on_select
        self._items: List[Dict] = []
        self._buttons: List[Dict] = []
        self._active_index = 0
        self._separators: List[tk.Frame] = []
        self._section_labels: List[tk.Label] = []

        self.pack_propagate(False)

        # Header area
        self._header = tk.Frame(self, bg=theme["sidebar"])
        self._header.pack(fill=tk.X, padx=10, pady=(18, 10))

        # Navigation items container
        self._nav_frame = tk.Frame(self, bg=theme["sidebar"])
        self._nav_frame.pack(fill=tk.BOTH, expand=True, padx=10)

        # Bottom section
        self._footer = tk.Frame(self, bg=theme["sidebar"])
        self._footer.pack(fill=tk.X, padx=10, pady=10)

        # Register with ThemeEngine
        if engine:
            engine.register(self, updater=self.update_theme)

    def set_header(self, widget_func: Callable):
        """Set header content using a builder function."""
        widget_func(self._header)

    def set_footer(self, widget_func: Callable):
        """Set footer content using a builder function."""
        widget_func(self._footer)

    def add_item(self, text: str, icon: str = "•", tag: str = ""):
        """Add a navigation item."""
        index = len(self._items)
        item = {"text": text, "icon": icon, "tag": tag or text.lower()}
        self._items.append(item)

        btn_frame = tk.Frame(
            self._nav_frame,
            bg=self._theme["sidebar"],
            cursor="hand2",
            pady=3,
        )
        btn_frame.pack(fill=tk.X, pady=1)

        # Active indicator bar
        indicator = tk.Frame(btn_frame, bg=self._theme["sidebar"], width=3)
        indicator.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))

        # Icon
        icon_label = tk.Label(
            btn_frame,
            text=icon,
            font=(FONT_FAMILY, 11),
            bg=self._theme["sidebar"],
            fg=self._theme["fg_muted"],
            width=2,
        )
        icon_label.pack(side=tk.LEFT, padx=(4, 4))

        # Text
        text_label = tk.Label(
            btn_frame,
            text=text,
            font=(FONT_FAMILY, 10, "bold"),
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
        self._separators.append(sep)

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
        label.pack(fill=tk.X, pady=(14, 4), padx=8)
        self._section_labels.append(label)

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
        """Update sidebar theme — called by ThemeEngine."""
        self._theme = theme
        self.configure(bg=theme["sidebar"])
        self._header.configure(bg=theme["sidebar"])
        self._nav_frame.configure(bg=theme["sidebar"])
        self._footer.configure(bg=theme["sidebar"])

        # Update section labels and separators
        for lbl in self._section_labels:
            lbl.configure(bg=theme["sidebar"], fg=theme["fg_muted"])
        for sep in self._separators:
            sep.configure(bg=theme["border"])

        # Update header children
        for child in self._header.winfo_children():
            try:
                child.configure(bg=theme["sidebar"])
                for sub in child.winfo_children():
                    try:
                        sub.configure(bg=theme["sidebar"])
                        # Update fg for labels
                        if isinstance(sub, tk.Label):
                            # Title labels get fg, version labels get fg_muted
                            current_font = sub.cget("font")
                            if "bold" in str(current_font):
                                sub.configure(fg=theme["fg"])
                            else:
                                sub.configure(fg=theme["fg_muted"])
                    except (tk.TclError, Exception):
                        pass
            except (tk.TclError, Exception):
                pass

        # Update footer children (theme button etc.)
        for child in self._footer.winfo_children():
            try:
                if isinstance(child, tk.Button):
                    child.configure(
                        bg=theme["bg_card"],
                        fg=theme["fg_secondary"],
                        activebackground=theme["bg_hover"],
                        activeforeground=theme["fg"],
                    )
            except (tk.TclError, Exception):
                pass

        self._update_styles()
