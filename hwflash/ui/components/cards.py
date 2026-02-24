"""
Reusable card widget with shadow, rounded corners, and hover effects.

Used throughout the app for grouping related controls.
"""

import tkinter as tk
from typing import Optional


class CardFrame(tk.Frame):
    """A modern card-style container with shadow and rounded appearance."""

    def __init__(
        self,
        parent,
        theme: dict,
        title: str = "",
        padding: int = 16,
        **kwargs,
    ):
        self._theme = theme
        super().__init__(
            parent,
            bg=theme["bg_card"],
            highlightbackground=theme["border"],
            highlightthickness=1,
            padx=padding,
            pady=padding,
            **kwargs,
        )

        if title:
            title_label = tk.Label(
                self,
                text=title,
                font=("Segoe UI", 12, "bold"),
                bg=theme["bg_card"],
                fg=theme["fg"],
                anchor="w",
            )
            title_label.pack(fill=tk.X, pady=(0, 8))
            sep = tk.Frame(self, bg=theme["border"], height=1)
            sep.pack(fill=tk.X, pady=(0, 8))

    def update_theme(self, theme: dict):
        """Update card colors when theme changes."""
        self._theme = theme
        self.configure(bg=theme["bg_card"], highlightbackground=theme["border"])


class StatusBadge(tk.Label):
    """Small colored status indicator badge."""

    STATUS_COLORS = {
        "success": "#22C55E",
        "warning": "#EAB308",
        "danger": "#EF4444",
        "info": "#3B82F6",
        "neutral": "#6B7A94",
    }

    def __init__(self, parent, status: str = "neutral", text: str = "", **kwargs):
        color = self.STATUS_COLORS.get(status, self.STATUS_COLORS["neutral"])
        super().__init__(
            parent,
            text=f" ● {text} " if text else " ● ",
            fg=color,
            font=("Segoe UI", 9),
            **kwargs,
        )

    def set_status(self, status: str, text: str = ""):
        color = self.STATUS_COLORS.get(status, self.STATUS_COLORS["neutral"])
        self.configure(fg=color, text=f" ● {text} " if text else " ● ")


class GradientBar(tk.Canvas):
    """A horizontal gradient bar widget."""

    def __init__(self, parent, height: int = 3, color_start: str = "#2563EB",
                 color_end: str = "#06B6D4", **kwargs):
        super().__init__(parent, height=height, highlightthickness=0, **kwargs)
        self._color_start = color_start
        self._color_end = color_end
        self.bind("<Configure>", self._draw_gradient)

    def _draw_gradient(self, event=None):
        self.delete("gradient")
        width = self.winfo_width()
        height = self.winfo_height()
        if width <= 0:
            return

        r1, g1, b1 = self._hex_to_rgb(self._color_start)
        r2, g2, b2 = self._hex_to_rgb(self._color_end)

        steps = max(1, width)
        for i in range(steps):
            ratio = i / steps
            r = int(r1 + (r2 - r1) * ratio)
            g = int(g1 + (g2 - g1) * ratio)
            b = int(b1 + (b2 - b1) * ratio)
            color = f"#{r:02x}{g:02x}{b:02x}"
            self.create_line(i, 0, i, height, fill=color, tags="gradient")

    @staticmethod
    def _hex_to_rgb(hex_color: str):
        hex_color = hex_color.lstrip("#")
        return tuple(int(hex_color[i: i + 2], 16) for i in (0, 2, 4))


class AnimatedProgress(tk.Canvas):
    """Smooth animated progress bar with gradient fill."""

    def __init__(self, parent, height: int = 6, color: str = "#2563EB",
                 bg_color: str = "#334155", **kwargs):
        super().__init__(parent, height=height, highlightthickness=0, bg=bg_color, **kwargs)
        self._progress = 0.0
        self._target = 0.0
        self._color = color
        self._bg_color = bg_color
        self._animating = False
        self.bind("<Configure>", self._redraw)

    def set_progress(self, value: float):
        """Set progress (0.0 to 1.0) with smooth animation."""
        self._target = max(0.0, min(1.0, value))
        if not self._animating:
            self._animate()

    def _animate(self):
        diff = self._target - self._progress
        if abs(diff) < 0.005:
            self._progress = self._target
            self._redraw()
            self._animating = False
            return

        self._animating = True
        self._progress += diff * 0.15
        self._redraw()
        self.after(16, self._animate)

    def _redraw(self, event=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= 0:
            return

        # Background
        self.create_rectangle(0, 0, w, h, fill=self._bg_color, outline="")

        # Progress fill
        fill_w = int(w * self._progress)
        if fill_w > 0:
            self.create_rectangle(0, 0, fill_w, h, fill=self._color, outline="")
            # Highlight
            self.create_rectangle(0, 0, fill_w, h // 3, fill=self._lighten(self._color, 30), outline="")

    @staticmethod
    def _lighten(hex_color: str, amount: int) -> str:
        hex_color = hex_color.lstrip("#")
        r, g, b = (int(hex_color[i: i + 2], 16) for i in (0, 2, 4))
        r = min(255, r + amount)
        g = min(255, g + amount)
        b = min(255, b + amount)
        return f"#{r:02x}{g:02x}{b:02x}"
