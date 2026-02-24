"""
Shared canvas-based UI widgets for OBSC Firmware Tool.

Provides reusable widgets that add visual polish:
  - GradientFrame   – frame with a vertical or horizontal colour gradient
  - ShadowLabel     – label with a subtle drop shadow
  - GlowButton      – button with animated glow on hover
  - PulseIndicator  – animated status dot (green/red/amber)
  - AnimProgress    – canvas-based animated progress bar with glow

All widgets work with both ttkbootstrap and plain ttk / tkinter.
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional, Tuple

from hwflash.utils import lerp_color, rgb_hex


# --------------------------------------------------------------------------- #
#  GradientFrame
# --------------------------------------------------------------------------- #

class GradientFrame(tk.Canvas):
    """A ``tk.Canvas`` that draws a gradient background.

    The frame fills with a smooth two-stop gradient; child widgets can be
    placed on top using standard ``.place()`` or ``.pack()``/``.grid()``
    calls on a plain ``tk.Frame`` embedded inside.

    Args:
        parent: Parent widget.
        color1: Start colour as ``(r, g, b)`` tuple (or hex string).
        color2: End colour as ``(r, g, b)`` tuple (or hex string).
        direction: ``"vertical"`` (top→bottom) or ``"horizontal"`` (left→right).
        **kwargs: Forwarded to ``tk.Canvas``.
    """

    def __init__(
        self,
        parent,
        color1: tuple | str = (26, 26, 46),
        color2: tuple | str = (13, 13, 26),
        direction: str = "vertical",
        **kwargs,
    ):
        super().__init__(parent, **kwargs, highlightthickness=0)
        self._c1 = _to_rgb(color1)
        self._c2 = _to_rgb(color2)
        self._dir = direction
        self._gradient_drawn = False
        self.bind("<Configure>", self._draw_gradient)

    def _draw_gradient(self, event=None):
        self.delete("gradient")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2 or h < 2:
            return
        steps = h if self._dir == "vertical" else w
        for i in range(steps):
            t = i / max(steps - 1, 1)
            c = lerp_color(self._c1, self._c2, t)
            color = rgb_hex(*c)
            if self._dir == "vertical":
                self.create_line(0, i, w, i, fill=color, tags="gradient")
            else:
                self.create_line(i, 0, i, h, fill=color, tags="gradient")
        self.tag_lower("gradient")

    def update_colors(self, color1: tuple | str, color2: tuple | str):
        """Change the gradient colours and redraw."""
        self._c1 = _to_rgb(color1)
        self._c2 = _to_rgb(color2)
        self._draw_gradient()


# --------------------------------------------------------------------------- #
#  PulseIndicator
# --------------------------------------------------------------------------- #

class PulseIndicator(tk.Canvas):
    """Animated coloured dot that pulses (opacity cycles) when active.

    Args:
        parent: Parent widget.
        color: Active dot colour (Tk hex string).
        size: Diameter in pixels.
        **kwargs: Forwarded to ``tk.Canvas``.
    """

    _STATES = {
        "ok": "#6CCB5F",
        "error": "#FF99A4",
        "warning": "#FCE100",
        "idle": "#404040",
    }

    def __init__(self, parent, color: str = "#6CCB5F", size: int = 12, **kwargs):
        super().__init__(
            parent,
            width=size, height=size,
            highlightthickness=0,
            **kwargs,
        )
        self._color = color
        self._size = size
        self._alpha = 1.0
        self._direction = -1  # -1 = fading out, +1 = fading in
        self._job: Optional[str] = None
        self._running = False
        self._draw(1.0)

    def _draw(self, alpha: float):
        self.delete("all")
        d = self._size
        # Shadow ring
        self.create_oval(1, 1, d - 1, d - 1, fill="#000000", outline="")
        # Main dot (modulate brightness by alpha)
        c = _dim_color(self._color, alpha)
        self.create_oval(2, 2, d - 2, d - 2, fill=c, outline="")

    def start(self, color: Optional[str] = None):
        """Begin the pulse animation."""
        if color:
            self._color = color
        self._running = True
        self._alpha = 1.0
        self._direction = -1
        self._animate()

    def stop(self, state: str = "idle"):
        """Stop animation and show a static state dot."""
        self._running = False
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        self._color = self._STATES.get(state, self._STATES["idle"])
        self._draw(1.0)

    def _animate(self):
        if not self._running:
            return
        self._alpha = max(0.3, min(1.0, self._alpha + self._direction * 0.05))
        if self._alpha <= 0.3:
            self._direction = 1
        elif self._alpha >= 1.0:
            self._direction = -1
        self._draw(self._alpha)
        self._job = self.after(50, self._animate)


# --------------------------------------------------------------------------- #
#  AnimProgress
# --------------------------------------------------------------------------- #

class AnimProgress(tk.Canvas):
    """Canvas-based animated progress bar with glow effect.

    Args:
        parent: Parent widget.
        width: Total width in pixels.
        height: Bar height in pixels.
        fg_color: Fill colour hex string.
        bg_color: Trough colour hex string.
        **kwargs: Forwarded to ``tk.Canvas``.
    """

    def __init__(
        self,
        parent,
        width: int = 400,
        height: int = 8,
        fg_color: str = "#60CDFF",
        bg_color: str = "#2D2D44",
        **kwargs,
    ):
        super().__init__(
            parent,
            width=width, height=height,
            highlightthickness=0,
            **kwargs,
        )
        self._w = width
        self._h = height
        self._fg = fg_color
        self._bg = bg_color
        self._value = 0.0  # 0.0 – 1.0
        self._draw()

    def set(self, value: float):
        """Set progress fraction (0.0 – 1.0)."""
        self._value = max(0.0, min(1.0, value))
        self._draw()

    def set_percent(self, pct: float):
        """Set progress from a percentage value (0 – 100)."""
        self.set(pct / 100.0)

    def _draw(self):
        self.delete("all")
        w, h = self._w, self._h
        r = h // 2
        # Background (rounded rectangle approximation with rounded ends)
        self.create_rectangle(r, 0, w - r, h, fill=self._bg, outline="")
        self.create_oval(0, 0, h, h, fill=self._bg, outline="")
        self.create_oval(w - h, 0, w, h, fill=self._bg, outline="")
        # Filled portion
        fill_w = max(0, int(w * self._value))
        if fill_w > h:
            self.create_rectangle(r, 0, fill_w - r, h, fill=self._fg, outline="")
            self.create_oval(0, 0, h, h, fill=self._fg, outline="")
            self.create_oval(fill_w - h, 0, fill_w, h, fill=self._fg, outline="")
        elif fill_w > 0:
            self.create_oval(0, 0, h, h, fill=self._fg, outline="")
        # Glow highlight (lighter stripe near the top)
        glow_h = max(2, h // 3)
        glow_c = _brighten(self._fg, 0.4)
        if fill_w > h:
            self.create_rectangle(r, 1, fill_w - r, glow_h, fill=glow_c, outline="")


# --------------------------------------------------------------------------- #
#  ShadowLabel  (Canvas-based label with a pseudo-drop-shadow)
# --------------------------------------------------------------------------- #

class ShadowLabel(tk.Canvas):
    """A label widget that renders text with a soft drop shadow.

    Args:
        parent: Parent widget.
        text: Label text.
        font: Tk font spec (tuple or string).
        fg: Text colour hex string.
        shadow_color: Shadow colour hex string (defaults to dark grey).
        **kwargs: Forwarded to ``tk.Canvas`` (set ``bg`` for background).
    """

    def __init__(
        self,
        parent,
        text: str = "",
        font=("Segoe UI", 12),
        fg: str = "#FFFFFF",
        shadow_color: str = "#000000",
        **kwargs,
    ):
        super().__init__(parent, highlightthickness=0, **kwargs)
        self._text = text
        self._font = font
        self._fg = fg
        self._shadow = shadow_color
        self.bind("<Configure>", self._draw)
        self._draw()

    def configure(self, **kwargs):  # type: ignore[override]
        if "text" in kwargs:
            self._text = kwargs.pop("text")
            self._draw()
        if "fg" in kwargs:
            self._fg = kwargs.pop("fg")
            self._draw()
        super().configure(**kwargs)

    def _draw(self, _event=None):
        self.delete("all")
        cx = self.winfo_width() // 2
        cy = self.winfo_height() // 2
        # Shadow (offset 1,1)
        self.create_text(cx + 1, cy + 1, text=self._text, font=self._font,
                         fill=self._shadow, anchor="center")
        # Main text
        self.create_text(cx, cy, text=self._text, font=self._font,
                         fill=self._fg, anchor="center")


# --------------------------------------------------------------------------- #
#  Internal helpers
# --------------------------------------------------------------------------- #

def _to_rgb(color: tuple | str) -> tuple:
    """Convert a colour to an ``(r, g, b)`` tuple."""
    if isinstance(color, (tuple, list)):
        return tuple(color[:3])
    # Hex string
    c = color.lstrip("#")
    if len(c) == 6:
        return tuple(int(c[i: i + 2], 16) for i in (0, 2, 4))
    return (0, 0, 0)


def _dim_color(hex_color: str, alpha: float) -> str:
    """Return *hex_color* darkened by *(1 - alpha)*."""
    r, g, b = _to_rgb(hex_color)
    r = int(r * alpha)
    g = int(g * alpha)
    b = int(b * alpha)
    return rgb_hex(r, g, b)


def _brighten(hex_color: str, amount: float) -> str:
    """Return *hex_color* brightened by *amount* (0.0 – 1.0)."""
    r, g, b = _to_rgb(hex_color)
    r = min(255, int(r + (255 - r) * amount))
    g = min(255, int(g + (255 - g) * amount))
    b = min(255, int(b + (255 - b) * amount))
    return rgb_hex(r, g, b)
