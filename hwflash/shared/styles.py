"""
Modern UI styles, colors, and theme engine.

Provides a reactive theming system: widgets register themselves with
the ``ThemeEngine`` and are updated automatically on theme toggle.
"""

from __future__ import annotations

import weakref
from typing import Callable, Dict, List, Optional, Tuple


# ── Brand colors ────────────────────────────────────────────────
PRIMARY = "#3B82F6"
PRIMARY_HOVER = "#2563EB"
PRIMARY_LIGHT = "#60A5FA"
SECONDARY = "#06B6D4"
SECONDARY_HOVER = "#0891B2"
ACCENT = "#8B5CF6"
SUCCESS = "#22C55E"
SUCCESS_HOVER = "#16A34A"
WARNING = "#EAB308"
DANGER = "#EF4444"
DANGER_HOVER = "#DC2626"

# ── Dark theme — balanced, not too dark ─────────────────────────
DARK: Dict[str, str] = {
    "bg": "#171C28",
    "bg_secondary": "#202737",
    "bg_card": "#232B3D",
    "bg_input": "#2B3448",
    "bg_hover": "#34405A",
    "bg_selected": "#2D4F86",
    "fg": "#E8ECF4",
    "fg_secondary": "#B0B9CB",
    "fg_muted": "#7D8AA4",
    "border": "#3D4860",
    "border_light": "#55617D",
    "shadow": "#0D1017",
    "accent": PRIMARY,
    "accent_hover": PRIMARY_HOVER,
    "success": SUCCESS,
    "warning": WARNING,
    "danger": DANGER,
    "error": DANGER,
    "gradient_start": "#1E2D4A",
    "gradient_end": "#1A1F2E",
    "sidebar": "#131A26",
    "titlebar": "#131A26",
    "tab_active": PRIMARY,
    "tab_inactive": "#242A3B",
    "scrollbar": "#4A5570",
    "scrollbar_hover": "#5E6B85",
    "terminal_bg": "#141820",
    "terminal_fg": "#7DD3FC",
    # Aliases for convenience
    "surface": "#242A3B",
    "surface_alt": "#2E3548",
    "log_bg": "#1A1F2E",
    "log_fg": "#C8D0E0",
    "progress_bg": "#3A4358",
    "progress_fg": PRIMARY,
}

# ── Light theme — clean, not washed out ─────────────────────────
LIGHT: Dict[str, str] = {
    "bg": "#F0F2F7",
    "bg_secondary": "#E4E8F0",
    "bg_card": "#FFFFFF",
    "bg_input": "#FFFFFF",
    "bg_hover": "#D8DEE9",
    "bg_selected": "#C9DAFB",
    "fg": "#1A2035",
    "fg_secondary": "#3D4B65",
    "fg_muted": "#7A879E",
    "border": "#CBD3E1",
    "border_light": "#B4BFCF",
    "shadow": "#8893A6",
    "accent": PRIMARY,
    "accent_hover": PRIMARY_HOVER,
    "success": SUCCESS,
    "warning": WARNING,
    "danger": DANGER,
    "error": DANGER,
    "gradient_start": "#DDE5F5",
    "gradient_end": "#F0F2F7",
    "sidebar": "#FFFFFF",
    "titlebar": "#FFFFFF",
    "tab_active": PRIMARY,
    "tab_inactive": "#D8DEE9",
    "scrollbar": "#B4BFCF",
    "scrollbar_hover": "#8893A6",
    "terminal_bg": "#F5F6FA",
    "terminal_fg": "#1A2035",
    "surface": "#FFFFFF",
    "surface_alt": "#E4E8F0",
    "log_bg": "#FFFFFF",
    "log_fg": "#1A2035",
    "progress_bg": "#CBD3E1",
    "progress_fg": PRIMARY,
}

THEMES: Dict[str, Dict[str, str]] = {
    "dark": DARK,
    "light": LIGHT,
}

# ── ttkbootstrap theme names ───────────────────────────────────
TTKB_DARK = "darkly"
TTKB_LIGHT = "cosmo"

# ── Fonts ───────────────────────────────────────────────────────
FONT_FAMILY = "Segoe UI"
FONT_SIZES: Dict[str, int] = {
    "title": 18,
    "subtitle": 13,
    "body": 10,
    "small": 9,
    "tiny": 8,
    "mono": 10,
}

# ── Layout tokens (kept for sidebar / tests) ───────────────────
PADDING: Dict[str, int] = {"xs": 4, "sm": 8, "md": 10, "lg": 14, "xl": 20, "xxl": 28}
RADIUS: Dict[str, int] = {"sm": 4, "md": 8, "lg": 12, "xl": 16}
ANIMATION: Dict[str, int] = {
    "fade_duration": 300,
    "slide_duration": 200,
    "hover_duration": 150,
    "pulse_interval": 2000,
}

SHADOWS: Dict[str, Dict[str, str | int]] = {
    "sm": {"offset": 1, "blur": 2, "color_key": "shadow"},
    "md": {"offset": 2, "blur": 4, "color_key": "shadow"},
    "lg": {"offset": 4, "blur": 8, "color_key": "shadow"},
}

GRADIENTS: Dict[str, tuple[str, str]] = {
    "accent": ("accent", "secondary"),
    "surface": ("gradient_start", "gradient_end"),
    "status_ok": ("success", "accent"),
    "status_warn": ("warning", "accent"),
}

# ── Color utilities ─────────────────────────────────────────────

def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{max(0, min(255, r)):02x}{max(0, min(255, g)):02x}{max(0, min(255, b)):02x}"


def lighten(hex_color: str, amount: int = 30) -> str:
    """Return *hex_color* lightened by *amount* (0-255)."""
    r, g, b = _hex_to_rgb(hex_color)
    return _rgb_to_hex(r + amount, g + amount, b + amount)


def darken(hex_color: str, amount: int = 30) -> str:
    """Return *hex_color* darkened by *amount* (0-255)."""
    r, g, b = _hex_to_rgb(hex_color)
    return _rgb_to_hex(r - amount, g - amount, b - amount)


def blend(c1: str, c2: str, ratio: float = 0.5) -> str:
    """Blend two hex colors.  *ratio* 0 → *c1*, 1 → *c2*."""
    r1, g1, b1 = _hex_to_rgb(c1)
    r2, g2, b2 = _hex_to_rgb(c2)
    t = max(0.0, min(1.0, ratio))
    return _rgb_to_hex(
        int(r1 + (r2 - r1) * t),
        int(g1 + (g2 - g1) * t),
        int(b1 + (b2 - b1) * t),
    )


# ── Public helpers (backward compat) ───────────────────────────

def get_theme(name: str = "dark") -> Dict[str, str]:
    """Get theme colors by name."""
    return THEMES.get(name, DARK)


def get_gradient(theme: Dict[str, str]) -> Tuple[str, str]:
    """Get gradient start/end colors for the theme."""
    return theme["gradient_start"], theme["gradient_end"]


# ── Reactive Theme Engine ──────────────────────────────────────

class _WidgetBinding:
    """Stores a weak reference to a widget and its property mapping."""

    __slots__ = ("ref", "prop_map", "updater")

    def __init__(
        self,
        widget,
        prop_map: Optional[Dict[str, str]],
        updater: Optional[Callable],
    ):
        self.ref = weakref.ref(widget)
        self.prop_map = prop_map
        self.updater = updater


class ThemeEngine:
    """Reactive theme engine.

    Usage::

        engine = ThemeEngine()

        # Register a tk widget — keys are widget configure options,
        # values are theme-dict keys.
        engine.register(my_label, {"bg": "bg", "fg": "fg"})

        # Or register a callback that receives the colors dict:
        engine.register(my_sidebar, updater=my_sidebar.update_theme)

        # Toggle theme — all registered widgets update instantly.
        engine.toggle()
    """

    def __init__(self, initial: str = "dark") -> None:
        self._name: str = initial
        self._bindings: List[_WidgetBinding] = []

    # ── Properties ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Current theme name (``'dark'`` or ``'light'``)."""
        return self._name

    @property
    def colors(self) -> Dict[str, str]:
        """Current theme color dict."""
        return THEMES.get(self._name, DARK)

    @property
    def is_dark(self) -> bool:
        return self._name == "dark"

    @property
    def ttkb_theme(self) -> str:
        """The ttkbootstrap theme name matching the current mode."""
        return TTKB_DARK if self._name == "dark" else TTKB_LIGHT

    # ── Registration ─────────────────────────────────────────────

    def register(
        self,
        widget,
        prop_map: Optional[Dict[str, str]] = None,
        *,
        updater: Optional[Callable] = None,
    ) -> None:
        """Register *widget* for automatic theme updates.

        Parameters
        ----------
        widget:
            A tkinter widget or any object with a ``configure`` method.
        prop_map:
            Maps widget configure keys to theme-dict keys.
            Example: ``{"bg": "sidebar", "fg": "fg"}``
        updater:
            A callable ``fn(colors_dict)`` invoked instead of (or in
            addition to) ``prop_map`` application.  Useful for
            components that need custom update logic (Sidebar, Titlebar).
        """
        self._bindings.append(_WidgetBinding(widget, prop_map, updater))

    # ── Application ──────────────────────────────────────────────

    def apply(self) -> None:
        """Push current colors to every registered widget.

        Dead widget references are pruned automatically.
        """
        colors = self.colors
        alive: List[_WidgetBinding] = []
        for b in self._bindings:
            widget = b.ref()
            if widget is None:
                continue
            alive.append(b)
            try:
                if b.prop_map:
                    cfg = {k: colors[v] for k, v in b.prop_map.items() if v in colors}
                    if cfg:
                        widget.configure(**cfg)
                if b.updater:
                    b.updater(colors)
            except Exception:
                pass  # widget may have been destroyed between ref() and configure()
        self._bindings = alive

    def set_theme(self, name: str) -> None:
        """Switch to *name* (``'dark'`` / ``'light'``) and apply."""
        if name in THEMES:
            self._name = name
            self.apply()

    def toggle(self) -> None:
        """Toggle between dark and light themes and apply."""
        self._name = "light" if self._name == "dark" else "dark"
        self.apply()

    # ── Visual engine helpers ───────────────────────────────────

    def token(self, key: str, fallback: Optional[str] = None) -> Optional[str]:
        """Return a color token by key."""
        return self.colors.get(key, fallback)

    def shadow(self, level: str = "md") -> Dict[str, str | int]:
        """Return shadow token data for logical elevation levels."""
        data = SHADOWS.get(level, SHADOWS["md"]).copy()
        color_key = data.get("color_key", "shadow")
        data["color"] = self.colors.get(color_key, self.colors["shadow"])
        return data

    def gradient(self, name: str = "surface") -> Tuple[str, str]:
        """Resolve a semantic gradient name into actual colors."""
        start_key, end_key = GRADIENTS.get(name, GRADIENTS["surface"])
        return self.colors.get(start_key, self.colors["gradient_start"]), self.colors.get(
            end_key, self.colors["gradient_end"]
        )

    def attach_hover(self, widget, *, bg: str = "bg_card", hover: str = "bg_hover") -> None:
        """Attach a simple hover transition to supported tkinter widgets."""

        def _on_enter(_event):
            try:
                widget.configure(bg=self.colors.get(hover, self.colors["bg_hover"]))
            except Exception:
                pass

        def _on_leave(_event):
            try:
                widget.configure(bg=self.colors.get(bg, self.colors["bg_card"]))
            except Exception:
                pass

        try:
            widget.bind("<Enter>", _on_enter, add="+")
            widget.bind("<Leave>", _on_leave, add="+")
        except Exception:
            pass
