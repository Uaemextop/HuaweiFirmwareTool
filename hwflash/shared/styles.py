"""
Modern UI styles, colors, and theme configuration.

Provides a centralized theming system with dark/light modes,
balanced contrast, and consistent component styling.
"""

from typing import Dict, Tuple


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
DARK = {
    "bg": "#1A1F2E",
    "bg_secondary": "#242A3B",
    "bg_card": "#242A3B",
    "bg_input": "#2E3548",
    "bg_hover": "#353D52",
    "bg_selected": "#2E4A7A",
    "fg": "#E8ECF4",
    "fg_secondary": "#A0AABE",
    "fg_muted": "#6B7A94",
    "border": "#3A4358",
    "border_light": "#4A5570",
    "shadow": "#0D1017",
    "accent": PRIMARY,
    "accent_hover": PRIMARY_HOVER,
    "success": SUCCESS,
    "warning": WARNING,
    "danger": DANGER,
    "error": DANGER,
    "gradient_start": "#1E2D4A",
    "gradient_end": "#1A1F2E",
    "sidebar": "#161B28",
    "titlebar": "#161B28",
    "tab_active": PRIMARY,
    "tab_inactive": "#242A3B",
    "scrollbar": "#4A5570",
    "scrollbar_hover": "#5E6B85",
    "terminal_bg": "#141820",
    "terminal_fg": "#7DD3FC",
    # Aliases used by theme styling
    "surface": "#242A3B",
    "surface_alt": "#2E3548",
    "log_bg": "#1A1F2E",
    "log_fg": "#C8D0E0",
    "progress_bg": "#3A4358",
    "progress_fg": PRIMARY,
}

# ── Light theme — clean, not washed out ─────────────────────────
LIGHT = {
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
    # Aliases used by theme styling
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

OBSC_MULTICAST_ADDR = "224.0.0.9"
DEVICE_STALE_TIMEOUT = 30
TTKB_DARK = "darkly"
TTKB_LIGHT = "cosmo"

FONT_FAMILY = "Segoe UI"
FONT_SIZES = {
    "title": 20,
    "subtitle": 14,
    "body": 11,
    "small": 9,
    "tiny": 8,
    "mono": 10,
}

ANIMATION = {
    "fade_duration": 300,
    "slide_duration": 200,
    "hover_duration": 150,
    "pulse_interval": 2000,
}

PADDING = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 24,
    "xxl": 32,
}

RADIUS = {
    "sm": 4,
    "md": 8,
    "lg": 12,
    "xl": 16,
}


def get_theme(name: str = "dark") -> Dict[str, str]:
    """Get theme colors by name."""
    return THEMES.get(name, DARK)


def get_gradient(theme: Dict[str, str]) -> Tuple[str, str]:
    """Get gradient start/end colors for the theme."""
    return theme["gradient_start"], theme["gradient_end"]

TAB_THEMES: Dict[str, Dict[str, str]] = THEMES

DEFAULT_IP_CONFIG = {
    'ip': '192.168.100.100',
    'netmask': '255.255.255.0',
    'gateway': '192.168.100.1',
    'dns1': '8.8.8.8',
    'dns2': '8.8.4.4',
}
