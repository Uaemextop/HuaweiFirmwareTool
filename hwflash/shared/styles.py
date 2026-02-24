"""
Modern UI styles, colors, and theme configuration.

Provides a centralized theming system with dark/light modes,
gradient colors, shadow effects, and animation support.
"""

from typing import Dict, Tuple


PRIMARY = "#2563EB"
PRIMARY_HOVER = "#1D4ED8"
PRIMARY_LIGHT = "#3B82F6"
SECONDARY = "#06B6D4"
SECONDARY_HOVER = "#0891B2"
ACCENT = "#8B5CF6"
SUCCESS = "#10B981"
SUCCESS_HOVER = "#059669"
WARNING = "#F59E0B"
DANGER = "#EF4444"
DANGER_HOVER = "#DC2626"

DARK = {
    "bg": "#0F172A",
    "bg_secondary": "#1E293B",
    "bg_card": "#1E293B",
    "bg_input": "#334155",
    "bg_hover": "#334155",
    "bg_selected": "#1E40AF",
    "fg": "#F8FAFC",
    "fg_secondary": "#94A3B8",
    "fg_muted": "#64748B",
    "border": "#334155",
    "border_light": "#475569",
    "shadow": "#000000",
    "accent": PRIMARY,
    "accent_hover": PRIMARY_HOVER,
    "success": SUCCESS,
    "warning": WARNING,
    "danger": DANGER,
    "gradient_start": "#1E3A5F",
    "gradient_end": "#0F172A",
    "sidebar": "#0F172A",
    "titlebar": "#0F172A",
    "tab_active": PRIMARY,
    "tab_inactive": "#1E293B",
    "scrollbar": "#475569",
    "scrollbar_hover": "#64748B",
    "terminal_bg": "#0D1117",
    "terminal_fg": "#58A6FF",
}

LIGHT = {
    "bg": "#F8FAFC",
    "bg_secondary": "#F1F5F9",
    "bg_card": "#FFFFFF",
    "bg_input": "#FFFFFF",
    "bg_hover": "#E2E8F0",
    "bg_selected": "#DBEAFE",
    "fg": "#0F172A",
    "fg_secondary": "#475569",
    "fg_muted": "#94A3B8",
    "border": "#E2E8F0",
    "border_light": "#CBD5E1",
    "shadow": "#94A3B8",
    "accent": PRIMARY,
    "accent_hover": PRIMARY_HOVER,
    "success": SUCCESS,
    "warning": WARNING,
    "danger": DANGER,
    "gradient_start": "#EFF6FF",
    "gradient_end": "#F8FAFC",
    "sidebar": "#FFFFFF",
    "titlebar": "#FFFFFF",
    "tab_active": PRIMARY,
    "tab_inactive": "#E2E8F0",
    "scrollbar": "#CBD5E1",
    "scrollbar_hover": "#94A3B8",
    "terminal_bg": "#FAFAFA",
    "terminal_fg": "#1E293B",
}

THEMES: Dict[str, Dict[str, str]] = {
    "dark": DARK,
    "light": LIGHT,
}

IP_MODE_DEFAULTS = {
    "Automatic (192.168.100.x)": {
        "ip": "192.168.100.2",
        "mask": "255.255.255.0",
        "gw": "192.168.100.1",
    },
    "Manual": {"ip": "", "mask": "255.255.255.0", "gw": ""},
    "DHCP": {"ip": "", "mask": "", "gw": ""},
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


LEGACY_THEMES = {
    'light': {
        'bg': '#F3F3F3', 'fg': '#1A1A1A',
        'accent': '#0078D4', 'accent_hover': '#106EBE',
        'surface': '#FFFFFF', 'surface_alt': '#F9F9F9',
        'border': '#D1D1D1',
        'success': '#0F7B0F', 'error': '#C42B1C', 'warning': '#9D5D00',
        'log_bg': '#FFFFFF', 'log_fg': '#1A1A1A',
        'progress_bg': '#E0E0E0', 'progress_fg': '#0078D4',
    },
    'dark': {
        'bg': '#202020', 'fg': '#FFFFFF',
        'accent': '#60CDFF', 'accent_hover': '#429CE3',
        'surface': '#2D2D2D', 'surface_alt': '#383838',
        'border': '#404040',
        'success': '#6CCB5F', 'error': '#FF99A4', 'warning': '#FCE100',
        'log_bg': '#1A1A1A', 'log_fg': '#D4D4D4',
        'progress_bg': '#404040', 'progress_fg': '#60CDFF',
    },
}

LEGACY_IP_DEFAULTS = {
    'ip': '192.168.100.100',
    'netmask': '255.255.255.0',
    'gateway': '192.168.100.1',
    'dns1': '8.8.8.8',
    'dns2': '8.8.4.4',
}
