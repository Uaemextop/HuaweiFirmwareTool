"""Constants and utility functions shared across GUI modules.

This module re-exports from shared.styles and shared.helpers for
backward compatibility with existing tab mixins.
"""

from obsc_tool.shared.helpers import safe_int as _safe_int  # noqa: F401
from obsc_tool.shared.styles import (  # noqa: F401
    OBSC_MULTICAST_ADDR,
    DEVICE_STALE_TIMEOUT,
    TTKB_DARK,
    TTKB_LIGHT,
)


# ── Theme Colors ─────────────────────────────────────────────────
# Keep the original theme dict structure for backward compat with mixins
THEMES = {
    'light': {
        'bg': '#F3F3F3',
        'fg': '#1A1A1A',
        'accent': '#0078D4',
        'accent_hover': '#106EBE',
        'surface': '#FFFFFF',
        'surface_alt': '#F9F9F9',
        'border': '#D1D1D1',
        'success': '#0F7B0F',
        'error': '#C42B1C',
        'warning': '#9D5D00',
        'log_bg': '#FFFFFF',
        'log_fg': '#1A1A1A',
        'progress_bg': '#E0E0E0',
        'progress_fg': '#0078D4',
    },
    'dark': {
        'bg': '#202020',
        'fg': '#FFFFFF',
        'accent': '#60CDFF',
        'accent_hover': '#429CE3',
        'surface': '#2D2D2D',
        'surface_alt': '#383838',
        'border': '#404040',
        'success': '#6CCB5F',
        'error': '#FF99A4',
        'warning': '#FCE100',
        'log_bg': '#1A1A1A',
        'log_fg': '#D4D4D4',
        'progress_bg': '#404040',
        'progress_fg': '#60CDFF',
    },
}

# ── IP Mode defaults ─────────────────────────────────────────────
IP_MODE_DEFAULTS = {
    'ip': '192.168.100.100',
    'netmask': '255.255.255.0',
    'gateway': '192.168.100.1',
    'dns1': '8.8.8.8',
    'dns2': '8.8.4.4',
}
