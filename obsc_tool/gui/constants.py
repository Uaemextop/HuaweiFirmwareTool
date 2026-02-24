"""Constants and utility functions shared across GUI modules."""


def _safe_int(value, default=0):
    """Convert a value to int, returning default on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


# ── Theme Colors ─────────────────────────────────────────────────

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

# ── IP Mode defaults (extracted from ONT_V100R002C00SPC253.exe) ──
# Binary analysis of the dialog resource at 0x877500 confirms:
#   - "本地网卡" (Local Network Card) = Ethernet adapter selector
#   - "组播服务器IP" (Multicast Server IP) = ONT IP (SysIPAddress32 control)
#   - Default FRSIZE options: 800, 1000, 1200, 1400 (default 1200)
#   - Default FRINTERV options: 10, 20 (default 10 ms)
#   - Send port 50000, receive port 50001
#   - The PC Ethernet adapter must be on the same subnet as the ONT.
# The ONT default LAN IP is 192.168.100.1; PC uses 192.168.100.100/24.
# The DESBLOQUEIO unlock method changes to FRSIZE=1400, FRINTERV=5ms.
IP_MODE_DEFAULTS = {
    'ip': '192.168.100.100',
    'netmask': '255.255.255.0',
    'gateway': '192.168.100.1',
    'dns1': '8.8.8.8',
    'dns2': '8.8.4.4',
}

# Multicast address used by the OBSC protocol for device discovery
# Found in the original EXE dialog: "组播服务器IP" (Multicast Server IP)
OBSC_MULTICAST_ADDR = '224.0.0.9'

# Staleness timeout — devices removed from table after this many seconds
DEVICE_STALE_TIMEOUT = 30

# ttkbootstrap theme names
TTKB_DARK = "darkly"
TTKB_LIGHT = "cosmo"
