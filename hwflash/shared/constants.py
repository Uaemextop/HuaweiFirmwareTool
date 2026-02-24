"""
Application-wide constants.

Protocol, network, and configuration defaults that don't belong
in the styling/theme module.
"""

# ── OBSC Protocol ────────────────────────────────────────────────
OBSC_MULTICAST_ADDR = "224.0.0.9"
DEVICE_STALE_TIMEOUT = 30  # seconds before a device is considered lost

# ── Default IP Configuration ────────────────────────────────────
DEFAULT_IP_CONFIG = {
    "ip": "192.168.100.100",
    "netmask": "255.255.255.0",
    "gateway": "192.168.100.1",
    "dns1": "8.8.8.8",
    "dns2": "8.8.4.4",
}
