"""
Network utilities for ONT Broadcast Tool.

Provides cross-platform network interface enumeration and
broadcast address calculation for Windows and Linux.
"""

import socket
import struct
import platform
import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkInterface:
    """Represents a network interface with its address information."""
    name: str
    friendly_name: str
    ip: str
    netmask: str
    broadcast: str
    mac: str = ''

    def __str__(self) -> str:
        return f"{self.friendly_name} ({self.ip})"


def _calc_broadcast(ip: str, netmask: str) -> str:
    """Calculate broadcast address from IP and netmask."""
    try:
        ip_int = struct.unpack('>I', socket.inet_aton(ip))[0]
        nm_int = struct.unpack('>I', socket.inet_aton(netmask))[0]
        bc_int = (ip_int & nm_int) | (~nm_int & 0xFFFFFFFF)
        return socket.inet_ntoa(struct.pack('>I', bc_int))
    except Exception:
        return '255.255.255.255'


def get_interfaces() -> List[NetworkInterface]:
    """Return all available network interfaces with IPv4 addresses."""
    interfaces: List[NetworkInterface] = []

    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                    ip      = addr.address
                    netmask = addr.netmask or '255.255.255.0'
                    broadcast = addr.broadcast or _calc_broadcast(ip, netmask)
                    # Get MAC address
                    mac = ''
                    for a in addrs:
                        if a.family == psutil.AF_LINK:
                            mac = a.address
                            break
                    iface = NetworkInterface(
                        name=name,
                        friendly_name=name,
                        ip=ip,
                        netmask=netmask,
                        broadcast=broadcast,
                        mac=mac,
                    )
                    interfaces.append(iface)
    except ImportError:
        # Fallback: use socket only
        hostname = socket.gethostname()
        try:
            host_ip = socket.gethostbyname(hostname)
            iface = NetworkInterface(
                name='default',
                friendly_name=f'Default ({host_ip})',
                ip=host_ip,
                netmask='255.255.255.0',
                broadcast=_calc_broadcast(host_ip, '255.255.255.0'),
            )
            interfaces.append(iface)
        except Exception as e:
            logger.warning("Could not enumerate interfaces: %s", e)

    if not interfaces:
        interfaces.append(NetworkInterface(
            name='broadcast',
            friendly_name='Global Broadcast',
            ip='0.0.0.0',
            netmask='0.0.0.0',
            broadcast='255.255.255.255',
        ))

    return interfaces


def get_interface_by_name(name: str) -> Optional[NetworkInterface]:
    """Return interface with the given name, or None."""
    for iface in get_interfaces():
        if iface.name == name:
            return iface
    return None
