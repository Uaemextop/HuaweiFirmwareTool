"""
Network adapter discovery for hwflash.
"""

import socket
import struct
import subprocess
import re
import sys
import logging

logger = logging.getLogger("hwflash.net.adapter")


class NetworkAdapter:
    """Represents a network interface/adapter."""

    __slots__ = ('name', 'ip', 'netmask', 'mac', 'description', 'index',
                 'gateway', 'status', 'speed', 'dhcp_enabled')

    def __init__(self, name="", ip="", netmask="", mac="", description="",
                 index=0, gateway="", status="Up", speed="", dhcp_enabled=False):
        self.name = name
        self.ip = ip
        self.netmask = netmask
        self.mac = mac
        self.description = description
        self.index = index
        self.gateway = gateway
        self.status = status
        self.speed = speed
        self.dhcp_enabled = dhcp_enabled

    def __repr__(self):
        return f"NetworkAdapter({self.name}, {self.ip}, {self.mac})"

    def display_name(self):
        """User-friendly display string."""
        parts = []
        if self.description:
            parts.append(self.description)
        elif self.name:
            parts.append(self.name)
        if self.ip:
            parts.append(f"[{self.ip}]")
        if self.mac:
            parts.append(f"({self.mac})")
        return " ".join(parts) if parts else "Unknown Adapter"

    def broadcast_address(self):
        """Calculate broadcast address from IP and netmask."""
        if not self.ip or not self.netmask:
            return "255.255.255.255"
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(self.ip))[0]
            mask_int = struct.unpack('!I', socket.inet_aton(self.netmask))[0]
            bcast_int = ip_int | (~mask_int & 0xFFFFFFFF)
            return socket.inet_ntoa(struct.pack('!I', bcast_int))
        except (OSError, struct.error):
            return "255.255.255.255"

    def details_dict(self):
        """Return all adapter details as an ordered dict for display."""
        return {
            "Name": self.name,
            "Description": self.description,
            "IP Address": self.ip,
            "Subnet Mask": self.netmask,
            "Broadcast": self.broadcast_address(),
            "Gateway": self.gateway or "N/A",
            "MAC Address": self.mac or "N/A",
            "Status": self.status,
            "Speed": self.speed or "N/A",
            "DHCP": "Enabled" if self.dhcp_enabled else "Static",
            "Interface Index": str(self.index),
        }


def discover_adapters():
    """Discover network adapters on the system.

    Returns:
        List of NetworkAdapter objects.
    """
    adapters = []

    if sys.platform == 'win32':
        adapters = _discover_adapters_windows()
    else:
        adapters = _discover_adapters_unix()

    # Filter to only adapters with valid IPs
    adapters = [a for a in adapters if a.ip and a.ip != '127.0.0.1']

    if not adapters:
        # Fallback: use socket to get at least one address
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip and ip != '127.0.0.1':
                adapter = NetworkAdapter(
                    name="Default",
                    ip=ip,
                    netmask="255.255.255.0",
                    description=f"Default ({hostname})"
                )
                adapters.append(adapter)
        except socket.error:
            pass

    return adapters


def _discover_adapters_windows():
    """Discover adapters on Windows using PowerShell with full details."""
    adapters = []

    mac_map = {}
    gw_map = {}
    status_map = {}
    speed_map = {}

    try:
        cmd_adapter = (
            'powershell -Command "'
            'Get-NetAdapter | '
            'Select-Object Name,InterfaceIndex,MacAddress,Status,LinkSpeed | '
            'ConvertTo-Csv -NoTypeInformation"'
        )
        result = subprocess.run(
            cmd_adapter, capture_output=True, text=True, timeout=5, shell=True
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) >= 5:
                    a_name = parts[0]
                    a_idx = int(parts[1]) if parts[1].isdigit() else 0
                    mac_map[a_idx] = parts[2].replace('-', ':')
                    status_map[a_name] = parts[3]
                    speed_map[a_name] = parts[4]
    except (subprocess.SubprocessError, OSError, ValueError):
        pass

    try:
        cmd_gw = (
            'powershell -Command "'
            'Get-NetIPConfiguration | '
            'Where-Object { $_.IPv4DefaultGateway } | '
            'Select-Object InterfaceAlias,'
            '@{N=\'Gateway\';E={$_.IPv4DefaultGateway.NextHop}} | '
            'ConvertTo-Csv -NoTypeInformation"'
        )
        result = subprocess.run(
            cmd_gw, capture_output=True, text=True, timeout=5, shell=True
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) >= 2:
                    gw_map[parts[0]] = parts[1]
    except (subprocess.SubprocessError, OSError, ValueError):
        pass

    try:
        cmd = (
            'powershell -Command "'
            'Get-NetIPAddress -AddressFamily IPv4 | '
            'Where-Object { $_.IPAddress -ne \'127.0.0.1\' } | '
            'Select-Object InterfaceAlias,IPAddress,PrefixLength,InterfaceIndex | '
            'ConvertTo-Csv -NoTypeInformation"'
        )
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, shell=True
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 4:
                        prefix_len = int(parts[2]) if parts[2].isdigit() else 24
                        mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                        netmask = socket.inet_ntoa(struct.pack('!I', mask_int))
                        iface_idx = int(parts[3]) if parts[3].isdigit() else 0

                        adapter = NetworkAdapter(
                            name=parts[0],
                            ip=parts[1],
                            netmask=netmask,
                            description=parts[0],
                            index=iface_idx,
                            mac=mac_map.get(iface_idx, ""),
                            gateway=gw_map.get(parts[0], ""),
                            status=status_map.get(parts[0], "Up"),
                            speed=speed_map.get(parts[0], ""),
                        )
                        adapters.append(adapter)
    except (subprocess.SubprocessError, OSError, ValueError):
        pass

    if not adapters:
        adapters = _discover_adapters_ipconfig()

    return adapters


def _discover_adapters_ipconfig():
    """Fallback Windows adapter discovery using ipconfig."""
    adapters = []
    try:
        result = subprocess.run(
            ['ipconfig', '/all'], capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return adapters

        current_name = ""
        current_ip = ""
        current_mask = ""
        current_mac = ""
        current_gw = ""
        current_dhcp = False

        for line in result.stdout.split('\n'):
            line = line.strip()

            name_match = re.match(r'^(Ethernet|Wi-Fi|Wireless).*adapter (.+):', line)
            if name_match:
                if current_name and current_ip:
                    adapters.append(NetworkAdapter(
                        name=current_name, ip=current_ip,
                        netmask=current_mask, mac=current_mac,
                        description=current_name, gateway=current_gw,
                        dhcp_enabled=current_dhcp,
                    ))
                current_name = name_match.group(2)
                current_ip = ""
                current_mask = ""
                current_mac = ""
                current_gw = ""
                current_dhcp = False

            if 'IPv4 Address' in line or 'IP Address' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    current_ip = match.group(1)

            if 'Subnet Mask' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    current_mask = match.group(1)

            if 'Physical Address' in line:
                match = re.search(r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:]'
                                  r'[0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:]'
                                  r'[0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})', line)
                if match:
                    current_mac = match.group(1)

            if 'Default Gateway' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    current_gw = match.group(1)

            if 'DHCP Enabled' in line and 'Yes' in line:
                current_dhcp = True

        if current_name and current_ip:
            adapters.append(NetworkAdapter(
                name=current_name, ip=current_ip,
                netmask=current_mask or "255.255.255.0",
                mac=current_mac, description=current_name,
                gateway=current_gw, dhcp_enabled=current_dhcp,
            ))

    except (subprocess.SubprocessError, OSError):
        pass

    return adapters


def _discover_adapters_unix():
    """Discover adapters on Linux/macOS."""
    adapters = []

    try:
        result = subprocess.run(
            ['ip', '-4', '-o', 'addr', 'show'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    idx = parts[0].rstrip(':')
                    name = parts[1]
                    for i, p in enumerate(parts):
                        if p == 'inet' and i + 1 < len(parts):
                            addr_mask = parts[i + 1]
                            if '/' in addr_mask:
                                ip, prefix = addr_mask.split('/')
                                prefix_len = int(prefix)
                                mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                                netmask = socket.inet_ntoa(struct.pack('!I', mask_int))
                                adapter = NetworkAdapter(
                                    name=name, ip=ip, netmask=netmask,
                                    description=name,
                                    index=int(idx) if idx.isdigit() else 0,
                                )
                                adapters.append(adapter)
                            break
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass

    if not adapters:
        try:
            result = subprocess.run(
                ['ifconfig'], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                current_name = ""
                for line in result.stdout.split('\n'):
                    iface_match = re.match(r'^(\S+)', line)
                    if iface_match and ':' not in line[:3]:
                        current_name = iface_match.group(1).rstrip(':')

                    inet_match = re.search(
                        r'inet\s+(\d+\.\d+\.\d+\.\d+).*?'
                        r'(?:netmask\s+(\S+)|Mask:(\d+\.\d+\.\d+\.\d+))',
                        line
                    )
                    if inet_match and current_name:
                        ip = inet_match.group(1)
                        mask = inet_match.group(2) or inet_match.group(3) or "255.255.255.0"
                        if mask.startswith('0x'):
                            mask_int = int(mask, 16)
                            mask = socket.inet_ntoa(struct.pack('!I', mask_int))
                        adapter = NetworkAdapter(
                            name=current_name, ip=ip, netmask=mask,
                            description=current_name,
                        )
                        adapters.append(adapter)
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            pass

    return adapters
