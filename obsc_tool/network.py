"""
Network utilities for adapter discovery and UDP communication.

Provides cross-platform network adapter enumeration and the low-level
UDP socket operations used by the OBSC protocol.
"""

import socket
import struct
import subprocess
import re
import sys
import time
import logging

logger = logging.getLogger("obsc_tool.network")


class NetworkAdapter:
    """Represents a network interface/adapter."""

    __slots__ = ('name', 'ip', 'netmask', 'mac', 'description', 'index')

    def __init__(self, name="", ip="", netmask="", mac="", description="", index=0):
        self.name = name
        self.ip = ip
        self.netmask = netmask
        self.mac = mac
        self.description = description
        self.index = index

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
    """Discover adapters on Windows using PowerShell."""
    adapters = []
    try:
        # Use PowerShell to get adapter info in a reliable format
        cmd = (
            'powershell -Command "'
            'Get-NetIPAddress -AddressFamily IPv4 | '
            'Where-Object { $_.IPAddress -ne \'127.0.0.1\' } | '
            'Select-Object InterfaceAlias,IPAddress,PrefixLength,InterfaceIndex | '
            'ConvertTo-Csv -NoTypeInformation"'
        )
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, shell=True
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]:
                    # Parse CSV: "InterfaceAlias","IPAddress","PrefixLength","InterfaceIndex"
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 4:
                        prefix_len = int(parts[2]) if parts[2].isdigit() else 24
                        mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                        netmask = socket.inet_ntoa(struct.pack('!I', mask_int))

                        adapter = NetworkAdapter(
                            name=parts[0],
                            ip=parts[1],
                            netmask=netmask,
                            description=parts[0],
                            index=int(parts[3]) if parts[3].isdigit() else 0,
                        )
                        adapters.append(adapter)
    except (subprocess.SubprocessError, OSError, ValueError):
        pass

    # Fallback to ipconfig if PowerShell fails
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

        for line in result.stdout.split('\n'):
            line = line.strip()

            # Adapter header
            name_match = re.match(r'^(Ethernet|Wi-Fi|Wireless).*adapter (.+):', line)
            if name_match:
                if current_name and current_ip:
                    adapters.append(NetworkAdapter(
                        name=current_name, ip=current_ip,
                        netmask=current_mask, mac=current_mac,
                        description=current_name
                    ))
                current_name = name_match.group(2)
                current_ip = ""
                current_mask = ""
                current_mac = ""

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

        if current_name and current_ip:
            adapters.append(NetworkAdapter(
                name=current_name, ip=current_ip,
                netmask=current_mask or "255.255.255.0",
                mac=current_mac, description=current_name
            ))

    except (subprocess.SubprocessError, OSError):
        pass

    return adapters


def _discover_adapters_unix():
    """Discover adapters on Linux/macOS."""
    adapters = []

    # Try ip command first (Linux)
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

    # Fallback to ifconfig
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
                        # Convert hex mask if needed
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


class UDPTransport:
    """Low-level UDP socket for OBSC protocol communication."""

    def __init__(self, bind_ip="0.0.0.0", bind_port=0,
                 dest_port=50000, broadcast=True):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.dest_port = dest_port
        self.broadcast = broadcast
        self.sock = None
        self.timeout = 5.0

    def open(self):
        """Create and bind the UDP socket."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.broadcast:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Set send buffer size for performance
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

        self.sock.settimeout(self.timeout)
        self.sock.bind((self.bind_ip, self.bind_port))

        logger.info("UDP socket bound to %s:%d", self.bind_ip, self.bind_port)

    def close(self):
        """Close the UDP socket."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send(self, data, dest_ip, dest_port=None):
        """Send UDP datagram.

        Args:
            data: Bytes to send.
            dest_ip: Destination IP address.
            dest_port: Destination port (uses default if None).
        """
        if not self.sock:
            raise RuntimeError("Socket not open")
        port = dest_port or self.dest_port
        self.sock.sendto(data, (dest_ip, port))

    def receive(self, bufsize=4096, timeout=None):
        """Receive UDP datagram.

        Args:
            bufsize: Maximum receive buffer size.
            timeout: Override timeout in seconds.

        Returns:
            Tuple of (data, (ip, port)) or (None, None) on timeout.
        """
        if not self.sock:
            raise RuntimeError("Socket not open")

        if timeout is not None:
            self.sock.settimeout(timeout)

        try:
            data, addr = self.sock.recvfrom(bufsize)
            return data, addr
        except socket.timeout:
            return None, None
        finally:
            if timeout is not None:
                self.sock.settimeout(self.timeout)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()
