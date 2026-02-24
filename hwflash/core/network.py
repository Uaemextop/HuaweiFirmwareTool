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
import logging

from hwflash.shared.helpers import _POPEN_FLAGS

logger = logging.getLogger("hwflash.network")


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

    # Gather MAC, gateway, status, and speed via Get-NetAdapter + Get-NetIPConfiguration
    mac_map = {}    # InterfaceIndex -> MAC
    gw_map = {}     # InterfaceAlias -> gateway
    status_map = {}  # InterfaceAlias -> status
    speed_map = {}   # InterfaceAlias -> speed

    try:
        # Get adapter hardware info (MAC, status, speed)
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-NetAdapter | '
             'Select-Object Name,InterfaceIndex,MacAddress,Status,LinkSpeed | '
             'ConvertTo-Csv -NoTypeInformation'],
            capture_output=True, text=True, timeout=5, **_POPEN_FLAGS
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
        # Get default gateway per adapter
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-NetIPConfiguration | '
             'Where-Object { $_.IPv4DefaultGateway } | '
             "Select-Object InterfaceAlias,"
             "@{N='Gateway';E={$_.IPv4DefaultGateway.NextHop}} | "
             'ConvertTo-Csv -NoTypeInformation'],
            capture_output=True, text=True, timeout=5, **_POPEN_FLAGS
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
        # Get IP addresses
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-NetIPAddress -AddressFamily IPv4 | '
             "Where-Object { $_.IPAddress -ne '127.0.0.1' } | "
             'Select-Object InterfaceAlias,IPAddress,PrefixLength,InterfaceIndex | '
             'ConvertTo-Csv -NoTypeInformation'],
            capture_output=True, text=True, timeout=5, **_POPEN_FLAGS
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

    # Fallback to ipconfig if PowerShell fails
    if not adapters:
        adapters = _discover_adapters_ipconfig()

    return adapters


def _discover_adapters_ipconfig():
    """Fallback Windows adapter discovery using ipconfig."""
    adapters = []
    try:
        result = subprocess.run(
            ['ipconfig', '/all'], capture_output=True, text=True, timeout=10,
            **_POPEN_FLAGS
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

            # Adapter header
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
                 dest_port=50000, broadcast=True, multicast_group=None):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.dest_port = dest_port
        self.broadcast = broadcast
        self.multicast_group = multicast_group
        self.sock = None
        self.timeout = 5.0

    def open(self):
        """Create and bind the UDP socket."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.broadcast:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Join multicast group if specified
        if self.multicast_group:
            try:
                if self.bind_ip and self.bind_ip != "0.0.0.0":
                    iface_addr = socket.inet_aton(self.bind_ip)
                else:
                    iface_addr = struct.pack('!I', 0)  # INADDR_ANY
                mreq = struct.pack(
                    '4s4s',
                    socket.inet_aton(self.multicast_group),
                    iface_addr,
                )
                self.sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                # Set multicast interface to the bind IP
                self.sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, iface_addr)
                # TTL=1 keeps multicast on local network
                self.sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                logger.info("Joined multicast group %s on %s",
                            self.multicast_group, self.bind_ip)
            except OSError as e:
                logger.warning("Multicast join failed: %s", e)

        # Set send buffer size for performance
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

        self.sock.settimeout(self.timeout)
        self.sock.bind((self.bind_ip, self.bind_port))

        logger.info("UDP socket bound to %s:%d (multicast=%s)",
                     self.bind_ip, self.bind_port,
                     self.multicast_group or "none")

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

    def get_status(self):
        """Return dict with socket status information."""
        if not self.sock:
            return {"state": "Closed"}
        try:
            local = self.sock.getsockname()
            return {
                "state": "Open",
                "local_addr": f"{local[0]}:{local[1]}",
                "broadcast": "Yes" if self.broadcast else "No",
                "multicast": self.multicast_group or "None",
                "timeout": f"{self.timeout}s",
                "send_buf": str(self.sock.getsockopt(
                    socket.SOL_SOCKET, socket.SO_SNDBUF)),
                "recv_buf": str(self.sock.getsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF)),
            }
        except OSError:
            return {"state": "Error"}


def configure_adapter_ip(adapter_name, ip, netmask, gateway=""):
    """Configure IP address on a Windows network adapter.

    Requires administrator privileges on Windows.
    On Linux, uses ip/ifconfig (requires root).

    Args:
        adapter_name: Interface name (e.g. "Ethernet", "eth0").
        ip: New IPv4 address.
        netmask: Subnet mask (e.g. "255.255.255.0").
        gateway: Optional default gateway.

    Returns:
        Tuple of (success: bool, message: str).
    """
    if sys.platform == 'win32':
        return _configure_adapter_windows(adapter_name, ip, netmask, gateway)
    else:
        return _configure_adapter_unix(adapter_name, ip, netmask, gateway)


def _configure_adapter_windows(adapter_name, ip, netmask, gateway):
    """Set static IP on Windows using netsh."""
    try:
        cmd = [
            'netsh', 'interface', 'ip', 'set', 'address',
            adapter_name, 'static', ip, netmask,
        ]
        if gateway:
            cmd.append(gateway)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, **_POPEN_FLAGS
        )
        if result.returncode == 0:
            msg = f"Set {adapter_name} to {ip}/{netmask}"
            if gateway:
                msg += f" gw {gateway}"
            logger.info(msg)
            return True, msg
        else:
            err = result.stderr.strip() or result.stdout.strip()
            logger.error("netsh failed: %s", err)
            return False, f"netsh error: {err}"
    except subprocess.SubprocessError as e:
        return False, f"Failed to run netsh: {e}"


def _configure_adapter_unix(adapter_name, ip, netmask, gateway):
    """Set IP on Linux using ip command."""
    try:
        # Calculate prefix length from netmask
        mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
        prefix = bin(mask_int).count('1')

        subprocess.run(
            ['ip', 'addr', 'flush', 'dev', adapter_name],
            capture_output=True, text=True, timeout=10
        )
        result = subprocess.run(
            ['ip', 'addr', 'add', f'{ip}/{prefix}', 'dev', adapter_name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            err = result.stderr.strip()
            return False, f"ip addr add failed: {err}"

        if gateway:
            subprocess.run(
                ['ip', 'route', 'add', 'default', 'via', gateway,
                 'dev', adapter_name],
                capture_output=True, text=True, timeout=10
            )

        msg = f"Set {adapter_name} to {ip}/{prefix}"
        if gateway:
            msg += f" gw {gateway}"
        logger.info(msg)
        return True, msg

    except (subprocess.SubprocessError, OSError) as e:
        return False, f"Failed: {e}"


def set_adapter_dhcp(adapter_name):
    """Set adapter to DHCP mode.

    Args:
        adapter_name: Interface name.

    Returns:
        Tuple of (success: bool, message: str).
    """
    if sys.platform == 'win32':
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ip', 'set', 'address',
                 adapter_name, 'dhcp'],
                capture_output=True, text=True, timeout=15, **_POPEN_FLAGS
            )
            if result.returncode == 0:
                return True, f"Set {adapter_name} to DHCP"
            err = result.stderr.strip() or result.stdout.strip()
            return False, f"netsh error: {err}"
        except subprocess.SubprocessError as e:
            return False, f"Failed: {e}"
    else:
        return False, "DHCP configuration requires dhclient on Linux"


def test_socket_bind(bind_ip, bind_port, broadcast=True):
    """Test if a UDP socket can bind to the given address.

    Args:
        bind_ip: IP address to bind to.
        bind_port: Port number to bind to.
        broadcast: Whether to enable broadcast.

    Returns:
        Tuple of (success: bool, message: str).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((bind_ip, bind_port))
        local = sock.getsockname()
        sock.close()
        return True, f"Socket bound to {local[0]}:{local[1]} (broadcast={'on' if broadcast else 'off'})"
    except OSError as e:
        return False, f"Bind failed: {e}"


def list_serial_ports():
    """List available serial/COM ports.

    Returns:
        List of dicts with 'device' and 'description' keys.
    """
    ports = []
    try:
        from serial.tools.list_ports import comports
        for p in comports():
            ports.append({
                'device': p.device,
                'description': p.description or p.device,
                'hwid': p.hwid or "",
            })
    except ImportError:
        # pyserial not installed; try Windows-only fallback
        if sys.platform == 'win32':
            try:
                result = subprocess.run(
                    ['powershell', '-Command',
                     'Get-WmiObject Win32_SerialPort | '
                     'Select-Object DeviceID,Name | '
                     'ConvertTo-Csv -NoTypeInformation'],
                    capture_output=True, text=True, timeout=10, **_POPEN_FLAGS
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:
                        parts = [p.strip('"') for p in line.split(',')]
                        if len(parts) >= 2:
                            ports.append({
                                'device': parts[0],
                                'description': parts[1],
                                'hwid': '',
                            })
            except (subprocess.SubprocessError, OSError):
                pass
    return ports
