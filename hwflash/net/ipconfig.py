"""
Network adapter IP configuration utilities for hwflash.
"""

import socket
import struct
import subprocess
import sys
import logging

logger = logging.getLogger("hwflash.net.ipconfig")


def configure_adapter_ip(adapter_name, ip, netmask, gateway=""):
    """Configure IP address on a network adapter.

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
            cmd, capture_output=True, text=True, timeout=15
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
                capture_output=True, text=True, timeout=15
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
