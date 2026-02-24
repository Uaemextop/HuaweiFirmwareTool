"""
UDP transport and serial port utilities for hwflash.
"""

import socket
import struct
import subprocess
import sys
import logging

logger = logging.getLogger("hwflash.net.transport")

OBSC_SEND_PORT = 50000
OBSC_RECV_PORT = 50001


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

        if self.multicast_group:
            try:
                if self.bind_ip and self.bind_ip != "0.0.0.0":
                    iface_addr = socket.inet_aton(self.bind_ip)
                else:
                    iface_addr = struct.pack('!I', 0)
                mreq = struct.pack(
                    '4s4s',
                    socket.inet_aton(self.multicast_group),
                    iface_addr,
                )
                self.sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                self.sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, iface_addr)
                self.sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                logger.info("Joined multicast group %s on %s",
                            self.multicast_group, self.bind_ip)
            except OSError as e:
                logger.warning("Multicast join failed: %s", e)

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
        """Send UDP datagram."""
        if not self.sock:
            raise RuntimeError("Socket not open")
        port = dest_port or self.dest_port
        self.sock.sendto(data, (dest_ip, port))

    def receive(self, bufsize=4096, timeout=None):
        """Receive UDP datagram.

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
        if sys.platform == 'win32':
            try:
                result = subprocess.run(
                    ['powershell', '-Command',
                     'Get-WmiObject Win32_SerialPort | '
                     'Select-Object DeviceID,Name | '
                     'ConvertTo-Csv -NoTypeInformation'],
                    capture_output=True, text=True, timeout=10
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
