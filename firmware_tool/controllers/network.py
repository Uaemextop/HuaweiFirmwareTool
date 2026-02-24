"""Network operations controller."""

import socket
import struct
from typing import Optional, Dict, Any, List, Tuple

from .base import BaseController
from ..utils import is_valid_ip, is_valid_port


class NetworkController(BaseController):
    """
    Controller for network operations.

    Handles:
    - Device connectivity testing
    - Network configuration
    - Device discovery
    - IP address validation
    """

    def __init__(self):
        """Initialize network controller."""
        super().__init__()
        self._connected_devices: List[Dict[str, Any]] = []

    def test_connection(self, ip: str, port: int, timeout: int = 5) -> bool:
        """
        Test connection to device.

        Args:
            ip: Device IP address
            port: Device port
            timeout: Connection timeout in seconds

        Returns:
            True if connection successful

        Emits:
            - connection_test_started: (ip, port)
            - connection_success: (ip, port)
            - connection_failed: (ip, port, error)
        """
        if not is_valid_ip(ip):
            self.emit_event('connection_failed', ip, port, "Invalid IP address")
            return False

        if not is_valid_port(port):
            self.emit_event('connection_failed', ip, port, "Invalid port")
            return False

        self.emit_event('connection_test_started', ip, port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.close()

            self.emit_event('connection_success', ip, port)
            self.logger.info(f"Connection successful: {ip}:{port}")
            return True

        except socket.timeout:
            self.emit_event('connection_failed', ip, port, "Connection timeout")
            return False
        except ConnectionRefusedError:
            self.emit_event('connection_failed', ip, port, "Connection refused")
            return False
        except Exception as e:
            self.emit_event('connection_failed', ip, port, str(e))
            return False

    def scan_network(self, network_prefix: str, port: int,
                    start_host: int = 1, end_host: int = 254) -> List[str]:
        """
        Scan network for devices.

        Args:
            network_prefix: Network prefix (e.g., "192.168.1")
            port: Port to scan
            start_host: Starting host number
            end_host: Ending host number

        Returns:
            List of responsive IP addresses

        Emits:
            - scan_started: (network_prefix, port, range)
            - device_found: (ip, port)
            - scan_completed: (found_devices)
        """
        found_devices = []

        self.emit_event('scan_started', network_prefix, port, (start_host, end_host))
        self.logger.info(f"Scanning {network_prefix}.{start_host}-{end_host}:{port}")

        for host in range(start_host, end_host + 1):
            ip = f"{network_prefix}.{host}"

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    found_devices.append(ip)
                    self.emit_event('device_found', ip, port)
                    self.logger.info(f"Device found: {ip}:{port}")

            except Exception as e:
                self.logger.debug(f"Error scanning {ip}: {e}")
                continue

        self.emit_event('scan_completed', found_devices)
        self.logger.info(f"Scan completed: {len(found_devices)} devices found")
        return found_devices

    def send_command(self, ip: str, port: int, command: bytes,
                    expect_response: bool = True) -> Optional[bytes]:
        """
        Send command to device and optionally receive response.

        Args:
            ip: Device IP address
            port: Device port
            command: Command bytes to send
            expect_response: Whether to wait for response

        Returns:
            Response bytes if expect_response=True, None otherwise

        Emits:
            - command_sent: (ip, port, command_length)
            - response_received: (ip, port, response_length)
            - command_failed: (ip, port, error)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, port))

            sock.sendall(command)
            self.emit_event('command_sent', ip, port, len(command))
            self.logger.debug(f"Command sent to {ip}:{port} ({len(command)} bytes)")

            if expect_response:
                response = sock.recv(4096)
                sock.close()
                self.emit_event('response_received', ip, port, len(response))
                self.logger.debug(f"Response received: {len(response)} bytes")
                return response
            else:
                sock.close()
                return None

        except Exception as e:
            self.handle_error(e, f"Command failed for {ip}:{port}")
            self.emit_event('command_failed', ip, port, str(e))
            return None

    def get_local_ip(self) -> str:
        """
        Get local machine IP address.

        Returns:
            Local IP address as string
        """
        try:
            # Create socket to determine local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def validate_network_config(self, ip: str, netmask: str, gateway: str) -> Tuple[bool, str]:
        """
        Validate network configuration.

        Args:
            ip: IP address
            netmask: Network mask
            gateway: Gateway address

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not is_valid_ip(ip):
            return False, f"Invalid IP address: {ip}"

        if not is_valid_ip(netmask):
            return False, f"Invalid netmask: {netmask}"

        if gateway and not is_valid_ip(gateway):
            return False, f"Invalid gateway: {gateway}"

        return True, ""

    def add_device(self, ip: str, port: int, name: str = ""):
        """
        Add device to connected devices list.

        Args:
            ip: Device IP
            port: Device port
            name: Optional device name
        """
        device = {
            'ip': ip,
            'port': port,
            'name': name or f"Device_{ip}",
        }
        self._connected_devices.append(device)
        self.emit_event('device_added', device)

    def remove_device(self, ip: str):
        """
        Remove device from connected devices list.

        Args:
            ip: Device IP to remove
        """
        self._connected_devices = [d for d in self._connected_devices if d['ip'] != ip]
        self.emit_event('device_removed', ip)

    def get_devices(self) -> List[Dict[str, Any]]:
        """
        Get list of connected devices.

        Returns:
            List of device dictionaries
        """
        return self._connected_devices.copy()
