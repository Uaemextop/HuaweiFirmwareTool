"""
obsc_protocol.py — OBSC (ONT Board Service Client) protocol implementation.

Implements the UDP broadcast protocol used by Huawei OBSC tools to discover
and flash firmware on ONT (Optical Network Terminal) devices.

Based on reverse engineering of OBSCTool.exe and OntSoftwareBroadcaster.exe.
"""

import socket
import struct
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default OBSC network parameters
DEFAULT_BROADCAST_PORT = 1200
DEFAULT_RETRY_INTERVAL_MS = 10
DEFAULT_CHUNK_SIZE = 1400

# OBSC packet types (from string analysis of OBSCTool.exe)
PKT_TYPE_DISCOVERY = 0x01
PKT_TYPE_DISCOVERY_RESP = 0x02
PKT_TYPE_CTRL_START = 0x03
PKT_TYPE_CTRL_ACK = 0x04
PKT_TYPE_DATA = 0x05
PKT_TYPE_DATA_ACK = 0x06
PKT_TYPE_CTRL_END = 0x07
PKT_TYPE_CTRL_END_ACK = 0x08
PKT_TYPE_STATUS = 0x09

# Result codes (from OSBC log analysis)
RESULT_SUCCESS = 0x00000000
RESULT_VERSION_MISMATCH = 0xF720404F
RESULT_TIMEOUT = 0xF7204028
RESULT_REJECTED = 0xF7204050
RESULT_BUSY = 0xF7204007
RESULT_VERIFY_FAIL = 0xF7204045

RESULT_MESSAGES = {
    RESULT_SUCCESS: "Success",
    RESULT_VERSION_MISMATCH: "Version mismatch / already at target version",
    RESULT_TIMEOUT: "Communication timeout",
    RESULT_REJECTED: "Upgrade rejected by device",
    RESULT_BUSY: "Device busy or in wrong state",
    RESULT_VERIFY_FAIL: "Verification failure",
}


@dataclass
class OntDevice:
    """Represents a discovered ONT device."""
    board_sn: str = ""
    sn_21: str = ""
    mac: str = ""
    ip_address: str = ""
    port: int = 0
    firmware_version: str = ""
    last_seen: float = 0.0

    def display_name(self) -> str:
        parts = []
        if self.board_sn:
            parts.append(self.board_sn)
        if self.mac:
            parts.append(self.mac)
        if self.ip_address:
            parts.append(self.ip_address)
        return " | ".join(parts) if parts else "(unknown device)"


@dataclass
class UpgradeProgress:
    """Tracks the progress of a firmware upgrade."""
    device: OntDevice
    total_bytes: int = 0
    sent_bytes: int = 0
    start_time: float = 0.0
    status: str = "Pending"
    result_code: int = -1
    error_message: str = ""

    @property
    def progress_percent(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return min(100.0, (self.sent_bytes / self.total_bytes) * 100.0)

    @property
    def elapsed_seconds(self) -> float:
        if self.start_time == 0:
            return 0.0
        return time.time() - self.start_time


class ObscBroadcaster:
    """
    OBSC firmware broadcaster.

    Discovers ONT devices on the local network and sends firmware packages
    via UDP broadcast, replicating the behavior of the original Huawei
    OBSCTool and OntSoftwareBroadcaster tools.
    """

    def __init__(
        self,
        broadcast_port: int = DEFAULT_BROADCAST_PORT,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        retry_interval_ms: int = DEFAULT_RETRY_INTERVAL_MS,
        bind_address: str = "0.0.0.0",
    ):
        self.broadcast_port = broadcast_port
        self.chunk_size = chunk_size
        self.retry_interval_ms = retry_interval_ms
        self.bind_address = bind_address

        self._sock: Optional[socket.socket] = None
        self._running = False
        self._discovery_thread: Optional[threading.Thread] = None
        self._upgrade_thread: Optional[threading.Thread] = None

        self.devices: Dict[str, OntDevice] = {}
        self._on_device_found: Optional[Callable[[OntDevice], None]] = None
        self._on_progress: Optional[Callable[[UpgradeProgress], None]] = None
        self._on_log: Optional[Callable[[str], None]] = None

    def set_callbacks(
        self,
        on_device_found: Optional[Callable[[OntDevice], None]] = None,
        on_progress: Optional[Callable[[UpgradeProgress], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Set callback functions for events."""
        self._on_device_found = on_device_found
        self._on_progress = on_progress
        self._on_log = on_log

    def _log(self, message: str) -> None:
        """Log a message and notify callback."""
        logger.info(message)
        if self._on_log:
            self._on_log(message)

    def _create_socket(self) -> socket.socket:
        """Create and configure a UDP broadcast socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        try:
            sock.bind((self.bind_address, self.broadcast_port))
        except OSError as e:
            self._log(f"Warning: Could not bind to port {self.broadcast_port}: {e}")
            sock.bind((self.bind_address, 0))
        return sock

    def start_discovery(self) -> None:
        """Start discovering ONT devices on the network."""
        if self._running:
            return

        self._running = True
        self._sock = self._create_socket()
        self._discovery_thread = threading.Thread(
            target=self._discovery_loop, daemon=True
        )
        self._discovery_thread.start()
        self._log("Device discovery started")

    def stop(self) -> None:
        """Stop all operations."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._log("Broadcaster stopped")

    def _discovery_loop(self) -> None:
        """Background thread for device discovery."""
        while self._running:
            try:
                self._send_discovery_broadcast()
                self._receive_responses(timeout=1.0)
            except OSError:
                if self._running:
                    time.sleep(0.5)
            except Exception as e:
                self._log(f"Discovery error: {e}")
                time.sleep(1.0)

    def _send_discovery_broadcast(self) -> None:
        """Send a discovery broadcast packet."""
        if not self._sock:
            return
        # OBSC discovery packet: type(1) + padding
        packet = struct.pack("<B", PKT_TYPE_DISCOVERY) + b"\x00" * 31
        try:
            self._sock.sendto(
                packet, ("<broadcast>", self.broadcast_port)
            )
        except OSError:
            pass

    def _receive_responses(self, timeout: float = 1.0) -> None:
        """Receive and process response packets."""
        if not self._sock:
            return
        end_time = time.time() + timeout
        while self._running and time.time() < end_time:
            try:
                data, addr = self._sock.recvfrom(4096)
                self._process_response(data, addr)
            except socket.timeout:
                break
            except OSError:
                break

    def _process_response(self, data: bytes, addr: tuple) -> None:
        """Process a received response packet."""
        if len(data) < 2:
            return

        pkt_type = data[0]
        if pkt_type == PKT_TYPE_DISCOVERY_RESP and len(data) >= 32:
            device = OntDevice(
                ip_address=addr[0],
                port=addr[1],
                last_seen=time.time(),
            )
            # Parse device info from response
            try:
                # Board SN at offset 2 (up to 20 bytes)
                device.board_sn = data[2:22].split(b"\x00")[0].decode(
                    "ascii", errors="replace"
                )
                # MAC at offset 22 (6 bytes)
                if len(data) >= 28:
                    mac_bytes = data[22:28]
                    device.mac = ":".join(f"{b:02X}" for b in mac_bytes)
            except (IndexError, UnicodeDecodeError):
                pass

            key = device.board_sn or device.ip_address
            is_new = key not in self.devices
            self.devices[key] = device

            if is_new and self._on_device_found:
                self._on_device_found(device)
                self._log(f"Device found: {device.display_name()}")

    def send_firmware(
        self,
        firmware_data: bytes,
        target_address: str = "<broadcast>",
    ) -> UpgradeProgress:
        """
        Send firmware data to target device(s).

        Args:
            firmware_data: Raw HWNP firmware package bytes
            target_address: IP address of target or "<broadcast>" for all

        Returns:
            UpgradeProgress tracking object
        """
        device = OntDevice(ip_address=target_address)
        progress = UpgradeProgress(
            device=device,
            total_bytes=len(firmware_data),
            start_time=time.time(),
            status="Starting",
        )

        self._upgrade_thread = threading.Thread(
            target=self._send_firmware_loop,
            args=(firmware_data, target_address, progress),
            daemon=True,
        )
        self._upgrade_thread.start()
        return progress

    def _send_firmware_loop(
        self,
        firmware_data: bytes,
        target_address: str,
        progress: UpgradeProgress,
    ) -> None:
        """Background thread for firmware sending."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2.0)

            total = len(firmware_data)
            offset = 0
            seq = 0

            self._log(f"Starting firmware upload: {total} bytes to {target_address}")
            progress.status = "Sending"

            if self._on_progress:
                self._on_progress(progress)

            while offset < total and self._running:
                chunk_end = min(offset + self.chunk_size, total)
                chunk = firmware_data[offset:chunk_end]

                # Build data packet: type(1) + seq(4) + offset(4) + total(4) + data
                packet = struct.pack(
                    "<B I I I",
                    PKT_TYPE_DATA,
                    seq,
                    offset,
                    total,
                )
                packet += chunk

                try:
                    sock.sendto(packet, (target_address, self.broadcast_port))
                except OSError as e:
                    self._log(f"Send error at offset {offset}: {e}")

                offset = chunk_end
                seq += 1
                progress.sent_bytes = offset

                if self._on_progress:
                    self._on_progress(progress)

                # Retry interval
                time.sleep(self.retry_interval_ms / 1000.0)

            # Send end-of-transfer control packet
            end_packet = struct.pack("<B I", PKT_TYPE_CTRL_END, seq)
            try:
                sock.sendto(end_packet, (target_address, self.broadcast_port))
            except OSError:
                pass

            progress.status = "Complete"
            progress.result_code = RESULT_SUCCESS
            self._log(
                f"Firmware upload complete: {total} bytes in "
                f"{progress.elapsed_seconds:.1f}s"
            )

        except Exception as e:
            progress.status = "Error"
            progress.error_message = str(e)
            self._log(f"Firmware upload error: {e}")
        finally:
            try:
                sock.close()
            except OSError:
                pass

            if self._on_progress:
                self._on_progress(progress)

    @staticmethod
    def get_network_interfaces() -> List[Dict[str, str]]:
        """Get list of available network interfaces."""
        interfaces = []
        try:
            hostname = socket.gethostname()
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
            seen = set()
            for addr in addrs:
                ip = addr[4][0]
                if ip not in seen and not ip.startswith("127."):
                    seen.add(ip)
                    interfaces.append({"name": ip, "address": ip})
        except OSError:
            pass

        # Always include the any address
        interfaces.insert(0, {"name": "All interfaces (0.0.0.0)", "address": "0.0.0.0"})
        return interfaces

    @staticmethod
    def result_message(code: int) -> str:
        """Get human-readable message for a result code."""
        return RESULT_MESSAGES.get(code, f"Unknown error (0x{code:08X})")
