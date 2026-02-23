"""
UDP Broadcast Engine for Huawei ONT Firmware Upgrade Tool.

Implements the UDP-based firmware broadcast protocol used to upgrade
Huawei ONT (Optical Network Terminal) devices.

The Huawei ONT upgrade protocol works as follows:
  1. The tool broadcasts an HWNP firmware package over UDP to the
     local subnet (or 255.255.255.255).
  2. ONT devices on the network receive the broadcast and check
     compatibility via the embedded UpgradeCheck.xml.
  3. Compatible ONTs flash the firmware package and execute any
     embedded scripts (e.g. duit9rr.sh, run.sh).
  4. The ONT logs the result, then reboots.

Log format (matches original OBSCTool):
  2025-02-19 20:33:39 [ONT_SN][EQUIP_SN] Start upgrade!
  2025-02-19 20:42:22 [ONT_SN][EQUIP_SN] Finish upgrade!uiRet=0x0

Known return codes:
  0x00000000 – Success
  0xf720404f – Error: rejected / version incompatible
  0xf7204028 – Error: signature mismatch
  0xf7204007 – Error: device busy / connection refused
  0xf7204050 – Error: timeout
"""

import socket
import struct
import threading
import time
import logging
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional

from .hwnp import HWNPPackage

logger = logging.getLogger(__name__)

# Protocol constants
HWNP_MAGIC          = b'HWNP'
DISCOVERY_PORT      = 53282       # Common Huawei ONT upgrade port
RESPONSE_PORT       = 53283       # ONT response port
CHUNK_SIZE_DEFAULT  = 1024        # bytes per UDP packet
MAX_PACKET_SIZE     = 65507       # max UDP payload


class DeviceStatus(Enum):
    DISCOVERED  = auto()
    UPGRADING   = auto()
    SUCCESS     = auto()
    FAILED      = auto()
    TIMEOUT     = auto()


@dataclass
class DeviceSession:
    """Tracks the upgrade state of a single ONT device."""
    ont_sn: str
    equip_sn: str
    ip: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: DeviceStatus = DeviceStatus.DISCOVERED
    ret_code: int = 0
    bytes_sent: int = 0
    total_bytes: int = 0

    @property
    def log_id(self) -> str:
        return f"[{self.ont_sn}][{self.equip_sn}]"

    @property
    def duration_s(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def progress_pct(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return min(100.0, self.bytes_sent / self.total_bytes * 100)


# Type alias for callbacks
LogCallback     = Callable[[str], None]
DeviceCallback  = Callable[[DeviceSession], None]
StatusCallback  = Callable[[str], None]


class BroadcastEngine:
    """
    UDP broadcast engine that sends HWNP firmware packages to Huawei ONT
    devices on the local network.
    """

    def __init__(
        self,
        broadcast_addr: str = '255.255.255.255',
        port: int = DISCOVERY_PORT,
        interface_ip: str = '',
        packet_interval_ms: int = 5,
        operation_timeout_s: int = 60,
        retry_count: int = 3,
        chunk_size: int = CHUNK_SIZE_DEFAULT,
    ):
        self.broadcast_addr     = broadcast_addr
        self.port               = port
        self.interface_ip       = interface_ip
        self.packet_interval_ms = packet_interval_ms
        self.operation_timeout_s = operation_timeout_s
        self.retry_count        = retry_count
        self.chunk_size         = chunk_size

        self._socket: Optional[socket.socket] = None
        self._running  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock     = threading.Lock()

        self._sessions: Dict[str, DeviceSession] = {}

        # Callbacks
        self.on_log:    Optional[LogCallback]    = None
        self.on_device: Optional[DeviceCallback] = None
        self.on_status: Optional[StatusCallback] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, package: HWNPPackage) -> None:
        """Start broadcasting the given HWNP package in a background thread."""
        if self._running.is_set():
            self._log("Already running – stop first")
            return

        if not package.is_valid:
            self._log("ERROR: Invalid HWNP package")
            return

        self._sessions.clear()
        self._running.set()
        self._thread = threading.Thread(
            target=self._broadcast_loop,
            args=(package,),
            daemon=True,
        )
        self._thread.start()
        self._log(f"Broadcast started → {self.broadcast_addr}:{self.port}")

    def stop(self) -> None:
        """Stop the broadcast engine."""
        self._running.clear()
        self._close_socket()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._log("Broadcast stopped")

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def sessions(self) -> List[DeviceSession]:
        with self._lock:
            return list(self._sessions.values())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f"{ts} {msg}"
        logger.info(msg)
        if self.on_log:
            self.on_log(line)

    def _status(self, msg: str) -> None:
        if self.on_status:
            self.on_status(msg)

    def _notify_device(self, session: DeviceSession) -> None:
        if self.on_device:
            self.on_device(session)

    def _open_socket(self) -> socket.socket:
        """Open a UDP broadcast socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.0)

        if self.interface_ip:
            try:
                sock.bind((self.interface_ip, 0))
            except OSError as e:
                logger.warning("Could not bind to %s: %s", self.interface_ip, e)

        return sock

    def _close_socket(self) -> None:
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _send_packet(self, data: bytes, sock: socket.socket) -> bool:
        """Send a single UDP packet. Returns True on success."""
        try:
            sock.sendto(data, (self.broadcast_addr, self.port))
            return True
        except OSError as e:
            logger.debug("sendto error: %s", e)
            return False

    def _broadcast_loop(self, package: HWNPPackage) -> None:
        """Main broadcast loop running in background thread."""
        try:
            self._socket = self._open_socket()
            self._status("Broadcasting…")
            self._log(
                f"Package: {package.size_kb:.1f} KB, "
                f"{package.item_counts} items, "
                f"products: {package.product_list[:40] or 'all'}"
            )

            payload = package.raw_bytes
            total   = len(payload)
            interval = self.packet_interval_ms / 1000.0

            # Track a synthetic session for broadcast progress display
            session = DeviceSession(
                ont_sn='BROADCAST',
                equip_sn='--',
                ip=self.broadcast_addr,
                start_time=datetime.now(),
                total_bytes=total,
                status=DeviceStatus.UPGRADING,
            )
            self._log(f"{session.log_id} Start upgrade!")
            with self._lock:
                self._sessions[session.ont_sn] = session
            self._notify_device(session)

            # Send the HWNP package in chunks
            offset = 0
            attempt = 0
            while self._running.is_set() and offset < total:
                chunk = payload[offset: offset + self.chunk_size]
                sent  = self._send_packet(chunk, self._socket)

                if sent:
                    offset += len(chunk)
                    session.bytes_sent = offset
                    self._notify_device(session)
                else:
                    attempt += 1
                    if attempt >= self.retry_count:
                        session.status   = DeviceStatus.FAILED
                        session.ret_code = 0xF7204007
                        session.end_time = datetime.now()
                        self._log(
                            f"{session.log_id} Finish upgrade!"
                            f"uiRet=0x{session.ret_code:08X}"
                        )
                        self._notify_device(session)
                        self._running.clear()
                        return

                # Respect packet interval
                if interval > 0:
                    time.sleep(interval)

            if self._running.is_set():
                # Completed
                session.status   = DeviceStatus.SUCCESS
                session.ret_code = 0x00000000
                session.end_time = datetime.now()
                self._log(
                    f"{session.log_id} Finish upgrade!"
                    f"uiRet=0x{session.ret_code:08X}"
                )
                self._status("Done – waiting for device reboot")
            else:
                session.status   = DeviceStatus.FAILED
                session.end_time = datetime.now()
                self._log(f"{session.log_id} Upgrade cancelled")
                self._status("Cancelled")

            self._notify_device(session)

        except Exception as e:
            self._log(f"ERROR: {e}")
            self._status(f"Error: {e}")
            logger.exception("Broadcast loop error")
        finally:
            self._close_socket()
            self._running.clear()
