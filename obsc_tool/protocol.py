"""
OBSC protocol implementation for Huawei ONT firmware flashing.

Implements the OBSC (ONT Bootloader Service Client) UDP-based protocol
used to discover and flash firmware to Huawei ONT devices on the
local network.

Protocol flow:
  1. Discovery: Broadcast discovery packets, ONTs in bootloader respond
  2. Control: Send control packet with firmware metadata
  3. Data: Fragment and send firmware data in frames
  4. Verify: ONT validates CRC32/HWNP signature, writes to flash
"""

import struct
import zlib
import time
import threading
import logging
from enum import IntEnum

logger = logging.getLogger("obsc_tool.protocol")


# ── OBSC Protocol Constants ──────────────────────────────────────

# Default OBSC ports
OBSC_SEND_PORT = 50000
OBSC_RECV_PORT = 50001

# Packet types
class PacketType(IntEnum):
    DISCOVERY = 0x01
    DISCOVERY_REPLY = 0x02
    CTRL_START = 0x03
    CTRL_ACK = 0x04
    DATA = 0x05
    DATA_ACK = 0x06
    RESULT = 0x07
    RESULT_ACK = 0x08


# Flash modes
class FlashMode(IntEnum):
    NORMAL = 0
    FORCED = 1


# Upgrade types
class UpgradeType(IntEnum):
    STANDARD = 0
    EQUIPMENT = 1
    EQUIPMENT_WC = 2


# Result codes
RESULT_SUCCESS = 0x00000000
RESULT_CODES = {
    0x00000000: "Success",
    0xF720404F: "Firmware verification failed",
    0xF7204050: "Hardware compatibility check failed",
    0xF7204007: "Communication error",
    0xF7204028: "Transfer timeout",
    0xF7204045: "Flash write error",
}


# ── OBSC Packet Structures ──────────────────────────────────────

class DiscoveryPacket:
    """OBSC discovery broadcast packet."""

    HEADER_FMT = '<BBHI'  # type, version, flags, session_id

    def __init__(self, session_id=0):
        self.packet_type = PacketType.DISCOVERY
        self.version = 1
        self.flags = 0
        self.session_id = session_id

    def serialize(self):
        return struct.pack(
            self.HEADER_FMT,
            self.packet_type, self.version,
            self.flags, self.session_id
        )


class ControlPacket:
    """OBSC control packet with firmware metadata."""

    def __init__(self, session_id=0, firmware_size=0, firmware_crc32=0,
                 frame_size=1400, frame_interval=5, flash_mode=FlashMode.NORMAL,
                 delete_cfg=False, version_pkg=""):
        self.packet_type = PacketType.CTRL_START
        self.version = 1
        self.session_id = session_id
        self.firmware_size = firmware_size
        self.firmware_crc32 = firmware_crc32
        self.frame_size = frame_size
        self.frame_interval = frame_interval
        self.flash_mode = flash_mode
        self.delete_cfg = delete_cfg
        self.version_pkg = version_pkg

    def serialize(self):
        # Header: type(1) + version(1) + session_id(4)
        # Payload: fw_size(4) + fw_crc32(4) + frame_size(4) + frame_interval(4)
        #          + flash_mode(1) + delete_cfg(1) + version(64)
        version_bytes = self.version_pkg.encode('ascii')[:63].ljust(64, b'\x00')
        return struct.pack(
            '<BBIIIIIBB',
            self.packet_type, self.version, self.session_id,
            self.firmware_size, self.firmware_crc32,
            self.frame_size, self.frame_interval,
            self.flash_mode, 1 if self.delete_cfg else 0
        ) + version_bytes


class DataPacket:
    """OBSC data packet with firmware fragment."""

    def __init__(self, session_id=0, sequence=0, total_frames=0, data=b""):
        self.packet_type = PacketType.DATA
        self.session_id = session_id
        self.sequence = sequence
        self.total_frames = total_frames
        self.data = data

    def serialize(self):
        return struct.pack(
            '<BBIII',
            self.packet_type, 1,  # version
            self.session_id, self.sequence, self.total_frames
        ) + self.data


# ── Device Info ──────────────────────────────────────────────────

class ONTDevice:
    """Discovered ONT device information."""

    __slots__ = ('ip', 'mac', 'board_sn', 'sn_21', 'model',
                 'version', 'status', 'last_seen')

    def __init__(self):
        self.ip = ""
        self.mac = ""
        self.board_sn = ""
        self.sn_21 = ""
        self.model = ""
        self.version = ""
        self.status = "Discovered"
        self.last_seen = 0.0

    def __repr__(self):
        return f"ONTDevice({self.ip}, {self.board_sn}, {self.status})"


# ── OBSC Worker ──────────────────────────────────────────────────

class OBSCWorker:
    """Main OBSC protocol worker that handles firmware transfer.

    This class manages the complete lifecycle of a firmware flash
    operation: discovery, control, data transfer, and result handling.

    Events are reported through callback functions.
    """

    def __init__(self, transport, adapter):
        """Initialize the OBSC worker.

        Args:
            transport: UDPTransport instance for network communication.
            adapter: NetworkAdapter to use for communication.
        """
        self.transport = transport
        self.adapter = adapter

        # Configuration
        self.frame_size = 1400
        self.frame_interval_ms = 5
        self.flash_mode = FlashMode.NORMAL
        self.delete_cfg = False
        self.upgrade_type = UpgradeType.STANDARD
        self.machine_filter = ""
        self.timeout = 600  # 10 minutes
        self.ctrl_retries = 3
        self.data_retries = 0

        # State
        self._running = False
        self._thread = None
        self._devices = {}
        self._session_id = 0
        self._lock = threading.Lock()

        # Callbacks
        self.on_device_found = None
        self.on_progress = None
        self.on_status = None
        self.on_complete = None
        self.on_error = None
        self.on_log = None

    @property
    def is_running(self):
        return self._running

    def start_discovery(self, duration=10):
        """Start device discovery in a background thread.

        Args:
            duration: How long to listen for responses (seconds).
        """
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._discovery_loop,
            args=(duration,),
            daemon=True,
            name="obsc-discovery"
        )
        self._thread.start()

    def start_upgrade(self, firmware_data, version_pkg=""):
        """Start firmware upgrade in a background thread.

        Args:
            firmware_data: Raw firmware bytes to send.
            version_pkg: Version string for the firmware package.
        """
        if self._running:
            return

        self._running = True
        self._session_id = int(time.time()) & 0xFFFFFFFF
        self._thread = threading.Thread(
            target=self._upgrade_loop,
            args=(firmware_data, version_pkg),
            daemon=True,
            name="obsc-upgrade"
        )
        self._thread.start()

    def stop(self):
        """Stop any running operation."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None

    def _emit(self, callback, *args):
        """Safely call a callback."""
        if callback:
            try:
                callback(*args)
            except Exception as e:
                logger.error("Callback error: %s", e)

    def _discovery_loop(self, duration):
        """Discovery thread main loop."""
        try:
            self._emit(self.on_status, "Discovering devices...")
            self._emit(self.on_log, "Starting device discovery...")

            broadcast_ip = self.adapter.broadcast_address()
            discovery_pkt = DiscoveryPacket(session_id=0).serialize()

            end_time = time.time() + duration

            while self._running and time.time() < end_time:
                # Send discovery broadcast
                try:
                    self.transport.send(discovery_pkt, broadcast_ip, OBSC_SEND_PORT)
                except OSError as e:
                    logger.warning("Send error: %s", e)

                # Listen for responses
                data, addr = self.transport.receive(timeout=1.0)
                if data and addr and len(data) >= 8:
                    self._handle_discovery_reply(data, addr)

            self._emit(self.on_status, f"Discovery complete. {len(self._devices)} device(s) found.")
            self._emit(self.on_log, f"Discovery finished: {len(self._devices)} device(s)")

        except Exception as e:
            self._emit(self.on_error, f"Discovery error: {e}")
            logger.exception("Discovery error")
        finally:
            self._running = False

    def _handle_discovery_reply(self, data, addr):
        """Process a discovery reply from an ONT device."""
        ip = addr[0]
        if ip in self._devices:
            self._devices[ip].last_seen = time.time()
            return

        device = ONTDevice()
        device.ip = ip
        device.last_seen = time.time()

        # Parse reply payload if available
        if len(data) >= 8:
            pkt_type = data[0]
            if pkt_type == PacketType.DISCOVERY_REPLY:
                # Extract device info from reply
                # Format varies by firmware version, parse what we can
                try:
                    if len(data) >= 32:
                        # Try to extract serial number
                        sn_data = data[8:32]
                        null_pos = sn_data.find(b'\x00')
                        if null_pos > 0:
                            device.board_sn = sn_data[:null_pos].decode('ascii', errors='replace')
                    if len(data) >= 56:
                        mac_data = data[32:38]
                        device.mac = ':'.join(f'{b:02X}' for b in mac_data)
                except (ValueError, IndexError):
                    pass

        with self._lock:
            self._devices[ip] = device

        self._emit(self.on_device_found, device)
        self._emit(self.on_log, f"Device found: {ip} (SN: {device.board_sn})")

    def _upgrade_loop(self, firmware_data, version_pkg):
        """Firmware upgrade thread main loop."""
        try:
            fw_size = len(firmware_data)
            fw_crc32 = zlib.crc32(firmware_data) & 0xFFFFFFFF
            total_frames = (fw_size + self.frame_size - 1) // self.frame_size

            self._emit(self.on_status, "Starting firmware upgrade...")
            self._emit(self.on_log,
                       f"Firmware: {fw_size:,} bytes, CRC32: 0x{fw_crc32:08X}, "
                       f"Frames: {total_frames}, Size: {self.frame_size}, "
                       f"Interval: {self.frame_interval_ms}ms")

            broadcast_ip = self.adapter.broadcast_address()

            # Phase 1: Send control packet
            ctrl = ControlPacket(
                session_id=self._session_id,
                firmware_size=fw_size,
                firmware_crc32=fw_crc32,
                frame_size=self.frame_size,
                frame_interval=self.frame_interval_ms,
                flash_mode=self.flash_mode,
                delete_cfg=self.delete_cfg,
                version_pkg=version_pkg,
            )
            self._emit(self.on_log, "Sending control packet...")

            for _ in range(self.ctrl_retries):  # Retry control packet
                if not self._running:
                    return
                try:
                    self.transport.send(ctrl.serialize(), broadcast_ip, OBSC_SEND_PORT)
                except OSError as e:
                    self._emit(self.on_log, f"Control send error: {e}")
                    continue

                # Wait for ACK
                data, addr = self.transport.receive(timeout=2.0)
                if data and len(data) >= 2 and data[0] == PacketType.CTRL_ACK:
                    self._emit(self.on_log, f"Control ACK received from {addr[0]}")
                    break
            else:
                # Continue even without ACK (some devices don't send one)
                self._emit(self.on_log, "No control ACK (continuing anyway)")

            # Phase 2: Send data frames
            self._emit(self.on_status, "Transferring firmware...")
            start_time = time.time()

            for seq in range(total_frames):
                if not self._running:
                    self._emit(self.on_status, "Upgrade cancelled")
                    self._emit(self.on_log, "Upgrade cancelled by user")
                    return

                offset = seq * self.frame_size
                chunk = firmware_data[offset:offset + self.frame_size]

                pkt = DataPacket(
                    session_id=self._session_id,
                    sequence=seq,
                    total_frames=total_frames,
                    data=chunk,
                )

                sent = False
                for attempt in range(max(1, self.data_retries + 1)):
                    try:
                        self.transport.send(pkt.serialize(), broadcast_ip, OBSC_SEND_PORT)
                        sent = True
                        break
                    except OSError as e:
                        if attempt < self.data_retries:
                            self._emit(self.on_log,
                                       f"Data send retry {attempt + 1} at frame {seq}: {e}")
                            time.sleep(0.01)
                        else:
                            self._emit(self.on_error,
                                       f"Data send error at frame {seq}: {e}")
                            return

                if not sent:
                    return

                # Progress callback
                progress = (seq + 1) / total_frames * 100
                if seq % max(1, total_frames // 100) == 0 or seq == total_frames - 1:
                    elapsed = time.time() - start_time
                    speed = (offset + len(chunk)) / max(0.001, elapsed)
                    eta = (fw_size - offset - len(chunk)) / max(1, speed)
                    self._emit(
                        self.on_progress, progress,
                        f"{progress:.1f}% | {speed / 1024:.0f} KB/s | ETA: {eta:.0f}s"
                    )

                # Frame interval delay
                if self.frame_interval_ms > 0:
                    time.sleep(self.frame_interval_ms / 1000.0)

            # Phase 3: Wait for result
            self._emit(self.on_status, "Waiting for device confirmation...")
            self._emit(self.on_log, "All frames sent. Waiting for result...")

            result_timeout = time.time() + 120  # 2 minutes for flash

            while self._running and time.time() < result_timeout:
                data, addr = self.transport.receive(timeout=2.0)
                if data and len(data) >= 6 and data[0] == PacketType.RESULT:
                    result_code = struct.unpack_from('<I', data, 2)[0]
                    result_msg = RESULT_CODES.get(result_code, f"Unknown (0x{result_code:08X})")

                    if result_code == RESULT_SUCCESS:
                        self._emit(self.on_status, f"Upgrade successful!")
                        self._emit(self.on_progress, 100, "Complete")
                    else:
                        self._emit(self.on_status, f"Upgrade failed: {result_msg}")

                    self._emit(self.on_log,
                               f"Result from {addr[0]}: 0x{result_code:08X} ({result_msg})")
                    self._emit(self.on_complete, result_code == RESULT_SUCCESS, result_msg)
                    return

            # Timeout
            elapsed_total = time.time() - start_time
            self._emit(self.on_status, f"Transfer complete ({elapsed_total:.0f}s). Device may be rebooting.")
            self._emit(self.on_log, "No result packet received (device may have rebooted)")
            self._emit(self.on_complete, True, "Transfer complete (no confirmation)")

        except Exception as e:
            self._emit(self.on_error, f"Upgrade error: {e}")
            logger.exception("Upgrade error")
        finally:
            self._running = False
