"""
OBSC protocol worker for hwflash.
"""

import struct
import zlib
import time
import threading
import logging

from hwflash.proto.packets import (
    PacketType, FlashMode, UpgradeType,
    OBSC_SEND_PORT, OBSC_RECV_PORT,
    RESULT_SUCCESS, RESULT_CODES,
    DiscoveryPacket, ControlPacket, DataPacket,
)

logger = logging.getLogger("hwflash.proto.worker")


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
        self.timeout = 600
        self.ctrl_retries = 3
        self.data_retries = 0
        self.multicast_addr = None

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
        """Start device discovery in a background thread."""
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
        """Start firmware upgrade in a background thread."""
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
                try:
                    self.transport.send(discovery_pkt, broadcast_ip, OBSC_SEND_PORT)
                except OSError as e:
                    logger.warning("Broadcast send error: %s", e)

                if self.multicast_addr:
                    try:
                        self.transport.send(
                            discovery_pkt, self.multicast_addr, OBSC_SEND_PORT)
                    except OSError as e:
                        logger.warning("Multicast send error: %s", e)

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

        if len(data) >= 8:
            pkt_type = data[0]
            if pkt_type == PacketType.DISCOVERY_REPLY:
                try:
                    if len(data) >= 32:
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

            for _ in range(self.ctrl_retries):
                if not self._running:
                    return
                try:
                    self.transport.send(ctrl.serialize(), broadcast_ip, OBSC_SEND_PORT)
                    if self.multicast_addr:
                        self.transport.send(
                            ctrl.serialize(), self.multicast_addr, OBSC_SEND_PORT)
                except OSError as e:
                    self._emit(self.on_log, f"Control send error: {e}")
                    continue

                data, addr = self.transport.receive(timeout=2.0)
                if data and len(data) >= 2 and data[0] == PacketType.CTRL_ACK:
                    self._emit(self.on_log, f"Control ACK received from {addr[0]}")
                    break
            else:
                self._emit(self.on_log, "No control ACK (continuing anyway)")

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

                for attempt in range(self.data_retries + 1):
                    try:
                        self.transport.send(pkt.serialize(), broadcast_ip, OBSC_SEND_PORT)
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

                progress = (seq + 1) / total_frames * 100
                if seq % max(1, total_frames // 100) == 0 or seq == total_frames - 1:
                    elapsed = time.time() - start_time
                    speed = (offset + len(chunk)) / max(0.001, elapsed)
                    eta = (fw_size - offset - len(chunk)) / max(1, speed)
                    self._emit(
                        self.on_progress, progress,
                        f"{progress:.1f}% | {speed / 1024:.0f} KB/s | ETA: {eta:.0f}s"
                    )

                if self.frame_interval_ms > 0:
                    time.sleep(self.frame_interval_ms / 1000.0)

            self._emit(self.on_status, "Waiting for device confirmation...")
            self._emit(self.on_log, "All frames sent. Waiting for result...")

            result_timeout = time.time() + 120

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

            elapsed_total = time.time() - start_time
            self._emit(self.on_status, f"Transfer complete ({elapsed_total:.0f}s). Device may be rebooting.")
            self._emit(self.on_log, "No result packet received (device may have rebooted)")
            self._emit(self.on_complete, True, "Transfer complete (no confirmation)")

        except Exception as e:
            self._emit(self.on_error, f"Upgrade error: {e}")
            logger.exception("Upgrade error")
        finally:
            self._running = False
