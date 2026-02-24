"""
OBSC protocol packet definitions for hwflash.
"""

import struct
import zlib
from enum import IntEnum

# Default OBSC ports
OBSC_SEND_PORT = 50000
OBSC_RECV_PORT = 50001


class PacketType(IntEnum):
    DISCOVERY = 0x01
    DISCOVERY_REPLY = 0x02
    CTRL_START = 0x03
    CTRL_ACK = 0x04
    DATA = 0x05
    DATA_ACK = 0x06
    RESULT = 0x07
    RESULT_ACK = 0x08


class FlashMode(IntEnum):
    NORMAL = 0
    FORCED = 1


class UpgradeType(IntEnum):
    STANDARD = 0
    EQUIPMENT = 1
    EQUIPMENT_WC = 2


RESULT_SUCCESS = 0x00000000
RESULT_CODES = {
    0x00000000: "Success",
    0xF720404F: "Firmware verification failed",
    0xF7204050: "Hardware compatibility check failed",
    0xF7204007: "Communication error",
    0xF7204028: "Transfer timeout",
    0xF7204045: "Flash write error",
}


class DiscoveryPacket:
    """OBSC discovery broadcast packet."""

    HEADER_FMT = '<BBHI'

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
            self.packet_type, 1,
            self.session_id, self.sequence, self.total_frames
        ) + self.data


class ResponsePacket:
    """OBSC response packet (placeholder)."""
    pass
