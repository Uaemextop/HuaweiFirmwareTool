"""
Tests for obsc_tool.protocol (OBSC packet serialization/deserialization).
"""

import struct

import pytest

from obsc_tool.protocol import (
    DiscoveryPacket,
    ControlPacket,
    DataPacket,
    PacketType,
    FlashMode,
    UpgradeType,
    OBSC_SEND_PORT,
    OBSC_RECV_PORT,
)


class TestDiscoveryPacket:
    def test_serializes_to_bytes(self):
        pkt = DiscoveryPacket(session_id=0x1234)
        data = pkt.serialize()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_packet_type_byte(self):
        pkt = DiscoveryPacket(session_id=0xABCD)
        data = pkt.serialize()
        assert data[0] == PacketType.DISCOVERY


class TestControlPacket:
    def test_serializes_to_bytes(self):
        pkt = ControlPacket(
            session_id=1,
            firmware_size=1024,
            frame_size=1400,
            flash_mode=FlashMode.NORMAL,
        )
        data = pkt.serialize()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_packet_type_byte(self):
        pkt = ControlPacket(
            session_id=2,
            firmware_size=2048,
            frame_size=1200,
            flash_mode=FlashMode.NORMAL,
        )
        data = pkt.serialize()
        assert data[0] == PacketType.CTRL_START


class TestDataPacket:
    def test_serializes_to_bytes(self):
        pkt = DataPacket(
            session_id=1,
            sequence=0,
            total_frames=100,
            data=b'\x00' * 1400,
        )
        raw = pkt.serialize()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_packet_type_byte(self):
        pkt = DataPacket(session_id=1, sequence=5, total_frames=10, data=b'hello')
        raw = pkt.serialize()
        assert raw[0] == PacketType.DATA

    def test_contains_payload(self):
        payload = b'FIRMWARE_CHUNK_DATA'
        pkt = DataPacket(session_id=1, sequence=0, total_frames=1, data=payload)
        raw = pkt.serialize()
        assert payload in raw

    def test_sequence_number_present(self):
        """Sequence number should appear in the serialized packet."""
        seq = 42
        pkt = DataPacket(session_id=1, sequence=seq, total_frames=100, data=b'X' * 8)
        raw = pkt.serialize()
        # Sequence should be encoded as a uint16 or uint32 somewhere in the packet
        packed16 = struct.pack('<H', seq)
        packed32 = struct.pack('<I', seq)
        assert packed16 in raw or packed32 in raw


class TestConstants:
    def test_send_port(self):
        assert OBSC_SEND_PORT == 50000

    def test_recv_port(self):
        assert OBSC_RECV_PORT == 50001

    def test_flash_mode_values(self):
        """FlashMode must have at least a Normal mode."""
        assert hasattr(FlashMode, 'NORMAL')

    def test_upgrade_type_values(self):
        """UpgradeType must have at least a Standard type."""
        assert hasattr(UpgradeType, 'STANDARD')
