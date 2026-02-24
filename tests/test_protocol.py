"""Tests for the OBSC protocol module."""

import struct
import pytest

from obsc_tool.protocol import (
    PacketType,
    FlashMode,
    UpgradeType,
    DiscoveryPacket,
    ControlPacket,
    DataPacket,
    ONTDevice,
    OBSCWorker,
    OBSC_SEND_PORT,
    OBSC_RECV_PORT,
    RESULT_CODES,
    RESULT_SUCCESS,
    MIN_FRAME_SIZE,
    MAX_FRAME_SIZE,
    MIN_FRAME_INTERVAL_MS,
    MAX_FRAME_INTERVAL_MS,
    MAX_FIRMWARE_SIZE,
)


class TestPacketSerialization:
    """Test packet serialization."""

    def test_discovery_packet(self):
        pkt = DiscoveryPacket(session_id=42)
        data = pkt.serialize()
        assert data[0] == PacketType.DISCOVERY
        assert data[1] == 1  # version
        session = struct.unpack_from('<I', data, 4)[0]
        assert session == 42

    def test_control_packet(self):
        pkt = ControlPacket(
            session_id=100,
            firmware_size=1024,
            firmware_crc32=0xDEADBEEF,
            frame_size=1400,
            frame_interval=5,
            flash_mode=FlashMode.FORCED,
            delete_cfg=True,
            version_pkg="V300R015C10SPC130",
        )
        data = pkt.serialize()
        assert data[0] == PacketType.CTRL_START
        # Verify firmware size field
        fw_size = struct.unpack_from('<I', data, 6)[0]
        assert fw_size == 1024
        # Verify CRC32 field
        fw_crc = struct.unpack_from('<I', data, 10)[0]
        assert fw_crc == 0xDEADBEEF

    def test_data_packet(self):
        payload = b'\xFF' * 100
        pkt = DataPacket(session_id=1, sequence=5, total_frames=100, data=payload)
        data = pkt.serialize()
        assert data[0] == PacketType.DATA
        seq = struct.unpack_from('<I', data, 6)[0]
        assert seq == 5
        total = struct.unpack_from('<I', data, 10)[0]
        assert total == 100
        assert data[14:] == payload

    def test_control_packet_version_truncation(self):
        long_version = "V" * 100  # exceeds 63 byte limit
        pkt = ControlPacket(version_pkg=long_version)
        data = pkt.serialize()
        # Version field is 64 bytes at the end
        version_part = data[-64:]
        assert len(version_part) == 64
        # Should be truncated to 63 chars + null
        assert version_part[-1] == 0


class TestONTDevice:
    """Test ONT device info."""

    def test_default_values(self):
        dev = ONTDevice()
        assert dev.ip == ""
        assert dev.mac == ""
        assert dev.status == "Discovered"

    def test_repr(self):
        dev = ONTDevice()
        dev.ip = "192.168.1.1"
        dev.board_sn = "HG8145V5"
        r = repr(dev)
        assert "192.168.1.1" in r
        assert "HG8145V5" in r


class TestOBSCWorkerValidation:
    """Test OBSCWorker parameter validation."""

    def _make_worker(self):
        """Create a worker with mock transport/adapter."""

        class MockTransport:
            pass

        class MockAdapter:
            def broadcast_address(self):
                return "255.255.255.255"

        return OBSCWorker(MockTransport(), MockAdapter())

    def test_empty_firmware_raises(self):
        worker = self._make_worker()
        with pytest.raises(ValueError, match="No firmware data"):
            worker.start_upgrade(b"")

    def test_firmware_too_large_raises(self):
        worker = self._make_worker()
        # Don't actually allocate 256MB, just test the validation path
        # by temporarily lowering the check
        large_data = b'\x00' * (MAX_FIRMWARE_SIZE + 1)
        with pytest.raises(ValueError, match="too large"):
            worker.start_upgrade(large_data)

    def test_invalid_frame_size_raises(self):
        worker = self._make_worker()
        worker.frame_size = 0
        with pytest.raises(ValueError, match="frame_size"):
            worker.start_upgrade(b'\x00' * 100)

    def test_frame_size_too_large_raises(self):
        worker = self._make_worker()
        worker.frame_size = MAX_FRAME_SIZE + 1
        with pytest.raises(ValueError, match="frame_size"):
            worker.start_upgrade(b'\x00' * 100)

    def test_negative_frame_interval_raises(self):
        worker = self._make_worker()
        worker.frame_interval_ms = -1
        with pytest.raises(ValueError, match="frame_interval_ms"):
            worker.start_upgrade(b'\x00' * 100)

    def test_valid_params_no_raise(self):
        worker = self._make_worker()
        worker.frame_size = 1400
        worker.frame_interval_ms = 5
        # This will start the thread but immediately return
        # since transport is mock and will fail
        worker.start_upgrade(b'\x00' * 100)
        worker.stop()


class TestProtocolConstants:
    """Test protocol constants."""

    def test_ports(self):
        assert OBSC_SEND_PORT == 50000
        assert OBSC_RECV_PORT == 50001

    def test_result_codes(self):
        assert RESULT_SUCCESS == 0x00000000
        assert RESULT_SUCCESS in RESULT_CODES
        assert "Success" in RESULT_CODES[RESULT_SUCCESS]

    def test_packet_types(self):
        assert PacketType.DISCOVERY == 0x01
        assert PacketType.DISCOVERY_REPLY == 0x02
        assert PacketType.CTRL_START == 0x03
        assert PacketType.RESULT == 0x07

    def test_validation_limits(self):
        assert MIN_FRAME_SIZE > 0
        assert MAX_FRAME_SIZE < 65536
        assert MAX_FIRMWARE_SIZE > 0
