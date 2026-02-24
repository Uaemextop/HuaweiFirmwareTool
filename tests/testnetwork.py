"""Tests for the network module."""

import socket
import struct
import pytest

from hwflash.core.network import (
    NetworkAdapter,
    UDPTransport,
    discover_adapters,
    test_socket_bind as _test_socket_bind,
)


class TestNetworkAdapter:
    """Test NetworkAdapter class."""

    def test_broadcast_address_class_c(self):
        adapter = NetworkAdapter(ip="192.168.1.100", netmask="255.255.255.0")
        assert adapter.broadcast_address() == "192.168.1.255"

    def test_broadcast_address_class_b(self):
        adapter = NetworkAdapter(ip="172.16.0.1", netmask="255.255.0.0")
        assert adapter.broadcast_address() == "172.16.255.255"

    def test_broadcast_address_slash_30(self):
        adapter = NetworkAdapter(ip="10.0.0.1", netmask="255.255.255.252")
        assert adapter.broadcast_address() == "10.0.0.3"

    def test_broadcast_address_no_ip(self):
        adapter = NetworkAdapter()
        assert adapter.broadcast_address() == "255.255.255.255"

    def test_broadcast_address_no_mask(self):
        adapter = NetworkAdapter(ip="192.168.1.1")
        assert adapter.broadcast_address() == "255.255.255.255"

    def test_display_name_full(self):
        adapter = NetworkAdapter(
            description="Ethernet", ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF"
        )
        name = adapter.display_name()
        assert "Ethernet" in name
        assert "192.168.1.1" in name
        assert "AA:BB:CC:DD:EE:FF" in name

    def test_display_name_minimal(self):
        adapter = NetworkAdapter()
        assert adapter.display_name() == "Unknown Adapter"

    def test_display_name_prefers_description(self):
        adapter = NetworkAdapter(name="eth0", description="Intel Ethernet")
        name = adapter.display_name()
        assert "Intel Ethernet" in name

    def test_details_dict(self):
        adapter = NetworkAdapter(
            name="eth0", ip="10.0.0.1", netmask="255.255.255.0",
            mac="AA:BB:CC:DD:EE:FF", gateway="10.0.0.254",
        )
        d = adapter.details_dict()
        assert d["Name"] == "eth0"
        assert d["IP Address"] == "10.0.0.1"
        assert d["Subnet Mask"] == "255.255.255.0"
        assert d["Gateway"] == "10.0.0.254"
        assert d["MAC Address"] == "AA:BB:CC:DD:EE:FF"

    def test_repr(self):
        adapter = NetworkAdapter(name="eth0", ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF")
        r = repr(adapter)
        assert "eth0" in r
        assert "1.2.3.4" in r


class TestUDPTransport:
    """Test UDP transport."""

    def test_open_close(self):
        transport = UDPTransport(bind_ip="127.0.0.1", bind_port=0, broadcast=False)
        transport.open()
        status = transport.get_status()
        assert status["state"] == "Open"
        transport.close()
        status = transport.get_status()
        assert status["state"] == "Closed"

    def test_context_manager(self):
        with UDPTransport(bind_ip="127.0.0.1", bind_port=0, broadcast=False) as t:
            assert t.sock is not None
        # After context exit, socket should be closed
        assert t.sock is None

    def test_send_receive_loopback(self):
        with UDPTransport(bind_ip="127.0.0.1", bind_port=0, broadcast=False) as t:
            # Get actual bound port
            local_addr = t.sock.getsockname()
            port = local_addr[1]
            # Send to self
            msg = b"test message"
            t.send(msg, "127.0.0.1", port)
            data, addr = t.receive(timeout=2.0)
            assert data == msg
            assert addr[0] == "127.0.0.1"

    def test_receive_timeout(self):
        with UDPTransport(bind_ip="127.0.0.1", bind_port=0, broadcast=False) as t:
            data, addr = t.receive(timeout=0.1)
            assert data is None
            assert addr is None

    def test_send_without_open_raises(self):
        transport = UDPTransport()
        with pytest.raises(RuntimeError, match="not open"):
            transport.send(b"test", "127.0.0.1")

    def test_receive_without_open_raises(self):
        transport = UDPTransport()
        with pytest.raises(RuntimeError, match="not open"):
            transport.receive()


class TestDiscoverAdapters:
    """Test adapter discovery."""

    def test_discover_returns_list(self):
        adapters = discover_adapters()
        assert isinstance(adapters, list)

    def test_no_loopback_in_results(self):
        adapters = discover_adapters()
        for a in adapters:
            assert a.ip != "127.0.0.1"


class TestSocketBind:
    """Test socket bind testing."""

    def test_bind_loopback(self):
        ok, msg = _test_socket_bind("127.0.0.1", 0, broadcast=False)
        assert ok is True
        assert "bound" in msg.lower()

    def test_bind_invalid_ip(self):
        ok, msg = _test_socket_bind("999.999.999.999", 0)
        assert ok is False
