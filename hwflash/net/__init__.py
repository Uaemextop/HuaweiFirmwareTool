"""Network subpackage for hwflash."""
from hwflash.net.adapter import NetworkAdapter, discover_adapters
from hwflash.net.transport import UDPTransport, OBSC_SEND_PORT, OBSC_RECV_PORT, list_serial_ports
from hwflash.net.ipconfig import configure_adapter_ip, set_adapter_dhcp, test_socket_bind

__all__ = [
    'NetworkAdapter', 'discover_adapters',
    'UDPTransport', 'OBSC_SEND_PORT', 'OBSC_RECV_PORT', 'list_serial_ports',
    'configure_adapter_ip', 'set_adapter_dhcp', 'test_socket_bind',
]
