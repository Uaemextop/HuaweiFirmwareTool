"""Network data models."""


class NetworkAdapter:
    """Represents a network interface/adapter."""

    __slots__ = ('name', 'ip', 'netmask', 'mac', 'description', 'index',
                 'gateway', 'status', 'speed', 'dhcp_enabled')

    def __init__(self, name="", ip="", netmask="", mac="", description="",
                 index=0, gateway="", status="Up", speed="", dhcp_enabled=False):
        """
        Initialize network adapter.

        Args:
            name: Adapter name
            ip: IP address
            netmask: Network mask
            mac: MAC address
            description: Human-readable description
            index: Interface index
            gateway: Gateway address
            status: Connection status
            speed: Link speed
            dhcp_enabled: Whether DHCP is enabled
        """
        self.name = name
        self.ip = ip
        self.netmask = netmask
        self.mac = mac
        self.description = description
        self.index = index
        self.gateway = gateway
        self.status = status
        self.speed = speed
        self.dhcp_enabled = dhcp_enabled

    def __repr__(self):
        """String representation."""
        return f"NetworkAdapter({self.name}, {self.ip}, {self.mac})"

    def display_name(self):
        """User-friendly display string."""
        parts = []
        if self.description:
            parts.append(self.description)
        elif self.name:
            parts.append(self.name)
        if self.ip:
            parts.append(f"[{self.ip}]")
        if self.mac:
            parts.append(f"({self.mac})")
        return " ".join(parts) if parts else "Unknown Adapter"


class NetworkDevice:
    """Represents a discovered network device."""

    __slots__ = ('ip', 'mac', 'device_type', 'serial', 'firmware_version',
                 'hardware_version', 'last_seen', 'status')

    def __init__(self, ip="", mac="", device_type="", serial=""):
        """
        Initialize network device.

        Args:
            ip: Device IP address
            mac: Device MAC address
            device_type: Type of device
            serial: Serial number
        """
        self.ip = ip
        self.mac = mac
        self.device_type = device_type
        self.serial = serial
        self.firmware_version = ""
        self.hardware_version = ""
        self.last_seen = 0.0
        self.status = "Unknown"

    def __repr__(self):
        """String representation."""
        return f"NetworkDevice({self.ip}, {self.mac}, {self.device_type})"
