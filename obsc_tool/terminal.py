"""
Serial and Telnet terminal for Huawei ONT device console access.

Provides terminal emulation over:
  - Telnet (port 23): Available after flashing telnet-enable firmware
  - Serial (COM port): Direct hardware connection to ONT UART

Also includes firmware dump commands that can be executed over
an active terminal session.
"""

import socket
import threading
import time
import logging
import re

logger = logging.getLogger("obsc_tool.terminal")


# ── Telnet Protocol Constants ───────────────────────────────────

TELNET_IAC = 0xFF    # Interpret As Command
TELNET_DONT = 0xFE
TELNET_DO = 0xFD
TELNET_WONT = 0xFC
TELNET_WILL = 0xFB
TELNET_SB = 0xFA     # Subnegotiation Begin
TELNET_SE = 0xF0     # Subnegotiation End

# Telnet options
TELOPT_ECHO = 0x01
TELOPT_SGA = 0x03     # Suppress Go Ahead
TELOPT_TTYPE = 0x18   # Terminal Type
TELOPT_NAWS = 0x1F    # Negotiate About Window Size
TELOPT_LINEMODE = 0x22


# ── Common ONT Shell Commands ───────────────────────────────────

# These are commands commonly available on Huawei ONT devices
# after enabling telnet access via the unlock firmware
ONT_COMMANDS = {
    'system_info': 'display sysinfo',
    'version': 'display version',
    'board_info': 'display board 0',
    'wan_info': 'display wan config',
    'optical_info': 'display optic 0',
    'cpu_info': 'display cpu',
    'memory_info': 'display memory',
    'flash_info': 'display flash',
    'mac': 'display mac',
    'serial_number': 'display sn',
    'config': 'display current-config',
    'mtd_partitions': 'cat /proc/mtd',
    'process_list': 'ps',
    'mount_points': 'mount',
    'kernel_version': 'uname -a',
}

# Firmware dump commands (executed over shell)
DUMP_COMMANDS = {
    'list_mtd': 'cat /proc/mtd',
    'dump_mtd': 'dd if=/dev/mtdblock{n} of=/tmp/mtd{n}.bin bs=4096',
    'list_tmp': 'ls -la /tmp/*.bin',
    'check_tftp': 'which tftp',
    'tftp_send': 'tftp -p -l /tmp/mtd{n}.bin {host}',
}


class TelnetClient:
    """Simple Telnet client for ONT device access.

    Handles Telnet protocol negotiation and provides a clean
    interface for sending commands and receiving output.
    """

    def __init__(self):
        self.sock = None
        self.host = ""
        self.port = 23
        self.timeout = 10.0
        self._connected = False
        self._recv_buffer = bytearray()
        self._recv_thread = None
        self._running = False
        self._lock = threading.Lock()

        # Callbacks
        self.on_data = None      # Called with received text
        self.on_connect = None   # Called on successful connection
        self.on_disconnect = None  # Called on disconnect
        self.on_error = None     # Called on error

    @property
    def connected(self):
        return self._connected

    def connect(self, host, port=23, timeout=10.0):
        """Connect to the ONT device via Telnet.

        Args:
            host: IP address of the ONT device.
            port: Telnet port (default 23).
            timeout: Connection timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((host, port))
            self._connected = True
            self._running = True

            # Start receive thread
            self._recv_thread = threading.Thread(
                target=self._receive_loop,
                daemon=True,
                name="telnet-recv"
            )
            self._recv_thread.start()

            if self.on_connect:
                self.on_connect(host, port)

            logger.info("Connected to %s:%d", host, port)

        except (socket.error, OSError) as e:
            self._connected = False
            if self.on_error:
                self.on_error(f"Connection failed: {e}")
            raise

    def disconnect(self):
        """Disconnect from the device."""
        self._running = False
        self._connected = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2)

        if self.on_disconnect:
            self.on_disconnect()

        logger.info("Disconnected from %s", self.host)

    def send(self, data):
        """Send raw bytes to the device.

        Args:
            data: Bytes or string to send.
        """
        if not self._connected or not self.sock:
            return

        if isinstance(data, str):
            data = data.encode('ascii', errors='replace')

        try:
            self.sock.sendall(data)
        except (socket.error, OSError) as e:
            logger.error("Send error: %s", e)
            self.disconnect()

    def send_command(self, command):
        """Send a command with newline.

        Args:
            command: Command string.
        """
        self.send(command + "\r\n")

    def send_line(self, line):
        """Send a line of text with CR+LF.

        Args:
            line: Text to send.
        """
        self.send(line + "\r\n")

    def _receive_loop(self):
        """Background thread to receive data."""
        while self._running and self._connected:
            try:
                self.sock.settimeout(0.5)
                data = self.sock.recv(4096)
                if not data:
                    # Connection closed
                    self._connected = False
                    if self.on_disconnect:
                        self.on_disconnect()
                    break

                # Process telnet negotiations
                clean_data = self._process_telnet(data)
                if clean_data and self.on_data:
                    self.on_data(clean_data)

            except socket.timeout:
                continue
            except (socket.error, OSError) as e:
                if self._running:
                    logger.error("Receive error: %s", e)
                    self._connected = False
                    if self.on_disconnect:
                        self.on_disconnect()
                break

    def _process_telnet(self, data):
        """Process telnet protocol bytes and return clean text.

        Handles IAC sequences and option negotiation.

        Args:
            data: Raw bytes from socket.

        Returns:
            Clean text string.
        """
        clean = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b == TELNET_IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd == TELNET_IAC:
                    # Escaped IAC = literal 0xFF
                    clean.append(0xFF)
                    i += 2
                elif cmd in (TELNET_DO, TELNET_DONT, TELNET_WILL, TELNET_WONT):
                    if i + 2 < len(data):
                        opt = data[i + 2]
                        self._negotiate(cmd, opt)
                        i += 3
                    else:
                        i += 2
                elif cmd == TELNET_SB:
                    # Skip subnegotiation
                    end = data.find(bytes([TELNET_IAC, TELNET_SE]), i + 2)
                    if end >= 0:
                        i = end + 2
                    else:
                        i += 2
                else:
                    i += 2
            else:
                clean.append(b)
                i += 1

        # Decode to text
        try:
            return clean.decode('utf-8', errors='replace')
        except (UnicodeDecodeError, ValueError):
            return clean.decode('ascii', errors='replace')

    def _negotiate(self, cmd, opt):
        """Handle telnet option negotiation.

        Responds with WILL for SGA and ECHO, WONT for everything else.
        """
        if cmd == TELNET_DO:
            if opt in (TELOPT_SGA, TELOPT_ECHO):
                response = bytes([TELNET_IAC, TELNET_WILL, opt])
            else:
                response = bytes([TELNET_IAC, TELNET_WONT, opt])
            self.send(response)
        elif cmd == TELNET_WILL:
            if opt in (TELOPT_SGA, TELOPT_ECHO):
                response = bytes([TELNET_IAC, TELNET_DO, opt])
            else:
                response = bytes([TELNET_IAC, TELNET_DONT, opt])
            self.send(response)


class SerialClient:
    """Serial port client for ONT device UART access.

    Requires pyserial library. Falls back gracefully if not available.
    """

    SERIAL_AVAILABLE = False

    def __init__(self):
        self.port = None
        self.serial_conn = None
        self._connected = False
        self._running = False
        self._recv_thread = None

        # Callbacks
        self.on_data = None
        self.on_connect = None
        self.on_disconnect = None
        self.on_error = None

    @property
    def connected(self):
        return self._connected

    @staticmethod
    def list_ports():
        """List available serial/COM ports.

        Returns:
            List of (port_name, description) tuples.
        """
        ports = []
        try:
            import serial.tools.list_ports
            for port in serial.tools.list_ports.comports():
                ports.append((port.device, port.description))
        except ImportError:
            # Try fallback for Windows
            import sys
            if sys.platform == 'win32':
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                         r"HARDWARE\DEVICEMAP\SERIALCOMM")
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            ports.append((value, name))
                            i += 1
                        except OSError:
                            break
                except OSError:
                    pass
            else:
                # Linux/Mac: check /dev/ttyUSB* and /dev/ttyACM*
                import glob
                for pattern in ['/dev/ttyUSB*', '/dev/ttyACM*', '/dev/ttyS*']:
                    for port in sorted(glob.glob(pattern)):
                        ports.append((port, port))
        return ports

    def connect(self, port, baudrate=115200, timeout=5.0):
        """Connect to serial port.

        Args:
            port: Serial port name (e.g., "COM3", "/dev/ttyUSB0").
            baudrate: Baud rate (default 115200 for Huawei ONT).
            timeout: Read timeout in seconds.

        Raises:
            ImportError: If pyserial is not installed.
            serial.SerialException: If port cannot be opened.
        """
        if not SerialClient.SERIAL_AVAILABLE:
            try:
                import serial  # noqa: F811
                SerialClient.SERIAL_AVAILABLE = True
            except ImportError:
                if self.on_error:
                    self.on_error("pyserial not installed. Install with: pip install pyserial")
                raise ImportError("pyserial is required for serial connections. "
                                  "Install with: pip install pyserial")

        import serial

        try:
            self.serial_conn = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout,
            )
            self.port = port
            self._connected = True
            self._running = True

            # Start receive thread
            self._recv_thread = threading.Thread(
                target=self._receive_loop,
                daemon=True,
                name="serial-recv"
            )
            self._recv_thread.start()

            if self.on_connect:
                self.on_connect(port, baudrate)

        except Exception as e:
            self._connected = False
            if self.on_error:
                self.on_error(f"Serial connection failed: {e}")
            raise

    def disconnect(self):
        """Close the serial connection."""
        self._running = False
        self._connected = False
        if self.serial_conn:
            try:
                self.serial_conn.close()
            except Exception:
                pass
            self.serial_conn = None

        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2)

        if self.on_disconnect:
            self.on_disconnect()

    def send(self, data):
        """Send data over serial.

        Args:
            data: Bytes or string to send.
        """
        if not self._connected or not self.serial_conn:
            return

        if isinstance(data, str):
            data = data.encode('ascii', errors='replace')

        try:
            self.serial_conn.write(data)
        except Exception as e:
            logger.error("Serial send error: %s", e)
            self.disconnect()

    def send_command(self, command):
        """Send command with newline."""
        self.send(command + "\r\n")

    def _receive_loop(self):
        """Background receive loop for serial data."""
        while self._running and self._connected:
            try:
                if self.serial_conn and self.serial_conn.in_waiting:
                    data = self.serial_conn.read(self.serial_conn.in_waiting)
                    if data and self.on_data:
                        text = data.decode('utf-8', errors='replace')
                        self.on_data(text)
                else:
                    time.sleep(0.05)
            except Exception as e:
                if self._running:
                    logger.error("Serial receive error: %s", e)
                    self._connected = False
                    if self.on_disconnect:
                        self.on_disconnect()
                break


class FirmwareDumper:
    """Firmware dump operations over a terminal session.

    Uses shell commands to read flash partitions and transfer
    them via TFTP or direct serial download.
    """

    def __init__(self, terminal_client):
        """Initialize with an active terminal client.

        Args:
            terminal_client: TelnetClient or SerialClient instance.
        """
        self.client = terminal_client
        self.partitions = []
        self._output_buffer = ""
        self._waiting = False
        self._original_callback = None

    def get_mtd_partitions(self, callback=None, timeout=3):
        """Read MTD partition table from the device.

        Sends 'cat /proc/mtd' and parses the output.

        Args:
            callback: Function to call with list of partition dicts.
            timeout: Seconds to wait for device response (default 3).
        """
        self._output_buffer = ""
        self._waiting = True

        # Capture output
        self._original_callback = self.client.on_data
        self.client.on_data = self._capture_output

        self.client.send_command("cat /proc/mtd")

        # Wait for output with configurable timeout
        def check_done():
            time.sleep(timeout)
            self.client.on_data = self._original_callback
            self._waiting = False
            self._parse_mtd()
            if callback:
                callback(self.partitions)

        t = threading.Thread(target=check_done, daemon=True)
        t.start()

    def _capture_output(self, text):
        """Capture terminal output for parsing."""
        self._output_buffer += text
        # Also forward to original callback
        if self._original_callback:
            self._original_callback(text)

    def _parse_mtd(self):
        """Parse /proc/mtd output into partition list."""
        self.partitions = []
        for line in self._output_buffer.split('\n'):
            match = re.match(
                r'mtd(\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"([^"]+)"',
                line.strip()
            )
            if match:
                self.partitions.append({
                    'id': int(match.group(1)),
                    'size': int(match.group(2), 16),
                    'erasesize': int(match.group(3), 16),
                    'name': match.group(4),
                })

    def dump_partition(self, partition_id, local_path=None):
        """Initiate a firmware partition dump.

        Sends dd command to dump the partition to /tmp on the device.

        Args:
            partition_id: MTD partition number.
            local_path: Not used for remote dump (for future TFTP integration).
        """
        cmd = f"dd if=/dev/mtdblock{partition_id} of=/tmp/mtd{partition_id}.bin bs=4096"
        self.client.send_command(cmd)

    def dump_all_partitions(self):
        """Dump all MTD partitions to /tmp on the device."""
        for p in self.partitions:
            self.dump_partition(p['id'])
            # Adaptive delay: ~1s per MB, minimum 1s
            delay = max(1, p.get('size', 0) / (1024 * 1024))
            time.sleep(delay)
