"""
Serial port client for Huawei ONT device UART access.
"""

import threading
import time
import logging

logger = logging.getLogger("hwflash.shell.serial")


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
        """Send data over serial."""
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
