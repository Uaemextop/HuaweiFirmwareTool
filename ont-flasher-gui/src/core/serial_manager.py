"""
Serial Manager - Handles serial communication with ONT devices
"""

import serial
import serial.tools.list_ports
import time
from utils.logger import get_logger

class SerialManager:
    """Manages serial port connections"""

    def __init__(self):
        self.logger = get_logger()
        self.connection = None
        self.is_connected = False

    def get_available_ports(self):
        """Get list of available COM ports"""
        try:
            ports = serial.tools.list_ports.comports()
            return [(port.device, port.description) for port in ports]
        except Exception as e:
            self.logger.error(f"Error getting ports: {e}")
            return []

    def connect(self, port, baudrate=115200, timeout=2.0):
        """Connect to serial port"""
        try:
            self.logger.info(f"Connecting to {port} at {baudrate} baud")

            self.connection = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False
            )

            self.is_connected = True
            self.logger.info("Serial connection established")
            return True

        except serial.SerialException as e:
            self.logger.error(f"Failed to connect: {e}")
            self.is_connected = False
            return False

    def disconnect(self):
        """Disconnect from serial port"""
        if self.connection and self.is_connected:
            try:
                self.connection.close()
                self.is_connected = False
                self.logger.info("Serial connection closed")
            except Exception as e:
                self.logger.error(f"Error closing connection: {e}")

    def write(self, data):
        """Write data to serial port"""
        if not self.is_connected or not self.connection:
            return False

        try:
            if isinstance(data, str):
                data = data.encode()

            bytes_written = self.connection.write(data)
            self.connection.flush()
            return bytes_written

        except Exception as e:
            self.logger.error(f"Write error: {e}")
            return 0

    def read(self, size=1):
        """Read data from serial port"""
        if not self.is_connected or not self.connection:
            return b''

        try:
            return self.connection.read(size)
        except Exception as e:
            self.logger.error(f"Read error: {e}")
            return b''

    def read_until(self, terminator=b'\n', size=None):
        """Read until terminator or size limit"""
        if not self.is_connected or not self.connection:
            return b''

        try:
            return self.connection.read_until(terminator, size)
        except Exception as e:
            self.logger.error(f"Read error: {e}")
            return b''

    def readline(self):
        """Read one line from serial port"""
        return self.read_until(b'\n')

    def in_waiting(self):
        """Get number of bytes waiting in input buffer"""
        if not self.is_connected or not self.connection:
            return 0

        try:
            return self.connection.in_waiting
        except Exception as e:
            self.logger.error(f"Error checking buffer: {e}")
            return 0

    def flush_input(self):
        """Flush input buffer"""
        if self.is_connected and self.connection:
            try:
                self.connection.reset_input_buffer()
            except Exception as e:
                self.logger.error(f"Error flushing input: {e}")

    def flush_output(self):
        """Flush output buffer"""
        if self.is_connected and self.connection:
            try:
                self.connection.reset_output_buffer()
            except Exception as e:
                self.logger.error(f"Error flushing output: {e}")
