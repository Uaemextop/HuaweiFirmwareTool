"""
Telnet client for Huawei ONT device console access.
"""

import socket
import threading
import time
import logging

logger = logging.getLogger("hwflash.shell.telnet")


# ── Telnet Protocol Constants ───────────────────────────────────

TELNET_IAC = 0xFF
TELNET_DONT = 0xFE
TELNET_DO = 0xFD
TELNET_WONT = 0xFC
TELNET_WILL = 0xFB
TELNET_SB = 0xFA
TELNET_SE = 0xF0

TELOPT_ECHO = 0x01
TELOPT_SGA = 0x03
TELOPT_TTYPE = 0x18
TELOPT_NAWS = 0x1F
TELOPT_LINEMODE = 0x22


# ── Common ONT Shell Commands ───────────────────────────────────

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

DUMP_COMMANDS = {
    'list_mtd': 'cat /proc/mtd',
    'dump_mtd': 'dd if=/dev/mtdblock{n} of=/tmp/mtd{n}.bin bs=4096',
    'list_tmp': 'ls -la /tmp/*.bin',
    'check_tftp': 'which tftp',
    'tftp_send': 'tftp -p -l /tmp/mtd{n}.bin {host}',
}


class TelnetClient:
    """Simple Telnet client for ONT device access."""

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

        self.on_data = None
        self.on_connect = None
        self.on_disconnect = None
        self.on_error = None

    @property
    def connected(self):
        return self._connected

    def connect(self, host, port=23, timeout=10.0):
        """Connect to the ONT device via Telnet."""
        self.host = host
        self.port = port
        self.timeout = timeout

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((host, port))
            self._connected = True
            self._running = True

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
        """Send raw bytes to the device."""
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
        """Send a command with newline."""
        self.send(command + "\r\n")

    def send_line(self, line):
        """Send a line of text with CR+LF."""
        self.send(line + "\r\n")

    def _receive_loop(self):
        """Background thread to receive data."""
        while self._running and self._connected:
            try:
                self.sock.settimeout(0.5)
                data = self.sock.recv(4096)
                if not data:
                    self._connected = False
                    if self.on_disconnect:
                        self.on_disconnect()
                    break

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
        """Process telnet protocol bytes and return clean text."""
        clean = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b == TELNET_IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd == TELNET_IAC:
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

        try:
            return clean.decode('utf-8', errors='replace')
        except (UnicodeDecodeError, ValueError):
            return clean.decode('ascii', errors='replace')

    def _negotiate(self, cmd, opt):
        """Handle telnet option negotiation."""
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
