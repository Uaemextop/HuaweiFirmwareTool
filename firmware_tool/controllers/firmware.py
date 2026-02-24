"""Firmware operations controller."""

import socket
import struct
import time
from pathlib import Path
from typing import Optional, Dict, Any, Callable

from .base import BaseController
from ..utils import is_valid_ip, is_valid_port, format_bytes, format_speed, read_binary


class FirmwareController(BaseController):
    """
    Controller for firmware operations.

    Handles:
    - Firmware file loading and validation
    - Firmware upload to device
    - Firmware backup from device
    - Progress tracking
    """

    def __init__(self):
        """Initialize firmware controller."""
        super().__init__()
        self._firmware_data: Optional[bytes] = None
        self._firmware_path: Optional[Path] = None

    def load_firmware(self, file_path: str) -> bool:
        """
        Load firmware file.

        Args:
            file_path: Path to firmware file

        Returns:
            True if loaded successfully

        Emits:
            - firmware_loaded: (file_path, size)
            - error: (exception, context)
        """
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"Firmware file not found: {file_path}")

            self._firmware_data = read_binary(path)
            self._firmware_path = path

            self.set_state('firmware_loaded', True)
            self.set_state('firmware_size', len(self._firmware_data))
            self.set_state('firmware_path', str(path))

            self.emit_event('firmware_loaded', str(path), len(self._firmware_data))
            self.logger.info(f"Loaded firmware: {path} ({format_bytes(len(self._firmware_data))})")
            return True

        except Exception as e:
            self.handle_error(e, "Failed to load firmware")
            return False

    def validate_firmware(self) -> bool:
        """
        Validate loaded firmware.

        Returns:
            True if firmware is valid

        Emits:
            - firmware_validated: (is_valid, message)
        """
        if not self._firmware_data:
            self.emit_event('firmware_validated', False, "No firmware loaded")
            return False

        # Basic validation
        size = len(self._firmware_data)
        if size < 1024:
            msg = f"Firmware too small: {size} bytes"
            self.emit_event('firmware_validated', False, msg)
            return False

        if size > 100 * 1024 * 1024:  # 100MB max
            msg = f"Firmware too large: {format_bytes(size)}"
            self.emit_event('firmware_validated', False, msg)
            return False

        self.emit_event('firmware_validated', True, "Firmware valid")
        return True

    def upload_firmware(self, device_ip: str, device_port: int,
                       progress_callback: Optional[Callable] = None) -> bool:
        """
        Upload firmware to device.

        Args:
            device_ip: Device IP address
            device_port: Device port
            progress_callback: Optional callback(percent, speed, eta)

        Returns:
            True if upload successful

        Emits:
            - upload_started: (device_ip, device_port, size)
            - upload_progress: (bytes_sent, total_bytes, percent, speed)
            - upload_completed: (total_bytes, duration)
            - upload_failed: (error, context)
        """
        if not self._firmware_data:
            self.emit_event('upload_failed', "No firmware loaded", "")
            return False

        if not is_valid_ip(device_ip):
            self.emit_event('upload_failed', "Invalid IP address", device_ip)
            return False

        if not is_valid_port(device_port):
            self.emit_event('upload_failed', "Invalid port", str(device_port))
            return False

        try:
            total_size = len(self._firmware_data)
            chunk_size = 4096

            self.emit_event('upload_started', device_ip, device_port, total_size)
            self.logger.info(f"Starting upload to {device_ip}:{device_port}")

            # Connect to device
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((device_ip, device_port))

            start_time = time.time()
            bytes_sent = 0

            # Send firmware in chunks
            for i in range(0, total_size, chunk_size):
                chunk = self._firmware_data[i:i + chunk_size]
                sock.sendall(chunk)
                bytes_sent += len(chunk)

                # Calculate progress
                percent = (bytes_sent / total_size) * 100
                elapsed = time.time() - start_time
                if elapsed > 0:
                    speed = bytes_sent / elapsed
                    eta = (total_size - bytes_sent) / speed if speed > 0 else 0
                else:
                    speed = 0
                    eta = 0

                self.emit_event('upload_progress', bytes_sent, total_size, percent, speed)

                if progress_callback:
                    progress_callback(percent, format_speed(speed), int(eta))

            sock.close()
            duration = time.time() - start_time

            self.emit_event('upload_completed', total_size, duration)
            self.logger.info(f"Upload completed in {duration:.2f}s")
            return True

        except Exception as e:
            self.handle_error(e, "Firmware upload failed")
            self.emit_event('upload_failed', str(e), "")
            return False

    def get_firmware_info(self) -> Dict[str, Any]:
        """
        Get information about loaded firmware.

        Returns:
            Dictionary with firmware information
        """
        if not self._firmware_data:
            return {'loaded': False}

        return {
            'loaded': True,
            'path': str(self._firmware_path),
            'size': len(self._firmware_data),
            'size_formatted': format_bytes(len(self._firmware_data)),
        }

    def clear_firmware(self):
        """
        Clear loaded firmware.

        Emits:
            - firmware_cleared
        """
        self._firmware_data = None
        self._firmware_path = None
        self.set_state('firmware_loaded', False)
        self.emit_event('firmware_cleared')
        self.logger.info("Firmware cleared")
