"""
Firmware Flasher - Core firmware flashing logic
Implements the OBSC protocol for flashing Huawei ONT devices
"""

import os
import struct
import time
import hashlib
from core.serial_manager import SerialManager
from utils.logger import get_logger

class FirmwareFlasher:
    """Handles firmware flashing operations"""

    # Protocol constants
    MAGIC_HEADER = b'HWNP'  # 0x504E5748
    CMD_START_FLASH = 0x01
    CMD_SEND_DATA = 0x02
    CMD_VERIFY = 0x03
    CMD_FINISH = 0x04
    CMD_REBOOT = 0x05

    RESPONSE_OK = 0x00
    RESPONSE_ERROR = 0x01

    def __init__(self):
        self.logger = get_logger()
        self.serial = SerialManager()
        self.firmware_data = None
        self.firmware_size = 0
        self.config = {}

    def connect(self, config):
        """Connect to device"""
        self.config = config

        return self.serial.connect(
            port=config['port'],
            baudrate=config['baudrate'],
            timeout=config['timeout']
        )

    def disconnect(self):
        """Disconnect from device"""
        self.serial.disconnect()

    def load_firmware(self, filepath):
        """Load firmware file"""
        try:
            self.logger.info(f"Loading firmware: {filepath}")

            with open(filepath, 'rb') as f:
                self.firmware_data = f.read()

            self.firmware_size = len(self.firmware_data)
            self.logger.info(f"Firmware loaded: {self.firmware_size} bytes")

            # Check if it's a valid firmware
            if self.firmware_size < 1024:
                self.logger.error("Firmware file too small")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error loading firmware: {e}")
            return False

    def flash_firmware(self, progress_callback=None):
        """Flash firmware to device"""
        try:
            if not self.firmware_data:
                self.logger.error("No firmware loaded")
                return False

            if self.config.get('dry_run', False):
                self.logger.info("DRY RUN MODE - Simulating flash")
                return self._simulate_flash(progress_callback)

            # Step 1: Send start command
            self.logger.info("Sending start flash command...")
            if not self._send_start_command():
                return False

            time.sleep(self.config.get('delay', 0.005))

            # Step 2: Send firmware data in chunks
            self.logger.info("Sending firmware data...")
            if not self._send_firmware_data(progress_callback):
                return False

            # Step 3: Verify if enabled
            if self.config.get('verify', True):
                self.logger.info("Verifying firmware...")
                if not self._verify_firmware():
                    return False

            # Step 4: Finish flash
            self.logger.info("Finishing flash operation...")
            if not self._send_finish_command():
                return False

            # Step 5: Reboot if enabled
            if self.config.get('reboot', True):
                self.logger.info("Rebooting device...")
                self._reboot_device()

            self.logger.info("Flash completed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Flash error: {e}")
            return False

    def _send_start_command(self):
        """Send start flash command"""
        try:
            # Build command packet
            # Format: MAGIC(4) + CMD(1) + SIZE(4)
            packet = struct.pack(
                '<4sBI',
                self.MAGIC_HEADER,
                self.CMD_START_FLASH,
                self.firmware_size
            )

            self.serial.write(packet)

            # Wait for response
            response = self.serial.read(1)
            if response and response[0] == self.RESPONSE_OK:
                self.logger.debug("Start command acknowledged")
                return True
            else:
                self.logger.error("Device did not acknowledge start command")
                return False

        except Exception as e:
            self.logger.error(f"Error sending start command: {e}")
            return False

    def _send_firmware_data(self, progress_callback=None):
        """Send firmware data in chunks"""
        try:
            chunk_size = self.config.get('chunk_size', 1024)
            retry_count = self.config.get('retry_count', 3)
            delay = self.config.get('delay', 0.005)

            offset = 0
            total_chunks = (self.firmware_size + chunk_size - 1) // chunk_size

            while offset < self.firmware_size:
                chunk_end = min(offset + chunk_size, self.firmware_size)
                chunk = self.firmware_data[offset:chunk_end]
                chunk_num = offset // chunk_size

                # Try sending chunk with retry
                success = False
                for attempt in range(retry_count):
                    if self._send_chunk(chunk, offset):
                        success = True
                        break
                    else:
                        self.logger.warning(f"Retry {attempt + 1}/{retry_count} for chunk {chunk_num}")
                        time.sleep(delay * 2)

                if not success:
                    self.logger.error(f"Failed to send chunk {chunk_num} after {retry_count} attempts")
                    return False

                offset = chunk_end

                # Update progress
                if progress_callback:
                    progress = (offset / self.firmware_size) * 100
                    progress_callback(progress)

                time.sleep(delay)

            return True

        except Exception as e:
            self.logger.error(f"Error sending firmware data: {e}")
            return False

    def _send_chunk(self, data, offset):
        """Send a single chunk of data"""
        try:
            # Build chunk packet
            # Format: MAGIC(4) + CMD(1) + OFFSET(4) + SIZE(2) + DATA(n)
            packet = struct.pack(
                '<4sBIH',
                self.MAGIC_HEADER,
                self.CMD_SEND_DATA,
                offset,
                len(data)
            ) + data

            self.serial.write(packet)
            self.serial.flush_output()

            # Wait for acknowledgment
            response = self.serial.read(1)
            if response and response[0] == self.RESPONSE_OK:
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"Error sending chunk: {e}")
            return False

    def _verify_firmware(self):
        """Verify firmware after flashing"""
        try:
            # Calculate checksum
            checksum = hashlib.md5(self.firmware_data).digest()

            # Send verify command with checksum
            packet = struct.pack(
                '<4sB',
                self.MAGIC_HEADER,
                self.CMD_VERIFY
            ) + checksum

            self.serial.write(packet)

            # Wait for verification result
            response = self.serial.read(1)
            if response and response[0] == self.RESPONSE_OK:
                self.logger.info("Firmware verification successful")
                return True
            else:
                self.logger.error("Firmware verification failed")
                return False

        except Exception as e:
            self.logger.error(f"Verification error: {e}")
            return False

    def _send_finish_command(self):
        """Send finish flash command"""
        try:
            packet = struct.pack(
                '<4sB',
                self.MAGIC_HEADER,
                self.CMD_FINISH
            )

            self.serial.write(packet)

            # Wait for response
            response = self.serial.read(1)
            if response and response[0] == self.RESPONSE_OK:
                self.logger.debug("Finish command acknowledged")
                return True
            else:
                self.logger.warning("Device did not acknowledge finish command")
                return True  # Continue anyway

        except Exception as e:
            self.logger.error(f"Error sending finish command: {e}")
            return False

    def _reboot_device(self):
        """Reboot device"""
        try:
            packet = struct.pack(
                '<4sB',
                self.MAGIC_HEADER,
                self.CMD_REBOOT
            )

            self.serial.write(packet)
            time.sleep(0.5)

            # Don't wait for response as device may reboot immediately

        except Exception as e:
            self.logger.warning(f"Error sending reboot command: {e}")

    def _simulate_flash(self, progress_callback=None):
        """Simulate flash operation for testing"""
        self.logger.info("=== SIMULATION MODE ===")

        steps = 20
        for i in range(steps + 1):
            time.sleep(0.1)
            if progress_callback:
                progress = (i / steps) * 100
                progress_callback(progress)

        self.logger.info("=== SIMULATION COMPLETE ===")
        return True
