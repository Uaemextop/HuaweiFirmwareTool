"""
Firmware dump operations over a terminal session.
"""

import threading
import time
import re
import logging

logger = logging.getLogger("hwflash.shell.dumper")


class FirmwareDumper:
    """Firmware dump operations over a terminal session."""

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

        Args:
            callback: Function to call with list of partition dicts.
            timeout: Seconds to wait for device response (default 3).
        """
        self._output_buffer = ""
        self._waiting = True

        self._original_callback = self.client.on_data
        self.client.on_data = self._capture_output

        self.client.send_command("cat /proc/mtd")

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
            delay = max(1, p.get('size', 0) / (1024 * 1024))
            time.sleep(delay)
