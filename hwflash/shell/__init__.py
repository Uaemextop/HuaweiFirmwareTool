"""Shell (terminal) subpackage for hwflash."""
from hwflash.shell.telnet import TelnetClient
from hwflash.shell.serial import SerialClient
from hwflash.shell.dumper import FirmwareDumper

__all__ = ['TelnetClient', 'SerialClient', 'FirmwareDumper']
