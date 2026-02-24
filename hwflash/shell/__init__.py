"""Shell (terminal) subpackage for hwflash."""
from hwflash.shell.telnet import TelnetClient, ONT_COMMANDS, DUMP_COMMANDS
from hwflash.shell.serial import SerialClient
from hwflash.shell.dumper import FirmwareDumper

__all__ = ['TelnetClient', 'SerialClient', 'FirmwareDumper', 'ONT_COMMANDS', 'DUMP_COMMANDS']
