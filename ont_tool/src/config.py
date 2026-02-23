"""
Configuration management for ONT Broadcast Tool.
Settings are persisted to a JSON file in the user's AppData directory.
"""

import json
import os
import platform
import logging
from dataclasses import dataclass, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# Default values derived from the original OBSCTool analysis:
# The instructions say "change 1200→1400 and 10ms→5ms"
DEFAULT_PORT       = 1400      # UDP port for firmware broadcast
DEFAULT_INTERVAL   = 5         # ms between successive packets
DEFAULT_TIMEOUT    = 60        # seconds to wait for device response
DEFAULT_RETRIES    = 3         # retry count on error
DEFAULT_BROADCAST  = '255.255.255.255'
DEFAULT_LOG_DIR    = ''        # empty = same dir as exe
DEFAULT_THEME      = 'dark'    # 'dark' or 'light'
DEFAULT_LANGUAGE   = 'en'


def _config_dir() -> str:
    """Return platform-appropriate directory for storing config."""
    if platform.system() == 'Windows':
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
        return os.path.join(base, 'ONTBroadcastTool')
    return os.path.join(os.path.expanduser('~'), '.ont_broadcast_tool')


def _config_file() -> str:
    return os.path.join(_config_dir(), 'settings.json')


@dataclass
class AppSettings:
    """All user-configurable settings."""
    # Network
    interface_name: str = ''
    broadcast_address: str = DEFAULT_BROADCAST
    udp_port: int = DEFAULT_PORT

    # Timing
    packet_interval_ms: int = DEFAULT_INTERVAL
    operation_timeout_s: int = DEFAULT_TIMEOUT
    retry_count: int = DEFAULT_RETRIES

    # Firmware
    last_firmware_dir: str = ''
    last_firmware_path: str = ''

    # Logging
    log_dir: str = DEFAULT_LOG_DIR
    log_level: str = 'INFO'         # DEBUG / INFO / WARNING / ERROR
    auto_save_log: bool = True

    # UI
    theme: str = DEFAULT_THEME       # 'dark' / 'light' / 'system'
    language: str = DEFAULT_LANGUAGE
    window_width: int = 950
    window_height: int = 700

    # Advanced
    raw_send_mode: bool = False      # send raw HWNP without handshake
    chunk_size: int = 1024           # bytes per UDP packet
    discovery_enabled: bool = True   # send discovery broadcast first


def load_settings() -> AppSettings:
    """Load settings from disk, returning defaults if not found."""
    path = _config_file()
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            s = AppSettings()
            for k, v in data.items():
                if hasattr(s, k):
                    setattr(s, k, v)
            return s
        except Exception as e:
            logger.warning("Could not load settings from %s: %s", path, e)
    return AppSettings()


def save_settings(settings: AppSettings) -> None:
    """Persist settings to disk."""
    cfg_dir = _config_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    path = _config_file()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(asdict(settings), f, indent=2)
    except Exception as e:
        logger.warning("Could not save settings to %s: %s", path, e)
