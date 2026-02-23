"""
Configuration management for ONT Broadcast Tool.
Settings are persisted to a JSON file in the user's AppData directory.

Also manages router presets: named profiles that bundle all network/timing
settings plus firmware path for quick per-router-model switching.
"""

import json
import os
import platform
import logging
import uuid
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

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


def _presets_file() -> str:
    return os.path.join(_config_dir(), 'presets.json')


# ---------------------------------------------------------------------------
# Router preset
# ---------------------------------------------------------------------------

@dataclass
class RouterPreset:
    """
    A named configuration profile for a specific router model.

    Bundles all network/timing/firmware settings so the user can switch
    between different router models with a single click.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = 'New Preset'
    description: str = ''
    router_model: str = ''          # e.g. "HG8145V5", "HG8245H2"

    # Network
    broadcast_address: str = DEFAULT_BROADCAST
    udp_port: int = DEFAULT_PORT

    # Timing
    packet_interval_ms: int = DEFAULT_INTERVAL
    operation_timeout_s: int = DEFAULT_TIMEOUT
    retry_count: int = DEFAULT_RETRIES
    chunk_size: int = 1024

    # Firmware
    firmware_path: str = ''         # path to default .bin for this router
    firmware_label: str = ''        # short label shown in the UI

    # Verification
    verify_crc32: bool = True        # verify HWNP CRC32 before sending
    verify_signature: bool = False   # verify RSA signature (requires key file)
    signature_key_path: str = ''     # path to PEM public key file

    # Broadcast behaviour
    send_repeat_count: int = 1       # send the package N times (for reliability)
    inter_repeat_delay_s: float = 5.0  # seconds between repeats
    discovery_enabled: bool = True   # send a discovery packet before firmware

    # Notes
    notes: str = ''


# Built-in presets (read-only templates, never persisted)
BUILTIN_PRESETS: List[RouterPreset] = [
    RouterPreset(
        id='builtin-hg8145v5-v3',
        name='HG8145V5 — V3 firmware',
        description='Most HG8145V5 devices on V3 firmware (R13C10–R17C00)',
        router_model='HG8145V5',
        firmware_label='Package 1 (V3)',
        verify_crc32=True,
    ),
    RouterPreset(
        id='builtin-hg8145v5-v5',
        name='HG8145V5 — V5 firmware',
        description='Most HG8145V5 devices on V5 firmware (full module)',
        router_model='HG8145V5',
        firmware_label='Package 2 (V5)',
        verify_crc32=True,
    ),
    RouterPreset(
        id='builtin-hg8145v5-new',
        name='HG8145V5 — newer devices',
        description='Partial support for newer HG8145V5 hardware revisions',
        router_model='HG8145V5',
        firmware_label='Package 3 (new)',
        verify_crc32=True,
    ),
    RouterPreset(
        id='builtin-hg8245h2',
        name='HG8245H2 — generic',
        description='Generic preset for HG8245H2 with default timing',
        router_model='HG8245H2',
        udp_port=1400,
        packet_interval_ms=10,
        verify_crc32=True,
    ),
    RouterPreset(
        id='builtin-ma5671a',
        name='MA5671A — ONT stick',
        description='Huawei MA5671A SFP ONT stick, slower interval',
        router_model='MA5671A',
        udp_port=1400,
        packet_interval_ms=20,
        operation_timeout_s=120,
        verify_crc32=True,
    ),
]


def load_presets() -> List[RouterPreset]:
    """Load user-created presets from disk."""
    path = _presets_file()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        presets = []
        for d in data:
            p = RouterPreset()
            for k, v in d.items():
                if hasattr(p, k):
                    setattr(p, k, v)
            presets.append(p)
        return presets
    except Exception as e:
        logger.warning("Could not load presets from %s: %s", path, e)
        return []


def save_presets(presets: List[RouterPreset]) -> None:
    """Persist user-created presets to disk (built-ins are never saved)."""
    cfg_dir = _config_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    # Only save user presets (IDs that don't start with 'builtin-')
    user_presets = [p for p in presets if not p.id.startswith('builtin-')]
    path = _presets_file()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump([asdict(p) for p in user_presets], f, indent=2)
    except Exception as e:
        logger.warning("Could not save presets to %s: %s", path, e)


def get_all_presets(user_presets: List[RouterPreset]) -> List[RouterPreset]:
    """Return built-in presets + user presets combined."""
    return list(BUILTIN_PRESETS) + list(user_presets)


def duplicate_preset(preset: RouterPreset) -> RouterPreset:
    """Return a deep copy of a preset with a new unique ID and modified name."""
    p = deepcopy(preset)
    p.id   = str(uuid.uuid4())
    p.name = f"{preset.name} (copy)"
    return p


# ---------------------------------------------------------------------------
# Application settings
# ---------------------------------------------------------------------------

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
    active_preset_id: str = ''      # ID of the last-used preset

    # Verification
    verify_crc32: bool = True         # verify HWNP CRC32 checksum before broadcast
    verify_signature: bool = False    # verify RSA signature embedded in SIGNINFO item
    signature_key_path: str = ''      # path to PEM public key for RSA verification
    skip_upgrade_check: bool = False  # ignore UpgradeCheck.xml hardware gates

    # Broadcast behaviour
    send_repeat_count: int = 1        # number of times to send the whole package
    inter_repeat_delay_s: float = 5.0 # seconds between repeat sends
    dry_run_mode: bool = False         # simulate broadcast without sending packets

    # Logging
    log_dir: str = DEFAULT_LOG_DIR
    log_level: str = 'INFO'           # DEBUG / INFO / WARNING / ERROR
    auto_save_log: bool = True
    log_timestamp_format: str = '%Y-%m-%d %H:%M:%S'  # strftime format for log lines

    # UI
    theme: str = DEFAULT_THEME        # 'dark' / 'light' / 'system'
    language: str = DEFAULT_LANGUAGE
    window_width: int = 980
    window_height: int = 720

    # Advanced
    raw_send_mode: bool = False       # send raw HWNP without handshake
    chunk_size: int = 1024            # bytes per UDP packet
    discovery_enabled: bool = True    # send discovery broadcast first
    socket_ttl: int = 64              # IP TTL for outgoing packets (1 = LAN only)
    socket_buf_size: int = 65536      # UDP send buffer size in bytes


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
