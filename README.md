# HuaweiFlash

Modern GUI for Huawei ONT firmware management via the OBSC UDP protocol.

## Features

- **Device Discovery**: Find ONT devices on local network via UDP broadcast
- **Firmware Flashing**: Flash HWNP firmware via OBSC protocol
- **Config Crypto**: AES-128-CBC encryption for device config files
- **Terminal Access**: Telnet and Serial console
- **Firmware Dump**: Extract MTD partitions from devices
- **Preset Management**: Save and load router-specific profiles
- **CRC32 Verification**: Integrity checks before flashing
- **Modern UI**: Sidebar navigation, gradient accents, dark/light themes

## Project Structure

```
hwflash/
├── core/                # Business logic
│   ├── protocol.py      # OBSC UDP protocol
│   ├── firmware.py      # HWNP firmware parser
│   ├── crypto.py        # AES-128-CBC config encryption
│   ├── network.py       # Adapter discovery & UDP transport
│   ├── terminal.py      # Telnet/Serial terminal clients
│   └── presets.py       # Router preset management
├── shared/              # Shared utilities
│   ├── helpers.py       # Type conversion, formatting, subprocess
│   ├── validators.py    # IP, port, range validation
│   ├── styles.py        # Theme colors, fonts, animations
│   └── icons.py         # Logo and icon generation
├── ui/                  # GUI layer
│   ├── app.py           # Main application with sidebar
│   ├── splash.py        # Animated splash screen
│   ├── tabs/            # Tab implementations
│   └── components/      # Reusable widgets (cards, sidebar)
└── main.py              # Entry point
```

## Quick Start

```bash
pip install -r hwflash/requirements.txt
python launcher.py
```

## Running Tests

```bash
pip install pytest pycryptodome
python -m pytest tests/ -v
```

## OBSC Protocol

The OBSC protocol uses UDP to discover and flash firmware to Huawei ONT
devices in bootloader mode:

1. **Discovery**: Broadcast to port 50000; ONTs respond with device info
2. **Control**: Send firmware metadata (size, CRC32, frame parameters)
3. **Data**: Fragment firmware into frames at configurable rate
4. **Result**: Wait for flash confirmation from the device

## Supported Devices

- Huawei HG8145V5
- Huawei HG8245H
- Huawei HG8546M
- Huawei HG8247H
- Huawei EG8145V5
- Other Huawei ONT devices using HWNP firmware format

## License

See [LICENSE](LICENSE) for details.
