# HuaweiFlash

Open-source toolkit for Huawei ONT (Optical Network Terminal) firmware management.
Modern sidebar-based GUI for firmware flashing via OBSC protocol, C++ utilities
for firmware packing/signing, and PE analysis tools.

## Features

### HuaweiFlash (Python GUI)
- **Device Discovery**: Find ONT devices on local network via UDP broadcast
- **Firmware Flashing**: Flash HWNP firmware via OBSC protocol
- **Config Crypto**: AES-128-CBC encryption for device config files
- **Terminal Access**: Telnet and Serial console
- **Firmware Dump**: Extract MTD partitions from devices
- **Preset Management**: Save and load router-specific profiles
- **CRC32 Verification**: Integrity checks before flashing
- **Modern UI**: Sidebar navigation, gradient accents, dark/light themes

### C++ Firmware Tools
- **hw_fmw**: Pack/unpack HWNP firmware packages
- **hw_sign**: Sign firmware items with RSA-2048 keys
- **hw_verify**: Verify RSA signatures on firmware items

### PE Analysis Tool
- Static analysis of Windows PE32 executables
- Hash calculation, section entropy analysis, import enumeration
- Packer/compiler detection

## Project Structure

```
HuaweiFirmwareTool/
├── hwflash/                 # Main Python package
│   ├── core/                # Business logic
│   │   ├── protocol.py      # OBSC UDP protocol
│   │   ├── firmware.py      # HWNP firmware parser
│   │   ├── crypto.py        # AES-128-CBC config encryption
│   │   ├── network.py       # Adapter discovery & UDP transport
│   │   ├── terminal.py      # Telnet/Serial terminal clients
│   │   └── presets.py       # Router preset management
│   ├── shared/              # Shared utilities
│   │   ├── helpers.py       # Type conversion, formatting, threading
│   │   ├── validators.py    # IP, port, range validation
│   │   ├── styles.py        # Theme colors, fonts, animations
│   │   └── icons.py         # Logo and icon generation
│   ├── ui/                  # GUI layer
│   │   ├── app.py           # Main application with sidebar
│   │   ├── splash.py        # Animated dependency installer
│   │   ├── tabs/            # Tab implementations
│   │   │   ├── upgrade.py, presets.py, verify.py, crypto.py
│   │   │   ├── terminal.py, dump.py, settings.py, info.py, log.py
│   │   │   ├── theme.py     # Theme switching
│   │   │   └── adapters.py  # Network adapter management
│   │   └── components/      # Reusable widgets
│   │       ├── cards.py     # Card, badge, gradient, progress
│   │       └── sidebar.py   # Sidebar navigation
│   └── main.py              # Entry point
├── obsc_tool/               # Backward compatibility redirects
├── cpp/                     # C++ firmware tools
├── tools/                   # Standalone analysis tools
│   └── analyzer.py          # PE32 executable analyzer
├── tests/                   # Unit tests (173 tests)
└── launcher.py              # GUI launcher with splash
```

## Quick Start

### Python GUI

```bash
pip install -r hwflash/requirements.txt

python launcher.py

# Or run directly
python -m hwflash.main
```

### Running Tests

```bash
pip install pytest pycryptodome
python -m pytest tests/ -v
```

### C++ Tools

#### Requirements (Debian/Ubuntu)
```bash
apt install cmake make g++ openssl zlib1g zlib1g-dev libssl-dev
```

#### Build
```bash
git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
cd HuaweiFirmwareTool
mkdir build && cd build
cmake ..
make
```

#### Usage: Firmware Pack/Unpack

```bash
# Unpack firmware
./hw_fmw -d unpack -u -f firmware.bin -v

# Pack firmware (mark items with '+' in unpack/item_list.txt)
./hw_fmw -d unpack -p -o new_firmware.bin -v
```

**item_list.txt format:**
```
HWNP(0x504e5748)
256 494|4B4|534|5D4|614|;COMMON|CMCC|
+ 0 file:/var/UpgradeCheck.xml UPGRDCHECK NULL 0
- 1 flash:flash_config FLASH_CONFIG NULL 0
+ 2 file:/var/hw_flashcfg_256.xml FLASH_CONFIG1 NULL 0
```

Fields: `+/-` (include flag) | index | item_path | section | version | policy

#### Usage: RSA Signing/Verification

```bash
# Generate RSA keys
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# Sign firmware items
./hw_sign -d unpack -k private.pem -o signature_file

# Verify signature
./hw_verify -d unpack -k public.pem -i signature_file
```

## OBSC Protocol Overview

The OBSC (ONT Bootloader Service Client) protocol uses UDP to discover and flash
firmware to Huawei ONT devices that are in bootloader mode:

1. **Discovery Phase**: Broadcast discovery packets to port 50000; ONTs respond with device info
2. **Control Phase**: Send firmware metadata (size, CRC32, frame parameters)
3. **Data Phase**: Fragment firmware into frames and send at configurable rate
4. **Result Phase**: Wait for flash confirmation from the device

## Supported Devices

- Huawei HG8145V5
- Huawei HG8245H
- Huawei HG8546M
- Huawei HG8247H
- Huawei EG8145V5
- Other Huawei ONT devices using HWNP firmware format

## License

See [LICENSE](LICENSE) for details.
