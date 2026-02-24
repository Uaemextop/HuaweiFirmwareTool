# HuaweiFirmwareTool

Open-source toolkit for Huawei ONT (Optical Network Terminal) firmware management.
Includes a modern GUI application for firmware flashing via the OBSC protocol, C++ utilities for firmware packing/signing, and a PE analysis tool.

## Features

### OBSC Firmware Tool (Python GUI)
- **Device Discovery**: Automatically discover ONT devices on the local network via UDP broadcast
- **Firmware Flashing**: Flash HWNP firmware packages to Huawei ONTs using the OBSC protocol
- **Configuration Crypto**: Encrypt/decrypt Huawei config files (hw_ctree.xml) with AES-128-CBC
- **Terminal Access**: Telnet and Serial console access to ONT devices
- **Firmware Dump**: Extract MTD partitions from devices via shell commands
- **Preset Management**: Save and load router-specific configurations
- **CRC32 Verification**: Validate firmware integrity before flashing
- **Modern UI**: Windows 11 themed interface with dark/light mode

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
├── obsc_tool/               # Python GUI application
│   ├── main.py              # Application entry point
│   ├── protocol.py          # OBSC UDP protocol implementation
│   ├── firmware.py          # HWNP firmware parser
│   ├── config_crypto.py     # AES-128-CBC config encryption
│   ├── network.py           # Network adapter discovery & UDP transport
│   ├── terminal.py          # Telnet/Serial terminal clients
│   ├── presets.py           # Router preset management
│   ├── splash.py            # Splash screen & dependency installer
│   └── gui/                 # GUI tab mixins
│       ├── upgrade_tab.py   # Firmware upgrade UI
│       ├── crypto_tab.py    # Config encryption UI
│       ├── terminal_tab.py  # Terminal emulation UI
│       ├── settings_tab.py  # Settings & adapter config
│       └── ...              # Other tabs
├── cpp/                     # C++ firmware tools
│   ├── CMakeLists.txt       # CMake build configuration
│   ├── hw_fmw.cpp           # Firmware pack/unpack
│   ├── hw_sign.cpp          # RSA firmware signing
│   ├── hw_verify.cpp        # RSA signature verification
│   └── ...                  # Utility modules
├── tools/                   # Standalone analysis tools
│   └── analyze_exe.py       # PE32 executable analyzer
├── tests/                   # Unit tests
│   ├── test_config_crypto.py
│   ├── test_firmware.py
│   ├── test_network.py
│   ├── test_presets.py
│   └── test_protocol.py
└── run_obsc_tool.py         # GUI launcher with dependency check
```

## Quick Start

### Python GUI Application

```bash
# Install dependencies
pip install -r obsc_tool/requirements.txt

# Run the application
python run_obsc_tool.py

# Or run directly (without splash screen)
python -m obsc_tool.main
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
