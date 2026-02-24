# HuaweiFirmwareTool

[![Build Status](https://github.com/Uaemextop/HuaweiFirmwareTool/workflows/Build%20OBSC%20Firmware%20Tool/badge.svg)](https://github.com/Uaemextop/HuaweiFirmwareTool/actions)
[![Tests](https://github.com/Uaemextop/HuaweiFirmwareTool/workflows/Tests%20and%20Code%20Quality/badge.svg)](https://github.com/Uaemextop/HuaweiFirmwareTool/actions)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Professional toolset for modifying, signing, and flashing firmware to Huawei ONT (Optical Network Terminal) devices.**

This project provides both command-line C++ tools for firmware manipulation and a Python GUI application for flashing firmware via the OBSC protocol.

## ✨ Features

### C++ Firmware Tools
- 🔓 **Firmware Unpacking**: Extract items from HWNP firmware packages
- 📦 **Firmware Packing**: Repack modified firmware items
- 🔐 **RSA Signing**: Sign firmware with RSA-2048 keys
- ✅ **Signature Verification**: Verify firmware authenticity

### Python GUI Application (OBSC Tool)
- 🚀 **Firmware Flashing**: Upload firmware via OBSC protocol over UDP
- 🌐 **Network Adapter Selection**: Auto-detect and select network interfaces
- 🖥️ **Terminal Access**: Telnet and Serial console clients
- 🔒 **Configuration Encryption**: Encrypt/decrypt device configurations
- 📊 **Device Information**: Display ONT device details
- 💾 **Memory Dumping**: Extract device memory
- 🎨 **Modern UI**: Dark/light themes with ttkbootstrap

## 🚀 Quick Start

### Installation

#### Python GUI Tool

```bash
# Clone repository
git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
cd HuaweiFirmwareTool

# Install dependencies
pip install -r requirements.txt

# Run GUI application
python run_firmware_tool.py
```

#### C++ Tools (Linux/macOS)

**Debian/Ubuntu:**
```bash
sudo apt install cmake g++ libssl-dev zlib1g-dev
cd cpp
mkdir build && cd build
cmake ..
make
```

**macOS:**
```bash
brew install cmake openssl@3 zlib
cd cpp
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
make
```

**Windows:**
See [Building on Windows](#building-on-windows) section.

## 📖 Usage

### C++ Command-Line Tools

#### Unpacking Firmware

```bash
./hw_fmw -u -f firmware.bin -d output_dir/
```

This extracts all firmware items to `output_dir/` and creates:
- `item_list.txt` - List of firmware items
- `sig_item_list.txt` - Items to be signed
- Individual item files

**Example `item_list.txt`:**
```
HWNP(0x504e5748)
256 494|4B4|534|5D4|614|;COMMON|CMCC|
+ 0 file:/var/UpgradeCheck.xml UPGRDCHECK NULL 0
- 1 flash:flash_config FLASH_CONFIG NULL 0
+ 2 file:/var/hw_flashcfg_256.xml FLASH_CONFIG1 NULL 0
```

**Format:**
- `+`/`-` - Include/exclude item when packing
- `0` - Item index
- `file:/var/UpgradeCheck.xml` - Item path
- `UPGRDCHECK` - Section name
- `NULL` - Version (or version string)
- `0` - Policy flags

#### Modifying Firmware Items

1. Edit files in `output_dir/`
2. Mark items to include with `+` in `item_list.txt`
3. Repack firmware

#### Packing Firmware

```bash
./hw_fmw -p -d output_dir/ -o modified_firmware.bin
```

#### Signing Firmware

**Generate RSA Key Pair:**
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

**Sign Firmware:**
```bash
./hw_sign -d output_dir/ -k private.pem -o signature.bin
```

**Verify Signature:**
```bash
./hw_verify -d output_dir/ -k public.pem -i signature.bin
```

### Python GUI Application

1. **Launch Application:**
   ```bash
   python run_firmware_tool.py
   ```

2. **Load Firmware:**
   - Click "Load Firmware" button
   - Select `.bin` firmware file
   - Verify firmware information

3. **Select Network Adapter:**
   - Choose your network interface
   - Verify adapter IP address

4. **Configure Device:**
   - Enter device IP (default: 192.168.1.1)
   - Set OBSC port (default: 50000)
   - Configure authentication if needed

5. **Flash Firmware:**
   - Click "Start Upload"
   - Monitor progress bar
   - Wait for completion

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[API Documentation](docs/API.md)** - Complete API reference for all modules
- **[Architecture](docs/ARCHITECTURE.md)** - System design and component overview
- **[Development Guide](docs/DEVELOPMENT.md)** - Contributing and development workflow

### Quick Links

- [Firmware File Format (HWNP)](ANALISIS_EXE.md) - Detailed analysis of HWNP structure
- [OBSC Protocol](firmware_tool/README.md) - Protocol documentation
- [C++ Tools Help](#c-tools-detailed-usage)

## 🛠️ Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
cd HuaweiFirmwareTool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install package in editable mode
pip install -e .
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=obsc_tool --cov-report=html

# Run specific test file
pytest tests/unit/test_firmware.py -v
```

### Code Quality Checks

```bash
# Format code
black firmware_tool/
isort firmware_tool/

# Lint code
flake8 firmware_tool/
pylint firmware_tool/

# Type checking
mypy firmware_tool/
```

### Building Executables

**Python Executable (Windows):**
```bash
pip install -r requirements-build.txt
pyinstaller run_firmware_tool.py --onefile --windowed --name OBSCFirmwareTool
```

**C++ Tools:**
```bash
cd cpp/build
cmake --build . --config Release
```

## 🏗️ Project Structure

```
HuaweiFirmwareTool/
├── firmware_tool/              # Python GUI application
│   ├── main.py             # Main application
│   ├── firmware.py         # HWNP parser
│   ├── protocol.py         # OBSC protocol
│   ├── network.py          # Network layer
│   ├── terminal.py         # Terminal clients
│   └── gui/                # GUI modules
├── cpp/                    # C++ tools
│   ├── hw_fmw.cpp          # Pack/unpack tool
│   ├── hw_sign.cpp         # Signing tool
│   └── hw_verify.cpp       # Verification tool
├── tests/                  # Test suite
│   ├── unit/               # Unit tests
│   └── integration/        # Integration tests
├── docs/                   # Documentation
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── DEVELOPMENT.md
├── pyproject.toml          # Python project config
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## 🧪 Testing

This project includes comprehensive unit tests:

- **16 unit tests** for firmware parsing
- CRC32 validation tests
- Invalid file handling tests
- Product list parsing tests
- Item extraction tests

**Test Coverage:**
- `firmware_tool.firmware`: Well covered
- More tests coming for `protocol.py` and `network.py`

## 🔒 Security

### Cryptographic Operations

- **RSA-2048** keys for firmware signing
- **SHA-256** hashing algorithm
- **AES-256-ECB** for configuration encryption
- **CRC32** checksums for data integrity

### Security Considerations

⚠️ **Important:**
- This tool modifies device firmware - use at your own risk
- Always backup original firmware before modifications
- Verify signatures before flashing
- Incorrect firmware can brick devices

## 🌐 Supported Devices

Successfully tested on:
- HG8245H
- HG8310M
- HG8240H
- Other Huawei ONT models using HWNP firmware format

## 📋 Requirements

### Python Requirements
- Python 3.8 or later
- See `requirements.txt` for dependencies

### C++ Requirements
- CMake 3.12+
- C++17 compatible compiler
- OpenSSL (libssl-dev)
- zlib (zlib1g-dev)

### System Requirements
- Windows 10+ / Linux / macOS 10.15+
- Network adapter for firmware flashing
- 50MB free disk space

## 🔧 Building on Windows

**Using vcpkg:**

```powershell
# Install vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat

# Install dependencies
.\vcpkg install openssl:x64-windows-static zlib:x64-windows-static

# Build
cd HuaweiFirmwareTool/cpp
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE="[path-to-vcpkg]/scripts/buildsystems/vcpkg.cmake"
cmake --build . --config Release
```

## 🤝 Contributing

Contributions are welcome! Please see [DEVELOPMENT.md](docs/DEVELOPMENT.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes and add tests
4. Run tests: `pytest tests/`
5. Run linters: `black firmware_tool/ && flake8 firmware_tool/`
6. Commit changes: `git commit -m 'feat: Add amazing feature'`
7. Push branch: `git push origin feature/amazing-feature`
8. Open pull request

## 📜 License

This project is released into the **public domain** under the [Unlicense](LICENSE).

You are free to use, modify, and distribute this software without any restrictions.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk.

- Modifying firmware can void warranties
- Incorrect firmware can permanently damage devices
- Authors are not responsible for any damages

## 🙏 Acknowledgments

- Reverse engineering of Huawei firmware format
- OBSC protocol analysis
- Community contributions

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Uaemextop/HuaweiFirmwareTool/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Uaemextop/HuaweiFirmwareTool/discussions)
- **Documentation**: See `docs/` directory

## 🗺️ Roadmap

- [ ] Add more unit tests (protocol, network)
- [ ] Implement firmware validation/dry-run mode
- [ ] Add rollback mechanism
- [ ] Create REST API for automation
- [ ] Support for additional device models
- [ ] Firmware backup/restore functionality

## 📈 Project Statistics

- **Languages**: Python (84%), C++ (16%)
- **Total Lines**: ~7,700+
- **Tests**: 16 unit tests (growing)
- **Documentation**: 3 comprehensive guides
- **Supported Platforms**: Windows, Linux, macOS
- **Python Versions**: 3.8 - 3.12

---

**Made with ❤️ for the Huawei ONT community**
