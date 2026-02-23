# ONT Firmware Flasher - Open Source GUI Tool

[![Build Windows EXE](https://github.com/Uaemextop/HuaweiFirmwareTool/actions/workflows/build-ont-flasher.yml/badge.svg)](https://github.com/Uaemextop/HuaweiFirmwareTool/actions/workflows/build-ont-flasher.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Windows 11](https://img.shields.io/badge/Windows-11-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows/windows-11)

Modern, open-source GUI application for flashing firmware to Huawei ONT (Optical Network Terminal) devices. Built with Python and PyQt6, designed specifically for Windows 11.

## ✨ Features

- 🖥️ **Modern Windows 11 UI** - Clean, intuitive interface with native look and feel
- 🔌 **Serial Communication** - Full support for COM port communication with ONT devices
- 📦 **Multiple Firmware Formats** - Support for .bin firmware files
- ⚙️ **Highly Configurable** - Customize timing, chunk size, retry logic, and more
- 📊 **Real-time Progress** - Visual progress bar and detailed logging
- 🎯 **Quick Presets** - Pre-configured settings for common devices (HG8145V5, HG8245)
- 💾 **Save/Load Configurations** - Save your settings for reuse
- 🔍 **Verification Support** - Optional firmware verification after flashing
- 🔄 **Auto-Reboot** - Automatically reboot device after successful flash
- 🐛 **Debug Mode** - Detailed protocol logging for troubleshooting
- 🧪 **Dry Run Mode** - Test flashing process without writing to device

## 📋 Requirements

### Runtime Requirements
- Windows 11 (or Windows 10 with compatibility mode)
- USB-to-Serial adapter or direct serial connection
- Administrator privileges (for serial port access)

### Development Requirements
- Python 3.9 or higher
- PyQt6
- pyserial
- PyInstaller (for building EXE)

## 🚀 Quick Start

### Download Pre-built EXE

Download the latest release from the [Releases page](https://github.com/Uaemextop/HuaweiFirmwareTool/releases).

1. Download `ONT-Flasher-GUI.exe` from the latest release
2. Run the executable (no installation required)
3. Select your COM port and firmware file
4. Click "Flash Firmware"

### Run from Source

```bash
# Clone the repository
git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
cd HuaweiFirmwareTool/ont-flasher-gui

# Install dependencies
pip install -r requirements.txt

# Run the application
python src/main.py
```

## 📖 Usage Guide

### Basic Flashing Process

1. **Select COM Port**: Choose the serial port your ONT is connected to
2. **Configure Timing**:
   - For HG8145V5 unlock: Use 1400ms timeout, 5ms delay
   - For standard operations: Use 1200ms timeout, 10ms delay
3. **Select Firmware**: Browse and select your firmware .bin file
4. **Flash**: Click "Flash Firmware" and wait for completion

### Using Presets

Quick preset configurations are available in the **Configuration** tab:

- **HG8145V5 Unlock**: Optimized for unlock operations (1400ms, 5ms)
- **HG8245 Standard**: Standard settings for HG8245 devices
- **Custom**: Create your own configuration

### Advanced Options

The **Advanced** tab provides:

- **Max Retry Count**: Number of retries for failed chunks (default: 3)
- **Chunk Size**: Data chunk size for transfer (default: 1024 bytes)
- **Debug Mode**: Enable detailed protocol logging
- **Dry Run Mode**: Simulate flash without actual device writing

### Configuration Management

Save and load your configurations:

1. Configure all settings as desired
2. Go to **Configuration** tab
3. Click **Save Configuration**
4. Choose a location for your .ini file

To load:
1. Click **Load Configuration**
2. Select your saved .ini file

## 🔧 Building from Source

### Build Standalone EXE

```bash
# Install build dependencies
pip install -r requirements.txt

# Run build script
python build_exe.py
```

The compiled EXE will be in the `dist/` directory.

### GitHub Actions Automated Build

The project includes a GitHub Actions workflow that automatically:
- Builds the Windows EXE on every push to main
- Uploads artifacts for testing
- Creates releases with downloadable executables

See `.github/workflows/build-ont-flasher.yml` for details.

## 📁 Project Structure

```
ont-flasher-gui/
├── src/
│   ├── main.py                 # Application entry point
│   ├── gui/
│   │   ├── __init__.py
│   │   └── main_window.py      # Main GUI window
│   ├── core/
│   │   ├── __init__.py
│   │   ├── serial_manager.py   # Serial communication
│   │   └── firmware_flasher.py # Flashing logic
│   └── utils/
│       ├── __init__.py
│       └── logger.py            # Logging utilities
├── resources/                   # Icons and resources
├── config/                      # Configuration files
├── docs/                        # Documentation
├── requirements.txt             # Python dependencies
├── build_exe.py                # Build script for EXE
└── README.md                    # This file
```

## 🔒 Security Considerations

- **Administrator Rights**: Required for serial port access on Windows
- **Device Safety**: Always backup current firmware before flashing
- **Verification**: Enable firmware verification to ensure data integrity
- **Dry Run**: Test your configuration with dry run mode first

## ⚠️ Disclaimer

This tool is provided for educational and research purposes. Flashing firmware may:

- Void device warranty
- Violate ISP terms of service
- Result in device malfunction ("bricking")
- Be illegal in some jurisdictions

Always:
- Backup current firmware if possible
- Understand what you're flashing
- Consult with your ISP
- Know local regulations

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 🔗 Related Documentation

- [EXE Analysis Report](../EXE_ANALYSIS_REPORT.md) - Technical analysis of original tools
- [Spanish Documentation](../ANALISIS_ES.md) - Documentación en español
- [Main Repository](../README.md) - HuaweiFirmwareTool main documentation

## 📞 Support

For issues and questions:
- Open an issue on [GitHub Issues](https://github.com/Uaemextop/HuaweiFirmwareTool/issues)
- Check existing documentation in the `docs/` folder

## 🙏 Acknowledgments

This open-source tool was developed based on analysis of:
- ONT_V100R002C00SPC253.exe (Official Huawei tool)
- 1211.exe (Community unlock tool)

Special thanks to the reverse engineering community for understanding these protocols.

---

**Built with ❤️ for the open-source community**

**Version**: 1.0.0
**Last Updated**: February 2026
