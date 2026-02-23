# ONT Flasher GUI - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [First Time Setup](#first-time-setup)
4. [Basic Usage](#basic-usage)
5. [Advanced Features](#advanced-features)
6. [Troubleshooting](#troubleshooting)
7. [FAQ](#faq)

## Introduction

ONT Flasher GUI is an open-source tool for flashing firmware to Huawei ONT (Optical Network Terminal) devices. It provides a user-friendly graphical interface for what was previously only available through command-line tools.

### What is an ONT?

An ONT is a device that connects fiber optic cable from your ISP to your home network. Flashing firmware allows you to:
- Update to newer software versions
- Fix bugs or security issues
- Unlock ISP-specific limitations (where legal)
- Customize device behavior

### Safety First

⚠️ **Important Warnings:**
- Flashing firmware can permanently damage ("brick") your device if done incorrectly
- Always backup current firmware if possible
- Ensure stable power supply during flashing
- Do not interrupt the process once started
- Check compatibility before flashing
- Consult your ISP before making changes

## Installation

### Option 1: Pre-built Executable (Recommended)

1. Go to the [Releases page](https://github.com/Uaemextop/HuaweiFirmwareTool/releases)
2. Download the latest `ONT-Flasher-GUI-vX.X.X.exe`
3. No installation required - just run the .exe file

### Option 2: Run from Source

```bash
# Requirements: Python 3.9+
git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
cd HuaweiFirmwareTool/ont-flasher-gui
pip install -r requirements.txt
python src/main.py
```

## First Time Setup

### Hardware Setup

1. **Connect your ONT:**
   - Connect ONT to power supply
   - Connect ONT to computer using USB-to-Serial adapter
   - Note the COM port number (e.g., COM3, COM4)

2. **Identify COM Port:**
   - Open Device Manager (Windows key + X, then M)
   - Expand "Ports (COM & LPT)"
   - Find your USB-to-Serial adapter
   - Note the COM port number

### Software Setup

1. **Run as Administrator:**
   - Right-click ONT-Flasher-GUI.exe
   - Select "Run as administrator"
   - This is required for serial port access

2. **First Launch:**
   - The application will create a `logs/` folder for logging
   - Default settings are pre-configured for common use cases

## Basic Usage

### Simple Firmware Flash

1. **Select COM Port:**
   - Click the dropdown next to "COM Port"
   - Select your device's COM port
   - Click "Refresh" if your device doesn't appear

2. **Choose Firmware:**
   - Click "Browse..." next to "Firmware File"
   - Navigate to your .bin firmware file
   - Select and confirm

3. **Configure Timing (Optional):**
   - For HG8145V5 unlock: 1400ms timeout, 5ms delay
   - For standard flash: 1200ms timeout, 10ms delay
   - Or use a preset from the Configuration tab

4. **Start Flashing:**
   - Click "Flash Firmware" button
   - Confirm the operation
   - Wait for completion (typically 5-10 minutes)
   - **Do not disconnect or power off during flashing!**

5. **Completion:**
   - Progress bar will show 100%
   - Log will display "Flash completed successfully!"
   - Device will automatically reboot (if enabled)

### Using Quick Presets

Save time with preconfigured settings:

1. Go to **Configuration** tab
2. Click a preset button:
   - **HG8145V5 Unlock**: Optimized for unlock operations
   - **HG8245 Standard**: Default settings for HG8245
   - **Custom**: Start with default settings
3. Return to **Flash Firmware** tab
4. Settings are now applied

## Advanced Features

### Custom Timing Configuration

Fine-tune communication parameters:

- **Timeout (ms)**: Maximum wait time for device response
  - Too low: Premature timeouts
  - Too high: Slow recovery from errors
  - Recommended: 1200-1400ms

- **Delay (ms)**: Pause between commands
  - Too low: Device may miss commands
  - Too high: Unnecessarily slow
  - Recommended: 5-10ms

### Advanced Protocol Settings

Access via **Advanced** tab:

- **Max Retry Count**: Retries for failed chunks (1-10)
- **Chunk Size**: Data transfer size (128-4096 bytes)
  - Smaller: More reliable, slower
  - Larger: Faster, less reliable
  - Recommended: 1024 bytes

### Developer Options

For debugging and testing:

- **Debug Mode**: Logs all protocol details
- **Dry Run Mode**: Simulates flash without writing
  - Use this to test configuration safely
  - No data is written to device

### Configuration Management

Save your settings for reuse:

1. Configure all options as desired
2. **Configuration** tab → **Save Configuration**
3. Choose filename (e.g., `hg8145v5-unlock.ini`)
4. Settings saved!

To load later:
1. **Configuration** tab → **Load Configuration**
2. Select your .ini file
3. Settings applied!

### Firmware Verification

Ensure data integrity:

1. **Configuration** tab
2. Check "Verify firmware after flashing"
3. Flash as normal
4. Tool will verify MD5 checksum after writing

### Auto-Reboot

Automatically restart device after flash:

1. **Configuration** tab
2. Check "Automatically reboot device after flash"
3. Device will reboot when flash completes

## Troubleshooting

### "No COM ports found"

**Causes:**
- USB-to-Serial adapter not connected
- Driver not installed
- Device not recognized

**Solutions:**
1. Check physical connection
2. Install CH340/FTDI drivers
3. Try different USB port
4. Check Device Manager for errors
5. Click "Refresh" button

### "Failed to connect to device"

**Causes:**
- Wrong COM port selected
- Device not in flash mode
- Another program using port
- Incorrect baud rate

**Solutions:**
1. Verify COM port in Device Manager
2. Close other serial programs (PuTTY, etc.)
3. Try different baud rates
4. Put device in flash/recovery mode
5. Restart device and try again

### "Flash operation failed"

**Causes:**
- Connection interrupted
- Corrupted firmware file
- Incompatible firmware
- Device not responsive

**Solutions:**
1. Check all physical connections
2. Verify firmware file integrity
3. Try lower chunk size (512 bytes)
4. Increase timeout value
5. Enable "Verify" option
6. Check logs for specific errors

### Device "bricked" (won't boot)

**Prevention:**
- Always use correct firmware
- Never interrupt flashing
- Ensure stable power
- Test with dry run first

**Recovery:**
- Some devices have TFTP recovery
- Some have UART recovery mode
- Consult device-specific recovery guides
- May require professional repair

### Slow Performance

**Solutions:**
1. Increase chunk size to 2048 bytes
2. Decrease retry count to 2
3. Disable verification (not recommended)
4. Close other applications
5. Use direct USB connection (not hub)

## FAQ

### Q: Is this tool safe to use?

A: The tool itself is safe, but flashing firmware always carries risk. Follow all safety guidelines and understand what you're flashing.

### Q: Will this void my warranty?

A: Possibly yes. Check your device warranty terms. Modifying firmware typically voids warranties.

### Q: Can I unbrick my device with this tool?

A: No. This tool requires a functional device. Bricked devices need special recovery procedures.

### Q: What firmware formats are supported?

A: Currently .bin files. The firmware should be in raw binary or HWNP format.

### Q: How long does flashing take?

A: Typically 5-15 minutes depending on:
- Firmware size
- Chunk size
- Timing configuration
- Device response time

### Q: Can I use this on other brands?

A: This tool is designed for Huawei ONT devices. It may work with compatible devices but is not tested or guaranteed.

### Q: Why does it need administrator rights?

A: Windows requires administrator privileges to access serial (COM) ports directly.

### Q: Can I flash multiple devices?

A: Yes, but one at a time. Select different COM ports for each device.

### Q: What if flashing gets stuck?

A: Wait at least 15 minutes. If truly stuck:
1. Note the percentage
2. Check logs
3. Click "Stop" button
4. Power cycle device
5. Try again with different settings

### Q: How do I report bugs?

A: Open an issue on [GitHub Issues](https://github.com/Uaemextop/HuaweiFirmwareTool/issues) with:
- Error message
- Log file (from logs/ folder)
- Device model
- Firmware file (name only)
- Steps to reproduce

## Additional Resources

- [Technical Documentation](../../EXE_ANALYSIS_REPORT.md)
- [Spanish Guide](../../ANALISIS_ES.md)
- [GitHub Repository](https://github.com/Uaemextop/HuaweiFirmwareTool)
- [Issue Tracker](https://github.com/Uaemextop/HuaweiFirmwareTool/issues)

## Support

For help:
1. Check this user guide
2. Review log files in `logs/` folder
3. Search existing GitHub issues
4. Create new issue with details

---

**Remember: Always backup, double-check compatibility, and never interrupt flashing!**
