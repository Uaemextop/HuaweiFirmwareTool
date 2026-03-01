# Open OBSC Tool — Open-source ONT Firmware Flashing Tool

A graphical, open-source replacement for the proprietary Huawei OBSCTool.exe and OntSoftwareBroadcaster.exe firmware flashing tools.

## Features

- **Load & Inspect** HWNP firmware packages — view items, sections, versions, and policies
- **Build Custom Packages** — create HWNP firmware files with your own items and scripts
- **Discover Devices** — find ONT devices on the local network via UDP broadcast
- **Flash Firmware** — send firmware to individual or all discovered devices
- **Configurable Settings** — port, chunk size, retry interval, network interface, board filters
- **Extract Items** — unpack all items from a firmware package to disk
- **Generate UpgradeCheck.xml** — create hardware validation files with customizable checks
- **Calculate Hashes** — SHA-256 verification for firmware files
- **Operation Logging** — timestamped log of all operations

## Requirements

- Python 3.8 or later
- tkinter (included with Python on Windows)
- No external dependencies for the GUI

## Quick Start

### Run from Source

```bash
cd opensource_tool
python open_obsc_tool.py
```

### Build Standalone Executable (Windows)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "OpenOBSCTool" --icon=icon.ico open_obsc_tool.py
```

The built executable will be in the `dist/` directory.

## Usage Guide

### Loading Firmware

1. Click **📂 Load Firmware** or use File → Load Firmware
2. Select a `.bin` or `.hwnp` file
3. The firmware items will be displayed in the table

### Building Custom Packages

1. Click **🔨 Build Package**
2. Add items using **Add File...** (scripts, binaries, configs)
3. Use **Add UpgradeCheck.xml** to include a hardware validation bypass
4. Set the board filter list (leave empty for universal compatibility)
5. Set policy=2 for scripts that should auto-execute on the device
6. Click **Build Package** to save

### Discovering Devices

1. Configure the broadcast port and network interface in Settings
2. Click **🔍 Discover Devices**
3. ONT devices on the network will appear in the Discovered Devices list

### Flashing Firmware

1. Load a firmware package
2. Optionally select a specific device from the list
3. Click **⚡ Flash Firmware**
4. Monitor progress in the status bar and log

### Settings

| Setting | Description | Default |
|---|---|---|
| Broadcast Port | UDP port for OBSC protocol | 1200 |
| Chunk Size | Bytes per UDP packet | 1400 |
| Retry Interval | Milliseconds between packets | 10 |
| Interface | Network interface to use | All (0.0.0.0) |
| Board Filter | Restrict to specific board types | (empty = all) |
| Bypass Checks | Disable UpgradeCheck.xml validation | Yes |

## Architecture

```
opensource_tool/
├── open_obsc_tool.py    # Main GUI application (tkinter)
├── hwnp.py              # HWNP firmware format parser/builder
├── obsc_protocol.py     # OBSC UDP broadcast protocol
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

### Module Overview

- **`hwnp.py`** — Pure Python implementation of the Huawei HWNP firmware format, based on `huawei_header.h` from this repository. Supports reading, writing, and building firmware packages.

- **`obsc_protocol.py`** — Implementation of the OBSC (ONT Board Service Client) protocol for discovering and flashing ONT devices over UDP broadcast.

- **`open_obsc_tool.py`** — tkinter GUI that ties everything together. Provides firmware inspection, package building, device discovery, and firmware flashing in a user-friendly interface.

## Comparison with Original Tools

| Feature | OBSCTool (2021) | OntSoftwareBroadcaster (2014) | **Open OBSC Tool** |
|---|---|---|---|
| Source | Closed | Closed | **Open source** |
| Platform | Windows only | Windows only | **Cross-platform** |
| GUI | MFC (Chinese) | MFC (Chinese) | **tkinter (English)** |
| Firmware loading | Embedded in .exe | External files | **Both supported** |
| Package building | No | No | **Yes** |
| Item extraction | No | No | **Yes** |
| Settings | Limited | Limited | **Fully configurable** |
| Board filter | Fixed | Fixed | **Customizable** |
| UpgradeCheck | Fixed | Fixed | **Customizable** |
| Dependencies | OpenSSL, Poco | None | **Python stdlib only** |

## License

Unlicense (Public Domain) — same as the parent HuaweiFirmwareTool project.
