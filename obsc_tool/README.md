# OBSC Firmware Tool

Open-source reimplementation of the Huawei OBSCTool for flashing firmware
to ONT (Optical Network Terminal) devices via the OBSC UDP protocol.

## Features

- **Network adapter selection** with auto-detection
- **HWNP firmware validation** — parses and validates CRC32 checksums
- **OBSC UDP protocol** — discovers and flashes ONT devices on the local network
- **Configurable transfer parameters:**
  - Frame size (1200, 1400, 1472, 4096, 8192 bytes)
  - Frame interval (1, 2, 5, 10, 20, 50 ms)
  - Flash mode (Normal / Forced)
  - Delete existing configuration option
  - Upgrade type (Standard / Equipment / Equipment WC)
  - Machine filter by serial number
- **Real-time progress** with transfer speed and ETA
- **Device discovery** — finds ONT devices in bootloader mode
- **Audit logging** — OBSC_LOG format
- **Dark / Light theme** — Windows 11 native look
- **Advanced settings:**
  - Custom send/receive ports
  - Broadcast address override
  - Configurable timeout
  - Auto-save logs

## Requirements

- Python 3.10 or later
- tkinter (included with Python on Windows)
- No external dependencies

## Usage

### Run from source

```bash
python run_obsc_tool.py
```

Or directly:

```bash
python -m obsc_tool.main
```

### Pre-built Windows EXE

Download `OBSCFirmwareTool.exe` from
[Releases](https://github.com/Uaemextop/HuaweiFirmwareTool/releases).

### Build EXE locally

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name OBSCFirmwareTool --add-data "obsc_tool;obsc_tool" run_obsc_tool.py
```

The executable will be in the `dist/` directory.

## How It Works

The tool implements the **OBSC** (ONT Bootloader Service Client) protocol:

1. **Discovery** — Sends UDP broadcast packets to find ONT devices in bootloader mode
2. **Control** — Sends firmware metadata (size, CRC32, frame parameters)
3. **Data Transfer** — Fragments firmware into frames and sends via UDP
4. **Verification** — Device validates HWNP signature and writes to flash

### Protocol Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| Frame Size | Size of each UDP data frame | 1400 bytes |
| Frame Interval | Delay between frames | 5 ms |
| Flash Mode | Normal or Forced write | Normal |
| Delete Config | Clear device configuration | No |
| Send Port | UDP destination port | 50000 |
| Receive Port | UDP listen port | 50001 |

## Project Structure

```
obsc_tool/
├── __init__.py      — Package metadata
├── main.py          — GUI application (tkinter)
├── firmware.py      — HWNP firmware parser and validator
├── network.py       — Network adapter discovery and UDP transport
├── protocol.py      — OBSC protocol implementation
└── requirements.txt — Build dependencies (PyInstaller)
```

## License

Unlicense — See [LICENSE](../LICENSE) for details.
