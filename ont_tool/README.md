# ONT Broadcast Tool

Open-source Python GUI replacement for the Huawei **OBSCTool**
(`ONT_V100R002C00SPC253.exe`) and **OntSoftwareBroadcaster** (`1211.exe`).

Broadcasts HWNP firmware packages to Huawei ONT (Optical Network Terminal)
devices over UDP for firmware upgrade and configuration unlock.

> See [ONT_EXE_ANALYSIS.md](../ONT_EXE_ANALYSIS.md) for the full reverse-engineering
> analysis of the original executables.

---

## Features

| Feature | Original EXEs | This tool |
|---------|--------------|-----------|
| UDP firmware broadcast | ✓ | ✓ |
| V3 / V5 package support | ✓ | ✓ |
| Custom firmware file | ✗ | ✓ |
| HWNP package inspector | ✗ | ✓ |
| Network interface selector | ✗ | ✓ |
| UDP port configuration | ✗ | ✓ |
| Packet interval config | ✓ (limited) | ✓ |
| Timeout / retry config | ✗ | ✓ |
| Per-device progress tracking | ✓ | ✓ |
| Log export | ✗ | ✓ |
| Dark / light mode | ✗ | ✓ |
| Settings persistence | ✗ | ✓ |
| Open source | ✗ | ✓ |

---

## Screenshot

The application uses a modern Windows 11 interface (dark/light mode via
[customtkinter](https://github.com/TomSchimansky/CustomTkinter)):

- **Top**: Network interface selection with broadcast address
- **Left**: Firmware package selection + quick settings
- **Right**: Device session list with progress bars
- **Bottom**: Operation log (matches original OBSC log format)

---

## Quick Start

### Option A — Pre-built EXE (Windows)

1. Download `ONTBroadcastTool.exe` from the [Releases](../../releases) page
2. Run it — no installation required
3. Select your network interface
4. Select a firmware package (or browse for a custom `.bin`)
5. Click **▶ Start**

### Option B — Run from source

```bash
# Install dependencies
pip install -r requirements.txt

# Run the tool
python main.py
```

### Option C — Build EXE yourself

```bash
pip install -r requirements.txt
pip install pyinstaller
pyinstaller ONTTool.spec --clean
# Output: dist/ONTBroadcastTool.exe
```

---

## Firmware Packages

The tool supports **any valid HWNP `.bin` file**. For the original OBSCTool
built-in packages (V3/V5/new devices), place the corresponding firmware files
alongside the EXE:

| Slot     | File      | Description |
|----------|-----------|-------------|
| Package 1 | `pkg1.bin` | V3 firmware devices (R13–R17) |
| Package 2 | `pkg2.bin` | V5 firmware devices (full module) |
| Package 3 | `pkg3.bin` | Newer devices |

Or select **Custom firmware file** and browse for any `.bin` HWNP package
(e.g. `1-TELNET.bin`, `2-UNLOCK.bin` from DESBLOQUEIO.rar).

---

## HG8145V5 Unlock (R22 → R20)

Based on `METODO DE DESBLOQUEIO R22.txt`:

1. **Settings**: Set port to `1400`, interval to `5 ms`
2. **Step 1**: Select `HG8145V5_V2_HG8145V5.bin` as custom firmware → Start → wait ~8–9 min
3. **Step 2**: Select `1-TELNET.bin` → Start → wait for success → Stop
4. **Step 3**: Select `2-UNLOCK.bin` → Start → ONT reboots unlocked → Stop

---

## Settings

All settings are persisted to:
- **Windows**: `%APPDATA%\ONTBroadcastTool\settings.json`
- **Linux/macOS**: `~/.ont_broadcast_tool/settings.json`

| Setting | Default | Description |
|---------|---------|-------------|
| UDP Port | `1400` | Target port on ONT devices |
| Packet Interval | `5 ms` | Delay between successive UDP packets |
| Operation Timeout | `60 s` | Max wait time per device |
| Retry Count | `3` | Packet retries on send error |
| Chunk Size | `1024 B` | Bytes per UDP datagram |
| Broadcast Address | `255.255.255.255` | Override per-interface broadcast |
| Theme | `dark` | `dark` / `light` / `system` |
| Auto-save Log | `true` | Save log on close |

---

## Architecture

```
ont_tool/
├── main.py                   Entry point
├── requirements.txt          Python dependencies
├── ONTTool.spec              PyInstaller build spec
└── src/
    ├── hwnp.py               HWNP firmware format parser
    ├── broadcaster.py        UDP broadcast engine
    ├── network.py            Network interface enumeration
    ├── config.py             Settings persistence
    └── gui/
        └── main_window.py    Main application window (customtkinter)
```

---

## HWNP Protocol

The Huawei HWNP (`0x504e5748`) firmware format is documented in
[`huawei_header.h`](../huawei_header.h). The broadcast flow:

```
PC (ONT Broadcast Tool)                ONT device
        |                                   |
        |── UDP broadcast (HWNP data) ─────>|
        |                                   | validate UpgradeCheck.xml
        |                                   | flash package items
        |                                   | execute scripts (duit9rr.sh)
        |                                   |   → cfgtool set TELNETLanEnable=1
        |                                   |   → aescrypt2 re-encrypt ctree
        |<── reboot & apply ─────────────── |
```

---

## Dependencies

- [customtkinter](https://github.com/TomSchimansky/CustomTkinter) — Modern GUI
- [Pillow](https://python-pillow.org/) — Required by customtkinter
- [psutil](https://github.com/giampaolo/psutil) — Network interface enumeration
