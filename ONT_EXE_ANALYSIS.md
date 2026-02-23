# ONT Firmware Tool Analysis

## Overview

This document covers the static analysis of two executables related to Huawei ONT (Optical Network Terminal) firmware management:

1. **`ONT_V100R002C00SPC253.exe`** — The main OBSCTool (ONT Broadband Service Console Tool) from this repository's V2 release.
2. **`1211.exe`** — An older OntSoftwareBroadcaster found inside `DESBLOQUEIO.R22.HG8145V5.E.HG8145V5V2.rar`.

Both tools serve the same fundamental purpose: **broadcast firmware upgrade packages to Huawei ONT devices over UDP**, enabling modification of the device's configuration tree (hw_ctree.xml) — including enabling Telnet/SSH/web access.

---

## 1. ONT_V100R002C00SPC253.exe

### Basic Information

| Property | Value |
|----------|-------|
| Internal Name | `OBSCTool.exe` |
| Product Name | OBSCTool |
| Version | 1.0.0.1 |
| Build Timestamp | 2021-03-03 09:13:12 UTC |
| Format | PE32, Win32 GUI, Intel i386 |
| File Size | ~8.7 MB |
| Compiler | Visual C++ (MFC 14.0) |
| Libraries | Poco framework, TinyXML, OpenSSL, GDI+ |
| Entry Point RVA | 0x1929c1 |
| Image Base | 0x400000 |

### PE Sections

| Section | Virtual Address | Raw Size | Purpose |
|---------|----------------|----------|---------|
| `.text` | 0x1000 | ~3 MB | Executable code |
| `.rdata` | 0x30e000 | ~961 KB | Read-only data, import table |
| `.data` | 0x401000 | ~48 KB | Writable data |
| `.gfids` | 0x41a000 | ~107 KB | Guard CFG function ID table |
| `.giats` | 0x435000 | 16 bytes | Guard IAT table |
| `.tls` | 0x436000 | 9 bytes | Thread Local Storage |
| `.rsrc` | 0x437000 | ~4.3 MB | Resources (firmware packages, icons, dialogs) |
| `.reloc` | 0x88a000 | ~214 KB | Relocations |

### Architecture and Framework

The application is built using **Microsoft MFC (Microsoft Foundation Classes)** with the **Poco C++ framework** for threading and notifications. Key class names found in RTTI data:

- `COBSCToolApp` — Main MFC application class
- `COBSCToolDlg` — Main dialog window class
- `COBSCWorker` (in `ONTFrameWork` namespace) — Background worker thread
- `CDialogChannel`, `CCtrlPktSender`, `CDataPktSender` — Communication classes
- `CUDPSender`, `CUdp` — UDP network transport classes
- `MailSlotServer` — Windows Mailslot IPC server
- `CMachineManage`, `CMachinePkg`, `CMachineCtrl*Pkg` — Device/machine management
- `CAuditInfoMgr`, `CEquipsAuditLog` — Audit logging
- `TiXml*` — TinyXML XML parsing
- `CIMachineCheckPolicy` — Hardware compatibility policy

### Imported DLLs and Notable Functions

| DLL | Key Functions / Purpose |
|-----|------------------------|
| `WS2_32.dll` | TCP/UDP socket communication |
| `IPHLPAPI.DLL` | `GetAdaptersAddresses` — enumerate network adapters |
| `ADVAPI32.dll` | `CryptGenRandom`, `CryptAcquireContext`, Registry access, Event logging |
| `KERNEL32.dll` | File I/O, Threading, Process management, Mailslot (`CreateMailslotW`, `GetMailslotInfo`) |
| `USER32.dll` | Full GUI framework (windows, dialogs, menus, drag & drop) |
| `GDI32.dll` | Custom drawing, bitmap handling |
| `gdiplus.dll` | Advanced image rendering |
| `SHELL32.dll` | File browser dialogs, `ShellExecuteW` |
| `ole32.dll` | COM/OLE, Clipboard, Drag-drop |
| `CRYPT32.dll` | Certificate handling |
| `bcrypt.dll` | `BCryptGenRandom` — cryptographic random |
| `WINMM.dll` | `PlaySoundW` — audio notifications |
| `UxTheme.dll` | Visual themes |

### User Interface

The application displays a dialog (`COBSCToolDlg`) with a **list box containing three firmware package options**:

```
使能包1---适用于大多数V3版本设备  (Package 1 — For most V3 version devices)
使能包2---适用于大多数V5版本设备  (Package 2 — For most V5 version devices)
使能包3---适用于部分新设备        (Package 3 — For some newer devices)
```

Additional UI elements include connection/timing parameters (baud rate, timeout), a log window, and Start/Stop buttons.

A log file is written to: `%PROGRAM%\log\OBSC_Debug.log`

### Embedded Firmware Packages (PE Resources)

The `.rsrc` section contains **six HWNP firmware packages** as BIN resources at resource IDs 130–135:

#### BIN_130 (~274 KB) — V3 Multi-version Equipment Package

Contains equipment archives for all firmware revisions from R13C10 through R17C00, plus the main upgrade script (`duit9rr.sh`). Supports hardware products: `120|130|140|141|150|160|170|171|180|190|...`

Items embedded:
- `UpgradeCheck.xml` — hardware compatibility checks (all checks disabled)
- `equipment_R13C10.tar.gz` through `equipment_R17C00.tar.gz` — version-specific configuration bundles
- `duit9rr.sh` — main upgrade script (15 KB, see below)
- `ramcheck` — binary RAM check utility

#### BIN_131 (~2 MB) — V5 Full Module Package

Contains the large GPON equipment module plus the Telnet/SSH enabler script.

Items embedded:
- `UpgradeCheck.xml`
- `signature` — RSA signature (SIGNINFO, 16 KB)
- `equipment.tar.gz` (~2 MB) — full equipment module
- `run.sh` — Telnet/SSH enabler script

#### BIN_132 (~140 KB) — Factory Restore Component Deletion

Items embedded:
- `UpgradeCheck.xml`
- `junk_file` (128 KB padding)
- `restorefactory_DeleteComponent.sh` — removes factory-restore hooks

#### BIN_133 and BIN_135 (~26 KB each) — Minimal V5 Package with run.sh

Two identical lightweight packages containing only the signature and `run.sh` script. BIN_135 is a byte-for-byte duplicate of BIN_133, likely included as a fallback/redundant copy.

Items embedded in each:
- `UpgradeCheck.xml`
- `signature` (SIGNINFO, 16 KB)
- `run.sh` — Telnet/SSH enabler script (~7 KB)

#### BIN_134 (~1.8 MB) — V5 Full Package with Telnet/SSH + ProductLineMode

Items embedded:
- `UpgradeCheck.xml`
- `signinfo_v5` (SIGNINFO, 13 KB)
- `ProductLineMode` — empty marker file (triggers product line behavior)
- `equipment.tar.gz` (~1.7 MB) — full V5 equipment module
- `TelnetEnable` — empty marker file (triggers Telnet enable)
- `duit9rr.sh` — main upgrade script (~6 KB)

### Embedded Script Analysis (`duit9rr.sh` / `run.sh`)

These shell scripts run **on the ONT device** after the firmware package is flashed. They implement the actual unlock logic.

#### Key Variables

```sh
var_jffs2_current_ctree_file="/mnt/jffs2/hw_ctree.xml"
var_current_ctree_bak_file="/var/hw_ctree_equipbak.xml"
var_pack_temp_dir="/bin/"  # location of aescrypt2 tool
```

#### Key Functions

**`HW_Open_TelnetSSH_Ctree_Node()`** — Enables Telnet and SSH in the configuration tree:
```sh
# 1. Copy the current encrypted/compressed config
cp -f /mnt/jffs2/hw_ctree.xml /var/hw_ctree_equipbak.xml

# 2. Attempt AES decryption (aescrypt2 mode 1 = decrypt)
/bin/aescrypt2 1 /var/hw_ctree_equipbak.xml /var/hw_ctree.xml.tmp

# 3. If encrypted, decompress the gzip layer
gunzip -f /var/hw_ctree_equipbak.xml.gz

# 4. Set Telnet/SSH nodes via cfgtool
cfgtool set /var/hw_ctree_equipbak.xml \
    InternetGatewayDevice.X_HW_Security.AclServices TELNETLanEnable 1
cfgtool set /var/hw_ctree_equipbak.xml \
    InternetGatewayDevice.X_HW_Security.AclServices SSHLanEnable 1
cfgtool set /var/hw_ctree_equipbak.xml \
    InternetGatewayDevice.UserInterface.X_HW_CLITelnetAccess Access 1

# 5. Add SSH control node if not present
cfgtool find /var/hw_ctree_equipbak.xml \
    InternetGatewayDevice.UserInterface.X_HW_CLISSHControl
cfgtool add ...  # if not found

# 6. Re-encrypt and replace the config file
gzip -f /var/hw_ctree_equipbak.xml
/bin/aescrypt2 0 /var/hw_ctree_equipbak.xml /var/hw_ctree.xml.tmp
cp -f /var/hw_ctree_equipbak.xml /mnt/jffs2/hw_ctree.xml
```

**`HW_Script_Encrypt(flag, path)`** — Conditionally re-encrypts config:
- Uses `gzip` + `aescrypt2 mode 0` (encrypt) with key derived from chip ID

**Version detection** — Parses `/etc/version` to extract V, R, C, SPC components and applies version-specific compatibility logic.

**Password clearing** — Clears LOID, EPON key, and serial number passwords from hw_boardinfo:
```sh
cfgtool set /mnt/jffs2/hw_boardinfo.xml BoardInfo.loid infoStr ""
cfgtool set /mnt/jffs2/hw_boardinfo.xml BoardInfo.snpassword infoStr ""
```

### Communication Protocol

The tool uses **UDP broadcast** to communicate with ONT devices on the local network:

1. `CUDPSender` opens a UDP socket and broadcasts to the LAN
2. `CDialogChannel` manages the dialog/handshake with the ONT
3. `CDataPktSender` streams the firmware package data
4. `MailSlotServer` receives status messages from the worker thread
5. The log format is: `[ONT_SN][Equipment_SN] Start/Finish upgrade!uiRet=0xHHHHHHHH`

**Known return codes:**
- `0x00000000` — Success
- `0xf720404f` — Error (upgrade rejected / incompatible version)
- `0xf7204028` — Error (signature/checksum mismatch)
- `0xf7204007` — Error (device busy / connection refused)
- `0xf7204050` — Error (timeout or repeated failure)

### Credential Found in Binary

A plaintext password string is present in the executable:
```
!#hwont89@
```
This is likely a default debug/maintenance credential for the ONT serial console.

---

## 2. 1211.exe (from DESBLOQUEIO.rar — FERRAMENTA HUAWEI)

### Basic Information

| Property | Value |
|----------|-------|
| Internal Name | `OntSoftwareBroadcaster.EXE` |
| Product Name | OntSoftwareBroadcaster |
| Description | Microsoft 基础类应用程序 (MFC Application) |
| Declared Version | 1.0.0.0 |
| Build Timestamp | 2014-08-15 01:55:16 |
| Format | PE32, Win32 GUI, Intel i386 |
| File Size | ~2.3 MB |
| Protection | **ZPByPassAll 1.0 RC3 by cektop** (Chinese PE obfuscation) |
| Requires Admin | Yes (manifest: `requireAdministrator`) |

### Protection Analysis

The executable is protected with **ZPByPassAll 1.0 RC3**, a Chinese PE protector that:
- Randomizes section names (`lS8TSGXu`, `HWB8zP1w`, `QrVbjeUa`, `LEXmTy1n`, `niBTgJWZ`, `sfW0L9wz`)
- Encrypts/compresses the main code section (`QrVbjeUa`, entropy ≈ 7.79 — fully encrypted)
- Decompresses and executes code at runtime
- The entry point section (`HWB8zP1w`) contains a stub loader

The `.text` section has `VSize = 0x20dc2c` but `RawSize = 0` (mapped entirely in memory by the loader).

### Relationship to ONT_V100R002C00SPC253.exe

`1211.exe` is an **earlier version** of the same ONT firmware broadcast tool (OBSCTool). Both tools:
- Are MFC-based Windows GUI applications
- Broadcast HWNP firmware packages via UDP to Huawei ONT devices
- Produce log files in the format `[SN][ESNO] Start/Finish upgrade!uiRet=0x...`
- Target the HG8145V5 and similar Huawei ONT hardware

---

## 3. DESBLOQUEIO.R22.HG8145V5.E.HG8145V5V2.rar — Archive Contents

This RAR5 archive (52 MB) is a complete HG8145V5 unlock kit for R22 firmware. It contains:

```
DESBLOQUEIO R22 HG8145V5 E HG8145V5V2/
├── DONGRAD R20/
│   └── HG8145V5_V2_HG8145V5.bin     (47 MB) — Downgrade firmware R22→R20
├── FERRAMENTA HUAWEI/
│   ├── 1211.exe                       (2.3 MB) — OntSoftwareBroadcaster tool
│   ├── OSBC_LOG_2025-02-19_20.log    — Sample upgrade log
│   ├── OSBC_LOG_2025-02-19_23.log    — Sample upgrade log
│   ├── OSBC_LOG_2025-02-20_00.log    — Sample upgrade log
│   ├── OSBC_LOG_2025-02-20_01.log    — Sample upgrade log
│   └── OSBC_LOG_2025-04-29_21.log    — Sample upgrade log
├── METODO DE DESBLOQUEIO R22.txt     — Step-by-step instructions (Portuguese)
└── UNLOCK/
    ├── 1-TELNET.bin                   (1.8 MB) — HWNP package: enable Telnet
    └── 2-UNLOCK.bin                   (179 KB) — HWNP package: write modified hw_ctree.xml
```

### Unlock Packages

#### 1-TELNET.bin
HWNP firmware package (same structure as BIN_134 in OBSCTool). Contents:
- `UpgradeCheck.xml` — all hardware checks disabled
- `signinfo_v5` — V5 signature (13 KB)
- `ProductLineMode` — empty marker (triggers product line mode)
- `equipment.tar.gz` — V5 equipment module (1.7 MB)
- `TelnetEnable` — empty marker (triggers Telnet enable)
- `duit9rr.sh` — Telnet/SSH enable script

Supported products: `120|130|140|141|150|160|170|171|180|190|1B1|1A1|...`

#### 2-UNLOCK.bin
HWNP firmware package containing a **pre-modified hw_ctree.xml** (174 KB) for product `111`.

Key settings in the configuration:
```xml
<!-- Telnet and HTTP access enabled, SSH disabled -->
<AclServices HTTPLanEnable="1" HTTPWanEnable="0"
             TELNETLanEnable="1" TELNETWanEnable="0"
             SSHLanEnable="0" SSHWanEnable="0"
             HTTPPORT="80" TELNETPORT="23" />

<!-- CLI Telnet access enabled -->
<X_HW_CLITelnetAccess Access="1" TelnetPort="23"/>

<!-- Root CLI user (password bcrypt-hashed) -->
<X_HW_CLIUserInfoInstance InstanceID="1"
    Username="root"
    Userpassword="$2;..."
    ModifyPWDFlag="0"
    EncryptMode="3"/>

<!-- Web users: root and telecomadmin (bcrypt-hashed) -->
<X_HW_WebUserInfoInstance InstanceID="1" UserName="root" Password="$2..."/>
<X_HW_WebUserInfoInstance InstanceID="2" UserName="telecomadmin" Password="$2..."/>
```

---

## 4. Step-by-Step Unlock Process (HG8145V5 R22)

From `METODO DE DESBLOQUEIO R22.txt` (translated from Portuguese):

```
STEP 1: Open 1211.exe
        Change timing: 1200 → 1400 (baud/rate parameter)
                       10ms → 5ms  (packet interval)
        These changes are REQUIRED.

STEP 2: Select HG8145V5_V2_HG8145V5.bin (downgrade R22 → R20)
        Wait approximately 8–9 minutes for success.
        After success the ONT will freeze its LEDs and reboot.

STEP 3: Select 1-TELNET.bin (REQUIRED)
        Wait for success. Then STOP the tool.
        The ONT will start blinking LEDs and reboot automatically.

STEP 4: Select 2-UNLOCK.bin
        ONT reboots automatically. Stop the tool.
        The ONT is now UNLOCKED.
```

### Technical Flow

```
[PC running OBSCTool/1211.exe]
         |
         | UDP broadcast (HWNP firmware packet)
         v
[HG8145V5 ONT device]
    |
    | Receives and flashes HWNP package
    | Runs embedded script (duit9rr.sh / run.sh)
    |   → aescrypt2 decrypt hw_ctree.xml
    |   → cfgtool set TELNETLanEnable=1
    |   → cfgtool set SSHLanEnable=1
    |   → aescrypt2 re-encrypt hw_ctree.xml
    |   → replace /mnt/jffs2/hw_ctree.xml
    v
[ONT reboots with Telnet/SSH enabled]
```

---

## 5. Analysis Summary

| Component | Purpose |
|-----------|---------|
| `ONT_V100R002C00SPC253.exe` | GUI tool to broadcast HWNP firmware packages to Huawei ONT devices via UDP. Embeds 6 firmware packages (V3/V5 variants) that enable Telnet/SSH access. |
| `1211.exe` | Older version of the same broadcast tool (OntSoftwareBroadcaster, 2014), protected with ZPByPassAll packer. |
| `HG8145V5_V2_HG8145V5.bin` | Full HG8145V5 firmware (R20) used as downgrade target from locked R22. |
| `1-TELNET.bin` | HWNP package that enables Telnet on V5 ONTs by running `duit9rr.sh`. |
| `2-UNLOCK.bin` | HWNP package that replaces `hw_ctree.xml` with a pre-configured version having Telnet/Web access enabled and known root/telecomadmin credentials. |

### Key Technologies

- **HWNP** (`0x504e5748`): Huawei's proprietary firmware container format with CRC32 checksums and RSA signature support (see `huawei_header.h`).
- **hw_ctree.xml**: Huawei ONT's TR-069-style device configuration tree. Stored encrypted (AES-256-CBC) + gzipped in JFFS2 flash at `/mnt/jffs2/hw_ctree.xml`.
- **aescrypt2**: ONT-side tool that encrypts/decrypts hw_ctree.xml. Key = `"Df7!ui%s9(lmV1L8"` with chip ID substituted for `%s`.
- **cfgtool**: ONT-side configuration editor that manipulates hw_ctree.xml nodes.
- **UDP broadcast upgrade**: The OBSCTool sends HWNP packages via UDP to devices on the LAN, which the ONT's upgrade daemon receives and processes.
