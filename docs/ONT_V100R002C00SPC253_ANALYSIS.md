# ONT_V100R002C00SPC253.exe — Binary Analysis Report

## 1. Overview

| Property | Value |
|---|---|
| **File name** | `ONT_V100R002C00SPC253.exe` |
| **Internal name** | `OBSCTool.exe` (ONT Board Service Client Tool) |
| **File type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **File size** | 9,101,312 bytes (8.68 MB) |
| **SHA-256** | `c882032e2dcd1a3ea2fc5e359e7c22a94d024fb0ae7e7be2f1cefd341796f8ec` |
| **Compile timestamp** | 2021-03-03 09:13:12 UTC |
| **Linker version** | 14.0 (MSVC 2015+) |
| **Target OS** | Windows (GUI subsystem, min version 6.0 = Vista) |
| **Image base** | 0x00400000 |
| **Entry point** | 0x001929C1 |
| **PDB path** | `D:\Work2015\Components\ONTFrameWork\Release\OBSCToolClient.pdb` |

## 2. What Is This Program?

**OBSCTool** (ONT Board Service Client) is a **Windows-based firmware flashing/upgrade tool** used by Huawei (and ISP technicians) to push firmware updates to Huawei ONT (Optical Network Terminal) devices such as the HG8245, HG8145V5, and similar GPON/EPON equipment.

The tool communicates with ONT devices over a local network using **UDP broadcast** to discover devices and push HWNP firmware packages. It is built with:

- **MFC** (Microsoft Foundation Classes) for the GUI
- **Poco C++ Libraries** for threading, events, and networking
- **OpenSSL** (statically linked) for RSA signature verification and cryptographic operations
- A custom **ONTFrameWork** library for the firmware upgrade protocol

## 3. PE Structure

### 3.1 Sections

| Section | Virtual Address | Virtual Size | Raw Offset | Raw Size | Description |
|---|---|---|---|---|---|
| `.text` | 0x00001000 | 0x0030C5CA | 0x00000400 | 0x0030C600 | Executable code (~3.0 MB) |
| `.rdata` | 0x0030E000 | 0x000F2486 | 0x0030CA00 | 0x000F2600 | Read-only data (~970 KB) |
| `.data` | 0x00401000 | 0x00018AB4 | 0x003FF000 | 0x0000C000 | Initialized data |
| `.gfids` | 0x0041A000 | 0x0001ACDC | 0x0040B000 | 0x0001AE00 | Guard CF function IDs |
| `.giats` | 0x00435000 | 0x00000010 | 0x00425E00 | 0x00000200 | Guard IAT section |
| `.tls` | 0x00436000 | 0x00000009 | 0x00426000 | 0x00000200 | Thread-local storage |
| `.rsrc` | 0x00437000 | 0x004521E0 | 0x00426200 | 0x00452200 | **Resources (~4.3 MB, 49.8% of file)** |
| `.reloc` | 0x0088A000 | 0x00035B48 | 0x00878400 | 0x00035C00 | Relocations |

> **Key observation**: Nearly half the file (49.8%) is in the `.rsrc` section, which contains embedded HWNP firmware packages.

### 3.2 Imported DLLs

| DLL | Purpose |
|---|---|
| `KERNEL32.dll` | Core Windows API |
| `USER32.dll` | Window management, UI |
| `GDI32.dll` / `gdiplus.dll` | Graphics rendering |
| `WS2_32.dll` | **Winsock2 — network communication (UDP)** |
| `IPHLPAPI.DLL` | IP Helper — network interface enumeration |
| `ADVAPI32.dll` | Security, registry |
| `CRYPT32.dll` / `bcrypt.dll` | Cryptography |
| `SHELL32.dll` / `SHLWAPI.dll` | Shell functions |
| `COMCTL32.dll` / `Comdlg32.dll` | Common controls and dialogs |
| `OLEAUT32.dll` / `ole32.dll` | COM/OLE |
| `WINMM.dll` | Multimedia (timers) |
| `IMM32.dll` | Input method manager |
| `UxTheme.dll` | Visual themes |

### 3.3 Version Information (Resource)

```
FileDescription:    OBSCTool
FileVersion:        1.0.0.1
InternalName:       OBSCTool.exe
OriginalFilename:   OBSCTool.exe
ProductVersion:     1.0.0.1
CompanyName:        TODO: <Company name>
LegalCopyright:     TODO: (c) <Company name>. All rights reserved.
```

The "TODO" placeholders suggest this is an internal/engineering build not intended for public distribution.

## 4. Software Architecture (from String Analysis)

### 4.1 Class Hierarchy

The program is structured around the `ONTFrameWork` namespace with these key classes:

| Class | Role |
|---|---|
| `COBSCToolApp` | MFC Application class |
| `COBSCToolDlg` | Main dialog window |
| `COBSCWorker` | Core upgrade worker (Poco::Task) |
| `CMachineManage` | Manages connected ONT devices |
| `CMachineCtrlPkg` | Controls firmware package delivery |
| `CMachineCtrlEquipsWPkg` | Equipment-specific package control |
| `CMachineCtrl21Pkg` | 21-pin board variant package control |
| `CCtrlPktSender` | Control packet sender (UDP) |
| `CDataPktSender` | Data packet sender (firmware data) |
| `CUdp` / `CUDPSender` | UDP socket abstraction |
| `CDialogChannel` | Dialog-based progress channel |
| `CDlgFlash` | Flash progress dialog |
| `CAuditInfoMgr` | Audit logging manager |
| `MailSlotServer` | Inter-process communication via mailslots |

### 4.2 Worker Threads

The tool uses a multi-threaded architecture with Poco `Task` objects:

- `BaseProcesWorker` — Base processing worker
- `BaseSubmitWorker` — Base submission worker
- `CtrlWorker` — Control protocol worker
- `DataWorker` — Data transfer worker
- `CMOWorker` — Configuration management worker
- `MachineManageWorker` — Device management worker
- `DevelopLastProcessWorker` — Final processing worker

### 4.3 Firmware Protocol Fields

From string analysis, the OBSC protocol uses these fields:

| Field | Description |
|---|---|
| `OBSC_BoardSN` | Board serial number |
| `OBSC_21SN` | 21-inch rack serial number |
| `OBSC_MAC` | Device MAC address |
| `OBSC_Result` | Operation result code |
| `OBSC_CheckResult` | Validation check result |
| `OBSC_UpgradeType` | Type of upgrade being performed |
| `OBSC_VersionPkg` | Firmware package version |
| `OBSC_VersionPkgSize` | Package size |

### 4.4 Package Types

The tool handles different firmware package types:

- `ONT_PKG` — Standard ONT firmware package
- `ONT_21_PKG` — 21-inch variant package
- `ONT_WORD_PKG` — Word/configuration package
- `ONT_WORD_COUNTRY_PKG` — Country-specific configuration

## 5. Embedded HWNP Firmware Packages

The `.rsrc` section contains **6 HWNP firmware packages** as BIN resources (IDs 130–135). All start with the `HWNP` (0x504E5748) magic header.

### 5.1 Resource 130 — Equipment & Telnet Enabler (15 items, 274 KB)

**Board compatibility**: `120|130|140|141|150|160|170|171|180|190|1B1|1A1|1A0|1B0|1D0|1F1|201|211|221|230|240|260|261|270|271|280|281|291|2A1|431|`

| # | Target Path | Section | Size | Purpose |
|---|---|---|---|---|
| 0 | `/var/UpgradeCheck.xml` | UPGRDCHECK | 1,069 B | Hardware validation (all checks disabled) |
| 1 | `/var/signature` | SIGNATURE | 1,446 B | Package signature |
| 2 | `/mnt/jffs2/Updateflag` | UPDATEFLAG | 2 B | Update status flag |
| 3–11 | `/var/equipment_R*.tar.gz` | UNKNOWN | Various | Equipment files for firmware versions R13C10 through R17C00 |
| 12 | `/tmp/duit9rr.sh` | UNKNOWN | 15,613 B | **Main upgrade script** (policy=2, auto-execute) |
| 13 | `/tmp/ramcheck` | UNKNOWN | 14,686 B | RAM check utility binary |
| 14 | `/var/efs` | EFS | 68 B | Extended file system marker |

### 5.2 Resource 131 — Module/Equipment Installer (6 items, 1.98 MB)

**Board compatibility**: Universal (empty board list)

| # | Target Path | Section | Size | Purpose |
|---|---|---|---|---|
| 0 | `/var/UpgradeCheck.xml` | UPGRDCHECK | 1,069 B | Hardware validation |
| 1 | `/var/signature` | SIGNINFO | 16,384 B | Extended signature info |
| 2 | `/mnt/jffs2/Updateflag` | UPDATEFLAG | 2 B | Update flag |
| 3 | `/mnt/jffs2/equipment.tar.gz` | MODULE | 2,050,401 B | **Main equipment module** (~2 MB) |
| 4 | `/var/run.sh` | UNKNOWN | 6,838 B | **Telnet/SSH enabler script** (policy=2) |
| 5 | `/var/efs` | EFS | 68 B | EFS marker |

### 5.3 Resource 132 — Factory Reset + Junk Fill (5 items, 141 KB)

**Board compatibility**: Same as Resource 130

| # | Target Path | Section | Size | Purpose |
|---|---|---|---|---|
| 0 | `/var/UpgradeCheck.xml` | UPGRDCHECK | 1,069 B | Hardware validation |
| 1 | `/var/signature` | SIGNATURE | 529 B | Package signature |
| 2 | `/var/junk_file` | UNKNOWN | 131,072 B | **128 KB junk/padding file** |
| 3 | `/tmp/restorefactory_DeleteComponent.sh` | UNKNOWN | 9,199 B | **Factory reset script** (policy=2) |
| 4 | `/var/efs` | EFS | 68 B | EFS marker |

### 5.4 Resources 133 & 135 — Run Script (identical, 5 items, 26 KB)

**Board compatibility**: Universal (empty board list)

| # | Target Path | Section | Size | Purpose |
|---|---|---|---|---|
| 0 | `/var/UpgradeCheck.xml` | UPGRDCHECK | 1,069 B | Hardware validation |
| 1 | `/var/signature` | SIGNINFO | 16,384 B | Extended signature info |
| 2 | `/mnt/jffs2/Updateflag` | UPDATEFLAG | 2 B | Update flag |
| 3 | `/var/run.sh` | UNKNOWN | 7,150 B | **Telnet/SSH enabler + config modifier** (policy=2) |
| 4 | `/var/efs` | EFS | 68 B | EFS marker |

### 5.5 Resource 134 — Equipment + Telnet + ProductLine (7 items, 1.72 MB)

**Board compatibility**: Same as Resource 130

| # | Target Path | Section | Size | Purpose |
|---|---|---|---|---|
| 0 | `/var/UpgradeCheck.xml` | UPGRDCHECK | 1,069 B | Hardware validation |
| 1 | `/var/signinfo_v5` | SIGNINFO | 13,868 B | V5 signature info |
| 2 | `/mnt/jffs2/ProductLineMode` | UNKNOWN | 1 B | Product line mode flag |
| 3 | `/var/equipment.tar.gz` | UNKNOWN | 1,784,882 B | Equipment files (~1.7 MB) |
| 4 | `/mnt/jffs2/TelnetEnable` | UNKNOWN | 1 B | **Telnet enable flag** |
| 5 | `/var/duit9rr.sh` | UNKNOWN | 5,811 B | Upgrade script (policy=2) |
| 6 | `/var/efs` | EFS | 68 B | EFS marker |

## 6. Upgrade Script Analysis

### 6.1 `duit9rr.sh` — Main Upgrade Script

This is the primary upgrade script executed on the ONT device after firmware delivery. Key functions:

1. **Version Parsing** (`ParseVersion`): Parses the firmware version string (e.g., `V300R013C10SPC108`) into components V, R, C, SPC
2. **Telnet/SSH Enabling**: Sets `TELNETLanEnable`, `SSHLanEnable` to "1" via `cfgtool` on the device's XML configuration tree (`hw_ctree.xml`)
3. **Config Encryption Handling**: Detects if `hw_ctree.xml` is AES-encrypted, decrypts with `aescrypt2`, modifies, then re-encrypts
4. **Equipment Deployment**: Extracts version-specific equipment tarballs to `/mnt/jffs2/equipment` based on the current firmware version
5. **Board Info Processing**: Reads and processes `hw_boardinfo` for 5113/5115 chip variants
6. **Factory File Cleanup**: Removes old CRC files, backup configs, and service configurations

### 6.2 `run.sh` — Telnet/SSH Enabler Script

A focused script that:

1. Opens telnet/SSH control nodes in the config tree
2. Decrypts `hw_ctree.xml` if encrypted
3. Sets `TELNETLanEnable=1`, `SSHLanEnable=1`
4. Enables CLI access via `X_HW_CLITelnetAccess` and `X_HW_CLISSHControl`
5. Handles password modification flags (`ModifyPWDFlag`)
6. Re-encrypts the config and copies it back

### 6.3 `restorefactory_DeleteComponent.sh` — Factory Reset

Restores default configuration by:

1. Copying `/etc/wap/hw_default_ctree.xml` to `/mnt/jffs2/hw_ctree.xml`
2. Removing custom board info, modules, and equipment files
3. Cleaning up JFFS2 persistent storage

### 6.4 UpgradeCheck.xml — Hardware Validation

All hardware checks are **disabled** (`CheckEnable="0"`), meaning the firmware packages will be accepted by any ONT hardware:

```xml
<upgradecheck>
  <HardVerCheck CheckEnable="0">...</HardVerCheck>
  <LswChipCheck CheckEnable="0">...</LswChipCheck>
  <WifiChipCheck CheckEnable="0">...</WifiChipCheck>
  <VoiceChipCheck CheckEnable="0">...</VoiceChipCheck>
  <UsbChipCheck CheckEnable="0">...</UsbChipCheck>
  <OpticalCheck CheckEnable="0">...</OpticalCheck>
  <OtherChipCheck CheckEnable="0">...</OtherChipCheck>
  <ProductCheck CheckEnable="0">...</ProductCheck>
  <ProgramCheck CheckEnable="0">...</ProgramCheck>
  <CfgCheck CheckEnable="0">...</CfgCheck>
</upgradecheck>
```

## 7. How the Tool Works — Complete Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    OBSCTool.exe (PC)                        │
│                                                             │
│  1. User selects firmware package type in GUI               │
│  2. COBSCToolDlg initializes CMachineManage                 │
│  3. CUdp broadcasts UDP discovery packets                   │
│  4. ONT devices respond with BoardSN, MAC, 21SN             │
│  5. Tool validates device against UpgradeCheck.xml          │
│  6. COBSCWorker begins firmware transfer:                   │
│     a. CCtrlPktSender sends control packets                 │
│     b. CDataPktSender streams HWNP firmware data            │
│     c. Progress shown in CDlgFlash dialog                   │
│  7. ONT receives firmware, validates CRC32                  │
│  8. ONT extracts items to target paths                      │
│  9. Scripts with policy=2 auto-execute (run.sh/duit9rr.sh)  │
│ 10. Scripts enable telnet, deploy equipment, modify config   │
│ 11. ONT reboots with new configuration                      │
│ 12. Tool logs result: "Finish upgrade! uiRet=0x0" (success) │
└─────────────────────────────────────────────────────────────┘
```

### Error Codes (from log analysis)

| Code | Meaning |
|---|---|
| `0x0` | Success |
| `0xf720404f` | Firmware version mismatch / already at target version |
| `0xf7204028` | Communication timeout (device not responding) |
| `0xf7204050` | Upgrade rejected by device |
| `0xf7204007` | Device busy or in wrong state |
| `0xf7204045` | Verification failure |

## 8. Security Observations

1. **All hardware checks disabled**: The embedded `UpgradeCheck.xml` has every check set to `CheckEnable="0"`, making the firmware packages accepted by any device regardless of hardware
2. **AES config encryption**: Uses `aescrypt2` tool with key template `Df7!ui%s9(lmV1L8` where `%s` is the chip ID
3. **RSA signatures**: Packages include signature sections (`SIGNATURE`/`SIGNINFO`) but the tool includes OpenSSL for verification
4. **Policy=2 scripts**: Items with `policy=2` are auto-executed shell scripts on the target device
5. **Telnet/SSH force-enable**: Multiple scripts specifically enable telnet and SSH access

## 9. Libraries and Dependencies (Statically Linked)

| Library | Version Evidence | Purpose |
|---|---|---|
| OpenSSL | 1.x (from string patterns) | RSA, AES, certificate handling |
| Poco C++ Libraries | Foundation module | Threading, events, file I/O, logging |
| MFC (Microsoft Foundation Classes) | v14.0 | Windows GUI framework |
| Huawei Certificate Authority | Custom root CA | Firmware signature verification |

The binary references Huawei's internal certificate chain:
- `Huawei Code Signing Certificate Authority`
- `Huawei Timestamp Certificate Authority`
