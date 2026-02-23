# DESBLOQUEIO R22 HG8145V5 — RAR Archive Analysis Report

## 1. Overview

| Property | Value |
|---|---|
| **File name** | `DESBLOQUEIO.R22.HG8145V5.E.HG8145V5V2.rar` |
| **Archive type** | RAR v5 |
| **File size** | 52,725,203 bytes (50.27 MB) |
| **SHA-256** | `4e4f99d4c2f9e4c57f031ef27e5e3696a80c5914b0d0e8b22afb384549a628db` |
| **Contents** | 10 files in 5 folders |
| **Uncompressed size** | 53,431,147 bytes (50.94 MB) |
| **Purpose** | HG8145V5 unlock/downgrade toolkit for R22 firmware |

## 2. Archive Contents

```
DESBLOQUEIO R22 HG8145V5 E HG8145V5V2/
└── DESBLOQUEIO R22 HG8145V5 E HG8145V5V2/
    ├── METODO DE DESBLOQUEIO R22.txt          (539 B)   — Instructions
    ├── FERRAMENTA HUAWEI/                                — Huawei flash tool
    │   ├── 1211.exe                           (2.26 MB) — OntSoftwareBroadcaster v1.12
    │   ├── OSBC_LOG_2025-02-19_20.log         (1.1 KB)  — Operation log
    │   ├── OSBC_LOG_2025-02-19_23.log         (2.6 KB)  — Operation log
    │   ├── OSBC_LOG_2025-02-20_00.log         (3.5 KB)  — Operation log
    │   ├── OSBC_LOG_2025-02-20_01.log         (1.0 KB)  — Operation log
    │   └── OSBC_LOG_2025-04-29_21.log         (1.0 KB)  — Operation log
    ├── DONGRAD R20/                                      — Downgrade firmware
    │   └── HG8145V5_V2_HG8145V5.bin           (46.7 MB) — Full rootfs firmware
    └── UNLOCK/                                           — Unlock firmware packages
        ├── 1-TELNET.bin                        (1.76 MB) — Telnet enabler
        └── 2-UNLOCK.bin                        (179 KB)  — Config unlock
```

## 3. Unlock Instructions (Translated from Portuguese)

The file `METODO DE DESBLOQUEIO R22.txt` contains these steps:

> **UNLOCK METHOD R22**
>
> 1. Open the tool. **Change from 1200 to 1400 and from 10ms to 5ms** (these are network parameters — port and retry interval). **This is mandatory.**
>
> 2. Select the file `HG8145V5_V2_HG8145V5` (downgrade firmware). Wait approximately 8–9 minutes until success. After success, the ONT LEDs will freeze and the device will restart.
>
> 3. Select `TELNET`. **This is mandatory.** Wait for success. Then stop the tool and select `UNLOCK`. The ONT will start blinking again and restart automatically. Stop the tool — the ONT is now unlocked.

### Unlock Process Flow

```
Step 1: Downgrade R22 → R20        (HG8145V5_V2_HG8145V5.bin, ~8-9 min)
        ↓
Step 2: Enable Telnet               (1-TELNET.bin, quick)
        ↓
Step 3: Apply Unlock Config          (2-UNLOCK.bin, quick)
        ↓
Result: ONT unlocked, telnet accessible
```

## 4. Tool: 1211.exe (OntSoftwareBroadcaster v1.12)

### 4.1 File Properties

| Property | Value |
|---|---|
| **Internal name** | `OntSoftwareBroadcaster.EXE` |
| **File description** | OntSoftwareBroadcaster Microsoft Application |
| **File version** | 1, 0, 0, 0 |
| **File size** | 2,366,464 bytes (2.26 MB) |
| **SHA-256** | `a3b6b88c4bee07b58800bcd3d545d5ee8ad805c0ea0111fb9e4b8ae9e109a94a` |
| **Compile timestamp** | 2014-08-15 01:55:16 UTC |
| **Linker version** | 10.0 (MSVC 2010) |
| **Target OS** | Windows XP+ (subsystem version 5.1) |
| **Image version** | 0.1423 |
| **Locale** | 0804 (Chinese Simplified) |

### 4.2 Key Differences from ONT_V100R002C00SPC253.exe

| Feature | 1211.exe (v1.12, 2014) | ONT_V100R002C00SPC253.exe (2021) |
|---|---|---|
| **Name** | OntSoftwareBroadcaster | OBSCTool |
| **Size** | 2.26 MB | 8.68 MB |
| **Compiled** | 2014-08-15 | 2021-03-03 |
| **MSVC** | 10.0 (VS2010) | 14.0 (VS2015) |
| **Min OS** | Windows XP | Windows Vista |
| **Embedded firmware** | None (external files) | 6 HWNP packages |
| **Architecture** | Simpler, standalone | ONTFrameWork + Poco |
| **Protection** | **Packed/obfuscated sections** | Standard PE |
| **OpenSSL** | Not detected | Statically linked |

### 4.3 Packing/Protection Analysis

The 1211.exe uses **obfuscated section names** and has characteristics of a packed executable:

| Section | Virtual Size | Raw Size | Ratio | Notes |
|---|---|---|---|---|
| `lS8TSGXu` | 0x0020DC2C | 0x00000000 | ∞ | **VSize >>0, RawSize=0** — unpacked at runtime |
| `HWB8zP1w` | 0x00002000 | 0x00001600 | 1.5x | Contains entry point + unpacker |
| `QrVbjeUa` | 0x00216000 | 0x00215200 | ~1x | Main packed data |
| `LEXmTy1n` | 0x00001000 | 0x00000600 | 2.7x | Small data |
| `niBTgJWZ` | 0x00029000 | 0x00028600 | ~1x | Resources |
| `sfW0L9wz` | 0x00001000 | 0x00000400 | 4x | Small data |
| `.text` | 0x00002000 | 0x00002000 | 1x | Unpacker stub |

The first section has **virtual size 2.1 MB but raw size 0** — this is the hallmark of runtime unpacking. The entry point (0x20F2FD) is in the second section, which serves as the unpacker stub.

### 4.4 Imported DLLs

Same network-capable imports as the newer version:

- `WS2_32.dll` — Winsock (UDP communication)
- `iphlpapi.dll` — Network interface enumeration
- `COMCTL32.dll`, `COMDLG32.dll` — GUI controls
- `GDI32.dll`, `gdiplus.dll` — Graphics
- `KERNEL32.dll`, `USER32.dll` — Windows core
- `ADVAPI32.dll` — Security
- `WINMM.dll` — Timers
- Standard MFC/OLE DLLs

## 5. Firmware Package Analysis

### 5.1 HG8145V5_V2_HG8145V5.bin — Downgrade Firmware

| Property | Value |
|---|---|
| **File size** | 49,026,072 bytes (46.75 MB) |
| **SHA-256** | `3a5466532817d0eaac9b1cd1d655b4c8508ae92e5eb095d81628bff119d78877` |
| **Format** | HWNP (0x504E5748) |
| **Item count** | 2 |
| **Board list** | Universal (empty) |
| **Version** | V500R020C00SPC458B001 |

**Contents:**

| # | Target | Section | Size | Version |
|---|---|---|---|---|
| 0 | `flash:rootfs` | ROOTFS | 49,024,992 B (46.7 MB) | V500R020C00SPC458B001 |
| 1 | `file:/var/efs` | EFS | 68 B | V500R020C00SPC458B001 |

This is a **complete rootfs image** that overwrites the device's root filesystem. The version V500R020C00SPC458B001 corresponds to the R20 firmware (downgrade target from R22).

### 5.2 1-TELNET.bin — Telnet Enabler

| Property | Value |
|---|---|
| **File size** | 1,845,780 bytes (1.76 MB) |
| **SHA-256** | `101e1c0cd2d220c5f24d7961439fd5b200f22993009a806c0a7ca5004e3a03c1` |
| **Format** | HWNP |
| **Item count** | 8 |
| **Board list** | `120\|130\|140\|141\|150\|160\|170\|171\|180\|190\|1B1\|1A1\|1A0\|1B0\|1D0\|1F1\|201\|211\|221\|230\|240\|260\|261\|270\|271\|280\|281\|291\|2A1\|431\|2D7\|2D7D\|2D7D.A\|` |

**Contents:**

| # | Target Path | Section | Size | Purpose |
|---|---|---|---|---|
| 0 | `/var/UpgradeCheck.xml` | UPGRDCHECK | 1,069 B | All checks disabled |
| 1 | `/var/signinfo_v5` | SIGNINFO | 13,868 B | V5 signature info |
| 2 | `/mnt/jffs2/ProductLineMode` | UNKNOWN | 1 B | ProductLine mode flag |
| 3 | `/var/equipment.tar.gz` | UNKNOWN | 1,784,882 B | Equipment files (~1.7 MB) |
| 4 | `/mnt/jffs2/TelnetEnable` | UNKNOWN | 1 B | **Telnet enable flag file** |
| 5 | `/var/duit9rr.sh` | UNKNOWN | 5,811 B | **Upgrade/telnet script** (policy=2) |
| 6 | `/mnt/jffs2/Equip.sh` | UNKNOWN | 36,908 B | Equipment installation script |
| 7 | `/var/efs` | EFS | 68 B | EFS marker |

This package enables telnet by:
1. Writing "1" to `/mnt/jffs2/TelnetEnable`
2. Setting ProductLineMode flag
3. Deploying equipment files
4. Running `duit9rr.sh` to modify `hw_ctree.xml` configuration

### 5.3 2-UNLOCK.bin — Configuration Unlock

| Property | Value |
|---|---|
| **File size** | 182,972 bytes (179 KB) |
| **SHA-256** | `67ad540f6c257f51e9e2d4a0f148edf7160b0073fca9bc792c2d62591b904e3a` |
| **Format** | HWNP |
| **Item count** | 4 |
| **Board list** | `111\|` (restricted to board type 111) |

**Contents:**

| # | Target Path | Section | Size | Purpose |
|---|---|---|---|---|
| 0 | `/var/UpgradeCheck.xml` | UPGRDCHECK | 1,069 B | All checks disabled |
| 1 | `/tmp/hw_ctree.xml` | UNKNOWN | 178,984 B | **Custom config tree (179 KB)** |
| 2 | `/var/singature` | upgradematch | 1,119 B | Upgrade match signature (note: typo "singature") |
| 3 | `/var/signature` | SIGNATURE | 68 B | Package signature |

This package replaces the device configuration tree (`hw_ctree.xml`) with a pre-configured version that has all restrictions removed. The misspelling of "singature" in item 2 is notable.

## 6. OSBC Log Analysis

The included log files show real unlock sessions performed on 2025-02-19/20 and 2025-04-29:

### Successful Operations (uiRet=0x0)

```
2025-02-19 20:42:22 [...RYQ5028248] Finish upgrade!uiRet=0x0     ← Downgrade success (~9 min)
2025-02-19 20:47:23 [...RYQ5028248] Finish upgrade!uiRet=0x0     ← Telnet enable success (~20 sec)
2025-04-29 21:18:23 [...RYQ1018699] Finish upgrade!uiRet=0x0     ← Downgrade success (~8 min)
2025-04-29 21:34:10 [...RYQ1018699] Finish upgrade!uiRet=0x0     ← Telnet success (~7 min)
2025-04-29 21:52:08 [...RYQ1018699] Finish upgrade!uiRet=0x0     ← Unlock success (~32 sec)
```

### Common Errors

| Code | Occurrences | Meaning |
|---|---|---|
| `0xf720404f` | Multiple | Version mismatch — device already at target version |
| `0xf7204028` | ~12 times | Timeout — device with SN `028JFFEGM9503019` repeatedly timed out (9 min each attempt) |
| `0xf7204007` | ~20 times | Device busy or wrong state — repeated rapid retries |
| `0xf7204050` | Multiple | Upgrade rejected |
| `0xf7204045` | 2 times | Verification failure |

### Devices Identified in Logs

| Board SN | 21-inch SN | Status |
|---|---|---|
| `029TTYRYQ7023137` | `2102314BUGRYQ7921338` | Successfully unlocked |
| `029TTYRYQ5028248` | `2102314BUGRYQ5933044` | Successfully unlocked |
| `029TTYRYP6026975` | `2102314BUGRYP6925621` | Successfully unlocked |
| `028BKVAGM8036351` | `2150084664AGM8037909` | Mixed results |
| `028JFFEGM9503019` | `2150084664EGM9048978` | Persistent timeout (0xf7204028) |
| `029TTYRYQ1018699` | `2102314BUGRYQ2906832` | Successfully unlocked (April 2025) |

## 7. Complete Unlock Workflow Diagram

```
  ┌──────────────────────────────────────────────────────┐
  │              STEP 1: DOWNGRADE (R22 → R20)           │
  │                                                      │
  │  PC (1211.exe) ──UDP broadcast──→ ONT (HG8145V5)    │
  │  Sends: HG8145V5_V2_HG8145V5.bin (46.7 MB)         │
  │  Contains: V500R020C00SPC458B001 rootfs              │
  │  Duration: ~8-9 minutes                              │
  │  Result: Device reboots with R20 firmware            │
  └──────────────┬───────────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────────┐
  │              STEP 2: ENABLE TELNET                   │
  │                                                      │
  │  PC (1211.exe) ──UDP broadcast──→ ONT (R20)         │
  │  Sends: 1-TELNET.bin (1.76 MB)                      │
  │  Actions on ONT:                                     │
  │    • Write /mnt/jffs2/TelnetEnable = 1               │
  │    • Write /mnt/jffs2/ProductLineMode                │
  │    • Extract equipment.tar.gz                        │
  │    • Execute duit9rr.sh (modifies hw_ctree.xml)      │
  │    • Enable TELNETLanEnable, SSHLanEnable            │
  │  Duration: ~20-30 seconds                            │
  └──────────────┬───────────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────────┐
  │              STEP 3: APPLY UNLOCK CONFIG              │
  │                                                      │
  │  PC (1211.exe) ──UDP broadcast──→ ONT (R20+telnet)  │
  │  Sends: 2-UNLOCK.bin (179 KB)                        │
  │  Actions on ONT:                                     │
  │    • Replace hw_ctree.xml with custom config          │
  │    • Device reboots with unlocked configuration       │
  │  Duration: ~30 seconds                               │
  │  Result: ONT fully unlocked                          │
  └──────────────────────────────────────────────────────┘
```

## 8. Comparison: OBSCTool (2021) vs OntSoftwareBroadcaster (2014)

Both tools serve the same fundamental purpose — broadcasting firmware to Huawei ONT devices via UDP — but the 2021 version is significantly more capable:

| Aspect | v1.12 (1211.exe, 2014) | V100R002C00SPC253 (2021) |
|---|---|---|
| **Firmware loading** | External .bin files selected by user | 6 packages embedded in resources |
| **Protocol** | Basic UDP broadcast | Enhanced with Poco threading |
| **Security** | Basic (packed/protected binary) | OpenSSL + RSA + Huawei cert chain |
| **GUI** | Simple MFC dialog | Rich MFC with multiple dialogs |
| **Logging** | OSBC log files | Structured audit logging |
| **Device management** | Basic | Full machine management framework |
| **Executable protection** | Heavy packing/obfuscation | Standard PE (no packing) |

The older 1211.exe (v1.12) is actually **more heavily protected** (packed with obfuscated section names and runtime unpacking), while the newer version relies on standard PE structure but includes sophisticated firmware signing and verification through OpenSSL.
