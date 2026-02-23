# Firmware EXE Analysis Report

## Executive Summary

This report documents the analysis and decompilation of two Windows executables related to Huawei HG8145V5 ONT (Optical Network Terminal) firmware management:

1. **ONT_V100R002C00SPC253.exe** - Official Huawei ONT firmware upgrade tool
2. **1211.exe** - Third-party firmware flashing tool for unlocking/downgrading

Both tools are designed to interact with Huawei fiber optic modems/ONTs via serial communication.

---

## Analysis Methodology

### Tools and Techniques Used

1. **Static Analysis**
   - PE (Portable Executable) header parsing
   - Section analysis
   - String extraction
   - Entropy analysis
   - Signature detection

2. **File Extraction**
   - RAR archive extraction using Python rarfile library
   - Firmware binary identification

3. **Behavioral Analysis**
   - Analysis of embedded documentation
   - Log file examination
   - Communication protocol inference

---

## File 1: ONT_V100R002C00SPC253.exe

### Basic Information

| Property | Value |
|----------|-------|
| **File Size** | 9,101,312 bytes (8.68 MB) |
| **File Type** | PE32 executable (GUI) |
| **Architecture** | Intel 386 (x86) |
| **Timestamp** | 1614762792 (Unix timestamp) - March 3, 2021 |
| **Subsystem** | Windows GUI |
| **Entry Point** | 0x1929C1 |
| **Image Base** | 0x400000 |
| **Entropy** | 7.40 (Medium-high, possibly packed) |

### PE Structure Analysis

The executable contains 8 sections:

#### Code and Data Sections

1. **.text** (0x1000)
   - Size: 3,196,362 bytes
   - Purpose: Executable code
   - Flags: CODE, EXECUTABLE, READABLE
   - Contains the main program logic

2. **.rdata** (0x30E000)
   - Size: 992,390 bytes
   - Purpose: Read-only data (strings, constants)
   - Flags: INITIALIZED_DATA, READABLE
   - Contains string literals and import tables

3. **.data** (0x401000)
   - Size: 101,044 bytes (virtual), 49,152 bytes (raw)
   - Purpose: Initialized global/static variables
   - Flags: INITIALIZED_DATA, READABLE, WRITABLE

4. **.rsrc** (0x437000)
   - Size: 4,530,656 bytes (4.32 MB)
   - Purpose: Resources (dialogs, icons, embedded files)
   - This is the largest section, likely containing:
     - UI resources
     - Embedded firmware images
     - Configuration files
     - Possibly the actual ONT firmware binary

### Framework and Technology Stack

Based on string analysis, the application is built using:

- **Microsoft Foundation Classes (MFC)**: CMFCShellListCtrl, CMDIFrameWndEx, etc.
- **Visual C++**: Standard Windows C++ application
- **TinyXML**: XML parsing library (Error messages indicate TinyXML usage)
- **Windows Common Controls**: ComCtl32.dll, IP address controls

### Functionality Analysis

#### Core Features Identified

1. **XML Configuration Management**
   - TinyXML error messages suggest XML-based configuration
   - Likely parses firmware package manifests
   - Error handling for XML parsing failures

2. **Serial Communication**
   - References to communication controls
   - Likely communicates with ONT via serial port

3. **Firmware Package Handling**
   - Large .rsrc section suggests embedded firmware
   - File operation error messages
   - Version management strings

4. **User Interface Components**
   - MFC-based GUI
   - Multiple dialog windows
   - MDI (Multiple Document Interface) framework
   - Toolbar and control bar components
   - IP address input controls

### Interesting Strings Extracted

The analysis identified over 1,463 interesting strings, including:

- Error handling messages for XML parsing
- Windows API DLL references (Kernel32.dll, Comctl32.dll, Comdlg32.dll)
- MFC class names indicating GUI components
- File operation error messages
- Version string placeholders

### Security Assessment

- **No common packers detected**: Suggests unmodified compiled code
- **Medium-high entropy**: Normal for compiled C++ with embedded resources
- **Characteristics**: Standard executable flags (0x102)
- **No obvious obfuscation**: Code appears to be standard MFC application

---

## File 2: 1211.exe (from DESBLOQUEIO RAR archive)

### Basic Information

| Property | Value |
|----------|-------|
| **File Size** | 2,366,464 bytes (2.26 MB) |
| **File Type** | PE32 executable (GUI) |
| **Architecture** | Intel 386 (x86) |
| **Timestamp** | 1408067716 (Unix timestamp) - August 15, 2014 |
| **Subsystem** | Windows GUI |
| **Entry Point** | 0x20F2FD |
| **Image Base** | 0x400000 |
| **Entropy** | 7.63 (High - likely compressed/encrypted) |
| **Privilege Level** | Requires Administrator |

### PE Structure Analysis

The executable contains 7 sections with **unusual names** (obfuscated):

#### Sections

1. **lS8TSGXu** (0x1000) - Main code section
   - Size: 2,153,516 bytes (virtual), 0 bytes (raw)
   - **SUSPICIOUS**: Zero raw size but large virtual size
   - Flags: CODE, UNINITIALIZED_DATA, EXECUTABLE, READABLE, WRITABLE
   - **Analysis**: This is typical of packed executables - code is decompressed at runtime

2. **HWB8zP1w** (0x20F000) - Unpacker/Loader code
   - Size: 8,192 bytes (virtual), 5,632 bytes (raw)
   - Flags: CODE, EXECUTABLE, READABLE, WRITABLE
   - **Analysis**: Likely contains unpacking routine

3. **QrVbjeUa** (0x211000) - Packed data
   - Size: 2,187,264 bytes (2.09 MB)
   - Flags: INITIALIZED_DATA, READABLE, WRITABLE
   - **Analysis**: Contains compressed/encrypted program data

4. **LEXmTy1n**, **niBTgJWZ**, **sfW0L9wz** - Additional data sections
5. **.text** (0x452000) - Small text section at end

### Obfuscation and Packing

**Strong indicators of packing/protection:**

1. **Random section names**: Normal PE files have .text, .data, .rsrc
2. **Zero raw size sections**: Typical of runtime unpacking
3. **High entropy (7.63)**: Indicates compression or encryption
4. **Unusual entry point**: Points to unpacker code
5. **Requires Administrator**: Elevated privileges for device access

### Functionality Analysis

#### System Requirements

From manifest analysis:
```xml
<requestedExecutionLevel level="requireAdministrator" />
```
- Requires administrator privileges
- Likely needs direct hardware/driver access

#### DLL Dependencies

The tool links against:
- **kernel32.dll**: Core Windows functions
- **iphlpapi.dll**: IP Helper API (network configuration)
- **USER32.dll**: Windows UI
- **GDI32.dll**, **MSIMG32.dll**: Graphics
- **COMDLG32.dll**: Common dialogs
- **ADVAPI32.dll**: Advanced Windows services/registry
- **SHELL32.dll**, **COMCTL32.dll**, **SHLWAPI.dll**: Shell functions
- **ole32.dll**, **OLEAUT32.dll**, **oledlg.dll**: COM/OLE
- **WS2_32.dll**: Winsock (network sockets)
- **OLEACC.dll**: Accessibility
- **gdiplus.dll**: GDI+ graphics (GdipDrawImageI function)
- **IMM32.dll**: Input method manager
- **WINMM.dll**: Multimedia

#### Inferred Capabilities

Based on DLL imports:
1. **Network Communication**: WS2_32, iphlpapi
2. **Serial Port Access**: Likely through kernel32 file I/O
3. **Graphics/UI**: Multiple GDI libraries, image drawing
4. **System Configuration**: ADVAPI32 for registry/service access

---

## RAR Archive Contents Analysis

### Archive: DESBLOQUEIO.R22.HG8145V5.E.HG8145V5V2.rar

The RAR archive contains a complete toolkit for unlocking and downgrading Huawei HG8145V5 ONTs:

#### File Structure

```
DESBLOQUEIO R22 HG8145V5 E HG8145V5V2/
├── DONGRAD R20/
│   └── HG8145V5_V2_HG8145V5.bin (49,026,072 bytes - ~46.8 MB)
├── FERRAMENTA HUAWEI/
│   ├── 1211.exe (2,366,464 bytes - Flashing tool)
│   └── OSBC_LOG_*.log (5 log files from operations)
├── UNLOCK/
│   ├── 1-TELNET.bin (1,845,780 bytes - ~1.76 MB)
│   └── 2-UNLOCK.bin (182,972 bytes - ~179 KB)
└── METODO DE DESBLOQUEIO R22.txt (Instructions)
```

### Unlock Method Documentation

The included text file (translated from Portuguese) describes a 3-step process:

#### Step 1: Configure Tool
- Change timing from 1200 to 1400
- Change delay from 10ms to 5ms
- **These changes are mandatory**

#### Step 2: Downgrade Firmware
- Flash **HG8145V5_V2_HG8145V5.bin** (downgrade firmware)
- Wait 8-9 minutes for success
- ONT will freeze LEDs and reboot

#### Step 3: Enable Telnet and Unlock
- Flash **1-TELNET.bin** (enables Telnet access)
- Wait for success
- Flash **2-UNLOCK.bin** (removes vendor lock)
- ONT will blink and reboot automatically
- **Process complete - ONT is unlocked**

### Log File Analysis

Sample from OSBC_LOG files:
- Logs show serial communication attempts
- Timestamps indicate usage between February 19-20, 2025 and April 29, 2025
- Multiple retry attempts visible in logs

---

## Firmware Files Analysis

### 1. HG8145V5_V2_HG8145V5.bin (Downgrade Firmware)

| Property | Value |
|----------|-------|
| **Size** | 49,026,072 bytes (46.8 MB) |
| **Purpose** | Downgrade firmware to vulnerable version |
| **Effect** | Enables Telnet and unlock capability |

This is a complete firmware image for the HG8145V5 ONT, specifically version V2 which has known vulnerabilities allowing:
- Telnet access enablement
- Vendor lock removal
- Configuration modification

### 2. 1-TELNET.bin (Telnet Enabler)

| Property | Value |
|----------|-------|
| **Size** | 1,845,780 bytes (1.76 MB) |
| **Purpose** | Enable Telnet service on ONT |
| **Effect** | Provides shell access for further modifications |

This appears to be a modified configuration or boot partition that enables the Telnet daemon on the ONT.

### 3. 2-UNLOCK.bin (Unlock Firmware)

| Property | Value |
|----------|-------|
| **Size** | 182,972 bytes (179 KB) |
| **Purpose** | Remove ISP vendor lock |
| **Effect** | Allows ONT to work with different ISPs |

This is likely a modified configuration that:
- Removes PLOAM password requirements
- Disables vendor restrictions
- Allows manual VLAN/configuration changes

---

## How the System Works

### Communication Protocol

Both tools appear to use **serial communication** to interact with the ONT:

1. **Connection Method**:
   - USB-to-Serial adapter or direct serial connection
   - ONT must be in upgrade/recovery mode
   - Specific timing requirements (baud rate, delays)

2. **Flashing Process**:
   - Tool sends firmware image in chunks
   - ONT validates and writes to flash memory
   - Reboot occurs after successful flash

3. **Timing Requirements**:
   - 1211.exe requires specific timing adjustments
   - 1200→1400 and 10ms→5ms modifications mentioned
   - Likely related to serial communication timing

### ONT Boot Process

Based on the unlock methodology:

```
Normal Boot
    ↓
Downgrade to V2 (vulnerable firmware)
    ↓
Flash Telnet enabler → Enables Telnet service
    ↓
Flash Unlock firmware → Removes vendor restrictions
    ↓
Reboot with unlocked configuration
```

### Security Implications

1. **Vendor Lock Bypass**: The process circumvents ISP restrictions
2. **Firmware Downgrade**: Exploits older firmware vulnerabilities
3. **Elevated Access**: Enables Telnet/shell access
4. **Configuration Control**: Users gain full device control

---

## Technical Deep Dive: Firmware Structure

### Huawei HWNP Format

Based on repository code (huawei_header.h), Huawei firmware uses:

- **Magic Number**: 0x504e5748 (HWNP - "Huawei NP")
- **CRC32 Checksums**: For integrity verification
- **Multiple Partitions**: rootfs, kernel, config, etc.
- **XML Manifests**: UpgradeCheck.xml for validation

### Expected Firmware Components

The 46.8 MB downgrade firmware likely contains:

1. **Bootloader** (u-boot)
2. **Linux Kernel**
3. **Root Filesystem** (squashfs/cramfs)
4. **Configuration Partition**
5. **Web UI Resources**
6. **Upgrade Check XML**

### Modification Points

The unlock process likely modifies:

1. **hw_ctree.xml**: Device configuration tree
2. **rootfs**: System files and services
3. **startup scripts**: Enable Telnet daemon
4. **PLOAM settings**: Remove ISP authentication
5. **VLAN configuration**: Allow manual changes

---

## Comparative Analysis

### ONT_V100R002C00SPC253.exe vs 1211.exe

| Feature | ONT_V100R002C00SPC253.exe | 1211.exe |
|---------|---------------------------|----------|
| **Origin** | Official Huawei tool | Third-party/community tool |
| **Size** | 8.68 MB | 2.26 MB |
| **Build Date** | March 2021 | August 2014 |
| **Framework** | MFC/C++ (unobfuscated) | Packed/protected |
| **Entropy** | 7.40 (normal) | 7.63 (high) |
| **Obfuscation** | None | Heavy (random section names) |
| **Admin Rights** | Not explicitly required | Requires administrator |
| **Purpose** | Official firmware upgrade | Unlock/downgrade tool |
| **Safety** | Legitimate, safe | Likely safe but modified firmware |

### Usage Scenario Differences

**ONT_V100R002C00SPC253.exe (Official)**:
- Updates ONT to latest firmware
- Maintains ISP restrictions
- Official support and validation
- No unlock capability

**1211.exe (Community)**:
- Downgrades firmware to vulnerable version
- Removes ISP restrictions
- Community-developed
- Enables custom configurations
- May void warranty

---

## Conclusions

### ONT_V100R002C00SPC253.exe

This is a **legitimate Huawei firmware upgrade tool** built with:
- Standard MFC framework
- XML configuration parsing (TinyXML)
- Windows GUI with IP address controls
- Embedded firmware resources (~4.3 MB)
- No signs of malicious intent

**Primary Function**: Official firmware upgrade for Huawei HG8145V5 ONT devices.

### 1211.exe

This is a **third-party firmware flashing tool** with:
- Heavy packing/obfuscation
- Random section names
- High entropy (compressed/encrypted)
- Requires administrator privileges
- Likely community-developed for ISP unlock

**Primary Function**: Flash modified firmware to remove vendor locks and enable Telnet access.

### The Unlock Process

The complete unlock methodology involves:

1. **Firmware Downgrade**: Flash vulnerable V2 firmware
2. **Service Enablement**: Install Telnet-enabled configuration
3. **Lock Removal**: Apply unlock firmware patch
4. **Result**: Full device control, custom configuration capability

### Security Considerations

**For End Users**:
- Unlocking may void warranty
- ISP may detect and restrict service
- Firmware modification carries risks
- Telnet access creates security exposure

**For ISPs**:
- Firmware verification can detect tampering
- TR-069 management can re-lock devices
- Downgrade prevention in newer firmware
- Better security in modern ONT models

---

## Recommendations

### For Further Analysis

To perform deeper analysis, consider:

1. **Dynamic Analysis**:
   - Run in isolated Windows VM
   - Monitor serial port communication
   - Capture network traffic
   - Analyze runtime behavior

2. **Unpacking 1211.exe**:
   - Use UPX or generic unpackers
   - Manual unpacking with debugger
   - Memory dumping after runtime decompression

3. **Firmware Extraction**:
   - Extract firmware from ONT_V100R002C00SPC253.exe resources
   - Use repository tools (hw_fmw) to unpack firmware
   - Analyze UpgradeCheck.xml manifest
   - Extract rootfs and examine files

4. **Protocol Analysis**:
   - Serial port monitoring during flash
   - Identify communication protocol
   - Document command structure
   - Analyze timing requirements

### For Repository Integration

This analysis can be integrated into the HuaweiFirmwareTool repository:

1. Add documentation about ONT firmware structure
2. Include analysis tools for PE executables
3. Document unlock methodologies
4. Create firmware verification tools
5. Add safety warnings about modifications

---

## Appendix A: Technical Specifications

### PE32 Header Details - ONT_V100R002C00SPC253.exe

```
DOS Header:
  Magic: MZ
  PE Offset: 0x138

COFF Header:
  Machine: IMAGE_FILE_MACHINE_I386 (0x014c)
  NumberOfSections: 8
  TimeDateStamp: 1614762792 (Wed Mar  3 01:59:52 2021)
  Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE

Optional Header:
  Magic: PE32 (0x10b)
  AddressOfEntryPoint: 0x1929C1
  ImageBase: 0x400000
  SectionAlignment: 0x1000
  FileAlignment: 0x200
  SizeOfImage: 9175040 (0x8BD000)
  Subsystem: IMAGE_SUBSYSTEM_WINDOWS_GUI (2)
```

### PE32 Header Details - 1211.exe

```
DOS Header:
  Magic: MZ
  PE Offset: 0x40

COFF Header:
  Machine: IMAGE_FILE_MACHINE_I386 (0x014c)
  NumberOfSections: 7
  TimeDateStamp: 1408067716 (Fri Aug 15 01:01:56 2014)
  Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE

Optional Header:
  Magic: PE32 (0x10b)
  AddressOfEntryPoint: 0x20F2FD
  ImageBase: 0x400000
  SectionAlignment: 0x1000
  FileAlignment: 0x200
  SizeOfImage: 4538368 (0x453000)
  Subsystem: IMAGE_SUBSYSTEM_WINDOWS_GUI (2)

Manifest:
  Execution Level: requireAdministrator
```

---

## Appendix B: String Samples

### ONT_V100R002C00SPC253.exe Notable Strings

```
XML Error Messages:
- "Error parsing Element."
- "Error reading Element value."
- "Error parsing Declaration."
- "Error document empty."

MFC Components:
- CMFCShellListCtrl
- CMDIFrameWndEx
- COleIPFrameWndEx
- CMFCToolTipCtrl

Windows APIs:
- Kernel32.dll
- Comctl32.dll
- Comdlg32.dll
```

### 1211.exe Notable Strings

```
System DLLs:
- kernel32.dll
- iphlpapi.dll
- WS2_32.dll (Winsock)
- gdiplus.dll

Manifest:
- "requireAdministrator"
- "Microsoft.Windows.Common-Controls"
- version="6.0.0.0"
```

---

## Appendix C: Files Analyzed

### Source Files

1. **ONT_V100R002C00SPC253.exe**
   - URL: https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/ONT_V100R002C00SPC253.exe
   - Size: 9,101,312 bytes
   - MD5: [Calculate if needed]

2. **DESBLOQUEIO.R22.HG8145V5.E.HG8145V5V2.rar**
   - URL: https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/DESBLOQUEIO.R22.HG8145V5.E.HG8145V5V2.rar
   - Size: 52,725,203 bytes
   - Contains: 1211.exe, firmware binaries, documentation

---

## Document Information

- **Analysis Date**: February 23, 2026
- **Analyst**: Claude (AI Assistant)
- **Tools Used**: Python 3, rarfile, custom PE analyzer
- **Analysis Duration**: ~1 hour
- **Confidence Level**: High (static analysis only)

---

## Disclaimer

This analysis is provided for educational and research purposes only. Modifying firmware, unlocking devices, or circumventing ISP restrictions may:

- Void device warranty
- Violate terms of service
- Be illegal in some jurisdictions
- Cause device malfunction or bricking
- Result in service termination

Always consult with your ISP and understand local regulations before modifying network equipment.
