# Firmware Packages — ONT_V100R002C00SPC253

The Huawei OBSCTool (`ONT_V100R002C00SPC253.exe`) embeds 6 HWNP firmware packages as PE BIN resources (IDs 130–135). These are used in pairs by the three **Enable Package** menu options to configure HG8145V5 ONT devices.

## Package Overview

| Menu Option | BIN IDs | Target | Strategy |
|------------|---------|--------|----------|
| **Enable Pkg 1** | 130 + 131 | V3 firmware devices | Version-detect upgrade with 9 equipment variants |
| **Enable Pkg 2** | 132 + 133 | V5 firmware devices | Factory reset then re-enable Telnet/SSH |
| **Enable Pkg 3** | 134 + 135 | New devices | Full upgrade with Telnet + duit9rr.sh |

## Detailed Package Analysis

### Enable Pkg 1 — V3 Version Devices (BIN130 + BIN131)

**BIN130** (274 KB, 15 items, 30 equipment IDs):
- `UpgradeCheck.xml` — Hardware validation (disables all checks: HardVer, LswChip, BoardId, Product, SoftVer)
- `signature` — RSA signature (13 SHA-256 hashes + 256-byte signature block)
- `Updateflag` — Update marker ("N\n")
- 9× `equipment_*.tar.gz` — Configuration packages for different firmware versions:
  - R13C10, R15C00, R15C10, R15C10cut, R15C80, R15C80_cut, R16C00, R16C10, R17C00
- **`duit9rr.sh`** (15,613 B, policy=2 AUTO-EXEC) — Main upgrade script:
  - Detects current firmware version (V/R/C/S parsing)
  - Selects appropriate equipment.tar.gz based on version
  - Enables Telnet via `cfgtool set` on `hw_ctree.xml` (AES-decrypted)
  - Creates `ProductLineMode` and `TelnetEnable` flags
  - Handles `ramcheck` binary for memory validation
- **`ramcheck`** (14,686 B, policy=2 AUTO-EXEC) — ARM ELF binary for memory validation
- `efs` — 68-byte equipment footer signature

**BIN131** (2,028 KB, 6 items, no equipment filter):
- `UpgradeCheck.xml` — Same validation XML
- `signature` — V5-format signature (16 KB `signinfo`)
- `Updateflag` — Update marker
- `equipment.tar.gz` (2,050,401 B) — Large equipment configuration archive
- **`run.sh`** (6,838 B, policy=2 AUTO-EXEC) — Telnet + SSH enabler:
  - Enables both `TELNETLanEnable` and `SSHLanEnable` via `cfgtool`
  - Configures CLI access (`X_HW_CLITelnetAccess`, `X_HW_CLISSHControl`)
  - Installs equipment.tar.gz to `/mnt/jffs2/equipment/`
  - Handles config encryption/decryption via `aescrypt2`
- `efs` — Equipment footer

**How Pkg1 works:** The tool first sends BIN130 via OBSC UDP broadcast. `duit9rr.sh` auto-executes on the ONT, detects the firmware version, selects the correct equipment archive, and enables Telnet. Then BIN131 is sent, and `run.sh` enables both Telnet and SSH access with the full equipment module.

---

### Enable Pkg 2 — V5 Version Devices (BIN132 + BIN133)

**BIN132** (140 KB, 5 items, 30 equipment IDs):
- `UpgradeCheck.xml` — Hardware validation
- `signature` — RSA signature (3 SHA-256 hashes)
- `junk_file` (131,072 B) — 128 KB of zero padding (dummy payload to meet minimum size)
- **`restorefactory_DeleteComponent.sh`** (9,199 B, policy=2 AUTO-EXEC) — Factory reset script:
  - Records board info (MachineItem, CfgFeatureWord) before reset
  - Performs factory reset via `restorefactory` command
  - Restores boardinfo after reset to preserve device identity
  - Handles both SD5113 and SD5115/5116 chipsets
  - Re-enables Telnet after factory reset
- `efs` — Equipment footer

**BIN133** (26 KB, 5 items, no equipment filter):
- `UpgradeCheck.xml` — Hardware validation
- `signature` — V5-format signature (16 KB `signinfo`)
- `Updateflag` — Update marker
- **`run.sh`** (7,150 B, policy=2 AUTO-EXEC) — Telnet + SSH enabler:
  - Same as BIN131's run.sh but slightly different version
  - Enables Telnet and SSH via `cfgtool` config manipulation
- `efs` — Equipment footer

**How Pkg2 works:** BIN132 is sent first — `restorefactory_DeleteComponent.sh` performs a factory reset to remove ISP customizations while preserving device identity, then re-enables Telnet. After the device reboots, BIN133 is sent and `run.sh` enables both Telnet and SSH access.

---

### Enable Pkg 3 — New Devices (BIN134 + BIN135)

**BIN134** (1,766 KB, 7 items, 30 equipment IDs):
- `UpgradeCheck.xml` — Hardware validation
- `signinfo_v5` (13,868 B) — V5-format signature with device-specific signing
- `ProductLineMode` (1 B) — Production line mode flag ("\n")
- `equipment.tar.gz` (1,784,882 B) — Equipment configuration archive
- `TelnetEnable` (1 B) — Telnet enable flag ("\n")
- **`duit9rr.sh`** (5,811 B, policy=2 AUTO-EXEC) — Simplified Telnet enabler:
  - Enables only Telnet (not SSH) via `cfgtool`
  - Creates `ProductLineMode` and `TelnetEnable` flags
  - Installs equipment.tar.gz
  - Shorter than BIN130's version (no version detection, no ramcheck)
- `efs` — Equipment footer

**BIN135** (26 KB, 5 items, no equipment filter):
- Identical to BIN133 (same CRC, same raw_sz)
- `run.sh` enables Telnet + SSH after reboot

**How Pkg3 works:** BIN134 is sent first — it directly creates `TelnetEnable` and `ProductLineMode` flags, installs equipment, and enables Telnet via `duit9rr.sh`. After reboot, BIN135's `run.sh` adds SSH access. This is the simplest approach, suitable for devices that haven't been previously configured.

---

## Key Differences Between Packages

| Feature | Pkg 1 (V3) | Pkg 2 (V5) | Pkg 3 (New) |
|---------|-----------|-----------|------------|
| Target firmware | V3 (R13–R17) | V5 (R20+) | Any new device |
| Version detection | ✅ Yes (9 variants) | ❌ No | ❌ No |
| Factory reset | ❌ No | ✅ Yes | ❌ No |
| Equipment archive | 9 small + 1 large | None (junk only) | 1 large |
| Telnet | ✅ Enabled | ✅ Re-enabled after reset | ✅ Enabled |
| SSH | ✅ Enabled (run.sh) | ✅ Enabled (run.sh) | ✅ Enabled (run.sh) |
| ProductLineMode | ✅ Created | ❌ No | ✅ Created |
| TelnetEnable flag | ✅ Created | ❌ No | ✅ Created |
| ramcheck binary | ✅ Yes (ARM ELF) | ❌ No | ❌ No |

## HWNP Package Format

Each package uses the Huawei HWNP format:

```
Header (36 bytes):
  +00: magic       "HWNP" (0x504E5748)
  +04: raw_sz      Total data size (big-endian u32)
  +08: raw_crc32   CRC32 of all item data (big-endian u32)
  +12: hdr_sz      Header+items+prodlist size (little-endian u32)
  +16: hdr_crc32   CRC32 of header region (little-endian u32)
  +20: item_counts Number of items (little-endian u32)
  +24: flags       (2 bytes)
  +26: prod_list_sz Product list size (little-endian u16)
  +28: item_sz     Size of each item struct (little-endian u32, always 360)
  +32: reserved    (little-endian u32)

Product List (prod_list_sz bytes):
  Pipe-separated equipment version IDs, e.g. "120|130|140|..."

Items (item_counts × 360 bytes each):
  +000: iter        Item index (little-endian u32)
  +004: item_crc32  CRC32 of this item's data (little-endian u32)
  +008: data_off    Offset to data from start of package (little-endian u32)
  +012: data_sz     Size of item data (little-endian u32)
  +016: item[256]   Target path on device (e.g. "file:/var/run.sh")
  +272: section[16] Section name (e.g. "UPGRDCHECK", "MODULE", "EFS")
  +288: version[64] Version string (usually empty)
  +352: policy      Execution policy (little-endian u32):
                      0 = file only (copied to target path)
                      2 = auto-execute (script runs after copy)
  +356: reserved    (little-endian u32)
```

## Creating a Custom HWNP Package

Use the C++ tools in this repository to create custom packages:

```bash
# Build the tools
mkdir build && cd build && cmake .. && make && cd ..

# 1. Create a directory with your firmware items
mkdir my_package
echo '<upgradecheck>...</upgradecheck>' > my_package/UpgradeCheck.xml

# 2. Create item_list.txt describing each item
cat > my_package/item_list.txt << 'EOF'
file:/var/UpgradeCheck.xml|UPGRDCHECK||0|UpgradeCheck.xml
file:/var/my_script.sh|UNKNOWN||2|my_script.sh
file:/var/efs|EFS||0|efs
EOF

# 3. Create signature (sig_item_list.txt)
# Use hw_sign to generate: ./build/hw_sign -k private.pem -d my_package

# 4. Pack into HWNP
./build/hw_fmw -p my_firmware.bin -d my_package

# 5. Verify
./build/hw_fmw -u my_firmware.bin -d unpacked/
```

### Item List Format

Each line in `item_list.txt`:
```
<target_path>|<section>|<version>|<policy>|<local_filename>
```

- **target_path**: Where the file is placed on the ONT (e.g., `file:/var/run.sh`)
- **section**: Category tag (`UPGRDCHECK`, `SIGNATURE`, `SIGNINFO`, `MODULE`, `UPDATEFLAG`, `EFS`, `UNKNOWN`)
- **version**: Version string (usually empty)
- **policy**: `0` = copy only, `2` = auto-execute after copy
- **local_filename**: Name of the file in your package directory

### Equipment IDs

The product list filters which devices accept the firmware. Common IDs for HG8145V5:
```
120|130|140|141|150|160|170|171|180|190|1B1|1A1|1A0|1B0|1D0|1F1|201|211|221|230|240|260|261|270|271|280|281|291|2A1|431|
```

Leave empty (no product list) to allow any device.

### Signing

The ONT device verifies firmware signatures during the update process. The tool's CRC32 check has been bypassed (see `unlock_ont_tool.py`), but the device-side RSA verification is separate and cannot be bypassed from this tool.

For testing purposes, you can use unsigned packages with devices that have had their signature verification disabled.

## Extraction

To extract packages from the EXE:

```bash
pip install pefile
python3 extract_firmware_packages.py ONT_V100R002C00SPC253_EN.exe firmware_packages/
```

This creates:
```
firmware_packages/
├── BIN130_pkg1_equipment.bin    (274 KB)
├── BIN131_pkg1_module.bin       (2,028 KB)
├── BIN132_pkg2_factory_reset.bin (140 KB)
├── BIN133_pkg2_telnet.bin       (26 KB)
├── BIN134_pkg3_full.bin         (1,766 KB)
├── BIN135_pkg3_telnet.bin       (26 KB)
└── scripts/
    ├── BIN130_duit9rr.sh
    ├── BIN131_run.sh
    ├── BIN132_restorefactory_DeleteComponent.sh
    ├── BIN133_run.sh
    ├── BIN134_duit9rr.sh
    └── BIN135_run.sh
```
