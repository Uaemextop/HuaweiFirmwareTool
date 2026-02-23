# Firmware Update Checker and Extractor

Python script for checking firmware updates and extracting components from Huawei ONT firmware files.

## Features

- ✅ Check for firmware updates from GitHub releases
- ✅ Download firmware files automatically
- ✅ Parse Huawei HWNP firmware format
- ✅ Extract specific components (rootfs, kernel, uboot, etc.)
- ✅ List all components in firmware
- ✅ Calculate SHA256 checksums

## Installation

### Requirements

```bash
pip install requests
```

Or using the script directly (only uses standard library except for requests):
```bash
python3 -m pip install requests
```

## Usage

### Check for Available Firmware Updates

```bash
python3 firmware_update_checker.py --check --model HG8145V5
```

This will query known firmware repositories and list available firmware files:

```
[*] Checking for HG8145V5 firmware updates...

Found 3 firmware files:
1. HG8145V5_remover5.bin
   Repo: Uaemextop/HuaweiFirmwareTool
   Release: V2
   Published: 2026-02-23 14:30:57
   Size: 46.42 MB
   URL: https://github.com/...
```

### Download Latest Firmware

```bash
# Download latest firmware
python3 firmware_update_checker.py --download --model HG8145V5 --output ./firmwares

# Download all available firmwares
python3 firmware_update_checker.py --download --model HG8145V5 --all --output ./firmwares
```

### List Components in Firmware

```bash
python3 firmware_update_checker.py --list firmware.bin
```

Output example:
```
================================================================================
Firmware: HG8145V5_remover5.bin
Product List: 164C|15AD|;E8C|COMMON|CHINA|CMCC|
Items: 12
================================================================================

  [0] UPGRDCHECK   | file:/var/UpgradeCheck.xml               |    0.00 MB | N/A
  [1] SIGNINFO     | flash:signinfo                           |    0.02 MB | V500R020C00SPC270B520
  [2] UBOOT        | flash:uboot                              |    0.41 MB | N/A
  [3] KERNEL       | flash:kernel                             |    2.15 MB | V500R020C00SPC270B520
  [4] ROOTFS       | flash:rootfs                             |   37.56 MB | V500R020C00SPC270B520
  ...
```

### Extract Rootfs

```bash
python3 firmware_update_checker.py --extract firmware.bin --component rootfs --output rootfs.bin
```

Output:
```
[+] Extracted rootfs to rootfs.bin (39383040 bytes)
[+] SHA256: b1645f78079b054d4e3b1567c03c58d5aaf37cafe35a8b8f71b6d8d3bb669334
```

### Extract Other Components

```bash
# Extract kernel
python3 firmware_update_checker.py --extract firmware.bin --component kernel --output kernel.bin

# Extract uboot
python3 firmware_update_checker.py --extract firmware.bin --component uboot --output uboot.bin

# Extract signinfo
python3 firmware_update_checker.py --extract firmware.bin --component signinfo --output signinfo.bin
```

## Extracted Rootfs Information

The script has successfully extracted rootfs from three HG8145V5 firmware variants:

### 1. HG8145V5-V500R021C00SPC210

- **Firmware Version**: V500R021C00SPC210B055
- **Rootfs Size**: 44,883,808 bytes (42.8 MB)
- **SHA256**: `f29aa37ca7356cf03d9597daf5d0271442be0bae3006f63ea6dca0e8490f7c8b`
- **Location**: `extracted_rootfs/HG8145V5-V500R021C00SPC210_rootfs.bin`

### 2. HG8145V5_remover5

- **Firmware Version**: V500R020C00SPC270B520
- **Rootfs Size**: 39,383,040 bytes (37.6 MB)
- **SHA256**: `b1645f78079b054d4e3b1567c03c58d5aaf37cafe35a8b8f71b6d8d3bb669334`
- **Location**: `extracted_rootfs/HG8145V5_remover5_rootfs.bin`

### 3. HG8145V5_V2

- **Firmware Version**: V500R020C00SPC458B001
- **Rootfs Size**: 49,024,992 bytes (46.8 MB)
- **SHA256**: `81e69e6108583bafb1262f43f02abfceeaad6b695012e46902a6a9a4142aa53f`
- **Location**: `extracted_rootfs/HG8145V5_V2_rootfs.bin`

## Firmware Update Mechanism

Huawei ONT devices check for firmware updates using the following mechanism:

### 1. Hardware and Compatibility Checks

The firmware includes an `UpgradeCheck.xml` file that defines:

- **Hardware Version Check**: Validates BoardId against allowed list
- **LSW Chip Check**: Validates switch chip compatibility
- **WiFi Chip Check**: Validates WiFi chip compatibility
- **Voice Chip Check**: Validates voice chip compatibility
- **USB Chip Check**: Validates USB chip compatibility
- **Optical Module Check**: Validates optical transceiver compatibility
- **Flash Memory Check**: Validates flash memory type
- **Product Check**: Validates product ID (e.g., 151D, 15AD, 163D, etc.)
- **Program Check**: Validates firmware program type (E8C, COMMON, CHINA, CMCC, etc.)

### 2. Update Sources

The device typically checks for updates from:

1. **OLT/ISP Server**: The primary source, controlled by the ISP via OMCI
2. **TR-069/CWMP**: Remote management protocol for firmware updates
3. **Web Interface**: Manual upload by administrator
4. **USB**: Manual update from USB storage

### 3. Update Process

1. Device connects to update server (usually via ISP)
2. Sends current version information and hardware details
3. Server responds with available update if compatible
4. Device downloads firmware package
5. Validates firmware signature and CRC32 checksums
6. Verifies hardware compatibility using UpgradeCheck.xml
7. Flashes new firmware to alternate partition
8. Reboots to new firmware
9. If successful, marks as active; if failed, rolls back

## Known Firmware Repositories

The script automatically checks these GitHub repositories:

1. **Uaemextop/HuaweiFirmwareTool**: Contains modified/custom firmwares
2. **Eduardob3677/mtkclient**: Contains stock and modified firmwares

## Firmware Format (HWNP)

The Huawei firmware uses the HWNP format:

- **Magic**: 0x504E5748 ('HWNP' in little endian)
- **Header**: 36 bytes with CRC32, size, item count
- **Product List**: Optional device compatibility list
- **Items**: Array of components (rootfs, kernel, uboot, etc.)
- **Data**: Actual component data

Each item contains:
- CRC32 checksum
- Offset and size
- Path (flash:rootfs, file:/var/efs, etc.)
- Section name (ROOTFS, KERNEL, UBOOT, etc.)
- Version string
- Policy flags

## Security Considerations

- Always verify SHA256 checksums after extraction
- Firmware files may be signed with RSA keys
- Only flash firmware from trusted sources
- Keep backups of original firmware
- Test in safe environment before production use

## Advanced Usage

### Batch Extract All Components

```bash
#!/bin/bash
FIRMWARE="firmware.bin"
OUTPUT_DIR="./extracted"

mkdir -p "$OUTPUT_DIR"

for component in rootfs kernel uboot signinfo; do
    python3 firmware_update_checker.py \
        --extract "$FIRMWARE" \
        --component "$component" \
        --output "$OUTPUT_DIR/${component}.bin"
done
```

### Monitor for New Firmware

```bash
#!/bin/bash
# Check for updates every 24 hours
while true; do
    python3 firmware_update_checker.py --check --model HG8145V5 > updates.txt
    # Parse updates.txt and notify if new firmware found
    sleep 86400
done
```

## Troubleshooting

### Invalid Magic Error

If you see "Invalid magic" error, the file may not be a Huawei HWNP firmware:
- Verify the file is a valid firmware file
- Check if the file is corrupted
- Some firmware files may use different formats

### Component Not Found

If extraction fails with "Component not found":
- Use `--list` to see available components
- Component names are case-insensitive
- Try common names: rootfs, kernel, uboot, signinfo

### Download Fails

If firmware download fails:
- Check internet connection
- Verify the release still exists
- GitHub may rate-limit API requests
- Try again after a few minutes

## Contributing

To add more firmware repositories:

1. Edit the `REPOS` list in `FirmwareUpdateChecker` class
2. Add GitHub API URL and repository info
3. The script will automatically check the new source

## Related Tools

- `hw_fmw`: C++ tool for packing/unpacking firmware (requires build)
- `analyze_firmware.sh`: Shell script for comprehensive firmware analysis
- `quick_repack.sh`: Quick firmware repacking tool

## License

This script is part of the HuaweiFirmwareTool project. See LICENSE for details.
