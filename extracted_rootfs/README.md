# Extracted Rootfs Manifest

This directory contains extracted rootfs filesystems from Huawei HG8145V5 firmware files.

**Note**: The actual .bin files are excluded from git due to their large size. Use the `firmware_update_checker.py` script to extract them from the original firmware files.

## Extracted Files

### 1. HG8145V5-V500R021C00SPC210_rootfs.bin
- **Source Firmware**: HG8145V5-V500R021C00SPC210.bin
- **Firmware Version**: V500R021C00SPC210B055
- **Size**: 44,883,808 bytes (42.8 MB)
- **SHA256**: `f29aa37ca7356cf03d9597daf5d0271442be0bae3006f63ea6dca0e8490f7c8b`
- **Source URL**: https://github.com/Eduardob3677/mtkclient/releases/download/v3/HG8145V5-V500R021C00SPC210.bin

### 2. HG8145V5_remover5_rootfs.bin
- **Source Firmware**: HG8145V5_remover5.bin
- **Firmware Version**: V500R020C00SPC270B520
- **Size**: 39,383,040 bytes (37.6 MB)
- **SHA256**: `b1645f78079b054d4e3b1567c03c58d5aaf37cafe35a8b8f71b6d8d3bb669334`
- **Source URL**: https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/HG8145V5_remover5.bin

### 3. HG8145V5_V2_rootfs.bin
- **Source Firmware**: HG8145V5_V2_HG8145V5.bin
- **Firmware Version**: V500R020C00SPC458B001
- **Size**: 49,024,992 bytes (46.8 MB)
- **SHA256**: `81e69e6108583bafb1262f43f02abfceeaad6b695012e46902a6a9a4142aa53f`
- **Source URL**: https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/HG8145V5_V2_HG8145V5.bin

## How to Extract

To extract these files yourself:

```bash
# Extract from remover5 firmware
python3 ../firmware_update_checker.py \
    --extract HG8145V5_remover5.bin \
    --component rootfs \
    --output HG8145V5_remover5_rootfs.bin

# Extract from V500R021C00SPC210 firmware
python3 ../firmware_update_checker.py \
    --extract HG8145V5-V500R021C00SPC210.bin \
    --component rootfs \
    --output HG8145V5-V500R021C00SPC210_rootfs.bin

# Extract from V2 firmware
python3 ../firmware_update_checker.py \
    --extract HG8145V5_V2_HG8145V5.bin \
    --component rootfs \
    --output HG8145V5_V2_rootfs.bin
```

## Verify Integrity

After extraction, verify the SHA256 checksum:

```bash
sha256sum HG8145V5_remover5_rootfs.bin
# Should output: b1645f78079b054d4e3b1567c03c58d5aaf37cafe35a8b8f71b6d8d3bb669334

sha256sum HG8145V5-V500R021C00SPC210_rootfs.bin
# Should output: f29aa37ca7356cf03d9597daf5d0271442be0bae3006f63ea6dca0e8490f7c8b

sha256sum HG8145V5_V2_rootfs.bin
# Should output: 81e69e6108583bafb1262f43f02abfceeaad6b695012e46902a6a9a4142aa53f
```

## Rootfs Format

These rootfs filesystems appear to be encrypted or compressed. The first bytes show:
- Possible signature/header
- Version information embedded
- May require specialized tools to fully unpack

Common formats for Huawei ONT rootfs:
- SquashFS (compressed)
- JFFS2 (Flash filesystem)
- UBI/UBIFS (raw flash format)
- Custom encrypted format

## Further Analysis

To analyze the rootfs:

```bash
# Check file type
file rootfs.bin

# Look for magic bytes
hexdump -C rootfs.bin | head

# Try binwalk
binwalk rootfs.bin

# Try to identify compression
binwalk -e rootfs.bin
```

## Security Note

These rootfs filesystems may contain:
- Configuration files
- Credentials (encrypted)
- Proprietary software
- Network configurations

Handle with care and respect intellectual property rights.
