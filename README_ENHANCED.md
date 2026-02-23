# HuaweiFirmwareTool

Advanced tools for analyzing, modifying, unpacking and repacking Huawei firmware images with cryptographic signature support.

## Features

- ✅ Unpack and repack Huawei firmware images (.bin files)
- ✅ Verify and calculate CRC32 checksums
- ✅ Generate and verify RSA signatures for firmware components
- ✅ Support for multiple firmware variants (HG8245, HG8145V5, etc.)
- ✅ Automated firmware analysis script
- ✅ Compatible with OpenSSL 3.0+

## Requirements

### Debian/Ubuntu
```bash
apt install cmake make g++ openssl zlib1g zlib1g-dev libssl-dev
```

### Optional Analysis Tools
```bash
apt install radare2 file xxd bsdextrautils
pip3 install binwalk
```

## Build

```bash
git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
cd HuaweiFirmwareTool
mkdir build && cd build
cmake ..
make
```

This will create three executables:
- `hw_fmw` - Main firmware pack/unpack tool
- `hw_sign` - Signature generation tool
- `hw_verify` - Signature verification tool

## Quick Start

### Using the Analysis Script

The easiest way to analyze firmware is using the included script:

```bash
# Basic analysis and unpacking
./analyze_firmware.sh firmware.bin

# Deep analysis with custom output directory
./analyze_firmware.sh -d -o /tmp/analysis firmware.bin

# Generate signature with private key
./analyze_firmware.sh -s private.pem firmware.bin

# Verify signature with public key
./analyze_firmware.sh -v public.pem firmware.bin
```

### Manual Usage

#### Unpack Firmware

```bash
./build/hw_fmw -d unpacked -u -f firmware.bin -v
```

This will:
1. Create `unpacked/` directory
2. Extract all firmware components
3. Generate `item_list.txt` with component metadata
4. Generate `sig_item_list.txt` for signature management
5. Verify CRC32 checksums

#### Modify Firmware Components

1. Edit extracted files in the `unpacked/` directory
2. Update `unpacked/item_list.txt`:
   - Mark items with `+` to include in repacked firmware
   - Mark items with `-` to exclude

Example `item_list.txt`:
```
0x504e5748
256 164C|15AD|;E8C|COMMON|CHINA|CMCC|
+ 0 file:/var/UpgradeCheck.xml UPGRDCHECK NULL 0
+ 1 flash:signinfo SIGNINFO V500R020C00SPC270B520 0
+ 2 flash:uboot UBOOT NULL 0
+ 3 flash:kernel KERNEL V500R020C00SPC270B520 0
+ 4 flash:rootfs ROOTFS V500R020C00SPC270B520 0
- 5 file:/mnt/jffs2/Updateflag UPDATEFLAG NULL 0
```

#### Repack Firmware

```bash
./build/hw_fmw -d unpacked -p -o new_firmware.bin -v
```

This will:
1. Read items marked with `+` from `item_list.txt`
2. Calculate new CRC32 checksums
3. Create `new_firmware.bin` with valid structure

## Cryptographic Signatures

### Generate RSA Keys

```bash
# Generate 2048-bit private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

### Sign Firmware Components

1. Edit `unpacked/sig_item_list.txt` to mark items for signing:
```
+ file:/var/UpgradeCheck.xml
- flash:signinfo
+ flash:uboot
+ flash:kernel
+ flash:rootfs
```

2. Generate signature:
```bash
./build/hw_sign -d unpacked -k private.pem -o unpacked/signature
```

### Verify Signatures

```bash
./build/hw_verify -d unpacked -k public.pem -i unpacked/signature
```

## Understanding item_list.txt Format

```
HWNP(0x504e5748) - Magic header
256 494|4B4|534|... - Product list size and identifiers
+ 0 file:/var/UpgradeCheck.xml UPGRDCHECK NULL 0
  │ │ │                         │          │    │
  │ │ │                         │          │    └─ Policy
  │ │ │                         │          └────── Version
  │ │ │                         └───────────────── Section name
  │ │ └─────────────────────────────────────────── Item path
  │ └───────────────────────────────────────────── Item index
  └─────────────────────────────────────────────── Include marker (+/-)
```

## Tested Firmware Variants

The tool has been tested and verified with:

- ✅ **HG8245H** (V300R015C10SPC130) - 2 components
- ✅ **HG8145V5** (V500R020C00SPC458B001) - 2 components
- ✅ **HG8145V5** (V500R020C00SPC270B520) - 12 components
- ✅ Various other Huawei ONT/ONU devices

### Example: HG8145V5 Firmware Structure

**HG8145V5_V2_HG8145V5.bin**:
- 2 items: `flash:rootfs`, `file:/var/efs`
- Empty product list
- Size: 47MB

**HG8145V5_remover5.bin**:
- 12 items including: UpgradeCheck.xml, signinfo, uboot, kernel, rootfs, plugins
- Product list: `164C|15AD|;E8C|COMMON|CHINA|CMCC|`
- Size: 47MB

## Command Line Options

### hw_fmw
```
Usage: ./hw_fmw -d /path/items [-u -f firmware.bin] [-p -o firmware.bin] [-v]
 -d Path (from|to) unpacked files
 -u Unpack (With -f)
 -p Pack (With -o)
 -f Path from firmware.bin
 -o Path to save firmware.bin
 -v Verbose
```

### hw_sign
```
Usage: ./hw_sign -d /path/to/items -k private_key.pem -o items/var/signature
 -d Path to unpacked files
 -k Path from private_key.pem (Without password)
 -o Path to save signature file
```

### hw_verify
```
Usage: ./hw_verify -d /path/to/items -k public_key.pem -i items/var/signature
 -d Path to unpacked files
 -k Path from pubsigkey.pem
 -i Path from signature file
```

## Advanced Analysis

### Using Binwalk

```bash
# Scan for embedded filesystems and files
binwalk firmware.bin

# Extract all found components
binwalk -e firmware.bin
```

### Using Radare2

```bash
# Open firmware in radare2
r2 firmware.bin

# Analyze the file
> aa

# Show entropy analysis
> p=e 100

# Search for strings
> iz
```

### Examining Components

```bash
# Check file type
file unpacked/rootfs

# If it's a filesystem (squashfs, jffs2, etc.)
# Mount or extract with appropriate tools

# For squashfs
unsquashfs unpacked/rootfs

# For jffs2
jefferson unpacked/rootfs -d extracted/
```

## Troubleshooting

### CRC32 Mismatch
If you see CRC32 verification failures:
- The tool automatically recalculates CRC32 on repack
- Old format firmware (offset -36) is auto-detected and handled

### Empty Items Error
```
Error: Empty items on header
```
Solution: Ensure items in `item_list.txt` are marked with `+`

### OpenSSL 3.0 Warnings
The deprecation warnings are cosmetic and don't affect functionality. The code works correctly with OpenSSL 3.0+.

## Project Structure

```
HuaweiFirmwareTool/
├── CMakeLists.txt          # Build configuration
├── huawei_header.h         # Firmware header structures
├── hw_fmw.cpp              # Main pack/unpack tool
├── hw_sign.cpp             # Signature generation
├── hw_verify.cpp           # Signature verification
├── util.cpp/hpp            # General utilities
├── util_hw.cpp/hpp         # Huawei-specific utilities
├── util_rsa.cpp/hpp        # RSA crypto utilities
├── analyze_firmware.sh     # Automated analysis script
└── README.md               # This file
```

## Security Considerations

- **Private Keys**: Never commit private keys to version control
- **Signature Verification**: Always verify signatures before flashing
- **Firmware Modifications**: Improper modifications can brick devices
- **Backup**: Always keep original firmware backup
- **Testing**: Test modified firmware in safe environment first

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with various firmware files
5. Submit a pull request

## License

This project is licensed under the terms specified in the LICENSE file.

## Acknowledgments

- Original tool by 0xuserpag3
- Enhanced firmware support and analysis tools
- Community testing and feedback

## Disclaimer

This tool is for educational and research purposes. Users are responsible for compliance with local laws and manufacturer warranties. Always maintain backups of original firmware.
