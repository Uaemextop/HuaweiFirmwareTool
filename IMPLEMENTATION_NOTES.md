# Implementation Notes

## Changes Made

### 1. Compilation Fix
- **File**: `util.hpp`
- **Issue**: Missing `<cstdint>` include caused compilation errors with `uint16_t` and `uint32_t` types
- **Fix**: Added `#include <cstdint>` at line 4
- **Impact**: Code now compiles successfully with modern C++ compilers and OpenSSL 3.0+

### 2. Analysis Tools Installation
Successfully installed and tested:
- `radare2` - Binary analysis framework
- `binwalk` - Firmware analysis tool (Python)
- `hexdump` - Hex viewer (via bsdextrautils)
- Standard analysis tools: `file`, `xxd`

### 3. Firmware Analysis Scripts

#### analyze_firmware.sh
- **Purpose**: Automated firmware unpacking and analysis
- **Features**:
  - Basic file information and hex header display
  - Firmware unpacking with verbose output
  - Optional deep analysis with binwalk
  - Signature generation/verification support
- **Usage**: `./analyze_firmware.sh [-d] [-o output_dir] [-s private.pem] [-v public.pem] firmware.bin`

#### quick_repack.sh
- **Purpose**: Simplified firmware repacking
- **Features**:
  - Automatically marks all items for inclusion
  - Single command repacking
  - Success verification
- **Usage**: `./quick_repack.sh <unpacked_dir> <output_firmware.bin>`

#### examples/complete_workflow.sh
- **Purpose**: End-to-end workflow demonstration
- **Features**:
  - Unpack firmware
  - Generate test RSA keys
  - Sign critical components
  - Verify signatures
  - Repack firmware
  - Compare checksums
- **Usage**: `./examples/complete_workflow.sh <firmware.bin>`

### 4. Documentation

#### README_ENHANCED.md
Comprehensive documentation including:
- Feature overview and requirements
- Detailed build instructions
- Quick start guide with analysis script
- Manual usage for all three tools (hw_fmw, hw_sign, hw_verify)
- Cryptographic signature workflow
- Format specification for item_list.txt
- Tested firmware variants
- Advanced analysis techniques
- Troubleshooting guide
- Security considerations

#### examples/README.md
Practical examples covering:
- Basic unpacking and repacking
- Signature creation and verification
- Automated analysis workflows
- Selective component repacking
- Extracting and analyzing rootfs
- Batch processing multiple firmwares
- Comparing firmware versions
- Common modifications
- Advanced topics

### 5. Project Infrastructure

#### .gitignore
Added exclusions for:
- Build artifacts (build/, *.o, *.a, binaries)
- Firmware files (*.bin, *.img)
- Unpacked directories
- Private keys and signatures (security)
- Editor and OS files

## Testing Results

### HG8145V5_V2_HG8145V5.bin
- **Size**: 47MB
- **Items**: 2 (flash:rootfs, file:/var/efs)
- **Product List**: Empty (256 bytes reserved)
- **Unpack**: ✅ Success
- **Repack**: ⚠️ Edge case with empty product list parsing (pre-existing issue)
- **CRC32**: All checksums verify correctly

### HG8145V5_remover5.bin
- **Size**: 47MB
- **Items**: 12 (UpgradeCheck.xml, signinfo, uboot, kernel, rootfs, plugins, etc.)
- **Product List**: "164C|15AD|;E8C|COMMON|CHINA|CMCC|"
- **Unpack**: ✅ Success
- **Repack**: ✅ Perfect - MD5 checksums match exactly (84dcff3b19f4c8dbebb60a26cde7c5f0)
- **CRC32**: All checksums verify correctly
- **Signature**: ✅ Generation and verification work correctly

## Known Issues

### Empty Product List Parsing
**Firmware**: HG8145V5_V2_HG8145V5.bin
**Issue**: When product list size is 256 but content is empty/whitespace, ReadHeaderFromFS reads beyond the product list into item lines
**Location**: `util_hw.cpp:403` - `fd >> std::setw(this->hdr.prod_list_sz) >> this->prod_list;`
**Impact**: Repacking doesn't work correctly for this specific firmware variant
**Status**: Pre-existing issue, not introduced by our changes
**Workaround**: Manually ensure product list has content or pad with spaces

## Firmware Format Details

### Header Structure
```c
struct huawei_header {
    uint32_t magic_huawei;     // 0x504e5748 (HWNP)
    uint32_t raw_sz;           // Total size (byte-swapped)
    uint32_t raw_crc32;        // Full firmware CRC32
    uint32_t hdr_sz;           // Header size
    uint32_t hdr_crc32;        // Header CRC32
    uint32_t item_counts;      // Number of items
    uint8_t _unknow_data_1;    // Usually 0x00
    uint8_t _unknow_data_2;    // Usually 0x00
    uint16_t prod_list_sz;     // Product list size
    uint32_t item_sz;          // Size of each item (360 bytes)
    uint32_t reserved;         // Reserved field
};
```

### Item Structure
```c
struct huawei_item {
    uint32_t iter;             // Item index
    uint32_t item_crc32;       // Item CRC32
    uint32_t data_off;         // Data offset in firmware
    uint32_t data_sz;          // Data size
    char item[256];            // Path (e.g., "flash:rootfs")
    char section[16];          // Section name (e.g., "ROOTFS")
    char version[64];          // Version string
    uint32_t policy;           // Policy value
    uint32_t reserved;         // Reserved field
};
```

### CRC32 Calculation
- **Header CRC32**: Calculated from offset 0x14 to end of header + product list + all item headers
- **Full CRC32**: Calculated from offset 0x0C to end of entire firmware
- **Item CRC32**: Individual CRC32 for each item's data
- Uses zlib's crc32() and crc32_combine() functions

### Signature Format
- **Algorithm**: RSA-2048 with SHA256
- **Structure**: Text file with SHA256 hashes followed by RSA signature
- **Format**:
  ```
  <item_count>\n
  <sha256_hash> <item_path>\n
  ...
  <256_byte_rsa_signature>
  ```

## Development Tips

### Adding Support for New Devices
1. Analyze firmware with hexdump and binwalk
2. Check if HWNP magic header matches (0x504e5748)
3. Verify header structure alignment
4. Test unpack/repack cycle
5. Verify CRC32 calculations
6. Test signature generation if device requires it

### Debugging Firmware Issues
1. Use `hexdump -C firmware.bin | head -40` to examine header
2. Check magic number: should be "HWNP" (0x48 0x57 0x4e 0x50)
3. Verify item count matches actual items
4. Check CRC32 values with verbose mode (-v flag)
5. For parsing issues, examine item_list.txt format carefully

### Testing Modifications
Always follow this sequence:
1. Unpack original firmware
2. Make modifications to unpacked files
3. Repack firmware
4. Compare file sizes (should be similar)
5. Verify CRC32 checksums
6. Test in safe environment before deploying

## Future Improvements

### Potential Enhancements
1. Fix empty product list parsing issue
2. Add GUI interface for easier use
3. Support for additional firmware formats
4. Automated firmware diffing tool
5. Database of known firmware signatures
6. Integration with online firmware repositories

### Code Quality
1. Update RSA code to use OpenSSL 3.0+ EVP API (remove deprecation warnings)
2. Add unit tests for CRC32 calculation
3. Add integration tests for common firmware types
4. Improve error messages and user feedback
5. Add logging levels (debug, info, warning, error)

## References

- [Original Repository](https://github.com/0xuserpag3/HuaweiFirmwareTool)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Binwalk Project](https://github.com/ReFirmLabs/binwalk)
- [Radare2 Book](https://book.rada.re/)
