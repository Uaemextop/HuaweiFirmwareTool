# Huawei Firmware Tool - Examples

This directory contains example scripts and workflows for common firmware modification tasks.

## Examples

### 1. Basic Firmware Unpacking and Repacking

```bash
# Unpack firmware
../build/hw_fmw -d unpacked -u -f firmware.bin -v

# Modify files (example: edit a config file)
vim unpacked/var/UpgradeCheck.xml

# Mark all items for inclusion
sed -i 's/^- /+ /' unpacked/item_list.txt

# Repack firmware
../build/hw_fmw -d unpacked -p -o modified_firmware.bin -v
```

### 2. Creating and Verifying Signatures

```bash
# Generate RSA key pair (if you don't have one)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Unpack firmware
../build/hw_fmw -d unpacked -u -f firmware.bin -v

# Mark items to sign (example: sign critical components)
cat > unpacked/sig_item_list.txt << EOF
+ flash:uboot
+ flash:kernel
+ flash:rootfs
EOF

# Generate signature
../build/hw_sign -d unpacked -k private.pem -o unpacked/signature

# Verify signature
../build/hw_verify -d unpacked -k public.pem -i unpacked/signature
```

### 3. Automated Analysis Workflow

```bash
# Use the analysis script for comprehensive firmware examination
../analyze_firmware.sh -d -o analysis_output firmware.bin

# This will:
# - Unpack the firmware
# - Show file structure
# - Run binwalk analysis (if available)
# - Display component information
```

### 4. Selective Component Repacking

```bash
# Unpack firmware
../build/hw_fmw -d unpacked -u -f firmware.bin -v

# Edit item_list.txt to include only specific components
# For example, to create a minimal firmware with only kernel and rootfs:
cat > unpacked/item_list.txt << EOF
0x504e5748
256 COMMON|
+ 0 flash:kernel KERNEL V500R020C00SPC270B520 0
+ 1 flash:rootfs ROOTFS V500R020C00SPC270B520 0
EOF

# Repack with selected components
../build/hw_fmw -d unpacked -p -o minimal_firmware.bin -v
```

### 5. Extracting and Analyzing Rootfs

```bash
# Unpack firmware
../build/hw_fmw -d unpacked -u -f firmware.bin -v

# Check rootfs type
file unpacked/rootfs

# If it's squashfs
unsquashfs unpacked/rootfs

# If it's a different format, use binwalk
binwalk -e unpacked/rootfs

# Examine extracted filesystem
ls -la squashfs-root/
```

### 6. Batch Processing Multiple Firmwares

Create a script `batch_process.sh`:

```bash
#!/bin/bash
for fw in *.bin; do
    echo "Processing: $fw"
    DIR="unpacked_${fw%.bin}"
    ../build/hw_fmw -d "$DIR" -u -f "$fw" -v

    # Your modifications here
    # ...

    ../quick_repack.sh "$DIR" "modified_${fw}"
done
```

### 7. Comparing Two Firmware Versions

```bash
# Unpack both versions
../build/hw_fmw -d unpacked_v1 -u -f firmware_v1.bin -v
../build/hw_fmw -d unpacked_v2 -u -f firmware_v2.bin -v

# Compare item lists
diff -u unpacked_v1/item_list.txt unpacked_v2/item_list.txt

# Compare specific components
diff <(hexdump -C unpacked_v1/kernel) <(hexdump -C unpacked_v2/kernel) | head -50
```

## Common Modifications

### Modify Product List

Edit the second line of `item_list.txt`:
```
0x504e5748
256 NEW_PRODUCT_ID|CUSTOM|REGION|
```

### Add Custom Files

1. Add your file to the unpacked directory
2. Add an entry in `item_list.txt`:
```
+ 99 file:/var/custom_script.sh CUSTOM NULL 0
```

### Remove Unnecessary Components

Simply mark components with `-` in `item_list.txt`:
```
- 5 file:/mnt/jffs2/Updateflag UPDATEFLAG NULL 0
```

## Testing

Always test modified firmware in a safe environment:
1. Verify CRC32 checksums after repacking
2. Check file sizes are reasonable
3. Test signature verification if applicable
4. Use a test device or VM when possible

## Troubleshooting

### Issue: "Empty items on header"
**Solution**: Ensure at least one item is marked with `+` in item_list.txt

### Issue: CRC32 mismatch
**Solution**: The tool automatically recalculates CRC32. This is normal for modified firmware.

### Issue: Device won't accept modified firmware
**Solution**:
- Check signature requirements
- Verify product list matches your device
- Ensure all required components are included
- Check that firmware size hasn't exceeded device limits

## Advanced Topics

### Custom Signature Format

If your device uses a different signature format, modify `util_rsa.cpp` accordingly.

### Supporting New Device Models

1. Analyze the firmware structure with hexdump and binwalk
2. Check if it matches the HWNP format
3. If magic header differs, update `huawei_header.h`
4. Test unpacking and repacking

## Resources

- [Huawei ONT/ONU Documentation](https://github.com/Uaemextop/HuaweiFirmwareTool)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Binwalk Project](https://github.com/ReFirmLabs/binwalk)
