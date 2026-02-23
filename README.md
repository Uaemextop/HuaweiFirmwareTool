# HuaweiFirmwareTool
Tools for modify firmware huawei

## Supported Models
- HG8245 (original)
- HG8145V5 (V500R020C00SPC270, V500R020C00SPC458, V500R021C00SPC210)

## Requires on Debian 11+ / Ubuntu 22.04+
```
apt install cmake make g++ openssl zlib1g zlib1g-dev libssl-dev
```

### Optional tools for firmware analysis
```
apt install binwalk squashfs-tools radare2 xxd
```

### Build
```
$ git clone https://github.com/Uaemextop/HuaweiFirmwareTool.git
$ cd HuaweiFirmwareTool
$ mkdir build && cd build
$ cmake ..
$ make
```

## Example modify firmware on HG8245 / HG8145V5
### Usage:

```
 $ ./hw_fmw 
Usage: ./hw_fmw -d /path/items [-u -f firmware.bin] [-p -o firmware.bin] [-v]
 -d Path (from|to) unpacked files
 -u Unpack (With -f)
 -p Pack (With -o)
 -f Path from firmware.bin
 -o Path to save firmware.bin
 -v Verbose
 ```
### Unpack:

```
$ ./hw_fmw -d unpack -u -f /home/user/HG8145V5_remover5.bin -v
```
Files that will be added to the firmware should be marked with a **'+'** sign in file **unpacked/item_list.txt**
```
$ head -n 5 unpack/item_list.txt
0x504e5748 0 0 0
256 164C|15AD|;E8C|COMMON|CHINA|CMCC|
+ 0 file:/var/UpgradeCheck.xml UPGRDCHECK NULL 0
- 1 flash:signinfo SIGNINFO V500R020C00SPC270B520 0
+ 2 flash:uboot UBOOT NULL 0
```
### More information about the file "item_list.txt"
```
First line: 
  (0) 0x504e5748 - Magic (HWNP little endian)
  (1) 0 - unknow_data_1
  (2) 0 - unknow_data_2
  (3) 0 - reserved field (1 for encrypted firmware)
Second line: 
  (0) 256 - size "Product list"
  (1) 164C|... - "Product" list (may be empty for some firmware)
After second line: 
  (0) minus(-) or plus(+) it's "checkbox" for append item to firmware
  (1) 0 - item index
  (2) file:/var/UpgradeCheck.xml - item:path
  (3) UPGRDCHECK - section
  (4) NULL - version
  (5) 0 - policy 
```
### Pack:
```
$ ./hw_fmw -d unpack -p -o /home/user/new_firmware.bin -v
```
## Example modify/verify firmware on HG8245 / HG8145V5 (need support check signature)
### Mark the file to sign
```
$ head -n 5 unpack/sig_item_list.txt 
+ file:/var/UpgradeCheck.xml
- flash:signinfo
+ flash:uboot
- flash:kernel
- flash:rootfs
```
### Generate keys:
```
$ openssl genrsa -out private.pem 2048
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```
### Make signature:
```
$ ./hw_sign -d unpack -k private.pem -o new_signature
```
### Verify signature:
```
$ ./hw_verify -d unpack -k public.pem -i new_signature
```

## Firmware Flash Tool (hw_flash)

Open-source TFTP-based firmware flash tool. Works on Windows and Linux.

### Usage:
```
$ ./hw_flash -i firmware.bin                    # Show firmware info
$ ./hw_flash -s -f firmware.bin                 # Start TFTP server (default: 192.168.1.10:69)
$ ./hw_flash -s -b 192.168.1.10 -p 69 -f firmware.bin  # Custom bind address
```

### Flash procedure:
1. Connect your PC to the ONT via Ethernet
2. Set your PC IP to `192.168.1.10`
3. Start the TFTP server: `./hw_flash -s -f firmware.bin`
4. Power on the ONT while holding the reset button
5. The ONT will request the firmware via TFTP automatically
6. Wait for the transfer to complete, then release the reset button

### Building on Windows:
```
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022"
cmake --build . --config Release
```

## Firmware Analysis Notes

### HG8145V5 Firmware Format
The HG8145V5 firmware uses the standard HWNP header format with `item_sz=360`.

**HG8145V5_remover5.bin** (V500R020C00SPC270B520):
- Contains: UpgradeCheck, signinfo, uboot, kernel, rootfs, plugins
- Rootfs: SquashFS with LZMA compression (extractable with `binwalk -e`)
- Product list: `164C|15AD|;E8C|COMMON|CHINA|CMCC|`

**HG8145V5_V2_HG8145V5.bin** (V500R020C00SPC458B001):
- Contains: rootfs, efs
- Rootfs: Encrypted with custom Huawei header (0x16041920)
- Product list: empty (256 null bytes)
- Reserved field: 1 (indicates encrypted firmware)

**HG8145V5-V500R021C00SPC210.bin** (V500R021C00SPC210B055):
- Contains: rootfs, efs
- Rootfs: Encrypted with custom Huawei header (0x16041920)
- Product list: empty (256 null bytes)
- Reserved field: 1 (indicates encrypted firmware)
- Same format as V2, compatible with all tool operations
