# HuaweiFirmwareTool
Tools for modify firmware huawei

### Requires on Debian 11
```
apt install cmake make g++ openssl zlib1g zlib1g-dev libssl1.1 libssl-dev
```

### Build
```
$ git clone https://github.com/0xuserpag3/HuaweiFirmwareTool.git
$ cd HuaweiFirmwareTool
$ mkdir build && cd build
$ cmake ..
$ make
```

## Example modify firmware on HG8245
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
$ ./hw_fmw -d unpack -u -f /home/user/hg8245hv300r015c10spc130_common_all.bin -v
```
Files that will be added to the firmware should be marked with a **'+'** sign in file **upacked/item_list.txt**
```
$ head -n 5 unpack/item_list.txt
HWNP(0x504e5748)
256 494|4B4|534|5D4|614|;COMMON|CMCC|
+ 0 file:/var/UpgradeCheck.xml UPGRDCHECK NULL 0
- 1 flash:flash_config FLASH_CONFIG NULL 0
+ 2 file:/var/hw_flashcfg_256.xml FLASH_CONFIG1 NULL 0
```
### More information about the file "item_list.txt"
```
First line: 
  (0) HWNP(0x504e5748 - little endian) - "Magic"
Second line: 
  (0) 256 - size "Product list"
  (1) 494|... - "Product" list
After second line: 
  (0) minus(-) or plus(+) it's "checkbox" for append item to firmware
  (1) 0 - item index
  (2) file:/var/UpgradeCheck.xml - item:path
  (3) UPGRDCHECK - section
  (4) NULL - version
  (5) 0 - plocicy 
```
### Pack:
```
$ ./hw_fmw -d unpack -p -o /home/user/new_hg8245hv300r015c10spc130_common_all.bin -v
```
## ONT Maintenance Tool (English Translation + Unlocked)

The file `ONT_V100R002C00SPC253_EN.exe` is an English-translated and unlocked version of
the Huawei ONT maintenance and enable tool (originally in Chinese). The translation was
performed using `translate_ont_tool.py` and the unlock using `unlock_ont_tool.py`.

### Recreate the translated and unlocked EXE
```
pip install pefile
python3 translate_ont_tool.py ONT_V100R002C00SPC253.exe ONT_V100R002C00SPC253_EN.exe
python3 unlock_ont_tool.py ONT_V100R002C00SPC253_EN.exe ONT_V100R002C00SPC253_EN.exe
```

### Translated UI elements
- Main window: buttons, labels, group boxes, status fields
- License dialog: registration, expiry, copyright info
- License input dialog: invitation code, OK/Cancel
- Warning dialog
- Menu items and enable package descriptions
- Table column headers (No., Board, MAC, Start/End Time, etc.)
- Notice text (tool usage warnings)
- License error messages (UTF-16LE)
- Bug tracking fields: Issue ID, Baseline, Severity, etc. (GBK)
- 124 internal error/log messages (GBK): license, registry, trial, XML, etc.

### Unlocked features
- **License corruption bypass**: The license validation functions (VA 0x437240 and 0x434b50)
  that return "corrupted" status have been patched to always return "valid". This prevents
  the "Lic.corrupted Force init Lic.?" dialog from appearing.
- **License validation bypass**: All 5 code paths that check the license init result and
  display "Init Lic.fail" are patched to always take the success path. The app no longer
  shows license errors at startup.
- **License timer bypass**: The 5-second countdown that closes the app when the license
  is invalid has been disabled.
- **Menu items enabled**: All 9 greyed-out menu commands (0x420E-0x4216) are now always
  enabled. These include firmware management operations that were previously gated behind
  license validation and connection state checks.

## Example modify/verify firmware on HG8245 (need support check signature)
### Mark the file to sign
```
$ head -n 5 unpack/sig_item_list.txt 
+ file:/var/UpgradeCheck.xml
- flash:flash_config
+ file:/var/hw_flashcfg_256.xml
- flash:uboot
- flash:kernel
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
