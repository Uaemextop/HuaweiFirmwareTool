# HG8145V5 Telmex Configuration Files

## Source

- **Router model**: Huawei HG8145V5
- **ISP**: Telmex (Mexico)
- **Firmware version**: V500R019C10SPC310B002 (rootfs V800R019C10B036)
- **Original config source**: [Uaemextop/huawei-hg8145v5](https://github.com/Uaemextop/huawei-hg8145v5)
- **Firmware source**: [Uaemextop/realfirmware-net](https://github.com/Uaemextop/realfirmware-net)

## Files

| File | Description |
|------|-------------|
| `hw_ctree_original.xml` | Original plaintext config extracted from user's router |
| `hw_ctree_modified.xml` | Modified config with all optimizations applied |
| `hw_ctree_encrypted.xml` | Factory encrypted config from firmware rootfs (AES, kmc_store keys) |
| `hw_aes_tree.xml` | AES field encryption schema from firmware |
| `hw_flashcfg.xml` | Flash partition layout from firmware |
| `UpgradeCheck.xml` | Firmware upgrade validation config (board IDs, chip checks) |

## Modifications Applied (41 changes)

### 1. XML Error Fixes
- Removed duplicate `PrefixInformationInstance` element outside `PrefixInformation`

### 2. Version Information
- Set `currentVersion` to `V500R020`
- Set `customInfo` to `COMMON`

### 3. Logging Enabled (Debug + Highest Level)
- `X_HW_Syslog Enable="1" Level="7"` (DEBUG level)
- `X_HW_LogCfg DbgSwitch="1" RtoSwitch="1" LogTypeMask="255"` (all log types)
- `X_HW_SyslogConfig LogServerEnable="1" Severity="7"` (remote logging, all severities)
- `X_HW_Reportlog Enable="1" ReportLogType="5"` (all report types)

### 4. Services Enabled
- **Telnet**: `X_HW_CLITelnetAccess Access="1"` (port 23)
- **SSH**: `X_HW_CLISSHAccess Access="1"` (port 22) — *added*
- **FTP**: `FtpEnable="1"` (port 21)
- **SFTP**: `SftpEnable="1" SftpLANEnable="1" SftpWANEnable="1"` (port 8022)
- **TFTP**: `X_HW_TftpServerEnable="1"`

### 5. Firmware Downgrade Enabled
- `X_HW_PSIXmlReset ResetFlag="0"` (prevent config reset on version change)
- `X_HW_CheckSafety Enable="0"` (disable firmware safety check)
- `UpgradesManaged="0"` (disable ISP firmware control)

### 6. TR-069/CWMP Disabled
- `EnableCWMP="0"`, `PeriodicInformEnable="0"`, `STUNEnable="0"`
- All ManagementServer credentials cleared
- `X_HW_iaccess Enable="0"` (ISP remote access disabled)
- `X_HW_Audit Enable="0"` (audit logging disabled)
- `X_HW_AppRemoteManage` URL cleared

### 7. Flash Preparation
- `EnablePowerSavingMode="0"` (stable power during flash)
- `X_HW_AutoReboot Enable="0"` (prevent auto-reboot during flash)
- `ExtDeviceInfo X_HW_LedSwitch="1"` (LED feedback during flash)
- `DHCPServerEnable="1"` (network access for firmware transfer)

## Firmware Extraction Results

The firmware `Firmware TELMEX R020 NEW.bin` (38.6 MB) contains:

| Item | Section | Size | Description |
|------|---------|------|-------------|
| UpgradeCheck.xml | UPGRDCHECK | 2.1 KB | Hardware/chip validation |
| signinfo | SIGNINFO | 16 KB | V500R019C10 signature |
| uboot | UBOOT | 396 KB | U-Boot bootloader |
| kernel | KERNEL | 1.8 MB | Linux kernel (whwh-wrapped) |
| rootfs | ROOTFS | 32.9 MB | SquashFS rootfs (offset 0x94 in whwh wrapper) |
| Updateflag | UPDATEFLAG | 2 B | Update flag ("N") |
| setequiptestmodeoff | UNKNOWN | 629 B | Equipment test mode script |
| dealcplgin.sh | UNKNOWN | 76 B | Plugin preload script |
| plugin_preload.tar.gz | UNKNOWN | 1.7 MB | Plugin archive |
| efs | EFS | 68 B | Equipment info |

**Product list**: 159D, 15DD, 15ED, 18ED (COMMON)

## Encryption Note

The factory `hw_ctree.xml` in the firmware rootfs uses AES encryption with keys derived
from `kmc_store_A`/`kmc_store_B` files, which are ultimately seeded from the device's
hardware e-fuse. This makes the encryption **device-specific** — the config cannot be
decrypted without access to the actual device's key material.

The plaintext config (`hw_ctree_original.xml`) was extracted directly from the user's
router via the web management interface.

## Tool Used

Generated using `tools/ctree_modifier.py`:

```bash
python tools/ctree_modifier.py --input hw_ctree_original.xml --output hw_ctree_modified.xml
```
