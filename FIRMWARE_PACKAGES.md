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

### Enable Pkg 3 — Factory Reset + Telnet (BIN134 + BIN135) [MODIFIED]

**BIN134** (1,769 KB, 7 items, 30 equipment IDs):
- `UpgradeCheck.xml` — Hardware validation
- `signinfo_v5` (13,868 B) — V5-format signature with device-specific signing
- `ProductLineMode` (1 B) — Production line mode flag ("\n")
- `equipment.tar.gz` (1,784,882 B) — Equipment configuration archive
- `TelnetEnable` (1 B) — Telnet enable flag ("\n")
- **`restorefactory_DeleteComponent.sh`** (9,199 B, policy=2 AUTO-EXEC) — Factory reset script (replaced from BIN132):
  - Records board info (MachineItem, CfgFeatureWord) before reset
  - Performs factory reset via `restorefactory` command
  - Restores boardinfo after reset to preserve device identity
  - Handles both SD5113 and SD5115/5116 chipsets
  - Re-enables Telnet after factory reset
  - Installs equipment.tar.gz
  - Shorter than BIN130's version (no version detection, no ramcheck)
- `efs` — Equipment footer

**BIN135** (26 KB, 5 items, no equipment filter):
- Identical to BIN133 (same CRC, same raw_sz)
- `run.sh` enables Telnet + SSH after reboot

**How Pkg3 works (MODIFIED):** BIN134 is sent first — it creates `TelnetEnable` and `ProductLineMode` flags, installs equipment, and runs `restorefactory_DeleteComponent.sh` which performs a factory reset while preserving device identity, then re-enables Telnet. After reboot, BIN135's `run.sh` adds SSH access. This combines the factory reset capability of Pkg2 with the equipment installation of the original Pkg3.

---

## Key Differences Between Packages

| Feature | Pkg 1 (V3) | Pkg 2 (V5) | Pkg 3 (Modified) |
|---------|-----------|-----------|------------|
| Target firmware | V3 (R13–R17) | V5 (R20+) | Any new device |
| Version detection | ✅ Yes (9 variants) | ❌ No | ❌ No |
| Factory reset | ❌ No | ✅ Yes | ✅ Yes (from Pkg2) |
| Equipment archive | 9 small + 1 large | None (junk only) | 1 large |
| Telnet | ✅ Enabled | ✅ Re-enabled after reset | ✅ Re-enabled after reset |
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

The ONT device verifies firmware signatures using a certificate chain. The tool's CRC32 check has been bypassed (see `unlock_ont_tool.py`), but the device-side RSA verification is separate.

#### Certificate Chain (from firmware analysis)

```
Huawei Root CA (4096-bit RSA, self-signed)
  └── Huawei Code Signing Certificate Authority 2 (2048-bit RSA)
       └── Transmission & Access Product Line Code Signing Certificate 3 (2048-bit RSA)
            └── Signs firmware packages
  └── Huawei Timestamp Certificate Authority 2 (2048-bit RSA)
       └── Huawei Time Stamping Signer (2048-bit RSA)
            └── Countersigns packages
```

#### Signature Format

**V3 format** (BIN130 `file:/var/signature`, section=SIGNATURE):
```
<item_count>\n
<sha256_hex> <item_path>\n
<sha256_hex> <item_path>\n
...
<256-byte RSA-2048 signature>
```
The signature covers the text portion (SHA-256 of all text before the signature).

**V5 format** (BIN131-135 `file:/var/signature` or `signinfo_v5`, section=SIGNINFO):
```
+0x00: magic "whwh" (4 bytes)
+0x04: version_string (e.g. "V500R020C00SPC060B031 | SIGNINFO") (60 bytes)
+0x40: signing metadata (timestamps, counters)
+0x68: SHA-256 hash list with item paths (text format)
+0xNN: X.509 certificate chain (DER-encoded)
       - Code Signing Certificate
       - Code Signing CA 2
       - Timestamp Signer
       - Timestamp CA 2
       (multiple cert groups for different signing epochs)
-256:  RSA-2048 signature (last 256 bytes)
```

#### Key Files Found in Firmware (EG8145V5 rootfs)

| File | Type | Purpose |
|------|------|---------|
| `/etc/app_cert.crt` | X.509 (4096-bit RSA) | Huawei Root CA — root of trust for firmware signing |
| `/etc/wap/root.crt` | X.509 (2048-bit RSA) | Huawei Fixed Network Product CA — device TLS |
| `/etc/wap/pub.crt` | X.509 (2048-bit RSA) | ont.huawei.com device certificate |
| `/etc/wap/prvt.key` | RSA-2048 (AES-256-CBC encrypted) | Device TLS private key |
| `/etc/wap/plugroot.crt` | X.509 (2048-bit RSA) | HuaWei ONT CA (self-signed) — plugin signing |
| `/etc/wap/plugpub.crt` | X.509 | Plugin public certificate |
| `/etc/wap/plugprvt.key` | RSA (AES-256-CBC encrypted) | Plugin signing private key |
| `/etc/wap/su_pub_key` | RSA-256 public key | Superuser verification (trivially breakable) |

**No private signing key for firmware was found.** The firmware signing private key is held exclusively by Huawei's build infrastructure and is not present in any device, EXE, or firmware image.

#### How to Sign Custom Packages

Since the actual Huawei private key is unavailable, there are two approaches:

1. **Use the existing bypassed tool**: The `unlock_ont_tool.py` bypasses the CRC32 check in the EXE, allowing it to send packages with modified content. The device-side verification must be separately handled.

2. **Generate your own key pair** (for devices with disabled signature check):
```bash
# Generate a 2048-bit RSA key pair
openssl genrsa -out my_private.pem 2048
openssl rsa -in my_private.pem -pubout -out my_public.pem

# Sign using the C++ tools from this repo
./build/hw_sign -d my_package/ -k my_private.pem -o my_package/var/signature

# Verify
./build/hw_verify -d my_package/ -k my_public.pem -i my_package/var/signature
```

---

## AES Encryption Analysis (hw_ctree.xml)

The device encrypts its configuration file (`hw_ctree.xml`) using AES. The `aescrypt2` utility handles this:

```
Usage: aescrypt2 <mode> <input> <output>
  mode: 0 = encrypt, 1 = decrypt
```

**Key findings:**
- `aescrypt2` is a 5.4 KB ARM binary wrapper that calls `OS_AescryptEncrypt`/`OS_AescryptDecrypt` from `libhw_ssp_basic.so`
- The AES implementation uses mbedTLS (`mbedtls_aes_crypt_cbc`, `mbedtls_aescrypt2`)
- The key is NOT passed as a command-line argument — it is **hardcoded internally** in `libhw_ssp_basic.so`
- The function `HW_XML_GetEncryptedKey` retrieves the internal key at runtime
- The key derivation uses MD5-based PBKDF from mbedTLS aescrypt format: `key = MD5(password + IV)` repeated to fill 256 bits
- Encrypted files use the mbedTLS aescrypt2 format: `AESCRYPT(1) + IV(16) + encrypted_data + HMAC(32)`

**Related crypto libraries on device:**
| Library | Purpose |
|---------|---------|
| `libhw_ssp_basic.so` (961 KB) | Main crypto: AES, SHA256, MD5, base64, XML encryption |
| `librsa_crypt.so` (9 KB) | RSA encrypt/decrypt/keygen wrapper around mbedTLS |
| `libhw_smp_sign.so` (87 KB) | CMS/PKCS#7 signature verification (firmware, vouchers) |
| `libpolarssl.so` (476 KB) | mbedTLS cryptographic primitives |
| `libcrypto.so.1.1` | OpenSSL (for TLS) |
| `libwlan_aes_crypto.so` (5 KB) | WLAN-specific AES |

For testing purposes, you can use unsigned packages with devices that have had their signature verification disabled.

---

## Firmware Analysis (EG8145V5-V500R022C00SPC340B019)

Full analysis of the production firmware downloaded from the releases.

### Firmware Structure

The `.bin` file is a single HWNP package containing 13 items:

| # | Path | Size | Section | Notes |
|---|------|------|---------|-------|
| 0 | `file:/var/UpgradeCheck.xml` | 2,633 B | UPGRDCHECK | Hardware/software compatibility checks |
| 1 | `flash:signinfo` | 16,384 B | SIGNINFO | `whwh` signed block with X.509 cert chain |
| 2 | `flash:uboot` | 503,808 B | UBOOT | `whwh` wrapped U-Boot bootloader |
| 3 | `flash:kernel` | 2,138,112 B | KERNEL | `whwh` wrapped Linux kernel (ARM uImage) |
| 4 | `flash:rootfs` | 38,137,856 B | ROOTFS | `whwh` wrapped SquashFS filesystem |
| 5 | `file:/mnt/jffs2/Updateflag` | 2 B | UPDATEFLAG | "N\n" marker |
| 6 | `file:/mnt/jffs2/ttree_spec_smooth.tar.gz` | 8,712 B | UNKNOWN | Encrypted spec tree |
| 7 | `file:/var/setequiptestmodeoff` | 791 B | UNKNOWN | Script (AUTO-EXEC) — exits equip test mode |
| 8 | `file:/var/dealcplgin.sh` | 244 B | UNKNOWN | Script (AUTO-EXEC) — cplugin cleanup |
| 9 | `file:/mnt/jffs2/app/preload_cplugin.tar.gz` | 2,047,991 B | UNKNOWN | Gzip — kernelapp C-plugin (net mgmt agent) |
| 10 | `file:/mnt/jffs2/sdkfs` | 98,388 B | sdk | `whwh` wrapped SquashFS — VoIP codec SDK |
| 11 | `file:/mnt/jffs2/plugin_timestamp` | 28 B | UNKNOWN | "V500R022C00SPC340A2402080348" |
| 12 | `file:/var/efs` | 68 B | EFS | Equipment footer ("HW\x00\x02" + MA5600 + CHS) |

### U-Boot Analysis

- **U-Boot 2020.01** (V500R022C00 V5 - V001)
- Architecture: ARM Cortex-A9 (HiSilicon SoC)
- Wrapped in `whwh` header with version string
- **Boot encryption support**: has `export work key`, `get work key`, `save work key` — manages AES work keys for encrypted flash partitions
- **Secure boot**: validates `Cert/Uboot Head magic`, checks e-fuse data, CRC validation of boot chain
- **Dual boot**: supports A/B partition switching ("Boot Area Change, Start from slave system")
- **Flash types**: SPI NOR, SPI NAND, parallel NAND, eMMC
- **E-fuse security**: reads hardware fuses for key derivation (`efuse read type`, `secram efuse crc check`)

Key strings found:
```
encrypt head decrypt fial, e_part_index:%d
<fatal error> encrypt version[%u] nor support!
export work key err
save work key err, ret=%d, part_index=%d
get work key err
Cert/Uboot Head magic 0x%08x is not right, %s area is not OK!
```

### Kernel Analysis

- **Linux 5.10.0** (SMP, ARM)
- Compiler: `arm-euler-linux-musleabi-gcc 7.3.0`
- Built: Wed Sep 27 00:43:40 CST 2023
- uImage format: Load address `0x80E08000`, entry `0x80E08000`
- Inner kernel is LZMA-compressed (decompresses to 4.2 MB)
- Crypto subsystem: `aes-generic`, `sha256_generic`, `cryptd`, `crc32c_generic`, `ctr`, `jitterentropy_rng`
- HiSilicon platform: `hisi_clk_*` drivers, ARM Cortex-A9 GIC/SCU/TWD

### Rootfs Analysis (SquashFS)

- 5,075 files, 703 directories, 266 symlinks
- musl libc (not glibc) — lightweight embedded C library
- **87 shell scripts** in `/bin/` covering: WiFi management, DSP control, customization, factory reset, diagnostics
- **180+ shared libraries** (`libhw_*.so`) forming the HuaWei Application Platform (WAP)

#### Key Crypto Components

| Binary/Library | Size | Purpose |
|---------------|------|---------|
| `/bin/aescrypt2` | 5.4 KB | AES encrypt/decrypt wrapper — calls `OS_AescryptEncrypt/Decrypt` |
| `/bin/decrypt_boardinfo` | — | Board info decryptor (`DM_DecryptBoardInfo`) |
| `/bin/keyfilemng` | 30 KB | Flash key file manager (save/restore/check) |
| `/bin/backupKey` | 9.5 KB | Key backup utility (`SwmReleaseKeyData`) |
| `/bin/cfgtool` | — | Configuration XML tool (reads/writes encrypted ctree) |
| `/lib/libhw_ssp_basic.so` | 961 KB | Core crypto: AES-CBC, SHA256, MD5, base64, XML encryption, CRC32 |
| `/lib/librsa_crypt.so` | 9 KB | RSA encrypt/decrypt/keygen via mbedTLS |
| `/lib/libhw_smp_sign.so` | 87 KB | CMS/PKCS#7 signature verification (uses CmscbbVerify* API) |
| `/lib/libpolarssl.so` | 476 KB | mbedTLS cryptographic primitives |
| `/lib/libcrypto.so.1.1` | 1.8 MB | OpenSSL 1.1 (for TLS) |
| `/lib/libhw_swm.so` | 170 KB | Software Manager — upgrade orchestration, CRC, cert loading |
| `/lib/libhw_swm_dll.so` | 412 KB | SWM detail — signature verification, hash checking, upgrade logic |
| `/lib/libhw_swm_product.so` | 189 KB | SWM product — e-fuse checks, root key, product-specific upgrade |

#### Firmware Signing Verification Chain (on-device)

```
1. SWM_CheckSignInfo()
2.   → SWM_SigCms_MainProcPf()         // Main CMS/PKCS#7 verification
3.     → SWM_Sig_CheckAllItemHash()     // Verify SHA-256 of each item
4.     → SWM_Sig_CheckHashByType()      // Check hash list integrity
5.     → SWM_CheckSignInfoPdtCert()     // Validate product certificate
6.       → SWM_CheckSocRootCa()         // Check against SoC root CA
7.       → HW_DM_GetRootPubKeyInfo()    // Get root public key from e-fuse/flash
8.       → CmscbbVerifyDetachSignature* // CMS detached signature verification
9.     → HW_SWM_CheckBufRsaValid()      // RSA signature validation
10.    → DM_EfuseGetVersionFromSignInfo // Anti-rollback via e-fuse version
```

The root of trust is **hardware-bound** (e-fuse in HiSilicon SoC). The `/etc/app_cert.crt` (Huawei Root CA 4096-bit RSA) is verified against the SoC's burned-in root public key hash.

#### Certificate/Key Inventory

| File | Type | Details |
|------|------|---------|
| `/etc/app_cert.crt` | X.509 | Huawei Root CA (4096-bit RSA, self-signed) — root of trust |
| `/etc/debug_check_cert.crt` | DER | Debug upgrade permission certificate |
| `/etc/wap/root.crt` | X.509 | Huawei Fixed Network Product CA → Huawei Equipment CA |
| `/etc/wap/pub.crt` | X.509 | ont.huawei.com (2048-bit RSA) — device TLS cert |
| `/etc/wap/prvt.key` | PEM | RSA-2048 (AES-256-CBC encrypted) — device TLS key |
| `/etc/wap/plugroot.crt` | X.509 | HuaWei ONT CA (2048-bit, self-signed) — plugin signing |
| `/etc/wap/plugpub.crt` | X.509 | Plugin public certificate |
| `/etc/wap/plugprvt.key` | PEM | RSA (AES-256-CBC encrypted) — plugin signing key |
| `/etc/wap/su_pub_key` | PEM | RSA-256 public key — superuser verification (trivially breakable) |
| `/etc/wap/hilinkcert/root.pem` | PEM | HiLink root CA |
| `/etc/wap/hilinkcert/servercert.pem` | X.509 | HiLink server cert |
| `/etc/wap/hilinkcert/serverkey.pem` | DER | HiLink server key (encrypted) |
| `/etc/dropbear/dropbear_rsa_host_key` | Dropbear | SSH host key |
| cplugin `server_key_ssl.pem` | PEM | RSA (AES-256-CBC encrypted) — kernelapp TLS key |
| cplugin `trust_ssl.pem` | X.509 | HuaWei ONT CA — plugin TLS trust |

#### SDKfs (VoIP Codec SDK)

Small SquashFS containing:
- `codec_sdk_le964x.ko` — ARM kernel module (Lantiq LE964x VoIP codec)
- `pef31001_*.bin` / `pef31002_*.bin` — PEF31002 SLIC firmware (Lantiq telephone line interface)
- `duslicxs2_130_1_0_1.bin` — DuSLIC-xS2 firmware
- `dxt_fw_pef3201.bin` — PEF3201 firmware

#### C-Plugin (kernelapp)

The `preload_cplugin.tar.gz` contains a management agent plugin:
- **59 files** including ARM shared libraries and shell scripts
- `kernelapp.config` — network management config (MQTT, REST, HTTPS)
- Embedded REST/HTTPS server using `libcivetweb.so`
- mbedTLS for crypto (`libmbedall.so` 722 KB)
- `libcurl.so` for HTTP client
- `libdriver_c.so` (428 KB) — device driver interface
- Runs in LXC container with CPU/memory limits

### AES Encryption Key Architecture

The AES key used by `aescrypt2` to encrypt/decrypt `hw_ctree.xml` is managed by a multi-layer key hierarchy:

```
E-fuse (HiSilicon SoC hardware)
  └── Root Key (burned into chip, irreversible)
       └── Work Key (derived, stored in flash keyfile partition)
            └── AES-256-CBC session key (for hw_ctree.xml encryption)
                 └── Key derivation: MD5(password + IV) via mbedTLS aescrypt2 format
```

- `HW_SWM_GetWorkSecretKey()` — retrieves the work key from flash
- `DM_ReadKeyFromFlashHead()` — reads key from flash partition header
- `HW_DM_GetEncryptedKey()` — gets the AES key for ctree encryption
- `FT_SSMP_CTREE_ENCRYPT_KEY` — feature flag enabling ctree encryption
- The key is **NOT** a simple hardcoded string — it is **derived from hardware-specific e-fuse data**

**Conclusion**: The AES key for `hw_ctree.xml` encryption is unique per device (derived from e-fuse). There is no universal key. This is why the ONT tool scripts use `cfgtool set` (which operates through the running firmware's API) rather than directly editing encrypted XML files.

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
├── BIN134_pkg3_full.bin         (1,769 KB)  [MODIFIED: factory reset script]
├── BIN135_pkg3_telnet.bin       (26 KB)
├── huawei_root_ca_pubkey.pem           Huawei Root CA (4096-bit RSA)
├── huawei_code_signing_ca2_pubkey.pem  Code Signing CA 2 (2048-bit RSA)
├── huawei_code_signing_pubkey.pem      Code Signing Cert 3 (2048-bit RSA)
└── scripts/
    ├── BIN130_duit9rr.sh
    ├── BIN131_run.sh
    ├── BIN132_restorefactory_DeleteComponent.sh
    ├── BIN133_run.sh
    ├── BIN134_restorefactory_DeleteComponent.sh  [MODIFIED]
    └── BIN135_run.sh
```
