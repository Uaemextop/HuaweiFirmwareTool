# EG8145V5-V500R022C00SPC340B019 Rootfs Analysis

Firmware: `EG8145V5-V500R022C00SPC340B019.bin`
MD5: `7768ad910c0d9d5a7f9a9d36246e1aec`
Rootfs: Unencrypted SquashFS (LZMA, 36.4 MB, 5340 files, 703 dirs, 266 symlinks)

## System Users (etc/wap/passwd)

| User | UID | GID | Description | Shell |
|------|-----|-----|-------------|-------|
| root | 0 | 0 | root | /sbin/nologin |
| srv_amp | 3003 | 2002 | hw_srv_amp | /bin/false |
| srv_web | 3004 | 2002 | hw_srv_web | /bin/false |
| osgi_proxy | 3005 | 2000 | hw_osgi_proxy | /bin/false |
| cfg_cwmp | 3007 | 2001 | hw_cfg_cwmp (TR-069) | /bin/false |
| srv_ssmp | 3008 | 2002 | hw_srv_ssmp | /bin/false |
| cfg_cli | 3010 | 2001 | hw_cfg_cli | /bin/false |
| srv_kmc | 3020 | 500 | hw_srv_kmc (Key Management) | /bin/false |
| srv_voice | 4002 | 2002 | VoIP service | /bin/false |
| nobody | 65534 | 65534 | Unprivileged | /bin/false |

Root login is disabled (`/sbin/nologin`). No password hashes in passwd (uses `*`).

## SSL Certificates

| File | Subject | Issuer | Valid From | Valid To | Key Size |
|------|---------|--------|-----------|----------|----------|
| etc/wap/pub.crt | ont.huawei.com | Huawei Fixed Network Product CA | 2020-08-25 | 2030-08-23 | RSA-2048 |
| etc/wap/root.crt | Huawei Fixed Network Product CA | Huawei Equipment CA | 2016-10-18 | 2041-10-12 | RSA-2048 |
| etc/wap/plugpub.crt | ont.huawei.com | HuaWei ONT CA | 2017-12-21 | 2067-12-09 | RSA-2048 |
| etc/wap/plugroot.crt | HuaWei ONT CA (self-signed) | HuaWei ONT CA | 2016-04-08 | 2026-04-06 | RSA-2048 |
| etc/app_cert.crt | Huawei Root CA (self-signed) | Huawei Root CA | 2015-10-15 | 2050-10-15 | RSA-2048 |
| etc/wap/hilinkcert/root.pem | root.home (self-signed) | root.home | 2014-07-14 | 2024-07-11 | RSA-2048 |
| etc/wap/hilinkcert/servercert.pem | mediarouter.home | root.home | 2014-07-14 | 2024-07-11 | RSA-2048 |

Certificate chain: `pub.crt` → `root.crt` → Huawei Equipment CA
Plugin chain: `plugpub.crt` → `plugroot.crt` (self-signed)
HiLink chain: `servercert.pem` → `root.pem` (self-signed, for local HTTPS management at 192.168.1.1)

## Private Keys (All Encrypted)

| File | Format | Cipher | Key Source |
|------|--------|--------|------------|
| etc/wap/prvt.key | PEM PKCS#1, encrypted | AES-256-CBC, IV=7EC546FB... | KMC (hardware-derived password) |
| etc/wap/plugprvt.key | PEM PKCS#1, encrypted | AES-256-CBC, IV=8699C0FB... | KMC (hardware-derived password) |
| etc/wap/hilinkcert/serverkey.pem | aescrypt2 format (type=1) | AES-256-CBC | Chip-specific key |
| etc/dropbear/dropbear_rsa_host_key | Dropbear binary format (872 bytes) | KMC obfuscated | Hardware-bound |

**None of these keys can be decrypted without physical access to the device.**
The password for PEM keys is stored in KMC (Key Management Center) which derives
keys from the hardware eFuse/OTP root key unique to each manufactured device.

## SSH (Dropbear)

- Binary: `bin/dropbear` (ARM ELF, musl-linked)
- Key generator: `bin/dropbearkey`
- Host key: `etc/dropbear/dropbear_rsa_host_key` (872 bytes, KMC-protected)
- SSH access is typically disabled in production firmware

## KMC (Key Management Center)

| File | Description |
|------|-------------|
| etc/wap/kmc_store_A | Encrypted master key store (primary) |
| etc/wap/kmc_store_B | Encrypted master key store (backup) |

Both KMC stores start with identical 16-byte header (`5f64978d194f89cf...`),
contain encrypted work keys managed by `srv_kmc` process (UID 3020).

## Encrypted Configuration Files

| File | Type | Description |
|------|------|-------------|
| etc/wap/hw_ctree.xml | aescrypt2 (type=1) | Main device configuration tree |
| etc/wap/hw_default_ctree.xml | aescrypt2 (type=1) | Factory default configuration |
| etc/wap/hilinkcert/serverkey.pem | aescrypt2 (type=1) | HiLink HTTPS private key |
| etc/wap/spec/encrypt_spec/encrypt_spec.tar.gz | aescrypt2 (type=1) | Encrypted spec config |
| etc/wap/spec/encrypt_spec_key/encrypt_spec_key.tar.gz | aescrypt2 (type=1) | Encrypted spec keys |

### Encryption Details (from binary analysis)

Key template (from `etc/wap/spec/spec_default.cfg`):
```
SPEC_OS_AES_CBC_APP_STR = "Df7!ui%s9(lmV1L8"
```

The `%s` is replaced with the chip ID at runtime (read from `/proc` or SoC registers).
The resulting string is processed by `HW_AES_GetCBCKey()` in `libhw_ssp_basic.so`
which calls KMC functions (`fcn.00091730`) for the final AES-256-CBC key derivation.

**Decryption call chain** (from disassembly of `bin/aescrypt2` and `lib/libhw_ssp_basic.so`):
```
aescrypt2 mode=1 (decrypt)
  → OS_AescryptDecrypt(input, output, key_flag, ...)
    → fcn.00062f40() [validate header]
    → fcn.00026d2c() [open/read file]
    → fcn.0006358c() [core decrypt]
      → HW_AES_GetCBCKey(password, key_buf, ...)
        → fcn.00091730() [KMC key derivation from eFuse]
        → AES-256-CBC decrypt with derived key
```

### Decryption Attempt Results

Extensive testing was performed with:
- Key template `Df7!ui%s9(lmV1L8` with 30+ chip IDs (SD5116H, SD5116, SD5182H, Hi5116H, etc.)
- Multiple key derivation methods (raw, MD5, SHA-256, HMAC-SHA256)
- Multiple IV sources (zero IV, hash fields from file headers)
- CRC32 validation against stored CRC in hw_ctree.xml header
- Known Huawei default passwords (telecomadmin, nE7jA%5m, etc.)
- KMC store bytes as key material

**Result:** No combination produced valid plaintext. Binary analysis confirms:
1. `DM_GetRootKey` (libsmp_api.so @ 0x917f) reads root key from hardware eFuse
2. `FlashEfuseEncrypt` (libsmp_api.so @ 0x9a58) handles eFuse-based encryption
3. `HW_DM_GetEncryptedKey` derives work keys from eFuse root key
4. KMC stores (kmc_store_A/B) are encrypted with the eFuse root key

**Conclusion:** The encrypted files (hw_ctree.xml, ttree_spec_smooth.tar.gz, private keys)
cannot be decrypted without physical access to the device's HiSilicon SoC eFuse/OTP memory.
Each manufactured device has a unique root key burned into the silicon during production.

## ISP Configurations (Web Interface Menus)

82 ISP menu XML files found in `html/menu/`. Notable ISPs:

| Region | ISP | Menu File |
|--------|-----|-----------|
| Mexico | Telmex | MenuTelmex.xml, MenuTelmexAccess.xml, MenuTelmexResale.xml |
| Mexico | Megacable | (Not present in this firmware - uses COMMON profile) |
| Argentina | Claro | MenuClaro.xml, MenuCablevision.xml |
| China | CMCC | MenuCmcc.xml, MenuChina.xml |
| Russia | Megafon | MenuSmartMegafon.xml |
| Vietnam | Viettel | MenuViettel.xml |
| Saudi | STC/Mobily | MenuSTC.xml, MenuMobily.xml |
| Philippines | PLDT | MenuAbroad_PLDT2.xml |

**Note:** Megacable does not have a specific menu XML in this firmware.
It likely uses `MenuChina.xml`, `MenuCmcc.xml`, or `COMMON` profile,
configured via TR-069 by the ISP's ACS server.

## Firmware Update Mechanism

### UpgradeCheck.xml

Compatible hardware:
- Board IDs: 13351, 13371, 13011, 13021, 13691, 13701, 126, 64, 66, 82, 89, etc.
- LSW chips: COMMON, NONE, HWSOC3_2, HWSOC6, HWSOC7
- WiFi chips: COMMON, AUTOFEM, HWWIFI1_1, HWWIFI1_2, HWWIFI_11521
- Products: 159D, 15ED, 15DD, 26AD, 2C1D, 2E1D, 31FD, 2D7D
- Programs: E8C, COMMON, CHINA, CMCC, CHOOSE, DT_HUNGARY

### Flash Layout (hw_flashcfg.xml)

```
Total flash: 128 MB (0x08000000)
├── bootcode (L1boot+L2boot+eFuse): 0x000a0000
├── allsystem A: 0x02C00000 (44 MB) [signinfo+uboot+kernel+rootfs]
├── allsystem B: 0x02C00000 (44 MB) [backup image]
└── ubilayer_v5: 0x02400000 (36 MB)
    ├── flash_config A/B: 0x0001F000
    ├── slave_param A/B: 0x0001F000
    ├── wifi_param A/B: 0x0001F000
    ├── keyfile: 0x00100000
    └── file_system: 0x01D80000
```

### Update Scripts

- `bin/customize_exec.sh` — Post-upgrade customization
- `bin/restorehwmode.sh` — Restore hardware mode after update
- `etc/rc.d/rc.start/1.sdk_init.sh` — SDK initialization on boot

### Update Protocols

From `libhw_swm_dll.so` string analysis:
- **TR-069/CWMP**: ISP pushes firmware URL via ACS Download RPC
- **OMCI**: OLT transfers firmware via GPON management (ME Class 7)
- **Web**: Manual upload through `html/ssmp/upgradeapp.asp`
- **TFTP**: Recovery mode (hold reset, device at 192.168.1.1)

## Plugin System (preload_cplugin.tar.gz)

Extracted: `preload_cplugin/kernelapp.cpk` (gzip → tar, 4.8 MB decompressed)

### MyPlugin Contents

| File | Description |
|------|-------------|
| bin/kernelapp | ARM ELF, main plugin binary (musl-linked) |
| bin/opkg | Package manager |
| bin/cpluginapp_real | Plugin application |
| daemon.sh | Plugin daemon (keepalive loop) |
| plugin_startup_new.sh | Startup script |
| plugin_monitor.sh | Memory watchdog (kills if VmRSS > 11246 KB) |
| etc/config/kernelapp.config | Main config (ports, SSL, encryption settings) |
| etc/config/server_ssl.pem | Plugin SSL certificate (ONT-Plugin, issued by Huawei Fixed Network Product CA) |
| etc/config/server_key_ssl.pem | Plugin SSL private key (AES-256-CBC encrypted) |
| etc/config/trust_ssl.pem | Trust CA certificate (HuaWei ONT CA) |

### Plugin Config Keys (from kernelapp.config)

```json
{
  "securityport": "9013",
  "mqttport": "1884",
  "restport": "9013",
  "AppString": "abc###78d!",
  "local_restssl_key": "sovolTuHdX5WHp89NbCwf2lMIc5miO60P2ab/rSw1POkdlHrQ36e19x95r4Bje8e"
}
```

### Plugin SSL Certificate Chain

```
server_ssl.pem: CN=ONT-Plugin, O=Huawei (2021-2036, RSA-3072)
  ← Issued by: Huawei Fixed Network Product CA
trust_ssl.pem: CN=HuaWei ONT CA (self-signed, 2016-2026, RSA-2048)
server_key_ssl.pem: RSA private key (AES-256-CBC encrypted, IV=17896CEE...)
```

## BOARDINFO Encryption

Found `BOARDINFO` string in:
- `lib/libsmp_api.so` — `DM_DecryptBoardInfo`, `DM_IsBoardInfoFileEncrypt`
- `lib/libhw_ssp_basic.so` — Board info encryption functions
- `lib/libhw_smp_dm_pdt.so` — Product-specific DM functions
- `bin/setboardinfo` — Board info configuration tool

Board info encryption uses key pattern `BOARDINFO(lmV1L8` (from previous reverse engineering sessions).

## EFS (Equipment Firmware Specification)

```
Magic:     HW (0x4857)
Version:   2
Platform:  MA5600 (Huawei OLT)
Board ID:  H801EPBA
```

## ttree_spec_smooth.tar.gz

Format: aescrypt2 encrypted (type=4)
This is a compressed device specification tree, encrypted with the
chip-specific AES key. Cannot be decrypted without device access.

## Full Shell Access (SU Challenge Bypass)

### WAP CLI Architecture

The router's telnet service provides a **restricted WAP CLI** (not a Linux shell).
The access chain is:

```
telnet port 23 → clid (WAP CLI daemon)
                  → restricted command tree
                  → 'su' command → RSA challenge-response → full shell (SU_root>)
```

### SU RSA Key (FACTORED — 256-bit, trivially weak)

The SU challenge uses a 256-bit RSA key stored in `/etc/wap/su_pub_key`.
This key was factored instantly via factordb.com:

```
Public key:  /etc/wap/su_pub_key (256-bit RSA)
Modulus (n): cdb6cda2aa36179aa239fc1d48ce9e82194cc577a631897a2df50dfd1f20dad5
Exponent:    65537

FACTORED PRIMES:
  p = 297098113301310309198580524816784910303
  q = 313186503727240930873981527043146130379

Private exponent (d):
  b79dc0a4bdeb345c690afab724e2906593e134bc0fec90a5afa79b91c6751d2d
```

Private key saved to: `etc/wap/su_private_key.pem`

### How to Get Full Shell

1. **Telnet** to the router: `telnet 192.168.1.1`
2. Login with WAP CLI credentials (e.g., root/admin or ISP-provided)
3. Type `su` — the router sends a hex challenge
4. Run: `python3 hw_su_challenge.py solve <challenge_hex>`
5. Paste the response → full shell access (`SU_root>` prompt)

Or automated: `python3 hw_su_challenge.py auto 192.168.1.1 -u root -p admin`

### Alternative Shell Access Methods

| Method | Feature Flag | Default | Description |
|--------|-------------|---------|-------------|
| SU Challenge | `FT_SSMP_CLI_SU_CHALLENGE` | 0 (off) | RSA challenge (factorable key) |
| Direct Shell | `FT_CLI_DEFAULT_TO_SHELL` | 0 (off) | CLI login → direct shell |
| TDE Shell | `SSMP_FT_TDE_OPEN_SHELL` | 1 (on for TDE) | Open shell for TDE profiles |
| No Auth | `SSMP_FT_CLI_NO_AUTH` | 0 (off) | Skip authentication |
| China Mode | `HW_SSMP_FEATURE_CLI_CHINA_MODE` | 0 (off) | SU → transparent mode |
| Equipment Test | CLI command | off | `huaweiequiptestmode-on` |
| Debug Flag | File | absent | Create `/etc/wap/DebugVersionFlag` |

### Transparent Mode (Direct Linux Shell)

After SU authentication, the commands `dcom transparent on boardid` or
`transparent on arm` provide direct passthrough to the underlying Linux shell.

## Config Field Encryption ($2...$ Format)

Inside `hw_ctree.xml` (once decrypted at file level), passwords and secrets
are stored as `$2....$` encrypted strings using:

- **Algorithm**: AES-256-CBC
- **Key**: `6fc6e3436a53b6310dc09a475494ac774e7afb21b9e58fc8e58b5660e48e2498` (hardcoded, universal)
- **Encoding**: Custom base-93 + ASCII visibility mapping
- **IV**: Embedded in the last 20 encoded bytes of each string

This is the **same key** used by:
- [huawei-utility-page](https://github.com/andreluis034/huawei-utility-page)
- [Ratr/Hwdecode](https://github.com/Jakiboy/Ratr) (via Jakiboy/Hwdecode)

Tool: `python3 hw_config_decrypt.py --decrypt '$2<encrypted>$'`

### Encryption Layers Summary

| Layer | Algorithm | Key Source | Decryptable? |
|-------|-----------|-----------|-------------|
| File-level (aescrypt2 type=1) | AES-256-CBC | KMC/eFuse hardware key | ❌ Requires device |
| File-level (aescrypt2 type=4) | AES-256-CBC | KMC/eFuse hardware key | ❌ Requires device |
| Field-level ($2...$) | AES-256-CBC | Hardcoded universal key | ✅ `hw_config_decrypt.py` |
| PEM private keys | AES-256-CBC | KMC-derived password | ❌ Requires device |
| SU challenge | RSA-256 | Public key in su_pub_key | ✅ `hw_su_challenge.py` |
