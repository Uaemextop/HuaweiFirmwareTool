# Huawei HG8145V5 Firmware Encryption Analysis

## Reverse Engineering Results

### Encryption Architecture

The Huawei HG8145V5 firmware uses a multi-layered encryption system:

```
Hardware Root Key (eFuse/OTP, per-device)
    │
    ├── KMC Master Key (kmc_store_A/B files)
    │   ├── Domain 0: Certificate/Key passwords (prvt.key, plugprvt.key)
    │   ├── Domain 1: Configuration encryption (hw_ctree.xml)
    │   └── Work Keys (rotatable, time-limited)
    │
    ├── File Config Cipher Key (aescrypt2 tool)
    │   Key template: "Df7!ui%s9(lmV1L8"
    │   where %s = chip-specific string from /proc or /sys
    │
    └── BOARDINFO Key: "BOARDINFO(lmV1L8"
        Used for board info flash encryption
```

### Discovered Hardcoded Values

| Item | Value | Location | Purpose |
|------|-------|----------|---------|
| Key Template | `Df7!ui%s9(lmV1L8` | bin/aescrypt2 @ 0x308f | Config file encryption key template |
| BOARDINFO Key | `BOARDINFO(lmV1L8` | lib/libsmp_api.so | Board info flash encryption |
| Source File | `hw_ssp_ctool.c` | bin/aescrypt2 @ 0x3080 | Original source filename |
| Salt Positions | `[11, 17, 23, 29]` | lib/libhw_ssp_basic.so @ 0xc57f0 | g_auiRandomSaltPos_AES256 |
| KMC Stores | `kmc_store_A`, `kmc_store_B` | /etc/wap/ | Encrypted master key stores |

### Key Derivation Flow

1. **AES-256-CBC Key** derived via `HW_AES_GetCBCKey` → HMAC-SHA256 of password
2. **Password Encryption** format: `$<base93_encoded_ciphertext>$` (modulo 0x5D)
3. **File Encryption** (aescrypt2): `[type:4B][CRC:4B][keylen:4B][key][payload][HMAC-SHA256]`

### Private Key Encryption

| Key File | Format | Cipher | Status |
|----------|--------|--------|--------|
| prvt.key | PKCS#8 (PBES2) | AES-256-CBC | Password from KMC |
| plugprvt.key | Traditional PEM | AES-256-CBC, IV=8699C0FB... | Password from KMC |
| prvt_1_telmex.pem | Traditional PEM | DES-EDE3-CBC | ISP password |
| prvt_1_totalplay.pem | Traditional PEM | DES-EDE3-CBC | ISP password |
| dropbear_rsa_host_key | Dropbear format | KMC obfuscated (entropy 7.75) | Device-specific |

### Encrypted Rootfs Format (V2/SPC210/SPC458)

```
Header (96 bytes):
  0x00: uint32 magic     = 0x20190416
  0x10: uint32 sections  = 7
  0x14: uint32 enc_type  = 1
  0x18: byte[16] md5_hash
  0x28: uint32 data_size
  0x2C: uint32 header_sz = 0x60
  0x34: uint32 crc32
  0x38: char[36] version_string

Payload: AES-256 encrypted, key from hardware eFuse/OTP
```

### Critical Binaries (from remover SPC270 rootfs)

| Binary | Purpose |
|--------|---------|
| `bin/aescrypt2` | File encrypt/decrypt (CTOOL_GetFileConfigCipherKey) |
| `bin/keyfilemng` | Key file management (DM_DecryptBoardInfo) |
| `lib/libhw_ssp_basic.so` | KMC core (HW_KMC_GetDecryptKey, HW_AES_GetCBCKey) |
| `lib/libsmp_api.so` | Flash encryption (DM_DecryptFlashData) |
| `lib/libhw_smp_cmp.so` | Certificate manager (CMP_SetPassword) |

### Certificates Found in Rootfs

| File | Subject | Issuer | Valid |
|------|---------|--------|-------|
| pub.crt | Huawei ONT | Huawei Technologies | 2017-2027 |
| root.crt | Huawei Technologies | Self-signed | 2017-2027 |
| plugpub.crt | ont.huawei.com | HuaWei ONT CA | 2017-2067 |
| pub_1_telmex.pem | Telmex | Example CA (Huawei) | 2019-2020 |
| pub_1_totalplay.pem | Totalplay | Self-signed | 2020-2030 |
| servercert.pem | mediarouter.home | root.home | 2014-2024 |

### Why Private Keys Cannot Be Decrypted Without Device

Private key passwords are managed by **KMC (Key Management Center)**:
1. Passwords encrypted with AES key derived from **hardware Root Key** (eFuse/OTP)
2. Root Key is unique per device, write-only after provisioning
3. KMC stores contain encrypted master keys requiring hardware root key
4. To decrypt: need physical device access + JTAG/hardware debug for eFuse extraction
