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

Verified by reverse-engineering `SWM_CheckEncryptFileHead` and `SWM_IsEncryptFileHead`
in `libhw_swm_dll.so`, and `DM_DecryptFlashData` in `libsmp_api.so`.

```
Header (0x60 = 96 bytes):
  Offset  Size  Field            Value / Description
  0x00    4     magicA           0x20190416 (checked by SWM_CheckEncryptFileHead)
  0x04    4     magicB           0x00343520 = " 54\0" (second magic check)
  0x08    4     field_08         1
  0x0C    4     field_0C         1
  0x10    4     sections         7 (number of flash partition sections)
  0x14    4     enc_type         1 (AES-256-CBC)
  0x18    16    md5_hash         MD5 of PLAINTEXT rootfs before encryption
  0x28    4     data_size        Size of encrypted payload (after header)
  0x2C    4     header_size      0x60 (always 96)
  0x30    4     total_padded     header_size + data_size, padded to alignment
  0x34    4     crc32            CRC32 of encrypted payload
  0x38    36    version_string   e.g. "V500R020C00SPC458B001"
  0x5C    4     padding          zeros

After header:
  0x60    16    md5_prefix       Same as md5_hash (plaintext verification prefix)
  0x70    ...   encrypted_data   AES-256-CBC encrypted SquashFS rootfs
```

#### Decryption Call Chain (from disassembly)

```
SWM_IsEncryptFileHead(header)
  → checks header[0] == 0x20190416 && header[4] == 0x343520
  → reads header[0x20] & 1 as "reservedFlag"

HW_SWM_EncryptFlashWrite(...)
  → SWM_GenerateEncryptFlashHead(key_buf, 32)
    → calls into DM layer (0x1316c) to get eFuse key
  → DM_FlashWriteEncryptAllsystem(...)
    → core flash write (0xe430, PLT stub to hardware layer)

DM_DecryptFlashData(input, key_len, output, out_len, key_buf)
  → HW_SSL_AesSetKeyDec(ctx, key_buf, 256)     // AES-256 key setup
  → HW_SSL_AesCryptCbc(ctx, DECRYPT, in, out, len, iv)  // AES-256-CBC decrypt

DM_FlashEfuseEncrypt(callback)
  → Gets hardware driver callback at offset r5+0x7c
  → Callback reads key from HiSilicon SoC eFuse OTP memory
```

#### Why Software Decryption Is Not Possible

The AES-256 key is stored in the HiSilicon SD5116H SoC's eFuse (One-Time Programmable)
memory region. This key:
- Is written once during manufacturing and cannot be read via software API
- Is only accessible through the SoC's internal hardware crypto engine
- Is unique per device (each manufactured unit has a different key)
- Cannot be extracted via JTAG without destructive chip decapping

Tested key candidates that do NOT work:
- All-zero key with zero IV
- All-zero key with MD5-as-IV
- `Df7!ui9(lmV1L8` (empty %s) - SHA256 hash and raw
- `Df7!uiSD50009(lmV1L8` - SHA256 hash and raw
- `Df7!uiSD5113A9(lmV1L8` - SHA256 hash and raw
- `BOARDINFO(lmV1L8` - SHA256 hash and raw

### aescrypt2 Tool Analysis (from ONT_V100R002C00SPC253.exe)

The ONT EXE embeds multiple HWNP firmware templates for different device generations.
The `aescrypt2` tool (ARM ELF, found in rootfs at `bin/aescrypt2`) handles
**config file encryption only** (hw_ctree.xml), NOT rootfs encryption.

```
Usage: aescrypt2 <mode> <input> <output>
  mode 0 = encrypt
  mode 1 = decrypt

Key derivation (from disassembly of CTOOL_GetFileConfigCipherKey):
  1. Read 4-byte key length prefix from encrypted file
  2. Read key_length bytes of encrypted key data
  3. CTOOL_GetFileConfigCipherKey calls HW_CTOOL_GetKeyChipStr
  4. HW_CTOOL_GetKeyChipStr uses template "Df7!ui%s9(lmV1L8" as AES key
  5. HW_OS_AESCBCEncrypt(data, key_template, key_template_len, output, ...)

Upgrade scripts from EXE (duit9rr.sh):
  HW_Script_Encrypt() {
      if [ $1 -eq 1 ]; then
          gzip -f $2
          mv $2".gz" $2
          aescrypt2 0 $2 $2"_tmp"   # encrypt
      fi
  }
  # Decrypt: aescrypt2 1 <file> <file_tmp>
  # Encrypt: aescrypt2 0 <file> <file_tmp>
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
