# Extracted Firmware Configurations

Original `hw_ctree.xml` and `hw_default_ctree.xml` configuration trees
extracted and **decrypted** from Huawei ONT firmware images using each
firmware's own `aescrypt2` binary and embedded key material (`kmc_store`/`prvt.key`).

Also includes extracted certificates, private keys (PEM-encrypted),
`kmc_store` key material, passwd files, and `encrypt_spec` tar archives.

## Summary

| Firmware | Version | Decrypted XML | Keys | Certs | Tars |
|----------|---------|:---:|:---:|:---:|:---:|
| `EG8145V5-V500R022C00SPC340B019` | V500R022C00SPC340B019 | ✓ 132,215 B | ✓ | ✓ | ✓ |
| `HG8145C-V5R019C00S105` | V300R017C10SPC208B261 | ✓ 125,365 B | — | — | — |
| `HG8145C_17120_ENG` | V300R017C10SPC120B153 | ✓ 117,359 B | — | — | — |
| `HG8145V5-V500R020C10SPC212` | V500R020C10SPC212B465 | ✓ 131,509 B | ✓ | ✓ | ✓ |
| `HG8245C-8145C-BLUE-R019-xpon` | V300R017C10SPC125B176 | ✓ 125,365 B | — | — | — |
| `HN8145XR-V500R022C10SPC160` | V500R022C10SPC160B014 | ✓ 132,367 B | ✓ | ✓ | ✓ |

## Key Material Per Firmware

### EG8145V5-V500R022C00SPC340B019

| File | Description |
|------|-------------|
| `keys/kmc_store_A` | KMC keystore A (1024 B, WSEC format) |
| `keys/kmc_store_B` | KMC keystore B (1024 B, identical to A) |
| `keys/prvt.key` | SSL private key (AES-256-CBC encrypted PEM) |
| `keys/plugprvt.key` | Plug private key (AES-256-CBC encrypted PEM) |
| `keys/hilink_serverkey.pem` | HiLink server key (encrypted binary) |
| `certs/pub.crt` | SSL public certificate (RSA-2048, `ont.huawei.com`) |
| `certs/root.crt` | Root CA (`Huawei Fixed Network Product CA`) |
| `certs/plugpub.crt` | Plug public certificate |
| `certs/plugroot.crt` | Plug root CA (`HuaWei ONT CA`) |
| `certs/app_cert.crt` | App certificate (DER format, `Huawei Root CA`) |
| `certs/hilink_root.pem` | HiLink root CA (`root.home`) |
| `certs/hilink_servercert.pem` | HiLink server cert (`mediarouter.home`) |
| `tars/encrypt_spec.tar.gz` | Encryption spec archive |
| `tars/encrypt_spec_key.tar.gz` | Encryption spec key archive |
| `passwd` | System user accounts (`/etc/wap/passwd`) |

### HG8145V5-V500R020C10SPC212

| File | Description |
|------|-------------|
| `keys/kmc_store_A` | KMC keystore A (1024 B) |
| `keys/kmc_store_B` | KMC keystore B (1024 B) |
| `keys/prvt.key` | SSL private key (identical across V500 firmwares) |
| `keys/plugprvt.key` | Plug private key |
| `keys/hilink_serverkey.pem` | HiLink server key |
| `certs/pub.crt` | SSL public certificate |
| `certs/root.crt` | Root CA |
| `certs/plugpub.crt` | Plug public certificate |
| `certs/plugroot.crt` | Plug root CA |
| `certs/hilink_root.pem` | HiLink root CA |
| `certs/hilink_servercert.pem` | HiLink server cert |
| `tars/encrypt_spec.tar.gz` | Encryption spec archive |
| `passwd` | System user accounts |

### HN8145XR-V500R022C10SPC160

| File | Description |
|------|-------------|
| `keys/prvt.key` | SSL private key (identical across V500 firmwares) |
| `keys/plugprvt.key` | Plug private key |
| `keys/hilink_serverkey.pem` | HiLink server key |
| `certs/pub.crt` | SSL public certificate |
| `certs/root.crt` | Root CA |
| `certs/plugpub.crt` | Plug public certificate |
| `certs/plugroot.crt` | Plug root CA |
| `certs/app_cert.crt` | App certificate (DER) |
| `certs/hilink_root.pem` | HiLink root CA |
| `certs/hilink_servercert.pem` | HiLink server cert |
| `tars/encrypt_spec.tar.gz` | Encryption spec archive |
| `tars/encrypt_spec_key.tar.gz` | Encryption spec key archive |
| `passwd` | System user accounts |

## Certificate Chain

```
Huawei Root CA (4096-bit RSA, self-signed, expires 2050)
  └── Huawei Equipment CA
        └── Huawei Fixed Network Product CA (2048-bit RSA, expires 2041)
              └── ont.huawei.com (2048-bit RSA, server cert, expires 2030)

HuaWei ONT CA (2048-bit RSA, self-signed, expires 2026)
  └── ont.huawei.com (2048-bit RSA, plug cert, expires 2067)

root.home (2048-bit RSA, self-signed, HiLink CA, expires 2024)
  └── mediarouter.home (2048-bit RSA, HiLink server cert, expires 2024)
```

## Private Key Encryption

All `prvt.key` and `plugprvt.key` files are PEM-encrypted with AES-256-CBC.
The passphrase is **not** a simple string — it is derived at runtime via:

```
HW_KMC_GetAppointKey(domain, key_id) → raw key material
    → CAC_Pbkdf2Api() → PBKDF2-HMAC-SHA-256 derivation
        → passphrase used with mbedtls_pk_parse_keyfile()
```

The KMC (Key Management Center) key material comes from `kmc_store_A/B`,
which in turn is derived from the device's hardware e-fuse root key.
The `prvt.key` is identical across all V500 firmwares (MD5: `0de20c81fc6cf1d0d3607a1bd600f935`).

## kmc_store Format

The `kmc_store_A/B` files use Huawei's WSEC (Wisdom Security) binary format:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 32 | HMAC-SHA-256 integrity hash |
| 0x20 | 16 | Version (2), creation date, expiry date |
| 0x30 | 64 | Root key info (encrypted) |
| 0x70 | 48 | Padding/reserved |
| 0xB0 | 16 | Key entry count + metadata |
| 0xC0+ | 256 each | Key entries (domain, keyID, type, dates, encrypted material) |

Each kmc_store_A and kmc_store_B are identical within the same firmware.
Key material differs between device models (EG8145V5 ≠ HG8145V5).

## System Accounts (passwd)

From `/etc/wap/passwd`:

| User | UID | Description |
|------|-----|-------------|
| root | 0 | Root (no login shell) |
| mgt_ssmp | 3008 | Device management (SSMP) |
| srv_web | 3004 | Web server |
| cfg_cwmp | 3007 | TR-069 CWMP |
| kmc | 3020 | Key Management Center |
| cfg_pon | 3009 | OMCI/OAM |

## aescrypt2 Binary Analysis (HN8145XR)

The HN8145XR aescrypt2 binary is a 5,404-byte ARM PIE ELF (musl libc):

| Function | Source |
|----------|--------|
| `OS_AescryptEncrypt` | `libhw_ssp_basic.so` — PBKDF2 + AES-256-CBC encrypt |
| `OS_AescryptDecrypt` | `libhw_ssp_basic.so` — PBKDF2 + AES-256-CBC decrypt |
| `CHIPER_GetAdvicedEnMode` | `libhw_ssp_basic.so` — encryption mode selector |
| `HW_OS_Printf` | `libhw_ssp_basic.so` — logging |
| `HW_PROC_DBG_LastWord` | `libhw_ssp_basic.so` — error recording |

File format (AEST): `magic(4) + orig_size(4) + IV(16) + AES-256-CBC ciphertext + HMAC-SHA-256(32)`

Key derivation: PBKDF2-HMAC-SHA-256, 8192 iterations, salt from random IV.

## Decryption Method

Files were decrypted using each firmware's own `/bin/aescrypt2` binary
executed via `qemu-arm-static` chroot, with key material from the firmware's
own rootfs (`/etc/wap/kmc_store_A`, `/etc/wap/kmc_store_B` for V500 firmwares,
or `/etc/wap/prvt.key`, `/etc/wap/EquipKey` for V300 firmwares).

```
sudo chroot <rootfs> qemu-arm-static /bin/aescrypt2 1 <input> <output>
```

### HN8145XR Decryption

The HN8145XR firmware has a split-rootfs layout with 7 SquashFS images.
The `hw_ctree.xml` is in the first rootfs, while `aescrypt2` is in the
second (26 MB) rootfs. Unlike other V500 firmwares, HN8145XR does not
include `kmc_store` files in `/etc/wap/` — the `kmc_store` is normally
generated at first boot from the device's hardware e-fuse.

However, by creating **empty** `kmc_store_A` and `kmc_store_B` files in
`/mnt/jffs2/` (the runtime keystore path), `aescrypt2` falls back to a
default key derivation that successfully decrypts the factory `hw_ctree.xml`.

```bash
# HN8145XR specific: use second SquashFS for aescrypt2 + empty kmc_store
mkdir -p <rootfs>/mnt/jffs2/
touch <rootfs>/mnt/jffs2/kmc_store_A <rootfs>/mnt/jffs2/kmc_store_B
sudo chroot <rootfs> qemu-arm-static /bin/aescrypt2 1 /tmp/hw_ctree.xml /tmp/out.xml
# Output is gzip → gunzip → <InternetGatewayDevice> XML
```

## Extraction Tool

```bash
python tools/ctree_extract.py -o extracted_configs
```
