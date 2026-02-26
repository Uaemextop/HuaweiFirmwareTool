# HG8145V5 / HN8145X – Certificate and Key Analysis

*Generated: 2026-02-26 05:39 UTC*

---

## Summary

| Item | Count |
|------|-------|
| Total certificates | 7 |
| &nbsp;&nbsp;Root/Intermediate CAs | 4 |
| &nbsp;&nbsp;Expired | 2 |
| Total private keys | 16 |
| &nbsp;&nbsp;Plaintext (decrypted) | 4 |
| &nbsp;&nbsp;Encrypted (eFuse required) | 12 |

---

## Certificates

### `firmware_app_cert.crt` 🔑 **CA** 🌐 **ROOT CA**

| Field | Value |
|-------|-------|
| Subject | `Huawei Root CA` |
| Subject (full) | `CN=Huawei Root CA,O=Huawei,C=CN` |
| Issuer | `Huawei Root CA` |
| Issuer (full) | `CN=Huawei Root CA,O=Huawei,C=CN` |
| Key type | `RSA-4096` |
| Valid | `2015-10-15` → `2050-10-15` |
| Serial | `0x45b614733830b479` |
| CA | `True` (path_len=None) |
| Self-signed | `True` |
| Key Usage | `key_cert_sign`, `crl_sign` |
| SHA-1 fingerprint | `14e25bad2f2f3381362779625b64caabe462a7ba` |
| SHA-256 fingerprint | `a9d549e214c1f8a297079082c8ecf36bea539daba31c7d5688aabbc7ab9ccbc2` |

**Role:** **Huawei Global Root CA** (RSA-4096, valid 2015–2050). This is the top-level certificate used to verify ALL Huawei ONT firmware signatures. The matching private key lives in Huawei's factory HSM and is never exported to any device. Its public key is burned into each device's eFuse OTP during manufacturing. **Cannot be used to sign firmware without the private key.**

### `firmware_plugpub.crt`

| Field | Value |
|-------|-------|
| Subject | `ont.huawei.com` |
| Subject (full) | `OU=Ont,O=HuaWei,1.2.840.113549.1.9.1=support@huawei.com,C=CH,ST=HB,CN=ont.huawei.com` |
| Issuer | `HuaWei ONT CA` |
| Issuer (full) | `O=Root CA of HuaWei ONT,1.2.840.113549.1.9.1=support@huawei.com,C=CN,ST=Guangdong,CN=HuaWei ONT CA` |
| Key type | `RSA-2048` |
| Valid | `2017-12-21` → `2067-12-09` |
| Serial | `0x2` |
| CA | `False` (path_len=None) |
| Self-signed | `False` |
| SHA-1 fingerprint | `ca0abe26a6401eeb8de6ef4164022df060b43970` |
| SHA-256 fingerprint | `6548017016932bf1b5dc8271d2d429d41c85aa42d5db752d0b541d7cde225cb6` |

**Role:** **WAP/plug device leaf certificate** (RSA-2048), issued by HuaWei ONT CA. Used for client authentication in the ONT plug/enable subsystem. **Cannot be used to sign firmware.**

### `firmware_plugroot.crt` 🔑 **CA** 🌐 **ROOT CA**

| Field | Value |
|-------|-------|
| Subject | `HuaWei ONT CA` |
| Subject (full) | `O=Root CA of HuaWei ONT,1.2.840.113549.1.9.1=support@huawei.com,C=CN,ST=Guangdong,CN=HuaWei ONT CA` |
| Issuer | `HuaWei ONT CA` |
| Issuer (full) | `O=Root CA of HuaWei ONT,1.2.840.113549.1.9.1=support@huawei.com,C=CN,ST=Guangdong,CN=HuaWei ONT CA` |
| Key type | `RSA-2048` |
| Valid | `2016-04-08` → `2026-04-06` |
| Serial | `0x92cacb8608d07828` |
| CA | `True` (path_len=None) |
| Self-signed | `True` |
| SHA-1 fingerprint | `89311c4481f216fec9cd99da7f764bbf81d47308` |
| SHA-256 fingerprint | `1c2058449ba8d7e2ce81a2bf9db2986a523cede9f53797e9fb6f4791118a0245` |

**Role:** **HuaWei ONT CA – Root CA for WAP/plug subsystem** (RSA-2048, self-signed). Used to sign the device's WAP/plug authentication certificate (`firmware_plugpub.crt`). Controls the HiLink 'Enable ONT' plug feature. **Cannot be used to sign firmware.**

### `firmware_pub.crt`

| Field | Value |
|-------|-------|
| Subject | `ont.huawei.com` |
| Subject (full) | `CN=ont.huawei.com,O=Huawei,C=CN` |
| Issuer | `Huawei Fixed Network Product CA` |
| Issuer (full) | `CN=Huawei Fixed Network Product CA,O=Huawei,C=CN` |
| Key type | `RSA-2048` |
| Valid | `2020-08-25` → `2030-08-23` |
| Serial | `0x70c23220c046b365` |
| CA | `False` (path_len=None) |
| Self-signed | `False` |
| SHA-1 fingerprint | `228081e0b7eb3a5507bbd820c56f3683ef573084` |
| SHA-256 fingerprint | `a978acd8ea8378c44ffa9d045a5c240a127bb7a2cf7de0b79e52e2b83a83a28c` |

**Role:** **Device identity leaf certificate for TR-069/ACS** (RSA-2048). Used with `firmware_prvt.key` for mutual TLS authentication to the ISP's ACS provisioning server. With the private key decrypted, could authenticate as this specific ONT to any TR-069 ACS. **Cannot be used to sign firmware.**

### `firmware_root.crt` 🔑 **CA**

| Field | Value |
|-------|-------|
| Subject | `Huawei Fixed Network Product CA` |
| Subject (full) | `CN=Huawei Fixed Network Product CA,O=Huawei,C=CN` |
| Issuer | `Huawei Equipment CA` |
| Issuer (full) | `CN=Huawei Equipment CA,O=Huawei,C=CN` |
| Key type | `RSA-2048` |
| Valid | `2016-10-18` → `2041-10-12` |
| Serial | `0x763ee77a96ab8051948bb634bbb05c3cea` |
| CA | `True` (path_len=0) |
| Self-signed | `False` |
| Key Usage | `key_cert_sign`, `crl_sign` |
| SHA-1 fingerprint | `aa8e82f4c4caab4073cc9878b3aeb6b8a25b9428` |
| SHA-256 fingerprint | `df4db670cd5ebf492a9d077cdaa89ae6afec7dd4be1eb91161ef56688bd2faeb` |

**Role:** **Huawei Fixed Network Product CA** (RSA-2048 intermediate CA). Signs device identity certificates (`ont.huawei.com`) for TR-069/ACS mutual-TLS authentication. Issued by the 'Huawei Equipment CA' (not in this dump). **Cannot be used to sign firmware.** Useful to verify the device identity cert chain.

### `firmware_root.pem` ⚠️ **EXPIRED** 🔑 **CA** 🌐 **ROOT CA**

| Field | Value |
|-------|-------|
| Subject | `root.home` |
| Subject (full) | `1.2.840.113549.1.9.1=mobile@huawei.com,CN=root.home,L=Wuhan,ST=Hubei,C=CN` |
| Issuer | `root.home` |
| Issuer (full) | `1.2.840.113549.1.9.1=mobile@huawei.com,CN=root.home,L=Wuhan,ST=Hubei,C=CN` |
| Key type | `RSA-2048` |
| Valid | `2014-07-14` → `2024-07-11` (**EXPIRED**) |
| Serial | `0xa84b01e03d358b25` |
| CA | `True` (path_len=None) |
| Self-signed | `True` |
| Key Usage | `key_cert_sign`, `crl_sign` |
| SHA-1 fingerprint | `bb458f89b252ee8ed359f90e73bc966f22b183cf` |
| SHA-256 fingerprint | `2e3a2a0f0a3c94b0ddaf5e7d586bfdcc086635ed81dd620b4b7a11c2757bb837` |

**Role:** **HiLink web management self-signed Root CA** (RSA-2048). **⚠️ EXPIRED – do not use for new TLS sessions.** Issues the mediarouter.home TLS server cert. **Cannot be used to sign firmware.**

### `firmware_servercert.pem` ⚠️ **EXPIRED**

| Field | Value |
|-------|-------|
| Subject | `mediarouter.home` |
| Subject (full) | `CN=mediarouter.home,L=Wuhan,ST=Hubei,C=CN` |
| Issuer | `root.home` |
| Issuer (full) | `1.2.840.113549.1.9.1=mobile@huawei.com,CN=root.home,L=Wuhan,ST=Hubei,C=CN` |
| Key type | `RSA-2048` |
| Valid | `2014-07-14` → `2024-07-11` (**EXPIRED**) |
| Serial | `0x1` |
| CA | `False` (path_len=None) |
| Self-signed | `False` |
| Key Usage | `digital_signature`, `key_encipherment` |
| SAN | `DNS:mediarouter.home`, `DNS:mediarouter1.home`, `DNS:mediarouter2.home`, `DNS:mediarouter3.home` |
| SHA-1 fingerprint | `069b85b13f43c45f181072e2965b2e105202982a` |
| SHA-256 fingerprint | `816735d1fd53b8747aa3a61e277dd8fd5dd303475bc9730ead8ad67155518e33` |

**Role:** **HiLink web management TLS server certificate** (RSA-2048). **⚠️ EXPIRED – do not use for new TLS sessions.** Issued by root.home self-signed CA. SAN covers mediarouter.home / mediarouter1-3.home. Used for HTTPS on the router's local web interface. **Cannot be used to sign firmware.**

---

## Private Keys

### `nand_ec_key_1.pem` ✅ **PLAINTEXT**

| Field | Value |
|-------|-------|
| Type | `EC-secp384r1 (384 bits)` |
| Status | `plaintext` |
| Public key | `04c3da2b344137582f8756fefc89ba29434b4ee06ec30e5753333958d452b491…` |

**Role:** **mbedTLS/PolarSSL standard library test key** (EC secp384r1, 384 bits). Passphrase: `PolarSSLTest`. Found embedded in UBIFS filesystem test data at multiple flash offsets. This is NOT a device production key. All 4 copies (nand_ec_key_1, nand_ec_key_2, nand_encrypted_key_3_dec, nand_encrypted_key_10_dec) are identical. **No production security value.**

### `nand_ec_key_2.pem` ✅ **PLAINTEXT**

| Field | Value |
|-------|-------|
| Type | `EC-secp384r1 (384 bits)` |
| Status | `plaintext` |
| Public key | `04c3da2b344137582f8756fefc89ba29434b4ee06ec30e5753333958d452b491…` |

**Role:** **mbedTLS/PolarSSL standard library test key** (EC secp384r1, 384 bits). Passphrase: `PolarSSLTest`. Found embedded in UBIFS filesystem test data at multiple flash offsets. This is NOT a device production key. All 4 copies (nand_ec_key_1, nand_ec_key_2, nand_encrypted_key_3_dec, nand_encrypted_key_10_dec) are identical. **No production security value.**

### `nand_encrypted_key_10_vol9_0x1b3e0d1.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN EC PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `DES-EDE3-CBC,307EAB469933D64E` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_10_vol9_0x1b3e0d1_decrypted.pem` ✅ **PLAINTEXT**

| Field | Value |
|-------|-------|
| Type | `EC-secp384r1 (384 bits)` |
| Status | `plaintext` |
| Public key | `04c3da2b344137582f8756fefc89ba29434b4ee06ec30e5753333958d452b491…` |

**Role:** **mbedTLS/PolarSSL standard library test key** (EC secp384r1, 384 bits). Passphrase: `PolarSSLTest`. Found embedded in UBIFS filesystem test data at multiple flash offsets. This is NOT a device production key. All 4 copies (nand_ec_key_1, nand_ec_key_2, nand_encrypted_key_3_dec, nand_encrypted_key_10_dec) are identical. **No production security value.**

### `nand_encrypted_key_1_vol9_0x591487.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_2_vol9_0x78f41f.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_3_vol9_0x7a30d1.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN EC PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `DES-EDE3-CBC,307EAB469933D64E` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_3_vol9_0x7a30d1_decrypted.pem` ✅ **PLAINTEXT**

| Field | Value |
|-------|-------|
| Type | `EC-secp384r1 (384 bits)` |
| Status | `plaintext` |
| Public key | `04c3da2b344137582f8756fefc89ba29434b4ee06ec30e5753333958d452b491…` |

**Role:** **mbedTLS/PolarSSL standard library test key** (EC secp384r1, 384 bits). Passphrase: `PolarSSLTest`. Found embedded in UBIFS filesystem test data at multiple flash offsets. This is NOT a device production key. All 4 copies (nand_ec_key_1, nand_ec_key_2, nand_encrypted_key_3_dec, nand_encrypted_key_10_dec) are identical. **No production security value.**

### `nand_encrypted_key_4_vol9_0xe30d0f.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_5_vol9_0x1272d0f.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_6_vol9_0x1691d0f.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_7_vol9_0x1692d0f.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_8_vol9_0x1693d0f.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `nand_encrypted_key_9_vol9_0x1a6250f.pem` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** (DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. Likely device TLS/authentication keys stored in UBIFS persistent storage. **Cannot be decrypted without the device eFuse key.**

### `firmware_plugprvt.key` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,8699C0FB1C5FA5FF6A3082AFD6082004` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **WAP/ONT-plug authentication private key** (RSA-2048, AES-256-CBC encrypted). Paired with `firmware_plugpub.crt`. Used for the HiLink ONT-enable/plug subsystem. Passphrase = `certprvtPassword` from `hw_ctree.xml`. **Cannot be decrypted without the device eFuse key.**

### `firmware_prvt.key` 🔒 **ENCRYPTED**

| Field | Value |
|-------|-------|
| Type | `BEGIN RSA PRIVATE KEY` |
| Status | `encrypted` |
| DEK-Info | `AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9` |
| Note | certprvtPassword (device-specific, derived from eFuse OTP) |

**Role:** **TR-069 / ACS mutual-TLS device private key** (RSA-2048, AES-256-CBC encrypted). Paired with `firmware_pub.crt`. Used for mTLS authentication to the ISP's TR-069 ACS server. Passphrase = `certprvtPassword` from `hw_ctree.xml` (device-specific, derived from eFuse OTP). **Cannot be decrypted without the device eFuse key.** If decrypted: could authenticate as this ONT to any TR-069 ACS (research use).

---

## Duplicate / Identical Keys

The following key files are **cryptographically identical** (same private scalar):

| Files | Note |
|-------|------|
| `nand_ec_key_1.pem`, `nand_ec_key_2.pem`, `nand_encrypted_key_3_*_decrypted.pem`, `nand_encrypted_key_10_*_decrypted.pem` | All are the standard **mbedTLS/PolarSSL library test key** (passphrase: `PolarSSLTest`, curve: secp384r1). Found in UBIFS test node data at 4 different flash offsets. This is NOT a device TLS key. |

The 8 encrypted RSA keys (`nand_encrypted_key_{1,2,4,5,6,7,8,9}_*`) all share the
same DEK-Info IV (`7EC546FB34CA7CD5599763D8D9AE6AC9`), meaning they share the same
OpenSSL EVP_BytesToKey derivation from a single certprvtPassword passphrase.

---

## Can These Keys/Certs Be Used to Sign Huawei Firmware?

**Short answer: NO.**

### Why Not

Huawei ONT firmware (HG8145V5, EG8145V5, HN8145X) uses a hardware-bound
signing chain that is anchored in the device eFuse OTP registers:

```
eFuse OTP (0x12010100, burned at factory, read-only)
    └── HW_DM_GetRootPubKeyInfo()      ← read from hardware registers
           └── Huawei Root CA (RSA-4096) ← public cert in firmware_app_cert.crt
                  └── Code Signing CA 2
                         └── Code Signing Cert 3
                                └── Firmware HWNP package signature
```

The verification path (`SWM_Sig_VerifySignature → CmscbbVerify →
HW_DM_GetRootPubKeyInfo`) reads the root CA public key **directly from the
eFuse registers** – not from flash. This means:

1. The **Huawei Root CA private key** (RSA-4096, matching `firmware_app_cert.crt`)
   never leaves Huawei's factory HSM. It is NOT stored anywhere in flash, NAND,
   or any extractable form.
2. Even if you had the intermediate CA certificates, you cannot forge the chain
   without the root private key.
3. The eFuse root public key is burned at the factory and **verified in hardware**
   on every boot – it cannot be changed.

### What Would Be Required

To sign firmware that the bootloader accepts, you would need:
- The RSA-4096 private key for `CN=Huawei Root CA` (stays at Huawei, never exported)
- OR: physical access to reprogram the eFuse OTP (irreversible, destroys warranty)
- OR: exploit a vulnerability in the signature verification code itself

### Keys Recovered in This Dump vs Firmware Signing

| Key/Cert | Role | Useful for Firmware Signing? |
|----------|------|------------------------------|
| `firmware_app_cert.crt` (Huawei Root CA, RSA-4096) | Firmware verification anchor | ✗ Public cert only – private key is at Huawei HQ |
| `firmware_root.crt` (Huawei Fixed Network Product CA) | Intermediate CA cert | ✗ Public cert only |
| `firmware_pub.crt` (ont.huawei.com) | Device identity leaf cert | ✗ Not a signing cert |
| `firmware_plugroot.crt` (HuaWei ONT CA) | WAP/TR-069 root CA | ✗ Different PKI tree |
| `firmware_plugpub.crt` (ont.huawei.com) | WAP/TR-069 leaf cert | ✗ Not a signing cert |
| `firmware_root.pem` (root.home, EXPIRED) | HiLink HTTPS root CA | ✗ Expired, different PKI |
| `firmware_servercert.pem` (mediarouter.home, EXPIRED) | HiLink HTTPS server cert | ✗ Expired TLS cert only |
| `firmware_serverkey.pem` | HiLink HTTPS private key | ✗ Proprietary binary format, HTTPS only |
| `firmware_prvt.key` / `firmware_plugprvt.key` (ENCRYPTED) | TR-069/WAP device auth key | ✗ Encrypted, HTTPS/TR-069 use only |
| EC secp384r1 keys × 4 (PolarSSLTest) | **mbedTLS test vectors** | ✗ Test key, no production use |
| NAND RSA keys × 8 (ENCRYPTED) | Device-specific TLS/auth keys | ✗ Encrypted + wrong PKI tree |

---

## Practical Uses for Security Research

### ✓ TR-069 / ACS Authentication Impersonation
`firmware_pub.crt` + `firmware_prvt.key` (once decrypted via eFuse) constitute
the device mTLS identity for the ISP's TR-069 ACS server. With the decrypted
private key, you could:
- Authenticate as this physical ONT device to any TR-069 ACS
- Observe what provisioning data the ACS sends
- **Scope**: Specific to this one device's identity only

### ✓ HiLink / HiRouter Web Interface MITM
`firmware_root.pem` + `firmware_servercert.pem` are the self-signed TLS
certificates for the `mediarouter.home` web interface. **Both EXPIRED July 2024.**
If the web server private key were available (in standard format), this could be
used to set up a local MITM for the router management interface. In practice,
the expired cert means most browsers will already warn users.

### ✓ WAP / ONT Plug Authentication
`firmware_plugroot.crt` + `firmware_plugpub.crt` + `firmware_plugprvt.key`
(once decrypted) are used for the HiLink "plug/enable" ONT subsystem.
Can be used for device-specific authentication analysis.

### ✓ mbedTLS Test Key Identification
The 4 identical EC secp384r1 keys (`PolarSSLTest` passphrase) confirm that the
device's UBIFS filesystem contains standard mbedTLS test data under UBIFS test
node data at multiple locations. This is a test suite artefact, not a device key.

### ✗ Cannot be used for
- Firmware signing (see section above)
- Signing bootloaders
- Bypassing secure boot
- Creating counterfeit firmware packages

---

## Certificate Chain Diagram

```
Huawei Firmware Signing PKI (hardware-anchored, CANNOT sign custom firmware):

  eFuse OTP registers (hardware, read by HW_DM_GetRootPubKeyInfo)
       │
       ├── firmware_app_cert.crt  [Huawei Root CA, RSA-4096, 2015-2050]
       │       └── (Code Signing CA 2 → Code Signing Cert 3 → HWNP signature)
       │           ← Private key at Huawei factory only, NEVER in flash

Huawei Fixed Network Product PKI (device identity, CANNOT sign firmware):

  Huawei Equipment CA  (external, not in dump)
       └── firmware_root.crt  [Huawei Fixed Network Product CA, RSA-2048, 2016-2041]
               └── firmware_pub.crt  [ont.huawei.com, RSA-2048, 2020-2030]
                       (+ firmware_prvt.key ENCRYPTED → TR-069/ACS mTLS)

HuaWei ONT CA PKI (plug/WPS subsystem, CANNOT sign firmware):

  firmware_plugroot.crt  [HuaWei ONT CA, RSA-2048, self-signed, 2016-2026 EXPIRED]
       └── firmware_plugpub.crt  [ont.huawei.com, RSA-2048, 2017-2067]
               (+ firmware_plugprvt.key ENCRYPTED → WAP/plug auth)

HiLink Web Interface PKI (local HTTPS, CANNOT sign firmware):

  firmware_root.pem  [root.home, RSA-2048, self-signed, 2014-2024 EXPIRED]
       └── firmware_servercert.pem  [mediarouter.home, RSA-2048, 2014-2024 EXPIRED]
               (+ firmware_serverkey.pem → binary, web HTTPS only)

UBIFS Test Data (NOT device keys):

  nand_ec_key_1/2.pem  [mbedTLS PolarSSLTest vector, secp384r1, 4× identical copies]

NAND Device Keys (device-specific, need eFuse to decrypt):

  nand_encrypted_key_{1,2,4,5,6,7,8,9}.pem  [RSA, AES-256-CBC, IV=7EC546FB...]
       (certprvtPassword stored in hw_ctree.xml, encrypted with eFuse-derived key)
```
