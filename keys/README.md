# HG8145V5 / HN8145X – Extracted Keys & Certificates

## Source Files

| File | Source | Type | Status |
|------|--------|------|--------|
| `firmware_prvt.key` | HN8145X rootfs `/etc/wap/prvt.key` | RSA private key (AES-256-CBC encrypted) | Encrypted – passphrase device-specific |
| `firmware_plugprvt.key` | HN8145X rootfs `/etc/wap/plugprvt.key` | RSA private key (AES-256-CBC encrypted) | Encrypted – passphrase device-specific |
| `firmware_pub.crt` | HN8145X rootfs `/etc/wap/pub.crt` | X.509 certificate | Plaintext |
| `firmware_plugpub.crt` | HN8145X rootfs `/etc/wap/plugpub.crt` | X.509 certificate | Plaintext |
| `firmware_root.crt` | HN8145X rootfs `/etc/wap/root.crt` | X.509 root CA | Plaintext |
| `firmware_plugroot.crt` | HN8145X rootfs `/etc/wap/plugroot.crt` | X.509 root CA | Plaintext |
| `firmware_serverkey.pem` | HN8145X rootfs HiLink | TLS server private key | Encrypted |
| `firmware_servercert.pem` | HN8145X rootfs HiLink | TLS server certificate | Plaintext |
| `firmware_root.pem` | HN8145X rootfs HiLink | Root CA | Plaintext |
| `firmware_app_cert.crt` | HN8145X rootfs `/etc/app_cert.crt` | Huawei Product CA chain | Plaintext |
| `nand_ec_key_1.pem` / `.der` | NAND dump vol_9 (UBIFS) | **DECRYPTED** EC private key | Plaintext (PolarSSLTest library test key) |
| `nand_ec_key_2.pem` / `.der` | NAND dump vol_9 (UBIFS) | **DECRYPTED** EC private key | Plaintext (PolarSSLTest library test key) |
| `nand_encrypted_key_*.pem` | NAND dump vol_9 (UBIFS) | RSA/EC private keys | Encrypted (passphrase in hw_ctree.xml, device-specific) |

## Encryption Details

### `firmware_prvt.key` / `nand_encrypted_key_*.pem` (RSA)
```
DEK-Info: AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9
Key derivation: EVP_BytesToKey(MD5, passphrase, salt=IV[:8], iter=1)
```
The passphrase is stored encrypted in `/mnt/jffs2/hw_ctree.xml` as `certprvtPassword`.
It is **unique per device** and derived from the device eFuse OTP — cannot be recovered offline.

### `nand_ec_key_1.pem` / `nand_ec_key_2.pem` (EC, DECRYPTED)
```
DEK-Info: DES-EDE3-CBC,307EAB469933D64E
Passphrase: PolarSSLTest
```
These are **PolarSSL/mbedTLS library test keys** embedded in the UBIFS filesystem test data.
They are NOT device TLS keys. The passphrase `PolarSSLTest` is stored in plaintext
immediately before the key in the UBIFS image (`vol_9 +0x4715a6`).

## How to Decrypt the RSA Keys (requires live device)

```bash
# 1. Get the passphrase from the running device (root shell)
xmltool get InternetGatewayDevice.X_HW_CertInfo.certprvtPassword

# 2. Decrypt
openssl rsa -in firmware_prvt.key -passin pass:<passphrase> -out firmware_prvt_dec.key

# 3. Verify
openssl rsa -in firmware_prvt_dec.key -check -noout
```

## Analysis Tool

Run the full NAND corruption analysis and extraction:
```bash
python3 tools/nand_fw_disasm.py --dump <NAND.BIN> --out nand_disasm/
```
