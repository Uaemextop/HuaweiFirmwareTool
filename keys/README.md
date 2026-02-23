# Extracted Huawei Public Keys

These keys were extracted from the ONT firmware upgrade tool (ONT_V100R002C00SPC253.exe)
and from the HG8145V5 firmware signinfo section.

## Certificate Chain

```
Huawei Root CA (self-signed)
├── Huawei Code Signing Certificate Authority
├── Huawei Code Signing Certificate Authority 2
│   └── Transmission & Access Product Line Code Signing Certificate 3
├── Huawei Timestamp Certificate Authority
└── Huawei Timestamp Certificate Authority 2
```

## Files

- `huawei_pubkey_0.pem` - `huawei_pubkey_5.pem`: RSA-2048 public keys extracted from
  the ONT upgrade tool and firmware signinfo blocks
- `huawei_code_signing_cert.pem`: Huawei Transmission & Access Product Line Code Signing
  Certificate 3 (the actual firmware signer certificate)
- `huawei_ca_cert.pem`: Huawei Code Signing Certificate Authority 2

## Usage

To verify a firmware signature using the extracted public key:
```bash
./hw_verify -d unpack -k keys/huawei_code_signing_cert.pem -i unpack/var/signature
```

## Note

These are **public keys only**. The corresponding private keys are held by Huawei
and are not embedded in any publicly available binary.

For custom firmware repacking, generate your own key pair:
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```
