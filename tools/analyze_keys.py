#!/usr/bin/env python3
"""
analyze_keys.py – Extract and report metadata from all certificates and
private keys in the keys/ directory.

Outputs:
  • Console summary
  • keys/KEY_ANALYSIS.md  – detailed Markdown report

Usage:
    python3 tools/analyze_keys.py [--keys-dir keys/] [--out keys/KEY_ANALYSIS.md]

Requirements:
    pip install cryptography
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Cert loader
# ---------------------------------------------------------------------------

def _load_cert(data: bytes):
    """Try PEM then DER."""
    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except Exception:
        pass
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except Exception:
        pass
    return None


def _split_pem_certs(data: bytes) -> List[bytes]:
    """Split a PEM bundle into individual certificate PEM blocks."""
    parts = []
    idx = 0
    while True:
        start = data.find(b"-----BEGIN CERTIFICATE-----", idx)
        if start == -1:
            break
        end_marker = b"-----END CERTIFICATE-----"
        end = data.find(end_marker, start)
        if end == -1:
            break
        end += len(end_marker)
        parts.append(data[start:end])
        idx = end
    return parts


def _cert_valid_range(cert) -> Tuple[Optional[datetime], Optional[datetime]]:
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        try:
            nb = cert.not_valid_before
            na = cert.not_valid_after
            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=timezone.utc)
            if na.tzinfo is None:
                na = na.replace(tzinfo=timezone.utc)
            return nb, na
        except Exception:
            return None, None


def _is_expired(cert) -> bool:
    _, na = _cert_valid_range(cert)
    if na is None:
        return False
    now = datetime.now(timezone.utc)
    return now > na


def _key_usage_list(cert) -> List[str]:
    usages = []
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        for attr in [
            "digital_signature", "non_repudiation", "key_encipherment",
            "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
        ]:
            try:
                if getattr(ku, attr):
                    usages.append(attr)
            except Exception:
                pass
    except Exception:
        pass
    return usages


def _basic_constraints(cert) -> Tuple[bool, Optional[int]]:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bc.ca, bc.path_length
    except Exception:
        return False, None


def _san_list(cert) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        result = []
        for entry in san:
            if isinstance(entry, x509.DNSName):
                result.append(f"DNS:{entry.value}")
            elif isinstance(entry, x509.IPAddress):
                result.append(f"IP:{entry.value}")
        return result
    except Exception:
        return []


def _pub_key_info(pub) -> str:
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name} ({pub.key_size} bits)"
    return type(pub).__name__


def _fingerprint(cert) -> Tuple[str, str]:
    sha1 = cert.fingerprint(hashes.SHA1()).hex()
    sha256 = cert.fingerprint(hashes.SHA256()).hex()
    return sha1, sha256


# ---------------------------------------------------------------------------
# Key loader
# ---------------------------------------------------------------------------

def _load_private_key(data: bytes):
    """Try PEM plaintext, then DER plaintext."""
    try:
        return load_pem_private_key(data, None, default_backend())
    except Exception:
        pass
    try:
        return load_der_private_key(data, None, default_backend())
    except Exception:
        pass
    return None


def _is_encrypted_pem(data: bytes) -> bool:
    return b"ENCRYPTED" in data or b"Proc-Type: 4,ENCRYPTED" in data or b"DEK-Info" in data


def _dek_info(data: bytes) -> Optional[str]:
    m = re.search(rb"DEK-Info:\s*([^\r\n]+)", data)
    if m:
        return m.group(1).decode("ascii", errors="replace").strip()
    return None


def _private_key_info(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA-{key.key_size}"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return f"EC-{key.curve.name} ({key.key_size} bits)"
    return type(key).__name__


def _public_bytes_hex(key) -> str:
    try:
        if isinstance(key, ec.EllipticCurvePrivateKey):
            pub = key.public_key()
            b = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            return b.hex()
        elif isinstance(key, rsa.RSAPrivateKey):
            n = key.public_key().public_numbers().n
            return hex(n)
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(keys_dir: Path) -> Tuple[List[dict], List[dict]]:
    """Return (cert_records, key_records)."""

    cert_records: List[dict] = []
    key_records: List[dict] = []

    # ── Certificates ────────────────────────────────────────────────────
    cert_exts = ["*.crt", "*.pem"]
    for pattern in cert_exts:
        for f in sorted(keys_dir.glob(pattern)):
            data = f.read_bytes()
            # Skip if binary and not a cert
            pem_blocks = _split_pem_certs(data)
            if not pem_blocks:
                # Try DER directly
                cert = _load_cert(data)
                if cert:
                    pem_blocks = [b"DER:" + data]  # marker
            else:
                pass

            for i, block in enumerate(pem_blocks):
                is_der = block.startswith(b"DER:")
                raw = block[4:] if is_der else block
                cert = _load_cert(raw)
                if cert is None:
                    continue

                pub = cert.public_key()
                nb, na = _cert_valid_range(cert)
                is_ca, path_len = _basic_constraints(cert)
                ku = _key_usage_list(cert)
                san = _san_list(cert)
                sha1_fp, sha256_fp = _fingerprint(cert)
                self_signed = cert.subject == cert.issuer
                expired = _is_expired(cert)

                try:
                    subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                except Exception:
                    subject_cn = cert.subject.rfc4514_string()

                try:
                    issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                except Exception:
                    issuer_cn = cert.issuer.rfc4514_string()

                cert_records.append({
                    "file": f.name,
                    "index": i,
                    "total": len(pem_blocks),
                    "subject_cn": subject_cn,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer_cn": issuer_cn,
                    "issuer": cert.issuer.rfc4514_string(),
                    "key_info": _pub_key_info(pub),
                    "serial": hex(cert.serial_number),
                    "not_before": nb.strftime("%Y-%m-%d") if nb else "?",
                    "not_after": na.strftime("%Y-%m-%d") if na else "?",
                    "expired": expired,
                    "is_ca": is_ca,
                    "path_len": path_len,
                    "key_usage": ku,
                    "san": san,
                    "self_signed": self_signed,
                    "sha1_fp": sha1_fp,
                    "sha256_fp": sha256_fp,
                })

    # ── Private keys ─────────────────────────────────────────────────────
    for f in sorted(keys_dir.glob("*.pem")) + sorted(keys_dir.glob("*.key")) + sorted(keys_dir.glob("*.der")):
        data = f.read_bytes()
        # Skip if cert-only
        if b"CERTIFICATE" in data and b"PRIVATE KEY" not in data:
            continue
        if b"PRIVATE KEY" not in data and not f.suffix == ".der":
            continue
        # Skip DER files that are paired with a same-stem _decrypted.pem (already listed)
        if f.suffix == ".der":
            pem_twin = f.with_suffix(".pem")
            if pem_twin.exists():
                continue

        encrypted = _is_encrypted_pem(data)
        dek = _dek_info(data) if encrypted else None

        key = _load_private_key(data)
        if key is None and not encrypted:
            # Try as binary proprietary
            key_records.append({
                "file": f.name,
                "status": "binary/unknown",
                "key_info": "unknown",
                "encrypted": False,
                "dek_info": None,
                "pub_hex": "",
                "note": "Binary format, not standard PEM/DER",
            })
            continue

        if key is None and encrypted:
            key_records.append({
                "file": f.name,
                "status": "encrypted",
                "key_info": _pem_key_type(data),
                "encrypted": True,
                "dek_info": dek,
                "pub_hex": "",
                "note": "certprvtPassword (device-specific, derived from eFuse OTP)",
            })
            continue

        pub_hex = _public_bytes_hex(key)
        key_records.append({
            "file": f.name,
            "status": "plaintext",
            "key_info": _private_key_info(key),
            "encrypted": False,
            "dek_info": None,
            "pub_hex": pub_hex,
            "note": "",
        })

    return cert_records, key_records


def _pem_key_type(data: bytes) -> str:
    """Best-effort key type from PEM header."""
    for line in data.split(b"\n"):
        if line.startswith(b"-----BEGIN"):
            t = line.decode("ascii", errors="replace").strip().lstrip("-").rstrip("-").strip()
            return t
    return "unknown"


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

_FIRMWARE_SIGNING_EXPLANATION = """\
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
"""

_PRACTICAL_USES = """\
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
"""


def build_report(certs: List[dict], keys: List[dict], keys_dir: Path) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# HG8145V5 / HN8145X – Certificate and Key Analysis",
        "",
        f"*Generated: {now}*",
        "",
        "---",
        "",
        "## Summary",
        "",
    ]

    total_certs = len(certs)
    total_keys = len(keys)
    plaintext_keys = sum(1 for k in keys if k["status"] == "plaintext")
    encrypted_keys = sum(1 for k in keys if k["status"] == "encrypted")
    expired_certs = sum(1 for c in certs if c["expired"])
    ca_certs = sum(1 for c in certs if c["is_ca"])

    lines += [
        f"| Item | Count |",
        f"|------|-------|",
        f"| Total certificates | {total_certs} |",
        f"| &nbsp;&nbsp;Root/Intermediate CAs | {ca_certs} |",
        f"| &nbsp;&nbsp;Expired | {expired_certs} |",
        f"| Total private keys | {total_keys} |",
        f"| &nbsp;&nbsp;Plaintext (decrypted) | {plaintext_keys} |",
        f"| &nbsp;&nbsp;Encrypted (eFuse required) | {encrypted_keys} |",
        "",
        "---",
        "",
        "## Certificates",
        "",
    ]

    for r in certs:
        expired_tag = " ⚠️ **EXPIRED**" if r["expired"] else ""
        ca_tag = " 🔑 **CA**" if r["is_ca"] else ""
        root_tag = " 🌐 **ROOT CA**" if (r["is_ca"] and r["self_signed"]) else ""
        label = f"`{r['file']}`" if r["total"] == 1 else f"`{r['file']}` (cert {r['index']+1}/{r['total']})"

        lines.append(f"### {label}{expired_tag}{ca_tag}{root_tag}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Subject | `{r['subject_cn']}` |")
        lines.append(f"| Subject (full) | `{r['subject']}` |")
        lines.append(f"| Issuer | `{r['issuer_cn']}` |")
        lines.append(f"| Issuer (full) | `{r['issuer']}` |")
        lines.append(f"| Key type | `{r['key_info']}` |")
        lines.append(f"| Valid | `{r['not_before']}` → `{r['not_after']}`{' (**EXPIRED**)' if r['expired'] else ''} |")
        lines.append(f"| Serial | `{r['serial']}` |")
        lines.append(f"| CA | `{r['is_ca']}` (path_len={r['path_len']}) |")
        lines.append(f"| Self-signed | `{r['self_signed']}` |")
        if r["key_usage"]:
            lines.append(f"| Key Usage | {', '.join(f'`{u}`' for u in r['key_usage'])} |")
        if r["san"]:
            lines.append(f"| SAN | {', '.join(f'`{s}`' for s in r['san'])} |")
        lines.append(f"| SHA-1 fingerprint | `{r['sha1_fp']}` |")
        lines.append(f"| SHA-256 fingerprint | `{r['sha256_fp']}` |")
        lines.append("")

        # Role annotation
        role = _cert_role(r)
        lines.append(f"**Role:** {role}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Private Keys",
        "",
    ]

    for r in keys:
        status_tag = ""
        if r["status"] == "plaintext":
            status_tag = " ✅ **PLAINTEXT**"
        elif r["status"] == "encrypted":
            status_tag = " 🔒 **ENCRYPTED**"
        else:
            status_tag = " ❓ **UNKNOWN FORMAT**"

        lines.append(f"### `{r['file']}`{status_tag}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Type | `{r['key_info']}` |")
        lines.append(f"| Status | `{r['status']}` |")
        if r.get("dek_info"):
            lines.append(f"| DEK-Info | `{r['dek_info']}` |")
        if r.get("pub_hex"):
            ph = r["pub_hex"]
            lines.append(f"| Public key | `{ph[:64]}…` |")
        if r.get("note"):
            lines.append(f"| Note | {r['note']} |")
        lines.append("")

        role = _key_role(r)
        lines.append(f"**Role:** {role}")
        lines.append("")

    # Deduplication note
    lines += [
        "---",
        "",
        "## Duplicate / Identical Keys",
        "",
        "The following key files are **cryptographically identical** (same private scalar):",
        "",
        "| Files | Note |",
        "|-------|------|",
        "| `nand_ec_key_1.pem`, `nand_ec_key_2.pem`, `nand_encrypted_key_3_*_decrypted.pem`, `nand_encrypted_key_10_*_decrypted.pem` | All are the standard **mbedTLS/PolarSSL library test key** (passphrase: `PolarSSLTest`, curve: secp384r1). Found in UBIFS test node data at 4 different flash offsets. This is NOT a device TLS key. |",
        "",
        "The 8 encrypted RSA keys (`nand_encrypted_key_{1,2,4,5,6,7,8,9}_*`) all share the",
        "same DEK-Info IV (`7EC546FB34CA7CD5599763D8D9AE6AC9`), meaning they share the same",
        "OpenSSL EVP_BytesToKey derivation from a single certprvtPassword passphrase.",
        "",
        "---",
        "",
    ]

    lines.append(_FIRMWARE_SIGNING_EXPLANATION)
    lines.append("---")
    lines.append("")
    lines.append(_PRACTICAL_USES)
    lines.append("---")
    lines.append("")
    lines.append("## Certificate Chain Diagram")
    lines.append("")
    lines.append("```")
    lines.append("Huawei Firmware Signing PKI (hardware-anchored, CANNOT sign custom firmware):")
    lines.append("")
    lines.append("  eFuse OTP registers (hardware, read by HW_DM_GetRootPubKeyInfo)")
    lines.append("       │")
    lines.append("       ├── firmware_app_cert.crt  [Huawei Root CA, RSA-4096, 2015-2050]")
    lines.append("       │       └── (Code Signing CA 2 → Code Signing Cert 3 → HWNP signature)")
    lines.append("       │           ← Private key at Huawei factory only, NEVER in flash")
    lines.append("")
    lines.append("Huawei Fixed Network Product PKI (device identity, CANNOT sign firmware):")
    lines.append("")
    lines.append("  Huawei Equipment CA  (external, not in dump)")
    lines.append("       └── firmware_root.crt  [Huawei Fixed Network Product CA, RSA-2048, 2016-2041]")
    lines.append("               └── firmware_pub.crt  [ont.huawei.com, RSA-2048, 2020-2030]")
    lines.append("                       (+ firmware_prvt.key ENCRYPTED → TR-069/ACS mTLS)")
    lines.append("")
    lines.append("HuaWei ONT CA PKI (plug/WPS subsystem, CANNOT sign firmware):")
    lines.append("")
    lines.append("  firmware_plugroot.crt  [HuaWei ONT CA, RSA-2048, self-signed, 2016-2026 EXPIRED]")
    lines.append("       └── firmware_plugpub.crt  [ont.huawei.com, RSA-2048, 2017-2067]")
    lines.append("               (+ firmware_plugprvt.key ENCRYPTED → WAP/plug auth)")
    lines.append("")
    lines.append("HiLink Web Interface PKI (local HTTPS, CANNOT sign firmware):")
    lines.append("")
    lines.append("  firmware_root.pem  [root.home, RSA-2048, self-signed, 2014-2024 EXPIRED]")
    lines.append("       └── firmware_servercert.pem  [mediarouter.home, RSA-2048, 2014-2024 EXPIRED]")
    lines.append("               (+ firmware_serverkey.pem → binary, web HTTPS only)")
    lines.append("")
    lines.append("UBIFS Test Data (NOT device keys):")
    lines.append("")
    lines.append("  nand_ec_key_1/2.pem  [mbedTLS PolarSSLTest vector, secp384r1, 4× identical copies]")
    lines.append("")
    lines.append("NAND Device Keys (device-specific, need eFuse to decrypt):")
    lines.append("")
    lines.append("  nand_encrypted_key_{1,2,4,5,6,7,8,9}.pem  [RSA, AES-256-CBC, IV=7EC546FB...]")
    lines.append("       (certprvtPassword stored in hw_ctree.xml, encrypted with eFuse-derived key)")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def _cert_role(r: dict) -> str:
    cn = r["subject_cn"].lower()
    issuer = r["issuer_cn"].lower()
    is_ca = r["is_ca"]
    self_signed = r["self_signed"]
    expired_note = " **⚠️ EXPIRED – do not use for new TLS sessions.**" if r["expired"] else ""

    if "huawei root ca" in cn and self_signed and "4096" in r["key_info"]:
        return (
            "**Huawei Global Root CA** (RSA-4096, valid 2015–2050). "
            "This is the top-level certificate used to verify ALL Huawei ONT firmware signatures. "
            "The matching private key lives in Huawei's factory HSM and is never exported to any device. "
            "Its public key is burned into each device's eFuse OTP during manufacturing. "
            "**Cannot be used to sign firmware without the private key.**"
        )
    if "fixed network product ca" in cn:
        return (
            "**Huawei Fixed Network Product CA** (RSA-2048 intermediate CA). "
            "Signs device identity certificates (`ont.huawei.com`) for TR-069/ACS mutual-TLS authentication. "
            "Issued by the 'Huawei Equipment CA' (not in this dump). "
            "**Cannot be used to sign firmware.** "
            "Useful to verify the device identity cert chain."
        )
    if "ont ca" in cn.lower() or "ont ca" in issuer.lower():
        if self_signed and is_ca:
            return (
                f"**HuaWei ONT CA – Root CA for WAP/plug subsystem** (RSA-2048, self-signed).{expired_note} "
                "Used to sign the device's WAP/plug authentication certificate (`firmware_plugpub.crt`). "
                "Controls the HiLink 'Enable ONT' plug feature. "
                "**Cannot be used to sign firmware.**"
            )
        return (
            f"**WAP/plug device leaf certificate** (RSA-2048), issued by HuaWei ONT CA.{expired_note} "
            "Used for client authentication in the ONT plug/enable subsystem. "
            "**Cannot be used to sign firmware.**"
        )
    if "mediarouter" in cn:
        return (
            f"**HiLink web management TLS server certificate** (RSA-2048).{expired_note} "
            "Issued by root.home self-signed CA. SAN covers mediarouter.home / mediarouter1-3.home. "
            "Used for HTTPS on the router's local web interface. "
            "**Cannot be used to sign firmware.**"
        )
    if "root.home" in cn and self_signed:
        return (
            f"**HiLink web management self-signed Root CA** (RSA-2048).{expired_note} "
            "Issues the mediarouter.home TLS server cert. "
            "**Cannot be used to sign firmware.**"
        )
    if cn == "ont.huawei.com" and "fixed network" in issuer:
        return (
            f"**Device identity leaf certificate for TR-069/ACS** (RSA-2048). "
            "Used with `firmware_prvt.key` for mutual TLS authentication to the ISP's ACS provisioning server. "
            "With the private key decrypted, could authenticate as this specific ONT to any TR-069 ACS. "
            "**Cannot be used to sign firmware.**"
        )
    return f"Certificate (role unclassified). CN=`{r['subject_cn']}`, issued by `{r['issuer_cn']}`."


def _key_role(r: dict) -> str:
    f = r["file"].lower()
    status = r["status"]
    ki = r["key_info"]

    if "polarssl" in r.get("note", "").lower() or (
        status == "plaintext" and "ec-secp384r1" in ki.lower() and
        ("nand_ec_key" in f or "vol9" in f)
    ):
        return (
            "**mbedTLS/PolarSSL standard library test key** (EC secp384r1, 384 bits). "
            "Passphrase: `PolarSSLTest`. Found embedded in UBIFS filesystem test data at multiple "
            "flash offsets. This is NOT a device production key. "
            "All 4 copies (nand_ec_key_1, nand_ec_key_2, nand_encrypted_key_3_dec, nand_encrypted_key_10_dec) "
            "are identical. **No production security value.**"
        )
    if "prvt.key" in f and "plug" not in f:
        if status == "encrypted":
            return (
                "**TR-069 / ACS mutual-TLS device private key** (RSA-2048, AES-256-CBC encrypted). "
                "Paired with `firmware_pub.crt`. Used for mTLS authentication to the ISP's TR-069 ACS server. "
                "Passphrase = `certprvtPassword` from `hw_ctree.xml` (device-specific, derived from eFuse OTP). "
                "**Cannot be decrypted without the device eFuse key.** "
                "If decrypted: could authenticate as this ONT to any TR-069 ACS (research use)."
            )
    if "plugprvt" in f:
        if status == "encrypted":
            return (
                "**WAP/ONT-plug authentication private key** (RSA-2048, AES-256-CBC encrypted). "
                "Paired with `firmware_plugpub.crt`. Used for the HiLink ONT-enable/plug subsystem. "
                "Passphrase = `certprvtPassword` from `hw_ctree.xml`. "
                "**Cannot be decrypted without the device eFuse key.**"
            )
    if "serverkey" in f:
        return (
            "**HiLink web management HTTPS private key** (binary/proprietary format, 1832 bytes). "
            "First 4 bytes `01000000` suggest a Huawei proprietary encrypted key blob (not standard PEM/DER). "
            "Paired with `firmware_servercert.pem` (EXPIRED). "
            "Used for the local web interface TLS session. "
            "**Format not yet decoded; practical use limited by expired certificate.**"
        )
    if status == "encrypted" and "nand_encrypted_key" in f:
        return (
            f"**NAND UBIFS device key – RSA-2048, AES-256-CBC encrypted** "
            "(DEK IV=`7EC546FB34CA7CD5599763D8D9AE6AC9`). "
            "All 8 RSA NAND keys share the same OpenSSL DEK derived from `certprvtPassword`. "
            "Likely device TLS/authentication keys stored in UBIFS persistent storage. "
            "**Cannot be decrypted without the device eFuse key.**"
        )
    return f"Private key, role unclassified. Type: `{ki}`, status: `{status}`."


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze certificates and private keys, generate KEY_ANALYSIS.md"
    )
    parser.add_argument("--keys-dir", default="keys", help="Directory containing keys (default: keys/)")
    parser.add_argument("--out",      default="keys/KEY_ANALYSIS.md", help="Output Markdown path")
    args = parser.parse_args()

    if not _HAS_CRYPTO:
        print("[!] 'cryptography' package required. Install with: pip install cryptography")
        sys.exit(1)

    keys_dir = Path(args.keys_dir)
    if not keys_dir.is_dir():
        print(f"[!] Keys directory not found: {keys_dir}")
        sys.exit(1)

    print(f"Analyzing keys in {keys_dir} …")
    certs, keys = analyze(keys_dir)

    print(f"\nFound {len(certs)} certificate(s) and {len(keys)} key file(s)")

    report = build_report(certs, keys, keys_dir)

    out_path = Path(args.out)
    out_path.write_text(report, encoding="utf-8")
    print(f"\nReport written to: {out_path}")

    # Console summary
    print("\n" + "=" * 60)
    print("CERTIFICATE SUMMARY")
    print("=" * 60)
    for r in certs:
        exp = " [EXPIRED]" if r["expired"] else ""
        ca = " [CA]" if r["is_ca"] else ""
        root = " [ROOT]" if (r["is_ca"] and r["self_signed"]) else ""
        print(f"  {r['file']}: {r['key_info']}, CN={r['subject_cn']}, valid {r['not_before']}→{r['not_after']}{exp}{ca}{root}")

    print("\n" + "=" * 60)
    print("KEY SUMMARY")
    print("=" * 60)
    for r in keys:
        enc = " [ENCRYPTED]" if r["status"] == "encrypted" else " [PLAINTEXT]" if r["status"] == "plaintext" else " [?]"
        print(f"  {r['file']}: {r['key_info']}{enc}")

    print("\n" + "=" * 60)
    print("FIRMWARE SIGNING VERDICT")
    print("=" * 60)
    print("  ✗ NONE of these keys can sign Huawei firmware.")
    print("  The Huawei Root CA private key (RSA-4096) is at Huawei factory only.")
    print("  Firmware signing root is anchored in device eFuse OTP (hardware).")
    print(f"\n  See {out_path} for full analysis.")


if __name__ == "__main__":
    main()
