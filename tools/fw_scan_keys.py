#!/usr/bin/env python3
"""
fw_scan_keys.py - Extract and analyze Huawei ONT firmware keys and certificates.

Clones realfirmware-net, extracts SquashFS rootfs from all HWNP firmware packages,
scans all binaries and libraries for keys, certificates, passphrases, and AES key
material. Saves PEM + DER files and writes a summary to keys/found_keys.txt.

Key findings:
  - PolarSSL/mbedTLS test keys in libpolarssl.so use passphrase "PolarSSLTest"
  - Hardcoded AES-128 key "Df7!ui%s9(lmV1L8" in aescrypt2 (CTOOL_GetKeyChipStr fallback)
  - firmware/etc/wap/prvt.key and plugprvt.key are KMC-derived (runtime-only)
  - HG8145X6-10 HWNP encrypted packages use AEST-like format with eFuse-derived KMC key

Encrypted HWNP (V500R022+ "hzs%" magic) payload layout:
  0x000-0x05f  Outer HWNP cleartext header
  0x060-0x11f  Zero padding
  0x120-0x3ff  Cleartext partition descriptor table
  0x400-0x45f  Item table entry 0:
               [0x00] type(4) id(4) ver(4) SHA1_of_payload(20) stride(4)
               [0x20] payload_size(4) timestamp(4) version_str(20)
               [0x50] IV(16) = pre-ciphertext nonce
  0x460-...    AES-256-CBC encrypted payload (key from KMC domain-0 + eFuse chip ID)
  EOF-56       Cleartext trailer: product_code("CHS"), build_date, internal_ID("H801EPBA")

CANNOT decrypt statically: key is eFuse-bound (unique per device).
WORKAROUND: chroot into extracted HG8145V5 rootfs with empty /mnt/jffs2/kmc_store_A/B
            files and run aescrypt2 — only works for hw_ctree.xml (AEST format), NOT
            for HWNP packages whose key chain requires the upgrade subsystem.
"""

import os
import re
import sys
import struct
import hashlib
import subprocess
import math
from collections import Counter
from pathlib import Path

# ── output dirs ────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR  = REPO_ROOT / "keys"
EXTRACTED = KEYS_DIR  / "extracted"
KEYS_TXT  = KEYS_DIR  / "found_keys.txt"
KEYS_DIR.mkdir(exist_ok=True)
EXTRACTED.mkdir(exist_ok=True)

REAL_FW_DIR = Path("/tmp/realfirmware-net")
EXTRACT_DIR = Path("/tmp/fw_scan_tmp")

# Passphrases to try on encrypted PEM keys (ordered by likelihood)
PASSPHRASES = [
    b"PolarSSLTest",   # confirmed: decrypts PolarSSL/mbedTLS embedded test keys
    b"polarssl",
    b"test",
    b"password",
    b"server",
    b"client",
    b"admin",
    b"huawei",
    None,              # no password (unencrypted key)
]

# ── helpers ────────────────────────────────────────────────────────────────────
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def md5hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def find_pem_blocks(data: bytes):
    """Yield (offset, pem_type, pem_bytes) for each PEM block found in binary data."""
    pos = 0
    while pos < len(data):
        start = data.find(b"-----BEGIN ", pos)
        if start == -1:
            break
        eh = data.find(b"-----", start + 11)
        if eh == -1:
            pos = start + 1
            continue
        ptype = data[start + 11 : eh].decode("ascii", "replace").strip()
        end_m = f"-----END {ptype}-----".encode()
        ep = data.find(end_m, eh)
        if ep == -1:
            pos = start + 1
            continue
        yield start, ptype, data[start : ep + len(end_m)]
        pos = ep + len(end_m)


def try_load_pem_key(pem_bytes: bytes):
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError:
        return None, None
    for pw in PASSPHRASES:
        try:
            k = load_pem_private_key(pem_bytes, password=pw)
            return k, pw
        except Exception:
            pass
    return None, None


def save_key_files(key_obj, base_name: str) -> str:
    """Save key as plaintext PEM + DER, return info string."""
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption)
        pem = key_obj.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        der = key_obj.private_bytes(
            Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        (EXTRACTED / f"{base_name}.pem").write_bytes(pem)
        (EXTRACTED / f"{base_name}.der").write_bytes(der)
        try:
            pub_nums = key_obj.public_key().public_numbers()
            return f"RSA-{key_obj.key_size}bit e={pub_nums.e} n={hex(pub_nums.n)[:48]}..."
        except Exception:
            return type(key_obj).__name__
    except Exception as ex:
        return f"save_error={ex}"


# ── firmware discovery ─────────────────────────────────────────────────────────
def clone_repo():
    if REAL_FW_DIR.exists():
        print(f"[INFO] {REAL_FW_DIR} already present, skipping clone")
        return
    print("[INFO] Cloning realfirmware-net …")
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/Uaemextop/realfirmware-net.git",
         str(REAL_FW_DIR)],
        check=True,
    )


def find_huawei_bins():
    """Return all Huawei HWNP firmware .bin files (skipping ZTE / Ping)."""
    skip = {"ZTE", "F660", "F670", "F680", "Ping", "FOlt"}
    result = []
    for p in sorted(REAL_FW_DIR.rglob("*.bin"),
                    key=lambda x: x.stat().st_size, reverse=True):
        if p.stat().st_size < 5 * 1024 * 1024:
            continue
        if any(s in str(p) for s in skip):
            continue
        try:
            magic = p.read_bytes()[:4]
        except Exception:
            continue
        if magic == b"HWNP":
            result.append(p)
    return result


# ── rootfs extraction ──────────────────────────────────────────────────────────
def extract_squashfs(fw_path: Path, tag: str) -> "Path | None":
    """Extract the largest SquashFS rootfs found in a whwh-format HWNP package."""
    out = EXTRACT_DIR / tag / "rootfs"
    if (out / "lib").exists():
        return out

    data = fw_path.read_bytes()
    best_off = best_size = 0
    off = 0
    while True:
        i = data.find(b"whwh", off)
        if i == -1:
            break
        sqsh_off = i + 0x94
        if sqsh_off + 4 > len(data):
            off = i + 1
            continue
        if data[sqsh_off : sqsh_off + 4] in (b"hsqs", b"sqsh"):
            try:
                sqsh_size = struct.unpack_from(">I", data, sqsh_off + 0x28)[0]
            except Exception:
                sqsh_size = 0
            if sqsh_size > best_size:
                best_off, best_size = sqsh_off, sqsh_size
        off = i + 4

    if best_off == 0:
        return None

    tmp = Path(f"/tmp/{tag}_rootfs.squashfs")
    tmp.write_bytes(data[best_off : best_off + best_size + 65536])
    out.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["unsquashfs", "-no-xattrs", "-ignore-errors", "-d", str(out), str(tmp)],
        capture_output=True, timeout=180,
    )
    tmp.unlink(missing_ok=True)
    if r.returncode not in (0, 1) or not out.exists():
        print(f"  [WARN] unsquashfs rc={r.returncode}")
        return None
    return out


# ── scan one rootfs ────────────────────────────────────────────────────────────
def scan_rootfs(rootfs: Path, fw_name: str, all_lines: list):
    lines = [f"\n### {fw_name} ###"]
    seen = set()

    for p in sorted(rootfs.rglob("*")):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except Exception:
            continue

        h = md5hex(data)
        if h in seen:
            continue
        seen.add(h)
        rel = str(p.relative_to(rootfs))

        # ── PEM blocks ─────────────────────────────────────────────────────────
        if b"-----BEGIN" in data:
            for offset, ptype, block in find_pem_blocks(data):
                bname = re.sub(r"[^A-Za-z0-9._-]", "_",
                               f"{fw_name}_{p.name}_{offset:07x}_{ptype.replace(' ','_')}")

                if "PRIVATE" in ptype.upper():
                    key_obj, pw = try_load_pem_key(block)
                    pw_str = repr(pw)
                    if key_obj is not None:
                        info = save_key_files(key_obj, bname + "_PLAIN")
                        lines.append(
                            f"[PRIVATE_KEY] src={rel}:0x{offset:x} "
                            f"type={ptype!r} pw={pw_str} {info}")
                    else:
                        dek = re.search(rb"DEK-Info: ([^\n\r]+)", block)
                        dek_s = (dek.group(1).decode("ascii", "replace")
                                 if dek else "none")
                        bk = md5hex(block)
                        if bk not in seen:
                            seen.add(bk)
                            (EXTRACTED / f"{bname}_ENCRYPTED.pem").write_bytes(block)
                        lines.append(
                            f"[PRIVATE_KEY_ENCRYPTED] src={rel}:0x{offset:x} "
                            f"type={ptype!r} DEK={dek_s}")

                elif ("CERTIFICATE" in ptype.upper()
                      and "REQUEST" not in ptype.upper()):
                    try:
                        from cryptography.x509 import load_pem_x509_certificate
                        cert = load_pem_x509_certificate(block)
                        subj = cert.subject.rfc4514_string()
                        bk = md5hex(block)
                        if bk not in seen:
                            seen.add(bk)
                            (EXTRACTED / f"{bname}.pem").write_bytes(block)
                        lines.append(
                            f"[CERT] src={rel}:0x{offset:x} subj={subj!r}")
                    except Exception:
                        pass

        # ── DER-format X.509 certificates ─────────────────────────────────────
        elif len(data) > 8 and data[:2] == b"\x30\x82" and b"BEGIN" not in data:
            try:
                from cryptography.x509 import load_der_x509_certificate
                from cryptography.hazmat.primitives.serialization import Encoding
                cert = load_der_x509_certificate(data)
                subj = cert.subject.rfc4514_string()
                bname = re.sub(r"[^A-Za-z0-9._-]", "_",
                               f"{fw_name}_{p.name}_cert")
                bk = md5hex(data)
                if bk not in seen:
                    seen.add(bk)
                    (EXTRACTED / f"{bname}.pem").write_bytes(
                        cert.public_bytes(Encoding.PEM))
                lines.append(f"[CERT_DER] src={rel} subj={subj!r}")
            except Exception:
                pass

        # ── Scan key binaries for hardcoded strings / blobs ────────────────────
        if (p.suffix in ("", ".so") or p.name in ("aescrypt2", "cfgtool")
                and len(data) < 20 * 1024 * 1024):
            if b"KEY" in data.upper() or b"AES" in data.upper():
                for m in re.finditer(rb"[ -~]{8,64}", data):
                    s = m.group().decode()
                    if any(kw in s.lower() for kw in
                           ["key", "passw", "secret", "aes", "kmc",
                            "chip", "default", "fallback"]):
                        line = (f"[HARDCODED_STR] "
                                f"{rel}:0x{m.start():x} {s!r}")
                        if line not in lines:
                            lines.append(line)

    all_lines.extend(lines)
    return len(lines) - 1


# ── analyse encrypted HWNP (V500R022+) ────────────────────────────────────────
def analyse_encrypted_hwnp(fw_path: Path, fw_name: str, all_lines: list):
    """
    Document the structure of an encrypted HWNP package.
    These files contain the magic 0x25737a68 ("hzs%") at offset 0x10.
    The AES-256-CBC payload key is derived at runtime from:
        KMC domain-0 work-key  (stored in /etc/wap/kmc_store_A/B)
        + HW_CTOOL_GetKeyChipStr()  (eFuse chip-specific key)
    Without physical device access the payload CANNOT be decrypted statically.
    """
    try:
        data = fw_path.read_bytes()
    except Exception:
        return
    if data[:4] != b"HWNP" or b"whwh" in data:
        return

    magic10 = struct.unpack_from("<I", data, 0x10)[0]
    if magic10 != 0x25737a68:
        return

    item_sha1    = data[0x40C:0x420]
    item_version = data[0x42C:0x444].split(b"\x00")[0].decode("ascii", "replace")
    payload_size = struct.unpack_from("<I", data, 0x424)[0]
    payload_iv   = data[0x450:0x460]
    trailer      = data[-56:]

    lines = [
        f"\n### {fw_name} (ENCRYPTED HWNP V500R022+) ###",
        f"[HWNP_ENC] file={fw_path.name} total_size={len(data)}",
        f"  version     = {item_version!r}",
        f"  item_sha1   = {item_sha1.hex()}  (SHA-1 of ciphertext)",
        f"  payload_iv  = {payload_iv.hex()}  (AES-CBC IV, 16 bytes before ciphertext)",
        f"  payload_size= {payload_size}",
        f"  trailer_hex = {trailer.hex()}",
        f"  product_id  = {re.sub(rb'[^\\x20-\\x7e]', b'.', trailer).decode()!r}",
        "  NOTE: payload is AES-256-CBC encrypted.",
        "        Key = KMC_domain0_work_key XOR CTOOL_GetKeyChipStr(eFuse_ID)",
        "        Cannot be recovered without physical device access.",
        "  WORKAROUND: All 3 ISP variants (TOTAL/MEGACABLE/TIGO) are byte-for-byte",
        "              identical — single product key; try on a live device via",
        "              'aescrypt2 1 payload.bin out.bin' in chroot.",
    ]
    all_lines.extend(lines)


# ── main ───────────────────────────────────────────────────────────────────────
def main():
    clone_repo()

    all_lines = [
        "# ============================================================",
        "# Huawei ONT Firmware – Key & Certificate Extraction Report",
        "# ============================================================",
        "#",
        "# PASSPHRASE FINDING:",
        "#   'PolarSSLTest' successfully decrypts the embedded PolarSSL",
        "#   test-suite RSA and EC private keys found in libpolarssl.so",
        "#   (R019C10SPC310B002, offset 0x6db60 and 0x6efe8).",
        "#",
        "# HARDCODED AES KEY:",
        "#   aescrypt2 binary contains fallback key string:",
        "#   'Df7!ui%s9(lmV1L8' (16 bytes, AES-128)",
        "#   Used by HW_CTOOL_GetKeyChipStr when no chip-specific data",
        "#   is available.  NOT sufficient alone to decrypt HWNP packages.",
        "#",
        "# ENCRYPTED FIRMWARE (HG8145X6-10 MEGACABLE/TOTAL/TIGO):",
        "#   HWNP magic 'hzs%' at 0x10 indicates V500R022+ encrypted format.",
        "#   All three ISP variants are byte-for-byte identical (same firmware,",
        "#   same AES-CBC key+IV, just different outer header).  The encryption",
        "#   key is bound to the device eFuse and cannot be recovered statically.",
        "#",
        "# PRIVATE KEYS (etc/wap/prvt.key, plugprvt.key):",
        "#   Encrypted with a passphrase derived at runtime by the KMC subsystem",
        "#   (HW_KMC_GetAppointKey -> PBKDF2 -> mbedTLS).  Unknown offline.",
        "#",
    ]

    fw_bins = find_huawei_bins()
    print(f"[INFO] Found {len(fw_bins)} Huawei HWNP firmware files")

    for fw_path in fw_bins:
        parts = fw_path.relative_to(REAL_FW_DIR).parts
        tag = re.sub(r"[^A-Za-z0-9._-]", "_",
                     "_".join(parts[:-1]) + "_" + fw_path.stem)[:80]
        print(f"\n[FW] {fw_path.relative_to(REAL_FW_DIR)}")

        rootfs = extract_squashfs(fw_path, tag)
        if rootfs:
            print(f"  rootfs → {rootfs}")
            n = scan_rootfs(rootfs, tag, all_lines)
            print(f"  scanned → {n} findings")
        else:
            print("  no whwh rootfs — checking for encrypted HWNP format")
            analyse_encrypted_hwnp(fw_path, tag, all_lines)

    KEYS_TXT.write_text("\n".join(all_lines) + "\n")
    print(f"\n[DONE] {len(all_lines)} lines → {KEYS_TXT}")
    files = list(EXTRACTED.iterdir())
    print(f"[DONE] {len(files)} files extracted → {EXTRACTED}/")


if __name__ == "__main__":
    main()
