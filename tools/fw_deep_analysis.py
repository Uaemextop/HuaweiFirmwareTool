#!/usr/bin/env python3
"""
fw_deep_analysis.py - Deep analysis of ALL Huawei firmware from realfirmware-net.

1. Clones realfirmware-net (if not present)
2. Extracts ALL Huawei firmware binaries (HWNP + tar/tar.gz)
3. Decompiles ARM libraries via `strings` + capstone for hardcoded passphrases/keys
4. Tries PolarSSLTest + other passphrases on encrypted PEM keys
5. Downloads and analyzes NAND dump for eFuse_ID chain
6. Appends all findings to keys/found_keys.txt
"""

import os, re, sys, struct, hashlib, subprocess, math, shutil, tarfile
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR  = REPO_ROOT / "keys"
EXTRACTED = KEYS_DIR / "extracted"
KEYS_TXT  = KEYS_DIR / "found_keys.txt"
KEYS_DIR.mkdir(exist_ok=True)
EXTRACTED.mkdir(exist_ok=True)

REAL_FW_DIR = Path("/tmp/realfirmware-net")
TMP         = Path("/tmp/fw_deep_tmp")
TMP.mkdir(exist_ok=True)

# All passphrases to try
PASSPHRASES = [
    "PolarSSLTest", "polarssl", "test", "password", "server", "client",
    "admin", "huawei", "Huawei@123", "root", "12345678", "mbedtls",
    "TestCA", "TestServer", "TestClient", "changeme",
]

LOG_LINES = []

def log(msg):
    print(msg)
    LOG_LINES.append(msg)

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, **kw)

def md5(data):
    return hashlib.md5(data).hexdigest()

def entropy(data):
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

# ──────────────────────────────────────────────────────────────────────────────
# 1. Clone firmware repo
# ──────────────────────────────────────────────────────────────────────────────
def ensure_fw_repo():
    if REAL_FW_DIR.exists():
        log(f"[+] realfirmware-net already cloned at {REAL_FW_DIR}")
        return
    log("[*] Cloning realfirmware-net...")
    r = run(["git","clone","--depth=1","https://github.com/Uaemextop/realfirmware-net.git",
             str(REAL_FW_DIR)])
    if r.returncode == 0:
        log("[+] Clone successful")
    else:
        log(f"[!] Clone failed: {r.stderr.decode(errors='replace')[:200]}")

# ──────────────────────────────────────────────────────────────────────────────
# 2. Collect ALL Huawei firmware files
# ──────────────────────────────────────────────────────────────────────────────
def collect_huawei_fw():
    """Return list of all firmware files under Huawei-* directories."""
    fws = []
    for p in REAL_FW_DIR.iterdir():
        if not p.is_dir(): continue
        name = p.name.lower()
        if not ("huawei" in name or "eg8" in name or "hg8" in name or "hs8" in name):
            continue
        for f in p.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".bin",".tar",".gz",".img",""):
                fws.append(f)
    return sorted(fws)

# ──────────────────────────────────────────────────────────────────────────────
# 3. Parse HWNP header
# ──────────────────────────────────────────────────────────────────────────────
HWNP_MAGIC = b"HWNP"
WHWH_MAGIC = b"whwh"
SQSH_MAGIC = b"hsqs"  # little-endian squashfs

def analyze_hwnp(fw_path: Path):
    """Return dict with HWNP metadata or None if not HWNP."""
    data = fw_path.read_bytes()
    if not data.startswith(HWNP_MAGIC):
        return None
    result = {"path": fw_path, "size": len(data), "encrypted": False}
    # Check for "hzs%" magic at offset 0x10 (V500R022 encrypted)
    if data[0x10:0x14] == b"hzs%":
        result["encrypted"] = True
        result["note"] = "V500R022+ KMC/eFuse encrypted payload"
        # Read trailer for product info
        trailer = data[-200:]
        for s in [b"H801", b"H802", b"MA5", b"EG81", b"HG81"]:
            idx = trailer.find(s)
            if idx >= 0:
                t = trailer[idx:idx+30]
                result["product"] = t.rstrip(b"\x00").decode(errors="replace")
                break
    else:
        result["encrypted"] = False
    return result

def find_squashfs_offsets(data: bytes):
    """Find all SquashFS signatures in data."""
    offsets = []
    pos = 0
    while True:
        pos = data.find(SQSH_MAGIC, pos)
        if pos < 0: break
        offsets.append(pos)
        pos += 4
    return offsets

def extract_rootfs_from_hwnp(fw_path: Path, out_dir: Path):
    """Extract SquashFS rootfs from unencrypted HWNP firmware."""
    data = fw_path.read_bytes()
    sqfs_offsets = find_squashfs_offsets(data)
    if not sqfs_offsets:
        return None

    # Find whwh blocks
    whwh_offsets = []
    pos = 0
    while True:
        pos = data.find(WHWH_MAGIC, pos)
        if pos < 0: break
        whwh_offsets.append(pos)
        pos += 4

    # Use last SquashFS (usually rootfs)
    sqfs_off = sqfs_offsets[-1]
    if len(sqfs_offsets) > 1:
        # Prefer one that comes after a whwh header with "rootfs" label
        for wo in whwh_offsets:
            label = data[wo+8:wo+40]
            if b"rootfs" in label:
                # SquashFS is at wo + 0x94
                candidate = wo + 0x94
                if data[candidate:candidate+4] == SQSH_MAGIC:
                    sqfs_off = candidate
                    break
                # Also try wo+4 aligned scan
                for s in find_squashfs_offsets(data[wo:wo+0x200]):
                    sqfs_off = wo + s
                    break

    # Extract sqfs to tmp file
    sqfs_data = data[sqfs_off:]
    sqfs_file = TMP / f"{fw_path.stem}_rootfs.sqfs"
    sqfs_file.write_bytes(sqfs_data)

    # Extract with unsquashfs
    rootfs_out = out_dir / fw_path.stem
    if rootfs_out.exists():
        shutil.rmtree(rootfs_out)
    rootfs_out.mkdir(parents=True, exist_ok=True)

    r = run(["unsquashfs", "-d", str(rootfs_out), "-no-xattrs", "-ignore-errors",
             str(sqfs_file)], timeout=120)
    sqfs_file.unlink(missing_ok=True)
    if r.returncode == 0 or (rootfs_out / "bin").exists():
        return rootfs_out
    return None

# ──────────────────────────────────────────────────────────────────────────────
# 4. Extract tar/tar.gz archives
# ──────────────────────────────────────────────────────────────────────────────
def extract_tar(fw_path: Path):
    """Extract tar/tar.gz and return extracted directory."""
    out = TMP / f"tar_{fw_path.stem}"
    out.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fw_path) as t:
            t.extractall(out)
        return out
    except Exception as e:
        return None

# ──────────────────────────────────────────────────────────────────────────────
# 5. Scan binary for strings/passphrases
# ──────────────────────────────────────────────────────────────────────────────
PASS_PATTERNS = [
    (rb"passphrase", 60),
    (rb"password",   50),
    (rb"passwd",     50),
    (rb"PolarSSL",   60),
    (rb"mbedtls",    50),
    (rb"AES.key",    60),
    (rb"secret",     50),
    (rb"private",    50),
    (rb"cipher",     50),
    (rb"PBKDF2",     60),
    (rb"KMC",        40),
    (rb"kmc",        40),
    (rb"eFuse",      70),
    (rb"efuse",      70),
    (rb"chip.id",    60),
    (rb"ChipID",     60),
    (rb"chipid",     60),
    (rb"GetKey",     40),
    (rb"GetAppointKey",  80),
    (rb"CTOOL_GetKey",   80),
    (rb"Df7!ui%s9", 100),    # known AES-128 fallback key
    (rb"PolarSSLTest", 100), # known PolarSSL test passphrase
]

INTERESTING_STRINGS_RE = re.compile(
    rb"(?:passphrase|password|passwd|secret|cipher|PBKDF|KMC|eFuse|ChipID|Df7!|PolarSSL"
    rb"|GetAppointKey|work.key|aescrypt|encrypt|decrypt|prvt|kmc_store|wap.key|telnet|ssh)",
    re.IGNORECASE
)

def scan_binary_for_keys(bin_path: Path):
    """Run strings on binary and look for key-related content."""
    findings = []
    try:
        r = run(["strings", "-n", "6", str(bin_path)], timeout=30)
        lines = r.stdout.decode(errors="replace").splitlines()
        for line in lines:
            if INTERESTING_STRINGS_RE.search(line.encode()):
                findings.append(line.strip())
    except Exception as e:
        pass
    return findings

def scan_library_for_hardcoded_keys(lib_path: Path):
    """Scan ARM ELF library for hardcoded AES keys and passphrases."""
    findings = []
    try:
        data = lib_path.read_bytes()
    except:
        return findings

    # Look for PEM blocks
    pem_re = re.compile(b"-----BEGIN ([A-Z ]+)-----")
    for m in pem_re.finditer(data):
        findings.append(f"  PEM block: {m.group(1).decode()} at offset {hex(m.start())}")

    # Look for 16/32-byte printable strings that could be AES keys
    aes_re = re.compile(rb"[\x20-\x7e]{16,48}")
    for m in aes_re.finditer(data):
        s = m.group()
        # Filter: must look like a passphrase/key (mixed chars, not a path/function name)
        if (any(c < 0x30 or c > 0x7a for c in s) and
            len(set(s)) > 6 and
            not s.startswith(b"/") and
            not s.startswith(b"lib") and
            not b".so" in s and
            not b"_hw_" in s and
            not b"Failed" in s):
            decoded = s.decode(errors="replace")
            if any(p in s for p in [b"Pass", b"pass", b"Key", b"key", b"AES", b"aes",
                                     b"Polar", b"polar", b"Test", b"test", b"Secret"]):
                findings.append(f"  Candidate key/pass: {decoded!r} at {hex(m.start())}")

    # Run strings
    str_findings = scan_binary_for_keys(lib_path)
    findings.extend(f"  strings: {s}" for s in str_findings[:30])

    return findings

# ──────────────────────────────────────────────────────────────────────────────
# 6. Try passphrases on PEM key
# ──────────────────────────────────────────────────────────────────────────────
def try_decrypt_pem(pem_path: Path):
    """Try all known passphrases on a PEM key. Returns (passphrase, der_bytes) or None."""
    for pp in PASSPHRASES:
        r = run(["openssl", "pkey", "-in", str(pem_path),
                 "-passin", f"pass:{pp}", "-outform", "DER"],
                timeout=10)
        if r.returncode == 0 and len(r.stdout) > 50:
            return (pp, r.stdout)
        # Also try openssl rsa (legacy RSA PEM)
        r2 = run(["openssl", "rsa", "-in", str(pem_path),
                  "-passin", f"pass:{pp}", "-outform", "DER"],
                 timeout=10)
        if r2.returncode == 0 and len(r2.stdout) > 50:
            return (pp, r2.stdout)
        # Try EC
        r3 = run(["openssl", "ec", "-in", str(pem_path),
                  "-passin", f"pass:{pp}", "-outform", "DER"],
                 timeout=10)
        if r3.returncode == 0 and len(r3.stdout) > 10:
            return (pp, r3.stdout)
    return None

# ──────────────────────────────────────────────────────────────────────────────
# 7. Copy important rootfs files to keys/extracted
# ──────────────────────────────────────────────────────────────────────────────
IMPORTANT_FILES = [
    "etc/wap/prvt.key", "etc/wap/plugprvt.key", "etc/wap/pub.crt",
    "etc/wap/plugpub.crt", "etc/wap/root.crt", "etc/wap/plugroot.crt",
    "etc/wap/su_pub_key", "etc/wap/kmc_store_A", "etc/wap/kmc_store_B",
    "etc/wap/hw_aes_tree.xml", "etc/wap/hw_default_ctree.xml",
    "etc/wap/hw_ctree.xml", "etc/wap/hw_flashcfg.xml", "etc/wap/hw_boardinfo",
    "etc/app_cert.crt",
    "etc/wap/hilinkcert/root.pem", "etc/wap/hilinkcert/servercert.pem",
    "etc/wap/cwmp/clientcert.pem", "etc/wap/cwmp/clientkey.pem",
    "bin/aescrypt2", "bin/cfgtool",
]

def copy_important_files(rootfs: Path, label: str, findings: list):
    dest = EXTRACTED / label
    dest.mkdir(parents=True, exist_ok=True)
    for rel in IMPORTANT_FILES:
        src = rootfs / rel
        if src.exists():
            d = dest / Path(rel).parent
            d.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, d / src.name)
            findings.append(f"  copied: {rel}")

# ──────────────────────────────────────────────────────────────────────────────
# 8. Deep ARM library analysis
# ──────────────────────────────────────────────────────────────────────────────
TARGET_LIBS = [
    "lib/libpolarssl.so", "lib/libhw_ssp_basic.so", "lib/libhw_ssp_ssl.so",
    "lib/libhw_swm_dll.so", "lib/libhw_swm_product.so", "lib/libhw_kmc.so",
    "lib/libmbedcrypto.so.0", "lib/libmbedtls.so", "lib/libcyassl.so.5.0.5",
    "lib/libwlan_aes_crypto.so",
    "bin/aescrypt2", "bin/cfgtool",
]

def analyze_rootfs_libs(rootfs: Path, label: str, all_findings: list):
    """Analyze all key ARM libraries in an extracted rootfs."""
    log(f"\n  [*] Analyzing ARM libraries in {label}...")
    found_any = False
    for rel in TARGET_LIBS:
        lib = rootfs / rel
        if not lib.exists(): continue
        found_any = True
        log(f"    [lib] {rel} ({lib.stat().st_size} bytes)")
        findings = scan_library_for_hardcoded_keys(lib)
        for f in findings[:20]:
            log(f"      {f}")
            all_findings.append(f"{label}/{rel}: {f}")
    if not found_any:
        log(f"    (no target libraries found)")

# ──────────────────────────────────────────────────────────────────────────────
# 9. Download + analyze NAND dump
# ──────────────────────────────────────────────────────────────────────────────
NAND_URL = ("https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/"
            "V2/Dump_LOCK_HG8145v5-20_r020.s212_DS35Q1GA.x4.@WSON8_nonECC.BIN")
NAND_PATH = Path("/tmp/nand_dump.bin")

def download_nand():
    if NAND_PATH.exists() and NAND_PATH.stat().st_size > 10_000_000:
        log(f"[+] NAND dump already present ({NAND_PATH.stat().st_size//1024//1024} MB)")
        return True
    log("[*] Downloading NAND dump (~132 MB)...")
    r = run(["wget", "-q", "-O", str(NAND_PATH), NAND_URL], timeout=300)
    if r.returncode == 0 and NAND_PATH.exists():
        log(f"[+] NAND dump downloaded ({NAND_PATH.stat().st_size//1024//1024} MB)")
        return True
    log(f"[!] NAND download failed: {r.stderr.decode(errors='replace')[:200]}")
    return False

EFUSE_PATTERNS = [
    (rb"eFuse", 40),
    (rb"efuse", 40),
    (rb"ChipID", 30),
    (rb"chip_id", 30),
    (rb"chipId",  30),
    (rb"CHIP_ID", 30),
    (rb"SN:", 20),
    (rb"BoardSN", 20),
    (rb"PatchID", 20),
    (rb"LUT_KEY", 30),
    (rb"ROOT_KEY", 30),
    (rb"root_key", 30),
]

def scan_nand_for_efuse(nand_path: Path, findings: list):
    """Scan NAND dump for eFuse chain data."""
    log(f"[*] Scanning NAND dump for eFuse/chipID markers...")
    try:
        # Use nand_dump_analyze.py if it exists
        nda = REPO_ROOT / "tools" / "nand_dump_analyze.py"
        if nda.exists():
            r = run(["python3", str(nda), str(nand_path)], timeout=300)
            out = r.stdout.decode(errors="replace")
            log(out[:3000])
            findings.append("=== NAND dump analysis ===")
            findings.append(out[:3000])
            return

        # Fallback: manual scan
        data = nand_path.read_bytes()
        page_size = 2112  # DS35Q1GA: 2048 + 64 OOB
        clean_pages = []

        log(f"[*] NAND size: {len(data)//1024//1024} MB, scanning for eFuse markers...")

        # Scan for strings across the dump
        r = run(["strings", "-n", "6", str(nand_path)], timeout=120)
        strings_out = r.stdout.decode(errors="replace").splitlines()
        efuse_strings = [l for l in strings_out
                         if any(p.decode() in l for p,_ in EFUSE_PATTERNS[:6])]
        for s in efuse_strings[:50]:
            log(f"  eFuse string: {s!r}")
            findings.append(f"NAND eFuse string: {s!r}")

        # Look for eFuse magic pattern 0xEF_USE or similar
        for pat in [b"eFuse", b"efuse", b"EFUSE", b"EF_USE"]:
            pos = 0
            while True:
                pos = data.find(pat, pos)
                if pos < 0: break
                ctx = data[max(0,pos-16):pos+64]
                log(f"  [eFuse] offset 0x{pos:x}: {ctx.hex()}")
                findings.append(f"NAND eFuse at 0x{pos:x}: {ctx.hex()}")
                pos += len(pat)
                if len(findings) > 200: break

        # Look for UBI superblocks
        ubi_magic = b"UBI#"
        pos = 0
        ubi_count = 0
        while True:
            pos = data.find(ubi_magic, pos)
            if pos < 0: break
            ubi_count += 1
            pos += 4
        log(f"[*] UBI superblocks found: {ubi_count}")
        findings.append(f"NAND UBI superblocks: {ubi_count}")

        # Look for PEM keys in NAND
        pem_re = re.compile(b"-----BEGIN ([A-Z ]+)-----")
        for m in pem_re.finditer(data):
            off = m.start()
            block_end = data.find(b"-----END", off)
            if block_end > 0:
                pem_data = data[off:block_end+30]
                key_type = m.group(1).decode(errors="replace")
                log(f"  [PEM] {key_type} at NAND offset 0x{off:x}")
                findings.append(f"NAND PEM {key_type} at offset 0x{off:x}")
                # Save it
                safe_type = re.sub(r"[^A-Za-z0-9_]", "_", key_type)
                out_pem = KEYS_DIR / f"nand2_pem_{safe_type}_{hex(off)}.pem"
                if not out_pem.exists():
                    out_pem.write_bytes(pem_data + b"\n-----END " + m.group(1) + b"-----\n")

    except Exception as e:
        log(f"[!] NAND scan error: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# 10. Main
# ──────────────────────────────────────────────────────────────────────────────
def main():
    log("=" * 72)
    log("Huawei Firmware Deep Analysis")
    log("=" * 72)

    ensure_fw_repo()

    all_findings = []
    fw_files = collect_huawei_fw()
    log(f"\n[*] Found {len(fw_files)} Huawei firmware files")

    processed = set()
    # Track already-extracted rootfs dirs
    already_extracted = {d.name for d in EXTRACTED.iterdir() if d.is_dir()}

    for fw in fw_files:
        suffix = fw.suffix.lower()
        fw_id  = fw.stem[:60]

        log(f"\n{'─'*60}")
        log(f"[FW] {fw.relative_to(REAL_FW_DIR)}")
        log(f"     Size: {fw.stat().st_size:,} bytes | Suffix: {suffix}")

        # ── tar/tar.gz ─────────────────────────────────────
        if suffix in (".tar", ".gz") or "tar" in fw.name.lower():
            log(f"  [tar] Extracting archive...")
            out = extract_tar(fw)
            if out:
                log(f"  [+] Extracted tar to {out}")
                all_findings.append(f"{fw.name}: tar extracted to {out}")
                # Scan extracted files
                for f in out.rglob("*"):
                    if f.is_file():
                        findings = scan_binary_for_keys(f)
                        for item in findings[:5]:
                            all_findings.append(f"  tar/{f.name}: {item}")
            continue

        # ── non-.bin files ──────────────────────────────────
        if suffix not in (".bin", ""):
            continue

        data = fw.read_bytes()
        if len(data) < 100:
            log(f"  [skip] too small ({len(data)} bytes)")
            continue

        magic4 = data[:4]

        # ── HWNP firmware ──────────────────────────────────
        if magic4 == HWNP_MAGIC:
            hwnp = analyze_hwnp(fw)
            if hwnp["encrypted"]:
                log(f"  [HWNP-ENC] Encrypted V500R022 package – {hwnp.get('product','unknown')}")
                log(f"  Note: Key is eFuse-bound (KMC domain-0 + chip ID). Cannot decrypt statically.")
                # Try to extract anyway (for structure analysis)
                sqfs_offsets = find_squashfs_offsets(data)
                if sqfs_offsets:
                    log(f"  Found {len(sqfs_offsets)} SquashFS offset(s): {[hex(o) for o in sqfs_offsets[:5]]}")
                # Analyse header strings
                header_strings = []
                s_re = re.compile(rb"[\x20-\x7e]{8,}")
                for m in s_re.finditer(data[:0x500]):
                    header_strings.append(m.group().decode(errors="replace"))
                if header_strings:
                    log(f"  Header strings: {header_strings[:10]}")
                    all_findings.append(f"{fw.name} HWNP-ENC header: {header_strings[:5]}")
                continue

            # Unencrypted HWNP
            log(f"  [HWNP] Unencrypted, attempting rootfs extraction...")
            label = fw.parent.parent.parent.name + "_" + fw.stem
            label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:80]
            if label in already_extracted:
                log(f"  [skip] already extracted: {label}")
                rootfs = EXTRACTED / label
            else:
                out_dir = EXTRACTED
                rootfs = extract_rootfs_from_hwnp(fw, out_dir)
                if rootfs:
                    log(f"  [+] Rootfs extracted to {rootfs}")
                    already_extracted.add(label)
                    all_findings.append(f"{fw.name}: rootfs extracted to {rootfs}")
                else:
                    log(f"  [!] Extraction failed or no SquashFS found")
                    all_findings.append(f"{fw.name}: extraction failed")
                    continue

            # Copy important files
            copy_important_files(rootfs, label, all_findings)
            # Analyze ARM libraries
            analyze_rootfs_libs(rootfs, label, all_findings)

        # ── Small unlock scripts / non-HWNP ────────────────
        else:
            log(f"  [BIN] magic={magic4.hex()} – scanning for embedded keys...")
            findings = scan_binary_for_keys(fw)
            if findings:
                log(f"  Found {len(findings)} interesting strings")
                for f in findings[:10]:
                    log(f"    {f}")
                    all_findings.append(f"{fw.name}: {f}")

    # ── Try PolarSSLTest + other passphrases on all extracted PEM keys ──────
    log(f"\n{'='*60}")
    log("[*] Trying passphrases on all encrypted PEM keys...")
    for pem_path in sorted(KEYS_DIR.rglob("*ENCRYPTED*.pem")):
        result = try_decrypt_pem(pem_path)
        if result:
            pp, der_bytes = result
            log(f"  [SUCCESS] {pem_path.name} decrypted with passphrase: {pp!r}")
            all_findings.append(f"DECRYPTED: {pem_path.name} passphrase={pp!r}")
            der_out = pem_path.with_suffix(".decrypted.der")
            der_out.write_bytes(der_bytes)
            pem_out = pem_path.with_suffix(".decrypted.pem")
            run(["openssl", "pkey", "-inform", "DER", "-in", str(der_out),
                 "-out", str(pem_out)])

    # ── NAND dump analysis ──────────────────────────────────────────────────
    log(f"\n{'='*60}")
    log("[*] NAND dump analysis for eFuse_ID...")
    if download_nand():
        scan_nand_for_efuse(NAND_PATH, all_findings)
    else:
        log("[!] Skipping NAND analysis (download failed)")

    # ── Write findings ──────────────────────────────────────────────────────
    log(f"\n{'='*60}")
    with open(KEYS_TXT, "a") as f:
        f.write("\n\n" + "=" * 72 + "\n")
        f.write("DEEP ANALYSIS RESULTS\n")
        f.write("=" * 72 + "\n")
        for line in all_findings:
            f.write(line + "\n")
    log(f"[+] Appended {len(all_findings)} findings to {KEYS_TXT}")
    log(f"[DONE] Deep analysis complete.")

if __name__ == "__main__":
    main()
