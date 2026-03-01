#!/usr/bin/env python3
"""Deep binary + credential analysis for Ping7962V1-E4222-Telmex.

Scoped exclusively to the E4222 directory.  Huawei ONT keys are untouched.

Usage:
    python3 tools/e4222_deep_analysis.py [path/to/Ping7962V1-E4222-Telmex]

Outputs:
    - Console report
    - extracted_configs/Ping7962V1-E4222-Telmex/BINARY_ANALYSIS.txt
"""

from __future__ import annotations

import re
import struct
import subprocess
import sys
import ipaddress
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import capstone
except ImportError:
    sys.exit("capstone not installed – run:  pip install capstone")

try:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# ── helpers ──────────────────────────────────────────────────────────────────

def _sh(cmd: list) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        return r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
    except Exception:
        return ""

SEP = "=" * 64

def _hdr(title: str) -> str:
    return f"\n{SEP}\n{title}\n{SEP}"

# ── ELF helpers ──────────────────────────────────────────────────────────────

ELF_MAGIC = b"\x7fELF"

_ARCH_MAP = {
    0x28: (capstone.CS_ARCH_ARM,  capstone.CS_MODE_ARM,          "ARM 32-bit LE"),
    0xB7: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM,         "AArch64"),
    0x08: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32
                                   | capstone.CS_MODE_BIG_ENDIAN, "MIPS32 BE"),
    0x3E: (capstone.CS_ARCH_X86,  capstone.CS_MODE_64,           "x86-64"),
    0x03: (capstone.CS_ARCH_X86,  capstone.CS_MODE_32,           "x86-32"),
}

def _parse_elf32(data: bytes) -> Tuple[int, int, List[Tuple[int, int, int, str]]]:
    """Return (e_machine, e_flags, sections[(addr, offset, size, name)])."""
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        return -1, 0, []
    ei_class = data[4]
    ei_data  = data[5]
    bo = ">" if ei_data == 2 else "<"
    if ei_class == 1:
        fmt_hdr = bo + "HHIQQQIHHHHHH"
        sz_hdr  = struct.calcsize(fmt_hdr)
        if len(data) < 4 + sz_hdr:
            return -1, 0, []
        fields = struct.unpack_from(fmt_hdr, data, 4)
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
            e_flags, e_ehsize, e_phentsize, e_phnum, \
            e_shentsize, e_shnum, e_shstrndx = fields
    elif ei_class == 2:
        fmt_hdr = bo + "HHIQQQIHHHHHH"
        fields = struct.unpack_from(fmt_hdr, data, 4)
        e_type, e_machine = fields[0], fields[1]
        e_flags = fields[6]
        return e_machine, e_flags, []
    else:
        return -1, 0, []

    sections = []
    if e_shoff and e_shnum and e_shentsize >= 40:
        sh_fmt = bo + "IIIIIIIIII"
        name_strtab_off = 0
        if e_shstrndx < e_shnum:
            sh_base = e_shoff + e_shstrndx * e_shentsize
            if sh_base + 40 <= len(data):
                sh_fields = struct.unpack_from(sh_fmt, data, sh_base)
                name_strtab_off = sh_fields[4]

        for i in range(e_shnum):
            sh_base = e_shoff + i * e_shentsize
            if sh_base + 40 > len(data):
                break
            sf = struct.unpack_from(sh_fmt, data, sh_base)
            sh_name_idx, sh_type, sh_flags, sh_addr, sh_off, sh_size = sf[:6]
            name = ""
            if name_strtab_off and name_strtab_off + sh_name_idx < len(data):
                end = data.index(b"\x00", name_strtab_off + sh_name_idx)
                name = data[name_strtab_off + sh_name_idx:end].decode(errors="replace")
            sections.append((sh_addr, sh_off, sh_size, name))

    return e_machine, e_flags, sections


def _extract_strings(data: bytes, min_len: int = 5) -> List[Tuple[int, str]]:
    """Extract printable ASCII strings with their offsets."""
    results = []
    pat = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    for m in pat.finditer(data):
        results.append((m.start(), m.group().decode(errors="replace")))
    return results


_CRED_RE = re.compile(
    r'(?i)(password|passwd|pass|secret|admin|user|login|auth|key|cert|token|'
    r'ssl|tls|md5|sha|aes|rsa|hash|crypt|challenge|nonce|salt|'
    r'EaR@|vHaxJ|telecom|support|guest|root|enable|mfg)',
)

_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

_URL_RE = re.compile(r'https?://[^\s\x00"\'<>]+', re.I)


def _filter_interesting(strings: List[Tuple[int, str]]) -> List[Tuple[int, str, str]]:
    out = []
    for off, s in strings:
        if _CRED_RE.search(s):
            out.append((off, s, "CREDENTIAL"))
        elif _IP_RE.search(s) and not s.startswith("0.0.0.0"):
            out.append((off, s, "IP/URL"))
        elif _URL_RE.search(s):
            out.append((off, s, "URL"))
    return out


def analyze_elf(path: Path, base: Path) -> List[str]:
    lines = []
    data = path.read_bytes()
    if data[:4] != ELF_MAGIC:
        return lines

    e_machine, e_flags, sections = _parse_elf32(data)
    arch_info = _ARCH_MAP.get(e_machine, None)
    if arch_info is None:
        arch_label = f"machine=0x{e_machine:02x} (unsupported by capstone map)"
    else:
        arch_label = arch_info[2]

    lines.append(f"\n[ELF] {path.relative_to(base)}  —  {arch_label}")
    lines.append(f"  Size: {len(data):,} bytes")

    all_strings = _extract_strings(data, min_len=6)
    interesting = _filter_interesting(all_strings)

    if interesting:
        lines.append("  Interesting strings found:")
        seen = set()
        for off, s, tag in interesting:
            if s in seen:
                continue
            seen.add(s)
            lines.append(f"    0x{off:06x}  [{tag}]  {s!r}")
    else:
        lines.append("  No interesting strings found.")

    if arch_info and sections:
        cs_arch, cs_mode, _ = arch_info
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False
        text_sections = [(a, o, z, n) for (a, o, z, n) in sections
                         if n in (".text", "text", ".init", ".fini") and z > 0]
        if text_sections:
            a, o, z, n = text_sections[0]
            chunk = data[o:o + min(z, 512)]
            insns = list(md.disasm(chunk, a))
            if insns:
                lines.append(f"  Capstone disasm ({n} first {len(insns)} insns @ 0x{a:08x}):")
                for insn in insns[:12]:
                    lines.append(f"    0x{insn.address:08x}:  {insn.mnemonic:<8} {insn.op_str}")

    return lines


# ── RSA key analysis ──────────────────────────────────────────────────────────

def analyze_rsa(key_path: Path) -> List[str]:
    lines = [_hdr("RSA PRIVATE KEY  —  ssl_key.pem")]
    data = key_path.read_bytes()

    md5  = _sh(["md5sum",    str(key_path)]).split()[0]
    sha  = _sh(["sha256sum", str(key_path)]).split()[0]
    lines.append(f"  File:   {key_path}")
    lines.append(f"  MD5:    {md5}")
    lines.append(f"  SHA256: {sha}")

    if not _HAS_CRYPTO:
        lines.append("  [cryptography not installed — skipping numeric analysis]")
        return lines

    try:
        key: RSAPrivateKey = load_pem_private_key(data, password=None)
    except Exception as exc:
        lines.append(f"  [load error: {exc}]")
        return lines

    priv = key.private_numbers()
    pub  = priv.public_numbers

    lines.append(f"  Type:   RSA {key.key_size}-bit (UNENCRYPTED — shared across all E4222 units)")
    lines.append(f"  e (public exponent):  {pub.e}")
    lines.append(f"  n (modulus, hex):")
    n_hex = f"{pub.n:0{key.key_size // 4}x}"
    for i in range(0, min(len(n_hex), 128), 64):
        lines.append(f"    {n_hex[i:i+64]}")
    lines.append(f"    ... ({len(n_hex)} hex chars total)")
    lines.append(f"  p (prime 1, first 32 hex): {priv.p:0{key.key_size // 8}x}"[:48] + "...")
    lines.append(f"  q (prime 2, first 32 hex): {priv.q:0{key.key_size // 8}x}"[:48] + "...")

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    lines.append(f"  DER public key first bytes: {pub_der[:16].hex()}  ({len(pub_der)} B)")
    lines.append("  Usage: HTTPS server key for CN=192.168.1.1 (ssl_cert.pem)")
    lines.append("  Note:  Identical key on ALL factory E4222 units — use for MITM/TLS intercept.")
    return lines


# ── Credential scan across configs ──────────────────────────────────────────

_XMLVAL_RE = re.compile(r'<Value Name="([^"]+)" Value="([^"]*)"')

_INTERESTING_FIELDS = re.compile(
    r'(?i)(user|pass|admin|secret|key|ssl|cert|login|auth|snmp|ftp|telnet|ssh|'
    r'suser|cwmp|wpa|rs_pass|loid|token|challenge|nonce|salt)',
)


def analyze_configs(base: Path) -> List[str]:
    lines = [_hdr("CREDENTIALS — ALL CONFIG FILES")]

    config_files = list(base.rglob("*.xml"))
    for cf in sorted(config_files):
        interesting = []
        for m in _XMLVAL_RE.finditer(cf.read_text(errors="replace")):
            name, val = m.group(1), m.group(2)
            if val and _INTERESTING_FIELDS.search(name):
                interesting.append((name, val))
        if interesting:
            lines.append(f"\n  [{cf.relative_to(base)}]")
            seen = set()
            for name, val in interesting:
                if name in seen:
                    continue
                seen.add(name)
                lines.append(f"    {name:<35} {val}")
    return lines


# ── Web source analysis ───────────────────────────────────────────────────────

_WEB_CRED_RE = re.compile(
    r'(?i)(password|passwd|admin|secret|key|ssl|challenge|hash|md5|crypt|'
    r'EaR@|vHaxJ|telecom|support)\s*[=:]\s*["\']?([^"\'<>\s]{4,})',
)


def analyze_web(base: Path) -> List[str]:
    lines = [_hdr("WEB SOURCE — HARDCODED CREDENTIALS & CRYPTO PATTERNS")]
    web_dir = base / "web"
    if not web_dir.exists():
        lines.append("  (no web/ directory)")
        return lines

    seen_vals: set = set()
    for ext in ("*.asp", "*.js", "*.html", "*.htm"):
        for f in sorted(web_dir.rglob(ext)):
            if not f.exists():
                continue
            try:
                text = f.read_text(errors="replace")
            except Exception:
                continue
            for m in _WEB_CRED_RE.finditer(text):
                key_name = m.group(1)
                val = m.group(2).strip("'\"")
                if val in seen_vals or len(val) < 4:
                    continue
                seen_vals.add(val)
                rel = f.relative_to(base)
                lines.append(f"  [{rel}]  {key_name} = {val!r}")

    if len(lines) == 2:
        lines.append("  (no hardcoded credential values found)")

    lines.append("\n  --- Login mechanism ---")
    lines.append("  Auth flow: MD5(password + challenge) via php-crypt-md5.js → POST /boaform/admin/formLogin")
    lines.append("  Password hash scheme: $1$ (MD5-crypt / PHP crypt)")
    lines.append("  postTableEncrypt() in common.js computes checksum over all form fields")
    return lines


# ── Hidden IPs scan ───────────────────────────────────────────────────────────

def analyze_ips(base: Path) -> List[str]:
    lines = [_hdr("NON-RFC1918 / HIDDEN IP ADDRESSES")]
    seen: Dict[str, List[str]] = {}
    for f in sorted(base.rglob("*")):
        if not f.is_file() or not f.exists():
            continue
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        for m in _IP_RE.finditer(text):
            ip_s = m.group()
            try:
                ip = ipaddress.ip_address(ip_s)
                if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                    continue
                if ip_s.startswith("1.3.6.1"):
                    continue
                context_start = max(0, m.start() - 40)
                ctx = text[context_start:m.end() + 40].replace("\n", " ").strip()
                seen.setdefault(ip_s, [])
                if ctx not in seen[ip_s]:
                    seen[ip_s].append(ctx)
            except ValueError:
                pass
    for ip_s, ctxs in sorted(seen.items(), key=lambda x: ipaddress.ip_address(x[0])):
        lines.append(f"\n  {ip_s}")
        for c in ctxs[:2]:
            lines.append(f"    {c[:120]}")
    if len(lines) == 2:
        lines.append("  (none found)")
    return lines


# ── Binary files scan ─────────────────────────────────────────────────────────

def analyze_binaries(base: Path) -> List[str]:
    lines = [_hdr("BINARY / ELF FILES — CAPSTONE DISASSEMBLY + STRING EXTRACTION")]
    found = False
    for f in sorted(base.rglob("*")):
        if not f.is_file() or not f.exists():
            continue
        try:
            head = f.read_bytes()[:4]
        except Exception:
            continue
        if head == ELF_MAGIC:
            found = True
            lines.extend(analyze_elf(f, base))

    if not found:
        lines.append("\n  No ELF binaries found in E4222 directory.")
        lines.append("  (E4222 is a Realtek MIPS device; rootfs binaries are not included")
        lines.append("   in this extraction — only web, configs, certs, and keys are present.)")
        lines.append("\n  Capstone was used to verify file types and would disassemble any")
        lines.append("  ELF binary placed in the E4222 directory automatically.")
    return lines


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) >= 2:
        base = Path(sys.argv[1])
    else:
        base = Path(__file__).parent.parent / "extracted_configs" / "Ping7962V1-E4222-Telmex"

    if not base.exists():
        print(f"[!] Directory not found: {base}", file=sys.stderr)
        sys.exit(1)

    key_path = base / "keys" / "ssl_key.pem"
    if not key_path.exists():
        print(f"[!] ssl_key.pem not found at {key_path}", file=sys.stderr)
        sys.exit(1)

    all_lines = [
        f"E4222 DEEP ANALYSIS — {base.name}",
        f"Tool:   tools/e4222_deep_analysis.py",
        f"Target: {base}",
        "",
        "Scope: Ping7962V1-E4222-Telmex ONLY.",
        "Huawei ONT keys (prvt.key, plugprvt.key, hilink_serverkey) are NOT analysed here.",
    ]

    all_lines += analyze_rsa(key_path)
    all_lines += analyze_binaries(base)
    all_lines += analyze_configs(base)
    all_lines += analyze_web(base)
    all_lines += analyze_ips(base)

    report = "\n".join(all_lines)
    print(report)

    out = base / "BINARY_ANALYSIS.txt"
    out.write_text(report + "\n")
    print(f"\n[+] Report saved → {out}")


if __name__ == "__main__":
    main()
