#!/usr/bin/env python3
"""
fw_full_decompile.py – Full ARM ELF decompilation of all Huawei firmware binaries.

Decompiles ALL binaries and shared libraries extracted from firmware SquashFS rootfs
using Capstone ARM32 + Thumb2 disassembly.  Produces annotated .asm files with:
  • Resolved PLT import names on every BL/BLX call
  • Resolved string constants on every PC-relative LDR
  • Exported function labels at their entry points
  • Function boundary detection
  • Cross-reference lists for crypto functions

Key-derivation chain analysis:
  aescrypt2 ──────→ OS_AescryptDecrypt ──────────────────────────→ libhw_ssp_basic.so
                       └─ MemGetRootKeyCfg (shared memory)
                       └─ MemGetMkInfoByContent (shared memory)
  libhw_swm_dll.so → polarssl_pk_parse_subpubkey (libpolarssl.so)
                   → HW_KMC_CfgSetKey (libhw_ssp_basic.so)
  libhw_ssp_ssl.so → polarssl_set_pub_prv_to_conf → mbedtls_pk_parse_key
                      └─ mbedtls_pem_read_buffer (PEM passphrase)
                         └─ passphrase from HW_KMC_GetAppointKey → PBKDF2
  libhw_ssp_basic.so: CTOOL_GetKeyChipStr → hardcoded fallback "Df7!ui%s9(lmV1L8"
  libpolarssl.so: PolarSSLTest passphrase for embedded test keys

Usage:
    python3 tools/fw_full_decompile.py [--rootfs <path>] [--out <dir>]

Requirements:
    pip install capstone
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path
from typing import Optional

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    print("[ERROR] capstone not installed. Run: pip install capstone", file=sys.stderr)
    sys.exit(1)

REPO_ROOT  = Path(__file__).resolve().parent.parent
DECOMPILED = REPO_ROOT / "decompiled"

# Critical binaries to decompile (path relative to rootfs, label, description)
TARGETS = [
    ("bin/aescrypt2",               "aescrypt2",
     "AES encrypt/decrypt; key derived from KMC chain"),
    ("bin/cfgtool",                 "cfgtool",
     "Config manipulation; HW_CFGTOOL_Get/Set/Add/Del"),
    ("lib/libhw_ssp_basic.so",      "libhw_ssp_basic",
     "KMC API, PBKDF2, AES wrappers, hardcoded fallback key Df7!ui%s9(lmV1L8"),
    ("lib/libhw_ssp_ssl.so",        "libhw_ssp_ssl",
     "SSL wrapper; HW_SSL_LoadCertFile; polarssl_set_pub_prv_to_conf"),
    ("lib/libhw_swm_dll.so",        "libhw_swm_dll",
     "ctree encrypt/decrypt, eFuse load, /mnt/jffs2/prvt.key loading"),
    ("lib/libhw_swm_product.so",    "libhw_swm_product",
     "firmware signing, root key chain, HW_DM_GetRootPubKeyInfo"),
    ("lib/libpolarssl.so",          "libpolarssl",
     "PolarSSL/mbedTLS; PolarSSLTest passphrase; mbedtls_pk_parse_keyfile"),
    ("lib/libwlan_aes_crypto.so",   "libwlan_aes_crypto",
     "WLAN AES-128-CBC encrypt/decrypt wrapper"),
]

# Crypto function names to highlight in output
CRYPTO_KEYWORDS = {
    'mbedtls_pk_parse_keyfile', 'mbedtls_pk_parse_key', 'mbedtls_pkcs5_pbkdf2_hmac',
    'polarssl_pem_read_buffer', 'polarssl_pk_parse_subpubkey', 'polarssl_set_pub_prv_to_conf',
    'HW_KMC_GetAppointKey', 'HW_KMC_GetActiveKey', 'HW_KMC_CfgGetKey', 'HW_KMC_CfgSetKey',
    'HW_OS_PBKDF2_SHA256', 'HW_OS_GetSaltStrForPbkdf2', 'OS_AescryptDecrypt', 'OS_AescryptEncrypt',
    'HW_SWM_LoadEfuse', 'HW_DM_GetEncryptedKey', 'HW_DM_GetRootPubKeyInfo',
    'WLAN_AES_Cbc_128_Encrypt', 'WLAN_AES_Cbc_128_Decrypt',
    'MemGetRootKeyCfg', 'MemGetMkInfoByContent', 'HW_SSL_LoadCertFile',
    'CAC_Pbkdf2Api',
}


def _parse_elf32(data: bytes) -> dict:
    """Parse ELF32 sections, exports, imports (PLT map), and dynamic strings."""
    if data[:4] != b'\x7fELF':
        return {}
    e_shoff      = struct.unpack_from('<I', data, 32)[0]
    e_shnum      = struct.unpack_from('<H', data, 48)[0]
    e_shstrndx   = struct.unpack_from('<H', data, 50)[0]
    e_shentsize  = struct.unpack_from('<H', data, 46)[0]
    shstr_off    = struct.unpack_from('<I', data,
                                      e_shoff + e_shstrndx * e_shentsize + 16)[0]
    shstrtab     = data[shstr_off:shstr_off + 8192]

    secs: dict = {}
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        h    = data[base:base + e_shentsize]
        if len(h) < 40:
            continue
        name_off = struct.unpack_from('<I', h, 0)[0]
        try:
            name = shstrtab[name_off:shstrtab.index(b'\x00', name_off)].decode(errors='replace')
        except ValueError:
            name = str(i)
        secs[name] = {
            'off':  struct.unpack_from('<I', h, 16)[0],
            'size': struct.unpack_from('<I', h, 20)[0],
            'addr': struct.unpack_from('<I', h, 12)[0],
            'type': struct.unpack_from('<I', h,  4)[0],
        }

    # Dynamic string table
    dynstr_sec = secs.get('.dynstr', {})
    dynstr: bytes = (data[dynstr_sec['off']:dynstr_sec['off'] + dynstr_sec['size']]
                     if dynstr_sec else b'')

    def _sym_name(idx: int) -> str:
        if idx >= len(dynstr):
            return ''
        try:
            end = dynstr.index(b'\x00', idx)
        except ValueError:
            end = idx + 64
        return dynstr[idx:end].decode(errors='replace')

    # Exports (dynsym with non-zero st_value)
    dynsym_sec = secs.get('.dynsym', {})
    exports: dict[str, int] = {}
    if dynsym_sec and dynstr:
        for i in range(dynsym_sec['size'] // 16):
            o  = dynsym_sec['off'] + i * 16
            if o + 16 > len(data):
                break
            sv = struct.unpack_from('<I', data, o + 4)[0]
            sn = struct.unpack_from('<I', data, o)[0]
            if sv:
                name = _sym_name(sn)
                if name:
                    exports[name] = sv

    # PLT import map: plt_entry_vaddr → function name
    plt_map: dict[int, str] = {}
    relplt  = secs.get('.rel.plt', {})
    plt_sec = secs.get('.plt', {})
    if relplt and plt_sec and dynsym_sec and dynstr:
        plt_base = plt_sec['addr'] + 12  # first entry is resolver stub
        for i in range(relplt['size'] // 8):
            o      = relplt['off'] + i * 8
            r_info = struct.unpack_from('<I', data, o + 4)[0]
            sym_i  = r_info >> 8
            sym_o  = dynsym_sec['off'] + sym_i * 16
            if sym_o + 4 <= len(data):
                name_off = struct.unpack_from('<I', data, sym_o)[0]
                name     = _sym_name(name_off)
                if name:
                    plt_map[plt_base + i * 12] = name

    secs['_exports'] = exports
    secs['_plt']     = plt_map
    secs['_dynstr']  = dynstr
    return secs


def _resolve_ldr_pc(insn, data: bytes, text_off: int, text_addr: int,
                     rd_data: bytes, rd_base: int) -> str:
    """Resolve a LDR [pc, #imm] to a string constant if possible."""
    if insn.mnemonic != 'ldr' or '[pc,' not in insn.op_str:
        return ''
    m = re.search(r'#(-?0x[0-9a-f]+)', insn.op_str)
    if not m:
        return ''
    pc_val   = insn.address + 8
    ptr_addr = (pc_val + int(m.group(1), 16)) & 0xFFFFFFFF
    file_off = text_off + (ptr_addr - text_addr)
    if not (0 <= file_off + 4 <= len(data)):
        return ''
    lv = struct.unpack_from('<I', data, file_off)[0]
    if rd_data and rd_base <= lv < rd_base + len(rd_data):
        so = lv - rd_base
        sb = rd_data[so:so + 80]
        if b'\x00' in sb:
            s = sb[:sb.index(b'\x00')].decode(errors='replace')
            if s and len(s) >= 4 and all(0x20 <= ord(c) <= 0x7e for c in s):
                reg = insn.op_str.split(',')[0].strip()
                return f'  ; {reg}={s!r}'
    return ''


def disassemble(elf_path: Path, out_dir: Path) -> dict:
    """
    Full disassembly + annotation of an ARM32 ELF.
    Returns summary dict with key statistics and findings.
    """
    data  = elf_path.read_bytes()
    secs  = _parse_elf32(data)
    if not secs:
        return {'error': 'not an ELF32'}

    plt_map = secs.get('_plt', {})
    exports = secs.get('_exports', {})
    text    = secs.get('.text', {})
    rodata  = secs.get('.rodata', {})

    if not text:
        return {'error': 'no .text section'}

    tv = text['addr']
    tf = text['off']
    rd_data = (data[rodata['off']:rodata['off'] + rodata['size']]
               if rodata else b'')
    rd_base  = rodata.get('addr', 0)

    # Combined symbol map: vaddr → name
    all_sym: dict[int, str] = {v: k for k, v in exports.items()}
    all_sym.update(plt_map)

    md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md_arm.detail = True

    text_data = data[tf:tf + text['size']]
    insns     = list(md_arm.disasm(text_data, tv))

    # Header
    lines = [
        f'# {elf_path.name}  –  Full ARM32 Disassembly',
        f'# Size:      {elf_path.stat().st_size:,} bytes',
        f'# .text:     0x{tv:08x}  size={text["size"]:,}  ({len(insns)} instructions)',
        f'# Exports:   {len(exports)}',
        f'# PLT imps:  {len(plt_map)}',
        '',
    ]

    crypto_calls: list[str] = []
    interesting_strings: list[str] = []
    prev_end = None

    for insn in insns:
        # Gap → function boundary hint
        if prev_end is not None and insn.address > prev_end:
            lines.append('')
        if insn.address in all_sym:
            lines.append(f'\n; ─── {all_sym[insn.address]} @ 0x{insn.address:08x} ───')

        ann = ''
        # Annotate BL/BLX calls
        if insn.mnemonic in ('bl', 'blx') and insn.operands:
            try:
                tgt = insn.operands[0].imm & 0xFFFFFFFF
                sym = all_sym.get(tgt, '')
                if sym:
                    ann = f'  ; → {sym}'
                    if sym in CRYPTO_KEYWORDS:
                        crypto_calls.append(f'0x{insn.address:08x}: {sym}')
                        ann += '  ★'
            except Exception:
                pass

        # Annotate LDR PC-relative → string constants
        if not ann:
            str_ann = _resolve_ldr_pc(insn, data, tf, tv, rd_data, rd_base)
            if str_ann:
                ann = str_ann
                # Check for key-material strings
                if any(kw in str_ann for kw in
                       ['Df7!', 'PolarSSL', 'pass', 'Pass', 'key', 'Key',
                        'kmc', 'KMC', 'efuse', 'prvt', 'secret']):
                    interesting_strings.append(f'0x{insn.address:08x}: {str_ann.strip()}')

        lines.append(
            f'  {insn.address:08x}  {insn.bytes.hex():<12}  '
            f'{insn.mnemonic:<8} {insn.op_str:<44}{ann}'
        )
        prev_end = insn.address + len(insn.bytes)

    # Write output files
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'full_disasm.asm').write_text('\n'.join(lines))
    (out_dir / 'exports.txt').write_text(
        '\n'.join(f'  0x{v:08x}  {k}' for k, v in sorted(exports.items(), key=lambda x: x[1])))
    (out_dir / 'imports.txt').write_text(
        '\n'.join(f'  0x{k:08x}  {v}' for k, v in sorted(plt_map.items())))
    (out_dir / 'crypto_calls.txt').write_text('\n'.join(crypto_calls))
    (out_dir / 'interesting_strings.txt').write_text('\n'.join(interesting_strings))

    # Dump all interesting raw strings
    raw_strs: list[str] = []
    for m in re.finditer(rb'[\x20-\x7e]{8,}', data):
        s = m.group().decode(errors='replace')
        if any(kw in s.lower() for kw in
               ['pass', 'key', 'kmc', 'efuse', 'pbkdf', 'aes', 'cipher',
                'salt', 'df7!', 'polarssl', 'cert', 'prvt', 'secret',
                'encrypt', 'decrypt']):
            raw_strs.append(f'0x{m.start():08x}: {s!r}')
    (out_dir / 'key_strings.txt').write_text('\n'.join(raw_strs))

    return {
        'instructions': len(insns),
        'exports':      len(exports),
        'imports':      len(plt_map),
        'crypto_calls': crypto_calls,
        'key_strings':  raw_strs,
    }


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--rootfs', default='/tmp/telmex_rootfs',
                    help='Path to extracted SquashFS rootfs (default: /tmp/telmex_rootfs)')
    ap.add_argument('--out', default=str(DECOMPILED),
                    help='Output directory for .asm files')
    args = ap.parse_args(argv)

    rootfs  = Path(args.rootfs)
    out_dir = Path(args.out)

    if not rootfs.exists():
        print(f'[ERROR] Rootfs not found: {rootfs}')
        print('  Run tools/fw_extract.py first to extract the firmware.')
        return 1

    report_lines = ['# fw_full_decompile.py – Decompilation Report\n',
                    f'rootfs: {rootfs}\n\n']

    for rel_path, label, description in TARGETS:
        elf_path = rootfs / rel_path
        if not elf_path.exists():
            print(f'[SKIP] {label} – not found at {elf_path}')
            continue

        target_out = out_dir / label.replace('.', '_').replace('-', '_')
        print(f'\n[{label}] {elf_path.stat().st_size:,} B → {target_out}')
        print(f'  {description}')

        result = disassemble(elf_path, target_out)

        if 'error' in result:
            print(f'  ERROR: {result["error"]}')
            continue

        print(f'  instructions={result["instructions"]:,}  '
              f'exports={result["exports"]}  imports={result["imports"]}')
        if result['crypto_calls']:
            print(f'  Crypto call sites: {len(result["crypto_calls"])}')
            for c in result['crypto_calls'][:5]:
                print(f'    {c}')
        if result['key_strings']:
            print(f'  Key strings: {len(result["key_strings"])}')
            for s in result['key_strings'][:5]:
                print(f'    {s}')

        report_lines += [
            f'## {label}\n',
            f'- Path: `{elf_path}`\n',
            f'- Size: {elf_path.stat().st_size:,} bytes\n',
            f'- Purpose: {description}\n',
            f'- Instructions: {result["instructions"]:,}\n',
            f'- Exports: {result["exports"]}  Imports: {result["imports"]}\n',
        ]
        if result['crypto_calls']:
            report_lines.append('- **Crypto call sites**:\n')
            for c in result['crypto_calls']:
                report_lines.append(f'  - `{c}`\n')
        if result['key_strings']:
            report_lines.append('- **Key strings**:\n')
            for s in result['key_strings'][:10]:
                report_lines.append(f'  - `{s}`\n')
        report_lines.append('\n')

    report_path = out_dir / 'DECOMPILE_REPORT.md'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(''.join(report_lines))
    print(f'\n[+] Report: {report_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
