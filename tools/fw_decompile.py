#!/usr/bin/env python3
"""
fw_decompile.py – Huawei EG8145V5 firmware extraction and disassembly tool.

Also handles:
  • file:/mnt/jffs2/ttree_spec_smooth.tar.gz      – AES-CBC encrypted config
  • file:/mnt/jffs2/app/preload_cplugin.tar.gz    – kernel app bundle
Both archives carry AES-related binaries described in the preload_cplugin
section; their content is catalogued and important binaries are disassembled.

Downloads (or uses a local copy of) EG8145V5-V500R022C00SPC340B019.bin,
extracts the following items from the HWNP firmware package, decompresses
the SquashFS rootfs, disassembles ARM32 ELF binaries with Capstone, and
writes a structured analysis report.

Targets:
  • /bin/aescrypt2                          (ARM32 PIE ELF, 5404 B)
  • /lib/libwlan_aes_crypto.so              (ARM32 shared lib, 5012 B)
  • file:/mnt/jffs2/ttree_spec_smooth.tar.gz      (8712 B, AES-CBC encrypted)
  • file:/mnt/jffs2/app/preload_cplugin.tar.gz    (2047991 B, gzip archive)
    → preload_cplugin/kernelapp.cpk               (gzip tar)
      → MyPlugin/bin/kernelapp                    (ARM32 ELF, 13436 B)
      → MyPlugin/bin/cpluginapp_real              (ARM32 ELF,  9348 B)
      → MyPlugin/Lib/libmbedall.so                (mbedTLS, 722452 B)
      → MyPlugin/Lib/libbasic.so / libsrv.so      (Huawei app libs)

Usage:
    python3 tools/fw_decompile.py [--fw <path>] [--out <dir>] [--report]

Requirements:
    pip install capstone

The reconstructed C sources live in decompiled/:
    decompiled/aescrypt2/aescrypt2.c
    decompiled/aescrypt2/hw_ssp_aescrypt.c / .h
    decompiled/wlan_aes/wlan_aes_crypto.c / .h
    decompiled/CMakeLists.txt
"""

from __future__ import annotations

import argparse
import io
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------
try:
    import capstone
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False
    print("[WARN] capstone not installed – disassembly disabled. "
          "Install with: pip install capstone", file=sys.stderr)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FW  = REPO_ROOT / "EG8145V5-V500R022C00SPC340B019.bin"
DEFAULT_OUT = REPO_ROOT / "decompiled" / "_extracted"
FW_URL = ("https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/"
          "V2/EG8145V5-V500R022C00SPC340B019.bin")

# ---------------------------------------------------------------------------
# HWNP parser (minimal, leveraging hwflash.core.firmware)
# ---------------------------------------------------------------------------

def _load_fw(fw_path: Path):
    """Return a parsed HWNPFirmware object."""
    sys.path.insert(0, str(REPO_ROOT))
    from hwflash.core.firmware import HWNPFirmware  # noqa: PLC0415
    fw = HWNPFirmware()
    fw.load(str(fw_path))
    return fw


# ---------------------------------------------------------------------------
# SquashFS extraction
# ---------------------------------------------------------------------------

def _extract_squashfs(sqfs_data: bytes, dest: Path) -> bool:
    """Write SquashFS to a temp file and run unsquashfs."""
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".sqfs", delete=False) as tmp:
        tmp.write(sqfs_data)
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            ["unsquashfs", "-force", "-d", str(dest), tmp_path],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("[WARN] unsquashfs not found – skipping SquashFS extraction",
              file=sys.stderr)
        return False
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------

def _parse_elf_sections(data: bytes) -> dict:
    """Return a dict {section_name: (file_offset, size, vaddr)} for an ELF32."""
    if data[:4] != b'\x7fELF':
        return {}
    e_shoff     = struct.unpack_from('<I', data, 32)[0]
    e_shnum     = struct.unpack_from('<H', data, 48)[0]
    e_shentsize = struct.unpack_from('<H', data, 46)[0]
    e_shstrndx  = struct.unpack_from('<H', data, 50)[0]

    if e_shoff == 0 or e_shnum == 0:
        return {}

    str_sh_off    = e_shoff + e_shstrndx * e_shentsize
    str_file_off  = struct.unpack_from('<I', data, str_sh_off + 16)[0]
    str_size      = struct.unpack_from('<I', data, str_sh_off + 20)[0]
    strtab        = data[str_file_off: str_file_off + str_size]

    sections: dict = {}
    for i in range(e_shnum):
        off   = e_shoff + i * e_shentsize
        n_idx = struct.unpack_from('<I', data, off)[0]
        vaddr = struct.unpack_from('<I', data, off + 12)[0]
        foff  = struct.unpack_from('<I', data, off + 16)[0]
        sz    = struct.unpack_from('<I', data, off + 20)[0]
        nend  = strtab.find(b'\x00', n_idx)
        name  = strtab[n_idx:nend].decode('ascii', errors='replace')
        if name:
            sections[name] = (foff, sz, vaddr)
    return sections


def _parse_elf_dynsyms(data: bytes) -> dict:
    """Return {name: (vaddr, size)} for exported dynamic symbols."""
    secs = _parse_elf_sections(data)
    if '.dynsym' not in secs or '.dynstr' not in secs:
        return {}
    ds_off, ds_sz, _ = secs['.dynsym']
    str_off, str_sz, _ = secs['.dynstr']
    dynstr = data[str_off: str_off + str_sz]

    syms: dict = {}
    for i in range(ds_sz // 16):
        off     = ds_off + i * 16
        st_name = struct.unpack_from('<I', data, off)[0]
        st_val  = struct.unpack_from('<I', data, off + 4)[0]
        st_size = struct.unpack_from('<I', data, off + 8)[0]
        nend    = dynstr.find(b'\x00', st_name)
        name    = dynstr[st_name:nend].decode('ascii', errors='replace')
        if name and st_val:
            syms[name] = (st_val, st_size)
    return syms


def _parse_plt_symbols(data: bytes) -> dict:
    """Return {plt_vaddr: import_name} from .rel.plt + .dynsym + .dynstr."""
    secs = _parse_elf_sections(data)
    if '.rel.plt' not in secs or '.dynsym' not in secs or '.dynstr' not in secs:
        return {}
    rp_off, rp_sz, _   = secs['.rel.plt']
    ds_off, _, _        = secs['.dynsym']
    str_off, str_sz, _  = secs['.dynstr']
    plt_off, _, plt_va  = secs.get('.plt', (0, 0, 0))
    dynstr = data[str_off: str_off + str_sz]

    plt_syms: dict = {}
    # PLT[0] is the resolver stub (20 bytes for ARM); entries start at plt_va+20
    for i in range(rp_sz // 8):
        off      = rp_off + i * 8
        r_info   = struct.unpack_from('<I', data, off + 4)[0]
        sym_idx  = r_info >> 8
        sym_off  = ds_off + sym_idx * 16
        st_name  = struct.unpack_from('<I', data, sym_off)[0]
        nend     = dynstr.find(b'\x00', st_name)
        name     = dynstr[st_name:nend].decode('ascii', errors='replace')
        entry_va = plt_va + 20 + i * 12  # ARM PLT entry = 12 bytes
        plt_syms[entry_va] = name
    return plt_syms


def _rodata_strings(data: bytes, secs: dict) -> list:
    """Extract printable null-terminated strings from .rodata."""
    if '.rodata' not in secs:
        return []
    off, sz, _ = secs['.rodata']
    rodata = data[off: off + sz]
    results = []
    i = 0
    while i < len(rodata):
        end = rodata.find(b'\x00', i)
        if end < 0:
            break
        s = rodata[i:end]
        if len(s) >= 3 and all(32 <= b < 127 for b in s):
            results.append(s.decode('ascii'))
        i = end + 1
    return results


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------

def _disassemble(data: bytes, vaddr: int, *, name: str = "",
                 plt_syms: Optional[dict] = None,
                 export_syms: Optional[dict] = None,
                 max_bytes: int = 0) -> list[str]:
    """Return list of disassembly lines for ARM32 code."""
    if not _HAS_CAPSTONE:
        return ["  [capstone not available]"]

    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    cs.detail = False
    plt_syms   = plt_syms   or {}
    export_syms = export_syms or {}
    lines = []
    if name:
        lines.append(f"\n; === {name} @ 0x{vaddr:08x} ===")

    chunk = data[:max_bytes] if max_bytes else data
    for insn in cs.disasm(chunk, vaddr):
        comment = ""
        if insn.mnemonic in ("bl", "b", "blx"):
            try:
                target = int(insn.op_str.lstrip("#"), 16)
                sym = plt_syms.get(target) or export_syms.get(target, ("",))[0]
                if sym:
                    comment = f"  ; {sym}"
            except (ValueError, TypeError):
                pass
        lines.append(f"  {insn.address:08x}  {insn.mnemonic:<8s} "
                     f"{insn.op_str}{comment}")
    return lines


# ---------------------------------------------------------------------------
# Encrypted-file header parser
# ---------------------------------------------------------------------------

AESCRYPT_MAGIC = 0x04
AESCRYPT_FLAG_ENC = 0x01
AESCRYPT_HDR_LEN = 24  # version(4)+flags(4)+IV(16)


def _parse_aescrypt_header(data: bytes) -> Optional[dict]:
    """
    Parse the Huawei aescrypt2 file header.

    Format (little-endian):
        0x00  uint32  version  (expected 0x04)
        0x04  uint32  flags    (0x01 = encrypted)
        0x08  bytes16 IV       (AES-CBC IV, random, device-unique)
        0x18  ...     AES-CBC ciphertext (PKCS#7 padded)
        last4 uint32  CRC-32 of header + ciphertext

    The AES-256-CBC key is derived on-device from the e-fuse root key via:
        MemGetRootKeyCfg() → flash keyfile → work key
    It is NOT stored in any binary in the firmware image.
    """
    if len(data) < AESCRYPT_HDR_LEN + 4:
        return None
    version, flags = struct.unpack_from('<II', data, 0)
    iv = data[8:24]
    crc_stored = struct.unpack_from('<I', data, len(data) - 4)[0]
    return {
        "version":     version,
        "flags":       flags,
        "iv_hex":      iv.hex(),
        "ciphertext_len": len(data) - AESCRYPT_HDR_LEN - 4,
        "crc32_stored": f"0x{crc_stored:08x}",
        "encrypted":   (flags == AESCRYPT_FLAG_ENC and version == AESCRYPT_MAGIC),
    }


# ---------------------------------------------------------------------------
# Main extraction + analysis
# ---------------------------------------------------------------------------

def analyse(fw_path: Path, out_dir: Path, *, write_report: bool = True) -> None:
    print(f"[*] Loading firmware: {fw_path}")
    fw = _load_fw(fw_path)
    print(f"    Layout: {fw.header_layout}  Items: {len(fw.items)}")

    out_dir.mkdir(parents=True, exist_ok=True)
    report_lines: list[str] = [
        "# EG8145V5 Firmware Decompilation Report",
        f"# Source: {fw_path.name}",
        f"# Generated by tools/fw_decompile.py",
        "",
    ]

    # ── 1. Save and analyse HWNP items ─────────────────────────────────────
    report_lines.append("## HWNP Firmware Items")
    for item in fw.items:
        report_lines.append(
            f"  {item.item_path:<55s}  {len(item.data):>10d} B  "
            f"section={item.section.strip()}"
        )

    # ── 2. Extract tar.gz items ─────────────────────────────────────────────
    report_lines += ["", "## Extracted Archives"]

    for item in fw.items:
        if not item.data:
            continue
        fname = Path(item.item_path).name

        if fname == "ttree_spec_smooth.tar.gz":
            _analyse_ttree(item.data, out_dir, report_lines)

        elif fname == "preload_cplugin.tar.gz":
            _analyse_preload(item.data, out_dir, report_lines)

    # ── 3. Extract SquashFS rootfs and analyse ELF binaries ─────────────────
    rootfs_item = next(
        (it for it in fw.items if "rootfs" in it.item_path.lower()), None
    )
    if rootfs_item and rootfs_item.data:
        sqfs_dest = out_dir / "rootfs"
        print(f"[*] Extracting SquashFS rootfs ({len(rootfs_item.data)} B) ...")
        ok = _extract_squashfs(rootfs_item.data, sqfs_dest)
        if ok:
            print(f"    → {sqfs_dest}")
            _analyse_elfs(sqfs_dest, out_dir, report_lines)
        else:
            report_lines.append("  [SquashFS extraction failed]")

    # ── 4. Write report ─────────────────────────────────────────────────────
    if write_report:
        report_path = out_dir / "analysis_report.md"
        report_path.write_text("\n".join(report_lines) + "\n")
        print(f"[*] Report written to {report_path}")


def _analyse_ttree(data: bytes, out_dir: Path, report: list[str]) -> None:
    """Analyse file:/mnt/jffs2/ttree_spec_smooth.tar.gz."""
    report.append("")
    report.append("### ttree_spec_smooth.tar.gz")
    report.append(f"  Size: {len(data)} bytes")

    hdr = _parse_aescrypt_header(data)
    if hdr and hdr["encrypted"]:
        report.append("  Format: Huawei aescrypt2 (AES-256-CBC encrypted)")
        report.append(f"  Header version : 0x{hdr['version']:02x}")
        report.append(f"  Flags          : 0x{hdr['flags']:02x} (encrypted)")
        report.append(f"  IV (hex)       : {hdr['iv_hex']}")
        report.append(f"  Ciphertext len : {hdr['ciphertext_len']} bytes")
        report.append(f"  CRC-32 (stored): {hdr['crc32_stored']}")
        report.append("  Content        : encrypted tar.gz (likely tree spec / XML config)")
        report.append("  Key derivation : device-unique e-fuse → flash keyfile → AES-256-CBC")
        report.append("  Decryptor      : /bin/aescrypt2  (calls OS_AescryptDecrypt)")
        out = out_dir / "ttree_spec_smooth.tar.gz.enc"
        out.write_bytes(data)
        report.append(f"  Saved to       : {out}")
    else:
        report.append("  Format: not aescrypt2 – storing raw bytes")
        (out_dir / "ttree_spec_smooth.bin").write_bytes(data)


def _analyse_preload(data: bytes, out_dir: Path, report: list[str]) -> None:
    """Analyse file:/mnt/jffs2/app/preload_cplugin.tar.gz."""
    report.append("")
    report.append("### preload_cplugin.tar.gz")
    report.append(f"  Size: {len(data)} bytes")

    raw_path = out_dir / "preload_cplugin.tar.gz"
    raw_path.write_bytes(data)

    try:
        extract_dir = out_dir / "preload_cplugin"
        extract_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(str(extract_dir))
        report.append("  Format: gzip tar")
        report.append(f"  Extracted to: {extract_dir}")

        # kernelapp.cpk is itself a gzip tar
        cpk_candidates = list(extract_dir.rglob("*.cpk"))
        for cpk in cpk_candidates:
            report.append(f"  → {cpk.name} ({cpk.stat().st_size} B)")
            try:
                cpk_dir = extract_dir / cpk.stem
                cpk_dir.mkdir(parents=True, exist_ok=True)
                with tarfile.open(str(cpk), mode="r:gz") as tf2:
                    tf2.extractall(str(cpk_dir))
                report.append(f"    Extracted kernelapp.cpk to: {cpk_dir}")
                for elf_path in sorted(cpk_dir.rglob("*")):
                    if elf_path.is_file():
                        sz = elf_path.stat().st_size
                        rel = elf_path.relative_to(cpk_dir)
                        report.append(f"      {rel}  ({sz} B)")
            except Exception as exc:
                report.append(f"    [extraction error: {exc}]")
    except Exception as exc:
        report.append(f"  [error: {exc}]")


def _analyse_elfs(rootfs: Path, out_dir: Path, report: list[str]) -> None:
    """Analyse ARM ELF binaries from SquashFS rootfs."""
    report += ["", "## ARM32 ELF Disassembly"]

    targets = [
        rootfs / "bin" / "aescrypt2",
        rootfs / "lib" / "libwlan_aes_crypto.so",
        rootfs / "bin" / "cfgtool",
        rootfs / "bin" / "oam",
        rootfs / "bin" / "mid",
        rootfs / "lib" / "libsmp_api.so",
        rootfs / "lib" / "libhw_smp_dm_pdt.so",
        rootfs / "lib" / "libhw_swm_dll.so",
        rootfs / "lib" / "libhw_ssp_basic.so",
        rootfs / "lib" / "modules" / "wap" / "hw_module_efuse.ko",
        rootfs / "lib" / "modules" / "wap" / "hw_module_sec.ko",
    ]

    asm_dir = out_dir / "disassembly"
    asm_dir.mkdir(parents=True, exist_ok=True)

    for elf_path in targets:
        if not elf_path.exists():
            report.append(f"  [not found: {elf_path}]")
            continue

        # Ensure readable
        try:
            elf_path.chmod(0o644)
        except PermissionError:
            pass

        data = elf_path.read_bytes()
        secs = _parse_elf_sections(data)
        syms = _parse_elf_dynsyms(data)
        plt  = _parse_plt_symbols(data)
        strs = _rodata_strings(data, secs)

        name = elf_path.name
        report.append("")
        report.append(f"### {name}")
        report.append(f"  Size: {len(data)} B")
        report.append(f"  Sections: {', '.join(secs.keys())}")
        report.append(f"  Exported symbols ({len(syms)}):")
        for sym_name, (va, sz) in sorted(syms.items(), key=lambda x: x[1][0]):
            report.append(f"    0x{va:08x}  [{sz:5d}]  {sym_name}")
        report.append(f"  PLT imports ({len(plt)}):")
        for va, imp_name in sorted(plt.items()):
            report.append(f"    0x{va:08x}  → {imp_name}")
        report.append(f"  Rodata strings:")
        for s in strs:
            report.append(f"    \"{s[:120]}\"")

        # Full disassembly of .text section
        if ".text" in secs and _HAS_CAPSTONE:
            txt_off, txt_sz, txt_va = secs[".text"]
            txt_data = data[txt_off: txt_off + txt_sz]
            asm_lines = _disassemble(
                txt_data, txt_va,
                name=f"{name} .text",
                plt_syms=plt,
                export_syms=syms,
            )
            asm_file = asm_dir / f"{name}.asm"
            asm_file.write_text("\n".join(asm_lines) + "\n")
            report.append(f"  Disassembly: {asm_file}")

        # Per-function disassembly for exported symbols
        if syms and _HAS_CAPSTONE:
            fn_lines = [f"; {name} – per-function disassembly", ""]
            for fn_name, (fn_va, fn_sz) in sorted(syms.items(),
                                                    key=lambda x: x[1][0]):
                if fn_sz == 0 or fn_va == 0:
                    continue
                fn_off = fn_va  # PIE at base 0: vaddr == file offset for .text
                fn_data = data[fn_off: fn_off + fn_sz]
                fn_lines += _disassemble(
                    fn_data, fn_va,
                    name=fn_name,
                    plt_syms=plt,
                    export_syms=syms,
                )
                fn_lines.append("")
            fn_file = asm_dir / f"{name}.functions.asm"
            fn_file.write_text("\n".join(fn_lines) + "\n")
            report.append(f"  Function disassembly: {fn_file}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Huawei EG8145V5 firmware extraction and disassembly tool"
    )
    p.add_argument(
        "--fw", metavar="PATH", default=str(DEFAULT_FW),
        help=f"Path to firmware .bin (default: {DEFAULT_FW})"
    )
    p.add_argument(
        "--out", metavar="DIR", default=str(DEFAULT_OUT),
        help=f"Output directory (default: {DEFAULT_OUT})"
    )
    p.add_argument(
        "--no-report", action="store_true",
        help="Skip writing the Markdown analysis report"
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    fw_path = Path(args.fw)

    if not fw_path.exists():
        print(f"[!] Firmware not found at {fw_path}")
        print(f"    Download from: {FW_URL}")
        sys.exit(1)

    out_dir = Path(args.out)
    analyse(fw_path, out_dir, write_report=not args.no_report)
    print("[✓] Done")


if __name__ == "__main__":
    main()
