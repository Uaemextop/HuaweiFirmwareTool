#!/usr/bin/env python3
"""
fw_rootfs_decompile.py – Rootfs binary analysis for Huawei EG8145V5.

Analyses key binaries from the extracted rootfs (busybox, clid, shellconfig)
using Capstone ARM32 disassembly.  Generates a structured markdown report and
C stub source files documenting imports, exports, and key functionality.

Usage:
    python3 tools/fw_rootfs_decompile.py [--rootfs <path>] [--out <dir>]

Requirements:
    pip install capstone
"""

from __future__ import annotations

import argparse
import struct
import sys
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
DEFAULT_ROOTFS = Path("/tmp/fw_extract/rootfs/EG8145V5-V500R022C00SPC340B019")
FALLBACK_DIR = REPO_ROOT / "decompiled" / "arm_binaries" / "EG8145V5_rootfs"
DEFAULT_OUT = REPO_ROOT / "decompiled"

TARGETS = ["busybox", "clid", "shellconfig"]


# ---------------------------------------------------------------------------
# ELF32 ARM helpers (consistent with tools/fw_decompile.py)
# ---------------------------------------------------------------------------

def _parse_elf_header(data: bytes) -> dict:
    """Parse ELF32 header fields."""
    if len(data) < 52 or data[:4] != b'\x7fELF':
        return {}
    return {
        "ei_class": data[4],
        "ei_data": data[5],
        "e_type": struct.unpack_from('<H', data, 16)[0],
        "e_machine": struct.unpack_from('<H', data, 18)[0],
        "e_entry": struct.unpack_from('<I', data, 24)[0],
        "e_phoff": struct.unpack_from('<I', data, 28)[0],
        "e_phnum": struct.unpack_from('<H', data, 44)[0],
    }


def _parse_elf_sections(data: bytes) -> dict:
    """Return {section_name: (file_offset, size, vaddr)} for an ELF32."""
    if data[:4] != b'\x7fELF':
        return {}
    e_shoff = struct.unpack_from('<I', data, 32)[0]
    e_shnum = struct.unpack_from('<H', data, 48)[0]
    e_shentsize = struct.unpack_from('<H', data, 46)[0]
    e_shstrndx = struct.unpack_from('<H', data, 50)[0]
    if e_shoff == 0 or e_shnum == 0:
        return {}
    str_sh_off = e_shoff + e_shstrndx * e_shentsize
    str_file_off = struct.unpack_from('<I', data, str_sh_off + 16)[0]
    str_size = struct.unpack_from('<I', data, str_sh_off + 20)[0]
    strtab = data[str_file_off: str_file_off + str_size]

    sections: dict = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        n_idx = struct.unpack_from('<I', data, off)[0]
        sh_type = struct.unpack_from('<I', data, off + 4)[0]
        vaddr = struct.unpack_from('<I', data, off + 12)[0]
        foff = struct.unpack_from('<I', data, off + 16)[0]
        sz = struct.unpack_from('<I', data, off + 20)[0]
        nend = strtab.find(b'\x00', n_idx)
        name = strtab[n_idx:nend].decode('ascii', errors='replace')
        if name:
            sections[name] = (foff, sz, vaddr, sh_type)
    return sections


def _parse_elf_dynsyms(data: bytes, sections: dict) -> dict:
    """Return {name: (vaddr, size, bind, type)} for dynamic symbols."""
    if '.dynsym' not in sections or '.dynstr' not in sections:
        return {}
    ds_off, ds_sz, _, _ = sections['.dynsym']
    str_off, str_sz, _, _ = sections['.dynstr']
    dynstr = data[str_off: str_off + str_sz]
    syms: dict = {}
    for i in range(ds_sz // 16):
        off = ds_off + i * 16
        st_name = struct.unpack_from('<I', data, off)[0]
        st_val = struct.unpack_from('<I', data, off + 4)[0]
        st_size = struct.unpack_from('<I', data, off + 8)[0]
        st_info = data[off + 12]
        nend = dynstr.find(b'\x00', st_name)
        name = dynstr[st_name:nend].decode('ascii', errors='replace')
        if name:
            bind = st_info >> 4
            stype = st_info & 0xf
            syms[name] = (st_val, st_size, bind, stype)
    return syms


def _parse_plt_symbols(data: bytes, sections: dict) -> dict:
    """Return {plt_vaddr: import_name} from .rel.plt + .dynsym + .dynstr."""
    if '.rel.plt' not in sections or '.dynsym' not in sections:
        return {}
    if '.dynstr' not in sections:
        return {}
    rp_off, rp_sz, _, _ = sections['.rel.plt']
    ds_off, _, _, _ = sections['.dynsym']
    str_off, str_sz, _, _ = sections['.dynstr']
    plt_off, _, plt_va, _ = sections.get('.plt', (0, 0, 0, 0))
    dynstr = data[str_off: str_off + str_sz]

    plt_syms: dict = {}
    for i in range(rp_sz // 8):
        off = rp_off + i * 8
        r_info = struct.unpack_from('<I', data, off + 4)[0]
        sym_idx = r_info >> 8
        sym_off = ds_off + sym_idx * 16
        st_name = struct.unpack_from('<I', data, sym_off)[0]
        nend = dynstr.find(b'\x00', st_name)
        name = dynstr[st_name:nend].decode('ascii', errors='replace')
        entry_va = plt_va + 20 + i * 12
        plt_syms[entry_va] = name
    return plt_syms


def _parse_dynamic(data: bytes, sections: dict) -> list:
    """Parse .dynamic section for DT_NEEDED entries."""
    if '.dynamic' not in sections or '.dynstr' not in sections:
        return []
    dyn_off, dyn_sz, _, _ = sections['.dynamic']
    str_off, str_sz, _, _ = sections['.dynstr']
    dynstr = data[str_off: str_off + str_sz]
    needed = []
    for i in range(dyn_sz // 8):
        off = dyn_off + i * 8
        d_tag = struct.unpack_from('<I', data, off)[0]
        d_val = struct.unpack_from('<I', data, off + 4)[0]
        if d_tag == 1:  # DT_NEEDED
            nend = dynstr.find(b'\x00', d_val)
            name = dynstr[d_val:nend].decode('ascii', errors='replace')
            needed.append(name)
        elif d_tag == 0:  # DT_NULL
            break
    return needed


def _rodata_strings(data: bytes, sections: dict, min_len: int = 4) -> list:
    """Extract printable null-terminated strings from .rodata."""
    if '.rodata' not in sections:
        return []
    off, sz, _, _ = sections['.rodata']
    rodata = data[off: off + sz]
    results = []
    i = 0
    while i < len(rodata):
        end = rodata.find(b'\x00', i)
        if end < 0:
            break
        s = rodata[i:end]
        if len(s) >= min_len and all(32 <= b < 127 for b in s):
            results.append(s.decode('ascii'))
        i = end + 1
    return results


def _disassemble_entry(data: bytes, sections: dict,
                       plt_syms: dict, max_insns: int = 80) -> list[str]:
    """Disassemble .text entry point (first max_insns instructions)."""
    if not _HAS_CAPSTONE or '.text' not in sections:
        return ["  [capstone not available or no .text section]"]
    txt_off, txt_sz, txt_va, _ = sections['.text']
    txt_data = data[txt_off: txt_off + txt_sz]
    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    cs.detail = False
    lines = []
    count = 0
    for insn in cs.disasm(txt_data, txt_va):
        comment = ""
        if insn.mnemonic in ("bl", "b", "blx"):
            try:
                target = int(insn.op_str.lstrip("#"), 16)
                sym = plt_syms.get(target)
                if sym:
                    comment = f"  ; {sym}"
            except (ValueError, TypeError):
                pass
        lines.append(f"  {insn.address:08x}  {insn.mnemonic:<8s} "
                     f"{insn.op_str}{comment}")
        count += 1
        if count >= max_insns:
            lines.append(f"  ... ({txt_sz // 4 - count} more instructions)")
            break
    return lines


# ---------------------------------------------------------------------------
# String classification helpers
# ---------------------------------------------------------------------------

def _classify_strings(strings: list[str], binary_name: str) -> dict:
    """Classify strings into categories based on content."""
    cats: dict = {
        "commands": [],
        "paths": [],
        "messages": [],
        "functions": [],
        "config_keys": [],
        "applets": [],
    }
    for s in strings:
        sl = s.lower()
        if s.startswith("/") or s.startswith("./"):
            cats["paths"].append(s)
        elif s.startswith("HW_") or s.startswith("hw_") or "_CMD_" in s:
            cats["functions"].append(s)
        elif "=" in s and not s.startswith(" ") and len(s) < 80:
            cats["config_keys"].append(s)
        elif any(kw in sl for kw in ["error", "fail", "success", "warning",
                                      "usage", "invalid", "cannot"]):
            cats["messages"].append(s)
        elif (binary_name == "busybox" and len(s) < 20
              and s.isalpha() and s == s.lower()):
            cats["applets"].append(s)
        elif any(kw in sl for kw in ["cmd", "cli", "shell", "config",
                                      "enable", "disable", "show", "set",
                                      "display", "quit", "exit"]):
            cats["commands"].append(s)
    return cats


def _filter_busybox_applets(strings: list[str]) -> list[str]:
    """Heuristic: extract BusyBox applet names from rodata."""
    applets = []
    known = {
        "ash", "cat", "chmod", "chown", "cp", "date", "dd", "df", "echo",
        "expr", "find", "grep", "gzip", "gunzip", "halt", "head", "hostname",
        "ifconfig", "init", "insmod", "kill", "killall", "klogd", "ln", "ls",
        "lsmod", "mkdir", "mknod", "mount", "mv", "netstat", "ping", "ping6",
        "poweroff", "ps", "pwd", "reboot", "rm", "rmdir", "rmmod", "route",
        "sed", "sh", "sleep", "syslogd", "tail", "tar", "tee", "telnetd",
        "test", "tftp", "top", "touch", "traceroute", "true", "false",
        "umount", "uname", "vi", "wc", "wget", "xargs", "yes", "awk",
        "basename", "brctl", "bunzip2", "bzcat", "chroot", "clear", "cmp",
        "comm", "cut", "diff", "dirname", "dmesg", "du", "env", "ether-wake",
        "free", "ftpget", "ftpput", "hexdump", "id", "ip", "ipaddr",
        "iplink", "iproute", "iptunnel", "less", "logger", "login", "md5sum",
        "mkfifo", "modprobe", "more", "nslookup", "od", "passwd", "patch",
        "pidof", "pivot_root", "printenv", "printf", "readlink", "realpath",
        "reset", "seq", "sort", "start-stop-daemon", "strings", "stty",
        "switch_root", "sync", "sysctl", "tr", "traceroute6", "uniq",
        "unzip", "uptime", "usleep", "vconfig", "watch", "which", "whoami",
        "arping", "ntpd",
    }
    for s in strings:
        if s in known:
            applets.append(s)
    # Also pick up short lowercase alpha strings near known applets
    in_applet_region = False
    for s in strings:
        if s in known:
            in_applet_region = True
        elif in_applet_region:
            stripped = s.replace("-", "").replace("_", "")
            is_valid_length = 2 <= len(s) <= 20
            is_valid_format = stripped.isalpha()
            is_lowercase = s == s.lower()
            if is_valid_length and is_valid_format and is_lowercase and s not in applets:
                applets.append(s)
            elif not is_valid_length or not is_valid_format:
                in_applet_region = False
    return sorted(set(applets))


def _filter_clid_commands(strings: list[str]) -> list[str]:
    """Extract CLI command-related strings from clid."""
    cmds = []
    for s in strings:
        if any(kw in s for kw in ["enable", "disable", "display", "quit",
                                   "config", "diagnose", "ping", "trace",
                                   "reboot", "save", "reset", "shell",
                                   "interface", "system", "service",
                                   "port", "wan", "vlan", "ont"]):
            cmds.append(s)
        elif s.startswith("WAP_") or s.startswith("CLI_") or s.startswith("CMD_"):
            cmds.append(s)
    return cmds


def _filter_shellconfig_funcs(strings: list[str]) -> list[str]:
    """Extract HW_CFGCMD_ and related function names from shellconfig."""
    funcs = []
    for s in strings:
        if ("CFGCMD" in s or "CfgCmd" in s or "cfgcmd" in s
                or s.startswith("HW_") or s.startswith("hw_")):
            funcs.append(s)
    return funcs


# ---------------------------------------------------------------------------
# Binary analysis
# ---------------------------------------------------------------------------

def _sanitize_identifier(s: str) -> str:
    """Convert an arbitrary string to a safe C identifier."""
    safe = s.replace(" ", "_").replace("-", "_").replace("/", "_")
    return "".join(ch for ch in safe if ch.isalnum() or ch == "_")


def _analyse_binary(path: Path) -> dict:
    """Analyse a single ARM32 ELF binary."""
    data = path.read_bytes()
    hdr = _parse_elf_header(data)
    secs = _parse_elf_sections(data)
    syms = _parse_elf_dynsyms(data, secs)
    plt = _parse_plt_symbols(data, secs)
    needed = _parse_dynamic(data, secs)
    strings = _rodata_strings(data, secs)
    entry_asm = _disassemble_entry(data, secs, plt)
    classified = _classify_strings(strings, path.name)

    # Separate imports (undefined, bind=GLOBAL/WEAK) from exports
    imports = {n: v for n, v in syms.items() if v[0] == 0 and v[2] in (1, 2)}
    exports = {n: v for n, v in syms.items() if v[0] != 0}

    return {
        "name": path.name,
        "path": str(path),
        "size": len(data),
        "header": hdr,
        "sections": secs,
        "imports": imports,
        "exports": exports,
        "plt": plt,
        "needed": needed,
        "strings": strings,
        "classified": classified,
        "entry_asm": entry_asm,
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _generate_report(analyses: list[dict], out_path: Path) -> None:
    """Write ROOTFS_BINARIES_REPORT.md."""
    lines = [
        "# EG8145V5 Rootfs Binaries – Decompilation Report",
        "",
        "Generated by `tools/fw_rootfs_decompile.py`",
        "",
        "Firmware: EG8145V5-V500R022C00SPC340B019",
        "Architecture: ARM32 (Cortex-A9), musl libc, PIE ELF",
        "",
        "---",
        "",
    ]

    for info in analyses:
        name = info["name"]
        hdr = info["header"]
        lines.append(f"## {name}")
        lines.append("")
        e_type_map = {2: "EXEC", 3: "DYN (PIE)"}
        e_type = e_type_map.get(hdr.get("e_type", 0), f"0x{hdr.get('e_type', 0):x}")
        lines.append(f"- **Size**: {info['size']:,} bytes ({info['size'] // 1024} KB)")
        lines.append(f"- **Type**: ELF32 ARM {e_type}")
        lines.append(f"- **Entry point**: 0x{hdr.get('e_entry', 0):08x}")
        lines.append(f"- **Sections**: {', '.join(info['sections'].keys())}")
        lines.append("")

        # Dynamic dependencies
        if info["needed"]:
            lines.append("### Dynamic Library Dependencies")
            lines.append("")
            for lib in info["needed"]:
                lines.append(f"- `{lib}`")
            lines.append("")

        # Section sizes
        lines.append("### Section Sizes")
        lines.append("")
        lines.append("| Section | Offset | Size | VAddr |")
        lines.append("|---------|--------|------|-------|")
        for sec_name, (foff, sz, va, _) in sorted(info["sections"].items(),
                                                    key=lambda x: x[1][0]):
            if sz > 0:
                lines.append(f"| {sec_name} | 0x{foff:x} | {sz:,} | 0x{va:08x} |")
        lines.append("")

        # PLT imports
        if info["plt"]:
            lines.append("### Function Imports (PLT)")
            lines.append("")
            lines.append("| PLT Address | Symbol |")
            lines.append("|-------------|--------|")
            for va, imp_name in sorted(info["plt"].items()):
                lines.append(f"| 0x{va:08x} | `{imp_name}` |")
            lines.append("")

        # Entry disassembly
        if info["entry_asm"]:
            lines.append("### Entry Point Disassembly (.text)")
            lines.append("")
            lines.append("```asm")
            for asm_line in info["entry_asm"]:
                lines.append(asm_line)
            lines.append("```")
            lines.append("")

        # Binary-specific analysis
        if name == "busybox":
            _report_busybox(info, lines)
        elif name == "clid":
            _report_clid(info, lines)
        elif name == "shellconfig":
            _report_shellconfig(info, lines)

        # Key strings
        classified = info["classified"]
        if classified["paths"]:
            lines.append("### File Paths Referenced")
            lines.append("")
            for s in classified["paths"][:50]:
                lines.append(f"- `{s}`")
            lines.append("")
        if classified["messages"]:
            lines.append("### Diagnostic Messages")
            lines.append("")
            for s in classified["messages"][:30]:
                lines.append(f"- `{s}`")
            lines.append("")
        if classified["functions"]:
            lines.append("### HW_* Function References")
            lines.append("")
            for s in classified["functions"][:40]:
                lines.append(f"- `{s}`")
            lines.append("")

        lines.append("---")
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n")
    print(f"[*] Report written to {out_path}")


def _report_busybox(info: dict, lines: list[str]) -> None:
    """Add BusyBox-specific analysis to the report."""
    applets = _filter_busybox_applets(info["strings"])
    lines.append("### BusyBox Applet List")
    lines.append("")
    if applets:
        lines.append(f"Detected {len(applets)} applets:")
        lines.append("")
        # 4-column table
        cols = 4
        for i in range(0, len(applets), cols):
            row = applets[i:i + cols]
            padded = row + [""] * (cols - len(row))
            cells = " | ".join(f"`{a}`" if a else "" for a in padded)
            lines.append(f"| {cells} |")
        lines.append("")
    else:
        lines.append("_No applets detected (binary may be stripped)_")
        lines.append("")


def _report_clid(info: dict, lines: list[str]) -> None:
    """Add clid-specific analysis to the report."""
    cmds = _filter_clid_commands(info["strings"])
    lines.append("### CLI Command Tree")
    lines.append("")
    if cmds:
        lines.append(f"Detected {len(cmds)} CLI-related strings:")
        lines.append("")
        for c in cmds[:60]:
            lines.append(f"- `{c}`")
        lines.append("")
    # Identify WAP/CLI function patterns
    cli_funcs = [s for s in info["strings"]
                 if s.startswith("WAP_CLI") or s.startswith("CLI_")
                 or s.startswith("WAP_CMD")]
    if cli_funcs:
        lines.append("### WAP CLI Functions")
        lines.append("")
        for f in cli_funcs[:40]:
            lines.append(f"- `{f}`")
        lines.append("")


def _report_shellconfig(info: dict, lines: list[str]) -> None:
    """Add shellconfig-specific analysis to the report."""
    funcs = _filter_shellconfig_funcs(info["strings"])
    lines.append("### HW_CFGCMD_ Function List")
    lines.append("")
    if funcs:
        for f in funcs[:40]:
            lines.append(f"- `{f}`")
        lines.append("")
    else:
        lines.append("_No HW_CFGCMD_ functions detected_")
        lines.append("")


# ---------------------------------------------------------------------------
# C stub generation
# ---------------------------------------------------------------------------

def _generate_busybox_stub(info: dict, out_dir: Path) -> None:
    """Generate decompiled/busybox_stub/busybox_stub.c."""
    d = out_dir / "busybox_stub"
    d.mkdir(parents=True, exist_ok=True)

    applets = _filter_busybox_applets(info["strings"])
    plt_entries = sorted(info["plt"].items())
    needed = info["needed"]

    lines = [
        "/*",
        " * busybox_stub.c – BusyBox multi-call binary (reconstructed stub)",
        " *",
        f" * Original binary: /bin/busybox ({info['size']:,} bytes)",
        " * Firmware: EG8145V5-V500R022C00SPC340B019",
        " * Architecture: ARM32 Cortex-A9, musl libc, PIE ELF",
        " * Linker: /lib/ld-musl-arm.so.1",
        " *",
        " * BusyBox is a multi-call binary combining many Unix utilities.",
        " * The applet is selected based on argv[0] (symlink name).",
        " *",
        " * Dynamic library dependencies:",
    ]
    for lib in needed:
        lines.append(f" *   - {lib}")
    lines += [
        " *",
        " * PLT imports:",
    ]
    for va, name in plt_entries:
        lines.append(f" *   0x{va:08x}  {name}")
    lines += [
        " */",
        "",
        "#include <stdio.h>",
        "#include <string.h>",
        "#include <stdlib.h>",
        "#include <unistd.h>",
        "",
        "/* ── Applet dispatch table ─────────────────────────────────────── */",
        "",
        "typedef int (*applet_main_t)(int argc, char **argv);",
        "",
        "struct applet_entry {",
        "    const char *name;",
        "    applet_main_t main_fn;",
        "};",
        "",
    ]
    # Generate stub prototypes
    for a in applets:
        ident = a.replace("-", "_")
        lines.append(f"static int {ident}_main(int argc, char **argv);")
    lines.append("")

    lines.append("static const struct applet_entry applet_table[] = {")
    for a in applets:
        ident = a.replace("-", "_")
        lines.append(f'    {{ "{a}", {ident}_main }},')
    lines.append("    { NULL, NULL }")
    lines.append("};")
    lines.append("")

    lines += [
        "/* ── Main entry point ──────────────────────────────────────────── */",
        "",
        "int main(int argc, char **argv)",
        "{",
        '    const char *applet = strrchr(argv[0], \'/\');',
        "    applet = applet ? applet + 1 : argv[0];",
        "",
        '    if (strcmp(applet, "busybox") == 0 && argc > 1) {',
        "        applet = argv[1];",
        "        argv++;",
        "        argc--;",
        "    }",
        "",
        "    for (const struct applet_entry *e = applet_table; e->name; e++) {",
        "        if (strcmp(applet, e->name) == 0)",
        "            return e->main_fn(argc, argv);",
        "    }",
        "",
        '    fprintf(stderr, "busybox: applet not found: %s\\n", applet);',
        "    return 127;",
        "}",
        "",
        "/* ── Applet stubs (implementations elided) ───────────────────── */",
        "",
    ]
    for a in applets:
        ident = a.replace("-", "_")
        lines += [
            f"static int {ident}_main(int argc, char **argv)",
            "{",
            f'    /* TODO: {a} implementation */',
            "    (void)argc; (void)argv;",
            "    return 0;",
            "}",
            "",
        ]

    (d / "busybox_stub.c").write_text("\n".join(lines) + "\n")
    print(f"[*] Generated {d / 'busybox_stub.c'}")


def _generate_clid_stub(info: dict, out_dir: Path) -> None:
    """Generate decompiled/clid/clid.c."""
    d = out_dir / "clid"
    d.mkdir(parents=True, exist_ok=True)

    plt_entries = sorted(info["plt"].items())
    needed = info["needed"]
    cmds = _filter_clid_commands(info["strings"])
    cli_funcs = [s for s in info["strings"]
                 if s.startswith("WAP_CLI") or s.startswith("CLI_")
                 or s.startswith("WAP_CMD") or s.startswith("WAP_")]
    paths = [s for s in info["strings"] if s.startswith("/")]

    lines = [
        "/*",
        " * clid.c – WAP CLI daemon (reconstructed stub)",
        " *",
        f" * Original binary: /bin/clid ({info['size']:,} bytes)",
        " * Firmware: EG8145V5-V500R022C00SPC340B019",
        " * Architecture: ARM32 Cortex-A9, musl libc, PIE ELF",
        " * Linker: /lib/ld-musl-arm.so.1",
        " *",
        " * clid is the Huawei WAP (Web Application Platform) CLI shell.",
        " * It provides the interactive command-line interface for ONT",
        " * management, accessible via serial console or telnet.",
        " *",
        " * Dynamic library dependencies:",
    ]
    for lib in needed:
        lines.append(f" *   - {lib}")
    lines += [
        " *",
        " * PLT imports:",
    ]
    for va, name in plt_entries:
        lines.append(f" *   0x{va:08x}  {name}")
    lines += [
        " *",
        " * Key file paths:",
    ]
    for p in paths[:20]:
        lines.append(f" *   {p}")
    lines += [
        " */",
        "",
        "#include <stdio.h>",
        "#include <string.h>",
        "#include <stdlib.h>",
        "#include <unistd.h>",
        "",
        "/* ── WAP CLI command processing flow ─────────────────────────── */",
        "/*",
        " * 1. main() → CLI_Init() → register command handlers",
        " * 2. CLI_MainLoop() → read line from console/telnet",
        " * 3. CLI_ParseCmd(line) → tokenize and match command tree",
        " * 4. CLI_DispatchCmd(cmd, args) → invoke registered handler",
        " * 5. Handler calls WAP_* APIs to query/modify device config",
        " * 6. Response printed to console, loop back to step 2",
        " */",
        "",
        "/* ── CLI command handler type ────────────────────────────────── */",
        "",
        "typedef int (*cli_handler_t)(int argc, const char **argv);",
        "",
        "struct cli_cmd_entry {",
        "    const char *name;",
        "    const char *help;",
        "    cli_handler_t handler;",
        "};",
        "",
        "/* ── Forward declarations ────────────────────────────────────── */",
        "",
    ]
    # Generate handler prototypes from CLI command strings
    handler_names = []
    for c in cmds[:30]:
        safe = _sanitize_identifier(c)
        if safe and safe not in handler_names:
            handler_names.append(safe)
            lines.append(f"static int cmd_{safe}(int argc, const char **argv);")
    lines.append("")

    lines.append("/* ── Command registration table ───────────────────────────── */")
    lines.append("")
    lines.append("static const struct cli_cmd_entry cli_commands[] = {")
    for i, c in enumerate(cmds[:30]):
        safe = _sanitize_identifier(c)
        if safe:
            lines.append(f'    {{ "{c[:60]}", NULL, cmd_{safe} }},')
    lines.append("    { NULL, NULL, NULL }")
    lines.append("};")
    lines.append("")

    lines += [
        "/* ── CLI initialization ───────────────────────────────────────── */",
        "",
        "static void CLI_Init(void)",
        "{",
        "    /* Register all CLI command handlers */",
        "    for (const struct cli_cmd_entry *e = cli_commands; e->name; e++) {",
        '        /* WAP_CLI_RegCmd(e->name, e->handler) */',
        "    }",
        "}",
        "",
        "/* ── Main loop ────────────────────────────────────────────────── */",
        "",
        "static void CLI_MainLoop(void)",
        "{",
        "    char line[256];",
        '    while (fgets(line, sizeof(line), stdin)) {',
        "        /* CLI_ParseCmd(line); */",
        "        /* CLI_DispatchCmd(cmd, args); */",
        "    }",
        "}",
        "",
        "int main(int argc, char **argv)",
        "{",
        "    (void)argc; (void)argv;",
        "    CLI_Init();",
        "    CLI_MainLoop();",
        "    return 0;",
        "}",
        "",
        "/* ── Command handler stubs ────────────────────────────────────── */",
        "",
    ]
    seen = set()
    for c in cmds[:30]:
        safe = _sanitize_identifier(c)
        if safe and safe not in seen:
            seen.add(safe)
            lines += [
                f"static int cmd_{safe}(int argc, const char **argv)",
                "{",
                f'    /* Handler for "{c[:60]}" */',
                "    (void)argc; (void)argv;",
                "    return 0;",
                "}",
                "",
            ]

    # Document WAP functions found
    if cli_funcs:
        lines.append("/* ── WAP/CLI function references found in binary ──────────── */")
        lines.append("/*")
        for f in cli_funcs[:40]:
            lines.append(f" * {f}")
        lines.append(" */")
        lines.append("")

    (d / "clid.c").write_text("\n".join(lines) + "\n")
    print(f"[*] Generated {d / 'clid.c'}")


def _generate_shellconfig_stub(info: dict, out_dir: Path) -> None:
    """Generate decompiled/shellconfig/shellconfig.c."""
    d = out_dir / "shellconfig"
    d.mkdir(parents=True, exist_ok=True)

    plt_entries = sorted(info["plt"].items())
    needed = info["needed"]
    cfg_funcs = _filter_shellconfig_funcs(info["strings"])
    paths = [s for s in info["strings"] if s.startswith("/")]

    lines = [
        "/*",
        " * shellconfig.c – Shell configuration utility (reconstructed stub)",
        " *",
        f" * Original binary: /bin/shellconfig ({info['size']:,} bytes)",
        " * Firmware: EG8145V5-V500R022C00SPC340B019",
        " * Architecture: ARM32 Cortex-A9, musl libc, PIE ELF",
        " * Linker: /lib/ld-musl-arm.so.1",
        " *",
        " * shellconfig executes configuration commands via the WAP",
        " * HW_CFGCMD infrastructure. It is typically invoked by",
        " * init scripts and the CLI daemon to apply device settings.",
        " *",
        " * Dynamic library dependencies:",
    ]
    for lib in needed:
        lines.append(f" *   - {lib}")
    lines += [
        " *",
        " * PLT imports:",
    ]
    for va, name in plt_entries:
        lines.append(f" *   0x{va:08x}  {name}")
    lines += [
        " *",
        " * Key file paths:",
    ]
    for p in paths[:10]:
        lines.append(f" *   {p}")
    lines += [
        " */",
        "",
        "#include <stdio.h>",
        "#include <string.h>",
        "#include <stdlib.h>",
        "#include <unistd.h>",
        "",
        "/* ── Config shell command execution flow ─────────────────────── */",
        "/*",
        " * 1. main(argc, argv) → parse command-line arguments",
        " * 2. Locate config command in HW_CFGCMD_ dispatch table",
        " * 3. Call HW_CFGCMD_Execute(cmd_id, params) via libhw_ssp_basic.so",
        " * 4. Print result / error to stdout/stderr",
        " */",
        "",
        "/* ── HW_CFGCMD function type ────────────────────────────────── */",
        "",
        "typedef int (*cfgcmd_handler_t)(int argc, const char **argv);",
        "",
        "struct cfgcmd_entry {",
        "    const char *name;",
        "    cfgcmd_handler_t handler;",
        "};",
        "",
        "/* ── Forward declarations ────────────────────────────────────── */",
        "",
    ]
    handler_names = []
    for f in cfg_funcs[:30]:
        safe = _sanitize_identifier(f)
        if safe and safe not in handler_names:
            handler_names.append(safe)
            lines.append(f"static int handle_{safe}(int argc, const char **argv);")
    lines.append("")

    lines.append("/* ── HW_CFGCMD dispatch table ─────────────────────────────── */")
    lines.append("")
    lines.append("static const struct cfgcmd_entry cfgcmd_table[] = {")
    for name in handler_names:
        lines.append(f'    {{ "{name}", handle_{name} }},')
    lines.append("    { NULL, NULL }")
    lines.append("};")
    lines.append("")

    lines += [
        "/* ── Main entry point ──────────────────────────────────────────── */",
        "",
        "int main(int argc, char **argv)",
        "{",
        "    if (argc < 2) {",
        '        fprintf(stderr, "Usage: shellconfig <command> [args...]\\n");',
        "        return 1;",
        "    }",
        "",
        "    const char *cmd = argv[1];",
        "    for (const struct cfgcmd_entry *e = cfgcmd_table; e->name; e++) {",
        "        if (strcmp(cmd, e->name) == 0)",
        "            return e->handler(argc - 1, (const char **)argv + 1);",
        "    }",
        "",
        '    fprintf(stderr, "shellconfig: unknown command: %s\\n", cmd);',
        "    return 1;",
        "}",
        "",
        "/* ── Handler stubs ────────────────────────────────────────────── */",
        "",
    ]
    for name in handler_names:
        lines += [
            f"static int handle_{name}(int argc, const char **argv)",
            "{",
            f'    /* HW_CFGCMD handler for "{name}" */',
            "    (void)argc; (void)argv;",
            "    return 0;",
            "}",
            "",
        ]

    (d / "shellconfig.c").write_text("\n".join(lines) + "\n")
    print(f"[*] Generated {d / 'shellconfig.c'}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Huawei EG8145V5 rootfs binary analysis and decompilation"
    )
    parser.add_argument(
        "--rootfs", metavar="PATH", default=str(DEFAULT_ROOTFS),
        help=f"Path to extracted rootfs (default: {DEFAULT_ROOTFS})"
    )
    parser.add_argument(
        "--out", metavar="DIR", default=str(DEFAULT_OUT),
        help=f"Output directory (default: {DEFAULT_OUT})"
    )
    args = parser.parse_args()

    rootfs = Path(args.rootfs)
    out_dir = Path(args.out)

    # Resolve binary paths: rootfs/bin/ or fallback directory
    bin_paths: dict[str, Optional[Path]] = {}
    for name in TARGETS:
        rootfs_path = rootfs / "bin" / name
        fallback_path = FALLBACK_DIR / name
        if rootfs_path.exists():
            bin_paths[name] = rootfs_path
            print(f"[*] Found {name} at {rootfs_path}")
        elif fallback_path.exists():
            bin_paths[name] = fallback_path
            print(f"[*] Found {name} at {fallback_path} (fallback)")
        else:
            bin_paths[name] = None
            print(f"[!] {name} not found in rootfs or fallback", file=sys.stderr)

    # Analyse each binary
    analyses = []
    for name in TARGETS:
        path = bin_paths[name]
        if path is None:
            continue
        print(f"[*] Analysing {name} ({path.stat().st_size:,} bytes) ...")
        info = _analyse_binary(path)
        analyses.append(info)
        print(f"    Sections: {len(info['sections'])}, "
              f"PLT imports: {len(info['plt'])}, "
              f"Strings: {len(info['strings'])}")

    if not analyses:
        print("[!] No binaries found – nothing to do.", file=sys.stderr)
        sys.exit(1)

    # Generate report
    report_path = out_dir / "ROOTFS_BINARIES_REPORT.md"
    _generate_report(analyses, report_path)

    # Generate C stubs
    for info in analyses:
        if info["name"] == "busybox":
            _generate_busybox_stub(info, out_dir)
        elif info["name"] == "clid":
            _generate_clid_stub(info, out_dir)
        elif info["name"] == "shellconfig":
            _generate_shellconfig_stub(info, out_dir)

    print("[✓] Done")


if __name__ == "__main__":
    main()
