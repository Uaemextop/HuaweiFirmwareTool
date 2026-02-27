#!/usr/bin/env python3
"""ISP-specific WAP shell (Telnet/SSH) activation guide for Huawei ONT devices.

Provides step-by-step instructions and cfgtool commands for enabling the
WAP management shell (Telnet and/or SSH) on Huawei ONT devices, with
per-ISP aliases and model mappings.

Supported ISPs (use any alias with ``--isp``):
  - Megacable (aliases: megacable, mega, megacable2)
  - Telmex      (aliases: telmex, infinitum)
  - Izzi        (aliases: izzi)
  - Generic     (alias: generic, any)

Usage::

    # Show shell activation steps for Megacable
    python tools/isp_shell_enable.py --isp megacable

    # Show steps for a specific model
    python tools/isp_shell_enable.py --model EG8145V5

    # Download firmware and show full analysis pipeline
    python tools/isp_shell_enable.py --isp megacable --download
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional


# ── ISP / device catalogue ────────────────────────────────────────────────────

# Normalised ISP name → list of accepted CLI aliases (all lowercase)
ISP_ALIASES: Dict[str, List[str]] = {
    "megacable": ["megacable", "mega", "megacable2"],
    "telmex":    ["telmex", "infinitum"],
    "izzi":      ["izzi"],
    "generic":   ["generic", "any"],
}

# Normalised ISP name → primary ONT model deployed by that ISP
ISP_DEFAULT_MODEL: Dict[str, str] = {
    "megacable": "EG8145V5",
    "telmex":    "HG8145V5",
    "izzi":      "HG8145V5",
    "generic":   "HG8145V5",
}

# Normalised ISP name → firmware release filename (V2 GitHub release)
ISP_FIRMWARE: Dict[str, str] = {
    "megacable": "EG8145V5-V500R022C00SPC340B019.bin",
    "telmex":    "5611_HG8145V5V500R020C10SPC212.bin",
    "izzi":      "5611_HG8145V5V500R020C10SPC212.bin",
    "generic":   "EG8145V5-V500R022C00SPC340B019.bin",
}

RELEASE_BASE = (
    "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/"
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def resolve_isp(name: str) -> Optional[str]:
    """Return the canonical ISP key for *name* (case-insensitive), or None."""
    lower = name.strip().lower()
    for canonical, aliases in ISP_ALIASES.items():
        if lower in aliases:
            return canonical
    return None


def firmware_url(isp: str) -> str:
    """Return the GitHub release download URL for the ISP's firmware."""
    filename = ISP_FIRMWARE.get(isp, ISP_FIRMWARE["generic"])
    return RELEASE_BASE + filename


# ── Shell activation instructions ────────────────────────────────────────────


def _download_section(isp: str) -> List[str]:
    url = firmware_url(isp)
    filename = ISP_FIRMWARE.get(isp, ISP_FIRMWARE["generic"])
    lines = [
        "## 1 · Download firmware",
        "",
        f"   Firmware: {filename}",
        f"   URL:      {url}",
        "",
        "   Using the project download script (tools/download_firmwares.py):",
        "",
        "       python tools/download_firmwares.py --output-dir firmwares/",
        "",
        "   To download only the firmware for this ISP:",
        "",
        f"       python tools/download_firmwares.py --output-dir firmwares/ --name {isp}",
        "",
        "   Or download directly:",
        "",
        f"       wget '{url}'",
    ]
    return lines


def _extract_section(isp: str) -> List[str]:
    filename = ISP_FIRMWARE.get(isp, ISP_FIRMWARE["generic"])
    return [
        "",
        "## 2 · Extract firmware and binaries",
        "",
        f"       python tools/fw_extract.py firmwares/{filename} -o fw_extracted/",
        "",
        "   This copies aescrypt2, libhw_ssp_basic.so, and other key binaries",
        "   into fw_extracted/binaries/.",
        "",
        "## 3 · Extract configuration files",
        "",
        f"       python tools/fw_ctree_extract.py firmwares/{filename} -o fw_configs/",
        "",
        "   Extracts hw_ctree.xml (encrypted), hw_aes_tree.xml, hw_flashcfg.xml,",
        "   passwd, and other plaintext config files from /etc/wap/.",
        "",
        "## 4 · Decrypt hw_ctree.xml (requires the physical device or qemu chroot)",
        "",
        "   V500 firmwares (EG8145V5, HG8145V5) — using the firmware's own aescrypt2:",
        "",
        "       sudo cp /usr/bin/qemu-arm-static fw_extracted/rootfs/usr/bin/",
        "       sudo chroot fw_extracted/rootfs qemu-arm-static \\",
        "           /bin/aescrypt2 1 /etc/wap/hw_ctree.xml /tmp/out.xml",
        "       gunzip /tmp/out.xml.gz",
        "",
        "   Then analyse the decrypted XML:",
        "",
        "       python tools/config_analyzer.py --configs-dir extracted_configs/",
    ]


def _shell_activation_section(model: str) -> List[str]:
    """Generate WAP shell activation instructions for *model*."""
    is_v5 = "V5" in model or "EG8" in model
    return [
        "",
        "## 5 · Enable WAP shell (Telnet / SSH)",
        "",
        "   The WAP shell gives you root access to the ONT Linux environment.",
        "   There are two methods depending on what access you already have:",
        "",
        "   ### Method A — OBSC Enable Package (no prior access needed)",
        "",
        "   Use the HuaweiFirmwareTool GUI or the OBSC protocol to flash the",
        "   unlock package while the ONT is in bootloader mode:",
        "",
        "       1. Put the ONT into bootloader mode:",
        "          - Hold the Reset button for 10 s until the PWR LED blinks red.",
        "       2. Connect your PC directly to LAN port 1 (use a static IP",
        "          on the 192.168.100.x/24 subnet).",
        "       3. Launch the tool and use 'Enable Package' → select the",
        "          V5 Telnet+SSH package (or V3 if your device is V300).",
        "       4. Wait for 'Flash OK' in the result window.",
        "       5. The ONT reboots; Telnet is now open on port 23.",
        "",
        f"   Package type for {model}: **{'V5' if is_v5 else 'V3'}**",
        "",
        "   ### Method B — cfgtool via existing web UI or TR-069",
        "",
        "   If you already have web access (default admin credentials):",
        "",
        "       # Enable Telnet",
        '       cfgtool set deftree InternetGatewayDevice.X_HW_Security \\',
        '           TelnetEnable 1',
        "",
        "       # Enable SSH",
        '       cfgtool set deftree InternetGatewayDevice.X_HW_Security \\',
        '           SSHEnable 1',
        "",
        "       # Save and apply",
        "       cfgtool set deftree InternetGatewayDevice.X_HW_Security \\",
        "           TelnetPort 23",
        "       cfgtool commit",
        "",
        "   ### Method C — Encrypted config backup modification",
        "",
        "   Export the config from the web UI → decrypt with the chip-ID key →",
        "   set TelnetEnable='1' and SSHEnable='1' → re-encrypt → import back.",
        "",
        "       from hwflash.core.crypto import CfgFileParser",
        "       cfg = CfgFileParser()",
        "       cfg.load('backup_config.bin')",
        "       cfg.set_value('X_HW_Security.TelnetEnable', '1')",
        "       cfg.set_value('X_HW_Security.SSHEnable', '1')",
        "       cfg.save('modified_config.bin', encrypt=True)",
        "",
        "   ## 6 · Connect to the shell",
        "",
        "       telnet 192.168.100.1",
        "       # login: root   password: (empty, or try 'admin' / 'Hua@12345')",
        "",
        "       ssh root@192.168.100.1 -p 22",
        "",
        "   Once logged in, useful commands:",
        "",
        "       cat /proc/version          # kernel version",
        "       cat /etc/wap/hw_boardinfo  # board identity / serial",
        "       cfgtool get deftree InternetGatewayDevice.X_HW_Security",
    ]


def _disasm_section(model: str) -> List[str]:
    return [
        "",
        "## 7 · Disassemble binaries and libraries",
        "",
        "   Using the project ARM disassembler (Capstone-based):",
        "",
        "       python tools/arm_disasm.py fw_extracted/binaries/aescrypt2",
        "       python tools/arm_disasm.py fw_extracted/binaries/libhw_ssp_basic.so",
        "",
        "   Using radare2 directly:",
        "",
        "       r2 -qc 'aaa; afl' fw_extracted/binaries/aescrypt2",
        "       r2 -qc 'aaa; pdf @sym.main' fw_extracted/binaries/aescrypt2",
        "       r2 -qc 'izz~TelnetEnable' fw_extracted/binaries/cfgtool",
        "",
        "   Inspect ELF symbols:",
        "",
        "       arm-linux-gnueabi-readelf -s fw_extracted/binaries/libhw_ssp_basic.so",
        "       arm-linux-gnueabi-objdump -d fw_extracted/binaries/aescrypt2 | head -200",
    ]


def build_guide(isp: str, model: str, include_download: bool = True) -> str:
    """Build the full shell-activation guide for *isp* / *model*."""
    lines: list[str] = []
    lines.append(f"# WAP Shell Activation Guide — {isp.capitalize()} / {model}")
    lines.append("")
    lines.append(
        f"ISP: **{isp.capitalize()}**  |  Device model: **{model}**"
    )
    lines.append("")
    lines.append(
        "This guide explains how to download and analyse the firmware, "
        "decrypt configuration files, and enable the built-in Telnet/SSH "
        "management shell (WAP shell) on your Huawei ONT."
    )

    if include_download:
        lines.extend(["", *_download_section(isp)])
        lines.extend(_extract_section(isp))

    lines.extend(_shell_activation_section(model))
    lines.extend(_disasm_section(model))

    lines.append("")
    lines.append(
        "> **Note**: Activating the WAP shell on an ISP-managed device "
        "may void your service agreement. Use this information for "
        "educational and personal research purposes only."
    )

    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WAP shell activation guide for Huawei ONT devices"
    )
    isp_group = parser.add_mutually_exclusive_group()
    isp_group.add_argument(
        "--isp",
        metavar="NAME",
        help=(
            "ISP name or alias.  Accepted aliases: "
            + ", ".join(
                f"{k} ({', '.join(v)})"
                for k, v in ISP_ALIASES.items()
            )
        ),
    )
    isp_group.add_argument(
        "--model",
        metavar="MODEL",
        help="ONT model (e.g. EG8145V5, HG8145V5). Skips ISP detection.",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Include firmware download instructions in the guide.",
    )
    parser.add_argument(
        "--list-isps",
        action="store_true",
        help="List all known ISP aliases and exit.",
    )
    args = parser.parse_args()

    if args.list_isps:
        print("Supported ISPs and aliases:")
        for canonical, aliases in ISP_ALIASES.items():
            print(f"  {canonical:12s}  ← {', '.join(aliases)}")
        sys.exit(0)

    # Resolve ISP / model
    if args.isp:
        isp = resolve_isp(args.isp)
        if isp is None:
            print(
                f"ERROR: Unknown ISP '{args.isp}'. "
                "Use --list-isps to see accepted names.",
                file=sys.stderr,
            )
            sys.exit(1)
        model = ISP_DEFAULT_MODEL[isp]
    elif args.model:
        model = args.model.strip()
        # Guess ISP from model
        isp = next(
            (k for k, v in ISP_DEFAULT_MODEL.items() if v == model),
            "generic",
        )
    else:
        parser.print_help()
        sys.exit(0)

    guide = build_guide(isp, model, include_download=args.download)
    print(guide)


if __name__ == "__main__":
    main()
