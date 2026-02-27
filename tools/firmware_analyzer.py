#!/usr/bin/env python3
"""Comprehensive firmware analysis tool for Huawei ONT devices.

Downloads firmware images, extracts SquashFS rootfs, decompiles key ARM
binaries, analyzes configuration files, decrypts hw_ctree.xml, and reports
shell/telnet/WAP access settings relevant to ISP-specific deployments
(e.g. Megacable / mega / megacable2).

Usage::

    # Full analysis of all available firmwares
    python tools/firmware_analyzer.py -o analysis_output

    # Analyze a single local firmware file
    python tools/firmware_analyzer.py firmware.bin -o analysis_output

    # Analyze with ISP filter (Megacable)
    python tools/firmware_analyzer.py --isp megacable -o analysis_output
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Allow running from repo root or tools/
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from hwflash.core.crypto import (  # noqa: E402
    KNOWN_CHIP_IDS,
    try_decrypt_all_keys,
)

# ── Constants ────────────────────────────────────────────────────────────────

SQUASHFS_MAGIC_LE = b"hsqs"
SQUASHFS_MAGIC_BE = b"sqsh"

# Known ISP aliases (Mexican market, Megacable variants)
ISP_ALIASES: Dict[str, List[str]] = {
    "megacable": ["megacable", "mega", "megacable2"],
}

# Key binaries to analyze from the rootfs
KEY_BINARIES = [
    "bin/aescrypt2",
    "bin/cfgtool",
    "lib/libhw_ssp_basic.so",
    "lib/libpolarssl.so",
    "lib/libhw_swm_dll.so",
    "lib/libhw_ssp_ssl.so",
]

# Key config files in /etc/wap/
KEY_CONFIGS = [
    "hw_ctree.xml",
    "hw_default_ctree.xml",
    "hw_aes_tree.xml",
    "hw_flashcfg.xml",
    "hw_boardinfo",
    "hw_firewall_v5.xml",
    "keyconfig.xml",
    "passwd",
    "hw_cli.xml",
    "hw_err.xml",
]

# Config paths relevant to shell/telnet/WAP access
WAP_SHELL_PATHS = [
    "X_HW_CLITelnetAccess",
    "AclServices",
    "X_HW_CLIUserInfo",
    "X_HW_CLIUserInfoInstance",
    "X_HW_WebUserInfo",
    "X_HW_WebUserInfoInstance",
    "NetInfo",
]


# ── Helpers ──────────────────────────────────────────────────────────────────


def find_squashfs(data: bytes) -> List[Tuple[int, int]]:
    """Return ``(offset, bytes_used)`` for every SquashFS image found."""
    results: list[Tuple[int, int]] = []
    for magic in (SQUASHFS_MAGIC_LE, SQUASHFS_MAGIC_BE):
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos == -1:
                break
            if pos + 48 <= len(data):
                bytes_used = struct.unpack_from("<Q", data, pos + 40)[0]
                if 0 < bytes_used <= len(data) - pos:
                    results.append((pos, bytes_used))
            idx = pos + 1
    results.sort(key=lambda t: t[1], reverse=True)
    return results


def classify_file(path: str) -> str:
    """Return a short format description for a config file."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(32)
    except (OSError, PermissionError):
        return "unreadable"
    if not head:
        return "empty"
    if head[:5] == b"<?xml" or (
        head[:1] == b"<" and b">" in head[:50] and head[:1] != b"\x00"
    ):
        return "XML"
    if head[:3] == b"\xef\xbb\xbf" and b"<" in head[:10]:
        return "XML (BOM)"
    if head[:4] == b"\x01\x00\x00\x00":
        return "encrypted"
    if head[:4] == b"AEST":
        return "AEST"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:4] == b"\x7fELF":
        return "ELF"
    return "binary"


def is_arm_elf(path: str) -> bool:
    """Check if a file is a 32-bit ARM ELF binary."""
    try:
        with open(path, "rb") as f:
            head = f.read(20)
        if len(head) < 20:
            return False
        return (
            head[:4] == b"\x7fELF"
            and head[4] == 1  # 32-bit
            and head[5] == 1  # little-endian
            and struct.unpack_from("<H", head, 18)[0] == 40  # ARM
        )
    except (OSError, PermissionError):
        return False


# ── Shell/WAP Access Analysis ───────────────────────────────────────────────


def extract_shell_access_info(xml_text: str) -> Dict[str, Any]:
    """Extract shell, telnet, SSH, and WAP access info from decrypted XML.

    Parses the ``hw_ctree.xml`` content for key access-control settings.
    """
    info: Dict[str, Any] = {
        "hostname": "",
        "telnet_lan_enable": None,
        "telnet_wan_enable": None,
        "telnet_wifi_enable": None,
        "telnet_port": None,
        "ssh_lan_enable": None,
        "ssh_wan_enable": None,
        "ssh_port": None,
        "http_port": None,
        "cli_telnet_access": None,
        "cli_users": [],
        "web_users": [],
    }

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return info

    # NetInfo (hostname — typically "WAP")
    for elem in root.iter("NetInfo"):
        info["hostname"] = elem.get("HostName", "")

    # AclServices
    for elem in root.iter("AclServices"):
        info["telnet_lan_enable"] = elem.get("TELNETLanEnable")
        info["telnet_wan_enable"] = elem.get("TELNETWanEnable")
        info["telnet_wifi_enable"] = elem.get("TELNETWifiEnable")
        info["telnet_port"] = elem.get("TELNETPORT")
        info["ssh_lan_enable"] = elem.get("SSHLanEnable")
        info["ssh_wan_enable"] = elem.get("SSHWanEnable")
        info["ssh_port"] = elem.get("SSHPORT")
        info["http_port"] = elem.get("HTTPPORT")

    # X_HW_CLITelnetAccess
    for elem in root.iter("X_HW_CLITelnetAccess"):
        info["cli_telnet_access"] = elem.get("Access")

    # CLI users
    for elem in root.iter("X_HW_CLIUserInfoInstance"):
        info["cli_users"].append({
            "username": elem.get("Username", ""),
            "password": elem.get("Userpassword", ""),
            "group": elem.get("UserGroup", ""),
            "encrypt_mode": elem.get("EncryptMode", ""),
        })

    # Web users
    for elem in root.iter("X_HW_WebUserInfoInstance"):
        info["web_users"].append({
            "username": elem.get("UserName", ""),
            "user_level": elem.get("UserLevel", ""),
            "enable": elem.get("Enable", ""),
            "pass_mode": elem.get("PassMode", ""),
        })

    return info


def extract_wan_info(xml_text: str) -> List[Dict[str, str]]:
    """Extract WAN connection details from decrypted XML."""
    connections: List[Dict[str, str]] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return connections

    for elem in root.iter("WANPPPConnectionInstance"):
        connections.append({
            "type": "PPPoE",
            "name": elem.get("Name", ""),
            "username": elem.get("Username", ""),
            "enable": elem.get("Enable", ""),
            "connection_type": elem.get("ConnectionType", ""),
        })

    for elem in root.iter("WANIPConnectionInstance"):
        connections.append({
            "type": "IPoE",
            "name": elem.get("Name", ""),
            "enable": elem.get("Enable", ""),
            "connection_type": elem.get("ConnectionType", ""),
            "addressing_type": elem.get("AddressingType", ""),
        })

    return connections


# ── Binary Analysis ──────────────────────────────────────────────────────────


def analyze_elf_imports(filepath: str) -> Dict[str, Any]:
    """Analyze an ARM ELF binary for imports and strings (no external tools).

    Returns basic ELF metadata including imported symbol names and
    printable strings found in the binary.
    """
    result: Dict[str, Any] = {
        "path": filepath,
        "size": 0,
        "is_elf": False,
        "arch": "",
        "type": "",
        "imports": [],
        "exports": [],
        "strings": [],
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (OSError, PermissionError):
        return result

    result["size"] = len(data)

    if len(data) < 52 or data[:4] != b"\x7fELF":
        return result

    result["is_elf"] = True

    # ELF header
    ei_class = data[4]
    ei_data = data[5]
    result["arch"] = "ARM" if struct.unpack_from("<H", data, 18)[0] == 40 else "unknown"

    e_type = struct.unpack_from("<H", data, 16)[0]
    type_map = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
    result["type"] = type_map.get(e_type, f"unknown({e_type})")

    if ei_class != 1 or ei_data != 1:
        return result  # Only handle 32-bit LE

    # Parse section headers
    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shentsize = struct.unpack_from("<H", data, 46)[0]
    e_shnum = struct.unpack_from("<H", data, 48)[0]
    e_shstrndx = struct.unpack_from("<H", data, 50)[0]

    if e_shoff == 0 or e_shnum == 0:
        return result

    # Section header string table
    shstr_base = e_shoff + e_shstrndx * e_shentsize
    if shstr_base + 20 > len(data):
        return result
    shstr_off = struct.unpack_from("<I", data, shstr_base + 16)[0]

    def _read_str(offset: int) -> str:
        end = data.find(b"\x00", offset)
        if end == -1:
            return ""
        return data[offset:end].decode("ascii", errors="replace")

    sections: Dict[str, Tuple[int, int, int]] = {}
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if base + 40 > len(data):
            break
        sh_name_idx = struct.unpack_from("<I", data, base)[0]
        sh_offset = struct.unpack_from("<I", data, base + 16)[0]
        sh_size = struct.unpack_from("<I", data, base + 20)[0]
        name = _read_str(shstr_off + sh_name_idx)
        sections[name] = (sh_offset, sh_size, struct.unpack_from("<I", data, base + 4)[0])

    # Dynamic symbol table
    if ".dynsym" in sections and ".dynstr" in sections:
        dsym_off, dsym_sz, _ = sections[".dynsym"]
        dstr_off, dstr_sz, _ = sections[".dynstr"]

        for i in range(dsym_sz // 16):
            base = dsym_off + i * 16
            if base + 16 > len(data):
                break
            st_name = struct.unpack_from("<I", data, base)[0]
            st_value = struct.unpack_from("<I", data, base + 4)[0]
            st_info = data[base + 12]
            st_shndx = struct.unpack_from("<H", data, base + 14)[0]

            if st_name and dstr_off + st_name < len(data):
                sym_name = _read_str(dstr_off + st_name)
                if sym_name:
                    if st_shndx == 0:  # import
                        result["imports"].append(sym_name)
                    elif st_value:
                        result["exports"].append(sym_name)

    # Extract printable strings (min length 6)
    current: list[int] = []
    for i, b in enumerate(data):
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= 6:
                s = bytes(current).decode("ascii")
                result["strings"].append(s)
            current = []
    # Keep only interesting strings (limit to 200)
    result["strings"] = result["strings"][:200]

    return result


# ── Config File Analysis ─────────────────────────────────────────────────────


def analyze_config_file(filepath: str) -> Dict[str, Any]:
    """Analyze a config file (XML, text, or encrypted)."""
    result: Dict[str, Any] = {
        "path": filepath,
        "filename": os.path.basename(filepath),
        "size": 0,
        "format": "",
        "elements": 0,
        "attributes": 0,
        "preview": "",
    }

    try:
        result["size"] = os.path.getsize(filepath)
        result["format"] = classify_file(filepath)
    except OSError:
        return result

    if result["format"] in ("XML", "XML (BOM)"):
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            result["elements"] = sum(1 for _ in root.iter())
            result["attributes"] = sum(len(e.attrib) for e in root.iter())

            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            result["preview"] = "".join(lines[:10])
        except (ET.ParseError, OSError):
            pass
    elif result["format"] not in ("encrypted", "AEST", "ELF", "binary"):
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                result["preview"] = f.read(500)
        except OSError:
            pass

    return result


# ── Decrypted Config Analysis ────────────────────────────────────────────────


def try_decrypt_ctree(filepath: str) -> Optional[Tuple[str, str]]:
    """Try to decrypt a hw_ctree.xml file using known chip IDs.

    Returns ``(chip_id, xml_text)`` on success, ``None`` on failure.
    """
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except (OSError, PermissionError):
        return None

    import gzip
    import io

    for skip in (0, 4):
        chunk = raw[skip:]
        remainder = len(chunk) % 16
        if remainder:
            chunk = chunk[: len(chunk) - remainder]
        if len(chunk) < 16:
            continue

        results = try_decrypt_all_keys(chunk)
        if results:
            chip_id, decrypted = results[0]
            # Try gunzip
            if len(decrypted) >= 2 and decrypted[:2] == b"\x1f\x8b":
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(decrypted)) as gz:
                        decrypted = gz.read()
                except OSError:
                    pass
            text = decrypted.decode("utf-8", errors="replace")
            if "<?xml" in text[:100] or "<InternetGatewayDevice" in text[:200]:
                return chip_id, text

    return None


# ── Report Generation ────────────────────────────────────────────────────────


def generate_analysis_report(
    firmware_name: str,
    configs: List[Dict[str, Any]],
    binaries: List[Dict[str, Any]],
    shell_info: Optional[Dict[str, Any]],
    wan_info: List[Dict[str, str]],
    isp: Optional[str],
) -> str:
    """Generate a Markdown analysis report."""
    lines: list[str] = []

    lines.append(f"# Firmware Analysis: {firmware_name}")
    lines.append("")

    if isp:
        isp_display = isp.capitalize()
        aliases = ISP_ALIASES.get(isp.lower(), [])
        if aliases:
            lines.append(
                f"**ISP**: {isp_display} (aliases: {', '.join(aliases)})"
            )
        else:
            lines.append(f"**ISP**: {isp_display}")
        lines.append("")

    # ── Shell/WAP Access ─────────────────────────────────────────────────
    if shell_info:
        lines.append("## Shell / WAP Access Configuration")
        lines.append("")
        lines.append(
            "The device hostname is set to "
            f"`{shell_info['hostname'] or 'WAP'}` in the config tree."
        )
        lines.append(
            "The following settings control shell and remote access:"
        )
        lines.append("")

        lines.append("### Telnet / SSH Access (AclServices)")
        lines.append("")
        lines.append("| Setting | Value | Description |")
        lines.append("|---------|-------|-------------|")
        lines.append(
            f"| TELNETLanEnable | "
            f"`{shell_info.get('telnet_lan_enable', 'N/A')}` | "
            f"Telnet access from LAN |"
        )
        lines.append(
            f"| TELNETWanEnable | "
            f"`{shell_info.get('telnet_wan_enable', 'N/A')}` | "
            f"Telnet access from WAN |"
        )
        lines.append(
            f"| TELNETWifiEnable | "
            f"`{shell_info.get('telnet_wifi_enable', 'N/A')}` | "
            f"Telnet access from WiFi |"
        )
        lines.append(
            f"| TELNETPORT | "
            f"`{shell_info.get('telnet_port', 'N/A')}` | "
            f"Telnet port |"
        )
        lines.append(
            f"| SSHLanEnable | "
            f"`{shell_info.get('ssh_lan_enable', 'N/A')}` | "
            f"SSH access from LAN |"
        )
        lines.append(
            f"| SSHWanEnable | "
            f"`{shell_info.get('ssh_wan_enable', 'N/A')}` | "
            f"SSH access from WAN |"
        )
        lines.append(
            f"| SSHPORT | "
            f"`{shell_info.get('ssh_port', 'N/A')}` | "
            f"SSH port |"
        )
        lines.append(
            f"| HTTPPORT | "
            f"`{shell_info.get('http_port', 'N/A')}` | "
            f"Web admin port |"
        )
        lines.append("")

        lines.append("### CLI Telnet Access")
        lines.append("")
        lines.append(
            f"- **X_HW_CLITelnetAccess**: "
            f"`Access={shell_info.get('cli_telnet_access', 'N/A')}`"
        )
        lines.append("")

        if shell_info.get("cli_users"):
            lines.append("### CLI Users (from hw_ctree.xml)")
            lines.append("")
            lines.append("| Username | Password | UserGroup | EncryptMode |")
            lines.append("|----------|----------|-----------|-------------|")
            for u in shell_info["cli_users"]:
                lines.append(
                    f"| `{u['username']}` | `{u['password']}` | "
                    f"`{u['group'] or '(empty)'}` | `{u['encrypt_mode']}` |"
                )
            lines.append("")

        if shell_info.get("web_users"):
            lines.append("### Web Users (from hw_ctree.xml)")
            lines.append("")
            lines.append("| Username | UserLevel | Enable | PassMode |")
            lines.append("|----------|-----------|--------|----------|")
            for u in shell_info["web_users"]:
                level_desc = {
                    "0": "Admin (telecomadmin)",
                    "1": "User (root)",
                    "2": "Guest",
                }
                desc = level_desc.get(u["user_level"], u["user_level"])
                lines.append(
                    f"| `{u['username']}` | `{u['user_level']}` ({desc}) | "
                    f"`{u['enable']}` | `{u['pass_mode']}` |"
                )
            lines.append("")

        # WAP shell activation guide
        lines.append("### How to Activate the WAP Shell")
        lines.append("")
        lines.append(
            "The WAP shell (Huawei CLI) is the built-in command-line "
            "interface accessible via Telnet on port 23. "
            "It provides access to device diagnostics, configuration, "
            "and management commands."
        )
        lines.append("")
        lines.append("**Requirements:**")
        lines.append(
            "- Telnet must be enabled "
            "(`TELNETLanEnable=1` in `AclServices`)"
        )
        lines.append(
            "- CLI Telnet access must be enabled "
            "(`X_HW_CLITelnetAccess Access=1`)"
        )
        lines.append(
            "- Valid CLI credentials "
            "(default: `root` / `admin`)"
        )
        lines.append("")
        lines.append("**Methods to enable the WAP shell:**")
        lines.append("")
        lines.append("1. **Via ONT Tool (OBSC protocol)**:")
        lines.append("   ```")
        lines.append(
            "   # Use the Enable Package feature in the ONT Tool"
        )
        lines.append(
            "   # Package 1 (V3): Enables Telnet + SSH"
        )
        lines.append(
            "   # Package 2 (V5): Factory reset then re-enables Telnet + SSH"
        )
        lines.append(
            "   # Package 3 (new devices): Full upgrade, Telnet then SSH"
        )
        lines.append("   ```")
        lines.append("")
        lines.append("2. **Via cfgtool on the device** (if shell is available):")
        lines.append("   ```bash")
        lines.append("   # Enable Telnet LAN access")
        lines.append(
            '   cfgtool set deftree '
            '"InternetGatewayDevice.X_HW_Security.AclServices" '
            '"TELNETLanEnable" "1"'
        )
        lines.append("   # Enable SSH LAN access")
        lines.append(
            '   cfgtool set deftree '
            '"InternetGatewayDevice.X_HW_Security.AclServices" '
            '"SSHLanEnable" "1"'
        )
        lines.append("   # Enable CLI Telnet access")
        lines.append(
            '   cfgtool set deftree '
            '"InternetGatewayDevice.UserInterface.X_HW_CLITelnetAccess" '
            '"Access" "1"'
        )
        lines.append("   ```")
        lines.append("")
        lines.append(
            "3. **Via config file modification** "
            "(import modified `hw_ctree.xml`):"
        )
        lines.append("")
        lines.append(
            "   Export the config from the web UI, decrypt it, modify the "
            "relevant XML attributes, re-encrypt, and import it back."
        )
        lines.append("")
        lines.append("   Key XML paths to modify:")
        lines.append("   ```xml")
        lines.append(
            '   <AclServices TELNETLanEnable="1" '
            'TELNETWanEnable="0" SSHLanEnable="1" SSHWanEnable="0" '
            'TELNETPORT="23" SSHPORT="22"/>'
        )
        lines.append('   <X_HW_CLITelnetAccess Access="1"/>')
        lines.append(
            '   <X_HW_CLIUserInfoInstance InstanceID="1" '
            'Username="root" Userpassword="admin" UserGroup=""/>'
        )
        lines.append("   ```")
        lines.append("")

    # ── WAN Connections ──────────────────────────────────────────────────
    if wan_info:
        lines.append("## WAN Connection Configuration")
        lines.append("")
        lines.append("| Type | Name | Enable | Connection Type |")
        lines.append("|------|------|--------|-----------------|")
        for w in wan_info:
            lines.append(
                f"| {w.get('type', '')} | `{w.get('name', '')}` | "
                f"`{w.get('enable', '')}` | "
                f"`{w.get('connection_type', '')}` |"
            )
        lines.append("")

    # ── Config Files ─────────────────────────────────────────────────────
    if configs:
        lines.append("## Configuration Files")
        lines.append("")
        lines.append("| File | Format | Size | Elements | Attributes |")
        lines.append("|------|--------|------|----------|------------|")
        for c in configs:
            lines.append(
                f"| `{c['filename']}` | {c['format']} | "
                f"{c['size']:,} B | {c['elements']} | {c['attributes']} |"
            )
        lines.append("")

    # ── Binary Analysis ──────────────────────────────────────────────────
    if binaries:
        lines.append("## Binary Analysis")
        lines.append("")
        for b in binaries:
            if not b["is_elf"]:
                continue
            lines.append(f"### `{os.path.basename(b['path'])}`")
            lines.append("")
            lines.append(f"- **Size**: {b['size']:,} bytes")
            lines.append(f"- **Architecture**: {b['arch']}")
            lines.append(f"- **Type**: {b['type']}")
            lines.append(f"- **Imports**: {len(b['imports'])}")
            lines.append(f"- **Exports**: {len(b['exports'])}")
            lines.append("")

            if b["imports"]:
                lines.append("**Key imports:**")
                lines.append("")
                for imp in b["imports"][:30]:
                    lines.append(f"- `{imp}`")
                if len(b["imports"]) > 30:
                    lines.append(
                        f"- ... and {len(b['imports']) - 30} more"
                    )
                lines.append("")

            if b["exports"]:
                lines.append("**Key exports:**")
                lines.append("")
                for exp in b["exports"][:30]:
                    lines.append(f"- `{exp}`")
                if len(b["exports"]) > 30:
                    lines.append(
                        f"- ... and {len(b['exports']) - 30} more"
                    )
                lines.append("")

    # ── Decryption Info ──────────────────────────────────────────────────
    lines.append("## Decryption")
    lines.append("")
    lines.append(
        "The `hw_ctree.xml` configuration tree is encrypted with "
        "AES-256-CBC. The encryption key is derived from the device's "
        "hardware e-fuse via PBKDF2."
    )
    lines.append("")
    lines.append("### Methods to decrypt hw_ctree.xml")
    lines.append("")
    lines.append(
        "1. **Using the firmware's own aescrypt2** (via qemu-arm-static "
        "chroot):"
    )
    lines.append("   ```bash")
    lines.append(
        "   sudo cp /usr/bin/qemu-arm-static rootfs/usr/bin/"
    )
    lines.append(
        "   sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 "
        "/etc/wap/hw_ctree.xml /tmp/out.xml"
    )
    lines.append("   gunzip /tmp/out.xml.gz")
    lines.append("   ```")
    lines.append("")
    lines.append(
        "2. **Using this tool's crypto module** (for web-exported configs):"
    )
    lines.append("   ```python")
    lines.append("   from hwflash.core.crypto import try_decrypt_all_keys")
    lines.append('   with open("config_backup.xml", "rb") as f:')
    lines.append("       data = f.read()")
    lines.append("   results = try_decrypt_all_keys(data)")
    lines.append("   if results:")
    lines.append("       chip_id, xml_content = results[0]")
    lines.append("   ```")
    lines.append("")
    lines.append("### Known chip IDs for backup config decryption")
    lines.append("")
    for cid in KNOWN_CHIP_IDS:
        lines.append(f"- `{cid}`")
    lines.append("")

    return "\n".join(lines)


# ── Main Analysis Pipeline ───────────────────────────────────────────────────


def analyze_extracted_configs(
    configs_dir: str, isp: Optional[str] = None
) -> str:
    """Analyze pre-extracted firmware configs in the repository.

    This works with the ``extracted_configs/`` directory that already
    contains decrypted XML files from previous extraction runs.
    """
    if not os.path.isdir(configs_dir):
        return f"Directory not found: {configs_dir}"

    all_reports: list[str] = []

    for fw_dir_name in sorted(os.listdir(configs_dir)):
        fw_dir = os.path.join(configs_dir, fw_dir_name)
        if not os.path.isdir(fw_dir):
            continue

        # Look for decrypted ctree
        decrypted_path = os.path.join(fw_dir, "hw_ctree_decrypted.xml")
        if not os.path.isfile(decrypted_path):
            continue

        print(f"Analyzing: {fw_dir_name}")

        # Read decrypted XML
        try:
            with open(decrypted_path, "r", encoding="utf-8", errors="replace") as f:
                xml_text = f.read()
        except OSError:
            continue

        # Extract shell/WAP info
        shell_info = extract_shell_access_info(xml_text)
        wan_info = extract_wan_info(xml_text)

        # Analyze config files in the directory
        configs: list[Dict[str, Any]] = []
        for fn in sorted(os.listdir(fw_dir)):
            fp = os.path.join(fw_dir, fn)
            if os.path.isfile(fp):
                configs.append(analyze_config_file(fp))

        # Generate per-firmware report
        report = generate_analysis_report(
            firmware_name=fw_dir_name,
            configs=configs,
            binaries=[],
            shell_info=shell_info,
            wan_info=wan_info,
            isp=isp,
        )
        all_reports.append(report)

    return "\n\n---\n\n".join(all_reports)


def analyze_firmware_file(
    fw_path: str,
    out_dir: str,
    isp: Optional[str] = None,
) -> str:
    """Analyze a single firmware .bin file."""
    import shutil
    import subprocess
    import tempfile

    os.makedirs(out_dir, exist_ok=True)
    fw_name = Path(fw_path).stem

    print(f"Reading firmware: {fw_path}")
    with open(fw_path, "rb") as f:
        data = f.read()

    sqfs_list = find_squashfs(data)
    if not sqfs_list:
        return f"No SquashFS found in {fw_path}"

    print(f"Found {len(sqfs_list)} SquashFS image(s)")

    # Extract the largest SquashFS (rootfs)
    offset, size = sqfs_list[0]
    print(f"Extracting rootfs at 0x{offset:08x} ({size:,} bytes)")

    rootfs_dir = tempfile.mkdtemp(prefix="rootfs_")
    try:
        img_path = os.path.join(rootfs_dir, "rootfs.sqfs")
        with open(img_path, "wb") as f:
            f.write(data[offset: offset + size])

        result = subprocess.run(
            [
                "unsquashfs", "-no-xattrs", "-ignore-errors",
                "-d", os.path.join(rootfs_dir, "rootfs"),
                "-f", img_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        rootfs = os.path.join(rootfs_dir, "rootfs")
        if not os.path.isdir(rootfs):
            return f"Failed to extract SquashFS from {fw_path}"

        # Analyze config files
        configs: list[Dict[str, Any]] = []
        wap_dir = os.path.join(rootfs, "etc", "wap")
        if os.path.isdir(wap_dir):
            for fn in KEY_CONFIGS:
                fp = os.path.join(wap_dir, fn)
                if os.path.isfile(fp):
                    cfg = analyze_config_file(fp)
                    configs.append(cfg)
                    # Copy to output
                    dst = os.path.join(out_dir, fn)
                    shutil.copy2(fp, dst)

        # Analyze binaries
        binaries: list[Dict[str, Any]] = []
        for rel_path in KEY_BINARIES:
            fp = os.path.join(rootfs, rel_path)
            if os.path.isfile(fp):
                b = analyze_elf_imports(fp)
                binaries.append(b)
                # Copy to output
                dst = os.path.join(out_dir, os.path.basename(rel_path))
                shutil.copy2(fp, dst)

        # Try decrypting hw_ctree.xml
        shell_info = None
        wan_info: list[Dict[str, str]] = []
        ctree_path = os.path.join(wap_dir, "hw_ctree.xml")
        if os.path.isfile(ctree_path):
            dec_result = try_decrypt_ctree(ctree_path)
            if dec_result:
                chip_id, xml_text = dec_result
                print(f"Decrypted hw_ctree.xml with chip ID: {chip_id}")
                # Save decrypted
                dec_path = os.path.join(out_dir, "hw_ctree_decrypted.xml")
                with open(dec_path, "w", encoding="utf-8") as f:
                    f.write(xml_text)
                shell_info = extract_shell_access_info(xml_text)
                wan_info = extract_wan_info(xml_text)
            else:
                print(
                    "Could not decrypt hw_ctree.xml with known chip IDs "
                    "(device-specific key required)"
                )

        # Check for pre-existing decrypted configs
        if shell_info is None:
            configs_dir = _REPO / "extracted_configs"
            for d in configs_dir.iterdir():
                if d.is_dir() and fw_name in d.name:
                    dec = d / "hw_ctree_decrypted.xml"
                    if dec.is_file():
                        xml_text = dec.read_text(encoding="utf-8", errors="replace")
                        shell_info = extract_shell_access_info(xml_text)
                        wan_info = extract_wan_info(xml_text)
                        break

        report = generate_analysis_report(
            firmware_name=fw_name,
            configs=configs,
            binaries=binaries,
            shell_info=shell_info,
            wan_info=wan_info,
            isp=isp,
        )

        # Save report
        report_path = os.path.join(out_dir, "ANALYSIS.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report saved: {report_path}")

        return report

    finally:
        shutil.rmtree(rootfs_dir, ignore_errors=True)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive Huawei ONT firmware analysis tool"
    )
    parser.add_argument(
        "firmware",
        nargs="?",
        help="Path to firmware .bin file. If omitted, analyzes "
        "pre-extracted configs from the repository.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="analysis_output",
        help="Output directory (default: analysis_output/)",
    )
    parser.add_argument(
        "--isp",
        default=None,
        help="ISP name for targeted analysis "
        "(e.g. megacable, mega, megacable2)",
    )
    parser.add_argument(
        "--configs-dir",
        default=None,
        help="Directory with pre-extracted firmware configs "
        "(default: extracted_configs/)",
    )
    args = parser.parse_args()

    # Normalize ISP
    isp = args.isp
    if isp:
        isp = isp.lower().strip()
        # Map aliases to canonical name
        for canonical, aliases in ISP_ALIASES.items():
            if isp in aliases:
                isp = canonical
                break

    if args.firmware:
        report = analyze_firmware_file(args.firmware, args.output, isp)
    else:
        # Use pre-extracted configs
        configs_dir = args.configs_dir
        if configs_dir is None:
            configs_dir = str(_REPO / "extracted_configs")
        report = analyze_extracted_configs(configs_dir, isp)

        # Save combined report
        os.makedirs(args.output, exist_ok=True)
        report_path = os.path.join(args.output, "ANALYSIS.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\nReport saved: {report_path}")

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()
