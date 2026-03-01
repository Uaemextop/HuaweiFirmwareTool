#!/usr/bin/env python3
"""
cli_security_analysis.py – EG8145V5 CLI (clid) security analysis tool.

Analyzes a decrypted hw_ctree.xml for known vulnerabilities and generates
a markdown report documenting the findings from reverse-engineering the
clid binary and associated configuration.

Usage
-----
    # Generate report (no XML needed, uses built-in findings)
    python3 tools/cli_security_analysis.py

    # Analyze a specific decrypted hw_ctree.xml and generate report
    python3 tools/cli_security_analysis.py --xml decrypted_hw_ctree.xml

    # Custom output path
    python3 tools/cli_security_analysis.py --output /tmp/report.md
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


# ── Known CmdGroup bitmask values from clid binary ──────────────────────

CMDGROUP_BITMASKS: Dict[int, str] = {
    0x00000010: "Basic user (read-only, very limited)",
    0x00002000: "Carrier / ISP commands",
    0x00004000: "Admin (partial)",
    0x00004010: "Admin + basic (most display commands)",
    0x80000000: "Super admin / engineer mode",
    0x80000010: "Super + basic",
    0x80002000: "Super + carrier",
    0x80004000: "Super + admin",
    0x80004010: "Super + admin + basic",
    0x10000000: "Hidden / factory mode",
}

# ── Feature flags from clid binary strings ───────────────────────────────

FEATURE_FLAGS: Dict[str, str] = {
    "FT_CLI_DEFAULT_TO_SHELL": "When enabled, CLI defaults to Linux shell",
    "SSMP_FT_TDE_OPEN_SHELL": "TDE open shell feature",
    "SSMP_FT_TDE_AUTH_SU_CMD": "SU command authentication",
    "SSMP_SPEC_CLI_ENABLE": "CLI enable/disable",
    "SSMP_SPEC_CLI_CUSTOMIZE_CMDLIST": "Custom command list file path",
    "FT_CLI_SECURITY_ACCESS": "Security access control",
}

# ── Shell access function call chain from clid disassembly ───────────────

SHELL_CALL_CHAIN = """\
HW_CLI_Shell
  → HW_CLI_LoginTty → HW_CLI_SetShellTtyAttr
       → SSP_ExecSysCmd → /bin/sh

HW_CLI_InnerShell / HW_CLI_InnerShellEx
  → SSP_ExecShellCmd

CLI_ToShellDirect   → directly enters shell
CLI_ToShellDefault  → enters shell with default settings

HW_CLI_SU_Mode
  → "Notice: Already in SU mode" / prompts for su password
  → HW_CLI_VerifySuPassword (uses su_pub_key)"""

# ── Key CLI commands restricted by CmdGroup ──────────────────────────────

RESTRICTED_COMMANDS: List[Dict[str, str]] = [
    {"cmd": "display password", "risk": "HIGH", "note": "Shows stored passwords"},
    {"cmd": "set userpasswd", "risk": "HIGH", "note": "Changes user passwords"},
    {"cmd": "display current-configuration", "risk": "HIGH", "note": "Full config dump"},
    {"cmd": "load cfg", "risk": "HIGH", "note": "Load config from file"},
    {"cmd": "backup cfg", "risk": "MEDIUM", "note": "Backup config to file"},
    {"cmd": "save data", "risk": "MEDIUM", "note": "Save running config to flash"},
    {"cmd": "reset", "risk": "CRITICAL", "note": "Factory reset"},
    {"cmd": "restore default configuration", "risk": "CRITICAL", "note": "Restore defaults"},
    {"cmd": "ssh remote", "risk": "HIGH", "note": "SSH to remote host"},
    {"cmd": "telnet remote", "risk": "HIGH", "note": "Telnet to remote host"},
    {"cmd": "display version", "risk": "LOW", "note": "Show firmware version"},
    {"cmd": "display firmware version", "risk": "LOW", "note": "Show firmware version"},
]

# ── BusyBox SUID applets ─────────────────────────────────────────────────

BUSYBOX_SUID_APPLETS = [
    "arping", "login", "passwd", "ping", "ping6",
    "su", "traceroute", "traceroute6",
]


# ─────────────────────────────────────────────────────────────────────────
# XML Analysis helpers
# ─────────────────────────────────────────────────────────────────────────

def _parse_cli_users(xml_text: str) -> List[Dict[str, str]]:
    """Extract X_HW_CLIUserInfoInstance attributes."""
    users: List[Dict[str, str]] = []
    for m in re.finditer(
        r"<X_HW_CLIUserInfoInstance\b([^>]*)/>", xml_text
    ):
        attrs: Dict[str, str] = {}
        for attr_m in re.finditer(r'(\w+)="([^"]*)"', m.group(1)):
            attrs[attr_m.group(1)] = attr_m.group(2)
        users.append(attrs)
    return users


def _parse_acl_services(xml_text: str) -> List[Dict[str, str]]:
    """Extract AclServices attributes."""
    services: List[Dict[str, str]] = []
    for m in re.finditer(r"<AclServices\b([^>]*)/?>", xml_text):
        attrs: Dict[str, str] = {}
        for attr_m in re.finditer(r'(\w+)="([^"]*)"', m.group(1)):
            attrs[attr_m.group(1)] = attr_m.group(2)
        services.append(attrs)
    return services


def _parse_telnet_access(xml_text: str) -> List[Dict[str, str]]:
    """Extract X_HW_CLITelnetAccess attributes."""
    entries: List[Dict[str, str]] = []
    for m in re.finditer(r"<X_HW_CLITelnetAccess\b([^>]*)/?>", xml_text):
        attrs: Dict[str, str] = {}
        for attr_m in re.finditer(r'(\w+)="([^"]*)"', m.group(1)):
            attrs[attr_m.group(1)] = attr_m.group(2)
        entries.append(attrs)
    return entries


def analyze_xml(xml_text: str) -> Dict[str, object]:
    """Analyze a decrypted hw_ctree.xml and return findings."""
    findings: Dict[str, object] = {
        "cli_users": _parse_cli_users(xml_text),
        "acl_services": _parse_acl_services(xml_text),
        "telnet_access": _parse_telnet_access(xml_text),
        "vulnerabilities": [],
    }

    vulns: List[str] = []

    for user in findings["cli_users"]:
        ug = user.get("UserGroup", "")
        pw = user.get("Userpassword", "")
        name = user.get("Username", "?")
        if ug == "" or ug == "0":
            vulns.append(
                f"CLI user '{name}' has empty/zero UserGroup → restricted to "
                f"exit and getcustomerinfo only"
            )
        if pw and pw.lower() in ("admin", "root", "1234", ""):
            vulns.append(
                f"CLI user '{name}' has weak/default password: '{pw}'"
            )

    for svc in findings["acl_services"]:
        if svc.get("TELNETLanEnable") == "1":
            vulns.append("Telnet is enabled on LAN (plaintext credentials)")
        if svc.get("TELNETWanEnable") == "1":
            vulns.append("Telnet is enabled on WAN (critical exposure)")
        if svc.get("SSHLanEnable") != "1":
            vulns.append("SSH is disabled on LAN (Telnet-only management)")

    findings["vulnerabilities"] = vulns
    return findings


# ─────────────────────────────────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────────────────────────────────

def generate_report(
    xml_findings: Optional[Dict[str, object]] = None,
) -> str:
    """Generate the full markdown security analysis report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sections: List[str] = []

    # ── Header ──
    sections.append(
        f"# EG8145V5 CLI Security Analysis Report\n"
        f"> Generated by `tools/cli_security_analysis.py` — {ts}\n"
        f"> Firmware: EG8145V5-V500R022C00SPC340B019\n"
        f"> Target binary: `/bin/clid` (ARM, ~2.5 MB)\n"
    )

    # ── 1. CmdGroup bitmask ──
    rows = "\n".join(
        f"| `0x{mask:08X}` | {desc} |"
        for mask, desc in sorted(CMDGROUP_BITMASKS.items())
    )
    sections.append(
        f"## 1. CmdGroup Access Level Bitmask System\n\n"
        f"The CLI uses a bitmask to control per-command access. Each command "
        f"in `hw_cli.xml` has a `CmdGroup` attribute; the user's `UserGroup` "
        f"must have the matching bits set.\n\n"
        f"| Bitmask | Description |\n"
        f"|---------|-------------|\n"
        f"{rows}\n\n"
        f"Setting `UserGroup=\"0xFFFFFFFF\"` grants access to **all** command "
        f"groups (600+ commands).\n"
    )

    # ── 2. Equipment Test Mode ──
    sections.append(
        "## 2. Equipment Test Mode Backdoor\n\n"
        "The clid binary contains the strings `huaweiequiptestmode-on` and "
        "`huaweiequiptestmode-off`.\n\n"
        "**Trigger:** When the file `/mnt/jffs2/equiptestmode` exists on the "
        "filesystem, the device enters Equipment Test Mode with elevated "
        "privileges.\n\n"
        "**Related functions:**\n"
        "- `HW_CLI_SetEquipTestMode`\n"
        "- `HW_CLI_RPC_GetEquipTestMode`\n"
        "- `HW_SSP_IsDebugMode`\n\n"
        "In this mode, additional diagnostic and configuration commands become "
        "available regardless of the user's `UserGroup` setting.\n"
    )

    # ── 3. Feature flags ──
    flag_rows = "\n".join(
        f"| `{flag}` | {desc} |" for flag, desc in FEATURE_FLAGS.items()
    )
    sections.append(
        f"## 3. Feature Flags Controlling Shell Access\n\n"
        f"These compile-time / runtime feature flags were found in the clid "
        f"binary strings:\n\n"
        f"| Flag | Description |\n"
        f"|------|-------------|\n"
        f"{flag_rows}\n"
    )

    # ── 4. Shell access flow ──
    sections.append(
        f"## 4. Shell Access Call Chain (clid disassembly)\n\n"
        f"```\n{SHELL_CALL_CHAIN}\n```\n\n"
        f"The key entry points are `CLI_ToShellDirect` (no auth) and "
        f"`HW_CLI_SU_Mode` (requires su password verified against "
        f"`su_pub_key`).\n"
    )

    # ── 5. hw_ctree.xml vulnerabilities ──
    sections.append("## 5. Configuration Vulnerabilities (hw_ctree.xml)\n")

    if xml_findings:
        users = xml_findings.get("cli_users", [])
        if users:
            sections.append("### CLI Users Found\n")
            sections.append(
                "| Username | Password | UserGroup | EncryptMode |"
            )
            sections.append(
                "|----------|----------|-----------|-------------|"
            )
            for u in users:
                sections.append(
                    f"| `{u.get('Username', '?')}` "
                    f"| `{u.get('Userpassword', '?')}` "
                    f"| `{u.get('UserGroup', '')}` "
                    f"| {u.get('EncryptMode', '?')} |"
                )
            sections.append("")

        svcs = xml_findings.get("acl_services", [])
        if svcs:
            sections.append("### ACL Services\n")
            for s in svcs:
                for k, v in sorted(s.items()):
                    sections.append(f"- **{k}**: `{v}`")
            sections.append("")

        vulns = xml_findings.get("vulnerabilities", [])
        if vulns:
            sections.append("### Detected Vulnerabilities\n")
            for i, v in enumerate(vulns, 1):
                sections.append(f"{i}. ⚠️  {v}")
            sections.append("")
    else:
        sections.append(
            "### Known Default Configuration\n\n"
            "From the decrypted hw_ctree.xml (key index 1):\n\n"
            "```xml\n"
            '<X_HW_CLIUserInfoInstance InstanceID="1" Username="root"\n'
            '    Userpassword="admin" UserGroup="" ModifyPWDFlag="0"\n'
            '    EncryptMode="3"/>\n'
            '<X_HW_CLITelnetAccess Access="1"/>\n'
            '<AclServices TELNETLanEnable="1" TELNETWanEnable="0"\n'
            '    SSHLanEnable="0" TELNETPORT="23" SSHPORT="22"/>\n'
            "```\n\n"
            "**Issues:**\n"
            '1. CLI user `root` has password `admin` with `UserGroup=""` '
            "(empty = most restricted)\n"
            "2. Telnet enabled on LAN with plaintext credentials\n"
            "3. SSH disabled — management is Telnet-only\n"
        )

    # ── 6. UserGroup values ──
    sections.append(
        "## 6. UserGroup Values and Command Access\n\n"
        "The `UserGroup` attribute on `X_HW_CLIUserInfoInstance` controls "
        "which `CmdGroup` commands are available to that user.\n\n"
        '- **Empty** `UserGroup=""` → most restricted (only `exit` and '
        "`getcustomerinfo`)\n"
        "- Bits must match the command's `CmdGroup` for it to appear\n"
        '- `UserGroup="0xFFFFFFFF"` → access to **ALL** 600+ commands\n'
    )

    # ── 7. BusyBox ──
    applets = ", ".join(f"`{a}`" for a in BUSYBOX_SUID_APPLETS)
    sections.append(
        "## 7. BusyBox Analysis\n\n"
        "- **Version:** busybox v1.32.1 with 166 applets\n"
        "- Includes: `ash`, `sh`, `telnet`, `wget`, `tftp`, `ftpget`, "
        "`ftpput`\n"
        f"- **busybox.suid** (79 KB, 8 SUID applets): {applets}\n\n"
        "The `su` SUID applet allows privilege escalation if the su password "
        "is known.\n"
    )

    # ── 8. Restricted CLI commands ──
    cmd_rows = "\n".join(
        f"| `{c['cmd']}` | {c['risk']} | {c['note']} |"
        for c in RESTRICTED_COMMANDS
    )
    sections.append(
        f"## 8. Key CLI Commands Restricted by CmdGroup\n\n"
        f"The WAP CLI has 600+ commands defined in `hw_cli.xml`. "
        f"Key commands gated by CmdGroup:\n\n"
        f"| Command | Risk | Note |\n"
        f"|---------|------|------|\n"
        f"{cmd_rows}\n"
    )

    # ── 9. Bypass via hw_ctree.xml modification ──
    sections.append(
        "## 9. Bypass: Modifying hw_ctree.xml for Full Shell Access\n\n"
        "### Steps\n\n"
        "1. **Decrypt** the hw_ctree.xml from NAND/backup:\n"
        "   ```bash\n"
        "   # Using the firmware tool's decrypt_ctree pipeline\n"
        "   python3 tools/decrypt_ctree.py --dump NAND.BIN --out keys/\n"
        "   # Or with aescrypt2 directly (key index 1)\n"
        "   aescrypt2 1 hw_ctree.xml decrypted.xml\n"
        "   ```\n\n"
        "2. **Modify** the decrypted XML using `ctree_modifier.py`:\n"
        "   ```bash\n"
        "   # Grant full command access to root user\n"
        "   python3 tools/ctree_modifier.py -i decrypted.xml \\\n"
        "       --set-usergroup root 0xFFFFFFFF\n\n"
        "   # Enable SSH and FTP\n"
        "   python3 tools/ctree_modifier.py -i decrypted.xml \\\n"
        "       --enable-ssh --enable-ftp\n"
        "   ```\n\n"
        "   Or manually edit:\n"
        "   ```xml\n"
        '   <!-- Change UserGroup to full access -->\n'
        '   <X_HW_CLIUserInfoInstance ... UserGroup="0xFFFFFFFF" .../>\n\n'
        '   <!-- Enable SSH on LAN -->\n'
        '   <AclServices ... SSHLanEnable="1" .../>\n\n'
        '   <!-- Enable FTP on LAN -->\n'
        '   <AclServices ... FTPLanEnable="1" .../>\n'
        "   ```\n\n"
        "3. **Re-encrypt** and flash:\n"
        "   ```bash\n"
        "   aescrypt2 0 decrypted.xml hw_ctree.xml\n"
        "   ```\n\n"
        "4. **Upload** the modified hw_ctree.xml back to the device "
        "(via TFTP, backup restore, or direct NAND write).\n"
    )

    # ── 10. Recommendations ──
    sections.append(
        "## 10. Security Recommendations\n\n"
        "1. **Change default CLI passwords** — `root`/`admin` is trivially "
        "guessable.\n"
        "2. **Disable Telnet**, enable SSH — Telnet transmits credentials in "
        "plaintext.\n"
        "3. **Restrict WAN management** — ensure `TELNETWanEnable` and "
        "`SSHWanEnable` are `0`.\n"
        "4. **Monitor for equiptestmode file** — its presence indicates "
        "backdoor activation.\n"
        "5. **Use per-user CmdGroup limits** — avoid `0xFFFFFFFF` in "
        "production.\n"
        "6. **Encrypt config backups** — decrypted hw_ctree.xml exposes all "
        "credentials.\n"
    )

    return "\n---\n\n".join(sections)


# ─────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze EG8145V5 CLI security and generate a report from "
            "clid binary findings and optional hw_ctree.xml analysis."
        )
    )
    parser.add_argument(
        "--xml", type=Path, default=None,
        help="Path to a decrypted hw_ctree.xml for live analysis",
    )
    parser.add_argument(
        "--output", "-o", type=Path,
        default=Path("decompiled/CLI_SECURITY_ANALYSIS.md"),
        help="Output report path (default: decompiled/CLI_SECURITY_ANALYSIS.md)",
    )

    args = parser.parse_args(argv)

    xml_findings = None
    if args.xml and args.xml.is_file():
        print(f"[*] Analyzing {args.xml} ...")
        xml_text = args.xml.read_text(encoding="utf-8", errors="replace")
        xml_findings = analyze_xml(xml_text)
        users = xml_findings.get("cli_users", [])
        vulns = xml_findings.get("vulnerabilities", [])
        print(f"    Found {len(users)} CLI user(s), {len(vulns)} issue(s)")
    elif args.xml:
        print(
            f"[!] {args.xml} not found — using built-in findings only",
            file=sys.stderr,
        )

    report = generate_report(xml_findings)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"[+] Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
