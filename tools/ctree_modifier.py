#!/usr/bin/env python3
"""
ctree_modifier.py – Modify decrypted Huawei hw_ctree.xml configuration.

Provides functions to patch CLI user access levels, enable/disable
services (SSH, Telnet, FTP), and adjust security settings in a
decrypted hw_ctree.xml file.

Usage
-----
    # Set CLI user "root" to full command access
    python3 tools/ctree_modifier.py --input decrypted.xml --set-usergroup root 0xFFFFFFFF

    # Enable SSH on LAN
    python3 tools/ctree_modifier.py --input decrypted.xml --enable-ssh

    # Apply multiple modifications
    python3 tools/ctree_modifier.py --input decrypted.xml \\
        --set-usergroup root 0xFFFFFFFF --enable-ssh --enable-ftp \\
        --output modified.xml
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# 0xFFFFFFFF – matches every CmdGroup bitmask, unlocking all 600+ commands.
USERGROUP_ALL = "4294967295"


def _read_xml_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _write_xml_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def set_cli_user_group(
    xml_text: str, username: str, user_group: str
) -> Tuple[str, bool]:
    """Set the UserGroup attribute for a CLI user in hw_ctree.xml.

    The UserGroup bitmask controls which CmdGroup commands are available.
    Setting it to ``0xFFFFFFFF`` grants access to all command groups.

    Returns the modified XML text and whether a change was made.
    """
    pattern = re.compile(
        r'(<X_HW_CLIUserInfoInstance\b[^>]*\bUsername="'
        + re.escape(username)
        + r'"[^>]*\bUserGroup=)"([^"]*)"'
    )
    new_text, count = pattern.subn(r'\g<1>"' + user_group + '"', xml_text)
    return new_text, count > 0


def set_acl_service(
    xml_text: str, service_attr: str, value: str
) -> Tuple[str, bool]:
    """Set an AclServices attribute (e.g. SSHLanEnable) to *value*.

    Returns the modified XML text and whether a change was made.
    """
    pattern = re.compile(
        r"(<AclServices\b[^>]*\b" + re.escape(service_attr) + r'=)"([^"]*)"'
    )
    new_text, count = pattern.subn(r'\g<1>"' + value + '"', xml_text)
    return new_text, count > 0


def enable_ssh(xml_text: str) -> Tuple[str, bool]:
    """Enable SSH on the LAN interface."""
    return set_acl_service(xml_text, "SSHLanEnable", "1")


def enable_ftp(xml_text: str) -> Tuple[str, bool]:
    """Enable FTP on the LAN interface."""
    return set_acl_service(xml_text, "FTPLanEnable", "1")


def enable_telnet(xml_text: str) -> Tuple[str, bool]:
    """Enable Telnet on the LAN interface."""
    return set_acl_service(xml_text, "TELNETLanEnable", "1")


def list_cli_users(xml_text: str) -> List[dict]:
    """Return a list of CLI user dicts parsed from the XML."""
    users: List[dict] = []
    for m in re.finditer(
        r"<X_HW_CLIUserInfoInstance\b([^>]*)/>", xml_text
    ):
        attrs: dict = {}
        for attr_m in re.finditer(r'(\w+)="([^"]*)"', m.group(1)):
            attrs[attr_m.group(1)] = attr_m.group(2)
        users.append(attrs)
    return users


def list_acl_services(xml_text: str) -> List[dict]:
    """Return AclServices attributes parsed from the XML."""
    services: List[dict] = []
    for m in re.finditer(r"<AclServices\b([^>]*)/?>", xml_text):
        attrs: dict = {}
        for attr_m in re.finditer(r'(\w+)="([^"]*)"', m.group(1)):
            attrs[attr_m.group(1)] = attr_m.group(2)
        services.append(attrs)
    return services


def set_web_user_level(
    xml_text: str, username: str, level: str
) -> Tuple[str, bool]:
    """Set UserLevel for a web user (0=admin, 1=regular).

    Returns the modified XML text and whether a change was made.
    """
    pattern = re.compile(
        r'(<X_HW_WebUserInfoInstance\b[^>]*\bUserName="'
        + re.escape(username)
        + r'"[^>]*\bUserLevel=)"([^"]*)"'
    )
    new_text, count = pattern.subn(r'\g<1>"' + level + '"', xml_text)
    return new_text, count > 0


def enable_ftp_service(xml_text: str) -> Tuple[str, bool]:
    """Enable the FTP file-transfer service (X_HW_ServiceManage)."""
    pattern = re.compile(
        r'(<X_HW_ServiceManage\b[^>]*\bFtpEnable=)"([^"]*)"'
    )
    new_text, count = pattern.subn(r'\g<1>"1"', xml_text)
    return new_text, count > 0


def disable_cwmp(xml_text: str) -> Tuple[str, bool]:
    """Disable TR-069/CWMP so the ISP cannot push config changes remotely.

    Returns the modified XML text and whether a change was made.
    """
    pattern = re.compile(
        r'(<ManagementServer\b[^>]*\bEnableCWMP=)"([^"]*)"'
    )
    new_text, count = pattern.subn(r'\g<1>"0"', xml_text)
    return new_text, count > 0


def disable_reset_flag(xml_text: str) -> Tuple[str, bool]:
    """Set ``X_HW_PSIXmlReset ResetFlag`` to ``"0"``.

    When ``ResetFlag="1"`` the modem restores factory defaults after a
    config import via the web interface, reverting all modifications.
    Setting it to ``"0"`` prevents this automatic reset.

    Returns the modified XML text and whether a change was made.
    """
    pattern = re.compile(
        r'(<X_HW_PSIXmlReset\b[^>]*\bResetFlag=)"1"'
    )
    new_text, count = pattern.subn(r'\g<1>"0"', xml_text)
    return new_text, count > 0


def set_inform_interval(xml_text: str, interval: str = "0") -> Tuple[str, bool]:
    """Set ``PeriodicInformEnable`` to ``"0"`` to stop periodic ISP check-ins.

    Returns the modified XML text and whether a change was made.
    """
    pattern = re.compile(
        r'(<ManagementServer\b[^>]*\bPeriodicInformEnable=)"([^"]*)"'
    )
    new_text, count = pattern.subn(r'\g<1>"' + interval + '"', xml_text)
    return new_text, count > 0


def unlock_all(xml_text: str, username: str = "root") -> Tuple[str, List[str]]:
    """Apply all modifications to unlock full access for *username*.

    Returns the modified XML text and a list of change descriptions.
    """
    changes: List[str] = []

    xml_text, ok = set_cli_user_group(xml_text, username, USERGROUP_ALL)
    if ok:
        changes.append(f"CLI UserGroup for '{username}' → 0xFFFFFFFF (all commands)")

    xml_text, ok = set_web_user_level(xml_text, username, "0")
    if ok:
        changes.append(f"Web UserLevel for '{username}' → 0 (admin)")

    xml_text, ok = enable_ssh(xml_text)
    if ok:
        changes.append("SSHLanEnable → 1")

    xml_text, ok = enable_ftp(xml_text)
    if ok:
        changes.append("FTPLanEnable → 1")

    xml_text, ok = enable_telnet(xml_text)
    if ok:
        changes.append("TELNETLanEnable → 1")

    xml_text, ok = enable_ftp_service(xml_text)
    if ok:
        changes.append("FtpEnable → 1 (service)")

    xml_text, ok = disable_cwmp(xml_text)
    if ok:
        changes.append("EnableCWMP → 0 (prevent ISP config push)")

    xml_text, ok = disable_reset_flag(xml_text)
    if ok:
        changes.append("PSIXmlReset ResetFlag → 0 (prevent factory reset on import)")

    xml_text, ok = set_inform_interval(xml_text, "0")
    if ok:
        changes.append("PeriodicInformEnable → 0 (stop ISP check-ins)")

    return xml_text, changes


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Modify decrypted Huawei hw_ctree.xml configuration"
    )
    parser.add_argument(
        "--input", "-i", required=True, type=Path,
        help="Path to decrypted hw_ctree.xml",
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output path (defaults to overwriting input)",
    )
    parser.add_argument(
        "--set-usergroup", nargs=2, metavar=("USER", "GROUP"),
        help='Set UserGroup for a CLI user, e.g. root 0xFFFFFFFF',
    )
    parser.add_argument("--enable-ssh", action="store_true")
    parser.add_argument("--enable-ftp", action="store_true")
    parser.add_argument("--enable-telnet", action="store_true")
    parser.add_argument("--disable-cwmp", action="store_true",
                        help="Disable TR-069/CWMP (prevent ISP config push)")
    parser.add_argument("--disable-reset-flag", action="store_true",
                        help="Set PSIXmlReset ResetFlag to 0 (prevent factory reset on import)")
    parser.add_argument("--disable-periodic-inform", action="store_true",
                        help="Disable PeriodicInformEnable (stop ISP check-ins)")
    parser.add_argument(
        "--set-web-level", nargs=2, metavar=("USER", "LEVEL"),
        help="Set web UserLevel (0=admin, 1=regular)",
    )
    parser.add_argument(
        "--unlock-all", metavar="USER", nargs="?", const="root",
        help="Apply all unlocks for USER (default: root)",
    )
    parser.add_argument(
        "--list-users", action="store_true",
        help="List CLI users and exit",
    )
    parser.add_argument(
        "--list-services", action="store_true",
        help="List AclServices and exit",
    )

    args = parser.parse_args(argv)
    if not args.input.is_file():
        print(f"Error: {args.input} not found", file=sys.stderr)
        return 1

    xml_text = _read_xml_text(args.input)

    if args.list_users:
        for u in list_cli_users(xml_text):
            print(u)
        return 0

    if args.list_services:
        for s in list_acl_services(xml_text):
            print(s)
        return 0

    changes: List[str] = []

    if args.unlock_all:
        xml_text, unlock_changes = unlock_all(xml_text, args.unlock_all)
        changes.extend(unlock_changes)

    if args.set_usergroup:
        user, group = args.set_usergroup
        xml_text, changed = set_cli_user_group(xml_text, user, group)
        if changed:
            changes.append(f"UserGroup for '{user}' → {group}")

    if args.set_web_level:
        user, level = args.set_web_level
        xml_text, changed = set_web_user_level(xml_text, user, level)
        if changed:
            changes.append(f"Web UserLevel for '{user}' → {level}")

    if args.enable_ssh:
        xml_text, changed = enable_ssh(xml_text)
        if changed:
            changes.append("SSHLanEnable → 1")

    if args.enable_ftp:
        xml_text, changed = enable_ftp(xml_text)
        if changed:
            changes.append("FTPLanEnable → 1")

    if args.enable_telnet:
        xml_text, changed = enable_telnet(xml_text)
        if changed:
            changes.append("TELNETLanEnable → 1")

    if args.disable_cwmp:
        xml_text, changed = disable_cwmp(xml_text)
        if changed:
            changes.append("EnableCWMP → 0")

    if args.disable_reset_flag:
        xml_text, changed = disable_reset_flag(xml_text)
        if changed:
            changes.append("PSIXmlReset ResetFlag → 0")

    if args.disable_periodic_inform:
        xml_text, changed = set_inform_interval(xml_text, "0")
        if changed:
            changes.append("PeriodicInformEnable → 0")

    if not changes:
        print("No modifications requested.", file=sys.stderr)
        return 0

    out_path = args.output or args.input
    _write_xml_text(out_path, xml_text)

    print(f"Wrote {out_path} with {len(changes)} change(s):")
    for c in changes:
        print(f"  • {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
