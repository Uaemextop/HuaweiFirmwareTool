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

    if args.set_usergroup:
        user, group = args.set_usergroup
        xml_text, changed = set_cli_user_group(xml_text, user, group)
        if changed:
            changes.append(f"UserGroup for '{user}' → {group}")

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
