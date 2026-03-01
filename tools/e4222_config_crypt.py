#!/usr/bin/env python3
"""Encrypt / decrypt configuration exports from the Ping Communication E4222
(7962V1) GPON ONT running firmware E4222-3.0.5-R (Realtek RTL8671 platform).

The modem's web interface exports and imports config files via:
    POST /boaform/formSaveConfig

The exported binary blob is a plain-text XML document XOR-ciphered with the
8-byte repeating key ``tecomtec``.  The same operation both encrypts and
decrypts (XOR is its own inverse).

Plaintext format
----------------
The decrypted file is a Realtek MIB XML document wrapped in::

    <Config_Information_File_8671>
    <Value Name="…" Value="…"/>
    …
    </Config_Information_File_8671>

Key facts discovered through binary analysis of libmib.so
----------------------------------------------------------
* ``CONFIG_HEADER``  = ``<Config_Information_File_8671>``
* ``CONFIG_TRAILER`` = ``</Config_Information_File_8671>``
* XOR key (period-8): ``tecomtec``  (derived from ``rtk_xmlfile_str_*`` in libmib.so)
* Individual sensitive string values inside the XML use an additional
  Caesar +1 / -1 shift applied by ``rtk_xmlfile_str_encrypt`` /
  ``rtk_xmlfile_str_decrypt`` in libmib.so (MIPS BE, offset 0x253a0 / 0x254d4).

Usage
-----
::

    python tools/e4222_config_crypt.py decrypt  config.xml  config_plain.xml
    python tools/e4222_config_crypt.py encrypt  config_plain.xml  config.xml
    python tools/e4222_config_crypt.py analyze  config_plain.xml
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

XOR_KEY = b"tecomtec"
CONFIG_HEADER = b"<Config_Information_File_8671>"
CONFIG_HEADER_HS = b"<Config_Information_File_HS>"
CONFIG_TRAILER = b"</Config_Information_File_8671>"
CONFIG_TRAILER_HS = b"</Config_Information_File_HS>"


def xor_crypt(data: bytes) -> bytes:
    key = XOR_KEY
    klen = len(key)
    return bytes(data[i] ^ key[i % klen] for i in range(len(data)))


def decrypt_file(src: str, dst: str) -> None:
    data = Path(src).read_bytes()
    Path(dst).write_bytes(xor_crypt(data))
    print(f"[+] Decrypted {len(data):,} bytes  →  {dst}")


def encrypt_file(src: str, dst: str) -> None:
    data = Path(src).read_bytes()
    enc = xor_crypt(data)
    Path(dst).write_bytes(enc)
    print(f"[+] Encrypted {len(data):,} bytes  →  {dst}")


_CRED_KEYS = {
    "SUSER_NAME", "SUSER_PASSWORD", "USER_NAME", "USER_PASSWORD",
    "WEB_SUSER_NAME", "WEB_SUSER_PASSWORD", "WEB_USER_NAME", "WEB_USER_PASSWORD",
    "CWMP_ACS_USERNAME", "CWMP_ACS_PASSWORD", "CWMP_CONREQ_USERNAME", "CWMP_CONREQ_PASSWORD",
    "CWMP_CERT_PASSWORD", "CWMP_LAN_CONFIGPASSWD",
    "MIB_SNMPV3_RO_NAME", "MIB_SNMPV3_RO_PASSWORD",
    "MIB_SNMPV3_RW_NAME", "MIB_SNMPV3_RW_PASSWORD",
    "GPON_PLOAM_PASSWD", "LOID", "LOID_PASSWD",
    "DEFAULT_SUSER_PASSWORD", "DEFAULT_USER_PASSWORD",
    "RS_PASSWORD", "ACCOUNT_RS_PASSWORD",
    "AUTO_CFG_FTP_USER", "AUTO_CFG_FTP_PASSWD",
    "FW_UPDATE_FTP_USER", "FW_UPDATE_FTP_PASSWD",
    "TR111_STUNUSERNAME", "TR111_STUNPASSWORD",
}

_NET_KEYS = {
    "LAN_IP_ADDR", "LAN_IP_ADDR2", "LAN_SUBNET",
    "CWMP_ACS_URL", "CWMP_ACS_URL_OLD",
    "NTP_SERVER_HOST1", "NTP_SERVER_HOST2", "NTP_SERVER_HOST3",
    "NTP_SERVER_HOST4", "NTP_SERVER_HOST5",
    "SNMP_SYS_NAME", "SNMP_SYS_DESCR", "SNMP_SYS_OID",
    "DEVICE_NAME", "DHCPS",
}

_SKIP_VALS = {"", "0", "0.0.0.0", "255.255.255.0", "http://", "http:// ", "::"}


def _parse_values(xml: str) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for name, val in re.findall(r'<Value Name="([^"]+)" Value="([^"]*)"', xml):
        result.setdefault(name, []).append(val)
    return result


def analyze_file(src: str) -> None:
    data = Path(src).read_bytes()
    if is_encrypted(data):
        print("[i] File is encrypted — decrypting in memory for analysis")
        data = xor_crypt(data)
    elif not is_plaintext(data):
        sys.exit(f"[!] {src}: unrecognised format")

    xml = data.decode("utf-8", errors="replace")
    values = _parse_values(xml)
    total = sum(len(v) for v in values.values())
    print(f"\n{'='*60}")
    print(f"  E4222 Config Analysis: {os.path.basename(src)}")
    print(f"  {total} values, {len(values)} unique keys, {len(data):,} bytes")
    print(f"{'='*60}")

    print("\n── Credentials ──────────────────────────────────────────")
    found_creds: List[Tuple[str, str]] = []
    for key in sorted(_CRED_KEYS):
        for val in values.get(key, []):
            if val and val not in _SKIP_VALS:
                found_creds.append((key, val))
                print(f"  {key:<35} = {val!r}")
    if not found_creds:
        print("  (none found)")

    print("\n── Network / ACS ────────────────────────────────────────")
    for key in sorted(_NET_KEYS):
        for val in values.get(key, []):
            if val and val not in _SKIP_VALS:
                print(f"  {key:<35} = {val!r}")

    print("\n── Hidden / non-default IPs ─────────────────────────────")
    ip_re = re.compile(r'\b(?!0\.0\.0\.0|255\.255|127\.0)(\d{1,3}(?:\.\d{1,3}){3})\b')
    seen_ips: set = set()
    default_ips = {"192.168.1.1", "192.168.100.1", "192.168.0.1", "0.0.0.0"}
    for name, vals in sorted(values.items()):
        for val in vals:
            for ip in ip_re.findall(val):
                if ip not in seen_ips and ip not in default_ips:
                    seen_ips.add(ip)
                    print(f"  {name:<35} → {ip}")

    print("\n── WAN summary ──────────────────────────────────────────")
    for key in ("WAN_MODE", "VPI", "VCI", "VLAN_TAG", "WAN_VLAN_ID_DATA",
                "CWMP_ACS_URL", "CWMP_ACS_USERNAME"):
        for val in values.get(key, []):
            if val:
                print(f"  {key:<35} = {val!r}")

    print()


def main() -> None:
    p = argparse.ArgumentParser(
        description="Encrypt / decrypt Ping E4222 config exports (XOR key: tecomtec)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="Decrypt an exported config.xml → plaintext XML")
    d.add_argument("input",  help="Encrypted config.xml from the modem")
    d.add_argument("output", help="Output plaintext XML file")

    e = sub.add_parser("encrypt", help="Encrypt a plaintext XML → importable config.xml")
    e.add_argument("input",  help="Plaintext XML file")
    e.add_argument("output", help="Output encrypted config.xml for the modem")

    a = sub.add_parser("analyze", help="Analyze and print credentials / IPs from a config")
    a.add_argument("input", help="Encrypted or plaintext config file")

    args = p.parse_args()

    if args.cmd == "decrypt":
        decrypt_file(args.input, args.output)
    elif args.cmd == "encrypt":
        encrypt_file(args.input, args.output)
    elif args.cmd == "analyze":
        analyze_file(args.input)


if __name__ == "__main__":
    main()
