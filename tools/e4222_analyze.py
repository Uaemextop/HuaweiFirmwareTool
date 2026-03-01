#!/usr/bin/env python3
import re
import sys
import os
import subprocess
import ipaddress
from pathlib import Path

def _openssl(args, data=None):
    try:
        r = subprocess.run(["openssl"] + args, input=data, capture_output=True)
        return r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
    except FileNotFoundError:
        return ""

def analyze_rsa_keys(base: Path):
    print("=" * 60)
    print("RSA PRIVATE KEYS  (Ping7962V1-E4222-Telmex/keys/)")
    print("=" * 60)
    keys_dir = base / "keys"
    certs_dir = base / "certs"
    for p in sorted(keys_dir.glob("*.pem")) + sorted(keys_dir.glob("*.key")):
        data = p.read_bytes()
        if b"PRIVATE KEY" in data and b"ENCRYPTED" not in data:
            print(f"\n[PRIVATE KEY] {p.name}")
            out = _openssl(["rsa", "-in", str(p), "-text", "-noout"])
            for line in out.splitlines():
                if any(k in line for k in ("bit", "modulus:", "Public-Key", "Private-Key")):
                    print(f"  {line.strip()}")
            md5 = subprocess.run(["md5sum", str(p)], capture_output=True).stdout.decode().split()[0]
            sha256 = subprocess.run(["sha256sum", str(p)], capture_output=True).stdout.decode().split()[0]
            print(f"  MD5:    {md5}")
            print(f"  SHA256: {sha256}")
            print(f"  Path:   {p.relative_to(base)}")

    print("\n" + "=" * 60)
    print("CERTIFICATES  (Ping7962V1-E4222-Telmex/certs/)")
    print("=" * 60)
    for p in sorted(certs_dir.glob("*.pem")) + sorted(certs_dir.glob("*.crt")):
        data = p.read_bytes()
        if b"CERTIFICATE" in data:
            print(f"\n[CERT] {p.name}")
            out = _openssl(["x509", "-in", str(p), "-subject", "-issuer", "-dates", "-noout"])
            for line in out.strip().splitlines():
                print(f"  {line.strip()}")

def analyze_ips(config_path: Path):
    print("\n" + "=" * 60)
    print("HIDDEN / NON-RFC1918 IP ADDRESSES")
    print("=" * 60)
    text = config_path.read_text(errors="replace")
    raw = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))
    non_private = []
    for s in sorted(raw):
        try:
            ip = ipaddress.ip_address(s)
            if not (ip.is_private or ip.is_loopback or ip.is_unspecified
                    or ip.is_link_local or ip.is_multicast):
                non_private.append(s)
        except ValueError:
            pass
    if non_private:
        for ip in sorted(non_private, key=lambda x: ipaddress.ip_address(x)):
            context = []
            for line in text.splitlines():
                if ip in line:
                    context.append(line.strip())
            print(f"\n  {ip}")
            for c in context[:3]:
                print(f"    {c}")
    else:
        print("  (none found)")
    # Also report certs with embedded IPs
    for p in sorted(config_path.parent.rglob("*.pem")):
        if b"CERTIFICATE" in p.read_bytes():
            out = _openssl(["x509", "-in", str(p), "-subject", "-noout"])
            m = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', out)
            for ip_s in m:
                try:
                    ip = ipaddress.ip_address(ip_s)
                    print(f"\n  {ip_s}  [embedded in cert {p.name}]")
                except ValueError:
                    pass

def analyze_accounts(config_path: Path):
    print("\n" + "=" * 60)
    print("USER ACCOUNTS & CREDENTIALS")
    print("=" * 60)
    text = config_path.read_text(errors="replace")

    patterns = [
        ("Web/Telnet/SSH superuser", r'<Value Name="SUSER_NAME" Value="([^"]+)"'),
        ("Web/Telnet/SSH password",  r'<Value Name="SUSER_PASSWORD" Value="([^"]+)"'),
        ("LOID (ONT auth user)",     r'<Value Name="LOID" Value="([^"]+)"'),
        ("LOID password",            r'<Value Name="LOID_PASSWD" Value="([^"]+)"'),
        ("SNMP v3 RO user",          r'<Value Name="MIB_SNMPV3_RO_NAME" Value="([^"]+)"'),
        ("SNMP v3 RO password",      r'<Value Name="MIB_SNMPV3_RO_PASSWORD" Value="([^"]+)"'),
        ("SNMP v3 RW user",          r'<Value Name="MIB_SNMPV3_RW_NAME" Value="([^"]+)"'),
        ("SNMP v3 RW password",      r'<Value Name="MIB_SNMPV3_RW_PASSWORD" Value="([^"]+)"'),
        ("FTP/USB share user",       r'<Value Name="name" Value="([^"]+)"'),
        ("FTP/USB share password",   r'<Value Name="password" Value="([^"]+)"'),
        ("FTP root path",            r'<Value Name="rootpath" Value="([^"]+)"'),
        ("CWMP ACS URL",             r'<Value Name="CWMP_ACS_URL" Value="([^"]+)"'),
        ("CWMP ACS username",        r'<Value Name="CWMP_ACS_USERNAME" Value="([^"]+)"'),
        ("CWMP ACS password",        r'<Value Name="CWMP_ACS_PASSWORD" Value="([^"]+)"'),
    ]
    seen = {}
    for label, pat in patterns:
        m = re.search(pat, text)
        if m and m.group(1):
            seen[label] = m.group(1)
    for label, val in seen.items():
        print(f"  {label:<30} {val}")

    # Additional: scan for any Value where the name contains PASSWORD/PASSWD/SECRET and value is non-empty
    print("\n  -- Additional non-empty credential fields --")
    for m in re.finditer(r'<Value Name="([^"]*(?:PASSWORD|PASSWD|SECRET)[^"]*)" Value="([^"]+)"', text, re.I):
        field, val = m.group(1), m.group(2)
        if field not in ("SUSER_PASSWORD", "SUSER_REMINDER", "MIB_SNMPV3_RO_PASSWORD", "MIB_SNMPV3_RW_PASSWORD",
                         "CWMP_ACS_PASSWORD", "CWMP_CERT_PASSWORD"):
            print(f"  {field:<30} {val}")

def main():
    if len(sys.argv) < 2:
        base = Path(__file__).parent.parent / "extracted_configs" / "Ping7962V1-E4222-Telmex"
    else:
        base = Path(sys.argv[1])

    config = base / "config_modified.xml"
    if not config.exists():
        config = base / "config_decrypted.xml"
    if not config.exists():
        print(f"No config found in {base}", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing: {config}\n")
    analyze_rsa_keys(base)
    analyze_ips(config)
    analyze_accounts(config)
    print()

if __name__ == "__main__":
    main()
