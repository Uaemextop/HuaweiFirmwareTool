#!/usr/bin/env python3
"""
hw_ctree.xml configuration modifier for Huawei ONT devices.

Downloads, parses, and modifies hw_ctree.xml configuration files to:
- Fix XML structural errors
- Enable logging (syslog, debug, all levels)
- Enable remote access services (FTP, SFTP, Telnet, SSH, TFTP)
- Enable firmware downgrade
- Disable TR-069/CWMP remote management
- Add firmware flash preparation settings

Usage:
    python tools/ctree_modifier.py [--input FILE] [--output FILE] [--url URL]
"""

import argparse
import os
import re
import sys
import urllib.request


def download_config(url):
    """Download a hw_ctree.xml config from a URL."""
    print(f"Downloading config from: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "HuaweiFirmwareTool"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    print(f"  Downloaded {len(data)} bytes")
    return data.decode("utf-8", errors="replace")


def fix_xml_errors(xml_text):
    """Fix common XML structural errors in hw_ctree.xml."""
    changes = []

    # Fix duplicate PrefixInformationInstance outside PrefixInformation
    # The pattern: <PrefixInformationInstance .../> immediately before
    # <PrefixInformation> is a known duplicate in some configs
    pattern = (
        r'(<X_HW_IPv6Config[^>]*>)\s*'
        r'<PrefixInformationInstance ([^/]*/>\s*)'
        r'(<PrefixInformation )'
    )
    match = re.search(pattern, xml_text)
    if match:
        xml_text = re.sub(pattern, r'\1\n\3', xml_text)
        changes.append("Removed duplicate PrefixInformationInstance outside PrefixInformation element")

    # Fix unclosed or malformed tags
    # Check for mismatched NumberOfInstances counts
    for tag_match in re.finditer(
        r'<(\w+)\s+NumberOfInstances="(\d+)"', xml_text
    ):
        tag_name = tag_match.group(1)
        declared_count = int(tag_match.group(2))
        # Count actual instances
        instance_tag = tag_name + "Instance"
        start_pos = tag_match.end()
        # Find the closing tag
        close_pattern = f"</{tag_name}>"
        close_pos = xml_text.find(close_pattern, start_pos)
        if close_pos > 0:
            section = xml_text[start_pos:close_pos]
            actual_count = section.count(f"<{instance_tag} ")
            if actual_count != declared_count and actual_count > 0:
                old_attr = f'NumberOfInstances="{declared_count}"'
                new_attr = f'NumberOfInstances="{actual_count}"'
                # Only fix within this specific tag occurrence
                tag_start = tag_match.start()
                tag_end = tag_match.end()
                before = xml_text[:tag_start]
                tag_text = xml_text[tag_start:tag_end]
                after = xml_text[tag_end:]
                tag_text = tag_text.replace(old_attr, new_attr, 1)
                xml_text = before + tag_text + after

    return xml_text, changes


def set_attribute(xml_text, element_pattern, attr_name, new_value):
    """Set an attribute value on an XML element matching a pattern.

    Returns (modified_text, was_changed).
    """
    # Find the element and change the attribute
    pattern = rf'(<{element_pattern}[^>]*\s){attr_name}="[^"]*"'
    replacement = rf'\g<1>{attr_name}="{new_value}"'
    new_text, count = re.subn(pattern, replacement, xml_text, count=1)
    return new_text, count > 0


def add_attribute(xml_text, element_pattern, attr_name, value):
    """Add an attribute to an element if it doesn't exist."""
    # Check if attribute already exists
    check = rf'<{element_pattern}[^>]*\s{attr_name}='
    if re.search(check, xml_text):
        return set_attribute(xml_text, element_pattern, attr_name, value)

    # Add the attribute before the closing > or />
    pattern = rf'(<{element_pattern}[^>]*?)(\s*/?>)'
    replacement = rf'\1 {attr_name}="{value}"\2'
    new_text, count = re.subn(pattern, replacement, xml_text, count=1)
    return new_text, count > 0


def enable_logging(xml_text):
    """Enable all logging: syslog, debug switch, highest level."""
    changes = []

    # Enable Syslog with Level 7 (DEBUG - highest verbosity)
    xml_text, ok = set_attribute(xml_text, "X_HW_Syslog", "Enable", "1")
    if ok:
        changes.append("Enabled X_HW_Syslog")
    xml_text, ok = set_attribute(xml_text, "X_HW_Syslog", "Level", "7")
    if ok:
        changes.append("Set X_HW_Syslog Level=7 (DEBUG)")

    # Enable debug switch in X_HW_LogCfg
    xml_text, ok = set_attribute(xml_text, "X_HW_LogCfg", "DbgSwitch", "1")
    if ok:
        changes.append("Enabled X_HW_LogCfg DbgSwitch=1")

    # Enable runtime logging
    xml_text, ok = set_attribute(xml_text, "X_HW_LogCfg", "RtoSwitch", "1")
    if ok:
        changes.append("Enabled X_HW_LogCfg RtoSwitch=1")

    # Set LogTypeMask to capture all log types (0xFF = all)
    xml_text, ok = set_attribute(xml_text, "X_HW_LogCfg", "LogTypeMask", "255")
    if ok:
        changes.append("Set X_HW_LogCfg LogTypeMask=255 (all types)")

    # Enable X_HW_SyslogConfig for remote log server
    xml_text, ok = set_attribute(
        xml_text, "X_HW_SyslogConfig", "LogServerEnable", "1"
    )
    if ok:
        changes.append("Enabled X_HW_SyslogConfig LogServerEnable=1")

    # Set severity to capture all levels
    xml_text, ok = set_attribute(xml_text, "X_HW_SyslogConfig", "Severity", "7")
    if ok:
        changes.append("Set X_HW_SyslogConfig Severity=7 (all levels)")

    # Enable X_HW_Reportlog
    xml_text, ok = set_attribute(xml_text, "X_HW_Reportlog", "Enable", "1")
    if ok:
        changes.append("Enabled X_HW_Reportlog")

    # Set report log type to capture all (5 = all types)
    xml_text, ok = set_attribute(xml_text, "X_HW_Reportlog", "ReportLogType", "5")
    if ok:
        changes.append("Set X_HW_Reportlog ReportLogType=5")

    return xml_text, changes


def enable_services(xml_text):
    """Enable FTP, SFTP, Telnet, SSH, TFTP services."""
    changes = []

    # Enable Telnet access
    xml_text, ok = set_attribute(
        xml_text, "X_HW_CLITelnetAccess", "Access", "1"
    )
    if ok:
        changes.append("Enabled Telnet CLI access (Access=1)")

    # Enable FTP in X_HW_ServiceManage
    xml_text, ok = set_attribute(
        xml_text, "X_HW_ServiceManage", "FtpEnable", "1"
    )
    if ok:
        changes.append("Enabled FTP service (FtpEnable=1)")

    # Enable SFTP
    xml_text, ok = set_attribute(
        xml_text, "X_HW_SFTP_ServerInfo", "SftpEnable", "1"
    )
    if ok:
        changes.append("Enabled SFTP service (SftpEnable=1)")

    # Enable SFTP LAN access
    xml_text, ok = set_attribute(
        xml_text, "X_HW_SFTP_ServerInfo", "SftpLANEnable", "1"
    )
    if ok:
        changes.append("Enabled SFTP LAN access (SftpLANEnable=1)")

    # Enable SFTP WAN access
    xml_text, ok = set_attribute(
        xml_text, "X_HW_SFTP_ServerInfo", "SftpWANEnable", "1"
    )
    if ok:
        changes.append("Enabled SFTP WAN access (SftpWANEnable=1)")

    # Enable TFTP server
    xml_text, ok = set_attribute(
        xml_text, "LANHostConfigManagement", "X_HW_TftpServerEnable", "1"
    )
    if ok:
        changes.append("Enabled TFTP server (X_HW_TftpServerEnable=1)")

    # Enable SSH - add X_HW_CLISSHAccess if not present
    ssh_pattern = r'<X_HW_CLISSHAccess\s'
    if not re.search(ssh_pattern, xml_text):
        # Insert SSH access element after the Telnet access element
        telnet_pattern = r'(<X_HW_CLITelnetAccess[^/]*/>\s*)'
        replacement = r'\1<X_HW_CLISSHAccess Access="1" SSHPort="22"/>\n'
        xml_text, count = re.subn(telnet_pattern, replacement, xml_text, count=1)
        if count > 0:
            changes.append("Added SSH CLI access (X_HW_CLISSHAccess Access=1, port 22)")
    else:
        xml_text, ok = set_attribute(
            xml_text, "X_HW_CLISSHAccess", "Access", "1"
        )
        if ok:
            changes.append("Enabled SSH CLI access (Access=1)")

    return xml_text, changes


def disable_tr069_cwmp(xml_text):
    """Disable TR-069 and CWMP remote management."""
    changes = []

    # Disable CWMP
    xml_text, ok = set_attribute(
        xml_text, "ManagementServer", "EnableCWMP", "0"
    )
    if ok:
        changes.append("Disabled CWMP (EnableCWMP=0)")

    # Clear management server URL
    xml_text, ok = set_attribute(xml_text, "ManagementServer", "URL", "")
    if ok:
        changes.append("Cleared ManagementServer URL")

    # Disable periodic inform
    xml_text, ok = set_attribute(
        xml_text, "ManagementServer", "PeriodicInformEnable", "0"
    )
    if ok:
        changes.append("Disabled PeriodicInformEnable")

    # Disable STUN
    xml_text, ok = set_attribute(
        xml_text, "ManagementServer", "STUNEnable", "0"
    )
    if ok:
        changes.append("Disabled STUNEnable")

    # Clear credentials
    xml_text, ok = set_attribute(xml_text, "ManagementServer", "Username", "")
    if ok:
        changes.append("Cleared ManagementServer Username")
    xml_text, ok = set_attribute(xml_text, "ManagementServer", "Password", "")
    if ok:
        changes.append("Cleared ManagementServer Password")
    xml_text, ok = set_attribute(
        xml_text, "ManagementServer", "ConnectionRequestUsername", ""
    )
    if ok:
        changes.append("Cleared ConnectionRequestUsername")
    xml_text, ok = set_attribute(
        xml_text, "ManagementServer", "ConnectionRequestPassword", ""
    )
    if ok:
        changes.append("Cleared ConnectionRequestPassword")

    # Disable certificate-based authentication
    xml_text, ok = set_attribute(
        xml_text, "ManagementServer", "X_HW_EnableCertificate", "0"
    )
    if ok:
        changes.append("Disabled X_HW_EnableCertificate")

    # Disable iaccess (ISP remote access)
    xml_text, ok = set_attribute(xml_text, "X_HW_iaccess", "Enable", "0")
    if ok:
        changes.append("Disabled X_HW_iaccess")

    xml_text, ok = set_attribute(
        xml_text, "X_HW_iaccess", "ReportEnable", "0"
    )
    if ok:
        changes.append("Disabled X_HW_iaccess ReportEnable")

    xml_text, ok = set_attribute(
        xml_text, "X_HW_iaccess", "SecPlatEnable", "0"
    )
    if ok:
        changes.append("Disabled X_HW_iaccess SecPlatEnable")

    # Disable X_HW_AppRemoteManage
    xml_text, ok = set_attribute(
        xml_text, "X_HW_AppRemoteManage", "MgtURL", ""
    )
    if ok:
        changes.append("Cleared X_HW_AppRemoteManage MgtURL")

    # Disable audit
    xml_text, ok = set_attribute(xml_text, "X_HW_Audit", "Enable", "0")
    if ok:
        changes.append("Disabled X_HW_Audit")

    return xml_text, changes


def enable_downgrade(xml_text):
    """Enable firmware downgrade by modifying version check settings."""
    changes = []

    # Set X_HW_PSIXmlReset to allow config reset on version change
    xml_text, ok = set_attribute(
        xml_text, "X_HW_PSIXmlReset", "ResetFlag", "0"
    )
    if ok:
        changes.append("Disabled PSI XML reset on upgrade (ResetFlag=0)")

    # Disable X_HW_CheckSafety which blocks unauthorized firmware
    xml_text, ok = set_attribute(
        xml_text, "X_HW_CheckSafety", "Enable", "0"
    )
    if ok:
        changes.append("Disabled X_HW_CheckSafety (firmware safety check)")

    # Ensure UpgradesManaged is disabled so ISP can't control upgrades
    xml_text, ok = set_attribute(
        xml_text, "ManagementServer", "UpgradesManaged", "0"
    )
    if ok:
        changes.append("Disabled UpgradesManaged (ISP firmware control)")

    return xml_text, changes


def set_version_info(xml_text):
    """Set correct version information in the config."""
    changes = []

    # Update X_HW_ProductInfo with correct version
    xml_text, ok = set_attribute(
        xml_text, "X_HW_ProductInfo", "currentVersion", "V500R020"
    )
    if ok:
        changes.append("Set currentVersion to V500R020")

    xml_text, ok = set_attribute(
        xml_text, "X_HW_ProductInfo", "customInfo", "COMMON"
    )
    if ok:
        changes.append("Set customInfo to COMMON")

    xml_text, ok = set_attribute(
        xml_text, "X_HW_ProductInfo", "customInfoDetail", "common"
    )
    if ok:
        changes.append("Set customInfoDetail to common")

    return xml_text, changes


def add_flash_config(xml_text):
    """Add configurations for firmware flashing preparation."""
    changes = []

    # Enable power saving mode off for stable flashing
    xml_text, ok = set_attribute(
        xml_text, "X_HW_APMPolicy", "EnablePowerSavingMode", "0"
    )
    if ok:
        changes.append("Disabled power saving for stable flashing")

    # Disable auto-reboot to prevent interruption during flash
    xml_text, ok = set_attribute(
        xml_text, "X_HW_AutoReboot", "Enable", "0"
    )
    if ok:
        changes.append("Disabled auto-reboot for safe flashing")

    # Ensure LED switch is on for visual feedback during flash
    xml_text, ok = set_attribute(
        xml_text, "ExtDeviceInfo", "X_HW_LedSwitch", "1"
    )
    if ok:
        changes.append("Enabled LED switch for flash visual feedback")

    # Set DHCP server for firmware transfer network
    xml_text, ok = set_attribute(
        xml_text, "LANHostConfigManagement", "DHCPServerEnable", "1"
    )
    if ok:
        changes.append("Enabled DHCP server for firmware transfer")

    return xml_text, changes


def modify_config(xml_text):
    """Apply all modifications to the config."""
    all_changes = []

    print("\n=== Fixing XML errors ===")
    xml_text, changes = fix_xml_errors(xml_text)
    all_changes.extend(changes)
    for c in changes:
        print(f"  ✓ {c}")
    if not changes:
        print("  No XML errors found")

    print("\n=== Setting version info ===")
    xml_text, changes = set_version_info(xml_text)
    all_changes.extend(changes)
    for c in changes:
        print(f"  ✓ {c}")

    print("\n=== Enabling logging ===")
    xml_text, changes = enable_logging(xml_text)
    all_changes.extend(changes)
    for c in changes:
        print(f"  ✓ {c}")

    print("\n=== Enabling services (FTP, SFTP, Telnet, SSH, TFTP) ===")
    xml_text, changes = enable_services(xml_text)
    all_changes.extend(changes)
    for c in changes:
        print(f"  ✓ {c}")

    print("\n=== Enabling firmware downgrade ===")
    xml_text, changes = enable_downgrade(xml_text)
    all_changes.extend(changes)
    for c in changes:
        print(f"  ✓ {c}")

    print("\n=== Disabling TR-069/CWMP ===")
    xml_text, changes = disable_tr069_cwmp(xml_text)
    all_changes.extend(changes)
    for c in changes:
        print(f"  ✓ {c}")

    print("\n=== Adding flash configurations ===")
    xml_text, changes = add_flash_config(xml_text)
    all_changes.extend(changes)
    for c in changes:
        print(f"  ✓ {c}")

    print(f"\n=== Total changes: {len(all_changes)} ===")
    return xml_text, all_changes


def main():
    parser = argparse.ArgumentParser(
        description="Modify Huawei ONT hw_ctree.xml configuration files"
    )
    parser.add_argument(
        "--input", "-i",
        help="Input hw_ctree.xml file path"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output modified hw_ctree.xml file path"
    )
    parser.add_argument(
        "--url", "-u",
        help="URL to download hw_ctree.xml from",
        default="https://raw.githubusercontent.com/Uaemextop/huawei-hg8145v5/refs/heads/main/hw_ctree.xml"
    )
    args = parser.parse_args()

    # Load config
    if args.input and os.path.isfile(args.input):
        print(f"Loading config from: {args.input}")
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            xml_text = f.read()
    else:
        xml_text = download_config(args.url)

    print(f"Config size: {len(xml_text)} characters")

    # Modify config
    modified, changes = modify_config(xml_text)

    # Save output
    output_path = args.output or "hw_ctree_modified.xml"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(modified)
    print(f"\nModified config saved to: {output_path}")
    print(f"Output size: {len(modified)} characters")

    return 0


if __name__ == "__main__":
    sys.exit(main())
