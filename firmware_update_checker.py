#!/usr/bin/env python3
"""
Huawei ONT Firmware Update Checker and Downloader

This script helps check for and download firmware updates for Huawei ONT devices
like HG8145V5. It can extract rootfs from firmware files and check for updates.

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
"""

import os
import sys
import struct
import hashlib
import argparse
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class HuaweiFirmwareHeader:
    """Parse Huawei firmware header (HWNP format)"""

    MAGIC = 0x504E5748  # 'HWNP' in little endian
    HEADER_SIZE = 36

    def __init__(self, data: bytes):
        if len(data) < self.HEADER_SIZE:
            raise ValueError("Data too short for firmware header")

        # Parse header
        (self.magic, self.raw_sz, self.raw_crc32, self.hdr_sz,
         self.hdr_crc32, self.item_counts) = struct.unpack('<IIIIII', data[:24])

        if self.magic != self.MAGIC:
            raise ValueError(f"Invalid magic: 0x{self.magic:08x} (expected 0x{self.MAGIC:08x})")

        # Parse additional fields
        self.unknow_data_1, self.unknow_data_2 = struct.unpack('BB', data[24:26])
        self.prod_list_sz = struct.unpack('<H', data[26:28])[0]
        self.item_sz = struct.unpack('<I', data[28:32])[0]
        self.reserved = struct.unpack('<I', data[32:36])[0]

    def __repr__(self):
        return (f"HuaweiFirmwareHeader(magic=0x{self.magic:08x}, "
                f"items={self.item_counts}, hdr_sz={self.hdr_sz})")


class HuaweiFirmwareItem:
    """Parse Huawei firmware item"""

    ITEM_SIZE = 360

    def __init__(self, data: bytes):
        if len(data) < self.ITEM_SIZE:
            raise ValueError("Data too short for item")

        self.iter = struct.unpack('<I', data[0:4])[0]
        self.item_crc32 = struct.unpack('<I', data[4:8])[0]
        self.data_off = struct.unpack('<I', data[8:12])[0]
        self.data_sz = struct.unpack('<I', data[12:16])[0]

        # Parse strings (null-terminated)
        self.item = data[16:272].split(b'\x00')[0].decode('utf-8', errors='ignore')
        self.section = data[272:288].split(b'\x00')[0].decode('utf-8', errors='ignore')
        self.version = data[288:352].split(b'\x00')[0].decode('utf-8', errors='ignore')

        self.policy = struct.unpack('<I', data[352:356])[0]

    def __repr__(self):
        return (f"FirmwareItem(item='{self.item}', section='{self.section}', "
                f"version='{self.version}', size={self.data_sz})")


class FirmwareExtractor:
    """Extract components from Huawei firmware files"""

    def __init__(self, firmware_path: str):
        self.firmware_path = Path(firmware_path)
        if not self.firmware_path.exists():
            raise FileNotFoundError(f"Firmware file not found: {firmware_path}")

        self.firmware_data = self.firmware_path.read_bytes()
        self.header = None
        self.items = []
        self.prod_list = ""

        self._parse()

    def _parse(self):
        """Parse firmware file"""
        # Parse header
        self.header = HuaweiFirmwareHeader(self.firmware_data)

        # Read product list
        offset = HuaweiFirmwareHeader.HEADER_SIZE
        if self.header.prod_list_sz > 0:
            self.prod_list = self.firmware_data[offset:offset + self.header.prod_list_sz]
            self.prod_list = self.prod_list.split(b'\x00')[0].decode('utf-8', errors='ignore')

        offset += self.header.prod_list_sz

        # Parse items
        for i in range(self.header.item_counts):
            item_data = self.firmware_data[offset:offset + HuaweiFirmwareItem.ITEM_SIZE]
            item = HuaweiFirmwareItem(item_data)
            self.items.append(item)
            offset += HuaweiFirmwareItem.ITEM_SIZE

    def extract_component(self, section: str, output_path: Optional[str] = None) -> Optional[bytes]:
        """Extract a specific component by section name"""
        for item in self.items:
            if item.section.upper() == section.upper():
                data = self.firmware_data[item.data_off:item.data_off + item.data_sz]

                if output_path:
                    Path(output_path).write_bytes(data)
                    print(f"[+] Extracted {section} to {output_path} ({len(data)} bytes)")

                return data

        print(f"[-] Component {section} not found")
        return None

    def list_components(self):
        """List all components in the firmware"""
        print(f"\n{'='*80}")
        print(f"Firmware: {self.firmware_path.name}")
        print(f"Product List: {self.prod_list or '(empty)'}")
        print(f"Items: {self.header.item_counts}")
        print(f"{'='*80}\n")

        for item in self.items:
            size_mb = item.data_sz / (1024 * 1024)
            version = item.version or 'N/A'
            print(f"  [{item.iter}] {item.section:12s} | {item.item:40s} | "
                  f"{size_mb:7.2f} MB | {version}")
        print()


class FirmwareUpdateChecker:
    """Check for firmware updates from various sources"""

    # Known firmware repositories
    REPOS = [
        {
            'name': 'Uaemextop/HuaweiFirmwareTool',
            'api': 'https://api.github.com/repos/Uaemextop/HuaweiFirmwareTool/releases',
            'type': 'github'
        },
        {
            'name': 'Eduardob3677/mtkclient',
            'api': 'https://api.github.com/repos/Eduardob3677/mtkclient/releases',
            'type': 'github'
        }
    ]

    def __init__(self, device_model: str = "HG8145V5"):
        self.device_model = device_model
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Huawei-Firmware-Updater/1.0'
        })

    def check_github_releases(self, repo_info: Dict) -> List[Dict]:
        """Check GitHub releases for firmware files"""
        try:
            response = self.session.get(repo_info['api'], timeout=10)
            response.raise_for_status()
            releases = response.json()

            firmware_files = []
            for release in releases:
                for asset in release.get('assets', []):
                    name = asset['name']
                    # Check if it's a firmware file for our device
                    if (name.endswith('.bin') and
                        self.device_model.upper() in name.upper()):
                        firmware_files.append({
                            'name': name,
                            'url': asset['browser_download_url'],
                            'size': asset['size'],
                            'release': release['tag_name'],
                            'published': release['published_at'],
                            'repo': repo_info['name']
                        })

            return firmware_files

        except Exception as e:
            print(f"[-] Error checking {repo_info['name']}: {e}")
            return []

    def check_all_sources(self) -> List[Dict]:
        """Check all known firmware sources"""
        all_firmware = []

        print(f"[*] Checking for {self.device_model} firmware updates...\n")

        for repo in self.REPOS:
            print(f"[*] Checking {repo['name']}...")
            firmware = self.check_github_releases(repo)
            all_firmware.extend(firmware)
            print(f"    Found {len(firmware)} firmware files\n")

        return all_firmware

    def download_firmware(self, firmware_info: Dict, output_dir: str = ".") -> Optional[str]:
        """Download firmware file"""
        output_path = Path(output_dir) / firmware_info['name']

        if output_path.exists():
            print(f"[*] File already exists: {output_path}")
            return str(output_path)

        print(f"[*] Downloading {firmware_info['name']}...")
        print(f"    URL: {firmware_info['url']}")
        print(f"    Size: {firmware_info['size'] / (1024*1024):.2f} MB")

        try:
            response = self.session.get(firmware_info['url'], stream=True, timeout=30)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        # Progress indicator
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\r    Progress: {progress:.1f}%", end='', flush=True)

            print(f"\n[+] Downloaded to {output_path}")
            return str(output_path)

        except Exception as e:
            print(f"\n[-] Download failed: {e}")
            if output_path.exists():
                output_path.unlink()
            return None


def main():
    parser = argparse.ArgumentParser(
        description='Huawei ONT Firmware Update Checker and Extractor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check for available firmware updates
  %(prog)s --check --model HG8145V5

  # Download a specific firmware
  %(prog)s --download --model HG8145V5 --output ./firmwares

  # Extract rootfs from firmware file
  %(prog)s --extract firmware.bin --component rootfs --output rootfs.bin

  # List all components in firmware
  %(prog)s --list firmware.bin
        """
    )

    parser.add_argument('--check', action='store_true',
                        help='Check for firmware updates')
    parser.add_argument('--download', action='store_true',
                        help='Download latest firmware')
    parser.add_argument('--extract', metavar='FIRMWARE',
                        help='Extract component from firmware file')
    parser.add_argument('--list', metavar='FIRMWARE',
                        help='List all components in firmware')
    parser.add_argument('--component', default='rootfs',
                        help='Component to extract (default: rootfs)')
    parser.add_argument('--model', default='HG8145V5',
                        help='Device model (default: HG8145V5)')
    parser.add_argument('--output', metavar='PATH',
                        help='Output path for downloads or extractions')
    parser.add_argument('--all', action='store_true',
                        help='Download all available firmwares')

    args = parser.parse_args()

    # Check for firmware updates
    if args.check or args.download:
        checker = FirmwareUpdateChecker(args.model)
        firmware_list = checker.check_all_sources()

        if not firmware_list:
            print("[-] No firmware found")
            return 1

        print(f"\n{'='*80}")
        print(f"Found {len(firmware_list)} firmware files:")
        print(f"{'='*80}\n")

        for i, fw in enumerate(firmware_list, 1):
            date = datetime.fromisoformat(fw['published'].replace('Z', '+00:00'))
            print(f"{i}. {fw['name']}")
            print(f"   Repo: {fw['repo']}")
            print(f"   Release: {fw['release']}")
            print(f"   Published: {date.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   Size: {fw['size'] / (1024*1024):.2f} MB")
            print(f"   URL: {fw['url']}")
            print()

        # Download if requested
        if args.download:
            output_dir = args.output or './firmwares'
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            if args.all:
                # Download all
                for fw in firmware_list:
                    checker.download_firmware(fw, output_dir)
            else:
                # Download latest
                if firmware_list:
                    latest = firmware_list[0]
                    checker.download_firmware(latest, output_dir)

        return 0

    # List components
    if args.list:
        try:
            extractor = FirmwareExtractor(args.list)
            extractor.list_components()
            return 0
        except Exception as e:
            print(f"[-] Error: {e}")
            return 1

    # Extract component
    if args.extract:
        try:
            extractor = FirmwareExtractor(args.extract)

            output_path = args.output
            if not output_path:
                output_path = f"{args.component}.bin"

            data = extractor.extract_component(args.component, output_path)

            if data:
                # Calculate hash
                sha256 = hashlib.sha256(data).hexdigest()
                print(f"[+] SHA256: {sha256}")
                return 0
            else:
                return 1

        except Exception as e:
            print(f"[-] Error: {e}")
            return 1

    # No action specified
    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
