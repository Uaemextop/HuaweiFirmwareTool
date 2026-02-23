#!/usr/bin/env python3
"""
Huawei ONT Firmware Download & Analysis Tool

Supports downloading firmware updates for Huawei HG8145V5 and similar ONT devices.
Supports extracting rootfs from HWNP firmware images.

Firmware Update Mechanisms (reverse-engineered from rootfs analysis):
  1. TR-069/CWMP: ISP pushes Download RPC via ACS (Auto-Configuration Server)
     - ManagementServer.URL points to ISP's ACS
     - ACS sends Download RPC with firmware URL (HTTP/FTP/TFTP)
     - Device downloads via: ftpget, httpc, or tftp commands
  2. OMCI: OLT pushes firmware via GPON management channel
     - Software Image ME (Class 7) handles image transfer
     - Sections transferred in windows, then activated and committed
  3. Local: Manual upload via web interface or TFTP recovery
     - Web: Upload through management page
     - TFTP: Device requests firmware on boot (reset button held)

Download command templates (from libhw_swm_dll.so):
  FTP:  ftpget "%s" "%s" %s %s -i -d
  HTTP: httpc -g -i -l %s <url>
  TFTP: tftp -i -l "%s" -r %s -g "%s"
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import urllib.request
import urllib.error


# ── HWNP Firmware Parser ────────────────────────────────────────────────────

HWNP_MAGIC = 0x504E5748  # "HWNP" little-endian
HWNP_HEADER_SIZE = 36     # sizeof(huawei_header)
HWNP_ITEM_SIZE = 360      # sizeof(huawei_item)

# Encrypted rootfs magic (found in V2/SPC210/SPC458 firmwares)
ENCRYPTED_ROOTFS_MAGIC = 0x20190416

# SquashFS magic
SQUASHFS_MAGIC = b'hsqs'

# uImage magic
UIMAGE_MAGIC = b'\x27\x05\x19\x56'


def read_hwnp_header(data):
    """Parse HWNP firmware header."""
    if len(data) < HWNP_HEADER_SIZE:
        return None

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != HWNP_MAGIC:
        return None

    hdr = {
        'magic': magic,
        'raw_sz': struct.unpack_from('<I', data, 4)[0],
        'raw_crc32': struct.unpack_from('<I', data, 8)[0],
        'hdr_sz': struct.unpack_from('<I', data, 12)[0],
        'hdr_crc32': struct.unpack_from('<I', data, 16)[0],
        'item_counts': struct.unpack_from('<I', data, 20)[0],
        '_unknow_data_1': data[24],
        '_unknow_data_2': data[25],
        'prod_list_sz': struct.unpack_from('<H', data, 26)[0],
        'item_sz': struct.unpack_from('<I', data, 28)[0],
        'reserved': struct.unpack_from('<I', data, 32)[0],
    }
    return hdr


def read_hwnp_items(data, hdr):
    """Parse firmware items from HWNP image."""
    items = []
    item_sz = hdr['item_sz'] if hdr['item_sz'] else HWNP_ITEM_SIZE
    base = HWNP_HEADER_SIZE + hdr['prod_list_sz']

    for i in range(hdr['item_counts']):
        off = base + i * item_sz
        if off + 16 > len(data):
            break

        it = {
            'iter': struct.unpack_from('<I', data, off)[0],
            'item_crc32': struct.unpack_from('<I', data, off + 4)[0],
            'data_off': struct.unpack_from('<I', data, off + 8)[0],
            'data_sz': struct.unpack_from('<I', data, off + 12)[0],
            'item': data[off + 16:off + 16 + 256].split(b'\x00')[0].decode('ascii', errors='replace'),
            'section': data[off + 272:off + 272 + 16].split(b'\x00')[0].decode('ascii', errors='replace'),
            'version': data[off + 288:off + 288 + 64].split(b'\x00')[0].decode('ascii', errors='replace'),
            'policy': struct.unpack_from('<I', data, off + 352)[0] if off + 356 <= len(data) else 0,
        }
        items.append(it)

    return items


def extract_rootfs(firmware_path, output_dir):
    """Extract rootfs and other items from an HWNP firmware image."""
    print(f"[*] Reading firmware: {firmware_path}")

    with open(firmware_path, 'rb') as f:
        data = f.read()

    hdr = read_hwnp_header(data)
    if not hdr:
        print("[-] Not a valid HWNP firmware image")
        return False

    print(f"[+] HWNP firmware detected")
    print(f"    Items: {hdr['item_counts']}")
    print(f"    Item size: {hdr['item_sz']}")
    print(f"    Reserved: {hdr['reserved']} {'(encrypted)' if hdr['reserved'] == 1 else ''}")

    prod_list = data[HWNP_HEADER_SIZE:HWNP_HEADER_SIZE + hdr['prod_list_sz']]
    prod_str = prod_list.split(b'\x00')[0].decode('ascii', errors='replace')
    if prod_str:
        print(f"    Products: {prod_str}")

    items = read_hwnp_items(data, hdr)

    os.makedirs(output_dir, exist_ok=True)

    for item in items:
        item_name = item['item'].split(':')[-1] if ':' in item['item'] else item['item']
        safe_name = item_name.replace('/', '_').lstrip('_')

        print(f"\n[*] Extracting: {item['item']} ({item['section']}) "
              f"[{item['data_sz']} bytes, version: {item['version'] or 'N/A'}]")

        item_data = data[item['data_off']:item['data_off'] + item['data_sz']]

        # Save raw item
        out_path = os.path.join(output_dir, safe_name)
        with open(out_path, 'wb') as f:
            f.write(item_data)
        print(f"    Saved: {out_path}")

        # Analyze rootfs
        if item['section'] == 'ROOTFS' and len(item_data) >= 4:
            _analyze_rootfs(item_data, output_dir, safe_name)

    return True


def _analyze_rootfs(item_data, output_dir, safe_name):
    """Analyze and identify rootfs format."""
    magic32 = struct.unpack_from('<I', item_data, 0)[0]

    if item_data[:4] == b'whwh':
        print(f"    Format: whwh container (unencrypted)")
        version = item_data[4:68].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"    Version: {version}")

        # Find SquashFS inside
        sqfs_off = item_data.find(SQUASHFS_MAGIC)
        if sqfs_off >= 0:
            print(f"    SquashFS found at offset 0x{sqfs_off:x}")
            sqfs_path = os.path.join(output_dir, safe_name + '.squashfs')
            with open(sqfs_path, 'wb') as f:
                f.write(item_data[sqfs_off:])
            print(f"    Saved SquashFS: {sqfs_path}")

            # Try to extract SquashFS automatically
            extract_dir = os.path.join(output_dir, 'rootfs_extracted')
            _try_unsquashfs(sqfs_path, extract_dir)

        # Find uImage
        uimg_off = item_data.find(UIMAGE_MAGIC)
        if uimg_off >= 0:
            print(f"    uImage found at offset 0x{uimg_off:x}")

    elif magic32 == ENCRYPTED_ROOTFS_MAGIC:
        print(f"    Format: Encrypted rootfs (magic 0x{ENCRYPTED_ROOTFS_MAGIC:08x})")
        _analyze_encrypted_rootfs(item_data, output_dir, safe_name)
    else:
        print(f"    Format: Unknown (magic 0x{magic32:08x})")


def _try_unsquashfs(sqfs_path, extract_dir):
    """Try to extract SquashFS using unsquashfs if available."""
    unsquashfs = shutil.which('unsquashfs')
    if not unsquashfs:
        print(f"    unsquashfs not found; install squashfs-tools to auto-extract")
        print(f"    Extract with: unsquashfs -d {extract_dir} {sqfs_path}")
        return

    if os.path.exists(extract_dir):
        print(f"    Skipping extraction: {extract_dir} already exists")
        return

    print(f"    Extracting SquashFS with unsquashfs...")
    try:
        result = subprocess.run(
            [unsquashfs, '-d', extract_dir, sqfs_path],
            capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            file_count = sum(1 for _ in _walk_count(extract_dir))
            print(f"    Extracted rootfs to: {extract_dir} ({file_count} files)")
        else:
            print(f"    unsquashfs failed: {result.stderr.strip()}")
            print(f"    Extract manually: unsquashfs -d {extract_dir} {sqfs_path}")
    except subprocess.TimeoutExpired:
        print(f"    unsquashfs timed out after 300s")
    except Exception as e:
        print(f"    unsquashfs error: {e}")
        print(f"    Extract manually: unsquashfs -d {extract_dir} {sqfs_path}")


def _walk_count(path):
    """Count files in a directory tree."""
    for root, dirs, files in os.walk(path):
        yield from files


def _analyze_encrypted_rootfs(item_data, output_dir, safe_name):
    """Parse and analyze encrypted rootfs header (0x20190416 format).

    Encrypted rootfs structure (reverse-engineered from libhw_swm_dll.so):
      Offset  Size   Field
      0x00    4      magicA = 0x20190416
      0x04    4      magicB = 0x00343520 (" 54\\0")
      0x08    4      field_08 (always 1)
      0x0C    4      field_0C (always 1)
      0x10    4      sections (number of flash sections, typically 7)
      0x14    4      enc_type (1 = AES-256-CBC encrypted)
      0x18    16     md5_hash (MD5 of plaintext rootfs before encryption)
      0x28    4      data_size (encrypted payload size)
      0x2C    4      header_size (always 0x60)
      0x30    4      total_size (header_size + data_size, padded)
      0x34    4      crc32 (CRC32 of encrypted payload)
      0x38    36     version_string (e.g. "V500R020C00SPC458B001")
      0x5C    4      padding

    Encryption: AES-256-CBC
      Key source: HiSilicon SoC eFuse/OTP (hardware-bound, per-device)
      Key path: DM_FlashEfuseEncrypt -> HiSilicon crypto driver
      Decryption function: DM_DecryptFlashData in libsmp_api.so
        1. HW_SSL_AesSetKeyDec(ctx, efuse_key, 256)
        2. HW_SSL_AesCryptCbc(ctx, DECRYPT, in, out, len, iv)

    The first 16 bytes after the 0x60 header are the plaintext MD5 hash
    (same as md5_hash field) used as a verification prefix.
    """
    if len(item_data) < 0x60:
        print(f"    Encrypted header too short ({len(item_data)} bytes)")
        return

    enc_hdr = {
        'magicA': struct.unpack_from('<I', item_data, 0x00)[0],
        'magicB': struct.unpack_from('<I', item_data, 0x04)[0],
        'field_08': struct.unpack_from('<I', item_data, 0x08)[0],
        'field_0C': struct.unpack_from('<I', item_data, 0x0C)[0],
        'sections': struct.unpack_from('<I', item_data, 0x10)[0],
        'enc_type': struct.unpack_from('<I', item_data, 0x14)[0],
        'md5': item_data[0x18:0x28],
        'data_size': struct.unpack_from('<I', item_data, 0x28)[0],
        'header_size': struct.unpack_from('<I', item_data, 0x2C)[0],
        'total_padded': struct.unpack_from('<I', item_data, 0x30)[0],
        'crc32': struct.unpack_from('<I', item_data, 0x34)[0],
        'version': item_data[0x38:0x5C].split(b'\x00')[0].decode('ascii', errors='replace'),
    }

    print(f"    Version:     {enc_hdr['version']}")
    print(f"    Sections:    {enc_hdr['sections']}")
    print(f"    Enc type:    {enc_hdr['enc_type']} (AES-256-CBC)")
    print(f"    Header size: 0x{enc_hdr['header_size']:x}")
    print(f"    Data size:   {enc_hdr['data_size']} ({enc_hdr['data_size'] / (1024*1024):.1f} MB)")
    print(f"    MD5 (plain): {enc_hdr['md5'].hex()}")
    print(f"    CRC32:       0x{enc_hdr['crc32']:08x}")

    # Verify MD5 prefix matches header
    if len(item_data) >= 0x70:
        md5_prefix = item_data[0x60:0x70]
        if md5_prefix == enc_hdr['md5']:
            print(f"    MD5 prefix:  verified (matches header)")
        else:
            print(f"    MD5 prefix:  {md5_prefix.hex()} (different from header)")

    # Save the encrypted rootfs with its header for reference
    enc_path = os.path.join(output_dir, safe_name + '.encrypted')
    with open(enc_path, 'wb') as f:
        f.write(item_data)
    print(f"    Saved encrypted rootfs: {enc_path}")

    print(f"    NOTE: Encrypted with AES-256-CBC, key from HiSilicon eFuse/OTP")
    print(f"    Decryption requires physical device access (eFuse key extraction)")


# ── Firmware Downloader ──────────────────────────────────────────────────────

# Known firmware download sources.
# ISPs use TR-069/CWMP to push firmware URLs to devices.
# These are public firmware repositories and known release URLs.
KNOWN_FIRMWARE_SOURCES = {
    'HG8145V5': {
        'description': 'Huawei HG8145V5 ONT (GPON)',
        'versions': {
            'V500R020C00SPC270': {
                'url': 'https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/HG8145V5_remover5.bin',
                'description': 'SPC270 (remover5) - Full firmware with SquashFS rootfs',
                'encrypted_rootfs': False,
            },
            'V500R020C00SPC458': {
                'url': 'https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/HG8145V5_V2_HG8145V5.bin',
                'description': 'SPC458 (V2) - Encrypted rootfs',
                'encrypted_rootfs': True,
            },
            'V500R021C00SPC210': {
                'url': 'https://github.com/Eduardob3677/mtkclient/releases/download/v3/HG8145V5-V500R021C00SPC210.bin',
                'description': 'SPC210 - Encrypted rootfs',
                'encrypted_rootfs': True,
            },
        },
    },
    'EG8145V5': {
        'description': 'Huawei EG8145V5 ONT (GPON)',
        'versions': {
            'V500R022C00SPC340': {
                'url': 'https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/EG8145V5-V500R022C00SPC340B019.bin',
                'description': 'SPC340B019 - Full firmware with SquashFS rootfs (unencrypted)',
                'encrypted_rootfs': False,
            },
        },
    },
}


def list_firmware():
    """List all known firmware versions."""
    print("Available firmware images:\n")
    for model, info in KNOWN_FIRMWARE_SOURCES.items():
        print(f"  Model: {model} - {info['description']}")
        for ver, vinfo in info['versions'].items():
            enc = " [ENCRYPTED]" if vinfo.get('encrypted_rootfs') else ""
            print(f"    {ver}: {vinfo['description']}{enc}")
            print(f"      URL: {vinfo['url']}")
        print()


def download_firmware(model, version, output_dir='.'):
    """Download a specific firmware version."""
    model = model.upper()
    if model not in KNOWN_FIRMWARE_SOURCES:
        print(f"[-] Unknown model: {model}")
        print(f"    Available: {', '.join(KNOWN_FIRMWARE_SOURCES.keys())}")
        return None

    versions = KNOWN_FIRMWARE_SOURCES[model]['versions']

    if version == 'latest':
        # Sort by version string to find actual latest
        version = sorted(versions.keys())[-1]
        print(f"[*] Latest version: {version}")

    if version == 'all':
        paths = []
        for v in versions:
            p = download_firmware(model, v, output_dir)
            if p:
                paths.append(p)
        return paths

    if version not in versions:
        print(f"[-] Unknown version: {version}")
        print(f"    Available: {', '.join(versions.keys())}")
        return None

    vinfo = versions[version]
    url = vinfo['url']
    filename = url.split('/')[-1]
    filepath = os.path.join(output_dir, filename)

    if os.path.exists(filepath):
        print(f"[+] Already downloaded: {filepath}")
        return filepath

    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Downloading: {vinfo['description']}")
    print(f"    URL: {url}")
    print(f"    Output: {filepath}")

    try:
        _download_with_progress(url, filepath)
        print(f"[+] Downloaded: {filepath} ({os.path.getsize(filepath)} bytes)")

        # Calculate checksums
        md5 = _file_hash(filepath, hashlib.md5)
        sha256 = _file_hash(filepath, hashlib.sha256)
        print(f"    MD5:    {md5}")
        print(f"    SHA256: {sha256}")

        return filepath

    except urllib.error.URLError as e:
        print(f"[-] Download failed: {e}")
        if os.path.exists(filepath):
            os.remove(filepath)
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        if os.path.exists(filepath):
            os.remove(filepath)
        return None


def _download_with_progress(url, filepath):
    """Download file with progress indicator."""
    req = urllib.request.Request(url, headers={'User-Agent': 'HuaweiFirmwareTool/1.0'})
    with urllib.request.urlopen(req) as response:
        total = int(response.headers.get('Content-Length', 0))
        downloaded = 0
        chunk_size = 1024 * 1024  # 1MB

        with open(filepath, 'wb') as f:
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    total_mb = total / (1024 * 1024)
                    print(f"\r    Progress: {pct}% ({mb:.1f}/{total_mb:.1f} MB)", end='', flush=True)

        if total > 0:
            print()


def _file_hash(filepath, hash_func):
    """Calculate file hash."""
    h = hash_func()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


# ── Firmware Update Info ─────────────────────────────────────────────────────

def print_update_info():
    """Print detailed information about how Huawei ONT firmware updates work."""
    info = """
╔══════════════════════════════════════════════════════════════════════╗
║          Huawei ONT Firmware Update Mechanisms                     ║
╚══════════════════════════════════════════════════════════════════════╝

The Huawei HG8145V5 ONT supports three firmware update methods:

┌─────────────────────────────────────────────────────────────────────┐
│ 1. TR-069/CWMP (ISP-Managed Remote Update)                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ISP ACS Server ──── Download RPC ────> ONT Device                 │
│      (URL)          (firmware URL)      (downloads & flashes)      │
│                                                                     │
│  Protocol: SOAP/HTTP to ACS, then FTP/HTTP/TFTP for firmware       │
│                                                                     │
│  TR-069 Parameters:                                                 │
│    InternetGatewayDevice.ManagementServer.URL  (ACS URL)           │
│    InternetGatewayDevice.DeviceInfo.SoftwareVersion                │
│    InternetGatewayDevice.DeviceInfo.HardwareVersion                │
│                                                                     │
│  Download RPC fields:                                               │
│    FileType: "1 Firmware Upgrade Image"                            │
│    URL: ftp://server/path/firmware.bin                             │
│    TargetFileName: firmware filename                                │
│    CommandKey: unique operation identifier                          │
│                                                                     │
│  Device download commands (from libhw_swm_dll.so):                 │
│    FTP:  ftpget "<server>" "<remote_path>" <user> <pass>           │
│    HTTP: httpc -g -i -l <local_path> <url>                         │
│    TFTP: tftp -i -l "<local>" -r <remote> -g "<server>"           │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ 2. OMCI (OLT-Managed GPON Update)                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  OLT ──── Software Image Download ────> ONT                       │
│           (ME Class 7, section transfer)                           │
│                                                                     │
│  Flow:                                                              │
│    1. OLT sends StartDownload with image size                      │
│    2. OLT transfers image sections (windowed)                      │
│    3. OLT sends EndDownload                                        │
│    4. OLT sends ActivateImage                                      │
│    5. OLT sends CommitImage                                        │
│    6. ONT reboots with new firmware                                │
│                                                                     │
│  The ONT maintains two image slots (img0/img1):                    │
│    /var/activeflag - tracks which image is active                  │
│    /var/softversion - current version string                       │
│    /mnt/jffs2/commitupgrade - commit flag                         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ 3. Local Update (Manual)                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  a) Web Interface: Upload .bin through management page             │
│  b) TFTP Recovery: Hold reset, device requests firmware via TFTP   │
│     - Device IP: 192.168.1.1 (default)                             │
│     - TFTP server: 192.168.1.10                                    │
│     - Use hw_flash tool (included in this repo): ./hw_flash -s -f firmware.bin│
└─────────────────────────────────────────────────────────────────────┘

Firmware Validation (from UpgradeCheck.xml):
  - BoardId check: Must match device hardware
  - Chip checks: LSW, WiFi, Voice, USB, Optical, Other
  - Product check: ProductID must be in allowed list
  - Program check: E8C, COMMON, CHINA, CMCC, etc.
  - Signature check: RSA signature in signinfo section
"""
    print(info)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Huawei ONT Firmware Download & Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                              List available firmware
  %(prog)s --download HG8145V5 all             Download all versions
  %(prog)s --download HG8145V5 latest          Download latest version
  %(prog)s --download HG8145V5 V500R020C00SPC270  Download specific version
  %(prog)s --extract firmware.bin -o output/   Extract rootfs from firmware
  %(prog)s --info                              Show update mechanism info
        """)

    parser.add_argument('--list', action='store_true',
                        help='List available firmware versions')
    parser.add_argument('--download', nargs=2, metavar=('MODEL', 'VERSION'),
                        help='Download firmware (model version|all|latest)')
    parser.add_argument('--extract', metavar='FIRMWARE',
                        help='Extract rootfs from firmware .bin file')
    parser.add_argument('--info', action='store_true',
                        help='Show firmware update mechanism details')
    parser.add_argument('-o', '--output', default='.',
                        help='Output directory (default: current)')

    args = parser.parse_args()

    if not any([args.list, args.download, args.extract, args.info]):
        parser.print_help()
        return

    if args.info:
        print_update_info()

    if args.list:
        list_firmware()

    if args.download:
        model, version = args.download
        result = download_firmware(model, version, args.output)
        if result is None:
            sys.exit(1)

    if args.extract:
        if not os.path.exists(args.extract):
            print(f"[-] File not found: {args.extract}")
            sys.exit(1)
        if not extract_rootfs(args.extract, args.output):
            sys.exit(1)


if __name__ == '__main__':
    main()
