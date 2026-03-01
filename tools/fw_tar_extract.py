#!/usr/bin/env python3
"""
fw_tar_extract.py – Extract ALL embedded tar.gz archives from Huawei HWNP firmware .bin files.

Scans every HWNP firmware package in the realfirmware-net repository, parses each
HWNP item section, detects embedded gzip/tar archives, extracts them, and recursively
unpacks nested archives (CPK, IPK, webs.tar.gz).

Archive types found:
  file:/var/equipment.tar.gz          – RTK diagnostic tools (diag, librtk.so, CLI XMLs)
  file:/mnt/jffs2/customize_xml.tar.gz – China province ctree defaults (42 XML files)
  file:/mnt/jffs2/app/plugin_preload.tar.gz – kernelapp.cpk (MyPlugin bundle)
    → MyPlugin/bin/kernelapp           – Huawei cloud agent (ARM32 ELF)
    → MyPlugin/Lib/libsrv.so           – Service library
    → MyPlugin/Lib/libmbedall.so       – mbedTLS bundle
    → MyPlugin/etc/config/kernelapp.config – CLOUD CREDENTIALS ← IMPORTANT
    → MyPlugin/etc/res/webs.tar.gz     – Web UI resources
  file:/mnt/jffs2/app/ThirdPartyPlugin.tar.gz – mabr.cpk (NanoCDN plugin)
  plugin_preload/eaiapp.ipk            – AI traffic classification app

Key findings:
  AppString:   "abc###78d!"               ← same in ALL firmware versions
  netopenip:   homenetwork.189cube.com    ← Huawei cloud server
  restssl_key: "$2*fR[YH14,Q<Q8SOgV..."  ← REST API SSL passphrase (R019/R020)
  restssl_key: "$22L;NS]5GTU=}:AUAXKcW..." ← REST API SSL passphrase (R022+)
  mqtt_port:   1884 (TLS off), rest_port: 9013 (TLS on)

Usage:
    python3 tools/fw_tar_extract.py [--firmware-dir <path>] [--out <dir>] [--verbose]

Requirements:
    pip install (none – uses stdlib only)
    The hwflash package (in this repo) for HWNP parsing.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FW_DIR = Path("/tmp/realfirmware-net")
DEFAULT_OUT    = REPO_ROOT / "extracted"

sys.path.insert(0, str(REPO_ROOT))
from hwflash.core.firmware import HWNPFirmware


# ---------------------------------------------------------------------------
# Archive detection and extraction helpers
# ---------------------------------------------------------------------------

def _try_unpack_nested(data: bytes, label: str, dest: Path, verbose: bool = False):
    """Recursively unpack nested archives (gzip inside gzip, tar inside gzip, etc.)."""
    dest.mkdir(parents=True, exist_ok=True)

    # gzip
    if data[:2] == b'\x1f\x8b':
        try:
            inner = gzip.decompress(data)
        except Exception:
            return []
        # tar inside gzip
        if inner[257:262] == b'ustar' or inner[:5] == b'./\x00\x00\x00':
            return _extract_tar(inner, label, dest, verbose)
        # double-gzip
        if inner[:2] == b'\x1f\x8b':
            return _try_unpack_nested(inner, label, dest, verbose)
        # write raw decompressed
        (dest / f"{label}.decompressed").write_bytes(inner)
        return [(label, len(inner), 'raw')]

    # plain tar
    if data[257:262] == b'ustar':
        return _extract_tar(data, label, dest, verbose)

    # AR (IPK)
    if data[:7] == b'!<arch>':
        return _extract_ipk(data, label, dest, verbose)

    # ZIP
    if data[:4] == b'PK\x03\x04':
        return _extract_zip(data, label, dest, verbose)

    return []


def _extract_tar(data: bytes, label: str, dest: Path, verbose: bool) -> list:
    """Extract tar archive and return list of (name, size, type) tuples."""
    results = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tf:
            members = tf.getmembers()
            tf.extractall(path=str(dest))
            for m in members:
                if not m.isdir():
                    results.append((m.name, m.size, 'file'))
                    if verbose:
                        print(f"      {m.size:>10,} B  {m.name}")
            # Recursively expand nested archives
            for m in members:
                if m.isdir():
                    continue
                mpath = dest / m.name
                if not mpath.exists():
                    continue
                ext = ''.join(mpath.suffixes).lower()
                if ext in ('.tar.gz', '.tgz', '.cpk', '.ipk', '.gz'):
                    nested_out = mpath.parent / (mpath.stem.split('.')[0] + '_extracted')
                    nested = _try_unpack_nested(mpath.read_bytes(), mpath.stem, nested_out, verbose)
                    if nested:
                        results.extend([('  nested/' + n, s, t) for n, s, t in nested])
    except Exception as e:
        if verbose:
            print(f"      [tar error] {e}")
    return results


def _extract_ipk(data: bytes, label: str, dest: Path, verbose: bool) -> list:
    """Extract Debian-style .ipk (ar archive) and expand data.tar.gz."""
    dest.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.NamedTemporaryFile(suffix='.ipk', delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        subprocess.run(['ar', 'x', '--output', str(dest), tmp_path],
                       capture_output=True, check=True)
        data_tgz = dest / 'data.tar.gz'
        if data_tgz.exists():
            inner_out = dest / 'data'
            results = _try_unpack_nested(data_tgz.read_bytes(), 'data', inner_out, verbose)
    except Exception as e:
        if verbose:
            print(f"      [ipk error] {e}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return results


def _extract_zip(data: bytes, label: str, dest: Path, verbose: bool) -> list:
    """Extract ZIP archive."""
    import zipfile
    results = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(path=str(dest))
            for name in zf.namelist():
                info = zf.getinfo(name)
                if not name.endswith('/'):
                    results.append((name, info.file_size, 'file'))
    except Exception as e:
        if verbose:
            print(f"      [zip error] {e}")
    return results


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

class FirmwareTarExtractor:
    """Extract all tar.gz archives from Huawei HWNP firmware files."""

    def __init__(self, fw_dir: Path, out_dir: Path, verbose: bool = False):
        self.fw_dir  = fw_dir
        self.out_dir = out_dir
        self.verbose = verbose
        self.results: list[dict] = []

    def run(self):
        """Process all .bin files and extract tar archives."""
        bin_files = sorted(self.fw_dir.rglob('*.bin'))
        huawei_bins = [b for b in bin_files
                       if '/Huawei' in str(b) and b.stat().st_size > 1000]

        print(f"[+] Scanning {len(huawei_bins)} Huawei firmware files …\n")

        for bf in sorted(huawei_bins, key=lambda x: x.stat().st_size):
            self._process_file(bf)

        self._write_report()
        return self.results

    def _process_file(self, bf: Path):
        rel = str(bf).replace(str(self.fw_dir) + '/', '')
        if self.verbose:
            print(f"[{rel}] ({bf.stat().st_size:,} B)")
        try:
            fw = HWNPFirmware()
            fw.load(str(bf))
        except Exception as e:
            if self.verbose:
                print(f"  [ERROR] {e}")
            return

        for item in fw.items:
            d    = item.data
            sec  = item.section
            path = item.item_path

            # Detect gzip at start of item data
            if d[:2] != b'\x1f\x8b':
                continue

            # Check if it decompresses to a tar
            try:
                inner = gzip.decompress(d)
            except Exception:
                continue

            if not (inner[257:262] == b'ustar' or inner[:5] == b'./\x00\x00\x00'):
                # Not a tar → skip
                continue

            md5 = hashlib.md5(d).hexdigest()
            safe_rel  = rel.replace('/', '_').replace(' ', '_')
            dest = self.out_dir / safe_rel / sec.replace('/', '_')

            print(f"  ✓ tar.gz  [{sec}]  {path!r}")
            print(f"    {len(d):,} B → {len(inner):,} B uncompressed")

            files = _extract_tar(inner, path.split('/')[-1], dest, self.verbose)

            print(f"    {len(files)} files extracted → {dest}")
            self.results.append({
                'firmware': rel,
                'section':  sec,
                'path':     path,
                'size_gz':  len(d),
                'size_raw': len(inner),
                'md5_gz':   md5,
                'files':    [f[0] for f in files if f[2] == 'file'],
                'dest':     str(dest),
            })

    def _write_report(self):
        """Write JSON summary and markdown report."""
        self.out_dir.mkdir(parents=True, exist_ok=True)
        report_json = self.out_dir / 'tar_extract_report.json'
        report_json.write_text(json.dumps(self.results, indent=2))

        lines = ['# Firmware tar.gz Extraction Report\n',
                 f'Found **{len(self.results)}** tar.gz archives\n\n']

        # Group by archive path
        by_path: dict[str, list] = {}
        for r in self.results:
            by_path.setdefault(r['path'], []).append(r['firmware'])

        lines.append('## Unique Archive Types\n\n')
        for path, fws in sorted(by_path.items()):
            r = next(x for x in self.results if x['path'] == path)
            lines.append(f'### `{path}`\n')
            lines.append(f'- Appears in {len(fws)} firmware file(s)\n')
            lines.append(f'- Uncompressed: {r["size_raw"]:,} B\n')
            if r["files"]:
                lines.append('- Files:\n')
                for f in sorted(set(r["files"]))[:20]:
                    lines.append(f'  - `{f}`\n')
            lines.append('\n')

        # Credentials
        kc = self.out_dir / 'kernelapp'
        for version_dir in sorted(kc.glob('*/kernelapp.config')) if kc.exists() else []:
            try:
                cfg = json.loads(version_dir.read_text())
                lines.append(f'## Credentials from kernelapp ({version_dir.parent.name})\n\n')
                for k in ['netopenip', 'netopenport', 'securityport', 'mqttport',
                          'mqttssl', 'restssl_key', 'AppString']:
                    if k in cfg:
                        lines.append(f'- `{k}`: `{cfg[k]}`\n')
                lines.append('\n')
            except Exception:
                pass

        report_md = self.out_dir / 'TAR_EXTRACT_REPORT.md'
        report_md.write_text(''.join(lines))
        print(f'\n[+] Report: {report_md}')
        print(f'[+] JSON:   {report_json}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--firmware-dir', default=str(DEFAULT_FW_DIR),
                    help='Path to realfirmware-net clone')
    ap.add_argument('--out', default=str(DEFAULT_OUT),
                    help='Output directory for extracted files')
    ap.add_argument('--verbose', '-v', action='store_true',
                    help='Verbose output')
    args = ap.parse_args(argv)

    extractor = FirmwareTarExtractor(
        fw_dir=Path(args.firmware_dir),
        out_dir=Path(args.out),
        verbose=args.verbose,
    )
    results = extractor.run()
    print(f'\n[+] Done. {len(results)} archives extracted.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
