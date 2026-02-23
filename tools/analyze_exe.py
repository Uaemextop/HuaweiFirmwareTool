#!/usr/bin/env python3
"""
Static analysis tool for Windows PE32 executables.

Performs header parsing, section analysis, import/export enumeration,
string extraction, packer detection, and entropy calculation without
any external dependencies beyond the Python standard library.

Usage:
    python3 tools/analyze_exe.py <path_to_exe>
"""

import sys
import os
import struct
import hashlib
import math
import re
from collections import defaultdict


def calculate_entropy(data):
    """Calculate Shannon entropy of a data block."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def read_cstring(data, offset, max_len=256):
    """Read a null-terminated ASCII string."""
    end = data.find(b'\x00', offset)
    if end == -1 or end - offset > max_len:
        end = offset + max_len
    raw = data[offset:end]
    try:
        return raw.decode('ascii')
    except UnicodeDecodeError:
        return raw.decode('latin-1')


def parse_pe(filepath):
    """Parse a PE32 executable and return analysis results."""
    with open(filepath, 'rb') as f:
        data = f.read()

    results = {}

    # ── File hashes ──────────────────────────────────────────────
    results['file_size'] = len(data)
    results['md5'] = hashlib.md5(data).hexdigest()
    results['sha256'] = hashlib.sha256(data).hexdigest()

    # ── DOS Header ───────────────────────────────────────────────
    if len(data) < 64:
        print("ERROR: File too small for DOS header")
        return None

    e_magic = struct.unpack_from('<H', data, 0)[0]
    if e_magic != 0x5A4D:
        print("ERROR: Not a valid PE file (bad MZ signature)")
        return None

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    results['dos_header'] = {'e_magic': e_magic, 'e_lfanew': e_lfanew}

    # ── PE Signature ─────────────────────────────────────────────
    pe_sig = struct.unpack_from('<I', data, e_lfanew)[0]
    if pe_sig != 0x00004550:
        print("ERROR: Not a valid PE file (bad PE signature)")
        return None

    # ── COFF / File Header ───────────────────────────────────────
    coff_offset = e_lfanew + 4
    machine, num_sections, timestamp, sym_table, num_symbols, opt_size, characteristics = \
        struct.unpack_from('<HHIIIHH', data, coff_offset)

    machines = {0x14C: 'i386', 0x8664: 'AMD64', 0x1C0: 'ARM', 0xAA64: 'ARM64'}
    results['file_header'] = {
        'machine': machines.get(machine, f'0x{machine:04X}'),
        'num_sections': num_sections,
        'timestamp': timestamp,
        'characteristics': characteristics,
    }

    # ── Optional Header ──────────────────────────────────────────
    opt_offset = coff_offset + 20
    opt_magic = struct.unpack_from('<H', data, opt_offset)[0]
    is_pe32_plus = (opt_magic == 0x20B)

    linker_major, linker_minor = struct.unpack_from('<BB', data, opt_offset + 2)
    entry_point = struct.unpack_from('<I', data, opt_offset + 16)[0]
    if is_pe32_plus:
        image_base = struct.unpack_from('<Q', data, opt_offset + 24)[0]
    else:
        image_base = struct.unpack_from('<I', data, opt_offset + 28)[0]
    subsystem = struct.unpack_from('<H', data, opt_offset + 68)[0]

    results['optional_header'] = {
        'magic': 'PE32+' if is_pe32_plus else 'PE32',
        'linker_version': f'{linker_major}.{linker_minor}',
        'entry_point': entry_point,
        'image_base': image_base,
        'subsystem': 'GUI' if subsystem == 2 else ('Console' if subsystem == 3 else f'Unknown({subsystem})'),
    }

    # ── Sections ─────────────────────────────────────────────────
    section_offset = opt_offset + opt_size
    sections = []
    for i in range(num_sections):
        s_off = section_offset + i * 40
        name_raw = data[s_off:s_off + 8]
        name = name_raw.split(b'\x00')[0].decode('ascii', errors='replace')
        vsize, va, raw_size, raw_ptr, _, _, _, _, chars = \
            struct.unpack_from('<IIIIIIHHI', data, s_off + 8)

        section_data = data[raw_ptr:raw_ptr + raw_size] if raw_size > 0 else b''
        entropy = calculate_entropy(section_data)

        sections.append({
            'name': name,
            'virtual_address': va,
            'virtual_size': vsize,
            'raw_size': raw_size,
            'raw_offset': raw_ptr,
            'entropy': entropy,
            'characteristics': chars,
        })

    results['sections'] = sections

    # ── Imports ──────────────────────────────────────────────────
    # Parse Data Directories to find Import Table
    if is_pe32_plus:
        dd_count_offset = opt_offset + 108
        dd_offset = opt_offset + 112
    else:
        dd_count_offset = opt_offset + 92
        dd_offset = opt_offset + 96

    num_rva_sizes = struct.unpack_from('<I', data, dd_count_offset)[0] if dd_count_offset + 4 <= len(data) else 0
    imports = []

    if num_rva_sizes > 1:
        import_rva, import_size = struct.unpack_from('<II', data, dd_offset + 8)  # Import is 2nd entry (index 1)
        if import_rva > 0 and import_size > 0:
            # Convert RVA to file offset
            import_file_offset = None
            for s in sections:
                if s['virtual_address'] <= import_rva < s['virtual_address'] + s['virtual_size']:
                    import_file_offset = import_rva - s['virtual_address'] + s['raw_offset']
                    break

            if import_file_offset:
                idt_offset = import_file_offset
                while idt_offset + 20 <= len(data):
                    ilt_rva, ts, fwd, name_rva, iat_rva = struct.unpack_from('<IIIII', data, idt_offset)
                    if ilt_rva == 0 and name_rva == 0:
                        break

                    # Resolve DLL name
                    dll_name_offset = None
                    for s in sections:
                        if s['virtual_address'] <= name_rva < s['virtual_address'] + s['virtual_size']:
                            dll_name_offset = name_rva - s['virtual_address'] + s['raw_offset']
                            break

                    dll_name = read_cstring(data, dll_name_offset) if dll_name_offset else f'RVA_0x{name_rva:X}'
                    imports.append(dll_name)
                    idt_offset += 20

    results['imports'] = imports

    # ── Strings extraction ───────────────────────────────────────
    ascii_strings = re.findall(rb'[\x20-\x7E]{8,}', data)
    results['strings_count'] = len(ascii_strings)

    # Filter interesting strings
    interesting = []
    keywords = [
        rb'(?i)huawei', rb'(?i)firmware', rb'(?i)upgrade', rb'(?i)tftp',
        rb'(?i)password', rb'(?i)serial', rb'(?i)telnet', rb'(?i)unlock',
        rb'(?i)osbc', rb'(?i)ont', rb'(?i)gpon', rb'(?i)omci',
        rb'(?i)\.bin', rb'(?i)\.pdb', rb'(?i)version', rb'(?i)board',
        rb'(?i)flash', rb'(?i)boot', rb'(?i)socket', rb'(?i)udp',
    ]
    for s in ascii_strings:
        for kw in keywords:
            if re.search(kw, s):
                try:
                    interesting.append(s.decode('ascii'))
                except UnicodeDecodeError:
                    pass
                break

    results['interesting_strings'] = interesting[:100]

    # ── Packer / Compiler detection ──────────────────────────────
    detections = []
    section_names = [s['name'] for s in sections]

    if 'UPX0' in section_names or 'UPX1' in section_names:
        detections.append('UPX Packer')
    if '.ndata' in section_names:
        detections.append('NSIS Installer')
    if 'MPRESS1' in section_names:
        detections.append('MPRESS Packer')

    # Random section names (packing indicator)
    standard_names = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.bss',
                      '.idata', '.edata', '.tls', '.debug', '.gfids', '.giats', '.CRT'}
    non_standard = [n for n in section_names if n and n not in standard_names and not n.startswith('.')]
    if len(non_standard) > 2:
        detections.append(f'Possible packer (non-standard sections: {non_standard})')

    # High entropy detection
    high_entropy_sections = [s['name'] for s in sections if s['entropy'] > 7.5]
    if high_entropy_sections:
        detections.append(f'High entropy sections (packed/encrypted): {high_entropy_sections}')

    # Virtual-only sections
    virtual_only = [s['name'] for s in sections if s['raw_size'] == 0 and s['virtual_size'] > 0]
    if virtual_only:
        detections.append(f'Virtual-only sections (runtime unpacking): {virtual_only}')

    # Known signatures in data
    if b'Borland' in data or b'Delphi' in data:
        detections.append('Borland Delphi / C++ Builder')
    if b'Themida' in data:
        detections.append('Themida Protector')
    if b'VMProtect' in data:
        detections.append('VMProtect')
    if b'.?AV' in data and b'CWnd@@' in data:
        detections.append('MFC (Microsoft Foundation Classes)')
    if b'Poco' in data:
        detections.append('POCO C++ Libraries')

    results['detections'] = detections

    return results


def print_report(results, filepath):
    """Print a formatted analysis report."""
    name = os.path.basename(filepath)
    print(f"\n{'=' * 72}")
    print(f"  PE ANALYSIS REPORT: {name}")
    print(f"{'=' * 72}")

    print(f"\n  File Size  : {results['file_size']:,} bytes ({results['file_size']/1024/1024:.2f} MB)")
    print(f"  MD5        : {results['md5']}")
    print(f"  SHA-256    : {results['sha256']}")

    dh = results['dos_header']
    print(f"\n  DOS Header : e_magic=0x{dh['e_magic']:04X} (MZ)  e_lfanew=0x{dh['e_lfanew']:08X}")

    fh = results['file_header']
    print(f"\n  Machine    : {fh['machine']}")
    print(f"  Sections   : {fh['num_sections']}")
    print(f"  Timestamp  : 0x{fh['timestamp']:08X}")
    print(f"  Characteristics : 0x{fh['characteristics']:04X}")

    oh = results['optional_header']
    print(f"\n  PE Type    : {oh['magic']}")
    print(f"  Linker     : {oh['linker_version']}")
    print(f"  Entry Point: 0x{oh['entry_point']:08X}")
    print(f"  Image Base : 0x{oh['image_base']:08X}")
    print(f"  Subsystem  : {oh['subsystem']}")

    print(f"\n  {'Section':12s} {'VirtAddr':>10s} {'VirtSize':>10s} {'RawSize':>10s} {'Entropy':>8s} {'Chars':>10s}")
    print(f"  {'-' * 62}")
    for s in results['sections']:
        flag = ''
        if s['entropy'] > 7.5:
            flag = ' [PACKED]'
        if s['raw_size'] == 0 and s['virtual_size'] > 0:
            flag = ' [VIRTUAL]'
        print(f"  {s['name']:12s} 0x{s['virtual_address']:08X} 0x{s['virtual_size']:08X} "
              f"0x{s['raw_size']:08X} {s['entropy']:7.2f} 0x{s['characteristics']:08X}{flag}")

    print(f"\n  Imported DLLs ({len(results['imports'])}):")
    for dll in results['imports']:
        print(f"    - {dll}")

    if results['detections']:
        print(f"\n  Detections:")
        for d in results['detections']:
            print(f"    * {d}")

    print(f"\n  Strings: {results['strings_count']} total, {len(results['interesting_strings'])} relevant")
    if results['interesting_strings']:
        print(f"  Sample interesting strings:")
        for s in results['interesting_strings'][:20]:
            print(f"    \"{s[:100]}\"")

    print(f"\n{'=' * 72}\n")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    results = parse_pe(filepath)
    if results:
        print_report(results, filepath)


if __name__ == '__main__':
    main()
