#!/usr/bin/env python3
"""
Analysis script for Windows PE executables
Performs basic static analysis without requiring specialized tools
"""
import struct
import sys
import os
from pathlib import Path

def read_dos_header(data):
    """Read DOS header"""
    if data[:2] != b'MZ':
        return None
    e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
    return e_lfanew

def read_pe_header(data, offset):
    """Read PE header"""
    if data[offset:offset+4] != b'PE\x00\x00':
        return None

    # COFF header
    machine = struct.unpack('<H', data[offset+4:offset+6])[0]
    num_sections = struct.unpack('<H', data[offset+6:offset+8])[0]
    time_stamp = struct.unpack('<I', data[offset+8:offset+12])[0]
    size_optional = struct.unpack('<H', data[offset+20:offset+22])[0]
    characteristics = struct.unpack('<H', data[offset+22:offset+24])[0]

    return {
        'machine': machine,
        'num_sections': num_sections,
        'timestamp': time_stamp,
        'size_optional': size_optional,
        'characteristics': characteristics,
        'optional_header_offset': offset + 24
    }

def read_optional_header(data, offset, size):
    """Read optional header"""
    if size == 0:
        return None

    magic = struct.unpack('<H', data[offset:offset+2])[0]

    if magic == 0x10b:  # PE32
        entry_point = struct.unpack('<I', data[offset+16:offset+20])[0]
        image_base = struct.unpack('<I', data[offset+28:offset+32])[0]
        section_alignment = struct.unpack('<I', data[offset+32:offset+36])[0]
        file_alignment = struct.unpack('<I', data[offset+36:offset+40])[0]
        size_of_image = struct.unpack('<I', data[offset+56:offset+60])[0]
        subsystem = struct.unpack('<H', data[offset+68:offset+70])[0]

        return {
            'magic': 'PE32',
            'entry_point': entry_point,
            'image_base': image_base,
            'section_alignment': section_alignment,
            'file_alignment': file_alignment,
            'size_of_image': size_of_image,
            'subsystem': subsystem
        }

    return None

def read_sections(data, pe_offset, pe_header):
    """Read section headers"""
    sections = []
    section_offset = pe_header['optional_header_offset'] + pe_header['size_optional']

    for i in range(pe_header['num_sections']):
        offset = section_offset + i * 40
        name = data[offset:offset+8].rstrip(b'\x00').decode('utf-8', errors='ignore')
        virtual_size = struct.unpack('<I', data[offset+8:offset+12])[0]
        virtual_address = struct.unpack('<I', data[offset+12:offset+16])[0]
        raw_size = struct.unpack('<I', data[offset+16:offset+20])[0]
        raw_address = struct.unpack('<I', data[offset+20:offset+24])[0]
        characteristics = struct.unpack('<I', data[offset+36:offset+40])[0]

        sections.append({
            'name': name,
            'virtual_size': virtual_size,
            'virtual_address': virtual_address,
            'raw_size': raw_size,
            'raw_address': raw_address,
            'characteristics': characteristics
        })

    return sections

def extract_strings(data, min_len=4):
    """Extract ASCII strings from binary data"""
    strings = []
    current = b''

    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                try:
                    strings.append(current.decode('ascii'))
                except:
                    pass
            current = b''

    if len(current) >= min_len:
        try:
            strings.append(current.decode('ascii'))
        except:
            pass

    return strings

def analyze_exe(filepath):
    """Perform analysis on an EXE file"""
    print(f"\n{'='*80}")
    print(f"ANALYZING: {os.path.basename(filepath)}")
    print(f"{'='*80}\n")

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File Size: {len(data):,} bytes ({len(data)/1024:.2f} KB)")

    # DOS Header
    pe_offset = read_dos_header(data)
    if not pe_offset:
        print("ERROR: Not a valid PE file (missing MZ signature)")
        return

    print(f"PE Header Offset: 0x{pe_offset:X}")

    # PE Header
    pe_header = read_pe_header(data, pe_offset)
    if not pe_header:
        print("ERROR: Invalid PE header")
        return

    machine_types = {
        0x014c: "Intel 386 (x86)",
        0x8664: "x64 (AMD64)",
        0x01c0: "ARM little endian",
        0xaa64: "ARM64 little endian"
    }

    print(f"\nMachine Type: {machine_types.get(pe_header['machine'], f'Unknown (0x{pe_header['machine']:X})')}")
    print(f"Number of Sections: {pe_header['num_sections']}")
    print(f"Timestamp: {pe_header['timestamp']} (Unix timestamp)")
    print(f"Characteristics: 0x{pe_header['characteristics']:X}")

    # Optional Header
    opt_header = read_optional_header(data, pe_header['optional_header_offset'], pe_header['size_optional'])
    if opt_header:
        print(f"\nImage Type: {opt_header['magic']}")
        print(f"Entry Point: 0x{opt_header['entry_point']:X}")
        print(f"Image Base: 0x{opt_header['image_base']:X}")
        print(f"Size of Image: {opt_header['size_of_image']:,} bytes")

        subsystems = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI (Console)",
            5: "OS/2 CUI",
            7: "POSIX CUI",
            9: "Windows CE GUI"
        }
        print(f"Subsystem: {subsystems.get(opt_header['subsystem'], f'Unknown ({opt_header['subsystem']})')}")

    # Sections
    sections = read_sections(data, pe_offset, pe_header)
    print(f"\n{'='*80}")
    print("SECTIONS:")
    print(f"{'='*80}")
    for section in sections:
        print(f"\nName: {section['name']}")
        print(f"  Virtual Address: 0x{section['virtual_address']:X}")
        print(f"  Virtual Size: {section['virtual_size']:,} bytes")
        print(f"  Raw Size: {section['raw_size']:,} bytes")
        print(f"  Raw Address: 0x{section['raw_address']:X}")
        print(f"  Characteristics: 0x{section['characteristics']:X}")

        # Decode characteristics
        chars = []
        if section['characteristics'] & 0x20:
            chars.append("CODE")
        if section['characteristics'] & 0x40:
            chars.append("INITIALIZED_DATA")
        if section['characteristics'] & 0x80:
            chars.append("UNINITIALIZED_DATA")
        if section['characteristics'] & 0x20000000:
            chars.append("EXECUTABLE")
        if section['characteristics'] & 0x40000000:
            chars.append("READABLE")
        if section['characteristics'] & 0x80000000:
            chars.append("WRITABLE")

        if chars:
            print(f"  Flags: {', '.join(chars)}")

    # Extract interesting strings
    print(f"\n{'='*80}")
    print("INTERESTING STRINGS:")
    print(f"{'='*80}")

    strings = extract_strings(data, min_len=8)

    # Filter for interesting patterns
    interesting_keywords = [
        'http', 'https', 'ftp', 'file://',
        'password', 'user', 'admin', 'root',
        'serial', 'telnet', 'ssh', 'cmd', 'shell',
        'huawei', 'ont', 'firmware', 'upgrade',
        'ip', 'address', 'port', 'socket',
        'registry', 'software', 'system32',
        'unlock', 'crack', 'patch', 'debug',
        'version', 'copyright', '.exe', '.dll', '.bin',
        'error', 'success', 'failed', 'warning'
    ]

    interesting_strings = []
    for s in strings:
        s_lower = s.lower()
        for keyword in interesting_keywords:
            if keyword in s_lower:
                interesting_strings.append(s)
                break

    # Remove duplicates while preserving order
    seen = set()
    unique_interesting = []
    for s in interesting_strings:
        if s not in seen:
            seen.add(s)
            unique_interesting.append(s)

    # Limit output
    for s in unique_interesting[:50]:
        print(f"  {s}")

    if len(unique_interesting) > 50:
        print(f"\n  ... and {len(unique_interesting) - 50} more interesting strings")

    # Check for common packers
    print(f"\n{'='*80}")
    print("PACKER DETECTION:")
    print(f"{'='*80}")

    packer_signatures = {
        b'UPX': 'UPX (Ultimate Packer for eXecutables)',
        b'MPRESS': 'MPRESS',
        b'Themida': 'Themida',
        b'WinRAR': 'WinRAR SFX',
        b'7-Zip': '7-Zip SFX',
        b'Nullsoft': 'NSIS (Nullsoft Scriptable Install System)',
    }

    found_packers = []
    for sig, name in packer_signatures.items():
        if sig in data:
            found_packers.append(name)

    if found_packers:
        print("Possible packers/tools detected:")
        for packer in found_packers:
            print(f"  - {packer}")
    else:
        print("No common packers detected")

    # Entropy calculation (high entropy might indicate encryption/compression)
    from collections import Counter
    import math
    byte_counts = Counter(data)
    file_size = len(data)
    entropy = 0
    for count in byte_counts.values():
        if count > 0:
            probability = count / file_size
            entropy -= probability * math.log2(probability)

    print(f"\nFile Entropy: {entropy:.2f} (0=low, 8=high)")
    if entropy > 7.5:
        print("  High entropy - likely compressed or encrypted")
    elif entropy > 6.5:
        print("  Medium-high entropy - possibly packed")
    else:
        print("  Normal entropy for executable code")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_exe.py <exe_file> [exe_file2 ...]")
        sys.exit(1)

    for exe_path in sys.argv[1:]:
        if not os.path.exists(exe_path):
            print(f"ERROR: File not found: {exe_path}")
            continue
        analyze_exe(exe_path)
