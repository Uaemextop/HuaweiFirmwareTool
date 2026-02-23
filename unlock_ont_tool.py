#!/usr/bin/env python3
"""
unlock_ont_tool.py - Unlock hidden options and menus in ONT_V100R002C00SPC253.exe

This script patches the Huawei OBSCTool binary to:
  1. Bypass the license validation timer that forces the app to close
  2. Enable all greyed-out menu items (firmware management commands)
  3. Translate remaining untranslated Chinese strings

Usage:
    python3 unlock_ont_tool.py <input.exe> <output.exe>

The input can be the original Chinese EXE or the already-translated English EXE.
"""
import struct
import sys


# --- Patch definitions ---

# Patch 1: License timer bypass
# The function at file offset 0x04a2d0 sets up a 5-second countdown timer
# that closes the application when the license is invalid.
# Original: 6A 00 (push 0) starts pushing SetTimer parameters
# Patched:  EB 1D (jmp +0x1D) skips directly to "mov eax, 1; pop esi; ret"
TIMER_BYPASS = {
    'offset': 0x04a2d8,
    'original': b'\x6a\x00',
    'patched': b'\xeb\x1d',
    'description': 'Skip license countdown timer (jmp to return 1)',
}

# Patch 2A: Menu enable function 1 (at 0x0fe293)
# This function disables menu items 0x4211, 0x4212, 0x4213, 0x4214, 0x420F
# by pushing MF_GRAYED (1) via EDI register: xor edi,edi; inc edi
# Patching INC EDI to NOP keeps EDI=0 (MF_ENABLED)
MENU_ENABLE_1 = {
    'offset': 0x0fe29d,
    'original': b'\x47',  # inc edi
    'patched': b'\x90',   # nop
    'description': 'Enable menu items in bulk-disable function 1 (5 items)',
}

# Patch 2B: Menu enable function 2 (at 0x11ac40)
# This function disables 7 menu items (0x4211-0x4215, 0x420E, 0x420F)
# Same pattern: xor ebx,ebx; inc ebx -> MF_GRAYED
# Patching INC EBX to NOP keeps EBX=0 (MF_ENABLED)
MENU_ENABLE_2 = {
    'offset': 0x11ac4a,
    'original': b'\x43',  # inc ebx
    'patched': b'\x90',   # nop
    'description': 'Enable menu items in bulk-disable function 2 (7 items)',
}

CODE_PATCHES = [TIMER_BYPASS, MENU_ENABLE_1, MENU_ENABLE_2]

# Remaining untranslated UTF-16LE strings
# Format: {file_offset: (chinese, english, max_bytes)}
# Note: '$year' is a literal placeholder in the original binary, not a variable
REMAINING_UTF16_TRANSLATIONS = {
    0x3cfdb8: ('License已注册', 'Lic. OK', 24),
    0x3cfdd0: ('程序License无效！程序将在%d秒后关闭！',
               'Lic invalid!Close %ds!', 48),
    0x3cff30: ('2020-$year 保留一切权利',
               '2020-$year (C)', 36),
}


def apply_code_patches(file_data):
    """Apply binary code patches to bypass license and enable menus."""
    count = 0
    for patch in CODE_PATCHES:
        offset = patch['offset']
        original = patch['original']
        patched = patch['patched']
        desc = patch['description']

        actual = bytes(file_data[offset:offset + len(original)])
        if actual == original:
            file_data[offset:offset + len(patched)] = patched
            count += 1
            print(f'  Patched 0x{offset:06x}: {desc}')
        elif actual == patched:
            print(f'  Already patched 0x{offset:06x}: {desc}')
            count += 1
        else:
            print(f'  WARNING: Unexpected bytes at 0x{offset:06x}: '
                  f'{actual.hex()} (expected {original.hex()}), skipping')
    return count


def patch_remaining_strings(file_data):
    """Patch remaining untranslated UTF-16LE strings."""
    count = 0
    for offset, (chinese, english, max_bytes) in REMAINING_UTF16_TRANSLATIONS.items():
        cn_encoded = chinese.encode('utf-16-le')
        en_encoded = english.encode('utf-16-le')

        if len(en_encoded) + 2 > max_bytes:  # +2 for UTF-16LE null terminator
            print(f'  WARNING: "{english}" too long for 0x{offset:x}, skipping')
            continue

        actual = bytes(file_data[offset:offset + len(cn_encoded)])
        if actual == cn_encoded:
            file_data[offset:offset + max_bytes] = (
                en_encoded + b'\x00' * (max_bytes - len(en_encoded)))
            count += 1
        elif actual[:len(en_encoded)] == en_encoded:
            pass  # Already translated
        else:
            print(f'  WARNING: Unexpected content at 0x{offset:x}, skipping')
    print(f'  Translated {count} remaining UTF-16LE strings')
    return count


def fixup_pe_checksum(file_data):
    """Recalculate and update the PE checksum."""
    # PE header offset
    pe_offset = struct.unpack_from('<I', file_data, 0x3C)[0]
    checksum_offset = pe_offset + 88  # OptionalHeader.CheckSum

    # Zero out current checksum
    file_data[checksum_offset:checksum_offset + 4] = b'\x00\x00\x00\x00'

    # Calculate new checksum (PE checksum algorithm)
    checksum = 0
    size = len(file_data)
    for i in range(0, size & ~1, 2):
        val = struct.unpack_from('<H', file_data, i)[0]
        checksum += val
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    if size % 2:
        checksum += file_data[-1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += size

    struct.pack_into('<I', file_data, checksum_offset, checksum & 0xFFFFFFFF)


def main():
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <input.exe> <output.exe>')
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    print(f'Unlocking ONT tool: {input_path} -> {output_path}')

    with open(input_path, 'rb') as f:
        file_data = bytearray(f.read())

    print(f'  Input size: {len(file_data)} bytes')

    # Apply code patches
    code_count = apply_code_patches(file_data)
    print(f'  Applied {code_count}/{len(CODE_PATCHES)} code patches')

    # Translate remaining strings
    patch_remaining_strings(file_data)

    # Fix PE checksum
    fixup_pe_checksum(file_data)

    with open(output_path, 'wb') as f:
        f.write(file_data)

    print(f'  Output size: {len(file_data)} bytes')
    print('Done!')


if __name__ == '__main__':
    main()
