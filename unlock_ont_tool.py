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

# Patches 3A-3E: License validation bypass
# Five code paths check the license init result and display "Init Lic.fail" (string
# ID 0x07e7) when the check fails. Four use "test eax,eax; jnz skip_error" where
# eax!=0 means success; we change jnz to jmp (always skip error). The fifth uses
# "test esi,esi; jnz show_error" where esi!=0 means failure; we NOP the jnz.
LICENSE_CHECK_1 = {
    'offset': 0x04790e,
    'original': b'\x75',  # jnz (skip error if eax!=0)
    'patched': b'\xeb',   # jmp (always skip error)
    'description': 'License validation bypass 1 (always skip Init Lic.fail)',
}
LICENSE_CHECK_2 = {
    'offset': 0x047aed,
    'original': b'\x75',
    'patched': b'\xeb',
    'description': 'License validation bypass 2 (always skip Init Lic.fail)',
}
LICENSE_CHECK_3 = {
    'offset': 0x047dc5,
    'original': b'\x75',
    'patched': b'\xeb',
    'description': 'License validation bypass 3 (always skip Init Lic.fail)',
}
LICENSE_CHECK_4 = {
    'offset': 0x048092,
    'original': b'\x75\x5a',  # jnz +0x5a (jump to error if esi!=0)
    'patched': b'\x90\x90',   # nop nop (never jump to error)
    'description': 'License validation bypass 4 (never show Init Lic.fail)',
}
LICENSE_CHECK_5 = {
    'offset': 0x04a139,
    'original': b'\x75',
    'patched': b'\xeb',
    'description': 'License validation bypass 5 (always skip Init Lic.fail)',
}

# Patches 4A-4E: NOP the AfxMessageBox calls in each error display block
# Even if execution somehow reaches the error display code (e.g. via exception
# handler or computed jump), these NOPs prevent the MessageBox from appearing.
# Replace "call AfxMessageBox" (e8 XX XX XX XX) with "xor eax,eax; nop; nop; nop"
# so eax=0 is returned (no dialog result).
MSGBOX_NOP_1 = {
    'offset': 0x047927,
    'original': b'\xe8\x94\x3a\xfc\xff',
    'patched': b'\x33\xc0\x90\x90\x90',
    'description': 'NOP AfxMessageBox in error block 1',
}
MSGBOX_NOP_2 = {
    'offset': 0x047b06,
    'original': b'\xe8\xb5\x38\xfc\xff',
    'patched': b'\x33\xc0\x90\x90\x90',
    'description': 'NOP AfxMessageBox in error block 2',
}
MSGBOX_NOP_3 = {
    'offset': 0x047dde,
    'original': b'\xe8\xdd\x35\xfc\xff',
    'patched': b'\x33\xc0\x90\x90\x90',
    'description': 'NOP AfxMessageBox in error block 3',
}
MSGBOX_NOP_4 = {
    'offset': 0x048108,
    'original': b'\xe8\xb3\x32\xfc\xff',
    'patched': b'\x33\xc0\x90\x90\x90',
    'description': 'NOP AfxMessageBox in error block 4',
}
MSGBOX_NOP_5 = {
    'offset': 0x04a152,
    'original': b'\xe8\x69\x12\xfc\xff',
    'patched': b'\x33\xc0\x90\x90\x90',
    'description': 'NOP AfxMessageBox in error block 5',
}

CODE_PATCHES = [
    TIMER_BYPASS, MENU_ENABLE_1, MENU_ENABLE_2,
    LICENSE_CHECK_1, LICENSE_CHECK_2, LICENSE_CHECK_3,
    LICENSE_CHECK_4, LICENSE_CHECK_5,
    MSGBOX_NOP_1, MSGBOX_NOP_2, MSGBOX_NOP_3,
    MSGBOX_NOP_4, MSGBOX_NOP_5,
]

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

# Error string to blank out as final safety net
# Even if all other patches fail, blanking this string ensures no alarming
# error message is shown to the user
ERROR_STRING_BLANK = {
    'offset': 0x3cfea4,
    'original_text': '初始化License信息失败',
    'replacement_text': 'OK',
    'translated_text': 'Init Lic.fail',
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


def blank_error_string(file_data):
    """Replace the 'Init Lic.fail' error string with 'OK' as final safety net."""
    info = ERROR_STRING_BLANK
    offset = info['offset']
    orig_cn = info['original_text'].encode('utf-16-le')
    translated = info['translated_text'].encode('utf-16-le')
    replacement = info['replacement_text'].encode('utf-16-le')
    orig_len = len(orig_cn)

    actual = bytes(file_data[offset:offset + orig_len])
    if actual[:len(translated)] == translated or actual[:len(orig_cn)] == orig_cn:
        if len(replacement) > orig_len:
            print(f'  WARNING: replacement too long for 0x{offset:06x}, skipping')
            return
        # Replace with short benign text + null padding
        file_data[offset:offset + orig_len] = (
            replacement + b'\x00' * (orig_len - len(replacement)))
        print(f'  Blanked error string at 0x{offset:06x}: -> "{info["replacement_text"]}"')
    elif actual[:len(replacement)] == replacement:
        print(f'  Error string already blanked at 0x{offset:06x}')
    else:
        print(f'  WARNING: Unexpected content at 0x{offset:06x}, skipping')


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

    # Blank the error string as final safety net
    blank_error_string(file_data)

    # Fix PE checksum
    fixup_pe_checksum(file_data)

    with open(output_path, 'wb') as f:
        f.write(file_data)

    print(f'  Output size: {len(file_data)} bytes')
    print('Done!')


if __name__ == '__main__':
    main()
