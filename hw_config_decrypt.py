#!/usr/bin/env python3
"""
Huawei ONT Config Decryptor — Decrypts $2...$ encrypted strings from hw_ctree.xml

Based on reverse engineering of Huawei ONT firmware encryption and the
huawei-utility-page project (https://github.com/andreluis034/huawei-utility-page).

Encryption: AES-128-CBC with a hardcoded 256-bit key.
Encoding: Custom base-93 with ASCII visibility mapping.

The $2...$ format is used inside Huawei config XML files (hw_ctree.xml)
to protect passwords, keys, and other sensitive values.

Usage:
    python3 hw_config_decrypt.py --decrypt '$2encrypted_string$'
    python3 hw_config_decrypt.py --encrypt 'plaintext'
    python3 hw_config_decrypt.py --file decrypted_hw_ctree.xml
"""

import argparse
import os
import re
import struct
import sys

from Crypto.Cipher import AES

# Hardcoded AES key used by all Huawei ONTs for $2...$ config field encryption
# (NOT the same as the eFuse/KMC key used for file-level encryption)
HW_CONFIG_KEY = bytes.fromhex(
    "6fc6e3436a53b6310dc09a475494ac774e7afb21b9e58fc8e58b5660e48e2498"
)

BLOCK_SIZE = 0x14  # 20 encoded bytes = 16 binary bytes (4 groups of 5→4)
BASE93 = 0x5D


def _asc_unvisible(encoded_str):
    """Decode ASCII-visible encoding to raw byte values."""
    buf = bytearray(len(encoded_str))
    for i, ch in enumerate(encoded_str):
        code = ord(ch)
        if code == 0x7E:  # '~'
            buf[i] = 0x1E
        else:
            buf[i] = code - 0x21
    return buf


def _asc_visible(buf):
    """Encode raw byte values to ASCII-visible string."""
    out = []
    for b in buf:
        if b == 0x1E:
            out.append('~')
        else:
            out.append(chr(b + 0x21))
    return ''.join(out)


def _base93_to_long(group):
    """Convert a 5-byte base-93 group to a 32-bit integer."""
    result = 0
    multiplier = 1
    for i in range(5):
        result += multiplier * group[i]
        multiplier *= BASE93
    return result & 0xFFFFFFFF


def _long_to_base93(value):
    """Convert a 32-bit integer to a 5-byte base-93 group."""
    out = bytearray(5)
    for i in range(5):
        out[i] = value % BASE93
        value = value // BASE93
    return out


def _plain_to_bin(buf):
    """Convert base-93 encoded buffer (multiple of 5) to binary (multiple of 4)."""
    if len(buf) % 5 != 0:
        return None
    out = bytearray(len(buf) * 4 // 5)
    for i in range(0, len(out), 4):
        group_start = i * 5 // 4
        value = _base93_to_long(buf[group_start:group_start + 5])
        struct.pack_into('<I', out, i, value)
    return bytes(out)


def _bin_to_plain(buf):
    """Convert binary buffer (multiple of 4) to base-93 encoded (multiple of 5)."""
    if len(buf) % 4 != 0:
        return None
    out = bytearray(len(buf) * 5 // 4)
    for i in range(0, len(buf), 4):
        value = struct.unpack_from('<I', buf, i)[0]
        group = _long_to_base93(value)
        group_start = i * 5 // 4
        out[group_start:group_start + 5] = group
    return bytes(out)


def decrypt_field(encrypted_str, key=HW_CONFIG_KEY):
    """Decrypt a Huawei $2...$ encrypted config field.

    Args:
        encrypted_str: The full $2...$ string
        key: 32-byte AES key (default: hardcoded Huawei key)

    Returns:
        Decrypted plaintext string, or None on failure
    """
    # Trim $2 prefix and $ suffix
    if len(encrypted_str) < 4:
        return None
    if not encrypted_str.startswith('$2') or not encrypted_str.endswith('$'):
        return None
    inner = encrypted_str[2:-1]
    if not inner:
        return None

    # Decode ASCII visibility
    unvisible = _asc_unvisible(inner)

    # Check block alignment
    block_count = len(unvisible) // BLOCK_SIZE
    if len(unvisible) != BLOCK_SIZE * block_count or block_count < 2:
        return None

    # Extract IV (last block) and ciphertext (all blocks before)
    iv_encoded = unvisible[(block_count - 1) * BLOCK_SIZE:]
    data_encoded = unvisible[:(block_count - 1) * BLOCK_SIZE]

    iv_bin = _plain_to_bin(iv_encoded)
    data_bin = _plain_to_bin(data_encoded)

    if iv_bin is None or data_bin is None:
        return None

    # AES-CBC decrypt
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv_bin)
        plaintext = cipher.decrypt(data_bin)
        # Strip zero padding
        plaintext = plaintext.rstrip(b'\x00')
        return plaintext.decode('utf-8', errors='replace')
    except Exception:
        return None


def encrypt_field(plaintext, key=HW_CONFIG_KEY):
    """Encrypt a string to Huawei $2...$ format.

    Args:
        plaintext: String to encrypt
        key: 32-byte AES key (default: hardcoded Huawei key)

    Returns:
        Encrypted $2...$ string
    """
    data = plaintext.encode('utf-8')
    # Pad to 16-byte boundary with zeros
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)

    # Random IV
    iv = os.urandom(16)

    # AES-CBC encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(data)

    # Combine ciphertext + IV
    combined = ciphertext + iv

    # Convert to base-93 encoding
    plain_encoded = _bin_to_plain(combined)
    if plain_encoded is None:
        return None

    # Apply ASCII visibility
    visible = _asc_visible(plain_encoded)

    return f"$2{visible}$"


def scan_xml_file(filepath, key=HW_CONFIG_KEY):
    """Scan an XML file for $2...$ encrypted fields and decrypt them.

    Args:
        filepath: Path to decrypted hw_ctree.xml
        key: 32-byte AES key

    Returns:
        List of (field_path, encrypted_value, decrypted_value) tuples
    """
    with open(filepath, 'r', errors='replace') as f:
        content = f.read()

    # Find all $2...$ patterns
    pattern = re.compile(r'\$2[!-~]{20,}\$')
    results = []

    for match in pattern.finditer(content):
        encrypted = match.group()
        decrypted = decrypt_field(encrypted, key)
        # Find context (preceding XML tag/attribute)
        start = max(0, match.start() - 100)
        context = content[start:match.start()]
        # Extract the closest attribute name
        attr_match = re.search(r'(\w+)=["\']?$', context)
        attr_name = attr_match.group(1) if attr_match else '(unknown)'
        results.append((attr_name, encrypted, decrypted))

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Huawei ONT Config Field Decryptor ($2...$ format)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--decrypt', '-d', metavar='STRING',
                       help='Decrypt a $2...$ encrypted string')
    group.add_argument('--encrypt', '-e', metavar='STRING',
                       help='Encrypt a plaintext string to $2...$ format')
    group.add_argument('--file', '-f', metavar='FILE',
                       help='Scan XML file for encrypted fields and decrypt all')

    args = parser.parse_args()

    if args.decrypt:
        result = decrypt_field(args.decrypt)
        if result is not None:
            print(f"Decrypted: {result}")
        else:
            print("Failed to decrypt (invalid format or wrong key)")
            sys.exit(1)

    elif args.encrypt:
        result = encrypt_field(args.encrypt)
        if result is not None:
            print(f"Encrypted: {result}")
        else:
            print("Failed to encrypt")
            sys.exit(1)

    elif args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            sys.exit(1)

        results = scan_xml_file(args.file)
        if not results:
            print("No $2...$ encrypted fields found in file")
            sys.exit(0)

        print(f"Found {len(results)} encrypted field(s):\n")
        for attr, enc, dec in results:
            print(f"  Attribute: {attr}")
            print(f"  Encrypted: {enc[:60]}...")
            print(f"  Decrypted: {dec}")
            print()


if __name__ == '__main__':
    main()
