"""
Config file encryption/decryption for Huawei ONT devices.

Implements the AES-128-CBC encryption used by Huawei devices to protect
configuration files (hw_ctree.xml). The encryption key is derived from
the device's chip ID using the template "Df7!ui%s9(lmV1L8".

Uses pycryptodome for AES operations. Falls back to a pure-Python
implementation if pycryptodome is not available.

Also provides cfgtool-compatible configuration file parsing and editing.
"""

import os
import re
import logging

logger = logging.getLogger("hwflash.config_crypto")

# Try to use pycryptodome (battle-tested) for AES operations
try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pkcs7_pad_crypto, unpad as _pkcs7_unpad_crypto
    _HAS_PYCRYPTODOME = True
except ImportError:
    _HAS_PYCRYPTODOME = False
    logger.warning("pycryptodome not available; using pure-Python AES fallback")

# Known Huawei chip IDs used in ONT devices
KNOWN_CHIP_IDS = [
    "SD5116H",   # HG8145V5, HG8245H, HG8546M (Hi5116H chipset)
    "SD5115H",   # Older HG8245A/H models
    "SD5118",    # Some HG8247H models
    "SD5116T",   # Some EG8145V5 models
    "5116H",     # Alternate naming
    "5115H",     # Alternate naming
]

# Key template: "Df7!ui%s9(lmV1L8" where %s is the chip ID
KEY_TEMPLATE = "Df7!ui%s9(lmV1L8"

# Huawei uses a zero IV for config file encryption
_DEFAULT_IV = b'\x00' * 16


def derive_key(chip_id):
    """Derive the AES-128 encryption key from a chip ID.

    The key is formed by substituting the chip ID into the template
    string "Df7!ui%s9(lmV1L8" and taking the first 16 bytes.

    Args:
        chip_id: Device chip ID string (e.g., "SD5116H").

    Returns:
        16-byte AES key.
    """
    key_str = KEY_TEMPLATE % chip_id
    # The key is the raw bytes of the string, truncated/padded to 16 bytes
    key_bytes = key_str.encode('ascii')
    if len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
    elif len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\x00')
    return key_bytes



def _pkcs7_pad(data, block_size=16):
    """Apply PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data):
    """Remove PKCS#7 padding with validation.

    Raises:
        ValueError: If padding is invalid.
    """
    if not data:
        raise ValueError("Empty data cannot be unpadded")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid padding length: {pad_len}")
    if not all(b == pad_len for b in data[-pad_len:]):
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def aes_cbc_encrypt(plaintext, key, iv=None):
    """Encrypt data using AES-128-CBC.

    Args:
        plaintext: Data to encrypt (will be PKCS7-padded).
        key: 16-byte AES key.
        iv: 16-byte initialization vector (defaults to all zeros).

    Returns:
        Encrypted bytes (IV is NOT prepended).
    """
    if iv is None:
        iv = _DEFAULT_IV

    if _HAS_PYCRYPTODOME:
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        padded = _pkcs7_pad_crypto(plaintext, _AES.block_size)
        return cipher.encrypt(padded)

    # Pure-Python fallback
    return _aes_cbc_encrypt_fallback(plaintext, key, iv)


def aes_cbc_decrypt(ciphertext, key, iv=None):
    """Decrypt data using AES-128-CBC.

    Args:
        ciphertext: Encrypted data (multiple of 16 bytes).
        key: 16-byte AES key.
        iv: 16-byte initialization vector (defaults to all zeros).

    Returns:
        Decrypted bytes with PKCS7 padding removed.
    """
    if iv is None:
        iv = _DEFAULT_IV

    if _HAS_PYCRYPTODOME:
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        try:
            return _pkcs7_unpad_crypto(decrypted, _AES.block_size)
        except ValueError:
            # Return raw decrypted data if padding is invalid
            return decrypted

    # Pure-Python fallback
    return _aes_cbc_decrypt_fallback(ciphertext, key, iv)


# Used only when pycryptodome is not installed.

# Pre-computed AES S-box (standard)
_AES_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

_AES_SBOX_INV = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_SBOX_INV[_v] = _i

_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _key_expansion(key):
    w = []
    for i in range(4):
        w.append(list(key[4 * i:4 * i + 4]))
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= _AES_RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], temp)])
    round_keys = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys


def _aes_encrypt_block(block, round_keys):
    state = list(block)
    state = [s ^ k for s, k in zip(state, round_keys[0])]
    for r in range(1, 10):
        state = [_AES_SBOX[b] for b in state]
        s = list(state)
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        state = s
        ns = list(state)
        for i in range(4):
            c = i * 4
            a = ns[c:c + 4]
            ns[c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            ns[c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            ns[c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            ns[c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        state = [s ^ k for s, k in zip(ns, round_keys[r])]
    state = [_AES_SBOX[b] for b in state]
    s = list(state)
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    state = [ss ^ k for ss, k in zip(s, round_keys[10])]
    return bytes(state)


def _aes_decrypt_block(block, round_keys):
    state = list(block)
    state = [s ^ k for s, k in zip(state, round_keys[10])]
    for r in range(9, 0, -1):
        s = list(state)
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
        state = [_AES_SBOX_INV[b] for b in s]
        state = [ss ^ k for ss, k in zip(state, round_keys[r])]
        ns = list(state)
        for i in range(4):
            c = i * 4
            a = ns[c:c + 4]
            ns[c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
            ns[c + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
            ns[c + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
            ns[c + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
        state = ns
    s = list(state)
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
    state = [_AES_SBOX_INV[b] for b in s]
    state = [ss ^ k for ss, k in zip(state, round_keys[0])]
    return bytes(state)


def _aes_cbc_encrypt_fallback(plaintext, key, iv):
    """Pure-Python AES-128-CBC encrypt (fallback)."""
    round_keys = _key_expansion(key)
    padded = _pkcs7_pad(plaintext)
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        xored = _xor_bytes(block, prev)
        encrypted = _aes_encrypt_block(xored, round_keys)
        ciphertext.extend(encrypted)
        prev = encrypted
    return bytes(ciphertext)


def _aes_cbc_decrypt_fallback(ciphertext, key, iv):
    """Pure-Python AES-128-CBC decrypt (fallback)."""
    round_keys = _key_expansion(key)
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted = _aes_decrypt_block(block, round_keys)
        plaintext.extend(_xor_bytes(decrypted, prev))
        prev = block
    try:
        return _pkcs7_unpad(bytes(plaintext))
    except ValueError:
        return bytes(plaintext)


def encrypt_config(data, chip_id="SD5116H"):
    """Encrypt a Huawei config file (hw_ctree.xml).

    Args:
        data: Config file content as bytes.
        chip_id: Device chip ID for key derivation.

    Returns:
        Encrypted bytes.
    """
    key = derive_key(chip_id)
    return aes_cbc_encrypt(data, key)


def decrypt_config(data, chip_id="SD5116H"):
    """Decrypt a Huawei config file.

    Args:
        data: Encrypted config file content.
        chip_id: Device chip ID for key derivation.

    Returns:
        Decrypted bytes.
    """
    key = derive_key(chip_id)
    return aes_cbc_decrypt(data, key)


def try_decrypt_all_keys(data):
    """Try decrypting with all known chip IDs.

    Useful when the exact chip ID is unknown.

    Args:
        data: Encrypted config file content.

    Returns:
        List of (chip_id, decrypted_data) for successful attempts.
        Success is determined by checking if the result looks like XML.
    """
    results = []
    for chip_id in KNOWN_CHIP_IDS:
        try:
            decrypted = decrypt_config(data, chip_id)
            # Check if result looks like XML
            if decrypted and len(decrypted) > 5 and (
                    b'<?xml' in decrypted[:100] or
                    b'<InternetGatewayDevice' in decrypted[:200] or
                    b'<Msg' in decrypted[:50]):
                results.append((chip_id, decrypted))
        except Exception:
            pass
    return results


class CfgFileParser:
    """Simple parser for Huawei config files (hw_ctree.xml).

    Provides read/modify operations on the XML configuration tree
    commonly used for ONT device settings.
    """

    def __init__(self):
        self.raw_content = b""
        self.text_content = ""
        self.is_encrypted = False
        self.chip_id = "SD5116H"

    def load(self, file_path, chip_id=None):
        """Load a config file, auto-detecting encryption.

        Args:
            file_path: Path to the config file.
            chip_id: Optional chip ID for decryption.
        """
        with open(file_path, 'rb') as f:
            self.raw_content = f.read()

        # Detect if encrypted (XML files start with '<' or BOM)
        if (self.raw_content[:1] == b'<' or
                self.raw_content[:3] == b'\xef\xbb\xbf' or
                b'<?xml' in self.raw_content[:100]):
            self.is_encrypted = False
            self.text_content = self.raw_content.decode('utf-8', errors='replace')
        else:
            self.is_encrypted = True
            if chip_id:
                self.chip_id = chip_id
                decrypted = decrypt_config(self.raw_content, chip_id)
                self.text_content = decrypted.decode('utf-8', errors='replace')
            else:
                # Try all known keys
                results = try_decrypt_all_keys(self.raw_content)
                if results:
                    self.chip_id = results[0][0]
                    self.text_content = results[0][1].decode('utf-8', errors='replace')
                else:
                    raise ValueError("Could not decrypt config file with known chip IDs")

    def save(self, file_path, encrypt=None, chip_id=None):
        """Save config file, optionally encrypting.

        Args:
            file_path: Output path.
            encrypt: True to encrypt, False for plaintext, None for auto.
            chip_id: Chip ID for encryption (uses loaded one if None).
        """
        data = self.text_content.encode('utf-8')
        cid = chip_id or self.chip_id

        should_encrypt = encrypt if encrypt is not None else self.is_encrypted
        if should_encrypt:
            data = encrypt_config(data, cid)

        with open(file_path, 'wb') as f:
            f.write(data)

    def get_value(self, xpath_like):
        """Get a value from the config using a simple path expression.

        Args:
            xpath_like: Dot-separated path (e.g., "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1").

        Returns:
            Value string or None.
        """
        # Simple tag search - not a full XML parser
        parts = xpath_like.split('.')
        search = parts[-1]
        content = self.text_content

        # Look for <TagName>value</TagName> or TagName="value"
        # Attribute pattern
        attr_match = re.search(rf'{re.escape(search)}="([^"]*)"', content)
        if attr_match:
            return attr_match.group(1)
        # Element pattern
        elem_match = re.search(rf'<{re.escape(search)}>([^<]*)</{re.escape(search)}>', content)
        if elem_match:
            return elem_match.group(1)
        return None

    def set_value(self, xpath_like, value):
        """Set a value in the config.

        Args:
            xpath_like: Dot-separated path.
            value: New value string.

        Returns:
            True if replaced, False if not found.
        """
        parts = xpath_like.split('.')
        search = parts[-1]

        # Try attribute pattern
        new_content, count = re.subn(
            rf'({re.escape(search)}=")([^"]*)"',
            rf'\g<1>{value}"',
            self.text_content, count=1
        )
        if count > 0:
            self.text_content = new_content
            return True

        # Try element pattern
        new_content, count = re.subn(
            rf'(<{re.escape(search)}>)[^<]*(</{re.escape(search)}>)',
            rf'\g<1>{value}\2',
            self.text_content, count=1
        )
        if count > 0:
            self.text_content = new_content
            return True

        return False

    def list_values(self, pattern=""):
        """List all tag=value pairs matching a pattern.

        Args:
            pattern: Substring to filter by (empty = all).

        Returns:
            List of (tag, value) tuples.
        """
        results = []

        # Element values
        for match in re.finditer(r'<(\w+)>([^<]+)</\1>', self.text_content):
            tag, val = match.group(1), match.group(2)
            if not pattern or pattern.lower() in tag.lower():
                results.append((tag, val.strip()))

        # Attribute values
        for match in re.finditer(r'(\w+)="([^"]*)"', self.text_content):
            tag, val = match.group(1), match.group(2)
            if not pattern or pattern.lower() in tag.lower():
                results.append((tag, val))

        return results
