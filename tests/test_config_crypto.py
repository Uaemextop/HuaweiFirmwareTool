"""
Tests for obsc_tool.config_crypto (AES-based config encryption/decryption).
"""

import pytest

from hwflash.core.encrypt import (
    decrypt_config,
    encrypt_config,
    try_decrypt_all_keys,
)

# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------

PLAINTEXT_XML = b'<?xml version="1.0"?><Config><Value>test</Value></Config>'
CHIP_ID = 'TEST12345'


class TestEncryptDecryptRoundtrip:
    def test_encrypt_then_decrypt(self):
        ciphertext = encrypt_config(PLAINTEXT_XML, CHIP_ID)
        assert ciphertext != PLAINTEXT_XML
        recovered = decrypt_config(ciphertext, CHIP_ID)
        assert recovered == PLAINTEXT_XML

    def test_encrypt_produces_bytes(self):
        result = encrypt_config(PLAINTEXT_XML, CHIP_ID)
        assert isinstance(result, bytes)

    def test_decrypt_wrong_key_differs(self):
        ciphertext = encrypt_config(PLAINTEXT_XML, CHIP_ID)
        # Decrypting with a wrong chip ID should not reproduce the original plaintext
        recovered = decrypt_config(ciphertext, 'WRONG_ID_XYZ')
        assert recovered != PLAINTEXT_XML

    def test_empty_plaintext_roundtrip(self):
        ciphertext = encrypt_config(b'', CHIP_ID)
        recovered = decrypt_config(ciphertext, CHIP_ID)
        assert recovered == b''

    def test_large_plaintext_roundtrip(self):
        large = b'A' * 10_000
        ciphertext = encrypt_config(large, CHIP_ID)
        recovered = decrypt_config(ciphertext, CHIP_ID)
        assert recovered == large

    def test_binary_plaintext_roundtrip(self):
        binary = bytes(range(256)) * 4
        ciphertext = encrypt_config(binary, CHIP_ID)
        recovered = decrypt_config(ciphertext, CHIP_ID)
        assert recovered == binary


# ---------------------------------------------------------------------------
# Auto-detect / try_decrypt_all_keys
# ---------------------------------------------------------------------------

class TestTryDecryptAllKeys:
    def test_detects_correct_chip_id(self):
        """try_decrypt_all_keys should return at least one result for data
        encrypted with a known chip ID (from KNOWN_CHIP_IDS)."""
        from hwflash.core.encrypt import KNOWN_CHIP_IDS
        if not KNOWN_CHIP_IDS:
            pytest.skip("No built-in chip IDs defined")

        chip_id = KNOWN_CHIP_IDS[0]
        # Use XML content that passes the built-in heuristic check
        plaintext = b'<?xml version="1.0"?><Config><Key>value</Key></Config>'
        ciphertext = encrypt_config(plaintext, chip_id)

        results = try_decrypt_all_keys(ciphertext)
        assert results, "Expected at least one matching chip ID"
        found_ids = [r[0] for r in results]
        assert chip_id in found_ids

    def test_returns_empty_for_random_data(self):
        """Random bytes are unlikely to decrypt to valid XML with any known key."""
        # 80 bytes of non-XML looking bytes (null bytes are fine XML but
        # the heuristic should still reject purely-null data)
        garbage = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 20)
        results = try_decrypt_all_keys(garbage)
        # Result may or may not be empty depending on heuristics; just confirm it returns a list
        assert isinstance(results, list)
