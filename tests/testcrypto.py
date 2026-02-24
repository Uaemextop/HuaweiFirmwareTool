"""Tests for config_crypto module."""

import pytest
from hwflash.core.crypto import (
    derive_key,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    encrypt_config,
    decrypt_config,
    try_decrypt_all_keys,
    CfgFileParser,
    KNOWN_CHIP_IDS,
    KEY_TEMPLATE,
    _pkcs7_pad,
    _pkcs7_unpad,
)


class TestDeriveKey:
    """Test AES key derivation."""

    def test_key_length_always_16(self):
        for chip_id in KNOWN_CHIP_IDS:
            key = derive_key(chip_id)
            assert len(key) == 16, f"Key for {chip_id} is {len(key)} bytes"

    def test_known_key_value(self):
        # "Df7!ui%s9(lmV1L8" % "SD5116H" -> "Df7!uiSD5116H9(l" (first 16 bytes)
        key = derive_key("SD5116H")
        expected = b"Df7!uiSD5116H9(l"
        assert key == expected

    def test_short_chip_id_padded(self):
        key = derive_key("X")
        assert len(key) == 16

    def test_different_chip_ids_different_keys(self):
        keys = set()
        for chip_id in KNOWN_CHIP_IDS:
            keys.add(derive_key(chip_id))
        assert len(keys) == len(KNOWN_CHIP_IDS)


class TestPKCS7:
    """Test PKCS#7 padding."""

    def test_pad_exact_block(self):
        data = b'\x00' * 16
        padded = _pkcs7_pad(data)
        assert len(padded) == 32
        assert padded[16:] == b'\x10' * 16

    def test_pad_one_byte_short(self):
        data = b'\x00' * 15
        padded = _pkcs7_pad(data)
        assert len(padded) == 16
        assert padded[-1] == 1

    def test_unpad_valid(self):
        padded = b'\x00' * 13 + b'\x03\x03\x03'
        result = _pkcs7_unpad(padded)
        assert result == b'\x00' * 13

    def test_unpad_invalid_raises(self):
        with pytest.raises(ValueError):
            _pkcs7_unpad(b'\x00' * 15 + b'\x05')

    def test_unpad_empty_raises(self):
        with pytest.raises(ValueError):
            _pkcs7_unpad(b'')

    def test_roundtrip(self):
        for size in [0, 1, 15, 16, 17, 31, 32, 100]:
            data = bytes(range(256))[:size]
            assert _pkcs7_unpad(_pkcs7_pad(data)) == data


class TestAESCBC:
    """Test AES-128-CBC encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = b'0123456789abcdef'
        plaintext = b'Hello, Huawei ONT!'
        ciphertext = aes_cbc_encrypt(plaintext, key)
        decrypted = aes_cbc_decrypt(ciphertext, key)
        assert decrypted == plaintext

    def test_encrypt_produces_different_output(self):
        key = b'0123456789abcdef'
        plaintext = b'Hello, World!'
        ciphertext = aes_cbc_encrypt(plaintext, key)
        assert ciphertext != plaintext

    def test_custom_iv(self):
        key = b'0123456789abcdef'
        iv = b'\x01' * 16
        plaintext = b'test data here!!'
        ciphertext = aes_cbc_encrypt(plaintext, key, iv)
        decrypted = aes_cbc_decrypt(ciphertext, key, iv)
        assert decrypted == plaintext

    def test_different_iv_different_ciphertext(self):
        key = b'0123456789abcdef'
        plaintext = b'same input data!'
        ct1 = aes_cbc_encrypt(plaintext, key, b'\x00' * 16)
        ct2 = aes_cbc_encrypt(plaintext, key, b'\x01' * 16)
        assert ct1 != ct2

    def test_ciphertext_is_block_aligned(self):
        key = b'0123456789abcdef'
        for size in [1, 15, 16, 17, 31, 32, 100]:
            plaintext = b'A' * size
            ciphertext = aes_cbc_encrypt(plaintext, key)
            assert len(ciphertext) % 16 == 0

    def test_large_data_roundtrip(self):
        key = b'0123456789abcdef'
        plaintext = bytes(range(256)) * 100  # 25.6 KB
        ciphertext = aes_cbc_encrypt(plaintext, key)
        decrypted = aes_cbc_decrypt(ciphertext, key)
        assert decrypted == plaintext


class TestConfigEncryption:
    """Test Huawei config encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        config = b'<?xml version="1.0"?><config><param>value</param></config>'
        for chip_id in KNOWN_CHIP_IDS:
            encrypted = encrypt_config(config, chip_id)
            decrypted = decrypt_config(encrypted, chip_id)
            assert decrypted == config, f"Roundtrip failed for {chip_id}"

    def test_wrong_key_gives_wrong_data(self):
        config = b'<?xml version="1.0"?><config/>'
        encrypted = encrypt_config(config, "SD5116H")
        decrypted = decrypt_config(encrypted, "SD5115H")
        assert decrypted != config

    def test_try_decrypt_all_keys(self):
        config = b'<?xml version="1.0"?><config>data</config>'
        encrypted = encrypt_config(config, "SD5116H")
        results = try_decrypt_all_keys(encrypted)
        assert len(results) >= 1
        assert results[0][0] == "SD5116H"
        assert results[0][1] == config


class TestCfgFileParser:
    """Test configuration file parser."""

    def test_get_value_element(self):
        parser = CfgFileParser()
        parser.text_content = '<root><Username>admin</Username></root>'
        assert parser.get_value("Username") == "admin"

    def test_get_value_attribute(self):
        parser = CfgFileParser()
        parser.text_content = '<root Enable="1" Name="WAN1"/>'
        assert parser.get_value("Enable") == "1"
        assert parser.get_value("Name") == "WAN1"

    def test_get_value_not_found(self):
        parser = CfgFileParser()
        parser.text_content = '<root><A>1</A></root>'
        assert parser.get_value("Missing") is None

    def test_set_value_element(self):
        parser = CfgFileParser()
        parser.text_content = '<root><Password>old</Password></root>'
        assert parser.set_value("Password", "new") is True
        assert "new" in parser.text_content
        assert "old" not in parser.text_content

    def test_set_value_attribute(self):
        parser = CfgFileParser()
        parser.text_content = '<root Enable="0"/>'
        assert parser.set_value("Enable", "1") is True
        assert 'Enable="1"' in parser.text_content

    def test_list_values(self):
        parser = CfgFileParser()
        parser.text_content = '<root><A>1</A><B>2</B> C="3"</root>'
        values = parser.list_values()
        tags = [v[0] for v in values]
        assert "A" in tags
        assert "B" in tags
        assert "C" in tags

    def test_list_values_filter(self):
        parser = CfgFileParser()
        parser.text_content = '<root><WANEnable>1</WANEnable><LANEnable>0</LANEnable></root>'
        results = parser.list_values("WAN")
        assert len(results) == 1
        assert results[0][0] == "WANEnable"
