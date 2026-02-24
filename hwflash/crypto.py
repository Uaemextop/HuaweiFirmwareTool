"""
hwflash.crypto – Huawei ONT configuration file encryption/decryption.

This is the canonical module for config-file crypto operations.
Re-exports from ``hwflash.core.encrypt`` for convenience.
"""

# Re-export everything from the original implementation so that existing
# imports of ``obsc_tool.config_crypto`` continue to work.
from hwflash.core.encrypt import (  # noqa: F401
    KNOWN_CHIP_IDS,
    KEY_TEMPLATE,
    CfgFileParser,
    derive_key,
    decrypt_config,
    encrypt_config,
    try_decrypt_all_keys,
)

__all__ = [
    "KNOWN_CHIP_IDS",
    "KEY_TEMPLATE",
    "CfgFileParser",
    "derive_key",
    "decrypt_config",
    "encrypt_config",
    "try_decrypt_all_keys",
]
