"""
obsc_tool.crypto – Huawei ONT configuration file encryption/decryption.

This is the canonical module for config-file crypto operations.
The old name ``obsc_tool.config_crypto`` is kept as a backward-compatible
re-export wrapper (see ``config_crypto.py``).
"""

# Re-export everything from the original implementation so that existing
# imports of ``obsc_tool.config_crypto`` continue to work.
from obsc_tool.config_crypto import (  # noqa: F401
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
