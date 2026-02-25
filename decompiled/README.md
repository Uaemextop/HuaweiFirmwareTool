# Decompiled Firmware Binaries

Reconstructed C source code from the **Huawei EG8145V5** firmware
(`EG8145V5-V500R022C00SPC340B019.bin`).

## aescrypt2

The `/bin/aescrypt2` binary is a command-line tool for encrypting and
decrypting files using the **mbedTLS aescrypt2** format (AES-256-CBC with
PBKDF2-HMAC-SHA-256 key derivation).

### Original binary details

| Property | Value |
|---|---|
| Path in firmware | `/bin/aescrypt2` |
| Architecture | ARM 32-bit, EABI5, PIE, stripped |
| Libc | musl (`/lib/ld-musl-arm.so.1`) |
| Source file (from .rodata) | `hw_ssp_ctool.c` |
| Version (from .rodata) | `version[v1.0]` |
| Dependencies | `libhw_ssp_basic.so`, `libpolarssl.so` (mbedTLS) |

### Key functions (from dynamic symbols)

- `OS_AescryptEncrypt` — encrypts a file (AES-256-CBC, AEST format)
- `OS_AescryptDecrypt` — decrypts an AEST-format file
- `HW_OS_StrToUInt32` — parses CLI mode argument
- `HW_OS_Printf` — formatted output
- `HW_PROC_DBG_LastWord` — error/debug logging

### AEST file format

```
Offset  Size  Description
──────  ────  ──────────────────────────────────
0x00    4     Magic: "AEST"
0x04    4     Original file size (big-endian u32)
0x08    16    Random IV (also used as PBKDF2 salt)
0x18    N     AES-256-CBC ciphertext (PKCS#7 padded)
N+0x18  32    HMAC-SHA-256 of (IV ‖ ciphertext)
```

### Build

```bash
cd decompiled/aescrypt2
cmake -B build
cmake --build build
```

Requires `libmbedtls-dev` (Debian/Ubuntu: `sudo apt install libmbedtls-dev`).

### Usage

```bash
# Encrypt
./build/aescrypt2 0 plaintext.bin encrypted.aes

# Decrypt
./build/aescrypt2 1 encrypted.aes decrypted.bin

# With password
./build/aescrypt2 0 plaintext.bin encrypted.aes mypassword

# With key file
./build/aescrypt2 0 plaintext.bin encrypted.aes keyfile.bin 1
```

## Firmware extraction

The tar.gz archives referenced in the firmware (`/mnt/jffs2/`) are
**runtime files** stored on the device's flash (JFFS2 partition) and are
**not embedded** in the firmware image:

| File | Description |
|---|---|
| `/mnt/jffs2/ttree_spec_smooth.tar.gz` | TTree specification data |
| `/mnt/jffs2/app/preload_cplugin.tar.gz` | Preloaded C plugin packages |
| `/mnt/jffs2/app/plugin_preload.tar.gz` | Plugin preload archive |

These are created at runtime by `libhw_plugin_mng.so` and
`libhw_swm_dll.so`.

## Tools

- **`tools/fw_extract.py`** — Downloads firmware, extracts SquashFS rootfs,
  copies out binaries of interest.
- **`tools/arm_disasm.py`** — Capstone-based ARM disassembler producing
  annotated assembly and pseudo-C output.

## Disassembly method

The decompilation was performed using:

1. **Capstone** (Python) for ARM instruction disassembly
2. **ELF parsing** for section/symbol resolution
3. **PLT → GOT** resolution for imported function identification
4. **String cross-referencing** from `.rodata` and `.dynstr`
5. **Manual reconstruction** based on known mbedTLS API patterns

The original firmware uses mbedTLS (loaded at runtime from
`/lib/libpolarssl.so`) for all cryptographic operations.
