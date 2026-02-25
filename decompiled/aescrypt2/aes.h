/*
 * aes.h — AES encryption / decryption interface.
 *
 * Reconstructed from the EG8145V5 firmware binaries:
 *   - /bin/aescrypt2            (calls OS_AescryptEncrypt / Decrypt)
 *   - /lib/libhw_ssp_basic.so  (implements OS_Aescrypt*, wraps mbedTLS)
 *   - /lib/libpolarssl.so      (mbedTLS — provides mbedtls_aescrypt2)
 *
 * The mbedTLS "aescrypt2" file format:
 *   Bytes 0-3:   magic "AEST"
 *   Bytes 4-7:   original file size (big-endian u32)
 *   Bytes 8-23:  16-byte random IV
 *   Bytes 24+:   AES-256-CBC ciphertext (PKCS#7 padded)
 *   Last 32:     HMAC-SHA-256 of (IV ‖ ciphertext)
 *
 * Key derivation: PBKDF2-HMAC-SHA-256, 8192 iterations, 32-byte key + 32-byte IV
 * (the IV from PBKDF2 is XOR'd with the random IV before use).
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── AES block constants ─────────────────────────────────────────────────── */

#define AES_BLOCK_SIZE   16
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_256 32

/* ── mbedTLS-compatible aescrypt2 file format ────────────────────────────── */

#define AESCRYPT2_MAGIC      "AEST"
#define AESCRYPT2_MAGIC_LEN  4
#define AESCRYPT2_IV_LEN     16
#define AESCRYPT2_HMAC_LEN   32
#define AESCRYPT2_PBKDF2_ITER 8192

/* ── AES context (simplified, CBC mode) ──────────────────────────────────── */

typedef struct {
    uint32_t rk[60];       /* Round keys (max AES-256: 14 rounds × 4 + 4) */
    int      nr;           /* Number of rounds (10/12/14) */
} aes_context;

/* ── Core AES API ────────────────────────────────────────────────────────── */

/**
 * Initialise AES context.
 */
void aes_init(aes_context *ctx);

/**
 * Set encryption key.
 * @param key     Key bytes (16, 24, or 32).
 * @param keybits Key length in **bits** (128, 192, 256).
 * @return 0 on success.
 */
int aes_setkey_enc(aes_context *ctx, const uint8_t *key, unsigned int keybits);

/**
 * Set decryption key.
 */
int aes_setkey_dec(aes_context *ctx, const uint8_t *key, unsigned int keybits);

/**
 * AES-ECB single block encrypt/decrypt.
 * @param mode 0 = encrypt, 1 = decrypt.
 */
int aes_crypt_ecb(aes_context *ctx, int mode,
                  const uint8_t input[16], uint8_t output[16]);

/**
 * AES-CBC encrypt/decrypt.
 * @param mode   0 = encrypt, 1 = decrypt.
 * @param length Must be a multiple of 16.
 * @param iv     16-byte IV (updated in-place).
 */
int aes_crypt_cbc(aes_context *ctx, int mode, size_t length,
                  uint8_t iv[16],
                  const uint8_t *input, uint8_t *output);

/**
 * Free AES context.
 */
void aes_free(aes_context *ctx);

/* ── High-level aescrypt2 file operations ────────────────────────────────── */

/**
 * Encrypt a file using the mbedTLS aescrypt2 format (AES-256-CBC).
 *
 * @param in_path   Input (plaintext) file.
 * @param out_path  Output (ciphertext) file.
 * @param key       Optional password / key material (NULL = device key).
 * @param key_mode  0 = password string, 1 = key-file path.
 * @return 0 on success, negative on error.
 */
int aescrypt2_encrypt(const char *in_path, const char *out_path,
                      const char *key, int key_mode);

/**
 * Decrypt a file using the mbedTLS aescrypt2 format.
 */
int aescrypt2_decrypt(const char *in_path, const char *out_path,
                      const char *key, int key_mode);

#ifdef __cplusplus
}
#endif

#endif /* AES_H */
