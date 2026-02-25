/*
 * aes.c — AES-CBC encrypt / decrypt + aescrypt2 file-format handlers.
 *
 * Reconstructed from:
 *   - /bin/aescrypt2  (ARM ELF, stripped, PIE, musl libc)
 *   - /lib/libhw_ssp_basic.so  (OS_AescryptEncrypt / OS_AescryptDecrypt,
 *     HW_SSL_AesCryptCbc, HW_SSL_AesSetKeyEnc, etc.)
 *   - /lib/libpolarssl.so  (mbedTLS 2.x, provides mbedtls_aescrypt2)
 *
 * The on-device aescrypt2 binary is a thin CLI wrapper.  The real work
 * happens in libhw_ssp_basic.so which dynamically loads libpolarssl.so
 * and calls the mbedTLS AES / SHA-256 / PBKDF2 functions.
 *
 * This reconstruction reimplements the logic using the system mbedTLS
 * library (libmbedtls / libmbedcrypto) so that it compiles and runs on
 * any Linux host.
 *
 * Key observations from firmware strings and disassembly:
 *   • File magic: "AEST" (4 bytes)
 *   • PBKDF2-HMAC-SHA-256, 8192 iterations, 32-byte derived key
 *   • AES-256-CBC with PKCS#7 padding
 *   • HMAC-SHA-256 integrity check (appended to ciphertext)
 *   • Source file reference: "aescrypt.c", "hw_ssp_aes.c"
 *
 * SPDX-License-Identifier: MIT
 */

#include "aes.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform.h>

/* ── Utility: read whole file ────────────────────────────────────────────── */

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    fseek(f, 0, SEEK_SET);
    *out = (uint8_t *)malloc((size_t)sz);
    if (!*out) { fclose(f); return -1; }
    *out_len = fread(*out, 1, (size_t)sz, f);
    fclose(f);
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    return (w == len) ? 0 : -1;
}

/* ── Random IV generation (simple /dev/urandom fallback) ─────────────────── */

static int gen_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return -1;
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    return (r == len) ? 0 : -1;
}

/* ── PKCS#7 padding ──────────────────────────────────────────────────────── */

static size_t pkcs7_pad(uint8_t *buf, size_t data_len, size_t block_size) {
    uint8_t pad_val = (uint8_t)(block_size - (data_len % block_size));
    for (size_t i = 0; i < pad_val; i++)
        buf[data_len + i] = pad_val;
    return data_len + pad_val;
}

static int pkcs7_unpad(const uint8_t *buf, size_t len, size_t *out_len) {
    if (len == 0 || len % AES_BLOCK_SIZE != 0)
        return -1;
    uint8_t pad_val = buf[len - 1];
    if (pad_val == 0 || pad_val > AES_BLOCK_SIZE)
        return -1;
    for (size_t i = 0; i < pad_val; i++) {
        if (buf[len - 1 - i] != pad_val)
            return -1;
    }
    *out_len = len - pad_val;
    return 0;
}

/* ── Core AES wrappers (thin layer over mbedTLS) ─────────────────────────── */

void aes_init(aes_context *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

int aes_setkey_enc(aes_context *ctx, const uint8_t *key, unsigned int keybits) {
    mbedtls_aes_context m;
    mbedtls_aes_init(&m);
    int ret = mbedtls_aes_setkey_enc(&m, key, keybits);
    memcpy(ctx->rk, &m, sizeof(m) < sizeof(ctx->rk) ? sizeof(m) : sizeof(ctx->rk));
    ctx->nr = (int)(keybits / 32 + 6);
    mbedtls_aes_free(&m);
    return ret;
}

int aes_setkey_dec(aes_context *ctx, const uint8_t *key, unsigned int keybits) {
    mbedtls_aes_context m;
    mbedtls_aes_init(&m);
    int ret = mbedtls_aes_setkey_dec(&m, key, keybits);
    memcpy(ctx->rk, &m, sizeof(m) < sizeof(ctx->rk) ? sizeof(m) : sizeof(ctx->rk));
    ctx->nr = (int)(keybits / 32 + 6);
    mbedtls_aes_free(&m);
    return ret;
}

int aes_crypt_ecb(aes_context *ctx, int mode,
                  const uint8_t input[16], uint8_t output[16]) {
    mbedtls_aes_context m;
    mbedtls_aes_init(&m);
    memcpy(&m, ctx->rk, sizeof(m) < sizeof(ctx->rk) ? sizeof(m) : sizeof(ctx->rk));
    int ret = mbedtls_aes_crypt_ecb(&m, mode, input, output);
    mbedtls_aes_free(&m);
    return ret;
}

int aes_crypt_cbc(aes_context *ctx, int mode, size_t length,
                  uint8_t iv[16],
                  const uint8_t *input, uint8_t *output) {
    mbedtls_aes_context m;
    mbedtls_aes_init(&m);
    memcpy(&m, ctx->rk, sizeof(m) < sizeof(ctx->rk) ? sizeof(m) : sizeof(ctx->rk));
    int ret = mbedtls_aes_crypt_cbc(&m, mode, length, iv, input, output);
    mbedtls_aes_free(&m);
    return ret;
}

void aes_free(aes_context *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

/* ── Key derivation (reconstructed from hw_ssp_aes.c / aescrypt.c) ───── */

/*
 * Derive a 32-byte AES key and a 32-byte IV from a password using
 * PBKDF2-HMAC-SHA-256 (8192 iterations).  This matches the logic
 * observed in libhw_ssp_basic.so → mbedtls_pkcs5_pbkdf2_hmac.
 */
static int derive_key_iv(const uint8_t *password, size_t pw_len,
                         const uint8_t salt[8],
                         uint8_t key[32], uint8_t iv_derived[32]) {
    uint8_t derived[64];
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
        return -1;

    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    int ret = mbedtls_md_setup(&md_ctx, md_info, 1);
    if (ret != 0) {
        mbedtls_md_free(&md_ctx);
        return ret;
    }

    ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, password, pw_len,
                                     salt, 8,
                                     AESCRYPT2_PBKDF2_ITER,
                                     64, derived);
    mbedtls_md_free(&md_ctx);
    if (ret != 0)
        return ret;

    memcpy(key, derived, 32);
    memcpy(iv_derived, derived + 32, 32);
    return 0;
}

/* ── HMAC-SHA-256 ────────────────────────────────────────────────────────── */

static int compute_hmac_sha256(const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t out[32]) {
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
        return -1;
    return mbedtls_md_hmac(md_info, key, key_len, data, data_len, out);
}

/* ── aescrypt2 encrypt (reconstructed from OS_AescryptEncrypt) ───────────── */

int aescrypt2_encrypt(const char *in_path, const char *out_path,
                      const char *key_str, int key_mode) {
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    int ret;

    ret = read_file(in_path, &plain, &plain_len);
    if (ret != 0) {
        fprintf(stderr, "Cannot read %s\n", in_path);
        return -1;
    }

    /* Default password if none provided */
    const uint8_t *password;
    size_t pw_len;
    const char default_pw[] = "";
    if (key_str && key_str[0]) {
        if (key_mode) {
            /* key_str is a path to a key file */
            uint8_t *kdata = NULL;
            size_t klen = 0;
            if (read_file(key_str, &kdata, &klen) != 0) {
                free(plain);
                return -1;
            }
            password = kdata;
            pw_len = klen;
        } else {
            password = (const uint8_t *)key_str;
            pw_len = strlen(key_str);
        }
    } else {
        password = (const uint8_t *)default_pw;
        pw_len = 0;
    }

    /* Generate random IV (also used as salt for PBKDF2) */
    uint8_t iv_random[AESCRYPT2_IV_LEN];
    if (gen_random(iv_random, sizeof(iv_random)) != 0) {
        free(plain);
        return -1;
    }

    /* Derive key and IV */
    uint8_t aes_key[32], iv_derived[32];
    ret = derive_key_iv(password, pw_len, iv_random, aes_key, iv_derived);
    if (ret != 0) {
        free(plain);
        return ret;
    }

    /* XOR derived IV with random IV */
    uint8_t iv[AESCRYPT2_IV_LEN];
    for (int i = 0; i < AESCRYPT2_IV_LEN; i++)
        iv[i] = iv_random[i] ^ iv_derived[i];

    /* PKCS#7 pad plaintext */
    size_t padded_len = plain_len + (AES_BLOCK_SIZE - (plain_len % AES_BLOCK_SIZE));
    uint8_t *padded = (uint8_t *)calloc(1, padded_len);
    if (!padded) { free(plain); return -1; }
    memcpy(padded, plain, plain_len);
    padded_len = pkcs7_pad(padded, plain_len, AES_BLOCK_SIZE);

    /* Encrypt with AES-256-CBC */
    uint8_t *cipher = (uint8_t *)malloc(padded_len);
    if (!cipher) { free(padded); free(plain); return -1; }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len,
                           iv, padded, cipher);
    mbedtls_aes_free(&aes);

    /* Compute HMAC-SHA-256 over (IV ‖ ciphertext) */
    uint8_t hmac[AESCRYPT2_HMAC_LEN];
    size_t hmac_input_len = AESCRYPT2_IV_LEN + padded_len;
    uint8_t *hmac_input = (uint8_t *)malloc(hmac_input_len);
    if (!hmac_input) { free(cipher); free(padded); free(plain); return -1; }
    memcpy(hmac_input, iv_random, AESCRYPT2_IV_LEN);
    memcpy(hmac_input + AESCRYPT2_IV_LEN, cipher, padded_len);
    compute_hmac_sha256(aes_key, 32, hmac_input, hmac_input_len, hmac);
    free(hmac_input);

    /* Build output: MAGIC(4) + orig_size(4) + IV(16) + cipher + HMAC(32) */
    size_t out_len = AESCRYPT2_MAGIC_LEN + 4 + AESCRYPT2_IV_LEN + padded_len + AESCRYPT2_HMAC_LEN;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) { free(cipher); free(padded); free(plain); return -1; }

    size_t off = 0;
    memcpy(out + off, AESCRYPT2_MAGIC, AESCRYPT2_MAGIC_LEN); off += AESCRYPT2_MAGIC_LEN;
    /* Original file size, big-endian */
    out[off++] = (uint8_t)(plain_len >> 24);
    out[off++] = (uint8_t)(plain_len >> 16);
    out[off++] = (uint8_t)(plain_len >> 8);
    out[off++] = (uint8_t)(plain_len);
    memcpy(out + off, iv_random, AESCRYPT2_IV_LEN); off += AESCRYPT2_IV_LEN;
    memcpy(out + off, cipher, padded_len);           off += padded_len;
    memcpy(out + off, hmac, AESCRYPT2_HMAC_LEN);     off += AESCRYPT2_HMAC_LEN;

    ret = write_file(out_path, out, out_len);

    free(out);
    free(cipher);
    free(padded);
    free(plain);
    return ret;
}

/* ── aescrypt2 decrypt (reconstructed from OS_AescryptDecrypt) ───────────── */

int aescrypt2_decrypt(const char *in_path, const char *out_path,
                      const char *key_str, int key_mode) {
    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret;

    ret = read_file(in_path, &data, &data_len);
    if (ret != 0) {
        fprintf(stderr, "Cannot read %s\n", in_path);
        return -1;
    }

    /* Minimum: MAGIC(4) + size(4) + IV(16) + 1 block(16) + HMAC(32) = 72 */
    size_t min_size = AESCRYPT2_MAGIC_LEN + 4 + AESCRYPT2_IV_LEN + AES_BLOCK_SIZE + AESCRYPT2_HMAC_LEN;
    if (data_len < min_size) {
        fprintf(stderr, "File too small\n");
        free(data);
        return -1;
    }

    /* Check magic */
    if (memcmp(data, AESCRYPT2_MAGIC, AESCRYPT2_MAGIC_LEN) != 0) {
        fprintf(stderr, "Invalid magic (expected AEST)\n");
        free(data);
        return -1;
    }

    /* Parse header */
    size_t off = AESCRYPT2_MAGIC_LEN;
    uint32_t orig_size = ((uint32_t)data[off] << 24) |
                         ((uint32_t)data[off+1] << 16) |
                         ((uint32_t)data[off+2] << 8) |
                         ((uint32_t)data[off+3]);
    off += 4;

    uint8_t iv_random[AESCRYPT2_IV_LEN];
    memcpy(iv_random, data + off, AESCRYPT2_IV_LEN);
    off += AESCRYPT2_IV_LEN;

    size_t cipher_len = data_len - AESCRYPT2_MAGIC_LEN - 4 - AESCRYPT2_IV_LEN - AESCRYPT2_HMAC_LEN;
    if (cipher_len % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Invalid ciphertext length\n");
        free(data);
        return -1;
    }

    uint8_t *cipher = data + off;
    uint8_t *stored_hmac = data + off + cipher_len;

    /* Resolve password */
    const uint8_t *password;
    size_t pw_len;
    const char default_pw[] = "";
    uint8_t *kdata = NULL;
    if (key_str && key_str[0]) {
        if (key_mode) {
            size_t klen = 0;
            if (read_file(key_str, &kdata, &klen) != 0) {
                free(data);
                return -1;
            }
            password = kdata;
            pw_len = klen;
        } else {
            password = (const uint8_t *)key_str;
            pw_len = strlen(key_str);
        }
    } else {
        password = (const uint8_t *)default_pw;
        pw_len = 0;
    }

    /* Derive key and IV */
    uint8_t aes_key[32], iv_derived[32];
    ret = derive_key_iv(password, pw_len, iv_random, aes_key, iv_derived);
    if (kdata) free(kdata);
    if (ret != 0) {
        free(data);
        return ret;
    }

    /* Verify HMAC */
    uint8_t computed_hmac[AESCRYPT2_HMAC_LEN];
    size_t hmac_input_len = AESCRYPT2_IV_LEN + cipher_len;
    uint8_t *hmac_input = (uint8_t *)malloc(hmac_input_len);
    if (!hmac_input) { free(data); return -1; }
    memcpy(hmac_input, iv_random, AESCRYPT2_IV_LEN);
    memcpy(hmac_input + AESCRYPT2_IV_LEN, cipher, cipher_len);
    compute_hmac_sha256(aes_key, 32, hmac_input, hmac_input_len, computed_hmac);
    free(hmac_input);

    if (memcmp(stored_hmac, computed_hmac, AESCRYPT2_HMAC_LEN) != 0) {
        fprintf(stderr, "HMAC verification failed — wrong key or corrupt file\n");
        free(data);
        return -1;
    }

    /* XOR derived IV with random IV */
    uint8_t iv[AESCRYPT2_IV_LEN];
    for (int i = 0; i < AESCRYPT2_IV_LEN; i++)
        iv[i] = iv_random[i] ^ iv_derived[i];

    /* Decrypt with AES-256-CBC */
    uint8_t *plain = (uint8_t *)malloc(cipher_len);
    if (!plain) { free(data); return -1; }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aes_key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, cipher_len,
                           iv, cipher, plain);
    mbedtls_aes_free(&aes);

    /* Remove PKCS#7 padding and verify original size */
    size_t unpadded_len = 0;
    ret = pkcs7_unpad(plain, cipher_len, &unpadded_len);
    if (ret != 0) {
        fprintf(stderr, "Invalid PKCS#7 padding\n");
        free(plain);
        free(data);
        return -1;
    }

    /* Prefer the stored original size if it matches */
    size_t out_len = (orig_size <= unpadded_len) ? orig_size : unpadded_len;

    ret = write_file(out_path, plain, out_len);

    free(plain);
    free(data);
    return ret;
}
