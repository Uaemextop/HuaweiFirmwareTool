/*
 * wlan_aes_crypto.h  –  Huawei WLAN AES crypto library API
 *
 * Reconstructed from libwlan_aes_crypto.so
 * (EG8145V5-V500R022C00SPC340B019 rootfs SquashFS, ARM32 Cortex-A9, musl libc).
 *
 * Source filename embedded in .rodata: "wlan_aes_crypto.c"
 *
 * Exported symbols (.dynsym):
 *   WLAN_AES_CheckCryptData  @ 0x07ac  size 124
 *   WLAN_AES_Cbc128Encrypt   @ 0x0828  size 424
 *   WLAN_AES_Cbc128Decrypt   @ 0x09d0  size 356
 *   WLAN_AES_GcmEncrypt      @ 0x0b34  size 284
 *   WLAN_AES_GcmDecrypt      @ 0x0c50  size 272
 *
 * Imported symbols (via PLT / libpolarssl.so, libmbedtls.so):
 *   mbedtls_gcm_init           polarssl_aes_init
 *   mbedtls_gcm_setkey         polarssl_aes_setkey_enc
 *   mbedtls_gcm_crypt_and_tag  polarssl_aes_setkey_dec
 *   mbedtls_gcm_auth_decrypt   polarssl_aes_crypt_cbc
 *   mbedtls_gcm_free           mbedtls_aes_free
 *   HW_OS_MemMallocSet         HW_OS_MemFreeD
 *   WLAN_AES_CheckCryptData    memset / memcpy_s
 *   HW_PROC_DBG_LastWord       __stack_chk_fail
 *
 * CBC context struct layout (inferred from WLAN_AES_Cbc128Encrypt disasm):
 *   Offset  Type            Field
 *   0x00    uint8_t *       input           [r7]
 *   0x04    uint32_t        input_len       [r7+4]
 *   0x08    uint8_t *       key             [r7+8]
 *   0x0c    uint32_t        key_bits        [r7+0xc]  (0x34 = 52? → 128-bit AES key)
 *   0x10    uint8_t *       output          [r7+0x10]
 *   0x18    uint8_t *       iv              [r7+0x18]
 *   0x1c    uint32_t *      output_len_out  [r7+0x1c]
 *
 * GCM context struct layout (inferred from WLAN_AES_GcmEncrypt disasm):
 *   0x00    void *          gcm_data        (same base as CBC [r4])
 *   0x04    uint32_t        input_len
 *   0x08    uint8_t *       key             [r4+8]
 *   0x0c    uint32_t        key_len         [r4+0xc]  (passed to mbedtls_gcm_setkey)
 *   0x10    uint8_t *       iv              [r4+0x10]
 *   0x14    size_t          iv_len          [r4+0x14]
 *   0x18    uint8_t *       aad             [r4+0x18]
 *   0x1c    size_t          aad_len         [r4+0x1c]
 *   0x20    uint8_t *       output          [r4+0x20]
 *   0x24    size_t          output_len      [r4+0x24]
 *   0x28    uint8_t *       tag             [r4+0x28]
 */

#ifndef WLAN_AES_CRYPTO_H
#define WLAN_AES_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── CBC context ────────────────────────────────────────────────────────── */

typedef struct {
    const uint8_t  *input;           /* plaintext / ciphertext */
    uint32_t        input_len;       /* byte count (must be multiple of 16) */
    const uint8_t  *key;             /* AES key (16/24/32 bytes) */
    uint32_t        key_bits;        /* key length in bits: 128/192/256 */
    uint8_t        *output;          /* output buffer (≥ input_len) */
    uint32_t        reserved;        /* padding to match observed struct size */
    uint8_t        *iv;              /* 16-byte IV; updated in-place after call */
    uint32_t       *output_len_out;  /* receives actual bytes written */
} WlanAesCbcCtx;

/* ── GCM context ────────────────────────────────────────────────────────── */

typedef struct {
    const void     *reserved0;       /* internal GCM state (opaque) */
    uint32_t        input_len;
    const uint8_t  *key;
    uint32_t        key_len;         /* key byte count (16/24/32) */
    const uint8_t  *iv;
    size_t          iv_len;
    const uint8_t  *aad;             /* additional authenticated data */
    size_t          aad_len;
    uint8_t        *output;
    size_t          output_len;
    uint8_t        *tag;             /* GCM authentication tag (16 bytes) */
} WlanAesGcmCtx;

/* ── API ────────────────────────────────────────────────────────────────── */

/**
 * WLAN_AES_CheckCryptData – null-check guard for crypt context pointers.
 *
 * Disasm (0x07ac – 0x07dc, 48 bytes):
 *   7ac  cmp  r0, #0         ; ctx == NULL?
 *   7b0  mov  ip, sp
 *   7b4  push {fp, ip, lr, pc}
 *   7bc  bne  7dc            ; ctx != NULL → return non-zero (ctx itself)
 *   7c4  mov  r0, #0x16      ; line 22 (error)
 *   7c8  ldr  r1, [pc, #0x50]; "wlan_aes_crypto.c"
 *   7cc  bl   0x76c          ; HW_PROC_DBG_LastWord(22, src, …)
 *   7d0  ldr  r0, [pc, #0x48]; return NULL
 *   7d4  ldm  sp, {fp, sp, pc}
 *   7dc: (return r0 = ctx)
 *
 * @param ctx  Pointer to validate (CBC or GCM context).
 * @return     ctx when non-NULL, NULL on null input (error logged).
 */
void *WLAN_AES_CheckCryptData(void *ctx);

/**
 * WLAN_AES_Cbc128Encrypt – AES-CBC encryption via polarssl_aes_crypt_cbc.
 *
 * Disasm (0x0828 – 0x09b4, 396 bytes):
 *   bl polarssl_aes_init(stack_ctx)
 *   bl HW_OS_MemMallocSet(aligned_len)   ; allocate output buffer
 *   bl polarssl_aes_setkey_enc(…, key, 0x34 [=52? → 128-bit in polarssl units])
 *   bl polarssl_aes_crypt_cbc(…, AES_ENCRYPT, len, iv, input, output)
 *   bl mbedtls_aes_free(stack_ctx)
 *   str r5, [r3]                          ; *output_len_out = encrypted_len
 *
 * @param ctx  Pointer to a WlanAesCbcCtx (must be non-NULL).
 * @return     0 on success, non-zero on error.
 */
int WLAN_AES_Cbc128Encrypt(WlanAesCbcCtx *ctx);

/**
 * WLAN_AES_Cbc128Decrypt – AES-CBC decryption via polarssl_aes_crypt_cbc.
 *
 * Disasm (0x09d0 – 0x0b1c, 332 bytes):
 *   bl polarssl_aes_init
 *   bl HW_OS_MemMallocSet
 *   bl polarssl_aes_setkey_dec(…, key, key_bits)
 *   bl polarssl_aes_crypt_cbc(…, AES_DECRYPT, len, iv, input, output)
 *   bl mbedtls_aes_free / HW_OS_MemFreeD
 *   str r2, [r3]   ; *output_len_out = decrypted_len
 *
 * @param ctx  Pointer to a WlanAesCbcCtx (must be non-NULL).
 * @return     0 on success, non-zero on error.
 */
int WLAN_AES_Cbc128Decrypt(WlanAesCbcCtx *ctx);

/**
 * WLAN_AES_GcmEncrypt – AES-GCM authenticated encryption via mbedTLS.
 *
 * Disasm (0x0b34 – 0x0c38, 260 bytes):
 *   bl mbedtls_gcm_init(stack_gcm)
 *   bl mbedtls_gcm_setkey(stack_gcm, MBEDTLS_CIPHER_ID_AES=2, key, key_bits)
 *   bl mbedtls_gcm_crypt_and_tag(stack_gcm, MBEDTLS_GCM_ENCRYPT=1,
 *          input_len, iv, iv_len, aad, aad_len, input, output,
 *          16, tag)
 *   bl mbedtls_gcm_free(stack_gcm)
 *
 * @param ctx  Pointer to a WlanAesGcmCtx (must be non-NULL).
 * @return     0 on success, non-zero on error.
 */
int WLAN_AES_GcmEncrypt(WlanAesGcmCtx *ctx);

/**
 * WLAN_AES_GcmDecrypt – AES-GCM authenticated decryption via mbedTLS.
 *
 * Disasm (0x0c50 – 0x0d48, 248 bytes):
 *   bl mbedtls_gcm_init
 *   bl mbedtls_gcm_setkey(…, 2 [AES], key, key_bits)
 *   bl mbedtls_gcm_auth_decrypt(stack_gcm, input_len,
 *          iv, iv_len, aad, aad_len, tag, 16, input, output)
 *   bl mbedtls_gcm_free
 *
 * @param ctx  Pointer to a WlanAesGcmCtx (must be non-NULL).
 * @return     0 on success, non-zero on error (includes authentication failure).
 */
int WLAN_AES_GcmDecrypt(WlanAesGcmCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WLAN_AES_CRYPTO_H */
