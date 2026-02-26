/*
 * wlan_aes_crypto.c  –  Huawei WLAN AES crypto library (reconstructed)
 *
 * Original: libwlan_aes_crypto.so (5012 bytes, ARM32 PIE ELF, stripped)
 * Source filename in .rodata: "wlan_aes_crypto.c"
 *
 * Firmware: EG8145V5-V500R022C00SPC340B019.bin
 * Architecture: ARM32 Cortex-A9, musl libc, EABI5
 * Disassembly via Capstone 5.x.
 *
 * Dependencies (dynamic, provided by libpolarssl.so / libmbedtls.so):
 *   polarssl_aes_init / polarssl_aes_setkey_enc / polarssl_aes_setkey_dec
 *   polarssl_aes_crypt_cbc
 *   mbedtls_gcm_init / mbedtls_gcm_setkey / mbedtls_gcm_free
 *   mbedtls_gcm_crypt_and_tag / mbedtls_gcm_auth_decrypt
 *   mbedtls_aes_free
 *   HW_OS_MemMallocSet / HW_OS_MemFreeD
 *   HW_PROC_DBG_LastWord
 *   memset / memcpy_s / __stack_chk_fail
 */

#include "wlan_aes_crypto.h"

#include <string.h>
#include <stdlib.h>

/* ── mbedTLS / polarssl (available at runtime via libmbedtls.so) ────────── */
#if defined(HAVE_MBEDTLS)
#  include <mbedtls/aes.h>
#  include <mbedtls/gcm.h>
#  define MBEDTLS_CIPHER_ID_AES  2
#else
/* Forward declarations for cross-compilation when headers are unavailable */
typedef struct { unsigned char buf[264]; } mbedtls_aes_context;
typedef struct { unsigned char buf[512]; } mbedtls_gcm_context;
int mbedtls_aes_setkey_enc(mbedtls_aes_context *, const unsigned char *, unsigned int);
int mbedtls_aes_setkey_dec(mbedtls_aes_context *, const unsigned char *, unsigned int);
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *, int, size_t,
                           unsigned char *, const unsigned char *, unsigned char *);
void mbedtls_aes_free(mbedtls_aes_context *);
void mbedtls_gcm_init(mbedtls_gcm_context *);
int  mbedtls_gcm_setkey(mbedtls_gcm_context *, int, const unsigned char *, unsigned int);
int  mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *, int, size_t,
                                const unsigned char *, size_t,
                                const unsigned char *, size_t,
                                const unsigned char *, unsigned char *,
                                size_t, unsigned char *);
int  mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *, size_t,
                               const unsigned char *, size_t,
                               const unsigned char *, size_t,
                               const unsigned char *, size_t,
                               const unsigned char *, unsigned char *);
void mbedtls_gcm_free(mbedtls_gcm_context *);
#define MBEDTLS_AES_ENCRYPT 1
#define MBEDTLS_AES_DECRYPT 0
#define MBEDTLS_CIPHER_ID_AES 2
#endif

/* polarssl_aes_crypt_cbc lives in libpolarssl.so on the device */
typedef struct { unsigned char buf[264]; } polarssl_aes_context;
extern void polarssl_aes_init(polarssl_aes_context *ctx);
extern int  polarssl_aes_setkey_enc(polarssl_aes_context *ctx,
                                     const unsigned char *key, unsigned int keybits);
extern int  polarssl_aes_setkey_dec(polarssl_aes_context *ctx,
                                     const unsigned char *key, unsigned int keybits);
extern int  polarssl_aes_crypt_cbc(polarssl_aes_context *ctx, int mode,
                                    size_t length, unsigned char *iv,
                                    const unsigned char *input, unsigned char *output);

/* Huawei memory helpers */
extern void *HW_OS_MemMallocSet(size_t size);
extern void  HW_OS_MemFreeD(void *ptr);
extern void  HW_PROC_DBG_LastWord(int line, const char *file,
                                   const char *msg, int a, int b, int c);

/* ── Internal error helper ──────────────────────────────────────────────── */
#define WLAN_AES_ERR(line, msg) \
    HW_PROC_DBG_LastWord((line), "wlan_aes_crypto.c", (msg), 0, 0, 0)

/* GCM tag length (16 bytes, constant in all GCM call sites) */
#define GCM_TAG_LEN  16u

/* ======================================================================== */
/* WLAN_AES_CheckCryptData                                                   */
/* ======================================================================== */

/*
 * Disasm (0x07ac – 0x07dc, 48 bytes):
 *   7ac  cmp  r0, #0
 *   7b0  mov  ip, sp
 *   7b4  push {fp, ip, lr, pc}
 *   7b8  sub  fp, ip, #4
 *   7bc  bne  7dc           ; non-NULL → return ctx unchanged
 *   7c4  mov  r0, #0x16     ; line 22
 *   7c8  ldr  r1, [pc, #0x50] ; "wlan_aes_crypto.c"
 *   7cc  bl   0x76c         ; HW_PROC_DBG_LastWord
 *   7d0  ldr  r0, [pc, #0x48] ; load NULL literal
 *   7d4  sub  sp, fp, #0xc
 *   7d8  ldm  sp, {fp, sp, pc}
 *   7dc  (return r0 = original ctx pointer)
 */
void *WLAN_AES_CheckCryptData(void *ctx)
{
    if (!ctx) {
        WLAN_AES_ERR(0x16, "ctx is NULL");
        return NULL;
    }
    return ctx;
}

/* ======================================================================== */
/* WLAN_AES_Cbc128Encrypt                                                    */
/* ======================================================================== */

/*
 * Disasm (0x0828 – 0x09b4, 396 bytes):
 *
 *   828  push {r4-r8,fp,ip,lr,pc}
 *   838  sub  sp, sp, #0x134         ; large stack frame for polarssl ctx
 *   848  mov  r7, r0                 ; r7 = ctx
 *   858  bl   polarssl_aes_init(sp+ctx_on_stack)
 *   85c  subs r4, r0, #0
 *   868  bne  →error 0x2a
 *   86c  ldr  r4, [r7, #4]           ; r4 = ctx->input_len
 *   870  tst  r4, #0xf               ; not 16-byte aligned?
 *   874  bicne r5, r4, #0xf          ; round down
 *   878  addne r5, r5, #0x10         ; round up to next 16-byte boundary
 *   87c  moveq r5, r4                ; already aligned
 *   880  mov  r0, r5
 *   884  bl   HW_OS_MemMallocSet(r5) ; allocate output buffer
 *   888  subs r6, r0, #0
 *   88c  bne  →error next
 *   890  ldr  r0, [pc, #0x12c]       ; "wlan_aes_crypto.c" literal
 *   89c  mov  r1, #0x34              ; key size field (0x34 passed to setkey)
 *   8b0  bl   polarssl_aes_setkey_enc(ctx_on_stack, key, 0x34)
 *     NOTE: polarssl uses key-bits/8 in some versions; 0x34=52 → likely 128-bit
 *     encoded differently.  The key pointer comes from ctx->key at [r7+8].
 *   (…allocate AES key structure on stack…)
 *   964  ldr  r3, [r7, #0x18]        ; iv
 *   968  mov  r1, #1                  ; ENCRYPT
 *   96c  mov  r2, r5                  ; aligned length
 *   974  mov  r0, r8                  ; stack AES ctx
 *   980  bl   polarssl_aes_crypt_cbc(ctx, ENCRYPT, len, iv, input, output)
 *   984  mov  r4, r0
 *   988  mov  r0, r8
 *   98c  bl   mbedtls_aes_free
 *   990  mov  r0, r6
 *   994  bl   HW_OS_MemFreeD
 *   998  cmp  r4, #0
 *   9ac  ldr  r3, [r7, #0x1c]        ; ctx->output_len_out
 *   9b0  str  r5, [r3]               ; *output_len_out = aligned_len
 */
int WLAN_AES_Cbc128Encrypt(WlanAesCbcCtx *ctx)
{
    polarssl_aes_context  pss_ctx;
    uint8_t              *out_buf;
    uint32_t              aligned_len;
    int                   ret;

    if (!WLAN_AES_CheckCryptData(ctx))
        return 0x2a; /* error code from disasm */

    /* Round input_len up to 16-byte boundary */
    aligned_len = ctx->input_len;
    if (aligned_len & 0xfu) {
        aligned_len = (aligned_len & ~0xfu) + 0x10u;
    }

    /* Allocate output buffer */
    out_buf = (uint8_t *)HW_OS_MemMallocSet(aligned_len);
    if (!out_buf) {
        WLAN_AES_ERR(0x3b, "malloc failed");
        return 0x3b;
    }

    /* Initialise and set encryption key (polarssl API on target) */
    polarssl_aes_init(&pss_ctx);
    if ((ret = polarssl_aes_setkey_enc(&pss_ctx, ctx->key,
                                        ctx->key_bits)) != 0) {
        WLAN_AES_ERR(0x45, "setkey_enc failed");
        HW_OS_MemFreeD(out_buf);
        return 0x45;
    }

    /* AES-CBC encrypt */
    ret = polarssl_aes_crypt_cbc(&pss_ctx, 1 /* encrypt */,
                                  aligned_len,
                                  ctx->iv,
                                  ctx->input,
                                  out_buf);

    /* Copy result to caller's output and release temp buffer */
    if (ret == 0) {
        memcpy(ctx->output, out_buf, aligned_len);
        if (ctx->output_len_out)
            *ctx->output_len_out = aligned_len;
    } else {
        WLAN_AES_ERR(0x52, "crypt_cbc encrypt failed");
    }

    HW_OS_MemFreeD(out_buf);
    return ret;
}

/* ======================================================================== */
/* WLAN_AES_Cbc128Decrypt                                                    */
/* ======================================================================== */

/*
 * Disasm (0x09d0 – 0x0b1c, 332 bytes):
 *
 *   9d0  push {r4-r7,fp,ip,lr,pc}
 *   9f0  mov  r4, r0                 ; r4 = ctx
 *   a00  bl   polarssl_aes_init
 *   a04  subs r6, r0, #0
 *   a08  beq  a44
 *   a0c  mov  r0, #0x62  ; line 98  → early error
 *   a44  ldr  r3, [r4, #4]           ; input_len
 *   a48  ands r5, r3, #0xf           ; check alignment
 *   a4c  beq  a78                    ; aligned
 *   a50  mov  r2, #1                 ; not aligned → log + error
 *   a54  str  r6, [sp, #8]
 *   a5c  mov  r1, #0x68              ; line 104
 *   a70  bl   polarssl_aes_setkey_enc  ; (misread—actually setkey_enc path)
 *   a78  sub  r6, fp, #0x138         ; stack work buffer
 *   a88  bl   HW_OS_MemMallocSet(input_len)
 *   a98  ldr  r1, [r4, #8]           ; key pointer
 *   aa0  bl   memcpy_s(r6, 0x80, key_ptr, …)  ; copy IV/key into work buf
 *   ac8  ldr  r3, [r4, #0x18]        ; iv
 *   acc  mov  r1, r5=0               ; DECRYPT
 *   ad0  ldr  r2, [r4, #4]           ; length
 *   ad4  mov  r0, r6
 *   ad8  str  r3, [sp, #4]           ; iv on stack
 *   adc  ldr  r3, [r4]               ; input
 *   ae0  str  r3, [sp]
 *   ae4  ldr  r3, [r4, #0x10]        ; output
 *   ae8  bl   polarssl_aes_crypt_cbc(…, DECRYPT, len, iv, input, output)
 *   aec  mov  r7, r0
 *   af0  bl   HW_OS_MemFreeD / mbedtls_aes_free
 *   af8  cmp  r7, #0
 *   afc  ldreq r3, [r4, #0x1c]       ; *output_len_out
 *   b00  ldreq r2, [r4, #4]
 *   b04  streq r2, [r3]              ; *output_len_out = decrypted_len
 */
int WLAN_AES_Cbc128Decrypt(WlanAesCbcCtx *ctx)
{
    polarssl_aes_context pss_ctx;
    int                  ret;

    if (!WLAN_AES_CheckCryptData(ctx))
        return 0x62; /* line from disasm */

    /* Input must be a multiple of 16 bytes */
    if (ctx->input_len & 0xfu) {
        WLAN_AES_ERR(0x68, "input_len not 16-byte aligned");
        return 0x68;
    }

    polarssl_aes_init(&pss_ctx);
    if ((ret = polarssl_aes_setkey_dec(&pss_ctx, ctx->key,
                                        ctx->key_bits)) != 0) {
        WLAN_AES_ERR(0x71, "setkey_dec failed");
        return 0x71;
    }

    ret = polarssl_aes_crypt_cbc(&pss_ctx, 0 /* decrypt */,
                                  ctx->input_len,
                                  ctx->iv,
                                  ctx->input,
                                  ctx->output);
    if (ret == 0) {
        if (ctx->output_len_out)
            *ctx->output_len_out = ctx->input_len;
    } else {
        WLAN_AES_ERR(0x7b, "crypt_cbc decrypt failed");
    }

    return ret;
}

/* ======================================================================== */
/* WLAN_AES_GcmEncrypt                                                       */
/* ======================================================================== */

/*
 * Disasm (0x0b34 – 0x0c38, 260 bytes):
 *
 *   b34  push {r4-r6,fp,ip,lr,pc}
 *   b50  subs r4, r0, #0        ; r4 = ctx, check non-NULL
 *   b64  bne  b9c
 *   b68  mov  r0, #0x8a         ; line 138
 *   b70  bl   HW_PROC_DBG_LastWord   → error
 *   b9c  sub  r6, fp, #0x1b4    ; mbedtls_gcm_context on stack (large!)
 *   ba0  bl   mbedtls_gcm_init(r6)
 *   ba8  mov  r1, #2             ; MBEDTLS_CIPHER_ID_AES = 2
 *   bac  ldrd r2, r3, [r4, #8]  ; key pointer + key_len
 *   bb0  bl   mbedtls_gcm_setkey(r6, AES, key, key_len*8)
 *   bb8  subs r5, r0, #0
 *   bbc  bne  →error 0x94
 *   bc8  ldr  r3, [r4, #0x18]   ; aad
 *   bcc  mov  r1, #1             ; MBEDTLS_GCM_ENCRYPT
 *   bd0  mov  r0, r6
 *   bd4  str  r3, [sp, #0x18]
 *   bd8  ldr  r3, [r4, #0x1c]   ; aad_len
 *   bdc  str  r3, [sp, #0x14]
 *   be0  ldr  r3, [r4, #0x28]   ; tag
 *   be4  str  r3, [sp, #0x10]
 *   be8  ldr  r3, [r4]           ; input
 *   bec  str  r3, [sp, #0xc]
 *   bf0  ldr  r3, [r4, #0x24]   ; output_len
 *   bf4  str  r3, [sp, #8]
 *   bf8  ldr  r3, [r4, #0x20]   ; output
 *   bfc  str  r3, [sp, #4]
 *   c00  ldr  r3, [r4, #0x14]   ; iv_len
 *   c04  str  r3, [sp]
 *   c08  ldr  r3, [r4, #0x10]   ; iv
 *   c0c  ldr  r2, [r4, #4]      ; input_len  → r2
 *   c10  bl   mbedtls_gcm_crypt_and_tag(ctx, ENCRYPT, input_len,
 *             iv, iv_len, aad, aad_len, input, output, GCM_TAG_LEN, tag)
 *   c14  subs r5, r0, #0
 *   c28  bl   mbedtls_gcm_free(r6)
 *   c38  ldm  sp, {r4-r6, fp, sp, pc}
 */
int WLAN_AES_GcmEncrypt(WlanAesGcmCtx *ctx)
{
    mbedtls_gcm_context gcm;
    int ret;

    if (!WLAN_AES_CheckCryptData(ctx))
        return 0x8a; /* line 138 */

    mbedtls_gcm_init(&gcm);

    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                              ctx->key, ctx->key_len * 8u);
    if (ret != 0) {
        WLAN_AES_ERR(0x94, "gcm_setkey failed");
        mbedtls_gcm_free(&gcm);
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(
            &gcm, MBEDTLS_AES_ENCRYPT,
            ctx->input_len,
            ctx->iv,       ctx->iv_len,
            ctx->aad,      ctx->aad_len,
            (const unsigned char *)ctx->reserved0,  /* input */
            ctx->output,
            GCM_TAG_LEN,
            ctx->tag);

    if (ret != 0)
        WLAN_AES_ERR(0x9d, "gcm_crypt_and_tag failed");

    mbedtls_gcm_free(&gcm);
    return ret;
}

/* ======================================================================== */
/* WLAN_AES_GcmDecrypt                                                       */
/* ======================================================================== */

/*
 * Disasm (0x0c50 – 0x0d48, 248 bytes):
 *
 *   c50  push {r4-r6,fp,ip,lr,pc}
 *   c6c  subs r4, r0, #0
 *   c80  bne  cb8
 *   c84  mov  r0, #0xab        ; line 171
 *   cb8  sub  r6, fp, #0x1b4
 *   cbc  bl   mbedtls_gcm_init(r6)
 *   cc4  mov  r1, #2
 *   cc8  ldrd r2, r3, [r4, #8]
 *   ccc  bl   mbedtls_gcm_setkey(r6, AES, key, key_len*8)
 *   cd4  subs r5, r0, #0
 *   cd8  bne  →error 0xb5
 *   ce4  ldr  r3, [r4, #0x28]  ; tag
 *   ce8  str  r3, [sp, #0x14]
 *   cec  ldr  r3, [r4]          ; input
 *   cf0  str  r3, [sp, #0x10]
 *   cf4  ldr  r3, [r4, #0x1c]  ; aad_len
 *   cf8  str  r3, [sp, #0xc]
 *   cfc  ldr  r3, [r4, #0x18]  ; aad
 *   d00  str  r3, [sp, #8]
 *   d04  ldr  r3, [r4, #0x24]  ; output_len
 *   d08  str  r3, [sp, #4]
 *   d0c  ldr  r3, [r4, #0x20]  ; output
 *   d10  str  r3, [sp]
 *   d18  ldrd r2, r3, [r4, #0x10]  ; iv, iv_len → r2, r3
 *   d1c  ldr  r1, [r4, #4]    ; input_len
 *   d20  bl   mbedtls_gcm_auth_decrypt(ctx, input_len,
 *             iv, iv_len, aad, aad_len, tag, GCM_TAG_LEN, input, output)
 *   d24  subs r5, r0, #0
 *   d38  bl   mbedtls_gcm_free
 *   d48  ldm  sp, {r4-r6, fp, sp, pc}
 */
int WLAN_AES_GcmDecrypt(WlanAesGcmCtx *ctx)
{
    mbedtls_gcm_context gcm;
    int ret;

    if (!WLAN_AES_CheckCryptData(ctx))
        return 0xab; /* line 171 */

    mbedtls_gcm_init(&gcm);

    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                              ctx->key, ctx->key_len * 8u);
    if (ret != 0) {
        WLAN_AES_ERR(0xb5, "gcm_setkey failed");
        mbedtls_gcm_free(&gcm);
        return ret;
    }

    ret = mbedtls_gcm_auth_decrypt(
            &gcm,
            ctx->input_len,
            ctx->iv,   ctx->iv_len,
            ctx->aad,  ctx->aad_len,
            ctx->tag,  GCM_TAG_LEN,
            (const unsigned char *)ctx->reserved0,  /* input */
            ctx->output);

    if (ret != 0)
        WLAN_AES_ERR(0xbe, "gcm_auth_decrypt failed");

    mbedtls_gcm_free(&gcm);
    return ret;
}
