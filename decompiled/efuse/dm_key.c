/*
 * dm_key.c  –  Huawei DM key derivation (reconstructed)
 *
 * Sources: libsmp_api.so  (libhw_smp_dm_pdt.so calls via shared func table)
 * Original source filenames embedded in .rodata: "efuse.c", "keyfile"
 *
 * ── Complete eFuse → AES-256 Key Derivation Chain ──────────────────────────
 *
 *  1. hal_efuse_get_data()                  [hw_module_efuse.ko]
 *       ↓ 64 bytes from SRAM eFuse shadow
 *  2. DM_GetRootKeyOffset()                 [libsmp_api.so, vaddr 0x289a0]
 *       Uses HW_SWM_GetMtdBlkNameAndOffset("KeyFile")
 *       Computes: flash_offset = MTD.offset + 0x20000 - caller_offset
 *       ↓ MTD block name + byte offset in flash
 *  3. HW_OS_FLASH_Read(mtd_block, flash_offset, buf, 0x60)  [96 bytes]
 *       Reads "flash head" from the KeyFile MTD partition
 *  4. DM_DecryptEncryptHead(buf, decrypt=1)  [libsmp_api.so, vaddr 0x36764]
 *       Calls DM_LdspDecryptData(buf, 0x60, work_buf, 0x60)
 *       ↓ decrypted flash head (96 bytes)
 *  5. DM_LdspDecryptData()                  [libsmp_api.so, vaddr 0x363f4]
 *       Dispatches via ProductShareFunc table at +0x80 →
 *       sec_hisi_crypto (hw_module_sec.ko) →
 *       hi_ipsec_crypto_decrypt (hardware IPSec AES engine)
 *       ↓ 32 bytes of raw key material (from decrypted flash head at offset +0x20)
 *  6. DM_GetKeyByMaterial()                 [libsmp_api.so, vaddr 0x365e8]
 *       Calls CAC_Pbkdf2Api(material, 0x20, salt, salt_len, iters, out, 0x20)
 *       PBKDF2-HMAC-SHA256: 32-byte output = AES-256 key
 *       ↓ 32-byte AES-256-CBC key
 *  7. OS_AescryptEncrypt / OS_AescryptDecrypt  [libhw_ssp_basic.so]
 *       AES-256-CBC with the derived key + IV from encrypted-file header
 *
 * ── Encrypted files using this key chain ──────────────────────────────────
 *   /mnt/jffs2/ttree_spec_smooth.tar.gz    (8712 B, aescrypt2 format)
 *   /mnt/jffs2/hw_ctree.xml                (AES-256-CBC, device-unique key)
 *   Other config files in /mnt/jffs2/ with Huawei aescrypt2 header
 *
 * ── eFuse Key Recovery Methods ────────────────────────────────────────────
 *
 * METHOD A – Live device UART/JTAG RAM dump:
 *   If UART debug boot is available (HiSilicon Hi3xxx bootloader U-Boot menu):
 *   1. Interrupt boot at U-Boot prompt (Ctrl+C or break on UART)
 *   2. Use U-Boot "md" command to read SRAM:
 *        md.b 0x12010100 40    # SD511x eFuse SRAM shadow
 *        md.b 0x10F00100 40    # Hi3798 variant
 *   3. The 64 bytes contain the eFuse key material.
 *
 * METHOD B – Running Linux kernel (requires root shell on device):
 *   The eFuse data is available via the exported kernel symbol:
 *     hal_efuse_get_data(buf, 64)
 *   Access methods:
 *     a) If /dev/mem is available: devmem2 0x12010100 b (64 reads)
 *     b) Write a kernel module that calls hal_efuse_get_data() and
 *        writes to /proc or /sys
 *     c) Telnet/SSH root shell → read /proc/driver/hw_efuse if registered
 *
 * METHOD C – Flash read (off-device, requires physical flash extraction):
 *   1. Desolder the NAND/NOR flash chip
 *   2. Read with programmer (e.g. XGecu T56, Dediprog SF600)
 *   3. Find the "KeyFile" MTD partition (index varies by firmware)
 *   4. Read 96 bytes at offset + 0x20000 = encrypted flash head
 *   5. The encrypted head CANNOT be decrypted without the eFuse key
 *      (chicken-and-egg: eFuse decrypts the flash head, flash head
 *       contains the key material, key material + PBKDF2 = AES key)
 *   NOTE: The eFuse is OTP burned during factory provisioning; it is
 *         NOT stored anywhere in the firmware image.
 *
 * METHOD D – ROM / bootloader extraction:
 *   The HiSilicon SD511x boot ROM copies the eFuse to SRAM before Linux
 *   boots.  On some variants the ROM is readable via:
 *     dd if=/dev/mem bs=1 skip=$((0x12010000)) count=4096 of=efuse_region.bin
 *   (requires /dev/mem access with CAP_SYS_RAWIO)
 *
 * ── Security note ─────────────────────────────────────────────────────────
 *   The eFuse is burned once at the factory and is DEVICE-UNIQUE.
 *   It is impossible to derive the key for device X from the firmware
 *   binary alone.  The key derivation functions (DM_GetKeyByMaterial,
 *   CAC_Pbkdf2Api) are deterministic GIVEN the eFuse material, but the
 *   material is hardware-only.
 */

#include "dm_key.h"

#include <string.h>
#include <stdint.h>

/* Host build: include safe-string stubs header */
#if !defined(__KERNEL__) && !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)
#  include "../stubs/hw_os_stubs.h"
#endif

#if defined(HAVE_MBEDTLS)
#  include <mbedtls/pkcs5.h>   /* mbedtls_pkcs5_pbkdf2_hmac */
#  include <mbedtls/md.h>
#endif

/* ── External dependencies (provided by runtime libs) ──────────────────── */
extern int  HW_OS_FLASH_Read(const char *mtd, uint32_t offset,
                               void *buf, uint32_t len);
extern int  HW_SWM_GetMtdBlkNameAndOffset(const char *partition_name,
                                            int flag, char *blk_name,
                                            uint32_t blk_name_len,
                                            uint32_t *offset_out);
extern int  hal_efuse_get_data(uint8_t *buf, uint32_t len);
extern void HW_PROC_DBG_LastWord(int line, const char *file,
                                  const char *msg, int a, int b, int c);
extern int  HW_OS_GetLastErr(void);

/* Kernel-side: resolved via ProductShareFunc table (hw_module_sec.ko) */
typedef int (*hw_ldsp_decrypt_fn)(void *dst, uint32_t dst_len,
                                    const void *src, uint32_t src_len);
extern void *HW_DM_GetProductShareFunc(void);
extern int   HW_DM_IsShareFuncsInit(void);

/* ── Internal helpers ──────────────────────────────────────────────────── */
#define DM_ERR(line, msg) HW_PROC_DBG_LastWord((line), "dm_key.c", (msg), 0, 0, 0)

/* ── KeyFile MTD partition name ──────────────────────────────────────────── */
#define KEYFILE_PARTITION   "KeyFile"
#define KEYFILE_BLK_LEN     16u
#define KEYFILE_HEAD_LEN    0x60u   /* 96 bytes – flash head struct */
#define KEYFILE_MATERIAL_OFFSET  0x20u  /* material starts at +32 in head */
#define KEYFILE_MATERIAL_LEN     0x20u  /* 32 bytes of raw material */
#define KEYFILE_OFFSET_BASE      0x20000u

/* ── AES-256 key derivation constants ───────────────────────────────────── */
#define PBKDF2_OUT_LEN      0x20u   /* 32 bytes = 256-bit AES key */
#define PBKDF2_ITER_COUNT   1u      /* single iteration (performance on device) */

/* ======================================================================== */
/* DM_GetRootKeyOffset                                                       */
/* ======================================================================== */

/*
 * Disassembly reference (libsmp_api.so 0x289a0 – 0x28ac0, size 316 bytes):
 *
 *   bl HW_SWM_GetMtdBlkNameAndOffset("KeyFile", 0, blk_name, 0x10, &raw_offset)
 *   ; if raw_offset > 0x20000: error (offset past partition base)
 *   ; *key_offset_out = 0x20000 + raw_offset - caller_offset
 *   ;                 = KEYFILE_OFFSET_BASE + raw_offset - in_offset
 *   ; then strcpy_s(blk_name_out, blk_name)
 *
 * @param in_offset      Caller offset within the 0x20000-byte region.
 * @param key_offset_out Receives the flash byte offset of the key head.
 * @param blk_name_out   Receives the MTD block device name (e.g. "/dev/mtd5").
 * @param blk_name_len   Size of blk_name_out buffer.
 * @param blk_size_out   Receives the key region size (0x10 bytes).
 * @return               0 on success, non-zero on error.
 */
int DM_GetRootKeyOffset(uint32_t in_offset,
                         uint32_t *key_offset_out,
                         char     *blk_name_out,
                         uint32_t  blk_name_len,
                         uint32_t *blk_size_out)
{
    char     blk_name[KEYFILE_BLK_LEN];
    uint32_t raw_offset = 0;
    uint32_t key_size   = KEYFILE_BLK_LEN;

    memset(blk_name, 0, sizeof(blk_name));

    /* Locate the "KeyFile" MTD partition and its start offset */
    if (HW_SWM_GetMtdBlkNameAndOffset(KEYFILE_PARTITION, 0,
                                       blk_name, sizeof(blk_name),
                                       &raw_offset) != 0) {
        DM_ERR(0x52, "GetMtdBlkNameAndOffset failed");
        return 1;
    }

    /* in_offset must be ≤ 0x20000 */
    if (in_offset > KEYFILE_OFFSET_BASE) {
        DM_ERR(0x57, "in_offset > 0x20000");
        return 1;
    }

    /* key lives at KEYFILE_OFFSET_BASE + raw_offset − in_offset */
    *key_offset_out = KEYFILE_OFFSET_BASE + raw_offset - in_offset;
    if (blk_size_out) *blk_size_out = key_size;

    if (blk_name_out)
        strcpy_s(blk_name_out, blk_name_len, blk_name);

    return 0;
}

/* ======================================================================== */
/* DM_LdspDecryptData                                                        */
/* ======================================================================== */

/*
 * Disassembly reference (libsmp_api.so 0x363f4 – 0x364a8, size 192 bytes):
 *
 *   bl   HW_DM_GetProductShareFunc()   → r4 = share_func_table ptr
 *   bl   HW_DM_IsShareFuncsInit()      → 0 = not init
 *   ldr  r4, [r4, #0x80]              → fn_ptr = share_func_table[0x80/4]
 *   blx  r4  (fn_ptr(dst, dst_len, src, src_len))
 *
 * The function at offset +0x80 in the share table is registered by
 * hw_module_sec.ko to sec_hisi_crypto → hi_ipsec_crypto_decrypt:
 * hardware AES-CBC using the eFuse-burned device key.
 *
 * @param dst      Output buffer (decrypted data).
 * @param dst_len  Output buffer size.
 * @param src      Encrypted input buffer.
 * @param src_len  Input size (must be multiple of 16).
 * @return         0 on success, non-zero on error.
 */
int DM_LdspDecryptData(void *dst, uint32_t dst_len,
                        const void *src, uint32_t src_len)
{
    void                 *share_funcs;
    hw_ldsp_decrypt_fn    fn_ptr;
    int                   ret;

    if (!HW_DM_IsShareFuncsInit()) {
        DM_ERR(0x6c, "share funcs not init");
        return 1;
    }

    share_funcs = HW_DM_GetProductShareFunc();
    fn_ptr = *(hw_ldsp_decrypt_fn *)((uint8_t *)share_funcs + 0x80);
    if (!fn_ptr) {
        DM_ERR(0x71, "LDSP decrypt fn is NULL");
        return 1;
    }

    ret = fn_ptr(dst, dst_len, src, src_len);
    if (ret != 0)
        DM_ERR(0x77, "LDSP decrypt failed");

    return ret;
}

/* ======================================================================== */
/* DM_DecryptEncryptHead                                                     */
/* ======================================================================== */

/*
 * Disassembly reference (libsmp_api.so 0x36764 – 0x3685c, size 268 bytes):
 *
 *   cmp  r4, #1           ; mode = 1 → decrypt, else encrypt
 *   bne  →encrypt
 *   →decrypt:
 *     bl   DM_LdspDecryptData(r6, 0x60, r6, 0x60)
 *     bl   memcpy_s(r6_out, 0x60, work_buf, 0x60)
 *   →encrypt:
 *     bl   DM_LdspEncryptData(...)
 *
 * @param buf      Buffer containing flash head (96 bytes, in/out).
 * @param decrypt  1 = decrypt, 0 = encrypt.
 * @return         0 on success.
 */
int DM_DecryptEncryptHead(void *buf, int decrypt)
{
    uint8_t work_buf[KEYFILE_HEAD_LEN];
    int     ret;

    if (!buf) {
        DM_ERR(0x32, "buf is NULL");
        return 1;
    }

    memset(work_buf, 0, sizeof(work_buf));

    if (decrypt) {
        ret = DM_LdspDecryptData(work_buf, KEYFILE_HEAD_LEN,
                                  buf, KEYFILE_HEAD_LEN);
    } else {
        /* DM_LdspEncryptData has same dispatch pattern */
        ret = DM_LdspDecryptData(work_buf, KEYFILE_HEAD_LEN,
                                  buf, KEYFILE_HEAD_LEN); /* placeholder */
    }

    if (ret == 0) {
        memcpy(buf, work_buf, KEYFILE_HEAD_LEN);
    }

    memset(work_buf, 0, sizeof(work_buf));  /* secure erase */
    return ret;
}

/* ======================================================================== */
/* DM_GetKeyByMaterial  –  PBKDF2 key derivation                           */
/* ======================================================================== */

/*
 * Disassembly reference (libsmp_api.so 0x365e8 – 0x36748, size 380 bytes):
 *
 *   bl  DM_LdspDecryptData(r6, 0x20, r7_material, 0x20)
 *                                   ; decrypt 32-byte material via hardware
 *   bl  CAC_Pbkdf2Api(r6, 0x20, r7, r8_salt, sl_extra,
 *                     fp_out_buf, fp_out_sz, r3_iters)
 *                                   ; PBKDF2-HMAC-SHA256
 *   bl  memset_s(r6, 0x20)          ; wipe intermediate
 *
 * CAC_Pbkdf2Api prototype (inferred from call sites):
 *   int CAC_Pbkdf2Api(const uint8_t *password, uint32_t pwd_len,
 *                     uint32_t pbkdf2_type,
 *                     const uint8_t *salt,    uint32_t salt_len,
 *                     uint8_t       *out,     uint32_t out_len,
 *                     uint32_t      iter_count);
 *
 * @param material     32-byte key material (from decrypted flash head).
 * @param salt         Salt for PBKDF2 (from flash head, same 96-byte struct).
 * @param salt_len     Salt length.
 * @param extra_param  Additional parameter passed to CAC_Pbkdf2Api.
 * @param out_key      Output buffer for AES-256 key (32 bytes).
 * @param out_key_len  Must be PBKDF2_OUT_LEN (32).
 * @return             0 on success.
 */
int DM_GetKeyByMaterial(const uint8_t *material,
                         const uint8_t *salt,     uint32_t salt_len,
                         uint32_t       extra_param,
                         uint8_t       *out_key,  uint32_t out_key_len)
{
    uint8_t decrypted_material[KEYFILE_MATERIAL_LEN];
    int     ret;

    if (!material || !salt || !out_key || out_key_len < PBKDF2_OUT_LEN) {
        DM_ERR(0x15, "invalid args");
        return 1;
    }

    memset(decrypted_material, 0, sizeof(decrypted_material));

    /* Step 1: hardware-decrypt the raw material (via eFuse-keyed AES) */
    ret = DM_LdspDecryptData(decrypted_material, KEYFILE_MATERIAL_LEN,
                              material, KEYFILE_MATERIAL_LEN);
    if (ret != 0) {
        DM_ERR(0x1c, "LdspDecryptData failed");
        return ret;
    }

    /* Step 2: PBKDF2-HMAC-SHA256 to derive the final AES-256 key */
#if defined(HAVE_MBEDTLS)
    {
        mbedtls_md_context_t md_ctx;
        const mbedtls_md_info_t *md_info =
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

        mbedtls_md_init(&md_ctx);
        ret = mbedtls_md_setup(&md_ctx, md_info, 1 /* use HMAC */);
        if (ret == 0) {
            ret = mbedtls_pkcs5_pbkdf2_hmac(
                    &md_ctx,
                    decrypted_material, KEYFILE_MATERIAL_LEN,
                    salt,               salt_len,
                    PBKDF2_ITER_COUNT,
                    (uint32_t)PBKDF2_OUT_LEN,
                    out_key);
        }
        mbedtls_md_free(&md_ctx);
    }
#else
    /* Without mbedTLS: copy material as placeholder (NOT secure) */
    memcpy(out_key, decrypted_material, PBKDF2_OUT_LEN);
    DM_ERR(0x24, "mbedTLS not available – PBKDF2 skipped");
#endif

    /* Secure-wipe intermediate material */
    memset(decrypted_material, 0, sizeof(decrypted_material));

    if (ret != 0)
        DM_ERR(0x24, "PBKDF2 failed");

    return ret;
}

/* ======================================================================== */
/* DM_ReadKeyFromFlashHead  –  full key reading pipeline                   */
/* ======================================================================== */

/*
 * Disassembly reference (libsmp_api.so 0x356d0 – 0x35868, size 432 bytes):
 *
 *   bl HW_OS_FLASH_Read(mtd_blk, offset, flash_head, 0x60)
 *   ; if decrypt == 1:
 *   bl DM_DecryptEncryptHead(flash_head, 1)   ; decrypt in-place
 *   ; head valid? check flash_head[0] != 0 (from DM_FlashHeadRead)
 *   ; extract material at head + KEYFILE_MATERIAL_OFFSET (0x20)
 *   bl DM_GetKeyByMaterial(material, salt, 0x20, ..., out_key, 0x20)
 *   ; secure-wipe flash_head
 *   bl memset_s(flash_head, 0x60)
 *
 * @param mtd_blk     MTD block name (e.g. "/dev/mtd5"), from DM_GetRootKeyOffset.
 * @param flash_off   Byte offset within that MTD block.
 * @param decrypt     1 = head is encrypted, 0 = plaintext (factory/debug mode).
 * @param extra_param Additional pass-through parameter.
 * @param out_key     Receives the derived AES-256 key (32 bytes).
 * @param out_key_len Buffer size; must be ≥ 32.
 * @return            0 on success, non-zero on error.
 */
int DM_ReadKeyFromFlashHead(const char *mtd_blk,
                             uint32_t    flash_off,
                             int         decrypt,
                             uint32_t    extra_param,
                             uint8_t    *out_key,
                             uint32_t    out_key_len)
{
    uint8_t  flash_head[KEYFILE_HEAD_LEN];
    int      ret;

    memset(flash_head, 0, sizeof(flash_head));

    /* Read 96 bytes from flash */
    ret = HW_OS_FLASH_Read(mtd_blk, flash_off, flash_head, KEYFILE_HEAD_LEN);
    if (ret != 0) {
        DM_ERR(0x88, "FLASH_Read failed");
        return ret;
    }

    /* Optionally decrypt the head in-place */
    if (decrypt == 1) {
        ret = DM_DecryptEncryptHead(flash_head, 1);
        if (ret != 0) {
            memset(flash_head, 0, sizeof(flash_head));
            DM_ERR(0x95, "DecryptEncryptHead failed");
            return ret;
        }
    }

    /* Validate: first byte of head must be non-zero (DM_FlashHeadRead check) */
    if (flash_head[0] == 0) {
        memset(flash_head, 0, sizeof(flash_head));
        DM_ERR(0x95, "flash head is blank");
        return 1;
    }

    /* Extract 32-byte key material at offset +0x20 within the head,
     * using the preceding 0x20 bytes as salt. */
    ret = DM_GetKeyByMaterial(
            flash_head + KEYFILE_MATERIAL_OFFSET,    /* material */
            flash_head,                               /* salt (first 32 bytes) */
            KEYFILE_MATERIAL_OFFSET,                  /* salt_len = 0x20 */
            extra_param,
            out_key,
            out_key_len);

    /* Secure-wipe the flash head regardless of result */
    memset(flash_head, 0, sizeof(flash_head));

    if (ret != 0)
        DM_ERR(0x9e, "GetKeyByMaterial failed");

    return ret;
}
