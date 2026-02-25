/*
 * dm_key.h  –  Huawei DM key derivation API
 *
 * Reconstructed from libsmp_api.so + hw_module_efuse.ko + hw_module_sec.ko
 * Firmware: EG8145V5-V500R022C00SPC340B019 (ARM32, musl libc, Linux 5.10.0)
 */

#ifndef DM_KEY_H
#define DM_KEY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Key sizes ──────────────────────────────────────────────────────────── */
#define DM_AES256_KEY_LEN    32u   /* output of DM_GetKeyByMaterial */
#define DM_FLASH_HEAD_LEN    96u   /* 0x60: flash head struct in KeyFile MTD */

/* ── eFuse read ──────────────────────────────────────────────────────────── */
/**
 * DM_GetRootKeyOffset – resolve the flash offset of the key head.
 *
 * @param in_offset      Caller-specified offset within the 0x20000 region.
 * @param key_offset_out Flash byte offset of the key head (output).
 * @param blk_name_out   MTD block device name (output, e.g. "/dev/mtd5").
 * @param blk_name_len   Size of blk_name_out.
 * @param blk_size_out   Key region size (output, typically 16).
 * @return               0 on success.
 */
int DM_GetRootKeyOffset(uint32_t  in_offset,
                         uint32_t *key_offset_out,
                         char     *blk_name_out,
                         uint32_t  blk_name_len,
                         uint32_t *blk_size_out);

/* ── Hardware-accelerated decryption ────────────────────────────────────── */
/**
 * DM_LdspDecryptData – decrypt data via hardware IPSec AES engine.
 *
 * Dispatches to sec_hisi_crypto (hw_module_sec.ko) via the product
 * shared-function table at offset +0x80.  The hardware key is derived
 * from the device eFuse and is NEVER exposed in software.
 *
 * @param dst     Plaintext output buffer.
 * @param dst_len Size of dst (bytes, multiple of 16).
 * @param src     Ciphertext input buffer.
 * @param src_len Size of src.
 * @return        0 on success.
 */
int DM_LdspDecryptData(void *dst, uint32_t dst_len,
                        const void *src, uint32_t src_len);

/**
 * DM_DecryptEncryptHead – decrypt or encrypt the 96-byte flash head in-place.
 *
 * @param buf     96-byte buffer (in/out).
 * @param decrypt 1 = decrypt, 0 = encrypt.
 * @return        0 on success.
 */
int DM_DecryptEncryptHead(void *buf, int decrypt);

/* ── PBKDF2 key derivation ──────────────────────────────────────────────── */
/**
 * DM_GetKeyByMaterial – derive AES-256 key via PBKDF2-HMAC-SHA256.
 *
 * Derivation:
 *   1. DM_LdspDecryptData(material, 32) → plaintext key material
 *   2. PBKDF2-HMAC-SHA256(material, salt, 1 iter, 32 bytes) → AES-256 key
 *
 * @param material   32 bytes of raw (hardware-encrypted) key material.
 * @param salt       Salt for PBKDF2 (typically first 32 bytes of flash head).
 * @param salt_len   Length of salt.
 * @param extra      Extra parameter (passed to CAC_Pbkdf2Api, may be 0).
 * @param out_key    32-byte AES-256 key output.
 * @param out_len    Must be ≥ DM_AES256_KEY_LEN.
 * @return           0 on success.
 */
int DM_GetKeyByMaterial(const uint8_t *material,
                         const uint8_t *salt,     uint32_t salt_len,
                         uint32_t       extra,
                         uint8_t       *out_key,  uint32_t out_len);

/**
 * DM_ReadKeyFromFlashHead – full key reading pipeline.
 *
 * Reads the 96-byte key head from the "KeyFile" MTD flash partition,
 * optionally decrypts it (if flash head is hardware-encrypted),
 * and derives the 32-byte AES-256 working key.
 *
 * @param mtd_blk    MTD block name ("/dev/mtd5" etc.).
 * @param flash_off  Byte offset within that MTD block.
 * @param decrypt    1 = flash head is encrypted, 0 = plaintext.
 * @param extra      Extra parameter (may be 0).
 * @param out_key    32-byte AES-256 key (output).
 * @param out_len    Must be ≥ DM_AES256_KEY_LEN.
 * @return           0 on success.
 */
int DM_ReadKeyFromFlashHead(const char *mtd_blk,
                             uint32_t    flash_off,
                             int         decrypt,
                             uint32_t    extra,
                             uint8_t    *out_key,
                             uint32_t    out_len);

#ifdef __cplusplus
}
#endif

#endif /* DM_KEY_H */
