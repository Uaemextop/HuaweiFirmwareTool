/*
 * hal_efuse.h  –  HiSilicon SD511x eFuse HAL API
 *
 * Reconstructed from hw_module_efuse.ko (Linux 5.10.0 ARM kernel module)
 * Source file in module: hal_efuse_ker_drv.c
 * Exports:
 *   hal_efuse_get_data              (used by DM_LdspDecryptData chain)
 *   hal_efuse_read_sram_efuse_data  (reads eFuse SRAM mirror)
 *   hal_efuse_register_chip_hook    (chip-specific callback registration)
 *
 * eFuse Physical Layout (HiSilicon SD511x / Hi3xxx EG8145V5):
 *   The eFuse controller is memory-mapped.  The bootloader copies the OTP
 *   bits into a SRAM shadow at boot; the kernel driver reads from that shadow.
 *
 *   Physical base address discovered via ioremap() in efuse_init():
 *     Typically 0x12010000 or 0x10F00000 depending on chip sub-variant.
 *     hw_chip_id is read to select the correct base.
 *
 *   Key region offsets (based on DM_GetRootKeyOffset disassembly):
 *     The MTD "KeyFile" partition is looked up via HW_SWM_GetMtdBlkNameAndOffset.
 *     Root key lives at: MTD_offset + 0x20000 - input_offset
 *     eFuse data buffer size: 0x40 bytes (64 bytes = 512 bits)
 *
 *   Key material (32 bytes / 256 bits) feeds PBKDF2-SHA256 to produce
 *   the AES-256-CBC encryption key used by OS_AescryptEncrypt/Decrypt.
 *
 * Kernel module dependencies:
 *   ksecurec  –  Huawei secure-c library (kernel version of huawei_libc_sec)
 *
 * hw_module_sec.ko exports used in key derivation:
 *   sec_hisi_crypto           –  hardware AES-CBC via HiSilicon IPSec engine
 *   hw_adpt_sec_getrandom     –  hardware TRNG (hi_sysctl_secure_trng_read)
 *   hi_ipsec_crypto_encrypt   –  raw IPSec block cipher
 *   hi_ipsec_crypto_decrypt   –  raw IPSec block cipher
 *
 * Key derivation chain (full):
 *   [eFuse OTP] → hal_efuse_read_sram_efuse_data
 *       → DM_LdspDecryptData  (dispatch via ProductShareFunc+0x80 → sec_hisi_crypto)
 *       → 32 bytes of key material
 *       → CAC_Pbkdf2Api (PBKDF2-HMAC-SHA256, 32-byte output, salt from flash head)
 *       → AES-256 key
 *       → OS_AescryptEncrypt / OS_AescryptDecrypt
 */

#ifndef HAL_EFUSE_H
#define HAL_EFUSE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── eFuse buffer sizes ─────────────────────────────────────────────────── */
#define EFUSE_KEY_BUF_LEN      64u   /* 512-bit eFuse key region */
#define EFUSE_ROOT_KEY_LEN     32u   /* 256-bit root key extracted from eFuse */
#define EFUSE_SRAM_SIZE        0x40u /* SRAM shadow size */

/* ── Chip hook callback (registered by chip-specific init) ─────────────── */
typedef int (*efuse_read_fn_t)(uint8_t *buf, uint32_t len);

/**
 * hal_efuse_register_chip_hook – register chip-specific eFuse read callback.
 *
 * Called during efuse_init() to register the chip-variant read function.
 * The hook reads raw eFuse bits from the memory-mapped OTP controller.
 *
 * @param hook  Function pointer to chip-specific eFuse reader.
 * @return      0 on success.
 */
int hal_efuse_register_chip_hook(efuse_read_fn_t hook);

/**
 * hal_efuse_read_sram_efuse_data – read eFuse data from the SRAM shadow.
 *
 * The bootloader copies eFuse bits into a SRAM region at startup.
 * This function reads len bytes from that shadow into buf.
 *
 * Source: hal_efuse_ker_drv.c, symbol at .symtab offset 0x55
 * Size: 116 bytes (ARM32)
 *
 * @param buf  Destination buffer (at least len bytes).
 * @param len  Number of bytes to read (max EFUSE_SRAM_SIZE).
 * @return     0 on success, -1 on error.
 */
int hal_efuse_read_sram_efuse_data(uint8_t *buf, uint32_t len);

/**
 * hal_efuse_get_data – exported kernel symbol, thin wrapper around
 *                      hal_efuse_read_sram_efuse_data.
 *
 * Exported via __ksymtab so that other kernel modules (e.g. hw_module_sec.ko)
 * can call it without a direct dependency.
 *
 * @param buf  Destination buffer.
 * @param len  Number of bytes to read.
 * @return     0 on success.
 */
int hal_efuse_get_data(uint8_t *buf, uint32_t len);

/* ── Methods for off-device eFuse emulation ─────────────────────────────── */
/* (host-build stubs; the device reads hardware OTP registers)              */

/**
 * efuse_init – module init: ioremap eFuse base, register chip hook.
 *
 * Selects the physical eFuse base address based on hw_chip_id,
 * calls ioremap() to map the region, calls hal_efuse_register_chip_hook().
 *
 * Known physical bases (HiSilicon SD511x family):
 *   0x12010000  –  SD5116 / SD511x (EG8145V5)
 *   0x10F00000  –  Hi3798 (older ONT platform)
 */
int efuse_init(void);

/**
 * efuse_exit – module cleanup: iounmap + deregister hook.
 */
void efuse_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* HAL_EFUSE_H */
