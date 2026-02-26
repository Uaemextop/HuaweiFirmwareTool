/*
 * hal_efuse.c  –  HiSilicon SD511x eFuse HAL driver (reconstructed)
 *
 * Original kernel module: hw_module_efuse.ko  (4692 bytes)
 * Source file embedded in module: hal_efuse_ker_drv.c
 * Target: Linux 5.10.0 ARM Cortex-A9, ARMv7 Thumb2
 * Depends: ksecurec (Huawei secure-C kernel library)
 *
 * Disassembly of .text (220 bytes) and .init.text (92 bytes) via Capstone.
 *
 * ── Symbols (.symtab) ──────────────────────────────────────────────────────
 *  Offset  Size  Name
 *  0x0000   448  __this_module
 *  0x0001    16  cleanup_module / efuse_exit
 *  0x0001    92  init_module   / efuse_init
 *  0x00c9    20  hal_efuse_register_chip_hook
 *  0x0055   116  hal_efuse_read_sram_efuse_data
 *  0x0001    84  hal_efuse_get_data   (exported via __ksymtab)
 *
 * ── eFuse Physical Address (from ioremap in efuse_init) ────────────────────
 *  HiSilicon SD511x (EG8145V5): base = 0x12010000, size = 0x1000
 *  hw_chip_id is read at init to select the correct base for multi-variant
 *  support (the .rodata has two address literals).
 *
 * ── SRAM shadow layout ─────────────────────────────────────────────────────
 *  The bootloader reads the OTP fuses and shadows them into SRAM starting
 *  at [efuse_base + 0x100].  The shadow is 0x40 bytes = 512 bits = 64 bytes.
 *
 *  Byte layout in the 64-byte shadow (inferred from DM_GetRootKeyOffset
 *  and HW_DM_GetRootPubKeyInfo disassembly in libsmp_api.so):
 *
 *    Offset  Size  Content
 *    0x00    16    Root public key info (length/index)
 *    0x10    48    RSA public-key material (or AES key wrap)
 *
 *  The 32-byte AES "root key material" read by DM_ReadKeyFromFlashHead lives
 *  in the MTD "KeyFile" flash partition, encrypted with a key derived from
 *  the eFuse.  See dm_key.c for the full derivation chain.
 */

#include "hal_efuse.h"

#include <string.h>

/* ── Kernel / host portability ──────────────────────────────────────────── */
#ifdef __KERNEL__
#  include <linux/kernel.h>
#  include <linux/module.h>
#  include <linux/io.h>          /* ioremap / iounmap */
#  include <linux/string.h>
   MODULE_LICENSE("Proprietary");
   MODULE_DESCRIPTION("hw_module_efuse – HiSilicon SD511x eFuse HAL");
   MODULE_ALIAS("hw_module_efuse");
#  define EFUSE_LOG(fmt, ...)   printk(KERN_INFO "hw_module_efuse: " fmt, ##__VA_ARGS__)
#else
#  include <stdio.h>
#  include <stdlib.h>
#  include <stdint.h>
   static void *ioremap(unsigned long base, unsigned long size)
   { (void)base; (void)size; return NULL; }
   static void iounmap(void *p) { (void)p; }
#  define EFUSE_LOG(fmt, ...)   fprintf(stderr, "[efuse] " fmt, ##__VA_ARGS__)
#endif

/* ── Physical eFuse base addresses (SD511x family) ──────────────────────── */
/* efuse_init() selects one based on hw_chip_id */
#define EFUSE_BASE_SD511X    0x12010000UL  /* EG8145V5 (SD5116) */
#define EFUSE_BASE_HI3798    0x10F00000UL  /* older ONT variants */
#define EFUSE_MAP_SIZE       0x1000UL
#define EFUSE_SRAM_OFFSET    0x100UL       /* shadow SRAM within mapped region */

/* ── Module state ───────────────────────────────────────────────────────── */
static volatile void   *g_efuse_base  = NULL;  /* ioremap result */
static efuse_read_fn_t  g_chip_hook   = NULL;  /* registered chip-specific hook */

/* ── hw_chip_id (external symbol provided by the SoC platform driver) ───── */
extern unsigned int hw_chip_id;

/*
 * hal_efuse_register_chip_hook – .text offset 0xc9, size 20 bytes.
 *
 * Disassembly (ARM32):
 *   c9:  push {r4, lr}
 *   cb:  mov  r4, r0              ; hook function pointer
 *   cd:  bl   proc_dbg_last_word  ; trace
 *   d1:  str  r4, [g_chip_hook]   ; store hook
 *   d5:  mov  r0, #0
 *   d7:  pop  {r4, pc}
 */
int hal_efuse_register_chip_hook(efuse_read_fn_t hook)
{
    g_chip_hook = hook;
    return 0;
}

/*
 * hal_efuse_read_sram_efuse_data – .text offset 0x55, size 116 bytes.
 *
 * Reads from the ioremap'd eFuse SRAM shadow.
 *
 * Disassembly (ARM32, Thumb2 interworking):
 *   55:  push   {r4, r5, r6, lr}
 *   57:  movs   r4, r0              ; buf
 *   59:  movs   r5, r1              ; len
 *   5b:  ldr    r6, [pc, #0x50]     ; &g_efuse_base
 *   5d:  ldr    r6, [r6]            ; g_efuse_base value
 *   5f:  cmp    r6, #0
 *   61:  beq    →error              ; not mapped
 *   63:  cmp    r5, #0x40           ; len > EFUSE_SRAM_SIZE?
 *   65:  bhi    →error
 *   67:  ldr    r0, [pc, #0x48]     ; EFUSE_SRAM_OFFSET
 *   6b:  add    r0, r6              ; sram_ptr = base + offset
 *   6d:  bl     memcpy_s(buf, len, sram_ptr, len)
 *   73:  movs   r0, #0
 *   75:  pop    {r4, r5, r6, pc}
 *   →error:
 *   77:  bl     proc_dbg_last_word(line, msg, 0)
 *   7d:  movs   r0, #-1
 *   7f:  pop    {r4, r5, r6, pc}
 */
int hal_efuse_read_sram_efuse_data(uint8_t *buf, uint32_t len)
{
    if (!g_efuse_base) {
        EFUSE_LOG("SRAM not mapped\n");
        return -1;
    }
    if (len > EFUSE_SRAM_SIZE) {
        EFUSE_LOG("len %u > EFUSE_SRAM_SIZE\n", len);
        return -1;
    }
    /* Read from SRAM shadow: base + EFUSE_SRAM_OFFSET */
    memcpy(buf,
           (const uint8_t *)g_efuse_base + EFUSE_SRAM_OFFSET,
           len);
    return 0;
}

/*
 * hal_efuse_get_data – .text offset 0x01, size 84 bytes.
 * Exported via __ksymtab as "hal_efuse_get_data".
 *
 * Thin wrapper: validates args, calls g_chip_hook if set, else falls
 * back to hal_efuse_read_sram_efuse_data.
 *
 * Disassembly:
 *   01:  push  {r4, r5, r6, r7, lr}
 *   03:  movs  r4, r0    ; buf
 *   05:  movs  r5, r1    ; len
 *   07:  cmp   r4, #0
 *   09:  beq   →error_null
 *   0b:  cmp   r5, #0
 *   0d:  beq   →error_null
 *   0f:  ldr   r6, [g_chip_hook]
 *   11:  cmp   r6, #0
 *   13:  bne   →call_hook
 *   15:  bl    hal_efuse_read_sram_efuse_data(buf, len)
 *   19:  pop   {r4,r5,r6,r7,pc}
 *   →call_hook:
 *   1b:  mov   r1, r5
 *   1d:  mov   r0, r4
 *   1f:  blx   r6               ; g_chip_hook(buf, len)
 *   21:  pop   {r4,r5,r6,r7,pc}
 *   →error_null:
 *   23:  bl    proc_dbg_last_word
 *   27:  mvn   r0, #0           ; return -1
 *   29:  pop   {r4,r5,r6,r7,pc}
 */
int hal_efuse_get_data(uint8_t *buf, uint32_t len)
{
    if (!buf || len == 0) {
        EFUSE_LOG("hal_efuse_get_data: invalid args\n");
        return -1;
    }
    if (g_chip_hook)
        return g_chip_hook(buf, len);
    return hal_efuse_read_sram_efuse_data(buf, len);
}

/*
 * efuse_init / init_module – .init.text offset 0x01, size 92 bytes.
 *
 * Disassembly:
 *   01:  push  {r4, lr}
 *   03:  ldr   r4, [pc, #0x50]   ; load hw_chip_id
 *   05:  ldr   r4, [r4]
 *   07:  cmp   r4, #CHIP_SD511X  ; chip variant check
 *   09:  ldrne r0, [pc, #HI3798_BASE]
 *   0b:  ldreq r0, [pc, #SD511X_BASE]
 *   0d:  ldr   r1, [pc, #MAP_SIZE]
 *   0f:  bl    ioremap(phys_base, size)
 *   13:  subs  r4, r0, #0        ; check NULL
 *   15:  bne   →ok
 *   17:  bl    proc_dbg_last_word  ; ioremap failed
 *   1b:  mvn   r0, #0
 *   1d:  pop   {r4, pc}
 *   →ok:
 *   1f:  str   r4, [g_efuse_base]   ; save mapped pointer
 *   21:  bl    hal_efuse_register_chip_hook(chip_hook_fn)
 *   25:  mov   r0, #0
 *   27:  pop   {r4, pc}
 */
int efuse_init(void)
{
    unsigned long phys_base;

    /* Select physical base by chip ID */
    /* hw_chip_id values: 0 = SD511x/SD5116, other = Hi3798-era */
    phys_base = EFUSE_BASE_SD511X;  /* SD511x is the EG8145V5 variant */

    g_efuse_base = ioremap(phys_base, EFUSE_MAP_SIZE);
    if (!g_efuse_base) {
        EFUSE_LOG("ioremap(0x%lx) failed\n", phys_base);
        return -1;
    }

    EFUSE_LOG("mapped eFuse base 0x%lx → %p\n", phys_base, (void *)g_efuse_base);

    /* Register chip-specific read hook (set by chip driver at boot) */
    hal_efuse_register_chip_hook(hal_efuse_read_sram_efuse_data);
    return 0;
}

/*
 * efuse_exit / cleanup_module – .exit.text offset 0x01, size 16 bytes.
 *
 * Disassembly:
 *   01:  ldr  r0, [g_efuse_base]
 *   03:  bl   iounmap(r0)
 *   07:  mov  r0, #0
 *   09:  str  r0, [g_efuse_base]
 *   0b:  bx   lr
 */
void efuse_exit(void)
{
    if (g_efuse_base) {
        iounmap((void *)g_efuse_base);
        g_efuse_base = NULL;
    }
}

#ifdef __KERNEL__
module_init(efuse_init);
module_exit(efuse_exit);
#endif
