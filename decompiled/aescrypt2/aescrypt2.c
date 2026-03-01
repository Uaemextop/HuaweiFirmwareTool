/*
 * aescrypt2.c  –  Huawei aescrypt2 utility (reconstructed)
 *
 * Original binary: /bin/aescrypt2
 * Source filename embedded in .rodata: "hw_ssp_ctool.c"
 * Version string in .rodata:           "version[v1.0]"
 *
 * Firmware: EG8145V5-V500R022C00SPC340B019.bin
 * Architecture: ARM32 Cortex-A9, musl libc, PIE ELF
 * Disassembly via Capstone 5.x.
 *
 * .text layout (vaddr, size):
 *   0x0830  340   main()
 *   0x09a8   92   _start_c / CRT entry
 *   0x0a04        __do_global_dtors_aux
 *   0x0a48        frame_dummy
 *   0x0a98        __do_global_ctors_aux
 *   0x0bb0   56   check_argc()   [static helper]
 *   0x0be8  176   validate_args() [static helper]
 *
 * Imported symbols (from .dynstr / .rel.plt):
 *   PLT 0x7a0  strcpy_s            (glibc / Huawei safe-string lib)
 *   PLT 0x7ac  OS_AescryptDecrypt  (libhw_ssp_basic.so)
 *   PLT 0x7b8  __cxa_finalize
 *   PLT 0x7c4  __stack_chk_fail
 *   PLT 0x7d0  memset
 *   PLT 0x7dc  OS_AescryptEncrypt  (libhw_ssp_basic.so)
 *   PLT 0x800  __libc_start_main
 *   PLT 0x80c  HW_OS_StrToUInt32   (libhw_ssp_basic.so)
 *   PLT 0x818  HW_PROC_DBG_LastWord(libhw_ssp_basic.so)
 *   PLT 0x824  HW_OS_Printf        (libhw_ssp_basic.so)
 *
 * Files encrypted with aescrypt2 (items in HWNP firmware package):
 *   file:/mnt/jffs2/ttree_spec_smooth.tar.gz   (8712 bytes, AES-CBC encrypted)
 *
 * Files decrypted/loaded by aescrypt2-compatible code:
 *   file:/mnt/jffs2/app/preload_cplugin.tar.gz (2047991 bytes, plain gzip)
 *     → preload_cplugin/kernelapp.cpk           (tar.gz)
 *       → MyPlugin/bin/kernelapp                (ARM32 ELF, 13436 bytes)
 *       → MyPlugin/bin/cpluginapp_real          (ARM32 ELF,  9348 bytes)
 *       → MyPlugin/Lib/libsrv.so                (ARM32 ELF, 1590780 bytes)
 *       → MyPlugin/Lib/libbasic.so              (ARM32 ELF,  413524 bytes)
 *       → MyPlugin/Lib/libmbedall.so            (ARM32 ELF,  722452 bytes – mbedTLS)
 *       → MyPlugin/etc/config/kernelapp.config  (JSON config)
 *       → MyPlugin/etc/res/webs.tar.gz          (web resources)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>
#ifndef _WIN32
#  include <unistd.h>
#else
#  include <process.h>
#  define getpid _getpid
#endif
#include "hw_ssp_aescrypt.h"

/* Host build: safe-string stubs */
#if !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)
#  include "../stubs/hw_os_stubs.h"
#endif

/* ── Huawei OS helpers (provided by libhw_ssp_basic.so at runtime) ───────── */
extern int HW_OS_Printf(const char *fmt, ...);
extern void HW_PROC_DBG_LastWord(int line, const char *file,
                                  const char *msg, int a, int b, int c);
extern int HW_OS_StrToUInt32(const char *str, uint32_t *val_out);

/* ── Filename buffer size (0x80 = 128 in device firmware; extended to 512
 *    for host builds where paths can be longer than device paths) ────── */
#define FILENAME_BUF   512

/* ── Work-mode constants ────────────────────────────────────────────────── */
#define MODE_ENCRYPT     0u
#define MODE_DECRYPT     1u
#define MODE_REENCRYPT   2u
#define MODE_ENCRYPT_ALL 3u

/* Key labels for human-readable output */
static const char *key_labels[6] = {
    "V300R017",
    "V500R019C10SPC310",
    "V500R019C00SPC050",
    "V500R019C10SPC386",
    "V500R020C00SPC240",
    "V500R020C10SPC212",
};

/* ── Gzip helper: compress file → temp file, return temp path ────────────── */
static int gzip_file(const char *input_path, const char *output_path)
{
    FILE *fin = fopen(input_path, "rb");
    if (!fin) return -1;

    gzFile gz = gzopen(output_path, "wb9");
    if (!gz) { fclose(fin); return -1; }

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        if (gzwrite(gz, buf, (unsigned)n) <= 0) {
            fclose(fin); gzclose(gz); return -1;
        }
    }
    fclose(fin);
    gzclose(gz);
    return 0;
}

/* ── Gzip helper: decompress file → output path ─────────────────────────── */
static int gunzip_file(const char *input_path, const char *output_path)
{
    gzFile gz = gzopen(input_path, "rb");
    if (!gz) return -1;

    FILE *fout = fopen(output_path, "wb");
    if (!fout) { gzclose(gz); return -1; }

    unsigned char buf[8192];
    int n;
    int err = 0;
    while ((n = gzread(gz, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, (size_t)n, fout) != (size_t)n) {
            err = -1;
            break;
        }
    }
    if (n < 0) err = -1;
    fclose(fout);
    gzclose(gz);
    return err;
}

/* ── Check if file starts with gzip magic (1f 8b) ──────────────────────── */
static int is_gzip_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char hdr[2] = {0, 0};
    size_t got = fread(hdr, 1, 2, f);
    fclose(f);
    return (got == 2 && hdr[0] == 0x1f && hdr[1] == 0x8b);
}

/*
 * check_argc – validate the argument count.
 *
 * Disasm (0x0bb0 – 0x0be4, 56 bytes):
 *   bb0  sub  r0, r0, #4     ; argc -= 4  (need at least 4 args)
 *   bb4  mov  ip, sp
 *   bb8  cmp  r0, #2         ; (argc-4) <= 2 ?  i.e. argc in [4..6]
 *   bbc  push {fp, ip, lr, pc}
 *   bc0  sub  fp, ip, #4
 *   bc4  bls  bdc            ; valid range → return 0
 *   bc8  ldr  r0, [pc, #0x14] ; load "usage" string ptr (PC-rel)
 *   bcc  add  r0, pc, r0
 *   bd0  bl   0x824           ; HW_OS_Printf(usage_str)
 *   bd4  mvn  r0, #0          ; return -1
 *   bd8  ldm  sp, {fp, sp, pc}
 *   bdc  mov  r0, #0
 *   be0  ldm  sp, {fp, sp, pc}
 *   be4  (literal pool: offset to usage string)
 *
 * Usage string (from .rodata, 0x0cb4):
 *   "version[v1.0]\n"
 *   "  aescrypt2 <mode> <input filename> <output filename>\n\n"
 *   "  <mode>: 0 = encrypt, 1 = decrypt\n\n"
 *   "  example: aescrypt2 0 file file.aes\n\n"
 */
static int check_argc(int argc)
{
    /* argc must be 4, 5 or 6 */
    if ((unsigned)(argc - 4) > 2u) {
        HW_OS_Printf("version[v2.0] – Huawei hw_ctree.xml encrypt/decrypt tool\n"
                     "  aescrypt2 <mode> <input.xml> <output.xml>\n\n"
                     "  <mode>:\n"
                     "    0 = encrypt (XML→gzip→AES)\n"
                     "    1 = decrypt (AES→gunzip→XML)\n"
                     "    2 = re-encrypt (decrypt with auto-key, re-encrypt with AESCRYPT2_KEY_INDEX)\n"
                     "    3 = encrypt-all (XML→gzip→AES with all 6 keys, output: <output>_key0..5.xml)\n\n"
                     "  example: aescrypt2 0 config.xml hw_ctree.xml\n"
                     "  example: aescrypt2 1 hw_ctree.xml decrypted.xml\n"
                     "  example: AESCRYPT2_KEY_INDEX=3 aescrypt2 2 old.bin new.bin\n"
                     "  example: aescrypt2 3 config.xml output\n\n"
                     "  env AESCRYPT2_KEY_INDEX=0..5 selects firmware key:\n"
                     "    0=V300R017  1=V500R019C10  2=V500R019C00\n"
                     "    3=V500R019C10SPC386  4=V500R020C00  5=V500R020C10\n\n");
        return -1;
    }
    return 0;
}

/*
 * validate_args – parse argv[1] as the work mode (0 or 1).
 *
 * Disasm (0x0be8 – 0x0c88, 160 bytes):
 *   be8  push {r4,r5,r6,fp,ip,lr,pc}
 *   bf4  mov  r5, r2         ; r5 = work_mode_out  (output pointer)
 *   bf8  (GOT setup for stack-canary)
 *   c08  mov  r6, r1         ; r6 = argv
 *   c1c  bl   0xbb0          ; check_argc(argc)
 *   c20  subs r4, r0, #0
 *   c24  bne  c78            ; fail
 *   c28  sub  r1, fp, #0x24  ; &local_uint (destination for parsed value)
 *   c2c  ldr  r0, [r6, #4]   ; argv[1]  (char *mode_str)
 *   c30  bl   0x80c           ; HW_OS_StrToUInt32(argv[1], &local_uint)
 *   c34  ldr  r3, [fp, #-0x24]  ; local_uint
 *   c38  cmp  r3, #1          ; mode <= 1 ?
 *   c3c  strls r3, [r5]       ; *work_mode_out = mode  (if valid)
 *   c40  bls  c78             ; return 0
 *   c44  ldr  r0, [pc, #0x44] ; "invalide operation workMode\n"
 *   c48  add  r0, pc, r0
 *   c4c  bl   0x824            ; HW_OS_Printf(...)
 *   c50  mvn  r0, #0           ; return -1
 *   c54  (stack-canary check) …
 *   c78  mov  r0, r4
 *   c7c  b    c54
 *   c80  ldm  sp, {..., pc}
 */
static int validate_args(int argc, char **argv, uint32_t *work_mode_out)
{
    uint32_t mode = 0;

    if (check_argc(argc) != 0)
        return -1;

    HW_OS_StrToUInt32(argv[1], &mode);

    if (mode <= MODE_ENCRYPT_ALL) {
        *work_mode_out = mode;
        return 0;
    }

    HW_OS_Printf("invalide operation workMode\n");
    return -1;
}

/*
 * main – entry point of aescrypt2.
 *
 * Disasm (0x0830 – 0x0970, 320 bytes):
 *
 *   830  (GOT / stack-canary prologue)
 *   868  bl   0xbe8    ; validate_args(argc, argv, &work_mode)
 *   86c  cmp  r0, #0
 *   870  bne  940      ; validate failed → return -1
 *   874  sub  r5, fp, #0x120   ; char infile[0x80]
 *   884  bl   memset(r5, 0, 0x80)
 *   894  bl   strcpy_s(r5, 0x80, argv[2])   ; copy input path
 *   898  subs r1, r0, #0
 *   89c  beq  8a8
 *   8a0  mov  r0, #0x49  ; line 73
 *   8a4  bl   0xb70      ; HW_PROC_DBG_LastWord(73, …)
 *   8a8  sub  r6, fp, #0xa0    ; char outfile[0x80]
 *   8b8  bl   memset(r6, 0, 0x80)
 *   8c8  bl   strcpy_s(r6, 0x80, argv[3])   ; copy output path
 *   8cc  subs r1, r0, #0
 *   8d0  beq  8dc
 *   8d4  mov  r0, #0x4f  ; line 79
 *   8d8  bl   0xb70      ; HW_PROC_DBG_LastWord(79, …)
 *   8dc  cmp  r4, #4     ; r4 = argc
 *   8ec  ldrgt r3, [r7, #0x10]  ; argv[4] if argc > 4, else NULL
 *   8f0  movle r3, #0
 *   8f4  cmp  r4, #5
 *   8f8  movle r4, #0    ; has_arg5 = (argc > 5) ? 1 : 0
 *   8fc  movgt r4, #1
 *   900  cmp  r2, #0     ; r2 = work_mode
 *   904  str  r4, [sp]   ; push has_arg5
 *   908  mov  r2, r6     ; outfile
 *   90c  bne  964        ; mode != 0 → decrypt
 *   910  bl   0x7dc      ; OS_AescryptEncrypt(1, infile, outfile, arg4, has_arg5)
 *   914  cmp  r0, #0
 *   918  mov  r4, r0     ; save return code
 *   91c  beq  93c
 *   920  mov  r1, r0     ; error code
 *   924  mov  r0, #0x5c  ; line 92
 *   928  bl   0xb70      ; HW_PROC_DBG_LastWord(92, …)
 *   92c  (load "Encrypt or decrypt %s failed!\r\n" string)
 *   938  bl   0x824      ; HW_OS_Printf("Encrypt or decrypt %s failed!\r\n", infile)
 *   93c  mov  r0, r4
 *   940  (stack-canary check)
 *   96c  ldm  sp, {..., pc}
 *   964  bl   0x7ac      ; OS_AescryptDecrypt(1, infile, outfile, arg4, has_arg5)
 *   968  b    914
 */
/* ── Encrypt a single file with a specific key index ─────────────────────── */
static int encrypt_with_key(const char *infile, const char *outfile, int key_idx)
{
    extern void HW_KMC_SetKeyIndex(int);
    char gz_tmp[FILENAME_BUF + 32];
    int ret;

    HW_KMC_SetKeyIndex(key_idx);

    snprintf(gz_tmp, sizeof(gz_tmp), "%s.%d.gz.tmp", infile, (int)getpid());

    if (gzip_file(infile, gz_tmp) != 0) {
        HW_OS_Printf("gzip compression of %s failed!\r\n", infile);
        return 1;
    }

    ret = HW_OS_AESCBCEncrypt(1, gz_tmp, outfile, NULL, 0);
    remove(gz_tmp);
    return ret;
}

int main(int argc, char **argv)
{
    char     infile[FILENAME_BUF];
    char     outfile[FILENAME_BUF];
    uint32_t work_mode = 0;
    const char *arg4   = NULL;
    int      has_arg5  = 0;
    int      ret;

    /* Validate argc and parse mode from argv[1] */
    if (validate_args(argc, argv, &work_mode) != 0)
        return -1;

    /* Copy argv[2] → infile (safe, bounded) */
    memset(infile, 0, sizeof(infile));
    if (strcpy_s(infile, sizeof(infile), argv[2]) != 0)
        HW_PROC_DBG_LastWord(0x49, "hw_ssp_ctool.c", NULL, 0, 0, 0);

    /* Copy argv[3] → outfile */
    memset(outfile, 0, sizeof(outfile));
    if (strcpy_s(outfile, sizeof(outfile), argv[3]) != 0)
        HW_PROC_DBG_LastWord(0x4f, "hw_ssp_ctool.c", NULL, 0, 0, 0);

    /* Optional argv[4] and argv[5] */
    if (argc > 4)
        arg4 = argv[4];
    has_arg5 = (argc > 5) ? 1 : 0;

    /* Dispatch to encrypt or decrypt */
    if (work_mode == MODE_ENCRYPT) {
        /* Mode 0: XML → gzip → AES-CBC → outfile */
        const char *env = getenv("AESCRYPT2_KEY_INDEX");
        int ki = (env && *env >= '0' && *env <= '5') ? (*env - '0') : 0;

        HW_OS_Printf("Compressing %s → gzip...\n", infile);
        ret = encrypt_with_key(infile, outfile, ki);
        if (ret == 0)
            HW_OS_Printf("Encrypted %s → %s (key %d: %s)\n",
                         infile, outfile, ki, key_labels[ki]);

    } else if (work_mode == MODE_DECRYPT) {
        /* Mode 1: AES-CBC → gunzip → XML outfile */
        char raw_tmp[FILENAME_BUF + 32];
        snprintf(raw_tmp, sizeof(raw_tmp), "%s.%d.raw.tmp", outfile, (int)getpid());

        ret = HW_OS_AESCBCDecrypt(1, infile, raw_tmp, arg4, has_arg5);

        if (ret == 0 && is_gzip_file(raw_tmp)) {
            HW_OS_Printf("Decompressing gzip → XML...\n");
            if (gunzip_file(raw_tmp, outfile) != 0) {
                HW_OS_Printf("gunzip failed, raw output in %s\n", raw_tmp);
                ret = 1;
            }
            remove(raw_tmp);
        } else if (ret == 0) {
            /* Not gzip — just rename raw output */
            rename(raw_tmp, outfile);
        } else {
            remove(raw_tmp);
        }

        if (ret == 0)
            HW_OS_Printf("Decrypted %s → %s (AES→gunzip→XML)\n", infile, outfile);

    } else if (work_mode == MODE_REENCRYPT) {
        /* Mode 2: decrypt input (auto-detect key), re-encrypt with target key */
        const char *env = getenv("AESCRYPT2_KEY_INDEX");
        int target_ki = (env && *env >= '0' && *env <= '5') ? (*env - '0') : 0;
        char dec_tmp[FILENAME_BUF + 32];
        char raw_tmp[FILENAME_BUF + 32];

        snprintf(dec_tmp, sizeof(dec_tmp), "%s.%d.dec.tmp", outfile, (int)getpid());
        snprintf(raw_tmp, sizeof(raw_tmp), "%s.%d.raw.tmp", outfile, (int)getpid());

        /* Step 1: Decrypt with auto-detected key */
        ret = HW_OS_AESCBCDecrypt(1, infile, raw_tmp, NULL, 0);
        if (ret != 0) {
            HW_OS_Printf("Re-encrypt: decryption failed\n");
            remove(raw_tmp);
            goto reencrypt_fail;
        }

        /* Step 2: Decompress if gzipped */
        if (is_gzip_file(raw_tmp)) {
            if (gunzip_file(raw_tmp, dec_tmp) != 0) {
                HW_OS_Printf("Re-encrypt: gunzip failed\n");
                remove(raw_tmp);
                ret = 1;
                goto reencrypt_fail;
            }
            remove(raw_tmp);
        } else {
            rename(raw_tmp, dec_tmp);
        }

        /* Step 3: Re-encrypt with target key */
        HW_OS_Printf("Re-encrypting with key %d (%s)...\n",
                     target_ki, key_labels[target_ki]);
        ret = encrypt_with_key(dec_tmp, outfile, target_ki);
        remove(dec_tmp);

        if (ret == 0)
            HW_OS_Printf("Re-encrypted %s → %s (key %d: %s)\n",
                         infile, outfile, target_ki, key_labels[target_ki]);

    } else if (work_mode == MODE_ENCRYPT_ALL) {
        /* Mode 3: encrypt XML with all 6 keys → output_key0..5.xml */
        int success_count = 0;

        HW_OS_Printf("Encrypting %s with all 6 firmware keys...\n\n", infile);

        for (int ki = 0; ki < 6; ki++) {
            char out_path[FILENAME_BUF + 32];
            snprintf(out_path, sizeof(out_path), "%s_key%d.xml", outfile, ki);

            HW_OS_Printf("[Key %d] %s → %s\n", ki, key_labels[ki], out_path);
            ret = encrypt_with_key(infile, out_path, ki);

            if (ret == 0) {
                HW_OS_Printf("[Key %d] ✓ OK\n", ki);
                success_count++;
            } else {
                HW_OS_Printf("[Key %d] ✗ FAILED\n", ki);
            }
        }

        HW_OS_Printf("\nDone: %d/6 encrypted files generated.\n", success_count);
        ret = (success_count == 6) ? 0 : 1;
    }

    if (ret != 0) {
        HW_PROC_DBG_LastWord(0x5c, "hw_ssp_ctool.c", NULL, ret, 0, 0);
        HW_OS_Printf("Encrypt or decrypt %s failed!\r\n", infile);
    }

    return ret;

reencrypt_fail:
    HW_PROC_DBG_LastWord(0x5c, "hw_ssp_ctool.c", NULL, ret, 0, 0);
    HW_OS_Printf("Encrypt or decrypt %s failed!\r\n", infile);
    return ret;
}
