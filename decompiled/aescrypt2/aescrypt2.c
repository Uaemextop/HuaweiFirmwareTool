/*
 * aescrypt2.c — Reconstructed from EG8145V5 firmware /bin/aescrypt2
 *
 * Decompiled via Capstone ARM disassembly of the stripped PIE ELF.
 * The binary is a thin wrapper around OS_AescryptEncrypt /
 * OS_AescryptDecrypt (from libhw_ssp_basic.so) which in turn call
 * mbedTLS (loaded from libpolarssl.so at runtime).
 *
 * Original source filename (from .rodata): "hw_ssp_ctool.c"
 * Version string (from .rodata):           "version[v1.0]"
 *
 * Reconstructed calling convention (ARM EABI, musl libc):
 *   main(int argc, char **argv)
 *     → parse_args(argc, argv, &workMode)
 *       → check_argc(argc)
 *     → memset(inFile,  0, 128); strcpy_s(inFile,  128, argv[2])
 *     → memset(outFile, 0, 128); strcpy_s(outFile, 128, argv[3])
 *     → if (workMode == 0) OS_AescryptEncrypt(…)
 *       else               OS_AescryptDecrypt(…)
 *
 * Build:
 *   cmake -B build && cmake --build build
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"

/* ── Forward declarations (hw_ssp stubs) ─────────────────────────────────── */

/* Matches HW_OS_Printf from libhw_ssp_basic.so */
static void HW_OS_Printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/* Matches HW_PROC_DBG_LastWord(line, errcode, file, 0, 0, 0) */
static void HW_PROC_DBG_LastWord(int line, int err,
                                  const char *file,
                                  int a, int b, int c) {
    (void)a; (void)b; (void)c;
    if (err != 0) {
        fprintf(stderr, "[DBG] %s:%d  error=%d\n", file, line, err);
    }
}

/* Matches HW_OS_StrToUInt32 — parse string to uint32 */
static int HW_OS_StrToUInt32(const char *str, uint32_t *out) {
    char *end = NULL;
    unsigned long v = strtoul(str, &end, 10);
    if (end == str || *end != '\0')
        return -1;
    *out = (uint32_t)v;
    return 0;
}

/* ── Error handler (decompiled from 0x0b70) ──────────────────────────────── */

static void report_error(int line, int errcode) {
    HW_PROC_DBG_LastWord(line, errcode, "hw_ssp_ctool.c", 0, 0, 0);
}

/* ── Argument checker (decompiled from 0x0bb0) ───────────────────────────── */

static int check_argc(int argc) {
    /*
     * 0x0bb0: sub r0, r0, #4      ; argc -= 4
     * 0x0bb8: cmp r0, #2          ; if (argc-4) > 2  → print usage
     * 0x0bc4: bls 0xbdc           ; unsigned ≤ 2  → OK (argc in 4..6)
     */
    if ((unsigned)(argc - 4) > 2) {
        printf("  aescrypt2 <mode> <input filename> <output filename>\n");
        printf("  <mode>: 0 = encrypt, 1 = decrypt\n");
        printf("  example: aescrypt2 0 file file.aes\n");
        return -1;
    }
    return 0;
}

/* ── Argument parser (decompiled from 0x0be8) ────────────────────────────── */

static int parse_args(int argc, char **argv, uint32_t *workMode) {
    int ret = check_argc(argc);
    if (ret != 0)
        return ret;

    /* HW_OS_StrToUInt32(argv[1], &mode) */
    ret = HW_OS_StrToUInt32(argv[1], workMode);
    if (*workMode > 1) {
        printf("invalid operation workMode\n");
        return -1;
    }
    return 0;
}

/* ── main (decompiled from 0x0830) ───────────────────────────────────────── */

int main(int argc, char **argv) {
    char inFile[128];
    char outFile[128];
    uint32_t workMode = 0;
    int ret;

    ret = parse_args(argc, argv, &workMode);
    if (ret != 0)
        return ret;

    /* memset + strcpy_s for input filename (argv[2]) */
    memset(inFile, 0, sizeof(inFile));
    if (strlen(argv[2]) >= sizeof(inFile)) {
        report_error(0x49, 1);
        return -1;
    }
    strncpy(inFile, argv[2], sizeof(inFile) - 1);

    /* memset + strcpy_s for output filename (argv[3]) */
    memset(outFile, 0, sizeof(outFile));
    if (strlen(argv[3]) >= sizeof(outFile)) {
        report_error(0x4f, 1);
        return -1;
    }
    strncpy(outFile, argv[3], sizeof(outFile) - 1);

    /* Optional 5th argument: extra key material (argv[4])
     * argc > 4  → extraKey = argv[4]
     * argc > 5  → flag = 1  (indicates key-file mode)
     */
    const char *extraKey = NULL;
    int keyFileMode = 0;

    if (argc > 4)
        extraKey = argv[4];
    if (argc > 5)
        keyFileMode = 1;

    /* Dispatch to encrypt or decrypt */
    if (workMode == 0) {
        ret = aescrypt2_encrypt(inFile, outFile, extraKey, keyFileMode);
    } else {
        ret = aescrypt2_decrypt(inFile, outFile, extraKey, keyFileMode);
    }

    if (ret != 0) {
        report_error(0x5c, ret);
        fprintf(stderr, "Encrypt or decrypt %s failed!\n", inFile);
    }

    return ret;
}
