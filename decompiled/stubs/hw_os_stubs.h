/*
 * hw_os_stubs.h  –  Host-build stubs for Huawei OS and safe-string helpers.
 *
 * Declares ALL HW_* functions imported by the aescrypt2 family of binaries
 * across 4 unique ARM binary variants from 11 Huawei firmware versions.
 */
#ifndef HW_OS_STUBS_H
#define HW_OS_STUBS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Common imports (all aescrypt2 versions, 27 functions) ───────────────── */

/* OS helpers */
int    HW_OS_Printf(const char *fmt, ...);
int    HW_OS_Fprintf(FILE *fp, const char *fmt, ...);
void   HW_PROC_DBG_LastWord(int line, const char *file,
                             const char *msg, int a, int b, int c);
int    HW_OS_StrToUInt32(const char *str, uint32_t *val_out);

/* File I/O */
FILE  *HW_OS_Fopen(const char *path, const char *mode);
void   HW_OS_Fclose(FILE *fp);
size_t HW_OS_Fread(void *buf, size_t size, size_t count, FILE *fp);
size_t HW_OS_Fwrite(const void *buf, size_t size, size_t count, FILE *fp);
int    HW_OS_Fseek(FILE *fp, long offset, int whence);
int    HW_OS_GetFileSize(const char *path, uint32_t *size_out);
int    HW_OS_GetLastErr(void);
int    HW_OS_Open(const char *path, int flags);
int    HW_OS_Close(int fd);
int    HW_OS_Read(int fd, void *buf, size_t len);
int    HW_OS_Remove(const char *path);

/* String / memory */
int    HW_OS_MemCmp(const void *a, const void *b, size_t n);
int    HW_OS_StrNCmp(const char *s1, const char *s2, size_t n);
size_t HW_OS_StrNLen(const char *s, size_t maxlen);

/* SSL / crypto wrappers (thin shims around mbedTLS) */
int    HW_SSL_AesCryptEcb(const uint8_t *key, uint32_t key_bits,
                           int mode, const uint8_t *input);
int    HW_SSL_AesSetKeyEnc(void *ctx, const uint8_t *key, uint32_t keybits);
int    HW_SSL_AesSetKeyDec(void *ctx, const uint8_t *key, uint32_t keybits);
int    HW_SSL_Sha2Start(void *ctx, int is224);
int    HW_SSL_Sha2Update(void *ctx, const uint8_t *input, size_t ilen);
int    HW_SSL_Sha2Finish(void *ctx, uint8_t *output);
int    HW_SSL_Sha2HmacStart(void *ctx, const uint8_t *key,
                              size_t keylen, int is224);
int    HW_SSL_Sha2HmacUpdate(void *ctx, const uint8_t *input, size_t ilen);
int    HW_SSL_Sha2HmacFinish(void *ctx, uint8_t *output);

/* ── Version-specific imports (V500R019+, 12 functions) ──────────────────── */

int    HW_KMC_CfgGetKey(const char *path, void *key_buf, size_t key_len);
int    HW_OS_AESCBCCalPSWLen(uint32_t len);
int    HW_OS_AESCBCEncrypt(int unused, const char *infile,
                            const char *outfile, const char *arg4,
                            int has_arg5);
int    HW_OS_AESCBCDecrypt(int unused, const char *infile,
                            const char *outfile, const char *arg4,
                            int has_arg5);
int    HW_OS_MemCpy_S(void *dst, size_t dstsz, const void *src, size_t n);
int    HW_OS_MemSet_S(void *s, size_t smax, int c, size_t n);
int    HW_OS_StrCmp(const char *s1, const char *s2);
size_t HW_OS_StrLen(const char *s);
int    HW_OS_StrNCpy_S(char *dst, size_t dstsz, const char *src, size_t count);
int    HW_OS_Rename(const char *oldpath, const char *newpath);
int    HW_OS_ReadFile(const char *path, void *buf, size_t len);
int    HW_OS_CopyFile(const char *src, const char *dst);

/* ── Additional helpers used by cfgtool and other tools ──────────────────── */

void  *HW_OS_MemMallocSet(size_t size);
void   HW_OS_MemFreeD(void *ptr);
int    HW_OS_Access(const char *path, int mode);
char  *HW_OS_Fgets(char *buf, int len, FILE *fp);
char  *HW_OS_StrtokR(char *str, const char *delim, char **saveptr);
char  *HW_OS_StrStr(const char *hay, const char *needle);
int    HW_OS_StrCaseCmp(const char *s1, const char *s2);
int    HW_OS_CmdFormat(char *buf, size_t len, const char *fmt, ...);
int    SSP_ExecShellCmd(const char *cmd);
void   HW_CFGTOOL_SysTrace(const char *file, int line, const char *fmt, ...);

/* Key management helpers (device stubs) */
int    MemGetRootKeyCfg(void *buf);
void  *MemGetMkInfoByContent(void);
void   MSG_GetShmData(void *dst, int zero, size_t len);

/* Safe-string stubs (C11 Annex K) */
#if !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)
int strcpy_s(char *dst, size_t dst_sz, const char *src);
int strncpy_s(char *dst, size_t dst_sz, const char *src, size_t count);
int memset_s(void *s, size_t smax, int c, size_t n);
int memcpy_s(void *dst, size_t dstsz, const void *src, size_t n);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HW_OS_STUBS_H */
