/*
 * hw_os_stubs.c  –  Host-build stubs for Huawei OS helpers
 *
 * On the target device these symbols are provided by libhw_ssp_basic.so.
 * For host builds (analysis / unit-testing) this file provides minimal
 * compatible implementations so the code links without the Huawei runtime.
 *
 * Do NOT ship this file to the device.
 */

#include "hw_os_stubs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

#ifndef _WIN32
#  include <unistd.h>
#  include <fcntl.h>
#  include <strings.h>
#  include <sys/stat.h>
#else
#  include <io.h>
#  include <sys/stat.h>
#  define access _access
#  define open   _open
#  define close  _close
#  define read   _read
#  define strcasecmp _stricmp
#endif

/* ======================================================================== */
/* Common imports (all aescrypt2 versions)                                   */
/* ======================================================================== */

int HW_OS_Printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

int HW_OS_Fprintf(FILE *fp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vfprintf(fp, fmt, ap);
    va_end(ap);
    return n;
}

void HW_PROC_DBG_LastWord(int line, const char *file,
                           const char *msg, int a, int b, int c)
{
    fprintf(stderr, "[DBG] %s:%d %s (0x%x 0x%x 0x%x)\n",
            file ? file : "?", line,
            msg  ? msg  : "", a, b, c);
}

int HW_OS_StrToUInt32(const char *str, uint32_t *val_out)
{
    if (!str || !val_out) return -1;
    char *end;
    unsigned long v = strtoul(str, &end, 10);
    if (end == str || *end != '\0') return -1;
    *val_out = (uint32_t)v;
    return 0;
}

/* ── File I/O ───────────────────────────────────────────────────────────── */

FILE *HW_OS_Fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}

void HW_OS_Fclose(FILE *fp)
{
    if (fp) fclose(fp);
}

size_t HW_OS_Fread(void *buf, size_t size, size_t count, FILE *fp)
{
    return fread(buf, size, count, fp);
}

size_t HW_OS_Fwrite(const void *buf, size_t size, size_t count, FILE *fp)
{
    return fwrite(buf, size, count, fp);
}

int HW_OS_Fseek(FILE *fp, long offset, int whence)
{
    return fseek(fp, offset, whence);
}

int HW_OS_GetFileSize(const char *path, uint32_t *size_out)
{
    struct stat st;
    if (!path || !size_out) return -1;
    if (stat(path, &st) != 0) return -1;
    *size_out = (uint32_t)st.st_size;
    return 0;
}

int HW_OS_GetLastErr(void)
{
    return errno;
}

int HW_OS_Open(const char *path, int flags)
{
    return open(path, flags);
}

int HW_OS_Close(int fd)
{
    return close(fd);
}

int HW_OS_Read(int fd, void *buf, size_t len)
{
    return (int)read(fd, buf, len);
}

int HW_OS_Remove(const char *path)
{
    return remove(path);
}

/* ── String / memory ────────────────────────────────────────────────────── */

int HW_OS_MemCmp(const void *a, const void *b, size_t n)
{
    return memcmp(a, b, n);
}

int HW_OS_StrNCmp(const char *s1, const char *s2, size_t n)
{
    return strncmp(s1, s2, n);
}

size_t HW_OS_StrNLen(const char *s, size_t maxlen)
{
    return strnlen(s, maxlen);
}

/* ── SSL / crypto wrappers ──────────────────────────────────────────────── */
#if defined(HAVE_MBEDTLS)
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>

int HW_SSL_AesSetKeyEnc(void *ctx, const uint8_t *key, uint32_t keybits)
{
    return mbedtls_aes_setkey_enc((mbedtls_aes_context *)ctx, key, keybits);
}

int HW_SSL_AesSetKeyDec(void *ctx, const uint8_t *key, uint32_t keybits)
{
    return mbedtls_aes_setkey_dec((mbedtls_aes_context *)ctx, key, keybits);
}

int HW_SSL_Sha2Start(void *ctx, int is224)
{
    return mbedtls_sha256_starts_ret((mbedtls_sha256_context *)ctx, is224);
}

int HW_SSL_Sha2Update(void *ctx, const uint8_t *input, size_t ilen)
{
    return mbedtls_sha256_update_ret((mbedtls_sha256_context *)ctx, input, ilen);
}

int HW_SSL_Sha2Finish(void *ctx, uint8_t *output)
{
    return mbedtls_sha256_finish_ret((mbedtls_sha256_context *)ctx, output);
}

int HW_SSL_Sha2HmacStart(void *ctx, const uint8_t *key,
                           size_t keylen, int is224)
{
    (void)is224;
    mbedtls_md_context_t *md = (mbedtls_md_context_t *)ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(md);
    int ret = mbedtls_md_setup(md, info, 1);
    if (ret == 0) ret = mbedtls_md_hmac_starts(md, key, keylen);
    return ret;
}

int HW_SSL_Sha2HmacUpdate(void *ctx, const uint8_t *input, size_t ilen)
{
    return mbedtls_md_hmac_update((mbedtls_md_context_t *)ctx, input, ilen);
}

int HW_SSL_Sha2HmacFinish(void *ctx, uint8_t *output)
{
    return mbedtls_md_hmac_finish((mbedtls_md_context_t *)ctx, output);
}

#else /* !HAVE_MBEDTLS */

int HW_SSL_AesSetKeyEnc(void *ctx, const uint8_t *key, uint32_t keybits)
{ (void)ctx; (void)key; (void)keybits; return 0; }
int HW_SSL_AesSetKeyDec(void *ctx, const uint8_t *key, uint32_t keybits)
{ (void)ctx; (void)key; (void)keybits; return 0; }
int HW_SSL_Sha2Start(void *ctx, int is224)
{ (void)ctx; (void)is224; return 0; }
int HW_SSL_Sha2Update(void *ctx, const uint8_t *input, size_t ilen)
{ (void)ctx; (void)input; (void)ilen; return 0; }
int HW_SSL_Sha2Finish(void *ctx, uint8_t *output)
{ (void)ctx; (void)output; return 0; }
int HW_SSL_Sha2HmacStart(void *ctx, const uint8_t *key,
                           size_t keylen, int is224)
{ (void)ctx; (void)key; (void)keylen; (void)is224; return 0; }
int HW_SSL_Sha2HmacUpdate(void *ctx, const uint8_t *input, size_t ilen)
{ (void)ctx; (void)input; (void)ilen; return 0; }
int HW_SSL_Sha2HmacFinish(void *ctx, uint8_t *output)
{ (void)ctx; (void)output; return 0; }

#endif /* HAVE_MBEDTLS */

/* ======================================================================== */
/* Version-specific imports (V500R019+)                                      */
/* ======================================================================== */

/*
 * HW_KMC_CfgGetKey – KMC key retrieval with embedded firmware keys.
 *
 * On device: reads key from kmc_store_A/B files via KMC_GetActiveMk.
 * Off device: uses keys captured from real aescrypt2 processes via GDB
 * breakpoint on HW_SSL_AesSetKeyDec across 6 firmware versions.
 *
 * The KMC subsystem generates a random AES-256 root key during first
 * init (when kmc_store is empty). This root key then derives the work
 * key via PBKDF2-SHA256. Each firmware build generates a different key
 * because the KMC seeding is version-specific.
 *
 * Key index (selected via AESCRYPT2_KEY_INDEX env var, 0-5):
 *   0 = V300R017 (HG8245Q, HG8247H)
 *   1 = V500R019C10SPC310 (HG8145V5 Telmex/Safaricom/Claro-AR)
 *   2 = V500R019C00SPC050 (HG8246M, HG8247H5 TO_V5)
 *   3 = V500R019C10SPC386 (HG8145V5 Totalplay G150)
 *   4 = V500R020C00SPC240 (HG8145V5 Claro-RD)
 *   5 = V500R020C10SPC212 (HG8145V5 General)
 */

/* AES-256 keys captured from real firmware via qemu + GDB */
static const uint8_t kmc_keys[6][32] = {
    /* 0: V300R017 – from HG8247H aes_string derivation */
    {0xe5,0x98,0xcd,0xb1,0x2e,0x61,0x20,0x7c,
     0x64,0x12,0xde,0xe5,0x3d,0xf3,0xb8,0xf6,
     0x01,0x17,0x3b,0x53,0xda,0x8c,0x28,0x37,
     0xb7,0x1e,0x73,0x90,0x88,0xc4,0x2a,0x65},
    /* 1: V500R019C10SPC310 – HG8145V5 Telmex/Safaricom */
    {0x77,0x68,0xc7,0x0b,0x5c,0x4a,0x66,0x4a,
     0xe1,0xb7,0x2b,0xf9,0x17,0x44,0x3b,0xb4,
     0xe3,0x2d,0x28,0x28,0xe6,0x7d,0x2e,0xb0,
     0x21,0x2b,0x80,0x0e,0xf5,0xb4,0x05,0x53},
    /* 2: V500R019C00SPC050 – HG8246M, HG8247H5 */
    {0xbf,0xfa,0xde,0xde,0x27,0xd4,0x69,0x39,
     0xce,0x6e,0x05,0xf0,0x08,0xdd,0x55,0x20,
     0xcf,0x86,0x5a,0xa0,0xf2,0x29,0x7a,0x35,
     0x47,0x32,0x84,0x4d,0xe4,0x46,0xfe,0x74},
    /* 3: V500R019C10SPC386 – HG8145V5 Totalplay */
    {0xb8,0xa2,0x1c,0x1d,0x15,0x6a,0xaf,0x42,
     0xf0,0xfc,0x6f,0xa1,0x79,0x94,0xb5,0x2e,
     0xb5,0xf8,0xd2,0x8c,0x6d,0xdf,0x31,0x10,
     0x5e,0xb5,0xda,0xb2,0x86,0xe9,0x49,0xcb},
    /* 4: V500R020C00SPC240 – HG8145V5 Claro-RD */
    {0xca,0xd6,0xb3,0x6d,0x64,0xa5,0xa1,0xe9,
     0xce,0xb7,0x8f,0x3e,0xd5,0x03,0x9f,0xac,
     0xad,0x6c,0x3d,0x3f,0x83,0xe8,0x18,0x92,
     0x6b,0x09,0xab,0x7e,0x1b,0x64,0x84,0xc2},
    /* 5: V500R020C10SPC212 – HG8145V5 General */
    {0xd5,0xfc,0xb9,0x2b,0xba,0x0c,0xd3,0x3b,
     0x79,0xb5,0xbd,0x1f,0x40,0xd2,0x06,0x83,
     0x63,0xb2,0x07,0xe7,0x94,0xe3,0x97,0xfb,
     0x2d,0x43,0x72,0xfe,0x09,0xf0,0x59,0x2a},
};

/* Currently selected key index (default 0 = V300, override via env) */
static int g_kmc_key_index = -1;

int HW_KMC_CfgGetKey(const char *path, void *key_buf, size_t key_len)
{
    /* Try to read key from file first (mimics /var/new_key_encryte_ctree) */
    if (path) {
        FILE *f = fopen(path, "rb");
        if (f) {
            size_t n = fread(key_buf, 1, key_len, f);
            fclose(f);
            if (n == key_len)
                return 0;
        }
    }

    /* Select key index from environment or default to 0 */
    if (g_kmc_key_index < 0) {
        const char *env = getenv("AESCRYPT2_KEY_INDEX");
        g_kmc_key_index = (env && *env >= '0' && *env <= '5')
                          ? (*env - '0') : 0;
    }

    if (key_len <= 32)
        memcpy(key_buf, kmc_keys[g_kmc_key_index], key_len);
    else {
        memset(key_buf, 0, key_len);
        memcpy(key_buf, kmc_keys[g_kmc_key_index], 32);
    }
    return 0;
}

/*
 * HW_KMC_SetKeyIndex – select which firmware key to use (0-5).
 * Called from the auto-detect logic in HW_OS_AESCBCDecrypt.
 */
void HW_KMC_SetKeyIndex(int idx)
{
    if (idx >= 0 && idx < 6)
        g_kmc_key_index = idx;
}

int HW_OS_AESCBCCalPSWLen(uint32_t len)
{
    /* Round up to next 16-byte boundary (AES block size) */
    return (int)((len + 15u) & ~15u);
}

int HW_OS_MemCpy_S(void *dst, size_t dstsz, const void *src, size_t n)
{
    if (!dst || !src || n > dstsz) return -1;
    memcpy(dst, src, n);
    return 0;
}

int HW_OS_MemSet_S(void *s, size_t smax, int c, size_t n)
{
    if (!s || n > smax) return -1;
    memset(s, c, n);
    return 0;
}

int HW_OS_StrCmp(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}

size_t HW_OS_StrLen(const char *s)
{
    return strlen(s);
}

int HW_OS_StrNCpy_S(char *dst, size_t dstsz, const char *src, size_t count)
{
    if (!dst || dstsz == 0) return -1;
    if (!src) { dst[0] = '\0'; return -1; }
    size_t n = (count < dstsz) ? count : dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

int HW_OS_Rename(const char *oldpath, const char *newpath)
{
    return rename(oldpath, newpath);
}

int HW_OS_ReadFile(const char *path, void *buf, size_t len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t n = fread(buf, 1, len, fp);
    fclose(fp);
    return (n > 0) ? 0 : -1;
}

int HW_OS_CopyFile(const char *src, const char *dst)
{
    FILE *fin = fopen(src, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(dst, "wb");
    if (!fout) { fclose(fin); return -1; }
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), fin)) > 0)
        fwrite(tmp, 1, n, fout);
    fclose(fin);
    fclose(fout);
    return 0;
}

/* ======================================================================== */
/* Additional helpers (cfgtool, memory, etc.)                                */
/* ======================================================================== */

void *HW_OS_MemMallocSet(size_t size)
{
    return calloc(1, size);
}

void HW_OS_MemFreeD(void *ptr)
{
    free(ptr);
}

int HW_OS_Access(const char *path, int mode)
{
    return access(path, mode);
}

char *HW_OS_Fgets(char *buf, int len, FILE *fp)
{
    return fgets(buf, len, fp);
}

char *HW_OS_StrtokR(char *str, const char *delim, char **saveptr)
{
#ifdef _WIN32
    return strtok_s(str, delim, saveptr);
#else
    return strtok_r(str, delim, saveptr);
#endif
}

char *HW_OS_StrStr(const char *hay, const char *needle)
{
    return strstr(hay, needle);
}

int HW_OS_StrCaseCmp(const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}

int HW_OS_CmdFormat(char *buf, size_t len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, len, fmt, ap);
    va_end(ap);
    return n;
}

int SSP_ExecShellCmd(const char *cmd)
{
    fprintf(stderr, "[STUB] SSP_ExecShellCmd: %s\n", cmd ? cmd : "(null)");
    return 0;
}

void HW_CFGTOOL_SysTrace(const char *file, int line, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[TRACE] %s:%d ", file ? file : "?", line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/* ── Key management helpers (device stubs) ──────────────────────────────── */

int MemGetRootKeyCfg(void *buf)
{
    (void)buf;
    fprintf(stderr, "[STUB] MemGetRootKeyCfg: device key not available on host\n");
    return 1;
}

void *MemGetMkInfoByContent(void)
{
    return NULL;
}

void MSG_GetShmData(void *dst, int zero, size_t len)
{
    (void)zero;
    if (dst) memset(dst, 0, len);
}

/* ── C11 Annex K safe-string stubs ──────────────────────────────────────── */
#if !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)
int strcpy_s(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) return -1;
    if (!src) { dst[0] = '\0'; return -1; }
    size_t n = strlen(src);
    if (n >= dst_sz) { dst[0] = '\0'; return -1; }
    memcpy(dst, src, n + 1);
    return 0;
}
int strncpy_s(char *dst, size_t dst_sz, const char *src, size_t count)
{
    if (!dst || dst_sz == 0) return -1;
    if (!src) { dst[0] = '\0'; return -1; }
    size_t n = (count < dst_sz) ? count : dst_sz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}
int memset_s(void *s, size_t smax, int c, size_t n)
{
    if (!s || n > smax) return -1;
    memset(s, c, n);
    return 0;
}
int memcpy_s(void *dst, size_t dstsz, const void *src, size_t n)
{
    if (!dst || !src || n > dstsz) return -1;
    memcpy(dst, src, n);
    return 0;
}
#endif /* !__STDC_LIB_EXT1__ */

/* ── polarssl wrappers (forward to mbedTLS when available) ──────────────── */
#if defined(HAVE_MBEDTLS)
#include <mbedtls/aes.h>

typedef struct { mbedtls_aes_context ctx; } polarssl_aes_context;

void polarssl_aes_init(polarssl_aes_context *ctx)
{
    mbedtls_aes_init(&ctx->ctx);
}
int polarssl_aes_setkey_enc(polarssl_aes_context *ctx,
                             const unsigned char *key, unsigned int keybits)
{
    return mbedtls_aes_setkey_enc(&ctx->ctx, key, keybits);
}
int polarssl_aes_setkey_dec(polarssl_aes_context *ctx,
                             const unsigned char *key, unsigned int keybits)
{
    return mbedtls_aes_setkey_dec(&ctx->ctx, key, keybits);
}
int polarssl_aes_crypt_cbc(polarssl_aes_context *ctx, int mode,
                            size_t length, unsigned char *iv,
                            const unsigned char *input, unsigned char *output)
{
    return mbedtls_aes_crypt_cbc(&ctx->ctx, mode, length, iv, input, output);
}
#endif /* HAVE_MBEDTLS */

/* ── Device-only stubs (efuse, flash, shared funcs) ─────────────────────── */

unsigned int hw_chip_id = 0;

int HW_OS_FLASH_Read(const char *mtd, uint32_t offset, void *buf, uint32_t len)
{
    (void)mtd; (void)offset; (void)buf; (void)len;
    fprintf(stderr, "[STUB] HW_OS_FLASH_Read: not available on host\n");
    return -1;
}

int HW_SWM_GetMtdBlkNameAndOffset(const char *partition_name, int flag,
                                    char *blk_name, uint32_t blk_name_len,
                                    uint32_t *offset_out)
{
    (void)partition_name; (void)flag; (void)blk_name;
    (void)blk_name_len; (void)offset_out;
    fprintf(stderr, "[STUB] HW_SWM_GetMtdBlkNameAndOffset: not available\n");
    return -1;
}

void *HW_DM_GetProductShareFunc(void)
{
    return NULL;
}

int HW_DM_IsShareFuncsInit(void)
{
    return 0;
}

/* ── cfgtool XML stubs (normally from libcfg_api.so) ────────────────────── */
/* When building standalone cfgtool, these are provided by cfgtool_xml.c */
#if !defined(STANDALONE_CFGTOOL)

void *HW_XML_ParseFile(const char *path, void **node_out)
{
    (void)path;
    if (node_out) *node_out = NULL;
    fprintf(stderr, "[STUB] HW_XML_ParseFile: not available on host\n");
    return NULL;
}

void HW_XML_FreeNode(void *node) { (void)node; }
void HW_XML_FreeSingleNode(void *node) { (void)node; }

void *HW_XML_NewNode(const char *name)
{
    (void)name;
    return NULL;
}

int HW_XML_SetNodeContent(void *node, const char *content)
{
    (void)node; (void)content;
    return -1;
}

int HW_XML_TransformFile(void *node, const char *path)
{
    (void)node; (void)path;
    return -1;
}

int HW_CFGTOOL_GetXMLValByPath(void *node, const char *xpath,
                                 char *out, size_t out_sz)
{
    (void)node; (void)xpath; (void)out; (void)out_sz;
    return -1;
}

int HW_CFGTOOL_SetXMLValByPath(void *node, const char *xpath,
                                 const char *value)
{
    (void)node; (void)xpath; (void)value;
    return -1;
}

int HW_CFGTOOL_AddXMLValByPath(void *node, const char *xpath,
                                 const char *value)
{
    (void)node; (void)xpath; (void)value;
    return -1;
}

int HW_CFGTOOL_DelXMLValByPath(void *node, const char *xpath)
{
    (void)node; (void)xpath;
    return -1;
}

int HW_CFGTOOL_CloneXMLValByPath(void *node, const char *xpath,
                                    const char *dst_xpath)
{
    (void)node; (void)xpath; (void)dst_xpath;
    return -1;
}

int HW_CFGTOOL_CheckArg(int op_type, int argc, char **argv)
{
    (void)op_type; (void)argc; (void)argv;
    return 0;
}

int HW_CFGTOOL_DealBatchType(void *node, const char *xml_path,
                               const char *batch_file)
{
    (void)node; (void)xml_path; (void)batch_file;
    fprintf(stderr, "[STUB] HW_CFGTOOL_DealBatchType: not available\n");
    return -1;
}

#endif /* !STANDALONE_CFGTOOL */
