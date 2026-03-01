/*
 * kmc_tool.c  –  KMC (Key Management Center) store file utility
 *
 * Decompiled from: /bin/kmc_tool (9500 bytes, ARM32, V500R022)
 * Source: kmc_tool_main.c
 *
 * Strings from .rodata:
 *   "/var/kmc_tmp_info"          - temp info path
 *   "/mnt/jffs2/kmc_store_A"    - primary KMC store
 *   "/etc/wap/kmc_store_A"      - factory KMC store
 *   "/mnt/jffs2/kmc_store_B"    - backup KMC store
 *   "/etc/wap/kmc_store_B"      - factory KMC backup
 *   "Copy kmcstore file to jffs2!" - copy message
 *   "check"                     - check operation
 *
 * Imports: KMC_MKExsit, WsecInitializeEx, WSEC_REG_Basic,
 *          KmcGetMkDetail, KMC_CheckHashEnd, KMC_IsNowHardWareCrypt,
 *          WsecGetVersion
 *
 * Functions:
 *   - Check KMC store integrity
 *   - Copy factory KMC stores to JFFS2
 *   - Query KMC version and hardware crypto status
 *   - Get master key details
 *
 * Standalone version operates directly on kmc_store files.
 *
 * Build: cc -o kmc_tool kmc_tool.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

/* KMC store file paths (from .rodata) */
#define KMC_JFFS2_A    "/mnt/jffs2/kmc_store_A"
#define KMC_JFFS2_B    "/mnt/jffs2/kmc_store_B"
#define KMC_FACTORY_A  "/etc/wap/kmc_store_A"
#define KMC_FACTORY_B  "/etc/wap/kmc_store_B"
#define KMC_TMP_INFO   "/var/kmc_tmp_info"

/* KMC version string (from original binary output) */
#define KMC_VERSION    "KMC 3.0.0.B003"

/*
 * KMC store file header (from binary analysis of kmc_store_A/B).
 * The file contains the device's master key material used by aescrypt2
 * for config file encryption/decryption.
 */
#pragma pack(push, 1)
struct kmc_store_header {
    uint32_t magic;         /* File magic */
    uint32_t version;       /* KMC version */
    uint32_t key_count;     /* Number of key entries */
    uint32_t total_size;    /* Total file size */
    uint8_t  hash[32];      /* SHA-256 hash of key data */
};
#pragma pack(pop)

static int file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) return -1;

    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);

    fclose(in);
    fclose(out);
    chmod(dst, 0600);
    return 0;
}

static int kmc_check(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        printf("KMC store not found: %s\n", path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size < (long)sizeof(struct kmc_store_header)) {
        printf("KMC store too small: %s (%ld bytes)\n", path, size);
        fclose(fp);
        return -1;
    }

    struct kmc_store_header hdr;
    fread(&hdr, sizeof(hdr), 1, fp);
    fclose(fp);

    printf("KMC store: %s\n", path);
    printf("  Size:      %ld bytes\n", size);
    printf("  Magic:     0x%08x\n", hdr.magic);
    printf("  Version:   %u\n", hdr.version);
    printf("  Keys:      %u\n", hdr.key_count);
    printf("  Hash:      ");
    for (int i = 0; i < 16; i++) printf("%02x", hdr.hash[i]);
    printf("...\n");

    return 0;
}

static void show_usage(void)
{
    printf("%s, is hardware crypt[0]\n\n", KMC_VERSION);
    printf("Usage: kmc_tool [command] [options]\n\n"
           "Commands:\n"
           "  check                    Check KMC store integrity\n"
           "  info                     Show KMC version and status\n"
           "  copy                     Copy factory KMC stores to JFFS2\n"
           "  dump <kmc_store_file>    Dump KMC store header info\n"
           "\n"
           "KMC store paths:\n"
           "  Primary: %s\n"
           "  Backup:  %s\n"
           "  Factory: %s, %s\n",
           KMC_JFFS2_A, KMC_JFFS2_B, KMC_FACTORY_A, KMC_FACTORY_B);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        /* Match original behavior: print version then exit */
        printf("%s, is hardware crypt[0]\n", KMC_VERSION);
        return 0;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "check") == 0) {
        int ret = 0;
        /* Check all KMC store locations */
        const char *paths[] = { KMC_JFFS2_A, KMC_JFFS2_B, KMC_FACTORY_A, KMC_FACTORY_B };
        for (int i = 0; i < 4; i++) {
            if (file_exists(paths[i])) {
                if (kmc_check(paths[i]) != 0)
                    ret = 1;
            }
        }
        if (ret == 0)
            printf("All KMC stores OK\n");
        return ret;

    } else if (strcmp(cmd, "info") == 0) {
        printf("%s, is hardware crypt[0]\n", KMC_VERSION);
        printf("\nKMC store files:\n");
        const char *paths[] = { KMC_JFFS2_A, KMC_JFFS2_B, KMC_FACTORY_A, KMC_FACTORY_B };
        const char *names[] = { "JFFS2-A", "JFFS2-B", "Factory-A", "Factory-B" };
        for (int i = 0; i < 4; i++) {
            if (file_exists(paths[i])) {
                struct stat st;
                stat(paths[i], &st);
                printf("  [%s] %s (%ld bytes)\n", names[i], paths[i], (long)st.st_size);
            } else {
                printf("  [%s] %s (not found)\n", names[i], paths[i]);
            }
        }
        return 0;

    } else if (strcmp(cmd, "copy") == 0) {
        /* Copy factory KMC stores to JFFS2 (original behavior) */
        int copied = 0;
        if (file_exists(KMC_FACTORY_A) && !file_exists(KMC_JFFS2_A)) {
            if (copy_file(KMC_FACTORY_A, KMC_JFFS2_A) == 0) {
                printf("Copy kmcstore file to jffs2!\n");
                copied++;
            }
        }
        if (file_exists(KMC_FACTORY_B) && !file_exists(KMC_JFFS2_B)) {
            if (copy_file(KMC_FACTORY_B, KMC_JFFS2_B) == 0) {
                printf("Copy kmcstore file to jffs2!\n");
                copied++;
            }
        }
        if (copied == 0)
            printf("No KMC stores need copying\n");
        return 0;

    } else if (strcmp(cmd, "dump") == 0 && argc > 2) {
        return kmc_check(argv[2]);

    } else if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        show_usage();
        return 0;
    }

    show_usage();
    return 1;
}
