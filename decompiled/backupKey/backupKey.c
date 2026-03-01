/*
 * backupKey.c  –  Backup key data from MTD flash partitions
 *
 * Decompiled from: /bin/backupKey (9500 bytes, ARM32 PIE, V500R022C00SPC340)
 * Source file: backupKey.c (from .rodata)
 *
 * Original binary imports (from libhw_ssp_basic.so, libhw_ldsp_common.so):
 *   HW_OS_Printf, HW_OS_Remove, HW_OS_ReadFile, HW_OS_GetLastErr,
 *   HW_OS_ExecShellCmdEx, HW_PROC_DBG_LastWord, SwmReleaseKeyData
 *
 * Original binary exports:
 *   main (184 bytes)
 *   TOOL_GetMTDNameByKeyWord (408 bytes)
 *
 * Strings from .rodata:
 *   "grep %s /proc/mtd | cut -d \":\" -f1 > /var/tmpmtdname"
 *   "mtd%d"
 *   "mtdblock%d"
 *   "keyfile"
 *
 * Function: Reads key data from the "keyfile" MTD partition and releases
 * (backs up) the key material. Uses /proc/mtd to find the partition.
 *
 * Standalone version: Reads from MTD device or regular file, copies
 * key data to backup location.
 *
 * Build: cc -o backupKey backupKey.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define TMP_MTD_NAME    "/var/tmpmtdname"
#define KEYFILE_KEYWORD "keyfile"

/*
 * TOOL_GetMTDNameByKeyWord – Find MTD device number for a named partition.
 *
 * Decompiled from original export (0xcb4, 408 bytes).
 * Original: executes "grep %s /proc/mtd | cut -d \":\" -f1 > /var/tmpmtdname"
 * then reads the result to get "mtdN" number.
 *
 * Standalone: parses /proc/mtd directly without shell commands.
 *
 * Embedded library functions:
 *   HW_OS_ExecShellCmdEx → system()
 *   HW_OS_ReadFile → fopen+fread+fclose
 *   HW_OS_Remove → remove()
 *   HW_OS_Printf → printf()
 */
static int TOOL_GetMTDNameByKeyWord(const char *keyword, int *mtd_num)
{
    FILE *fp = fopen("/proc/mtd", "r");
    if (!fp) {
        fprintf(stderr, "Cannot open /proc/mtd\n");
        return -1;
    }

    char line[256];
    /* Skip header line */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        /* Format: mtdN: XXXXXXXX XXXXXXXX "name" */
        int num;
        char name[128] = "";
        if (sscanf(line, "mtd%d:", &num) == 1) {
            char *q1 = strchr(line, '"');
            if (q1) {
                q1++;
                char *q2 = strchr(q1, '"');
                if (q2) {
                    size_t len = (size_t)(q2 - q1);
                    if (len >= sizeof(name)) len = sizeof(name) - 1;
                    memcpy(name, q1, len);
                    name[len] = '\0';
                }
            }
            if (strcmp(name, keyword) == 0) {
                *mtd_num = num;
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    return -1;
}

/*
 * Read key data from MTD block device.
 *
 * Embedded library functions:
 *   HW_OS_ReadFile → fopen+fread+fclose
 *   SwmReleaseKeyData → writes key data to backup file
 *   HW_OS_GetLastErr → errno
 */
static int read_key_from_mtd(int mtd_num, const char *output_path)
{
    char dev_path[64];
    snprintf(dev_path, sizeof(dev_path), "/dev/mtdblock%d", mtd_num);

    FILE *fp = fopen(dev_path, "rb");
    if (!fp) {
        /* Try /dev/mtd%d instead */
        snprintf(dev_path, sizeof(dev_path), "/dev/mtd%d", mtd_num);
        fp = fopen(dev_path, "rb");
        if (!fp) {
            fprintf(stderr, "Cannot open %s\n", dev_path);
            return -1;
        }
    }

    /* Read key data - typical keyfile partition is 64KB-256KB */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) {
        fprintf(stderr, "Invalid MTD size: %ld\n", size);
        fclose(fp);
        return -1;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)size);
    if (!data) {
        fclose(fp);
        return -1;
    }

    size_t read_len = fread(data, 1, (size_t)size, fp);
    fclose(fp);

    if (read_len == 0) {
        free(data);
        return -1;
    }

    /* Write to output */
    FILE *out = fopen(output_path, "wb");
    if (!out) {
        fprintf(stderr, "Cannot write to %s\n", output_path);
        free(data);
        return -1;
    }

    fwrite(data, 1, read_len, out);
    fclose(out);
    free(data);

    printf("Backed up %zu bytes from %s to %s\n", read_len, dev_path, output_path);
    return 0;
}

/*
 * Read key data from a regular file (for standalone use).
 */
static int read_key_from_file(const char *src, const char *dst)
{
    FILE *fp = fopen(src, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open %s\n", src);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0) {
        fclose(fp);
        return -1;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)size);
    if (!data) { fclose(fp); return -1; }

    size_t n = fread(data, 1, (size_t)size, fp);
    fclose(fp);

    FILE *out = fopen(dst, "wb");
    if (!out) { free(data); return -1; }
    fwrite(data, 1, n, out);
    fclose(out);
    free(data);

    printf("Copied %zu bytes from %s to %s\n", n, src, dst);
    return 0;
}

static void show_usage(void)
{
    printf("Usage: backupKey [options]\n"
           "  -m          Read key from MTD 'keyfile' partition\n"
           "  -f FILE     Read key from regular file\n"
           "  -o OUTPUT   Output path (default: /var/backKey/keyfile)\n"
           "  -l          List MTD partitions\n"
           "  -h          Show help\n");
}

/*
 * main – Decompiled from original (0x9d0, 184 bytes)
 *
 * Original flow:
 *   1. TOOL_GetMTDNameByKeyWord("keyfile", &mtd_num)
 *   2. HW_OS_ReadFile(sprintf("mtdblock%d", mtd_num), ...)
 *   3. SwmReleaseKeyData(data, size)
 */
int main(int argc, char **argv)
{
    const char *output = "/var/backKey/keyfile";
    const char *input_file = NULL;
    int use_mtd = 0, list_mtd = 0;
    int c;

    while ((c = getopt(argc, argv, "mf:o:lh")) != -1) {
        switch (c) {
        case 'm': use_mtd = 1; break;
        case 'f': input_file = optarg; break;
        case 'o': output = optarg; break;
        case 'l': list_mtd = 1; break;
        case 'h': show_usage(); return 0;
        default:  show_usage(); return 1;
        }
    }

    if (list_mtd) {
        FILE *fp = fopen("/proc/mtd", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp))
                printf("%s", line);
            fclose(fp);
        } else {
            printf("No /proc/mtd available (not running on router)\n");
        }
        return 0;
    }

    if (input_file) {
        return read_key_from_file(input_file, output);
    }

    if (use_mtd || argc == 1) {
        int mtd_num = -1;
        if (TOOL_GetMTDNameByKeyWord(KEYFILE_KEYWORD, &mtd_num) == 0) {
            printf("Found keyfile partition: mtd%d\n", mtd_num);
            return read_key_from_mtd(mtd_num, output);
        } else {
            fprintf(stderr, "MTD partition '%s' not found\n", KEYFILE_KEYWORD);
            if (argc == 1) show_usage();
            return 1;
        }
    }

    show_usage();
    return 1;
}
