/*
 * keyfilemng.c  –  Key file manager (save/check/restore)
 *
 * Decompiled from: /bin/keyfilemng (21936 bytes, ARM32, V500R022)
 * Source: keyfile_mng.c, keyfile_data.c, keyfile_restore_boardinfo.c
 *
 * Original operations (from .rodata and usage output):
 *   save     - Backup key files to /var/backKey/
 *   check    - Verify backup integrity with CRC
 *   restore  - Restore key files from backup
 *              Supports: all, boardtype, boardinfo, defaultctree,
 *                       customizepara, kmcstore
 *
 * File paths from .rodata:
 *   /var/backKey/             - backup directory
 *   /mnt/jffs2/              - JFFS2 partition (active config)
 *   /mnt/jffs2/hw_boardinfo  - board info file
 *   /etc/wap/hw_boardinfo    - factory board info
 *   /var/backKey_check.tar.gz - backup check archive
 *   kmc_store_A              - KMC key store
 *   hw_default_ctree.xml     - default config tree
 *   customizepara.txt        - customization parameters
 *   customize.txt            - customize word file
 *
 * CRC format: "%s.crc" - CRC stored alongside each backed-up file
 *
 * Build: cc -o keyfilemng keyfilemng.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define BACKUP_DIR       "/var/backKey/"
#define JFFS2_DIR        "/mnt/jffs2/"
#define BOARDINFO_PATH   "/mnt/jffs2/hw_boardinfo"
#define BOARDINFO_BAK    "/mnt/jffs2/hw_boardinfo.bak"
#define FACTORY_BOARD    "/etc/wap/hw_boardinfo"
#define BACKUP_CHECK_TGZ "/var/backKey_check.tar.gz"

/* Files to backup/restore */
struct key_file {
    const char *obj_name;
    const char *filenames[4]; /* possible filenames, NULL-terminated */
};

static const struct key_file key_files[] = {
    { "boardtype",      { "board_type", NULL } },
    { "boardinfo",      { "hw_boardinfo", NULL } },
    { "defaultctree",   { "hw_default_ctree.xml", NULL } },
    { "customizepara",  { "customizepara.txt", "customize.txt", NULL } },
    { "kmcstore",       { "kmc_store_A", NULL } },
    { NULL,             { NULL } }
};

/* CRC32 (same as getfilecrc.c) */
static uint32_t crc32_table[256];
static int crc32_inited = 0;

static void crc32_init(void)
{
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? ((c >> 1) ^ 0xEDB88320U) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_inited = 1;
}

static uint32_t file_crc32(const char *path)
{
    if (!crc32_inited) crc32_init();

    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    uint32_t crc = 0xFFFFFFFFU;
    unsigned char buf[4096];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        for (size_t i = 0; i < n; i++)
            crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }

    fclose(fp);
    return crc ^ 0xFFFFFFFFU;
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
    return 0;
}

static int cmd_save(void)
{
    printf("KEYFILE_Save Start!\n");

    /* Create backup directory */
    mkdir(BACKUP_DIR, 0755);

    int saved = 0;
    for (int i = 0; key_files[i].obj_name; i++) {
        for (int j = 0; key_files[i].filenames[j]; j++) {
            char src[256], dst[256], crc_path[264];
            snprintf(src, sizeof(src), "%s%s", JFFS2_DIR, key_files[i].filenames[j]);

            if (access(src, R_OK) != 0) {
                /* Try /etc/wap/ */
                snprintf(src, sizeof(src), "/etc/wap/%s", key_files[i].filenames[j]);
                if (access(src, R_OK) != 0)
                    continue;
            }

            snprintf(dst, sizeof(dst), "%s%s", BACKUP_DIR, key_files[i].filenames[j]);

            if (copy_file(src, dst) == 0) {
                /* Save CRC */
                uint32_t crc = file_crc32(dst);
                snprintf(crc_path, sizeof(crc_path), "%s.crc", dst);
                FILE *fp = fopen(crc_path, "w");
                if (fp) {
                    fprintf(fp, "0x%x\n", crc);
                    fclose(fp);
                }
                printf("save obj %s to mem ret 0, errno 0\n", key_files[i].obj_name);
                saved++;
            }
        }
    }

    if (saved > 0) {
        /* Create backup_ok marker */
        FILE *fp = fopen("/mnt/jffs2/backup_ok", "w");
        if (fp) { fprintf(fp, "ok\n"); fclose(fp); }
    }

    printf("Saved %d key files\n", saved);
    return 0;
}

static int cmd_check(void)
{
    int errors = 0, checked = 0;

    for (int i = 0; key_files[i].obj_name; i++) {
        for (int j = 0; key_files[i].filenames[j]; j++) {
            char bak_path[256], crc_path[264];
            snprintf(bak_path, sizeof(bak_path), "%s%s", BACKUP_DIR, key_files[i].filenames[j]);

            if (access(bak_path, R_OK) != 0) continue;

            snprintf(crc_path, sizeof(crc_path), "%s.crc", bak_path);

            uint32_t actual_crc = file_crc32(bak_path);

            /* Read stored CRC */
            uint32_t stored_crc = 0;
            FILE *fp = fopen(crc_path, "r");
            if (fp) {
                fscanf(fp, "0x%x", &stored_crc);
                fclose(fp);
            }

            checked++;
            if (actual_crc == stored_crc && stored_crc != 0) {
                printf("KEYFILE_CheckBackKeyInDir OK:[%s]\n", key_files[i].obj_name);
            } else {
                printf("KEYFILE_CheckBackKeyInDir err:[%s] expected=0x%x actual=0x%x\n",
                       key_files[i].obj_name, stored_crc, actual_crc);
                errors++;
            }
        }
    }

    if (checked == 0) {
        printf("No backup files found in %s\n", BACKUP_DIR);
        return 1;
    }

    printf("Checked %d files, %d errors\n", checked, errors);
    return errors ? 1 : 0;
}

static int cmd_restore(const char *obj_name)
{
    int found = 0;

    for (int i = 0; key_files[i].obj_name; i++) {
        if (obj_name && strcmp(obj_name, "all") != 0 &&
            strcmp(obj_name, key_files[i].obj_name) != 0)
            continue;

        for (int j = 0; key_files[i].filenames[j]; j++) {
            char bak_path[256], dst_path[256];
            snprintf(bak_path, sizeof(bak_path), "%s%s", BACKUP_DIR, key_files[i].filenames[j]);

            if (access(bak_path, R_OK) != 0) {
                if (obj_name && strcmp(obj_name, "all") != 0)
                    printf("backup file [%s] not exist, ignore!\n", bak_path);
                continue;
            }

            snprintf(dst_path, sizeof(dst_path), "%s%s", JFFS2_DIR, key_files[i].filenames[j]);

            if (copy_file(bak_path, dst_path) == 0) {
                printf("restore %s from %s successful.\n", key_files[i].obj_name, bak_path);
                found++;
            } else {
                printf("restore %s from %s fail.\n", key_files[i].obj_name, bak_path);
            }
        }
    }

    return found > 0 ? 0 : 1;
}

static void show_usage(void)
{
    printf("\nUsage:  keyfilemng [cmd] [obj]\n"
           "cmd:    support save/check/restore\n"
           "obj:    only support restore, you can chose following object:\n"
           "        all/boardtype/boardinfo/defaultctree/customizepara\n"
           "example:\n"
           "        keyfilemng save\n"
           "        keyfilemng check\n"
           "        keyfilemng restore\n"
           "        keyfilemng restore boardtype\n"
           "        keyfilemng restore boardinfo\n"
           "        keyfilemng restore defaultctree\n"
           "        keyfilemng restore customizepara\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        show_usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "save") == 0) {
        return cmd_save();
    } else if (strcmp(cmd, "check") == 0) {
        return cmd_check();
    } else if (strcmp(cmd, "restore") == 0) {
        const char *obj = (argc > 2) ? argv[2] : "all";
        return cmd_restore(obj);
    } else if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        show_usage();
        return 0;
    }

    fprintf(stderr, "Bad objname %s\n", cmd);
    show_usage();
    return 1;
}
