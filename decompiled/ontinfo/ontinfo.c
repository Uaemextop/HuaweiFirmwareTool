/*
 * ontinfo.c  –  ONT device information query tool (standalone)
 *
 * Decompiled from original Huawei firmware binary:
 *   /bin/ontinfo (9500 bytes, ARM32 PIE, V500R022C00SPC340)
 *
 * Original function: Reads board type and PCB version from the device's
 * hw_boardinfo configuration file via HW_DM_PDGetAttr.
 *
 * Standalone version: Parses hw_boardinfo file directly.
 *
 * Usage (from original binary .rodata):
 *   ontinfo [OPTION]...
 *     -s   used with -p or -b, output information directly
 *     -p   output PCB version (e.g., pcbver=3)
 *     -b   output Board Type (e.g., boardtype=HG8145V5)
 *     -f   path to hw_boardinfo file (optional)
 *     -h   display help information
 *
 * Build: cc -o ontinfo ontinfo.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

/* Default paths matching the firmware layout */
#define BOARDINFO_PATH      "/mnt/jffs2/hw_boardinfo"
#define BOARDINFO_ALT_PATH  "/etc/wap/hw_boardinfo"

static char g_board_type[64]  = "";
static char g_pcb_version[64] = "";

/*
 * parse_boardinfo – read hw_boardinfo file and extract fields.
 *
 * The file format (from HW_DM_PDGetAttr in libhw_smp_dm_pdt.so):
 *   obj.FieldName = "Value" ;
 */
static int parse_boardinfo(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;

        char *key_start = line;
        while (*key_start == ' ' || *key_start == '\t') key_start++;
        if (strncmp(key_start, "obj.", 4) == 0) key_start += 4;

        char *key_end = eq;
        while (key_end > key_start && (*(key_end-1) == ' ' || *(key_end-1) == '\t'))
            key_end--;

        char field[64];
        size_t flen = (size_t)(key_end - key_start);
        if (flen >= sizeof(field)) flen = sizeof(field) - 1;
        memcpy(field, key_start, flen);
        field[flen] = '\0';

        char *val_start = strchr(eq + 1, '"');
        if (!val_start) continue;
        val_start++;
        char *val_end = strchr(val_start, '"');
        if (!val_end) continue;

        char value[64];
        size_t vlen = (size_t)(val_end - val_start);
        if (vlen >= sizeof(value)) vlen = sizeof(value) - 1;
        memcpy(value, val_start, vlen);
        value[vlen] = '\0';

        if (strcmp(field, "BoardType") == 0)
            strncpy(g_board_type, value, sizeof(g_board_type) - 1);
        else if (strcmp(field, "PCBVersion") == 0)
            strncpy(g_pcb_version, value, sizeof(g_pcb_version) - 1);
    }

    fclose(fp);
    return 0;
}

static void show_usage(void)
{
    printf("Usage: ontinfo [OPTION]... \n\n"
           "Options are listed as follows. \n"
           "  -s        used with -p or -b, output information directly."
           " for example: HG8245, or 3.\n"
           "  -p        output PCB version, for example: pcbver=3.\n"
           "  -b        output Board Type, for example: boardtype=HG8245"
           " or HG8240, HG8247, HG8447, HG8010, HG8110.\n"
           "  -f FILE   path to hw_boardinfo file.\n"
           "  -h        display help infomation.\n"
           "  -?        display help infomation.\n");
}

int main(int argc, char **argv)
{
    int opt_b = 0, opt_p = 0, opt_s = 0;
    int c;
    const char *boardinfo_path = NULL;

    while ((c = getopt(argc, argv, "bpshf:?")) != -1) {
        switch (c) {
        case 'b': opt_b = 1; break;
        case 'p': opt_p = 1; break;
        case 's': opt_s = 1; break;
        case 'f': boardinfo_path = optarg; break;
        case 'h':
        case '?':
            show_usage();
            return 0;
        default:
            show_usage();
            return 1;
        }
    }

    if (!opt_b && !opt_p) {
        show_usage();
        return 0;
    }

    if (!boardinfo_path) {
        if (access(BOARDINFO_PATH, R_OK) == 0)
            boardinfo_path = BOARDINFO_PATH;
        else if (access(BOARDINFO_ALT_PATH, R_OK) == 0)
            boardinfo_path = BOARDINFO_ALT_PATH;
    }

    if (boardinfo_path)
        parse_boardinfo(boardinfo_path);

    if (opt_b) {
        if (opt_s)
            printf("%s\n", g_board_type);
        else
            printf("boardtype=%s\n", g_board_type);
    }

    if (opt_p) {
        if (opt_s)
            printf("%s\n", g_pcb_version);
        else
            printf("pcbver=%s\n", g_pcb_version);
    }

    return 0;
}
