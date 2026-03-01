/*
 * hw_qoe_getloid.c  –  Get LOID (Logical ONT ID) from device
 *
 * Decompiled from: /bin/hw_qoe_getloid (5456 bytes, ARM32, V500R022)
 * Imports: HW_DM_PDGetAttr, HW_OS_StrCaseCmp, HW_PROC_DBG_LastWord, HW_OS_Printf
 *
 * Original: Reads LOID from the device's product attribute database
 * (libhw_smp_dm_pdt.so), checks ISP customize word (JSCT, GDCT, etc.),
 * and outputs the LOID string.
 *
 * Standalone: Reads LOID from hw_boardinfo file or cfgtool XML path.
 *
 * Build: cc -o hw_qoe_getloid hw_qoe_getloid.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BOARDINFO_PATH     "/mnt/jffs2/hw_boardinfo"
#define BOARDINFO_ALT      "/etc/wap/hw_boardinfo"
#define CTREE_LOID_PATH    "InternetGatewayDevice.WANDevice.WANConnectionDevice.WANPPPConnection.LOID"

/* Known ISP customize words from .rodata */
static const char *known_isps[] = {
    "JSCT", "JSCTNOVOICE", "GDCT", "GDGCT", "GXCT",
    "HUNCT", "HUNGCT", "HUBCT", "QHCT", "HENCT",
    "SDCT", "AHCT", "SAXCT", NULL
};

static int parse_field(const char *path, const char *field_name, char *out, size_t out_sz)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "obj.", 4) == 0) p += 4;

        /* Check field name */
        if (strncmp(p, field_name, strlen(field_name)) != 0) continue;

        char *val = strchr(eq + 1, '"');
        if (!val) continue;
        val++;
        char *end = strchr(val, '"');
        if (!end) continue;

        size_t len = (size_t)(end - val);
        if (len >= out_sz) len = out_sz - 1;
        memcpy(out, val, len);
        out[len] = '\0';
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return -1;
}

int main(int argc, char **argv)
{
    char loid[128] = "";
    const char *boardinfo = NULL;

    if (argc > 1 && strcmp(argv[1], "-f") == 0 && argc > 2) {
        boardinfo = argv[2];
    } else {
        if (access(BOARDINFO_PATH, R_OK) == 0)
            boardinfo = BOARDINFO_PATH;
        else if (access(BOARDINFO_ALT, R_OK) == 0)
            boardinfo = BOARDINFO_ALT;
    }

    if (boardinfo) {
        if (parse_field(boardinfo, "LOID", loid, sizeof(loid)) == 0) {
            printf("%s\n", loid);
            return 0;
        }
        /* Try OntRegAuthLoid */
        if (parse_field(boardinfo, "OntRegAuthLoid", loid, sizeof(loid)) == 0) {
            printf("%s\n", loid);
            return 0;
        }
    }

    fprintf(stderr, "LOID not found\n");
    return -1;
}
