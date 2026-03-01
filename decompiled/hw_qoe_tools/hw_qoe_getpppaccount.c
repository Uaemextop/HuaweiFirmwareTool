/*
 * hw_qoe_getpppaccount.c  –  Get PPP connection account info
 *
 * Decompiled from: /bin/hw_qoe_getpppaccount (9500 bytes, ARM32, V500R022)
 * Imports: HW_OS_Printf, HW_OS_StrCaseCmp, HW_PROC_DBG_LastWord, HW_DM_PDGetAttr
 *
 * Original: Retrieves PPP connection username/password from device database
 * for QoE (Quality of Experience) diagnostics, checking ISP customize word.
 *
 * Standalone: Reads PPP credentials from hw_boardinfo or hw_ctree.xml.
 *
 * Build: cc -o hw_qoe_getpppaccount hw_qoe_getpppaccount.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BOARDINFO_PATH     "/mnt/jffs2/hw_boardinfo"
#define BOARDINFO_ALT      "/etc/wap/hw_boardinfo"

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

static void show_usage(void)
{
    printf("Usage: hw_qoe_getpppaccount [-f boardinfo_path]\n"
           "  Reads PPP account information from device configuration.\n"
           "  -f FILE   path to hw_boardinfo file\n");
}

int main(int argc, char **argv)
{
    char username[256] = "";
    char password[256] = "";
    const char *boardinfo = NULL;

    if (argc > 1 && strcmp(argv[1], "-h") == 0) {
        show_usage();
        return 0;
    }

    if (argc > 2 && strcmp(argv[1], "-f") == 0) {
        boardinfo = argv[2];
    } else {
        if (access(BOARDINFO_PATH, R_OK) == 0)
            boardinfo = BOARDINFO_PATH;
        else if (access(BOARDINFO_ALT, R_OK) == 0)
            boardinfo = BOARDINFO_ALT;
    }

    if (!boardinfo) {
        fprintf(stderr, "No boardinfo file found\n");
        return -1;
    }

    int found = 0;
    if (parse_field(boardinfo, "PPPUserName", username, sizeof(username)) == 0) {
        printf("PPPUserName=%s\n", username);
        found = 1;
    }
    if (parse_field(boardinfo, "PPPPassword", password, sizeof(password)) == 0) {
        printf("PPPPassword=%s\n", password);
        found = 1;
    }

    if (!found) {
        fprintf(stderr, "PPP account not found in %s\n", boardinfo);
        return -1;
    }

    return 0;
}
