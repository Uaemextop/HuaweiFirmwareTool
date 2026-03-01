/*
 * setboardinfo.c  –  Set/modify hw_boardinfo fields
 *
 * Decompiled from: /bin/setboardinfo (13636 bytes, ARM32, V500R022)
 * Options: -p product -f field -o output -v value -c customize -m model
 * String: "p:f:o:v:c:m:" (getopt format from .rodata at 0x260e)
 * String: "/mnt/jffs2/hw_boardinfo" (default path from .rodata)
 * String: "Df7!ui%s9(lmV1L8" (obfuscation key from .rodata)
 *
 * Original: Modifies hw_boardinfo file fields via HW_DM_PDSetAttr.
 * Used during factory provisioning and ISP customization.
 *
 * Standalone: Directly modifies hw_boardinfo text file.
 *
 * Build: cc -o setboardinfo setboardinfo.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define DEFAULT_BOARDINFO_PATH "/mnt/jffs2/hw_boardinfo"
#define MAX_LINE 1024
#define MAX_LINES 512

static char *lines[MAX_LINES];
static int nlines = 0;

static int load_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char buf[MAX_LINE];
    nlines = 0;
    while (fgets(buf, sizeof(buf), fp) && nlines < MAX_LINES) {
        lines[nlines] = strdup(buf);
        nlines++;
    }
    fclose(fp);
    return 0;
}

static int save_file(const char *path)
{
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    for (int i = 0; i < nlines; i++) {
        fputs(lines[i], fp);
    }
    fclose(fp);
    return 0;
}

static void free_lines(void)
{
    for (int i = 0; i < nlines; i++)
        free(lines[i]);
    nlines = 0;
}

static int set_field(const char *field, const char *value)
{
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "obj.%s", field);

    for (int i = 0; i < nlines; i++) {
        if (strstr(lines[i], search_key)) {
            char new_line[MAX_LINE];
            snprintf(new_line, sizeof(new_line), "obj.%s = \"%s\" ;\n", field, value);
            free(lines[i]);
            lines[i] = strdup(new_line);
            return 0;
        }
    }

    /* Field not found - add it before the last line (closing brace) */
    if (nlines > 0 && nlines < MAX_LINES) {
        char new_line[MAX_LINE];
        snprintf(new_line, sizeof(new_line), "obj.%s = \"%s\" ;\n", field, value);
        /* Shift last line */
        lines[nlines] = lines[nlines - 1];
        lines[nlines - 1] = strdup(new_line);
        nlines++;
    }
    return 0;
}

static void show_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n"
           "  -p PRODUCT     Set product name (BoardType)\n"
           "  -f FIELD       Field name to set\n"
           "  -v VALUE       Value to set\n"
           "  -o OUTPUT      Output file path (default: overwrite input)\n"
           "  -c CUSTOMIZE   Set CustomizeWord\n"
           "  -m MODEL       Set EquipmentID\n"
           "  -i INPUT       Input boardinfo path (default: %s)\n"
           "  -h             Show this help\n"
           "\nExample:\n"
           "  %s -p HG8145V5 -c JSCT -i hw_boardinfo\n"
           "  %s -f SerialNumber -v 485754430F000001\n",
           prog, DEFAULT_BOARDINFO_PATH, prog, prog);
}

int main(int argc, char **argv)
{
    const char *input_path = DEFAULT_BOARDINFO_PATH;
    const char *output_path = NULL;
    const char *product = NULL;
    const char *field = NULL;
    const char *value = NULL;
    const char *customize = NULL;
    const char *model = NULL;
    int c;

    while ((c = getopt(argc, argv, "p:f:o:v:c:m:i:h")) != -1) {
        switch (c) {
        case 'p': product = optarg; break;
        case 'f': field = optarg; break;
        case 'o': output_path = optarg; break;
        case 'v': value = optarg; break;
        case 'c': customize = optarg; break;
        case 'm': model = optarg; break;
        case 'i': input_path = optarg; break;
        case 'h': show_usage(argv[0]); return 0;
        default:  show_usage(argv[0]); return 1;
        }
    }

    if (!product && !field && !customize && !model) {
        show_usage(argv[0]);
        return 1;
    }

    if (load_file(input_path) != 0) {
        fprintf(stderr, "Error: cannot open %s\n", input_path);
        return 1;
    }

    if (product)   set_field("BoardType", product);
    if (customize) set_field("CustomizeWord", customize);
    if (model)     set_field("EquipmentID", model);
    if (field && value) set_field(field, value);

    if (!output_path) output_path = input_path;

    if (save_file(output_path) != 0) {
        fprintf(stderr, "Error: cannot write %s\n", output_path);
        free_lines();
        return 1;
    }

    printf("Updated %s\n", output_path);
    free_lines();
    return 0;
}
