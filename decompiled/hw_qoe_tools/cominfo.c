/*
 * cominfo.c  –  Process/component information query tool
 *
 * Decompiled from: /bin/cominfo (9524 bytes, ARM32, V500R022)
 * Imports: HW_OS_Printf, HW_OS_StrCaseCmp, HW_OS_StrLen, HW_PROC_DBG_LastWord,
 *          HW_OS_MemMallocSet, HW_OS_MemFreeD
 *
 * Options: "grkdhc:f:" (getopt string from .rodata)
 *
 * Usage: cominfo -g get com info -c com_name
 *
 * Strings from .rodata:
 *   COMSTATE_NONE, COMSTATE_INIT, COMSTATE_ACTIVE, COMSTATE_STOP,
 *   COMSTATE_RESTART, COMSTATE_INITERR
 *   "Dependentapp:%s", "AttachList:%s"
 *
 * Original: Queries the router's internal component/process management
 * system for status information.
 *
 * Standalone: Reads from /proc or a status file.
 *
 * Build: cc -o cominfo cominfo.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>

/* Component state names from .rodata */
static const char *state_names[] = {
    "COMSTATE_NONE",
    "COMSTATE_INIT",
    "COMSTATE_ACTIVE",
    "COMSTATE_STOP",
    "COMSTATE_RESTART",
    "COMSTATE_INITERR",
};

struct com_info {
    char name[64];
    int pid;
    const char *state;
    char dependent[256];
    char attach_list[256];
};

static int get_com_info(const char *com_name, struct com_info *info)
{
    memset(info, 0, sizeof(*info));
    strncpy(info->name, com_name, sizeof(info->name) - 1);
    info->state = state_names[0]; /* NONE by default */

    /* Try to find running process */
    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    struct dirent *ent;
    while ((ent = readdir(proc))) {
        /* Check if it's a PID directory */
        char *endp;
        long pid = strtol(ent->d_name, &endp, 10);
        if (*endp != '\0' || pid <= 0) continue;

        char cmdline_path[128];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%ld/cmdline", pid);

        FILE *fp = fopen(cmdline_path, "r");
        if (!fp) continue;

        char cmdline[256] = "";
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
        fclose(fp);
        if (n == 0) continue;
        cmdline[n] = '\0';

        /* Extract basename */
        char *base = strrchr(cmdline, '/');
        base = base ? base + 1 : cmdline;

        if (strcmp(base, com_name) == 0) {
            info->pid = (int)pid;
            info->state = state_names[2]; /* ACTIVE */
            break;
        }
    }

    closedir(proc);
    return 0;
}

static void show_usage(void)
{
    printf("usage:\n"
           "-g get com info -c com name\n");
}

int main(int argc, char **argv)
{
    int opt_g = 0, opt_r = 0, opt_k = 0, opt_d = 0;
    const char *com_name = NULL;
    const char *com_file = NULL;
    int c;

    while ((c = getopt(argc, argv, "grkdhc:f:")) != -1) {
        switch (c) {
        case 'g': opt_g = 1; break;
        case 'r': opt_r = 1; break;
        case 'k': opt_k = 1; break;
        case 'd': opt_d = 1; break;
        case 'c': com_name = optarg; break;
        case 'f': com_file = optarg; break;
        case 'h':
            show_usage();
            return 0;
        default:
            show_usage();
            return 1;
        }
    }

    if (!com_name && !opt_g) {
        show_usage();
        return 0;
    }

    if (opt_g && com_name) {
        struct com_info info;
        if (get_com_info(com_name, &info) == 0) {
            printf("process: %s\n", info.name);
            printf("pid: %d\n", info.pid);
            printf("state: %s\n", info.state);
            if (info.dependent[0])
                printf("Dependentapp:%s\n", info.dependent);
            if (info.attach_list[0])
                printf("AttachList:%s\n", info.attach_list);
        } else {
            fprintf(stderr, "Failed to get info for %s\n", com_name);
            return 1;
        }
    }

    (void)opt_r;
    (void)opt_k;
    (void)opt_d;
    (void)com_file;

    return 0;
}
