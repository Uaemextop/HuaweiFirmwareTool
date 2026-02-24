/*
 * Cross-platform getopt compatibility header.
 *
 * On POSIX systems (Linux, macOS), delegates to <unistd.h>.
 * On Windows (MSVC), provides a minimal getopt() implementation.
 */
#ifndef COMPAT_GETOPT_H
#define COMPAT_GETOPT_H

#ifdef _WIN32

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static char *optarg = NULL;
static int optind = 1;
static int opterr = 1;
static int optopt = 0;

static int
getopt(int argc, char *const argv[], const char *optstring)
{
    static int sp = 1;

    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
        return -1;
    }

    if (!strcmp(argv[optind], "--")) {
        optind++;
        return -1;
    }

    int c = argv[optind][sp];
    const char *cp = strchr(optstring, c);

    if (c == ':' || cp == NULL) {
        optopt = c;
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }

    if (*(cp + 1) == ':') {
        if (argv[optind][sp + 1] != '\0') {
            optarg = &argv[optind++][sp + 1];
        } else if (++optind >= argc) {
            optopt = c;
            sp = 1;
            return '?';
        } else {
            optarg = argv[optind++];
        }
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }

    return c;
}

#ifdef __cplusplus
}
#endif

#else /* POSIX */

#include <unistd.h>

#endif /* _WIN32 */

#endif /* COMPAT_GETOPT_H */
