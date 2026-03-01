/*
 * ConvertLog2Dst.c  –  Convert firmware log format to readable output
 *
 * Decompiled from: /bin/ConvertLog2Dst (9500 bytes, ARM32, V500R022)
 * Imports: HW_OS_Printf, HW_OS_Fopen, HW_OS_Fclose, HW_OS_Fread, HW_OS_IsFileAccess,
 *          HW_OS_MemMallocD, HW_OS_MemFreeD, HW_OS_GetFileSize,
 *          HW_CFGTOOL_SysTrace, HW_PROC_DBG_LastWord
 *
 * Format string: "%04d-%02d-%02d %02d:%02d:%02d" (timestamp from .rodata)
 * Format string: "%s %s" (output format)
 * Format string: "ddddsddsddbddcddcddb" (field descriptor from .rodata)
 *
 * Usage: ConvertLog2Dst srcPath dstPath
 *
 * Original: Reads binary-format log files from the router's flash
 * and converts them to human-readable text with timestamps.
 *
 * The log format uses packed binary records with the field descriptor
 * "ddddsddsddbddcddcddb" where:
 *   d = 4-byte int (DWORD), s = string, b = byte, c = char
 *
 * Standalone: Reads binary log, outputs formatted text.
 *
 * Build: cc -o ConvertLog2Dst ConvertLog2Dst.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* Log record header (from binary analysis):
 * Each record has a fixed header followed by variable-length message.
 * The timestamp is stored as 6 separate DWORD fields (year, month, day, hour, min, sec).
 */
#pragma pack(push, 1)
struct log_record_header {
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
    uint32_t level;
    uint32_t module_id;
    uint32_t msg_len;
};
#pragma pack(pop)

static void show_usage(void)
{
    printf("ConvertLog2Dst Usage: \n"
           "ConvertLog2Dst srcPath dstPath: \n");
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        show_usage();
        return 1;
    }

    const char *src_path = argv[1];
    const char *dst_path = argv[2];

    FILE *src = fopen(src_path, "rb");
    if (!src) {
        fprintf(stderr, "Error: cannot open %s\n", src_path);
        return 1;
    }

    FILE *dst = fopen(dst_path, "w");
    if (!dst) {
        fprintf(stderr, "Error: cannot create %s\n", dst_path);
        fclose(src);
        return 1;
    }

    /* Get file size */
    fseek(src, 0, SEEK_END);
    long file_size = ftell(src);
    fseek(src, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Error: empty file %s\n", src_path);
        fclose(src);
        fclose(dst);
        return 1;
    }

    /* Read and convert records */
    int record_count = 0;
    while (ftell(src) < file_size) {
        struct log_record_header hdr;

        if (fread(&hdr, sizeof(hdr), 1, src) != 1)
            break;

        /* Sanity check timestamp */
        if (hdr.year > 2100 || hdr.month > 12 || hdr.day > 31) {
            /* Not a valid record header - try to find next valid one */
            /* Skip forward one byte and retry */
            fseek(src, -(long)(sizeof(hdr) - 1), SEEK_CUR);
            continue;
        }

        /* Read message */
        uint32_t msg_len = hdr.msg_len;
        if (msg_len > 4096) msg_len = 4096;

        char *msg = (char *)malloc(msg_len + 1);
        if (!msg) break;

        size_t read_len = fread(msg, 1, msg_len, src);
        msg[read_len] = '\0';

        /* Strip trailing newlines */
        while (read_len > 0 && (msg[read_len-1] == '\n' || msg[read_len-1] == '\r'))
            msg[--read_len] = '\0';

        /* Output formatted record (matches original "%04d-%02d-%02d %02d:%02d:%02d" format) */
        fprintf(dst, "%04u-%02u-%02u %02u:%02u:%02u [%u/%u] %s\n",
                hdr.year, hdr.month, hdr.day,
                hdr.hour, hdr.minute, hdr.second,
                hdr.level, hdr.module_id, msg);

        free(msg);
        record_count++;
    }

    fclose(src);
    fclose(dst);

    printf("Converted %d records from %s to %s\n", record_count, src_path, dst_path);
    return 0;
}
