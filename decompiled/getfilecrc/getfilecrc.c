/*
 * getfilecrc.c  –  Calculate CRC32 of a file
 *
 * Decompiled from: /bin/getfilecrc (9392 bytes, ARM32, V500R022)
 * Source file: (no source reference in .rodata)
 *
 * This binary uses ONLY standard libc: fopen, ftell, fread, fseek, malloc, free, printf
 * No HW_ imports at all — it's a pure CRC32 calculator.
 *
 * The CRC32 implementation uses the standard Ethernet polynomial (0xEDB88320).
 * This is the same CRC used by the firmware to verify config files and key data.
 *
 * Usage: getfilecrc <filepath>
 * Output: prints "0xABCDEF12" (CRC32 hex value)
 *
 * Build: cc -o getfilecrc getfilecrc.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * CRC32 lookup table (Ethernet/ZIP polynomial 0xEDB88320).
 * This is the standard implementation used across all Huawei firmware
 * for config file integrity checks (hw_ctree.xml, hw_boardinfo, etc.)
 */
static uint32_t crc32_table[256];
static int crc32_table_init = 0;

static void crc32_init(void)
{
    uint32_t i, j, crc;
    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320U;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    crc32_table_init = 1;
}

static uint32_t crc32_calc(const unsigned char *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFU;
    size_t i;

    if (!crc32_table_init)
        crc32_init();

    for (i = 0; i < len; i++)
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);

    return crc ^ 0xFFFFFFFFU;
}

int main(int argc, char **argv)
{
    FILE *fp;
    unsigned char *buf;
    long file_size;
    size_t read_size;
    uint32_t crc;

    if (argc < 2) {
        printf("Please input file path.\n");
        return 1;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("Error: cannot open %s\n", argv[1]);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        printf("Error: empty file\n");
        fclose(fp);
        return 1;
    }

    buf = (unsigned char *)malloc((size_t)file_size);
    if (!buf) {
        printf("Error: out of memory\n");
        fclose(fp);
        return 1;
    }

    read_size = fread(buf, 1, (size_t)file_size, fp);
    fclose(fp);

    crc = crc32_calc(buf, read_size);
    printf("0x%08x\n", crc);

    free(buf);
    return 0;
}
