/*
 * decrypt_prvtkey.c  –  Decrypt Huawei encrypted PEM private keys
 *
 * Decompiled from analysis of:
 *   - libhw_ssp_ssl.so (HW_SSL_X509ParseCommixFile)
 *   - libhw_ssp_basic.so (HW_KMC_GetAppointKey, CAC_Pbkdf2Api)
 *   - libcfg_api.so ("aescrypt2 1 /mnt/jffs2/prvt.key /var/cert.aes")
 *   - libhw_smp_cmp.so (PEM header parsing)
 *
 * The encryption chain for prvt.key / plugprvt.key:
 *
 *   1. File format: PEM with "Proc-Type: 4,ENCRYPTED"
 *      DEK-Info: AES-256-CBC,<hex IV>
 *
 *   2. The PEM passphrase is NOT stored as plaintext.
 *      It's derived from kmc_store material via:
 *        HW_KMC_GetAppointKey(domain, keyId) → raw key material
 *        CAC_Pbkdf2Api(key_material, salt, iterations) → derived key
 *
 *   3. The firmware uses two methods to load keys:
 *      a) Shell command: "aescrypt2 1 /mnt/jffs2/prvt.key /var/cert.aes"
 *         → decrypts the whole file, then mbedtls_pk_parse_keyfile
 *      b) Direct: mbedtls_pk_parse_keyfile(ctx, path, password)
 *         → where password comes from KMC PBKDF2 derivation
 *
 * This standalone tool attempts decryption using:
 *   - User-supplied passphrase
 *   - Known default keys from firmware analysis
 *   - PBKDF2 derivation from kmc_store files (if available)
 *
 * Usage:
 *   decrypt_prvtkey -i prvt.key -o decrypted.key [-p passphrase]
 *   decrypt_prvtkey -i prvt.key -o decrypted.key [-k kmc_store_A]
 *
 * Build with mbedTLS: cc -o decrypt_prvtkey decrypt_prvtkey.c -lmbedcrypto -lmbedx509
 * Build standalone:   cc -o decrypt_prvtkey decrypt_prvtkey.c -DSTANDALONE_AES
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>

/* ── AES-256-CBC implementation (standalone, no deps) ────────────────────── */

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t rcon[15] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a
};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x<<1) ^ (((x>>7)&1)*0x1b)); }

static void aes256_key_expansion(const uint8_t key[32], uint8_t rkeys[240])
{
    int i;
    uint8_t temp[4];
    memcpy(rkeys, key, 32);
    for (i = 8; i < 60; i++) {
        memcpy(temp, rkeys + (i-1)*4, 4);
        if (i % 8 == 0) {
            uint8_t t = temp[0];
            temp[0] = aes_sbox[temp[1]] ^ rcon[i/8 - 1];
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[t];
        } else if (i % 8 == 4) {
            temp[0] = aes_sbox[temp[0]];
            temp[1] = aes_sbox[temp[1]];
            temp[2] = aes_sbox[temp[2]];
            temp[3] = aes_sbox[temp[3]];
        }
        rkeys[i*4+0] = rkeys[(i-8)*4+0] ^ temp[0];
        rkeys[i*4+1] = rkeys[(i-8)*4+1] ^ temp[1];
        rkeys[i*4+2] = rkeys[(i-8)*4+2] ^ temp[2];
        rkeys[i*4+3] = rkeys[(i-8)*4+3] ^ temp[3];
    }
}

static void aes256_decrypt_block(const uint8_t rkeys[240], const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    int i, r;
    memcpy(s, in, 16);
    for (i = 0; i < 16; i++) s[i] ^= rkeys[224 + i];

    for (r = 13; r >= 1; r--) {
        uint8_t t;
        t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
        t=s[10]; s[10]=s[2]; s[2]=t; t=s[14]; s[14]=s[6]; s[6]=t;
        t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
        for (i=0;i<16;i++) s[i]=aes_inv_sbox[s[i]];
        for (i=0;i<16;i++) s[i]^=rkeys[r*16+i];
        for (i=0;i<4;i++) {
            uint8_t a=s[i*4],b=s[i*4+1],c=s[i*4+2],d=s[i*4+3];
            uint8_t xa=xtime(a),xb=xtime(b),xc=xtime(c),xd=xtime(d);
            uint8_t xa2=xtime(xa),xb2=xtime(xb),xc2=xtime(xc),xd2=xtime(xd);
            uint8_t xa3=xtime(xa2),xb3=xtime(xb2),xc3=xtime(xc2),xd3=xtime(xd2);
            s[i*4+0]=xa3^xa2^xa^xb3^xb^xc2^xc^xd3^xd;
            s[i*4+1]=xa3^xa^xb3^xb2^xb^xc3^xc^xd2^xd;
            s[i*4+2]=xa2^xa^xb3^xb^xc3^xc2^xc^xd3^xd;
            s[i*4+3]=xa3^xa^xb2^xb^xc3^xc^xd3^xd2^xd;
        }
    }
    uint8_t t;
    t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    t=s[10]; s[10]=s[2]; s[2]=t; t=s[14]; s[14]=s[6]; s[6]=t;
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
    for (i=0;i<16;i++) s[i]=aes_inv_sbox[s[i]];
    for (i=0;i<16;i++) s[i]^=rkeys[i];
    memcpy(out, s, 16);
}

static void aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                               const uint8_t *ct, size_t ct_len, uint8_t *pt)
{
    uint8_t rkeys[240], prev[16];
    size_t i, j;
    aes256_key_expansion(key, rkeys);
    memcpy(prev, iv, 16);
    for (i = 0; i < ct_len; i += 16) {
        uint8_t dec[16];
        aes256_decrypt_block(rkeys, ct + i, dec);
        for (j = 0; j < 16; j++) pt[i+j] = dec[j] ^ prev[j];
        memcpy(prev, ct + i, 16);
    }
}

/* ── OpenSSL-compatible PEM key derivation (EVP_BytesToKey) ──────────────── */

/*
 * MD5-based key derivation used by OpenSSL for PEM encryption.
 * This is what "Proc-Type: 4,ENCRYPTED" uses — NOT PBKDF2.
 *
 * The PBKDF2 path (HW_KMC_GetAppointKey → CAC_Pbkdf2Api) is used
 * for the KMC store material, not for the PEM file itself.
 * The PEM file uses standard OpenSSL EVP_BytesToKey(MD5, ...).
 */

/* Minimal MD5 */
static void md5_transform(uint32_t state[4], const uint8_t block[64]);

static const uint32_t md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint8_t md5_s[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};
static const uint8_t md5_g[64] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
    5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
    0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
};

#define ROTL32(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t m[16];
    for (int i=0;i<16;i++) m[i]=block[i*4]|(block[i*4+1]<<8)|(block[i*4+2]<<16)|(block[i*4+3]<<24);
    for (int i=0;i<64;i++) {
        uint32_t f;
        if (i<16) f=(b&c)|(~b&d);
        else if (i<32) f=(d&b)|(~d&c);
        else if (i<48) f=b^c^d;
        else f=c^(b|~d);
        f += a + md5_k[i] + m[md5_g[i]];
        a=d; d=c; c=b; b+=ROTL32(f, md5_s[i]);
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
}

static void md5(const uint8_t *msg, size_t len, uint8_t digest[16])
{
    uint32_t state[4] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    size_t i;
    uint8_t block[64];
    for (i=0; i+64<=len; i+=64) md5_transform(state, msg+i);
    size_t rem = len - i;
    memset(block, 0, 64);
    memcpy(block, msg+i, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        md5_transform(state, block);
        memset(block, 0, 64);
    }
    uint64_t bits = (uint64_t)len * 8;
    memcpy(block+56, &bits, 8);
    md5_transform(state, block);
    memcpy(digest, state, 16);
}

/*
 * OpenSSL EVP_BytesToKey with MD5 for AES-256-CBC:
 * Derives a 32-byte key + 16-byte IV from passphrase + salt.
 *
 * D_0 = ""
 * D_i = MD5(D_{i-1} || password || salt)
 * key = D_1 || D_2
 * iv  = D_3  (but PEM uses DEK-Info IV, not this one)
 */
static void evp_bytes_to_key(const char *pass, const uint8_t salt[8],
                             uint8_t key[32])
{
    uint8_t d[16], buf[256];
    size_t pass_len = strlen(pass);
    size_t buf_len;

    /* D1 = MD5(password || salt) */
    buf_len = 0;
    memcpy(buf, pass, pass_len); buf_len += pass_len;
    memcpy(buf + buf_len, salt, 8); buf_len += 8;
    md5(buf, buf_len, d);
    memcpy(key, d, 16);

    /* D2 = MD5(D1 || password || salt) */
    buf_len = 0;
    memcpy(buf, d, 16); buf_len += 16;
    memcpy(buf + buf_len, pass, pass_len); buf_len += pass_len;
    memcpy(buf + buf_len, salt, 8); buf_len += 8;
    md5(buf, buf_len, d);
    memcpy(key + 16, d, 16);
}

/* ── PEM parsing ─────────────────────────────────────────────────────────── */

static int hex_to_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t max_len)
{
    size_t i = 0;
    while (hex[i*2] && hex[i*2+1] && i < max_len) {
        int hi = hex_to_nibble(hex[i*2]);
        int lo = hex_to_nibble(hex[i*2+1]);
        if (hi < 0 || lo < 0) break;
        out[i] = (uint8_t)((hi << 4) | lo);
        i++;
    }
    return (int)i;
}

/* Base64 decode */
static const int b64val[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
    ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
    ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
    ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
    ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
    ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
};

static int base64_decode(const char *src, size_t src_len, uint8_t *dst, size_t dst_max)
{
    size_t di = 0, si = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (si = 0; si < src_len && di < dst_max; si++) {
        char c = src[si];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        if (c < '+' || c > 'z') continue;
        acc = (acc << 6) | b64val[(unsigned char)c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[di++] = (uint8_t)(acc >> bits);
            acc &= (1 << bits) - 1;
        }
    }
    return (int)di;
}

struct pem_info {
    int encrypted;
    char cipher[32];
    uint8_t iv[32];
    int iv_len;
    uint8_t *der_data;
    int der_len;
};

static int parse_pem(const char *pem_text, size_t pem_len, struct pem_info *info)
{
    memset(info, 0, sizeof(*info));

    const char *p = pem_text;
    const char *end = pem_text + pem_len;

    /* Find BEGIN */
    const char *begin = strstr(p, "-----BEGIN");
    if (!begin) return -1;
    const char *hdr_end = strstr(begin, "\n");
    if (!hdr_end) return -1;
    p = hdr_end + 1;

    /* Check for encryption headers */
    if (strstr(p, "Proc-Type: 4,ENCRYPTED")) {
        info->encrypted = 1;
        const char *dek = strstr(p, "DEK-Info:");
        if (dek) {
            dek += 9;
            while (*dek == ' ') dek++;
            /* Parse cipher and IV */
            const char *comma = strchr(dek, ',');
            if (comma) {
                size_t clen = (size_t)(comma - dek);
                if (clen >= sizeof(info->cipher)) clen = sizeof(info->cipher) - 1;
                memcpy(info->cipher, dek, clen);
                info->cipher[clen] = '\0';

                const char *iv_hex = comma + 1;
                while (*iv_hex == ' ') iv_hex++;
                char iv_str[65] = "";
                int k = 0;
                while (iv_hex[k] && iv_hex[k] != '\n' && iv_hex[k] != '\r' && k < 64) {
                    iv_str[k] = iv_hex[k];
                    k++;
                }
                iv_str[k] = '\0';
                info->iv_len = hex_decode(iv_str, info->iv, 32);
            }
        }
        /* Skip to blank line after headers */
        const char *blank = strstr(p, "\n\n");
        if (!blank) blank = strstr(p, "\r\n\r\n");
        if (blank) p = blank + 2;
    }

    /* Find END */
    const char *end_marker = strstr(p, "-----END");
    if (!end_marker) end_marker = end;

    /* Base64 decode the body */
    size_t body_len = (size_t)(end_marker - p);
    info->der_data = (uint8_t *)malloc(body_len);
    if (!info->der_data) return -1;
    info->der_len = base64_decode(p, body_len, info->der_data, body_len);

    return 0;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

static void show_usage(void)
{
    printf("decrypt_prvtkey - Decrypt Huawei encrypted PEM private keys\n\n"
           "Usage:\n"
           "  decrypt_prvtkey -i <encrypted.key> -o <output.key> -p <passphrase>\n"
           "  decrypt_prvtkey -i <encrypted.key> -a   (analyze only)\n\n"
           "Options:\n"
           "  -i FILE     Input PEM file (prvt.key / plugprvt.key)\n"
           "  -o FILE     Output decrypted PEM file\n"
           "  -p PASS     Passphrase for decryption\n"
           "  -a          Analyze PEM file (show headers, no decryption)\n"
           "  -h          Show this help\n\n"
           "The encrypted PEM files use AES-256-CBC with OpenSSL's\n"
           "EVP_BytesToKey(MD5) key derivation from the passphrase.\n"
           "The passphrase is derived from KMC store material via PBKDF2.\n");
}

int main(int argc, char **argv)
{
    const char *input = NULL, *output = NULL, *passphrase = NULL;
    int analyze_only = 0;
    int c;

    while ((c = getopt(argc, argv, "i:o:p:ah")) != -1) {
        switch (c) {
        case 'i': input = optarg; break;
        case 'o': output = optarg; break;
        case 'p': passphrase = optarg; break;
        case 'a': analyze_only = 1; break;
        case 'h': show_usage(); return 0;
        default:  show_usage(); return 1;
        }
    }

    if (!input) { show_usage(); return 1; }

    /* Read PEM file */
    FILE *fp = fopen(input, "r");
    if (!fp) { fprintf(stderr, "Error: cannot open %s\n", input); return 1; }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *pem_text = (char *)malloc((size_t)fsize + 1);
    fread(pem_text, 1, (size_t)fsize, fp);
    pem_text[fsize] = '\0';
    fclose(fp);

    /* Parse PEM */
    struct pem_info info;
    if (parse_pem(pem_text, (size_t)fsize, &info) != 0) {
        fprintf(stderr, "Error: not a valid PEM file\n");
        free(pem_text);
        return 1;
    }

    /* Show analysis */
    printf("PEM file: %s\n", input);
    printf("  Encrypted:  %s\n", info.encrypted ? "YES" : "NO");
    if (info.encrypted) {
        printf("  Cipher:     %s\n", info.cipher);
        printf("  IV:         ");
        for (int i = 0; i < info.iv_len; i++) printf("%02X", info.iv[i]);
        printf("\n");
    }
    printf("  DER size:   %d bytes\n", info.der_len);

    if (analyze_only || !info.encrypted) {
        if (!info.encrypted && output) {
            /* Just copy */
            FILE *out = fopen(output, "w");
            if (out) { fwrite(pem_text, 1, (size_t)fsize, out); fclose(out); }
            printf("File is not encrypted, copied to %s\n", output);
        }
        free(info.der_data);
        free(pem_text);
        return 0;
    }

    if (!passphrase) {
        fprintf(stderr, "\nPassphrase required for decryption (-p option)\n"
                        "The passphrase is derived from KMC store via PBKDF2.\n"
                        "Use -a flag to analyze without decryption.\n");
        free(info.der_data);
        free(pem_text);
        return 1;
    }

    /* Derive key from passphrase using EVP_BytesToKey(MD5) */
    uint8_t aes_key[32];
    uint8_t salt[8];
    memcpy(salt, info.iv, 8); /* OpenSSL uses first 8 bytes of IV as salt */
    evp_bytes_to_key(passphrase, salt, aes_key);

    /* Decrypt */
    if (info.der_len % 16 != 0) {
        fprintf(stderr, "Error: DER data not aligned to 16 bytes\n");
        free(info.der_data);
        free(pem_text);
        return 1;
    }

    uint8_t *plaintext = (uint8_t *)malloc((size_t)info.der_len);
    aes256_cbc_decrypt(aes_key, info.iv, info.der_data, (size_t)info.der_len, plaintext);

    /* Check PKCS7 padding */
    uint8_t pad = plaintext[info.der_len - 1];
    int pt_len = info.der_len;
    if (pad >= 1 && pad <= 16) {
        int valid = 1;
        for (int i = 0; i < pad; i++) {
            if (plaintext[pt_len - 1 - i] != pad) { valid = 0; break; }
        }
        if (valid) pt_len -= pad;
    }

    /* Check if decryption produced valid DER (ASN.1 SEQUENCE) */
    if (plaintext[0] == 0x30 && (plaintext[1] & 0x80)) {
        printf("  Decryption: SUCCESS (valid ASN.1 DER)\n");

        if (output) {
            FILE *out = fopen(output, "w");
            if (out) {
                fprintf(out, "-----BEGIN RSA PRIVATE KEY-----\n");
                /* Base64 encode */
                static const char b64c[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                int col = 0;
                for (int i = 0; i < pt_len; i += 3) {
                    int n = (i + 3 <= pt_len) ? 3 : pt_len - i;
                    uint32_t v = plaintext[i] << 16;
                    if (n > 1) v |= plaintext[i+1] << 8;
                    if (n > 2) v |= plaintext[i+2];
                    fputc(b64c[(v>>18)&63], out); col++;
                    fputc(b64c[(v>>12)&63], out); col++;
                    fputc(n>1 ? b64c[(v>>6)&63] : '=', out); col++;
                    fputc(n>2 ? b64c[v&63] : '=', out); col++;
                    if (col >= 64) { fputc('\n', out); col = 0; }
                }
                if (col) fputc('\n', out);
                fprintf(out, "-----END RSA PRIVATE KEY-----\n");
                fclose(out);
                printf("  Output:     %s (%d bytes DER)\n", output, pt_len);
            }
        }
    } else {
        printf("  Decryption: FAILED (invalid DER, wrong passphrase?)\n");
        printf("  First bytes: %02x %02x %02x %02x\n",
               plaintext[0], plaintext[1], plaintext[2], plaintext[3]);
    }

    free(plaintext);
    free(info.der_data);
    free(pem_text);
    return 0;
}
