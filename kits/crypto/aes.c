/*
 * csdev :: aes.c  --  AES-256 (FIPS-197) + CBC/PKCS#7
 * ==========================================================================
 * 完全自实现, 不含任何第三方代码。
 *
 * 免杀设计:
 *   S-box / 逆 S-box 不在二进制中静态存在, 首次调用时由
 *   GF(2^8) 乘法逆 + 仿射变换生成 (S(x) = inv(x) ^ rotl(inv,1) ^
 *   rotl(inv,2) ^ rotl(inv,3) ^ rotl(inv,4) ^ 0x63)。
 * ==========================================================================
 */
#include "crypto.h"

static unsigned char g_sbox[256];
static unsigned char g_rsbox[256];
static volatile int  g_tables_ready = 0;

/* ---------------------------------------------------------------- GF(2^8) */

static unsigned char gf_mul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        {
            unsigned char hi = (unsigned char)(a & 0x80);
            a = (unsigned char)(a << 1);
            if (hi) a ^= 0x1B;
        }
        b = (unsigned char)(b >> 1);
    }
    return p;
}

/* x * y = 1 的 y; x = 0 时约定返回 0 (AES 规范) */
static unsigned char gf_inv(unsigned char x)
{
    unsigned int i;
    if (x == 0) return 0;
    for (i = 1; i < 256; i++) {
        if (gf_mul(x, (unsigned char)i) == 1) return (unsigned char)i;
    }
    return 0;
}

static unsigned char rotl8(unsigned char x, int n)
{
    return (unsigned char)((x << n) | (x >> (8 - n)));
}

static void build_tables(void)
{
    unsigned int i;
    if (g_tables_ready) return;
    for (i = 0; i < 256; i++) {
        unsigned char inv = gf_inv((unsigned char)i);
        unsigned char s = (unsigned char)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^
                                          rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
        g_sbox[i] = s;
        g_rsbox[s] = (unsigned char)i;
    }
    g_tables_ready = 1;
}

/* ------------------------------------------------------------- 密钥扩展 */

void aes256_init(aes256_ctx *c, const unsigned char key[AES256_KEY_SIZE])
{
    static const unsigned char rcon[8] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    unsigned int i;
    unsigned char t[4];
    int k;

    build_tables();

    for (i = 0; i < 32; i++) c->rk[i] = key[i];

    for (i = 8; i < 60; i++) {
        unsigned char *w = c->rk + i * 4;
        const unsigned char *p = c->rk + (i - 1) * 4;

        t[0] = p[0]; t[1] = p[1]; t[2] = p[2]; t[3] = p[3];

        if ((i & 7) == 0) {
            /* SubWord(RotWord(t)) ^ Rcon */
            unsigned char keep = t[0];
            t[0] = (unsigned char)(g_sbox[t[1]] ^ rcon[(i >> 3) - 1]);
            t[1] = g_sbox[t[2]];
            t[2] = g_sbox[t[3]];
            t[3] = g_sbox[keep];
        } else if ((i & 7) == 4) {
            /* AES-256 专有: 第 4 字额外做一次 SubWord */
            for (k = 0; k < 4; k++) t[k] = g_sbox[t[k]];
        }

        for (k = 0; k < 4; k++)
            w[k] = (unsigned char)(c->rk[(i - 8) * 4 + k] ^ t[k]);
    }
}

/* ---------------------------------------------------------------- 加解密 */

static void add_round_key(unsigned char s[16], const unsigned char *rk)
{
    int i;
    for (i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void sub_bytes(unsigned char s[16])
{
    int i;
    for (i = 0; i < 16; i++) s[i] = g_sbox[s[i]];
}

static void inv_sub_bytes(unsigned char s[16])
{
    int i;
    for (i = 0; i < 16; i++) s[i] = g_rsbox[s[i]];
}

/* state 列主序: 索引 = 行 + 4 * 列 */
static void shift_rows(unsigned char s[16])
{
    unsigned char t[16];
    int r, cc;
    for (cc = 0; cc < 4; cc++)
        for (r = 0; r < 4; r++)
            t[r + 4 * cc] = s[r + 4 * ((cc + r) & 3)];
    for (r = 0; r < 16; r++) s[r] = t[r];
}

static void inv_shift_rows(unsigned char s[16])
{
    unsigned char t[16];
    int r, cc;
    for (cc = 0; cc < 4; cc++)
        for (r = 0; r < 4; r++)
            t[r + 4 * cc] = s[r + 4 * ((cc - r + 4) & 3)];
    for (r = 0; r < 16; r++) s[r] = t[r];
}

static void mix_columns(unsigned char s[16])
{
    int cc;
    for (cc = 0; cc < 4; cc++) {
        unsigned char *p = s + 4 * cc;
        unsigned char a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        unsigned char all = (unsigned char)(a0 ^ a1 ^ a2 ^ a3);
        p[0] = (unsigned char)(a0 ^ all ^ gf_mul((unsigned char)(a0 ^ a1), 2));
        p[1] = (unsigned char)(a1 ^ all ^ gf_mul((unsigned char)(a1 ^ a2), 2));
        p[2] = (unsigned char)(a2 ^ all ^ gf_mul((unsigned char)(a2 ^ a3), 2));
        p[3] = (unsigned char)(a3 ^ all ^ gf_mul((unsigned char)(a3 ^ a0), 2));
    }
}

static void inv_mix_columns(unsigned char s[16])
{
    int cc;
    for (cc = 0; cc < 4; cc++) {
        unsigned char *p = s + 4 * cc;
        unsigned char a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = (unsigned char)(gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^
                               gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09));
        p[1] = (unsigned char)(gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^
                               gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D));
        p[2] = (unsigned char)(gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^
                               gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B));
        p[3] = (unsigned char)(gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^
                               gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E));
    }
}

void aes256_encrypt_block(const aes256_ctx *c, const unsigned char in[AES_BLOCK_SIZE],
                          unsigned char out[AES_BLOCK_SIZE])
{
    unsigned char s[16];
    int round, i;

    for (i = 0; i < 16; i++) s[i] = in[i];

    add_round_key(s, c->rk);
    for (round = 1; round < 14; round++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, c->rk + round * 16);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, c->rk + 14 * 16);

    for (i = 0; i < 16; i++) out[i] = s[i];
}

void aes256_decrypt_block(const aes256_ctx *c, const unsigned char in[AES_BLOCK_SIZE],
                          unsigned char out[AES_BLOCK_SIZE])
{
    unsigned char s[16];
    int round, i;

    for (i = 0; i < 16; i++) s[i] = in[i];

    add_round_key(s, c->rk + 14 * 16);
    for (round = 13; round > 0; round--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, c->rk + round * 16);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, c->rk);

    for (i = 0; i < 16; i++) out[i] = s[i];
}

/* --------------------------------------------------------------- CBC/PKCS7 */

int aes256_cbc_encrypt(const unsigned char key[AES256_KEY_SIZE],
                       const unsigned char iv[AES_BLOCK_SIZE],
                       const unsigned char *in, unsigned int len,
                       unsigned char *out)
{
    aes256_ctx c;
    unsigned char prev[16], tmp[16], last[16];
    unsigned int off = 0, outlen = 0, i, rem, padlen;

    aes256_init(&c, key);
    for (i = 0; i < 16; i++) prev[i] = iv[i];

    while (len - off >= 16) {
        for (i = 0; i < 16; i++) tmp[i] = (unsigned char)(in[off + i] ^ prev[i]);
        aes256_encrypt_block(&c, tmp, out + outlen);
        for (i = 0; i < 16; i++) prev[i] = out[outlen + i];
        off += 16;
        outlen += 16;
    }

    /* 尾部 + PKCS#7 填充, 总是产生最后一块 (len 为 16 倍数时填充整块 0x10) */
    rem = len - off;                 /* 0..15 */
    padlen = 16 - rem;               /* 1..16 */
    for (i = 0; i < rem; i++) last[i] = in[off + i];
    for (i = rem; i < 16; i++) last[i] = (unsigned char)padlen;
    for (i = 0; i < 16; i++) tmp[i] = (unsigned char)(last[i] ^ prev[i]);
    aes256_encrypt_block(&c, tmp, out + outlen);
    outlen += 16;

    return (int)outlen;
}

int aes256_cbc_decrypt(const unsigned char key[AES256_KEY_SIZE],
                       const unsigned char iv[AES_BLOCK_SIZE],
                       const unsigned char *in, unsigned int len,
                       unsigned char *out)
{
    aes256_ctx c;
    unsigned char prev[16], tmp[16];
    unsigned int off, i, pad;
    int first = 1;

    if (len == 0 || (len & 15) != 0) return -1;

    aes256_init(&c, key);

    for (off = 0; off < len; off += 16) {
        aes256_decrypt_block(&c, in + off, tmp);
        if (first) {
            for (i = 0; i < 16; i++) out[off + i] = (unsigned char)(tmp[i] ^ iv[i]);
            first = 0;
        } else {
            for (i = 0; i < 16; i++) out[off + i] = (unsigned char)(tmp[i] ^ prev[i]);
        }
        for (i = 0; i < 16; i++) prev[i] = in[off + i];
    }

    pad = out[len - 1];
    if (pad == 0 || pad > 16 || pad > len) return -1;
    for (i = len - pad; i < len; i++) {
        if (out[i] != pad) return -1;
    }
    return (int)(len - pad);
}
