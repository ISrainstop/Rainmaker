/*
 * csdev :: sha256.c  --  SHA-256 (FIPS-180-4) + HMAC-SHA256 (RFC 2104)
 * ==========================================================================
 * 完全自实现, 不含任何第三方代码。
 * ==========================================================================
 */
#include "crypto.h"

static const unsigned int K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)     (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BSIG1(x)     (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SSIG0(x)     (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SSIG1(x)     (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static void sha256_block(sha256_ctx *c, const unsigned char *p)
{
    unsigned int w[64];
    unsigned int a, b, cc, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned int)p[i * 4] << 24) | ((unsigned int)p[i * 4 + 1] << 16) |
               ((unsigned int)p[i * 4 + 2] << 8) | (unsigned int)p[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
    }

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5];  g = c->state[6];  h = c->state[7];

    for (i = 0; i < 64; i++) {
        unsigned int t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        unsigned int t2 = BSIG0(a) + MAJ(a, b, cc);
        h = g; g = f; f = e;
        e = d + t1;
        d = cc; cc = b; b = a;
        a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g;  c->state[7] += h;
}

void sha256_init(sha256_ctx *c)
{
    c->state[0] = 0x6a09e667u; c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u; c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu; c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu; c->state[7] = 0x5be0cd19u;
    c->bits = 0;
    c->buflen = 0;
}

void sha256_update(sha256_ctx *c, const unsigned char *data, unsigned int len)
{
    unsigned int i = 0;

    c->bits += (unsigned long long)len * 8u;

    if (c->buflen > 0) {
        while (i < len && c->buflen < 64) c->buf[c->buflen++] = data[i++];
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
    while (len - i >= 64) {
        sha256_block(c, data + i);
        i += 64;
    }
    while (i < len) c->buf[c->buflen++] = data[i++];
}

void sha256_final(sha256_ctx *c, unsigned char out[SHA256_DIGEST])
{
    unsigned long long bits = c->bits;
    unsigned int i;
    unsigned char pad = 0x80;

    sha256_update(c, &pad, 1);
    pad = 0x00;
    while (c->buflen != 56) sha256_update(c, &pad, 1);

    /* 长度域 (大端 64 位) —— 直接写入缓冲, 绕过 update 的计数 */
    for (i = 0; i < 8; i++) {
        c->buf[56 + i] = (unsigned char)(bits >> (56 - 8 * i));
    }
    sha256_block(c, c->buf);
    c->buflen = 0;

    for (i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char)(c->state[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->state[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->state[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c->state[i]);
    }
}

void sha256(const unsigned char *data, unsigned int len, unsigned char out[SHA256_DIGEST])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* -------------------------------------------------------------------- HMAC */

#define IPAD 0x36
#define OPAD 0x5C

void hmac_init(hmac_ctx *c, const unsigned char *key, unsigned int keylen)
{
    unsigned char k[64];
    unsigned char pad[64];
    unsigned char tk[32];
    unsigned int i;

    for (i = 0; i < 64; i++) k[i] = 0;

    if (keylen > 64) {
        sha256(key, keylen, tk);
        for (i = 0; i < 32; i++) k[i] = tk[i];
    } else {
        for (i = 0; i < keylen; i++) k[i] = key[i];
    }

    for (i = 0; i < 64; i++) pad[i] = (unsigned char)(k[i] ^ IPAD);
    sha256_init(&c->inner);
    sha256_update(&c->inner, pad, 64);

    for (i = 0; i < 64; i++) pad[i] = (unsigned char)(k[i] ^ OPAD);
    sha256_init(&c->outer);
    sha256_update(&c->outer, pad, 64);

    /* 清理栈上的密钥副本 */
    for (i = 0; i < 64; i++) { k[i] = 0; pad[i] = 0; }
    for (i = 0; i < 32; i++) tk[i] = 0;
}

void hmac_update(hmac_ctx *c, const unsigned char *data, unsigned int len)
{
    sha256_update(&c->inner, data, len);
}

void hmac_final(hmac_ctx *c, unsigned char out[HMAC_SHA256_SIZE])
{
    unsigned char inner[32];
    sha256_final(&c->inner, inner);
    sha256_update(&c->outer, inner, 32);
    sha256_final(&c->outer, out);
}

void hmac_sha256(const unsigned char *key, unsigned int keylen,
                 const unsigned char *data, unsigned int datalen,
                 unsigned char out[HMAC_SHA256_SIZE])
{
    hmac_ctx c;
    hmac_init(&c, key, keylen);
    hmac_update(&c, data, datalen);
    hmac_final(&c, out);
}

/* -------------------------------------------------------------- 常数时间比较 */

int csdev_ct_equal(const unsigned char *a, const unsigned char *b, unsigned int len)
{
    unsigned char diff = 0;
    unsigned int i;
    for (i = 0; i < len; i++) diff = (unsigned char)(diff | (a[i] ^ b[i]));
    return diff == 0;
}
