/*
 * csdev :: rsa_linux.c  --  自研 RSA-2048 / PKCS#1 v1.5 (无 OpenSSL 依赖)
 * ==========================================================================
 * 组成:
 *   1. 大数: 32 位 limb 小端数组, 2048 位 = 64 limb
 *   2. 模乘: 64x64 全宽乘法 (128 limb 中间积) + 二进制长除法约减
 *   3. 模幂: 平方-乘, 从指数最高有效位起
 *   4. 填充: PKCS#1 v1.5   EM = 00 || 02 || PS(非零随机, >=8B) || 00 || M
 *   5. CSPRNG: getrandom(2), 回退 /dev/urandom
 *
 * 性能说明: 公钥指数通常是 65537 (0x10001, 17 位), 平方-乘只需 16 次平方
 *   + 2 次模乘。二进制长除法约减在 2048 位上约 4096 次比较/减法迭代,
 *   单次加密约 20-40 ms —— 对每次上线只做一次密钥交换的植入体完全够用。
 *
 * 安全说明: PKCS#1 v1.5 加密使用公钥, 不存在时序侧信道问题;
 *   PS 用拒绝采样保证非零, 不做任何长度相关的分支优化。
 * ==========================================================================
 */
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/random.h>

#include "rsa_linux.h"

/* ---------------------------------------------------------------- 常量 */

#define BN_LIMBS 64                        /* 2048 / 32 */
#define RSA_BYTES 256                      /* 2048 / 8  */
#define RSA_MAX_PLAIN (RSA_BYTES - 11)     /* 245, PKCS#1 v1.5 上限 */

/* BLOBHEADER(8) + RSAPUBKEY(12) = 20 字节后才跟模数 */
#define BLOB_HDR_LEN 20

/* ---------------------------------------------------------------- 大数 */

typedef struct {
    uint32_t d[BN_LIMBS];   /* d[0] 为最低 32 位 */
} bn;

static void bn_zero(bn *x)
{
    int i;
    for (i = 0; i < BN_LIMBS; i++) x->d[i] = 0;
}

static void bn_from_be(bn *x, const unsigned char *be, unsigned int len)
{
    unsigned int i, j, k;

    bn_zero(x);
    /* be 为大端: be[len-1] 是最低字节。每 4 字节折成一个 limb。 */
    for (i = 0; i < BN_LIMBS; i++) {
        uint32_t v = 0;
        for (j = 0; j < 4; j++) {
            /* 该 limb 对应的字节索引 (从低位算): i*4 + j */
            unsigned int idx = i * 4u + j;
            if (idx >= len) break;
            k = len - 1u - idx;      /* 对应的大端数组下标 */
            v |= ((uint32_t)be[k]) << (8u * j);
        }
        x->d[i] = v;
    }
}

static void bn_to_be(const bn *x, unsigned char *be, unsigned int len)
{
    unsigned int i, j;

    for (i = 0; i < len; i++) be[i] = 0;
    for (i = 0; i < BN_LIMBS; i++) {
        uint32_t v = x->d[i];
        for (j = 0; j < 4; j++) {
            unsigned int idx = i * 4u + j;
            if (idx >= len) break;
            be[len - 1u - idx] = (unsigned char)((v >> (8u * j)) & 0xFFu);
        }
    }
}

/* 128 limb 全宽乘法: r = a * b */
static void bn_mul(uint32_t *r, const bn *a, const bn *b)
{
    int i, j;

    for (i = 0; i < 2 * BN_LIMBS; i++) r[i] = 0;

    for (i = 0; i < BN_LIMBS; i++) {
        uint64_t carry = 0;
        uint32_t ai = a->d[i];

        if (ai == 0) continue;   /* r[i+BN_LIMBS] 保持 0, 与逐位运算等价 */

        for (j = 0; j < BN_LIMBS; j++) {
            uint64_t cur = (uint64_t)r[i + j] + (uint64_t)ai * (uint64_t)b->d[j] + carry;
            r[i + j] = (uint32_t)cur;
            carry    = cur >> 32;
        }
        r[i + BN_LIMBS] = (uint32_t)carry;   /* 该位置此前从未被写过 */
    }
}

/* r(65 limb) >= m(64 limb, 高位补 0)? */
static int bn_ge65(const uint32_t *r, const bn *m)
{
    int j;

    if (r[BN_LIMBS] != 0) return 1;
    for (j = BN_LIMBS - 1; j >= 0; j--) {
        if (r[j] > m->d[j]) return 1;
        if (r[j] < m->d[j]) return 0;
    }
    return 1;   /* 相等 */
}

/* r(65 limb) -= m */
static void bn_sub65(uint32_t *r, const bn *m)
{
    uint64_t borrow = 0;
    int j;

    for (j = 0; j < BN_LIMBS; j++) {
        uint64_t sub = (uint64_t)m->d[j] + borrow;
        uint64_t cur = (uint64_t)r[j];
        borrow = (cur < sub) ? 1u : 0u;
        r[j] = (uint32_t)(cur - sub);
    }
    r[BN_LIMBS] = (uint32_t)((uint64_t)r[BN_LIMBS] - borrow);
}

/* out = x mod m, x 为 xlimbs 个 limb 的大数。
 * 二进制长除法: 从最高位逐位下沉, 每步保证 R < m, 故 R < 2^2048,
 * 用 65 个 limb (2080 位) 承载 R << 1 不丢位。 */
static void bn_mod_reduce(bn *out, const uint32_t *x, unsigned int xlimbs, const bn *m)
{
    uint32_t r[BN_LIMBS + 1];
    int i, j;
    unsigned int total_bits = xlimbs * 32u;

    for (j = 0; j <= BN_LIMBS; j++) r[j] = 0;

    for (i = (int)total_bits - 1; i >= 0; i--) {
        unsigned int bit = (x[(unsigned int)i >> 5] >> ((unsigned int)i & 31u)) & 1u;

        for (j = BN_LIMBS; j > 0; j--) {
            r[j] = (r[j] << 1) | (r[j - 1] >> 31);
        }
        r[0] = (r[0] << 1) | bit;

        if (bn_ge65(r, m)) bn_sub65(r, m);
    }

    for (j = 0; j < BN_LIMBS; j++) out->d[j] = r[j];
}

/* r = a * b mod m */
static void bn_modmul(bn *r, const bn *a, const bn *b, const bn *m)
{
    uint32_t prod[2 * BN_LIMBS];
    bn_mul(prod, a, b);
    bn_mod_reduce(r, prod, 2 * BN_LIMBS, m);
}

/* r = base^e mod m, e 为 32 位指数 */
static void bn_modpow(bn *r, const bn *base, uint32_t e, const bn *m)
{
    bn acc;
    int start, bit;

    if (e == 0) {          /* 约定 0 次幂 = 1 */
        bn_zero(&acc);
        acc.d[0] = 1;
        *r = acc;
        return;
    }

    start = 31;
    while (start > 0 && ((e >> start) & 1u) == 0) start--;

    acc = *base;
    for (bit = start - 1; bit >= 0; bit--) {
        bn_modmul(&acc, &acc, &acc, m);
        if ((e >> bit) & 1u) bn_modmul(&acc, &acc, base, m);
    }
    *r = acc;
}

/* ---------------------------------------------------------------- CSPRNG */

int csdev_random(unsigned char *buf, unsigned int len)
{
    unsigned int got = 0;

    if (!buf || len == 0) return 0;

    /* 首选 getrandom(2): 内核 CSPRNG, 不经过文件系统 */
    while (got < len) {
        ssize_t n = getrandom(buf + got, (size_t)(len - got), 0);
        if (n > 0) { got += (unsigned int)n; continue; }
        if (n < 0 && (errno == EINTR)) continue;
        break;   /* ENOSYS / EAGAIN 等 -> 回退 */
    }
    if (got == len) return 1;

    /* 回退 /dev/urandom */
    got = 0;
    {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        while (got < len) {
            ssize_t n = read(fd, buf + got, (size_t)(len - got));
            if (n > 0) { got += (unsigned int)n; continue; }
            if (n < 0 && errno == EINTR) continue;
            close(fd);
            return 0;
        }
        close(fd);
    }
    return 1;
}

int csdev_make_session_keys(unsigned char aes_key[32], unsigned char hmac_key[32])
{
    unsigned char both[64];
    int i;

    /* 一次取 64 字节, 前半 aes_key 后半 hmac_key (与 Windows 侧一致) */
    if (!csdev_random(both, sizeof(both))) return 0;

    for (i = 0; i < 32; i++) {
        aes_key[i]  = both[i];
        hmac_key[i] = both[32 + i];
    }
    {
        volatile unsigned char *v = both;
        for (i = 0; i < 64; i++) v[i] = 0;
    }
    return 1;
}

/* ------------------------------------------------------------ BLOB 解析 */

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int rsa_blob_modulus(const unsigned char *blob, unsigned int bloblen,
                     unsigned char *mod_be, unsigned int cap,
                     unsigned int *modlen, unsigned int *pubexp)
{
    unsigned int bitlen, bytes, i;

    if (!blob || !mod_be || !modlen || !pubexp) return 0;
    if (bloblen < BLOB_HDR_LEN) return 0;

    /* BLOBHEADER: bType 必须为 PUBLICKEYBLOB(0x06), bVersion 0x02 */
    if (blob[0] != 0x06 || blob[1] != 0x02) return 0;

    /* RSAPUBKEY: magic "RSA1" */
    if (blob[8] != 'R' || blob[9] != 'S' || blob[10] != 'A' || blob[11] != '1')
        return 0;

    bitlen = le32(blob + 12);
    if (bitlen != 2048) return 0;

    bytes = bitlen / 8u;
    if (bytes != RSA_BYTES) return 0;
    if (bloblen < BLOB_HDR_LEN + bytes) return 0;
    if (cap < bytes) return 0;

    *pubexp = le32(blob + 16);
    if (*pubexp == 0 || (*pubexp & 1u) == 0) return 0;   /* 指数必须为奇数 */

    /* 模数在 BLOB 中为**小端**, 反转为大端 */
    for (i = 0; i < bytes; i++) {
        mod_be[i] = blob[BLOB_HDR_LEN + bytes - 1u - i];
    }
    *modlen = bytes;
    return 1;
}

/* ---------------------------------------------------------------- 加密 */

static int rsa_encrypt_core(const unsigned char *mod_be, unsigned int modlen,
                            unsigned int pubexp,
                            const unsigned char *in, unsigned int inlen,
                            unsigned char *out, unsigned int outcap,
                            unsigned int *outlen)
{
    unsigned char em[RSA_BYTES];
    unsigned int pslen, i;
    bn n, m, c;

    if (!mod_be || !in || !out || !outlen) return 0;
    if (modlen != RSA_BYTES) return 0;
    if (outcap < modlen) return 0;
    if (inlen == 0 || inlen > RSA_MAX_PLAIN) return 0;
    if (pubexp == 0) return 0;

    bn_from_be(&n, mod_be, modlen);

    /* PKCS#1 v1.5: EM = 00 || 02 || PS || 00 || M, PS 长度 >= 8 且字节非零 */
    pslen = RSA_BYTES - 3u - inlen;

    em[0] = 0x00;
    em[1] = 0x02;
    for (i = 0; i < pslen; ) {
        unsigned char b;
        if (!csdev_random(&b, 1)) return 0;
        if (b == 0) continue;              /* 拒绝采样, 保证非零 */
        em[2 + i] = b;
        i++;
    }
    em[2 + pslen] = 0x00;
    if (inlen) memcpy(em + 3u + pslen, in, inlen);

    bn_from_be(&m, em, RSA_BYTES);
    bn_modpow(&c, &m, pubexp, &n);
    bn_to_be(&c, out, modlen);             /* 标准 PKCS#1: 大端输出 */

    /* 擦除中间明文 (含填充后的编码块) */
    {
        volatile unsigned char *v = em;
        for (i = 0; i < RSA_BYTES; i++) v[i] = 0;
    }

    *outlen = modlen;
    return 1;
}

int rsa_encrypt_raw(const unsigned char *mod_be, unsigned int modlen,
                    unsigned int pubexp,
                    const unsigned char *in, unsigned int inlen,
                    unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    return rsa_encrypt_core(mod_be, modlen, pubexp, in, inlen, out, outcap, outlen);
}

int rsa_encrypt_pub(const unsigned char *blob, unsigned int bloblen,
                    const unsigned char *in, unsigned int inlen,
                    unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    unsigned char mod_be[RSA_BYTES];
    unsigned int modlen = 0, pubexp = 0;

    if (!rsa_blob_modulus(blob, bloblen, mod_be, sizeof(mod_be), &modlen, &pubexp))
        return 0;

    return rsa_encrypt_core(mod_be, modlen, pubexp, in, inlen, out, outcap, outlen);
}
