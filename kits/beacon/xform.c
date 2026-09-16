/*
 * csdev :: xform.c  --  Malleable profile body 变换实现
 * ==========================================================================
 * 算法与 go/profile/model.go 严格对应:
 *
 *   base64     标准字母表 + '=' 填充
 *   base64url  URL 安全字母表, 去填充
 *   netbios    每字节 → ('a'+高4位, 'a'+低4位)
 *   netbiosu   同上但用 'A'
 *   mask       先逐字节 XOR 0x2E, 再 base64
 *
 * 解码侧容忍: base64 的缺失填充与空白字符; netbios 的大小写差异。
 * ==========================================================================
 */
#include "xform.h"

static void xcopy(void *d, const void *s, unsigned int n)
{
    unsigned char *a = (unsigned char *)d;
    const unsigned char *b = (const unsigned char *)s;
    while (n--) *a++ = *b++;
}

static const char B64STD[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int xform_kind(const char *name)
{
    if (!name || !name[0]) return XF_NONE;

    /* 内容变换 */
    if (name[0] == 'b') {
        if (name[7] == 'u' || name[7] == 'U') return XF_BASE64U;
        return XF_BASE64;
    }
    if (name[0] == 'n') {
        if (name[7] == 'u' || name[7] == 'U') return XF_NETBIOSU;
        return XF_NETBIOS;
    }
    if (name[0] == 'm' && name[1] == 'a' && name[2] == 's') return XF_MASK;

    /* 放置类与恒等: 对 body 编解码而言是空操作, 不计入链 */
    if (name[0] == 'r' && name[1] == 'a' && name[2] == 'w') return XF_NONE;
    if (name[0] == 'p') return XF_NONE;   /* print / parameter */
    if (name[0] == 'h') return XF_NONE;   /* header */
    if (name[0] == 'u') return XF_NONE;   /* uri-append */
    if (name[0] == 'a') return XF_NONE;   /* append */
    if (name[0] == 's') return XF_NONE;   /* strrep */

    return -1;
}

int xform_chain_parse(xform_chain *c, const char *spec)
{
    int n = 0;
    char buf[64];
    unsigned int bi = 0;
    unsigned int i;

    c->n = 0;
    if (!spec || !spec[0]) return 0;

    for (i = 0; ; i++) {
        char ch = spec[i];
        if (ch == '+' || ch == 0 || bi >= sizeof(buf) - 1) {
            int k;
            buf[bi] = 0;
            if (bi > 0) {
                k = xform_kind(buf);
                if (k < 0) return 1;
                if (k != XF_NONE) {
                    if (n >= XF_MAX_CHAIN) return 1;
                    c->kinds[n++] = k;
                }
            }
            bi = 0;
            if (ch == 0) break;
            continue;
        }
        buf[bi++] = ch;
    }
    c->n = n;
    return 0;
}

/* ---------------------------------------------------------------- base64 */

static int b64_index(char ch)
{
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+' || ch == '-') return 62;
    if (ch == '/' || ch == '_') return 63;
    return -1;
}

static int b64_encode(const unsigned char *in, unsigned int inlen,
                      unsigned char *out, unsigned int outcap, unsigned int *outlen,
                      int url, int pad)
{
    const char *tab = url ? B64URL : B64STD;
    unsigned int need = ((inlen + 2) / 3) * 4;
    unsigned int i = 0, o = 0;

    if (outcap < need + 1) return 2;

    while (i + 3 <= inlen) {
        unsigned int v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8) | in[i + 2];
        out[o++] = (unsigned char)tab[(v >> 18) & 0x3F];
        out[o++] = (unsigned char)tab[(v >> 12) & 0x3F];
        out[o++] = (unsigned char)tab[(v >> 6) & 0x3F];
        out[o++] = (unsigned char)tab[v & 0x3F];
        i += 3;
    }
    if (inlen - i == 1) {
        unsigned int v = (unsigned int)in[i] << 16;
        out[o++] = (unsigned char)tab[(v >> 18) & 0x3F];
        out[o++] = (unsigned char)tab[(v >> 12) & 0x3F];
        if (pad) { out[o++] = '='; out[o++] = '='; }
    } else if (inlen - i == 2) {
        unsigned int v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8);
        out[o++] = (unsigned char)tab[(v >> 18) & 0x3F];
        out[o++] = (unsigned char)tab[(v >> 12) & 0x3F];
        out[o++] = (unsigned char)tab[(v >> 6) & 0x3F];
        if (pad) out[o++] = '=';
    }
    *outlen = o;
    return 0;
}

static int b64_decode(const unsigned char *in, unsigned int inlen,
                      unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    unsigned int i, o = 0;
    unsigned int acc = 0;
    int bits = 0;

    for (i = 0; i < inlen; i++) {
        int v;
        char ch = (char)in[i];
        if (ch == '=') break;
        v = b64_index(ch);
        if (v < 0) {
            /* 容忍空白 (profile 里的 print 与换行) */
            if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') continue;
            return 3;
        }
        acc = (acc << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outcap) return 2;
            out[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    *outlen = o;
    return 0;
}

/* --------------------------------------------------------------- netbios */

static int nb_encode(const unsigned char *in, unsigned int inlen,
                     unsigned char *out, unsigned int outcap, unsigned int *outlen,
                     unsigned char base)
{
    unsigned int i, o = 0;

    if (outcap < inlen * 2u + 1u) return 2;
    for (i = 0; i < inlen; i++) {
        out[o++] = (unsigned char)(base + (in[i] >> 4));
        out[o++] = (unsigned char)(base + (in[i] & 0x0F));
    }
    *outlen = o;
    return 0;
}

static int nb_decode(const unsigned char *in, unsigned int inlen,
                     unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    unsigned int i, o = 0;

    if (inlen & 1u) return 3;                 /* 长度必须为偶数 */

    for (i = 0; i + 1 < inlen; i += 2) {
        int hi, lo;
        char a = (char)in[i], b = (char)in[i + 1];

        if (a >= 'A' && a <= 'P') hi = a - 'A';
        else if (a >= 'a' && a <= 'p') hi = a - 'a';
        else return 3;

        if (b >= 'A' && b <= 'P') lo = b - 'A';
        else if (b >= 'a' && b <= 'p') lo = b - 'a';
        else return 3;

        if (o >= outcap) return 2;
        out[o++] = (unsigned char)((hi << 4) | lo);
    }
    *outlen = o;
    return 0;
}

/* ------------------------------------------------------------------ mask */

static int mask_xor(const unsigned char *in, unsigned int inlen,
                    unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    unsigned int i;
    if (outcap < inlen + 1) return 2;
    for (i = 0; i < inlen; i++) out[i] = (unsigned char)(in[i] ^ 0x2E);
    *outlen = inlen;
    return 0;
}

/* ------------------------------------------------------------- 单级分发 */

int xform_one(int kind, int decode, const unsigned char *in, unsigned int inlen,
              unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    switch (kind) {
    case XF_NONE:
        if (outcap < inlen + 1) return 2;
        xcopy(out, in, inlen);
        *outlen = inlen;
        return 0;

    case XF_BASE64:
        if (!decode) return b64_encode(in, inlen, out, outcap, outlen, 0, 1);
        return b64_decode(in, inlen, out, outcap, outlen);

    case XF_BASE64U:
        if (!decode) return b64_encode(in, inlen, out, outcap, outlen, 1, 0);
        return b64_decode(in, inlen, out, outcap, outlen);

    case XF_NETBIOS:
        if (!decode) return nb_encode(in, inlen, out, outcap, outlen, 'a');
        return nb_decode(in, inlen, out, outcap, outlen);

    case XF_NETBIOSU:
        if (!decode) return nb_encode(in, inlen, out, outcap, outlen, 'A');
        return nb_decode(in, inlen, out, outcap, outlen);

    case XF_MASK:
        {
            /* mask = XOR 0x2E 后 base64。编码: xor → b64; 解码: b64 → xor */
            static unsigned char tmp[1u << 20];
            unsigned int tlen = 0;
            int rc;
            if (!decode) {
                rc = mask_xor(in, inlen, tmp, sizeof(tmp), &tlen);
                if (rc) return rc;
                return b64_encode(tmp, tlen, out, outcap, outlen, 0, 1);
            }
            rc = b64_decode(in, inlen, tmp, sizeof(tmp), &tlen);
            if (rc) return rc;
            return mask_xor(tmp, tlen, out, outcap, outlen);
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ 链式 */

/* 链式变换的中间缓冲。免杀考虑: 不引入 malloc, 用一次性 VirtualAlloc。 */
#ifdef _WIN32
#include <windows.h>
static unsigned char *xbuf(void)
{
    static unsigned char *p = 0;
    if (!p) p = (unsigned char *)VirtualAlloc(NULL, 8u << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return p;
}
#else
#include <stdlib.h>
static unsigned char *xbuf(void)
{
    static unsigned char *p = 0;
    if (!p) p = (unsigned char *)malloc(8u << 20);
    return p;
}
#endif

int xform_encode(const xform_chain *c, const unsigned char *in, unsigned int inlen,
                 unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    const unsigned char *cur = in;
    unsigned int curlen = inlen;
    unsigned char *buf = xbuf();
    int i, rc;

    if (c->n == 0) {
        if (outcap < inlen + 1) return 2;
        xcopy(out, in, inlen);
        *outlen = inlen;
        return 0;
    }
    if (!buf) return 1;

    for (i = 0; i < c->n; i++) {
        unsigned int olen = 0;
        int last = (i == c->n - 1);
        unsigned char *dst = last ? out : (buf + ((i & 1) ? 0 : (4u << 20)));
        unsigned int cap = last ? outcap : (4u << 20);

        rc = xform_one(c->kinds[i], 0, cur, curlen, dst, cap, &olen);
        if (rc) return rc;

        /* 结果回抄到另一块半区, 供下一级读取 (避免原地覆盖) */
        if (!last) {
            unsigned char *other = buf + ((i & 1) ? (4u << 20) : 0);
            xcopy(other, dst, olen);
            cur = other;
            curlen = olen;
        } else {
            *outlen = olen;
        }
    }
    return 0;
}

int xform_decode(const xform_chain *c, const unsigned char *in, unsigned int inlen,
                 unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    const unsigned char *cur = in;
    unsigned int curlen = inlen;
    unsigned char *buf = xbuf();
    int i, rc;

    if (c->n == 0) {
        if (outcap < inlen + 1) return 2;
        xcopy(out, in, inlen);
        *outlen = inlen;
        return 0;
    }
    if (!buf) return 1;

    /* 逆序解码 */
    for (i = c->n - 1; i >= 0; i--) {
        unsigned int olen = 0;
        int last = (i == 0);
        unsigned char *dst = last ? out : (buf + ((i & 1) ? 0 : (4u << 20)));
        unsigned int cap = last ? outcap : (4u << 20);

        rc = xform_one(c->kinds[i], 1, cur, curlen, dst, cap, &olen);
        if (rc) return rc;

        if (!last) {
            unsigned char *other = buf + ((i & 1) ? (4u << 20) : 0);
            xcopy(other, dst, olen);
            cur = other;
            curlen = olen;
        } else {
            *outlen = olen;
        }
    }
    return 0;
}
