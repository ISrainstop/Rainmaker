/*
 * csdev :: crypto.h  --  自研密码学库 (AES-256-CBC / SHA-256 / HMAC-SHA256 / RSA)
 * ==========================================================================
 * 设计约束 (见 docs/protocol_v2.md 第 0 节):
 *   植入体侧不得引入新 DLL 依赖 —— 本库除 CryptoAPI (ADVAPI32, 已在导入表)
 *   外不依赖任何外部实现, AES/SHA256/HMAC 全部自实现。
 *
 * 免杀考虑:
 *   AES S-box 不静态存放, 运行期由 GF(2^8) 乘法逆 + 仿射变换生成,
 *   避免静态 S-box 表成为可被 YARA 匹配的特征。
 * ==========================================================================
 */
#ifndef CSDEV_CRYPTO_H
#define CSDEV_CRYPTO_H

#define AES_BLOCK_SIZE   16
#define AES256_KEY_SIZE  32
#define SHA256_DIGEST    32
#define HMAC_SHA256_SIZE 32

/* ---------------------------------------------------------------- AES-256 */

typedef struct {
    unsigned char rk[240];   /* 15 组轮密钥 × 16 字节 */
} aes256_ctx;

void aes256_init(aes256_ctx *c, const unsigned char key[AES256_KEY_SIZE]);
void aes256_encrypt_block(const aes256_ctx *c, const unsigned char in[AES_BLOCK_SIZE],
                          unsigned char out[AES_BLOCK_SIZE]);
void aes256_decrypt_block(const aes256_ctx *c, const unsigned char in[AES_BLOCK_SIZE],
                          unsigned char out[AES_BLOCK_SIZE]);

/* CBC + PKCS#7。
 * 加密: out 容量至少 ((len / 16) + 1) * 16，返回密文长度。
 * 解密: out 容量至少 len，返回明文长度；返回 -1 表示长度非法或填充校验失败。 */
int aes256_cbc_encrypt(const unsigned char key[AES256_KEY_SIZE],
                       const unsigned char iv[AES_BLOCK_SIZE],
                       const unsigned char *in, unsigned int len,
                       unsigned char *out);
int aes256_cbc_decrypt(const unsigned char key[AES256_KEY_SIZE],
                       const unsigned char iv[AES_BLOCK_SIZE],
                       const unsigned char *in, unsigned int len,
                       unsigned char *out);

/* ---------------------------------------------------------------- SHA-256 */

typedef struct {
    unsigned int  state[8];
    unsigned long long bits;
    unsigned char buf[64];
    unsigned int  buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const unsigned char *data, unsigned int len);
void sha256_final(sha256_ctx *c, unsigned char out[SHA256_DIGEST]);
void sha256(const unsigned char *data, unsigned int len, unsigned char out[SHA256_DIGEST]);

/* ------------------------------------------------------------ HMAC-SHA256 */

void hmac_sha256(const unsigned char *key, unsigned int keylen,
                 const unsigned char *data, unsigned int datalen,
                 unsigned char out[HMAC_SHA256_SIZE]);

/* 分段 HMAC: 用于 "帧头 || IV || 密文" 这类多段输入, 避免额外拼接缓冲 */
typedef struct {
    sha256_ctx inner;
    sha256_ctx outer;
} hmac_ctx;

void hmac_init(hmac_ctx *c, const unsigned char *key, unsigned int keylen);
void hmac_update(hmac_ctx *c, const unsigned char *data, unsigned int len);
void hmac_final(hmac_ctx *c, unsigned char out[HMAC_SHA256_SIZE]);

/* ---------------------------------------------------------------- 随机数 */

/* CSPRNG (CryptGenRandom)。返回 1 成功, 0 失败。 */
int csdev_random(unsigned char *buf, unsigned int len);

/* ------------------------------------------------------------------- RSA */

/* 用内嵌的 CryptoAPI PUBLICKEYBLOB 加密 (PKCS#1 v1.5)。
 * inlen 上限 245 字节 (2048 位密钥)。outcap 至少 256。
 * 返回 1 成功 (密文长度写入 outlen), 0 失败。 */
int rsa_encrypt_pub(const unsigned char *blob, unsigned int bloblen,
                    const unsigned char *in, unsigned int inlen,
                    unsigned char *out, unsigned int outcap, unsigned int *outlen);

/* 常数时间比较, 返回 1 相等 */
int csdev_ct_equal(const unsigned char *a, const unsigned char *b, unsigned int len);

/* ------------------------------------------------------------ 便捷封装 */

/* 生成会话密钥材料 (aes_key 32B + hmac_key 32B) */
int csdev_make_session_keys(unsigned char aes_key[32], unsigned char hmac_key[32]);

#endif /* CSDEV_CRYPTO_H */
