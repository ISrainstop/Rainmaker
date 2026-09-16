/*
 * csdev :: rsa_linux.h  --  Linux 侧 RSA-2048 公钥加密 (自研, 不依赖 OpenSSL)
 * ==========================================================================
 * kits/crypto/rsa.c 是 Windows CryptoAPI 版本 (ADVAPI32), Linux 上没有对应
 * 实现, 本文件提供同签名的替换, 并额外暴露 BLOB 解析接口供自测使用。
 *
 * 契约 (docs/protocol_v2.md 第 1.2 节):
 *   输入  PUBLICKEYBLOB (CryptoAPI 布局, 模数为**小端**)
 *   输出  PKCS#1 v1.5 密文, **大端**, 固定 256 字节
 *
 * 字节序陷阱 (kits/crypto/rsa.c 注释所述):
 *   CryptoAPI 的 CryptEncrypt 输出小端, Windows 侧因此手工反转了一次。
 *   标准 PKCS#1 / Go crypto/rsa / OpenSSL 一律为大端, 本实现直接按大端
 *   输出 —— **不得再次反转**, 否则 Go 侧 DecryptPKCS1v15 会报解密失败。
 * ==========================================================================
 */
#ifndef CSDEV_RSA_LINUX_H
#define CSDEV_RSA_LINUX_H

/* 与 kits/crypto/crypto.h 的声明保持一致 (同符号, 供 frame.c 调用)。
 * 用内嵌的 CryptoAPI PUBLICKEYBLOB 加密 (PKCS#1 v1.5)。
 * inlen 上限 245 字节 (2048 位密钥)。outcap 至少 256。
 * 返回 1 成功 (密文长度写入 outlen), 0 失败。 */
int rsa_encrypt_pub(const unsigned char *blob, unsigned int bloblen,
                    const unsigned char *in, unsigned int inlen,
                    unsigned char *out, unsigned int outcap, unsigned int *outlen);

/* CSPRNG: getrandom(2), 回退 /dev/urandom。返回 1 成功。 */
int csdev_random(unsigned char *buf, unsigned int len);

/* 生成会话密钥材料 (aes_key 32B + hmac_key 32B)。返回 1 成功。 */
int csdev_make_session_keys(unsigned char aes_key[32], unsigned char hmac_key[32]);

/* 解析 PUBLICKEYBLOB, 把模数转成**大端**字节串写出。
 * mod_be 容量需 >= 256。成功返回 1, 模长写入 *modlen, 公钥指数写入 *pubexp。
 * 供 rsa_selftest 构造测试向量使用。 */
int rsa_blob_modulus(const unsigned char *blob, unsigned int bloblen,
                     unsigned char *mod_be, unsigned int cap,
                     unsigned int *modlen, unsigned int *pubexp);

/* 用给定的**大端**模数与指数加密 (绕过 BLOB), 供自测构造任意测试密钥。
 * 返回 1 成功。 */
int rsa_encrypt_raw(const unsigned char *mod_be, unsigned int modlen,
                    unsigned int pubexp,
                    const unsigned char *in, unsigned int inlen,
                    unsigned char *out, unsigned int outcap, unsigned int *outlen);

#endif /* CSDEV_RSA_LINUX_H */
