/*
 * csdev :: rsa_selftest.c  --  RSA 向量自测 (C 侧加密端)
 * ==========================================================================
 * 交叉验证链 (tools/linux_e2e.ps1 / linux/rsa_crosscheck.py 驱动):
 *
 *   embedded <plain_hex>
 *       用内嵌的 CSDEV_PUBKEY_BLOB (即服务端 data/csdev.key 对应的公钥)
 *       加密, 密文 hex 输出到 stdout。期望能被服务端私钥解开 —— 这是
 *       "植入体能否真的上线" 的密码学前提。
 *
 *   custom <mod_hex_be> <exp_dec> <plain_hex>
 *       用任意测试模数加密。先用给定的 n/e 反向拼出 CryptoAPI
 *       PUBLICKEYBLOB 再走正式接口, 顺便验证 BLOB 解析路径。
 *
 * 输出: stdout 只打印密文 hex (便于脚本解析), 诊断信息走 stderr。
 * ==========================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsa_linux.h"
#include "../kits/beacon/pubkey.h"

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned int hex2bin(const char *hex, unsigned char *out, unsigned int cap)
{
    unsigned int n = 0, i = 0, len;

    if (!hex) return 0;
    len = (unsigned int)strlen(hex);
    while (i + 1 < len && n < cap) {
        int hi = hexval((unsigned char)hex[i]);
        int lo = hexval((unsigned char)hex[i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[n++] = (unsigned char)((hi << 4) | lo);
        i += 2;
    }
    return n;
}

static void bin2hex(const unsigned char *b, unsigned int n)
{
    static const char *H = "0123456789abcdef";
    unsigned int i;

    for (i = 0; i < n; i++) {
        putchar(H[(b[i] >> 4) & 0xF]);
        putchar(H[b[i] & 0xF]);
    }
    putchar('\n');
}

/* 用给定的大端模数/指数拼出 CryptoAPI PUBLICKEYBLOB (2048 位) */
static unsigned int build_blob(const unsigned char *mod_be, unsigned int modlen,
                               unsigned int pubexp, unsigned char *blob)
{
    unsigned int i, bits = modlen * 8u;

    memset(blob, 0, 20u + modlen);

    blob[0] = 0x06;                     /* bType = PUBLICKEYBLOB */
    blob[1] = 0x02;                     /* bVersion = 2 */
    /* aiKeyAlg = CALG_RSA_KEYX = 0x0000A400, 小端 */
    blob[4] = 0x00; blob[5] = 0xA4; blob[6] = 0x00; blob[7] = 0x00;

    blob[8]  = 'R'; blob[9] = 'S'; blob[10] = 'A'; blob[11] = '1';
    /* bitlen, 小端 */
    blob[12] = (unsigned char)(bits & 0xFFu);
    blob[13] = (unsigned char)((bits >> 8) & 0xFFu);
    blob[14] = (unsigned char)((bits >> 16) & 0xFFu);
    blob[15] = (unsigned char)((bits >> 24) & 0xFFu);
    /* pubexp, 小端 */
    blob[16] = (unsigned char)(pubexp & 0xFFu);
    blob[17] = (unsigned char)((pubexp >> 8) & 0xFFu);
    blob[18] = (unsigned char)((pubexp >> 16) & 0xFFu);
    blob[19] = (unsigned char)((pubexp >> 24) & 0xFFu);

    /* 模数转回**小端**存放 */
    for (i = 0; i < modlen; i++) {
        blob[20u + i] = mod_be[modlen - 1u - i];
    }
    return 20u + modlen;
}

static void usage(void)
{
    fprintf(stderr,
        "用法:\n"
        "  rsa_selftest embedded <plain_hex>                (内嵌服务端公钥)\n"
        "  rsa_selftest custom <mod_hex_be> <exp_dec> <plain_hex>\n");
}

int main(int argc, char **argv)
{
    unsigned char plain[512];
    unsigned char ct[512];
    unsigned int  plen = 0, ctlen = 0;

    if (argc < 3) { usage(); return 2; }

    if (strcmp(argv[1], "embedded") == 0) {
        unsigned char mod_be[256];
        unsigned int modlen = 0, exp = 0;

        if (!rsa_blob_modulus(CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN,
                              mod_be, sizeof(mod_be), &modlen, &exp)) {
            fprintf(stderr, "[-] 解析内嵌 PUBLICKEYBLOB 失败\n");
            return 3;
        }
        fprintf(stderr, "[*] embedded pubkey: %u 字节模数, e=%u, 指纹=%s\n",
                modlen, exp, CSDEV_PUBKEY_FINGERPRINT);

        plen = hex2bin(argv[2], plain, sizeof(plain));
        if (!plen) { fprintf(stderr, "[-] 明文 hex 解析失败\n"); return 3; }

        if (!rsa_encrypt_pub(CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN,
                             plain, plen, ct, sizeof(ct), &ctlen)) {
            fprintf(stderr, "[-] rsa_encrypt_pub 失败\n");
            return 4;
        }
    } else if (strcmp(argv[1], "custom") == 0) {
        unsigned char mod_be[256], blob[512];
        unsigned int  modlen, bloflen, exp;
        long e;

        if (argc < 5) { usage(); return 2; }

        modlen = hex2bin(argv[2], mod_be, sizeof(mod_be));
        if (!modlen) { fprintf(stderr, "[-] 模数 hex 解析失败\n"); return 3; }

        e = strtol(argv[3], NULL, 10);
        if (e <= 0 || e > 0xFFFFFFFFL) { fprintf(stderr, "[-] 指数非法\n"); return 3; }
        exp = (unsigned int)e;

        plen = hex2bin(argv[4], plain, sizeof(plain));
        if (!plen) { fprintf(stderr, "[-] 明文 hex 解析失败\n"); return 3; }

        bloflen = build_blob(mod_be, modlen, exp, blob);

        if (!rsa_encrypt_pub(blob, bloflen, plain, plen, ct, sizeof(ct), &ctlen)) {
            fprintf(stderr, "[-] rsa_encrypt_pub (custom) 失败\n");
            return 4;
        }
        fprintf(stderr, "[*] custom key: %u 字节模数, e=%u, blob=%u 字节\n",
                modlen, exp, bloflen);
    } else {
        usage();
        return 2;
    }

    fprintf(stderr, "[+] 明文 %u 字节 -> 密文 %u 字节\n", plen, ctlen);
    bin2hex(ct, ctlen);
    return 0;
}
