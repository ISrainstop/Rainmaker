/*
 * csdev :: rsa_probe.c  --  RSA 加密互通性探针
 * ==========================================================================
 * 用途: 定位 C 侧 CryptoAPI 公钥加密与 Go/.NET 私钥解密的互操作问题。
 *       输出 (明文, 密文) 十六进制到 stdout, 由外部脚本用私钥解密比对。
 *
 * 编译:
 *   gcc -O2 -I..\kits\beacon -o rsa_probe.exe rsa_probe.c ..\kits\crypto\rsa.c \
 *       ..\kits\crypto\aes.c ..\kits\crypto\sha256.c -ladvapi32
 * ==========================================================================
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "pubkey.h"
#include "crypto.h"

int main(void)
{
    unsigned char pt[64];
    unsigned char ct[512];
    unsigned int  ctlen = 0;
    int i;

    for (i = 0; i < 64; i++) pt[i] = (unsigned char)i;

    if (!rsa_encrypt_pub(CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN, pt, 64, ct, sizeof(ct), &ctlen)) {
        printf("FAIL encrypt\n");
        return 1;
    }

    printf("BLOB_LEN %d\n", CSDEV_PUBKEY_LEN);
    printf("CT_LEN %u\n", ctlen);
    printf("PT ");
    for (i = 0; i < 64; i++) printf("%02x", pt[i]);
    printf("\nCT ");
    for (i = 0; i < (int)ctlen; i++) printf("%02x", ct[i]);
    printf("\n");
    return 0;
}
