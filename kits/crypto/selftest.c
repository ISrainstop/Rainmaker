/*
 * csdev :: selftest.c  --  密码学库标准向量自检
 * ==========================================================================
 * 编译 (MinGW):
 *   gcc -O2 -o selftest.exe selftest.c aes.c sha256.c rsa.c -ladvapi32
 *
 * 向量来源:
 *   AES 块加密   FIPS-197 附录 C.3
 *   AES-CBC      NIST SP 800-38A F.2.5
 *   SHA-256      FIPS-180-4 示例 ("abc" / "")
 *   HMAC-SHA256  RFC 4231 Test Case 1 / 2
 *   RSA          往返验证 (用内嵌公钥, 若存在 pubkey.h)
 *
 * 退出码 0 = 全部通过。
 * ==========================================================================
 */
#include <stdio.h>
#include <string.h>

#include "crypto.h"

static int g_pass = 0;
static int g_fail = 0;

static void hex2bin(const char *hex, unsigned char *out, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned int v;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (unsigned char)v;
    }
}

static void check(const char *name, const unsigned char *got, const char *want_hex, int n)
{
    unsigned char want[128];
    hex2bin(want_hex, want, n);
    if (memcmp(got, want, (size_t)n) == 0) {
        printf("  [PASS] %s\n", name);
        g_pass++;
    } else {
        int i;
        printf("  [FAIL] %s\n         got  ", name);
        for (i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n         want %s\n", want_hex);
        g_fail++;
    }
}

static void check_int(const char *name, int got, int want)
{
    if (got == want) { printf("  [PASS] %s\n", name); g_pass++; }
    else { printf("  [FAIL] %s  got=%d want=%d\n", name, got, want); g_fail++; }
}

/* ------------------------------------------------------------------ AES */

static void test_aes_block(void)
{
    unsigned char key[32], pt[16], ct[16], back[16];
    aes256_ctx c;

    printf("[AES-256 单块] FIPS-197 C.3\n");
    hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
    hex2bin("00112233445566778899aabbccddeeff", pt, 16);

    aes256_init(&c, key);
    aes256_encrypt_block(&c, pt, ct);
    check("加密", ct, "8ea2b7ca516745bfeafc49904b496089", 16);

    aes256_decrypt_block(&c, ct, back);
    check("解密还原", back, "00112233445566778899aabbccddeeff", 16);
}

static void test_aes_cbc(void)
{
    unsigned char key[32], iv[16], pt[64], ct[128], back[128];
    int n, m;

    printf("[AES-256-CBC] NIST SP 800-38A F.2.5\n");
    hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 32);
    hex2bin("000102030405060708090a0b0c0d0e0f", iv, 16);
    hex2bin("6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710", pt, 64);

    n = aes256_cbc_encrypt(key, iv, pt, 64, ct);
    check_int("密文长度 (4 块 + 填充块)", n, 80);

    /* NIST 向量为无填充模式, 故只比对前 64 字节 */
    check("前 4 块密文", ct, "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                             "9cfc4e967edb808d679f777bc6702c7d"
                             "39f23369a9d9bacfa530e26304231461"
                             "b2eb05e2c39be9fcda6c19078c6a9d1b", 64);

    m = aes256_cbc_decrypt(key, iv, ct, (unsigned int)n, back);
    check_int("解密长度", m, 64);
    check("解密还原", back, "6bc1bee22e409f96e93d7e117393172a"
                            "ae2d8a571e03ac9c9eb76fac45af8e51"
                            "30c81c46a35ce411e5fbc1191a0a52ef"
                            "f69f2445df4f9b17ad2b417be66c3710", 64);
}

static void test_aes_roundtrip(void)
{
    unsigned char key[32], iv[16], pt[600], ct[640], back[640];
    unsigned int lens[8];
    int i, n, m;

    printf("[AES-CBC 往返] 边界长度\n");
    lens[0] = 0; lens[1] = 1; lens[2] = 15; lens[3] = 16;
    lens[4] = 17; lens[5] = 31; lens[6] = 32; lens[7] = 600;

    for (i = 0; i < 32; i++) key[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < 16; i++) iv[i] = (unsigned char)(i * 11 + 1);
    for (i = 0; i < 600; i++) pt[i] = (unsigned char)(i & 0xFF);

    for (i = 0; i < 8; i++) {
        char label[64];
        n = aes256_cbc_encrypt(key, iv, pt, lens[i], ct);
        m = aes256_cbc_decrypt(key, iv, ct, (unsigned int)n, back);
        sprintf(label, "len=%u 往返", lens[i]);
        if (m == (int)lens[i] && memcmp(pt, back, lens[i]) == 0) {
            printf("  [PASS] %s (密文 %d)\n", label, n);
            g_pass++;
        } else {
            printf("  [FAIL] %s  m=%d\n", label, m);
            g_fail++;
        }
    }

    /* 篡改填充必须被拒 */
    {
        unsigned char bad[64];
        n = aes256_cbc_encrypt(key, iv, pt, 20, ct);
        memcpy(bad, ct, (size_t)n);
        bad[n - 1] ^= 0xFF;
        check_int("篡改填充被拒", aes256_cbc_decrypt(key, iv, bad, (unsigned int)n, back), -1);
    }
    /* 非块对齐密文必须被拒 */
    check_int("非对齐密文被拒", aes256_cbc_decrypt(key, iv, ct, 15, back), -1);
}

/* --------------------------------------------------------------- SHA-256 */

static void test_sha256(void)
{
    unsigned char d[32];

    printf("[SHA-256] FIPS-180-4\n");
    sha256((const unsigned char *)"abc", 3, d);
    check("sha256(\"abc\")", d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);

    sha256((const unsigned char *)"", 0, d);
    check("sha256(\"\")", d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);

    sha256((const unsigned char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    check("sha256(448bit 消息)", d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 32);

    /* 长消息跨块 + 分段喂入 一致性 */
    {
        unsigned char big[1000];
        unsigned char d1[32], d2[32];
        sha256_ctx c;
        int i;
        for (i = 0; i < 1000; i++) big[i] = (unsigned char)(i & 0xFF);
        sha256(big, 1000, d1);
        sha256_init(&c);
        sha256_update(&c, big, 1);
        sha256_update(&c, big + 1, 300);
        sha256_update(&c, big + 301, 699);
        sha256_final(&c, d2);
        check_int("分段更新一致", memcmp(d1, d2, 32) == 0, 1);
    }
}

/* ---------------------------------------------------------------- HMAC */

static void test_hmac(void)
{
    unsigned char k1[20], d[32];

    printf("[HMAC-SHA256] RFC 4231\n");
    memset(k1, 0x0b, sizeof(k1));
    hmac_sha256(k1, 20, (const unsigned char *)"Hi There", 8, d);
    check("TC1", d, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32);

    hmac_sha256((const unsigned char *)"Jefe", 4, (const unsigned char *)"what do ya want for nothing?", 28, d);
    check("TC2", d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32);
}

/* ------------------------------------------------------------------ RSA */

#ifdef CSDEV_HAVE_PUBKEY
#include "pubkey.h"
static void test_rsa(void)
{
    unsigned char pt[80], ct[256], rand_aes[32];
    unsigned int ctlen = 0;
    int i;

    printf("[RSA-2048] 公钥加密\n");
    if (!csdev_make_session_keys(rand_aes, pt)) { printf("  [FAIL] CSPRNG\n"); g_fail++; return; }
    for (i = 0; i < 32; i++) pt[i] = rand_aes[i];
    for (i = 32; i < 64; i++) pt[i] = (unsigned char)(0xA0 + i);

    check_int("加密 (64 字节明文)",
              rsa_encrypt_pub(CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN, pt, 64, ct, sizeof(ct), &ctlen), 1);
    check_int("密文长度 = 256", (int)ctlen, 256);

    {
        unsigned char too_long[246];
        unsigned int o = 0;
        memset(too_long, 0x41, sizeof(too_long));
        check_int("超长明文被拒 (246 > 245)",
                  rsa_encrypt_pub(CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN, too_long, 246, ct, sizeof(ct), &o), 0);
    }
}
#endif

/* ----------------------------------------------------------------- main */

int main(void)
{
    printf("csdev crypto selftest\n");
    printf("================================================\n");

    test_aes_block();
    test_aes_cbc();
    test_aes_roundtrip();
    test_sha256();
    test_hmac();
#ifdef CSDEV_HAVE_PUBKEY
    test_rsa();
#else
    printf("[RSA-2048] 跳过 (未定义 CSDEV_HAVE_PUBKEY)\n");
#endif

    printf("================================================\n");
    printf("PASS %d   FAIL %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
