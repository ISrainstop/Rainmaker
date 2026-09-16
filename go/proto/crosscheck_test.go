// csdev :: proto/crosscheck_test.go  --  Go/C 跨实现交叉验证
//
// 目的: 证明 proto 包与 kits/crypto 在字节级完全一致, 特别是
// PUBLICKEYBLOB 能被真实的 Windows CryptoAPI (CryptImportKey) 接受,
// 且 CryptoAPI 用该 blob 加密的密文能由 Go 私钥解密。
//
// 依赖 gcc (MinGW-w64) 与 kits/crypto 源码; 任一不可用时自动跳过, 不影响 go test 全绿。
package proto

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// probeC 交叉验证探针: 只调用 kits/crypto 的公开接口, 输出全部为 hex 行。
const probeC = `
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "pubkey.h"

static void dump(const char *tag, const unsigned char *b, int n)
{
    int i;
    printf("%s=", tag);
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void)
{
    unsigned char pt[80], ct[256], out[256];
    unsigned char key[32], iv[16], hdr[20], mac[32];
    unsigned int ctlen = 0;
    int i, n;

    printf("BLOB_LEN=%d\n", CSDEV_PUBKEY_LEN);

    /* 1) CryptoAPI 用内嵌 PUBLICKEYBLOB 加密固定明文 */
    for (i = 0; i < 64; i++) pt[i] = (unsigned char)(i * 7 + 3);
    if (!rsa_encrypt_pub(CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN, pt, 64, ct, sizeof(ct), &ctlen)) {
        printf("RSA_FAIL\n");
        return 2;
    }
    dump("RSA_CT", ct, (int)ctlen);
    dump("RSA_PT", pt, 64);

    /* 2) AES-256-CBC + PKCS#7 (固定 key/iv, 供 Go 侧重算比对) */
    for (i = 0; i < 32; i++) key[i] = (unsigned char)(0x60 + i);
    for (i = 0; i < 16; i++) iv[i] = (unsigned char)i;
    for (i = 0; i < 64; i++) pt[i] = (unsigned char)(i ^ 0x5A);
    n = aes256_cbc_encrypt(key, iv, pt, 64, out);
    dump("AES_KEY", key, 32);
    dump("AES_IV", iv, 16);
    dump("AES_PT", pt, 64);
    dump("AES_CT", out, n);

    /* 3) 分段 HMAC: 自定义 key 覆盖 iv||密文 (模拟协议 2.2 的覆盖范围) */
    for (i = 0; i < 20; i++) hdr[i] = (unsigned char)(0xA0 + i);
    hmac_sha256(hdr, sizeof(hdr), out, 32, mac);
    dump("HMAC_KEY", hdr, sizeof(hdr));
    dump("HMAC_DATA", out, 32);
    dump("HMAC_OUT", mac, 32);

    return 0;
}
`

func TestCryptoAPICrossCheck(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("未找到 gcc, 跳过 Go/C 交叉验证")
	}
	kitsDir, err := filepath.Abs(filepath.Join("..", "..", "kits", "crypto"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"crypto.h", "aes.c", "sha256.c", "rsa.c"} {
		if _, err := os.Stat(filepath.Join(kitsDir, f)); err != nil {
			t.Skipf("kits/crypto/%s 不可用 (%v), 跳过交叉验证", f, err)
		}
	}

	tmp := t.TempDir()

	// 1) 生成密钥对与 C 头文件
	if err := GenerateKeypair(tmp); err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}
	priv, err := LoadKeypair(tmp)
	if err != nil {
		t.Fatalf("加载密钥对失败: %v", err)
	}
	blob := PublicKeyBlob(&priv.PublicKey)
	headerPath := filepath.Join(tmp, "pubkey.h")
	if err := EmitPubkeyHeader(headerPath, blob); err != nil {
		t.Fatalf("生成 pubkey.h 失败: %v", err)
	}

	// 2) 编译探针
	srcPath := filepath.Join(tmp, "probe.c")
	if err := os.WriteFile(srcPath, []byte(probeC), 0o644); err != nil {
		t.Fatal(err)
	}
	exePath := filepath.Join(tmp, "probe.exe")
	cmd := exec.Command(gcc,
		"-O2", "-Wall", "-o", exePath, srcPath,
		filepath.Join(kitsDir, "aes.c"),
		filepath.Join(kitsDir, "sha256.c"),
		filepath.Join(kitsDir, "rsa.c"),
		"-I", kitsDir, "-I", tmp,
		"-ladvapi32",
	)
	cmd.Dir = tmp
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc 编译失败: %v\n%s", err, out)
	}

	// 3) 运行探针, 收集 hex 行
	run := exec.Command(exePath)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("探针执行失败: %v\n%s", err, out)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("探针输出异常行: %q", line)
		}
		fields[k] = v
	}
	if fields["RSA_FAIL"] == "" && fields["RSA_CT"] == "" {
		t.Fatalf("探针未产生 RSA 密文:\n%s", out)
	}

	hexOf := func(name string) []byte {
		t.Helper()
		v, ok := fields[name]
		if !ok {
			t.Fatalf("探针输出缺少 %s:\n%s", name, out)
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatalf("%s 不是合法 hex: %v", name, err)
		}
		return b
	}

	// 4) 断言: CryptoAPI 接受的 blob 必须与 Go 私钥严格配对
	if got, want := fields["BLOB_LEN"], strconv.Itoa(len(blob)); got != want {
		t.Fatalf("C 侧 CSDEV_PUBKEY_LEN = %s, Go 侧 %s", got, want)
	}
	rsaCT := hexOf("RSA_CT")
	rsaPT := hexOf("RSA_PT")
	if len(rsaCT) != 256 {
		t.Fatalf("CryptoAPI 密文长度 %d, 期望 256", len(rsaCT))
	}
	back, err := DecryptPKCS1v15(priv, rsaCT)
	if err != nil {
		t.Fatalf("CryptoAPI 密文无法用 Go 私钥解密 (PUBLICKEYBLOB 布局与 Go 密钥不匹配?): %v", err)
	}
	if !bytes.Equal(back, rsaPT) {
		t.Fatalf("CryptoAPI 加密的明文与 Go 解密结果不一致\n得到 % X\n期望 % X", back, rsaPT)
	}

	// 5) 断言: AES-256-CBC + PKCS#7 两侧逐字节一致
	aesCT, err := EncryptAESCBCWithIV(hexOf("AES_KEY"), hexOf("AES_IV"), hexOf("AES_PT"))
	if err != nil {
		t.Fatalf("Go 侧 AES 加密失败: %v", err)
	}
	if want := hexOf("AES_CT"); !bytes.Equal(aesCT, want) {
		t.Fatalf("AES-CBC 密文两侧不一致\nGo  % X\nC   % X", aesCT, want)
	}
	// 反向: C 侧密文由 Go 解密
	cBack, err := DecryptAESCBC(hexOf("AES_KEY"), hexOf("AES_IV"), hexOf("AES_CT"))
	if err != nil {
		t.Fatalf("Go 侧解密 C 侧密文失败: %v", err)
	}
	if !bytes.Equal(cBack, hexOf("AES_PT")) {
		t.Fatal("C 侧 AES 密文解密结果与明文不符")
	}

	// 6) 断言: HMAC-SHA256 两侧一致
	if got, want := HMACSHA256(hexOf("HMAC_KEY"), hexOf("HMAC_DATA")), hexOf("HMAC_OUT"); !bytes.Equal(got, want) {
		t.Fatalf("HMAC-SHA256 两侧不一致\nGo  % X\nC   % X", got, want)
	}

	t.Logf("Go/C 交叉验证通过: PUBLICKEYBLOB(%d 字节) 被 CryptoAPI 接受, AES-CBC 与 HMAC-SHA256 逐字节一致", len(blob))
}
