// csdev :: proto/crypto_test.go  --  密码学原语测试
//
// 向量与 C 侧 kits/crypto/selftest.c 完全相同, 用于证明 Go/C 两侧实现逐字节一致:
//
//	AES-256-CBC : NIST SP 800-38A F.2.5
//	HMAC-SHA256 : RFC 4231 Test Case 1 / 2
package proto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("测试向量 hex 非法: %v", err)
	}
	return b
}

// ---------------------------------------------------------------- AES-CBC

func TestAESCBCRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xA5}, AESKeySize)
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 100, 255, 1024, 512 * 1024} {
		plain := make([]byte, n)
		if _, err := rand.Read(plain); err != nil {
			t.Fatalf("构造明文失败: %v", err)
		}
		iv, ct, err := EncryptAESCBC(key, plain)
		if err != nil {
			t.Fatalf("明文 %d 字节: 加密失败: %v", n, err)
		}
		if len(iv) != AESBlockSize {
			t.Fatalf("明文 %d 字节: IV 长度 %d, 期望 %d", n, len(iv), AESBlockSize)
		}
		if len(ct) == 0 || len(ct)%AESBlockSize != 0 {
			t.Fatalf("明文 %d 字节: 密文长度 %d 非法", n, len(ct))
		}
		// PKCS#7: 整除时也要补满一整块
		if want := (n/AESBlockSize + 1) * AESBlockSize; len(ct) != want {
			t.Fatalf("明文 %d 字节: 密文长度 %d, 期望 %d", n, len(ct), want)
		}
		back, err := DecryptAESCBC(key, iv, ct)
		if err != nil {
			t.Fatalf("明文 %d 字节: 解密失败: %v", n, err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("明文 %d 字节: 往返不一致", n)
		}
	}
}

func TestAESCBCNISTVector(t *testing.T) {
	// NIST SP 800-38A F.2.5 (AES-256-CBC), 与 kits/crypto/selftest.c 同一向量
	key := mustHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	pt := mustHex(t,
		"6bc1bee22e409f96e93d7e117393172a"+
			"ae2d8a571e03ac9c9eb76fac45af8e51"+
			"30c81c46a35ce411e5fbc1191a0a52ef"+
			"f69f2445df4f9b17ad2b417be66c3710")
	want := mustHex(t,
		"f58c4c04d6e5f1ba779eabfb5f7bfbd6"+
			"9cfc4e967edb808d679f777bc6702c7d"+
			"39f23369a9d9bacfa530e26304231461"+
			"b2eb05e2c39be9fcda6c19078c6a9d1b")

	ct, err := EncryptAESCBCWithIV(key, iv, pt)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if len(ct) != 80 { // 64 字节明文 + 16 字节填充块
		t.Fatalf("密文长度 %d, 期望 80", len(ct))
	}
	if !bytes.Equal(ct[:64], want) {
		t.Fatalf("前 4 块密文与 NIST 向量不符\n得到 %x\n期望 %x", ct[:64], want)
	}
	back, err := DecryptAESCBC(key, iv, ct)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("NIST 向量解密还原失败")
	}
	t.Logf("AES-256-CBC NIST SP800-38A F.2.5 向量一致 (前 4 块密文 %x)", ct[:16])
}

func TestAESCBCRejectsBadInput(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, AESKeySize)
	iv := bytes.Repeat([]byte{0x22}, 8)

	if _, err := EncryptAESCBCWithIV(key, iv, []byte("x")); err == nil {
		t.Fatal("IV 长度非法时必须报错")
	}
	if _, _, err := EncryptAESCBC([]byte("short"), []byte("x")); err == nil {
		t.Fatal("AES 密钥长度非法时必须报错")
	}
	if _, err := DecryptAESCBC(key, bytes.Repeat([]byte{0x22}, AESBlockSize), nil); err == nil {
		t.Fatal("空密文必须报错")
	}
	if _, err := DecryptAESCBC(key, bytes.Repeat([]byte{0x22}, AESBlockSize), []byte("not-block")); err == nil {
		t.Fatal("密文长度非分组整数倍必须报错")
	}
}

func TestPKCS7UnpadRejectsBadPadding(t *testing.T) {
	cases := map[string][]byte{
		"空":       {},
		"长度非整块":   bytes.Repeat([]byte{0x01}, 15),
		"填充值为0":   append(bytes.Repeat([]byte{0x00}, 15), 0x00),
		"填充值超16":  append(bytes.Repeat([]byte{0x00}, 15), 0x11),
		"填充字节不一致": append(bytes.Repeat([]byte{0x00}, 15), 0x03),
	}
	for name, in := range cases {
		_, err := pkcs7Unpad(in)
		if err == nil {
			t.Fatalf("%s: 必须返回 error", name)
		}
		if !errors.Is(err, ErrPadding) {
			t.Fatalf("%s: 错误应可用 errors.Is(err, ErrPadding) 匹配, 实际 %v", name, err)
		}
	}
	// 合法填充边界: 1 与 16
	for _, pad := range []int{1, 16} {
		in := append(bytes.Repeat([]byte{0xAA}, AESBlockSize*2-pad), bytes.Repeat([]byte{byte(pad)}, pad)...)
		out, err := pkcs7Unpad(in)
		if err != nil {
			t.Fatalf("填充 %d: 不应报错: %v", pad, err)
		}
		if len(out) != AESBlockSize*2-pad {
			t.Fatalf("填充 %d: 剥离后长度 %d", pad, len(out))
		}
	}
}

// ---------------------------------------------------------------- HMAC

func TestHMACSHA256RFC4231(t *testing.T) {
	tc1 := HMACSHA256(bytes.Repeat([]byte{0x0b}, 20), []byte("Hi There"))
	if got := hex.EncodeToString(tc1); got != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" {
		t.Fatalf("RFC4231 TC1 不符: %s", got)
	}
	tc2 := HMACSHA256([]byte("Jefe"), []byte("what do ya want for nothing?"))
	if got := hex.EncodeToString(tc2); got != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" {
		t.Fatalf("RFC4231 TC2 不符: %s", got)
	}
	t.Logf("HMAC-SHA256 RFC4231 TC1/TC2 一致")
}

func TestHMACPartsEqualsJoint(t *testing.T) {
	key := bytes.Repeat([]byte{0x5C}, HMACKeySize)
	a, b, c := []byte("frame-header-20B!!"), []byte("0123456789abcdef"), []byte("ciphertext")
	if !bytes.Equal(hmacParts(key, a, b, c), HMACSHA256(key, append(append(append([]byte{}, a...), b...), c...))) {
		t.Fatal("分段 HMAC 与拼接后 HMAC 不一致")
	}
}

// ---------------------------------------------------------------- 密钥对

func TestGenerateKeypairIdempotent(t *testing.T) {
	dir := t.TempDir()

	if err := GenerateKeypair(dir); err != nil {
		t.Fatalf("首次生成失败: %v", err)
	}
	priv1, err := LoadKeypair(dir)
	if err != nil {
		t.Fatalf("加载私钥失败: %v", err)
	}
	if priv1.N.BitLen() != RSAKeyBits {
		t.Fatalf("密钥位长 %d, 期望 %d", priv1.N.BitLen(), RSAKeyBits)
	}

	keyBefore, err := os.ReadFile(filepath.Join(dir, PrivKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := GenerateKeypair(dir); err != nil {
		t.Fatalf("二次调用必须幂等成功: %v", err)
	}
	keyAfter, _ := os.ReadFile(filepath.Join(dir, PrivKeyFile))
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("二次调用覆盖了既有私钥")
	}
	priv2, _ := LoadKeypair(dir)
	if priv2.N.Cmp(priv1.N) != 0 || priv2.D.Cmp(priv1.D) != 0 {
		t.Fatal("二次加载的私钥与首次不一致")
	}

	// 私钥存在但公钥缺失 → 用私钥补齐
	pubPath := filepath.Join(dir, PubKeyFile)
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKeypair(dir); err != nil {
		t.Fatalf("公钥缺失时应能补齐: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("公钥未被补齐: %v", err)
	}

	// 公钥存在但私钥缺失 → 必须报错
	if err := os.Remove(filepath.Join(dir, PrivKeyFile)); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKeypair(dir); err == nil {
		t.Fatal("私钥缺失时必须报错")
	}
}

func TestLoadKeypairRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadKeypair(dir); err == nil {
		t.Fatal("文件不存在时必须报错")
	}
	if err := os.WriteFile(filepath.Join(dir, PrivKeyFile), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeypair(dir); err == nil {
		t.Fatal("非 PEM 内容必须报错")
	}
}

// ---------------------------------------------------------------- PUBLICKEYBLOB

// TestPublicKeyBlobLayout 用确定性模数逐字节核对 1.2 节布局。
func TestPublicKeyBlobLayout(t *testing.T) {
	// N 的大端字节固定为 80 01 02 ... FF, 便于预测 blob 内容
	nBytes := make([]byte, RSAModulusBytes)
	nBytes[0] = 0x80
	for i := 1; i < RSAModulusBytes; i++ {
		nBytes[i] = byte(i)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: 65537}

	blob := PublicKeyBlob(pub)
	if len(blob) != 276 {
		t.Fatalf("blob 长度 %d, 期望 276", len(blob))
	}

	// BLOBHEADER (8B) + RSAPUBKEY (12B)
	wantHead := mustHex(t, "06 02 00 00 00 A4 00 00 52 53 41 31 00 08 00 00 01 00 01 00")
	if !bytes.Equal(blob[:20], wantHead) {
		t.Fatalf("blob 前 20 字节不符\n得到 % X\n期望 % X", blob[:20], wantHead)
	}
	// 模数小端: 最低有效字节 0xFF 在最前, 最高有效字节 0x80 在最后
	if blob[20] != 0xFF || blob[275] != 0x80 {
		t.Fatalf("模数字节序错误: blob[20]=0x%02X blob[275]=0x%02X", blob[20], blob[275])
	}

	// 从 blob 反向恢复公钥, 应与原始 N/E 完全一致 (证明与 C 侧 CryptImportKey 语义等价)
	le := blob[20:276]
	rev := make([]byte, RSAModulusBytes)
	for i, b := range le {
		rev[RSAModulusBytes-1-i] = b
	}
	if new(big.Int).SetBytes(rev).Cmp(pub.N) != 0 {
		t.Fatal("从 blob 恢复的模数与原始 N 不一致")
	}

	if PublicKeyBlob(nil) != nil {
		t.Fatal("nil 公钥应返回 nil")
	}
	t.Logf("PUBLICKEYBLOB 前 32 字节: % X", blob[:32])
}

// TestPublicKeyBlobRoundTripRealKey 用真实密钥验证 blob 与 RSA 加解密链路自洽。
func TestPublicKeyBlobRoundTripRealKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	blob := PublicKeyBlob(&priv.PublicKey)
	if len(blob) != 276 {
		t.Fatalf("blob 长度 %d, 期望 276", len(blob))
	}
	t.Logf("真实密钥 PUBLICKEYBLOB 前 32 字节: % X", blob[:32])
	t.Logf("真实密钥 PUBLICKEYBLOB SHA-256 指纹: %s", PubkeyFingerprint(blob))

	// 模拟 C 侧: 从 blob 取出模数(小端)与指数导入后加密。注意 blob 内所有字段均为小端。
	le := blob[20:276]
	rev := make([]byte, RSAModulusBytes)
	for i, b := range le {
		rev[RSAModulusBytes-1-i] = b
	}
	exp := int(binary.LittleEndian.Uint32(blob[16:20]))
	if exp != priv.PublicKey.E {
		t.Fatalf("从 blob 读出的 pubexp = %d, 期望 %d", exp, priv.PublicKey.E)
	}
	imported := &rsa.PublicKey{N: new(big.Int).SetBytes(rev), E: exp}
	msg := []byte("csdev-pubkey-blob-roundtrip")
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, imported, msg)
	if err != nil {
		t.Fatalf("用导入公钥加密失败: %v", err)
	}
	if len(ct) != 256 {
		t.Fatalf("密文长度 %d, 期望 256", len(ct))
	}
	back, err := DecryptPKCS1v15(priv, ct)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("blob 往返不一致")
	}

	if _, err := DecryptPKCS1v15(priv, ct[:200]); err == nil {
		t.Fatal("密文长度不足时必须报错")
	}
	if _, err := DecryptPKCS1v15(nil, ct); err == nil {
		t.Fatal("nil 私钥必须报错")
	}
}

func TestEmitPubkeyHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "pubkey.h") // 目录不存在, 应自动创建

	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	blob := PublicKeyBlob(&priv.PublicKey)
	if err := EmitPubkeyHeader(path, blob); err != nil {
		t.Fatalf("写出头文件失败: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	for _, want := range []string{
		"static const unsigned char CSDEV_PUBKEY_BLOB[] = {",
		"#define CSDEV_PUBKEY_LEN 276",
		PubkeyFingerprint(blob),
		"0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("头文件缺少 %q\n%s", want, text)
		}
	}
	// 276 个 0xNN 元素
	if n := strings.Count(text, "0x"); n != 276 {
		t.Fatalf("blob 元素个数 %d, 期望 276", n)
	}
	if err := EmitPubkeyHeader(filepath.Join(dir, "empty.h"), nil); err == nil {
		t.Fatal("空 blob 必须报错")
	}
}
