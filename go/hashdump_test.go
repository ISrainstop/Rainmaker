// csdev :: hashdump_test.go  --  hashdump 解析器单测
//
// 覆盖:
//   1. bootkey 置换表
//   2. RID -> DES 密钥 (与 volatility3 原版实现的输出逐字节比对, 跨语言向量)
//   3. hbootkey 派生的两种形态 (rev2=RC4 / rev3=AES)
//   4. 用户哈希解密的两种形态 (rev1=RC4+DES / rev2=AES+DES)
//   5. 坏输入不 panic 且给出明确错误
//   6. 真实 hive 回归 (有样本时跑, 无样本时 skip)
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	rc4c "crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- 1. bootkey

func TestBootKeyPermutation(t *testing.T) {
	// 输入 0x00..0x0F, 置换后按 bootKeyPerm 取值, 期望值可以直接对表写出来
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = byte(i)
	}
	got, err := applyBootKeyPerm(raw)
	if err != nil {
		t.Fatalf("applyBootKeyPerm 报错: %v", err)
	}
	want := []byte{0x08, 0x05, 0x04, 0x02, 0x0B, 0x09, 0x0D, 0x03,
		0x00, 0x06, 0x01, 0x0C, 0x0E, 0x0A, 0x0F, 0x07}
	if !bytes.Equal(got, want) {
		t.Fatalf("置换结果不符\n got=%x\nwant=%x", got, want)
	}

	// 长度不对必须报错而不是静默截断
	if _, err := applyBootKeyPerm(raw[:15]); err == nil {
		t.Fatalf("15 字节输入应当报错")
	}
}

// ---------------------------------------------------------------- 2. DES 密钥

// 期望值由 volatility3 原版 sid_to_key/sidbytes_to_key 的源码原样提取后执行得到,
// 不是本实现算出来再回填的 —— 这是一条跨语言对照向量。
func TestSIDToKeysMatchesVolatility3(t *testing.T) {
	cases := []struct {
		rid  uint32
		k1   string
		k2   string
	}{
		{500, "f40140010ea10401", "017a01200107d002"},
		{501, "f48040010ea80401", "017a40200107d502"},
		{1000, "e901c1010e400d01", "017501610107a107"},
		{1001, "e980c1010e490d01", "017540610107a407"},
		{1234, "d30201010d911001", "0168808001074908"},
		{0xFFFFFFFF, "fefefefefefefefe", "fefefefefefefefe"},
	}
	for _, c := range cases {
		k1, k2 := sidToKeys(c.rid)
		if got := hex.EncodeToString(k1); got != c.k1 {
			t.Errorf("RID %d 的 DES key1 = %s, 期望 %s", c.rid, got, c.k1)
		}
		if got := hex.EncodeToString(k2); got != c.k2 {
			t.Errorf("RID %d 的 DES key2 = %s, 期望 %s", c.rid, got, c.k2)
		}
		// DES 密钥每字节必须是奇校验
		for i, b := range append(append([]byte{}, k1...), k2...) {
			if bits.OnesCount8(b)%2 != 1 {
				t.Errorf("RID %d 密钥字节 %d = 0x%02X 不是奇校验", c.rid, i, b)
			}
		}
	}
}

// ---------------------------------------------------------------- 3. hbootkey

func buildFValueRev2(t *testing.T, hbootKey []byte) []byte {
	t.Helper()
	f := make([]byte, 0xA8)
	f[0x00] = 2
	salt := []byte("0123456789abcdef")
	copy(f[0x70:0x80], salt)

	m := md5.New()
	m.Write(salt)
	m.Write(aqwerty)
	m.Write(bootKeyTest)
	m.Write(anum)
	c, err := rc4c.NewCipher(m.Sum(nil))
	if err != nil {
		t.Fatalf("RC4 初始化失败: %v", err)
	}
	// 加密方向: 把 hbootkey 补到 32 字节后 RC4
	plain := make([]byte, 32)
	copy(plain, hbootKey)
	c.XORKeyStream(f[0x80:0xA0], plain)
	return f
}

func buildFValueRev3(t *testing.T, hbootKey []byte) []byte {
	t.Helper()
	f := make([]byte, 0xA8)
	f[0x00] = 3
	iv := []byte("abcdefghijklmnop")
	copy(f[0x78:0x88], iv)
	blk, err := aes.NewCipher(bootKeyTest)
	if err != nil {
		t.Fatalf("AES 初始化失败: %v", err)
	}
	plain := make([]byte, 32)
	copy(plain, hbootKey)
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(f[0x88:0xA8], plain)
	return f
}

var bootKeyTest = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01}

func TestDeriveHashedBootKeyRev2RC4(t *testing.T) {
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	f := buildFValueRev2(t, want)
	got, err := DeriveHashedBootKeyFromF(f, bootKeyTest)
	if err != nil {
		t.Fatalf("rev2 派生失败: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("rev2 hbootkey 不符\n got=%x\nwant=%x", got, want)
	}
}

func TestDeriveHashedBootKeyRev3AES(t *testing.T) {
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C}
	f := buildFValueRev3(t, want)
	got, err := DeriveHashedBootKeyFromF(f, bootKeyTest)
	if err != nil {
		t.Fatalf("rev3 派生失败: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("rev3 hbootkey 不符\n got=%x\nwant=%x", got, want)
	}
}

// ---------------------------------------------------------------- 4. 用户哈希

// buildVValue 按给定的形态构造一个合成 V 值。
// rev1: blob = [0..1 保留][2]=1[3]=0[4..19] = RC4(MD5(hboot||rid||LMNT), DES密文)
// rev2: NT blob 的 salt 在 +8, 密文在 +24; LM blob 的 salt 在 +4, 密文在 +20
func buildVValue(t *testing.T, hbootKey []byte, rid uint32, rev int, ntHash []byte) []byte {
	t.Helper()
	v := make([]byte, 0x180)
	const base = 0xCC

	// 用户名
	uname := encodeUTF16LE("TestUser")
	nameOff := 0x160
	copy(v[nameOff:], uname)
	binary.LittleEndian.PutUint32(v[0x0C:0x10], uint32(nameOff-base))
	binary.LittleEndian.PutUint32(v[0x10:0x14], uint32(len(uname)))

	// LM blob 放在 base, NT blob 放在 base+0x60
	lmBlob := base
	ntBlob := base + 0x60

	var lmLen, ntLen int

	// --- LM: 固定用一个已知的哈希值 ---
	lmHash := []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7}
	k1, k2 := sidToKeys(rid)

	encDES := func(plain []byte) []byte {
		d1, err := des.NewCipher(k1)
		if err != nil {
			t.Fatalf("DES1: %v", err)
		}
		d2, err := des.NewCipher(k2)
		if err != nil {
			t.Fatalf("DES2: %v", err)
		}
		out := make([]byte, 16)
		d1.Encrypt(out[0:8], plain[0:8])
		d2.Encrypt(out[8:16], plain[8:16])
		return out
	}

	if rev == 1 {
		v[lmBlob+2] = 1
		v[ntBlob+2] = 1
		lmLen, ntLen = 20, 20
		v[lmBlob+4+16] = 0 // 边界标记, 不参与解密
		copy(v[lmBlob+4:lmBlob+20], rc4HashBlob(hbootKey, rid, lmPassword, encDES(lmHash)))
		copy(v[ntBlob+4:ntBlob+20], rc4HashBlob(hbootKey, rid, ntPassword, encDES(ntHash)))
	} else {
		v[lmBlob+2] = 2
		v[ntBlob+2] = 2
		lmLen, ntLen = 56, 56
		aesEnc := func(salt, plain []byte) []byte {
			blk, err := aes.NewCipher(hbootKey[:16])
			if err != nil {
				t.Fatalf("AES: %v", err)
			}
			out := make([]byte, 32)
			cipher.NewCBCEncrypter(blk, salt).CryptBlocks(out, plain)
			return out
		}
		lmSalt := []byte("lmsalt0123456789")
		ntSalt := []byte("ntsalt0123456789")
		copy(v[lmBlob+4:lmBlob+20], lmSalt)
		copy(v[lmBlob+20:lmBlob+52], aesEnc(lmSalt, encDES(lmHash)))
		copy(v[ntBlob+8:ntBlob+24], ntSalt)
		copy(v[ntBlob+24:ntBlob+56], aesEnc(ntSalt, encDES(ntHash)))
	}

	binary.LittleEndian.PutUint32(v[0x9C:0xA0], uint32(lmBlob-base))
	binary.LittleEndian.PutUint32(v[0xA0:0xA4], uint32(lmLen))
	binary.LittleEndian.PutUint32(v[0xA8:0xAC], uint32(ntBlob-base))
	binary.LittleEndian.PutUint32(v[0xAC:0xB0], uint32(ntLen))
	return v
}

func rc4HashBlob(hbootKey []byte, rid uint32, lmnt, enc []byte) []byte {
	m := md5.New()
	m.Write(hbootKey[:16])
	var rb [4]byte
	binary.LittleEndian.PutUint32(rb[:], rid)
	m.Write(rb[:])
	m.Write(lmnt)
	c, _ := rc4c.NewCipher(m.Sum(nil))
	out := make([]byte, len(enc))
	c.XORKeyStream(out, enc)
	return out
}

func TestDecryptUserHashesRev1(t *testing.T) {
	hb := []byte("0123456789abcdef")
	rid := uint32(1001)
	wantNT := []byte{0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
		0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0}
	v := buildVValue(t, hb, rid, 1, wantNT)

	uh, err := DecryptUserHashes(v, hb, rid)
	if err != nil {
		t.Fatalf("rev1 解密失败: %v", err)
	}
	if uh.NT != hex.EncodeToString(wantNT) {
		t.Fatalf("rev1 NT = %s, 期望 %s", uh.NT, hex.EncodeToString(wantNT))
	}
	if uh.LM != "a0a1a2a3a4a5a6a7b0b1b2b3b4b5b6b7" {
		t.Fatalf("rev1 LM = %s", uh.LM)
	}
	if !uh.LMReal || !uh.NTReal {
		t.Fatalf("rev1 应当是真实解出的哈希: %s", uh.Note)
	}
	if name := usernameFromV(v); name != "TestUser" {
		t.Fatalf("用户名解析 = %q, 期望 TestUser", name)
	}
}

func TestDecryptUserHashesRev2(t *testing.T) {
	hb := []byte("fedcba9876543210")
	rid := uint32(500)
	wantNT := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	v := buildVValue(t, hb, rid, 2, wantNT)

	uh, err := DecryptUserHashes(v, hb, rid)
	if err != nil {
		t.Fatalf("rev2 解密失败: %v", err)
	}
	if uh.NT != hex.EncodeToString(wantNT) {
		t.Fatalf("rev2 NT = %s, 期望 %s", uh.NT, hex.EncodeToString(wantNT))
	}
	if uh.LM != "a0a1a2a3a4a5a6a7b0b1b2b3b4b5b6b7" {
		t.Fatalf("rev2 LM = %s", uh.LM)
	}
	if !uh.LMReal || !uh.NTReal {
		t.Fatalf("rev2 应当是真实解出的哈希: %s", uh.Note)
	}
}

// rev2 若把 NT 的 salt 偏移误当成 LM 的 +4/+20, 解出来必然是错的。
// 这条用例专门钉住这个差异。
func TestDecryptUserHashesRev2NTSaltOffset(t *testing.T) {
	hb := []byte("fedcba9876543210")
	rid := uint32(500)
	wantNT := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	v := buildVValue(t, hb, rid, 2, wantNT)

	// 篡改 NT blob 的 +4..+8 (LM 风格 salt 会用到、NT 不会用的位置)
	copy(v[0xCC+0x60+4:0xCC+0x60+8], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	uh, err := DecryptUserHashes(v, hb, rid)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if uh.NT != hex.EncodeToString(wantNT) {
		t.Fatalf("NT 结果被不该参与的位置影响: %s", uh.NT)
	}
}

// ---------------------------------------------------------------- 5. 坏输入

func TestDecryptUserHashesRejectsBadInput(t *testing.T) {
	hb := []byte("0123456789abcdef")

	cases := []struct {
		name    string
		v       []byte
		hb      []byte
		wantErr bool
	}{
		{"空 V", nil, hb, true},
		{"截断的 V", make([]byte, 0x40), hb, true},
		{"hbootkey 过短", make([]byte, 0x180), []byte{1, 2, 3}, true},
		// 单个块越界: 不整体失败, 但必须把原因写进 Note
		{"单个块偏移越界", badOffsetV(0x9C, 0xFFFFFFF0), hb, false},
		{"两个块偏移都越界", badBothOffsetV(), hb, true},
		// 全零 V 的哈希块版本是 0: 属于"此处没有哈希", 按约定回哨兵值而不是报错
		{"长度字段极端值", badLenV(), hb, false},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: 发生 panic: %v", c.name, r)
				}
			}()
			uh, err := DecryptUserHashes(c.v, c.hb, 500)
			if c.wantErr && err == nil {
				t.Errorf("%s: 期望报错, 实际成功", c.name)
			}
			if !c.wantErr && err != nil {
				t.Errorf("%s: 期望不报错, 实得 %v", c.name, err)
				return
			}
			if c.wantErr {
				return
			}
			if uh.LMReal || uh.NTReal {
				t.Errorf("%s: 不该解出任何哈希", c.name)
			}
			// "单块越界"必须留下异常说明; "Windows 标记无哈希"则不该有 Note
			if strings.Contains(c.name, "越界") && uh.Note == "" {
				t.Errorf("%s: 解析异常必须写进 Note", c.name)
			}
			if !strings.Contains(c.name, "越界") && uh.Note != "" {
				t.Errorf("%s: 正常形态不该产生 Note, 实得 %q", c.name, uh.Note)
			}
		}()
	}
}

// 空哈希块 (长度 24, Windows 的"无哈希"标记) 必须走哨兵值而不是报错,
// 也不能被当成"解析异常" —— 与 impacket/vol3 行为一致
func TestDecryptUserHashesEmptyBlockUsesSentinel(t *testing.T) {
	hb := []byte("0123456789abcdef")
	v := make([]byte, 0x180)
	binary.LittleEndian.PutUint32(v[0x9C:0xA0], 0x40) // lm off
	binary.LittleEndian.PutUint32(v[0xA0:0xA4], 24)   // 长度 24 = Windows 的"无哈希"标记
	binary.LittleEndian.PutUint32(v[0xA8:0xAC], 0x60)
	binary.LittleEndian.PutUint32(v[0xAC:0xB0], 24)
	v[0xCC+0x40+2] = 2
	v[0xCC+0x60+2] = 2

	uh, err := DecryptUserHashes(v, hb, 500)
	if err != nil {
		t.Fatalf("哨兵值路径不应报错: %v", err)
	}
	if uh.LM != emptyLMHash || uh.NT != emptyNTHash {
		t.Fatalf("期望哨兵值, 实得 LM=%s NT=%s", uh.LM, uh.NT)
	}
	if uh.LMReal || uh.NTReal {
		t.Fatalf("标记值不应被标成真实解出")
	}
	if uh.Note != "" {
		t.Fatalf("这是正常的无哈希标记, 不该记为异常: %q", uh.Note)
	}
}

func badOffsetV(field int, val uint32) []byte {
	v := make([]byte, 0x180)
	binary.LittleEndian.PutUint32(v[field:field+4], val)
	return v
}

// 两个哈希块的偏移都指向文件外: 这才是"整体不可解"
func badBothOffsetV() []byte {
	v := make([]byte, 0x180)
	binary.LittleEndian.PutUint32(v[0x9C:0xA0], 0xFFFFFFF0)
	binary.LittleEndian.PutUint32(v[0xA8:0xAC], 0xFFFFFFE0)
	return v
}

func badLenV() []byte {
	v := make([]byte, 0x180)
	binary.LittleEndian.PutUint32(v[0x9C:0xA0], 0x10)
	binary.LittleEndian.PutUint32(v[0xA0:0xA4], 0xFFFFFF)
	binary.LittleEndian.PutUint32(v[0xA8:0xAC], 0x20)
	binary.LittleEndian.PutUint32(v[0xAC:0xB0], 0xFFFFFF)
	return v
}

func TestParseHiveRejectsGarbage(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"过短", []byte("regf")},
		{"非 hive", bytes.Repeat([]byte{0x41}, 8192)},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: 发生 panic: %v", c.name, r)
				}
			}()
			h, err := ParseHive(c.data)
			if err == nil {
				t.Errorf("%s: 期望报错", c.name)
				return
			}
			if h != nil {
				t.Errorf("%s: 出错时不应返回 hive", c.name)
			}
		}()
	}
}

// 头部合法但内部损坏: 不能 panic
func TestParseHiveHandlesCorruptBody(t *testing.T) {
	b := make([]byte, 0x3000)
	copy(b, "regf")
	binary.LittleEndian.PutUint32(b[0x24:0x28], 0x2000) // 根键指向文件末尾之外
	h, err := ParseHive(b)
	if err != nil {
		t.Fatalf("头部合法时应能解析: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("损坏主体导致 panic: %v", r)
		}
	}()
	if _, err := h.Root(); err == nil {
		t.Fatalf("越界的根键偏移应当报错")
	}
}

func TestDeriveHashedBootKeyRejectsBadRevision(t *testing.T) {
	f := make([]byte, 0xA8)
	f[0x00] = 9 // 不支持的版本
	if _, err := DeriveHashedBootKeyFromF(f, bootKeyTest); err == nil {
		t.Fatalf("不支持的 F 版本应当报错")
	}
	// 过短的 F
	if _, err := DeriveHashedBootKeyFromF(make([]byte, 0x10), bootKeyTest); err == nil {
		t.Fatalf("过短的 F 应当报错")
	}
}

// ---------------------------------------------------------------- 6. 真实 hive

// realHivePaths 返回可用于回归的真实 hive 路径。
// 优先环境变量, 其次 testdata 下的开发样本 —— 两者都没有就 skip。
// **真实 hive 含本机账户哈希, 不入版本库** (见 .gitignore)。
func realHivePaths() (string, string, bool) {
	sam := os.Getenv("CSDEV_HASHDUMP_SAM")
	sys := os.Getenv("CSDEV_HASHDUMP_SYSTEM")
	if sam != "" && sys != "" {
		return sam, sys, true
	}
	base := filepath.Join("testdata", "hashdump")
	s, y := filepath.Join(base, "SAM.real.hiv"), filepath.Join(base, "SYSTEM.real.hiv")
	if _, err := os.Stat(s); err != nil {
		return "", "", false
	}
	if _, err := os.Stat(y); err != nil {
		return "", "", false
	}
	return s, y, true
}

func TestHashdumpOnRealHive(t *testing.T) {
	samPath, sysPath, ok := realHivePaths()
	if !ok {
		t.Skip("跳过: 没有真实 hive 样本 (设 CSDEV_HASHDUMP_SAM/CSDEV_HASHDUMP_SYSTEM 或放 testdata/hashdump/*.real.hiv)")
	}

	hashes, err := DumpSAMHashFiles(samPath, sysPath)
	if err != nil {
		t.Fatalf("解析真实 hive 失败: %v", err)
	}
	if len(hashes) == 0 {
		t.Fatalf("真实 hive 未解析出任何账户")
	}
	t.Logf("解析出 %d 个账户:", len(hashes))
	for _, h := range hashes {
		if len(h.NT) != 32 {
			t.Errorf("%s: NT 哈希长度 %d, 期望 32", h.User, len(h.NT))
		}
		if len(h.LM) != 32 {
			t.Errorf("%s: LM 哈希长度 %d, 期望 32", h.User, len(h.LM))
		}
		t.Logf("  %s", h.Line())
	}

	// 本机必然存在的两个内置账户 (RID 500 Administrator / 501 Guest)
	seen := map[uint32]bool{}
	for _, h := range hashes {
		seen[h.RID] = true
	}
	if !seen[500] {
		t.Errorf("没有解析出 RID 500 (Administrator)")
	}
}

// 真实 hive 上 bootkey 必须是非零且稳定的 (两次派生一致)
func TestRealHiveBootKeyStable(t *testing.T) {
	_, sysPath, ok := realHivePaths()
	if !ok {
		t.Skip("跳过: 没有真实 SYSTEM hive 样本")
	}
	raw, err := os.ReadFile(sysPath)
	if err != nil {
		t.Fatalf("读取 SYSTEM hive: %v", err)
	}
	h, err := ParseHive(raw)
	if err != nil {
		t.Fatalf("解析 SYSTEM hive: %v", err)
	}
	k1, err := DeriveBootKey(h)
	if err != nil {
		t.Fatalf("派生 bootkey: %v", err)
	}
	k2, _ := DeriveBootKey(h)
	if !bytes.Equal(k1, k2) {
		t.Fatalf("bootkey 两次派生不一致")
	}
	allZero := true
	for _, b := range k1 {
		if b != 0 {
			allZero = false
		}
	}
	if allZero {
		t.Fatalf("bootkey 全零, 说明类名读取失败")
	}
	t.Logf("bootkey = %x", k1)
}

func encodeUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// ================================================================
// 独立闭环验证
//
// NTLM 哈希 = MD4(UTF-16LE(口令))。要证明 hashdump 解出来的哈希是对的,
// 唯一的办法是自己独立算出期望值再比对。Go 标准库没有 MD4
// (golang.org/x/crypto 不在依赖里), 所以这里按 RFC 1320 附录 A 的参考
// 实现另写一份 —— 注意它只存在于测试侧, 主代码不引入任何新依赖。
//
// 这份 MD4 自身的正确性由 RFC 1320 A.5 的官方测试套件钉住。
// ================================================================

func md4(msg []byte) []byte {
	var a, b, c, d uint32 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

	// 填充: 0x80, 补零到 56 mod 64, 再补 64 位原始比特长度(小端)
	ml := uint64(len(msg)) * 8
	m := make([]byte, len(msg), len(msg)+72)
	copy(m, msg)
	m = append(m, 0x80)
	for len(m)%64 != 56 {
		m = append(m, 0)
	}
	var lb [8]byte
	binary.LittleEndian.PutUint64(lb[:], ml)
	m = append(m, lb[:]...)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }

	for i := 0; i < len(m); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(m[i+j*4 : i+j*4+4])
		}
		aa, bb, cc, dd := a, b, c, d

		// Round 1: [ABCD k s] s = 3,7,11,19
		for j := 0; j < 16; j++ {
			s := [...]int{3, 7, 11, 19}[j%4]
			switch j % 4 {
			case 0:
				a = bits.RotateLeft32(a+f(b, c, d)+x[j], s)
			case 1:
				d = bits.RotateLeft32(d+f(a, b, c)+x[j], s)
			case 2:
				c = bits.RotateLeft32(c+f(d, a, b)+x[j], s)
			case 3:
				b = bits.RotateLeft32(b+f(c, d, a)+x[j], s)
			}
		}
		// Round 2: k 顺序 0,4,8,12,...; s = 3,5,9,13
		var k2 = [16]int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for j := 0; j < 16; j++ {
			s := [...]int{3, 5, 9, 13}[j%4]
			switch j % 4 {
			case 0:
				a = bits.RotateLeft32(a+g(b, c, d)+x[k2[j]]+0x5a827999, s)
			case 1:
				d = bits.RotateLeft32(d+g(a, b, c)+x[k2[j]]+0x5a827999, s)
			case 2:
				c = bits.RotateLeft32(c+g(d, a, b)+x[k2[j]]+0x5a827999, s)
			case 3:
				b = bits.RotateLeft32(b+g(c, d, a)+x[k2[j]]+0x5a827999, s)
			}
		}
		// Round 3: k 顺序 0,8,4,12,...; s = 3,9,11,15
		var k3 = [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for j := 0; j < 16; j++ {
			s := [...]int{3, 9, 11, 15}[j%4]
			switch j % 4 {
			case 0:
				a = bits.RotateLeft32(a+h(b, c, d)+x[k3[j]]+0x6ed9eba1, s)
			case 1:
				d = bits.RotateLeft32(d+h(a, b, c)+x[k3[j]]+0x6ed9eba1, s)
			case 2:
				c = bits.RotateLeft32(c+h(d, a, b)+x[k3[j]]+0x6ed9eba1, s)
			case 3:
				b = bits.RotateLeft32(b+h(c, d, a)+x[k3[j]]+0x6ed9eba1, s)
			}
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}

// RFC 1320 A.5 的官方测试套件 —— 先证明测试侧的 MD4 本身是对的
func TestMD4ReferenceVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(md4([]byte(c.in))); got != c.want {
			t.Errorf("MD4(%q) = %s, RFC 1320 期望 %s", c.in, got, c.want)
		}
	}
	// 空口令的 NTLM 就是 MD4(""), 借此钉住哨兵值的含义
	if hex.EncodeToString(md4(nil)) != emptyNTHash {
		t.Errorf("emptyNTHash 常量与 MD4(\"\") 不一致")
	}
}

// 端到端闭环: 对一个口令已知的本机账户, 断言 hashdump 解出的 NT 哈希
// 等于 MD4(UTF-16LE(口令))。
//
// 用法:
//   $env:CSDEV_HASHDUMP_TESTUSER='csdevhd9'
//   $env:CSDEV_HASHDUMP_TESTPASS='Csdev#Tst24x'
//   go test -run TestHashdumpRealHiveMatchesKnownPassword -v .
// 没设这两个变量就 skip。
func TestHashdumpRealHiveMatchesKnownPassword(t *testing.T) {
	user := os.Getenv("CSDEV_HASHDUMP_TESTUSER")
	pass := os.Getenv("CSDEV_HASHDUMP_TESTPASS")
	if user == "" || pass == "" {
		t.Skip("跳过: 未设置 CSDEV_HASHDUMP_TESTUSER / CSDEV_HASHDUMP_TESTPASS")
	}
	samPath, sysPath, ok := realHivePaths()
	if !ok {
		t.Skip("跳过: 没有真实 hive 样本")
	}

	want := hex.EncodeToString(md4(encodeUTF16LE(pass)))
	t.Logf("独立算出的期望 NT 哈希 (MD4 of UTF-16LE 口令) = %s", want)

	hashes, err := DumpSAMHashFiles(samPath, sysPath)
	if err != nil {
		t.Fatalf("解析 hive 失败: %v", err)
	}
	var found *SamHash
	for i := range hashes {
		if strings.EqualFold(hashes[i].User, user) {
			found = &hashes[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("hive 里没找到账户 %q (共 %d 个)", user, len(hashes))
	}
	t.Logf("hashdump 解出: %s", found.Line())
	if found.NT != want {
		t.Fatalf("NT 哈希不匹配\n  hashdump = %s\n  独立计算 = %s", found.NT, want)
	}
	if !found.NTReal {
		t.Fatalf("NT 应当是真实解出的哈希 (Note=%q)", found.Note)
	}
	t.Logf("闭环验证通过: hashdump 输出与 MD4(UTF-16LE(口令)) 一致")
}
