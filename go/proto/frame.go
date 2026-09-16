// csdev :: proto/frame.go  --  协议 v2 帧编解码 (docs/protocol_v2.md 第 2 节)
//
// 帧结构 (固定 20 字节帧头, 网络序 BE):
//
//	偏移 长度 字段
//	0    4    magic     = 0x4353324B ("CS2K")
//	4    4    session_id (checkin 为 0)
//	8    4    seq       会话内单调递增
//	12   4    flags     F_CHECKIN / F_HASRESULT / F_CHUNKED / F_ERROR / F_NOHMAC
//	16   4    body_len  其后 body 字节数
//
// 非 checkin body: [16B IV][AES-256-CBC 密文][32B HMAC]
// HMAC 覆盖:       帧头(20B 原样) || IV || 密文
//
// 关键顺序: 先算密文 → 回填 body_len → 再算 HMAC。
package proto

import (
	"crypto/hmac"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
)

// Magic 帧头魔数, ASCII "CS2K" (协议 2.1)。
const Magic uint32 = 0x4353324B

// flags 位定义 (协议 2.1)。
const (
	F_CHECKIN   uint32 = 1 << 0 // 首次上线帧, body 为 RSA 密文
	F_HASRESULT uint32 = 1 << 1 // 上行帧携带结果 TLV
	F_CHUNKED   uint32 = 1 << 2 // 携带文件分块
	F_ERROR     uint32 = 1 << 3 // 服务端应答中的错误标记
	F_NOHMAC    uint32 = 1 << 4 // 显式声明无 HMAC (checkin 与空应答)
)

const (
	HeaderSize   = 20      // 固定帧头长度
	MaxFrameBody = 4 << 20 // 单帧上限 4 MB (协议 7)
	ProtoVersion = 0x02    // 协议版本 (协议 2.3)

	// CheckinFixedLen = 32(aes_key) + 32(hmac_key) + 16(iv_seed) + 1(ver) + 1(meta_len)
	CheckinFixedLen = AESKeySize + HMACKeySize + IVSeedSize + 2
	// CheckinMetaMax meta 长度字段只有 1 字节
	CheckinMetaMax = 0xFF
)

// MetaSep checkin/META_UPDATE 中 meta 字段的分隔符 (协议 2.3)。
const MetaSep = 0x1F

// Frame 一帧的头部字段与 body。Body 为原始字节, 未解密。
type Frame struct {
	SessionID uint32
	Seq       uint32
	Flags     uint32
	Body      []byte
}

// NewFrame 构造空帧 (Body 为 nil)。
func NewFrame(sessionID, seq, flags uint32) *Frame {
	return &Frame{SessionID: sessionID, Seq: seq, Flags: flags}
}

// Header 生成 20 字节帧头, body_len 取 len(f.Body)。
func (f *Frame) Header() []byte {
	h := make([]byte, HeaderSize)
	PutBE32(h[0:4], Magic)
	PutBE32(h[4:8], f.SessionID)
	PutBE32(h[8:12], f.Seq)
	PutBE32(h[12:16], f.Flags)
	PutBE32(h[16:20], uint32(len(f.Body)))
	return h
}

// Encode 编码为完整帧字节 (帧头 || body)。
func (f *Frame) Encode() []byte {
	h := f.Header()
	out := make([]byte, 0, HeaderSize+len(f.Body))
	out = append(out, h...)
	out = append(out, f.Body...)
	return out
}

// String 便于日志输出。
func (f *Frame) String() string {
	if f == nil {
		return "<nil frame>"
	}
	return fmt.Sprintf("frame{sid=%d seq=%d flags=%s len=%d}",
		f.SessionID, f.Seq, FlagString(f.Flags), len(f.Body))
}

// FlagString 把 flags 渲染成可读标志串, 未知位置以 0x%X 呈现。
func FlagString(flags uint32) string {
	known := []struct {
		bit  uint32
		name string
	}{
		{F_CHECKIN, "CHECKIN"}, {F_HASRESULT, "HASRESULT"},
		{F_CHUNKED, "CHUNKED"}, {F_ERROR, "ERROR"}, {F_NOHMAC, "NOHMAC"},
	}
	var parts []string
	rest := flags
	for _, k := range known {
		if flags&k.bit != 0 {
			parts = append(parts, k.name)
			rest &^= k.bit
		}
	}
	if rest != 0 {
		parts = append(parts, fmt.Sprintf("0x%X", rest))
	}
	if len(parts) == 0 {
		return "0"
	}
	return strings.Join(parts, "|")
}

// ParseFrame 解析原始字节为帧。校验 magic 与 body_len 边界, 任一项不满足即返回 error。
// raw 尾部的多余字节会被忽略 (容忍从流式缓冲中读取的整块数据)。
func ParseFrame(raw []byte) (*Frame, error) {
	if len(raw) < HeaderSize {
		return nil, fmt.Errorf("%w: 帧头需要 %d 字节, 实际 %d", ErrTruncated, HeaderSize, len(raw))
	}
	if magic := BE32(raw[0:4]); magic != Magic {
		return nil, fmt.Errorf("%w: 0x%08X, 期望 0x%08X (\"CS2K\")", ErrMagic, magic, Magic)
	}
	bodyLen := BE32(raw[16:20])
	if bodyLen > MaxFrameBody {
		return nil, fmt.Errorf("proto: 帧 body 超限: 声明 %d 字节, 上限 %d", bodyLen, MaxFrameBody)
	}
	if int(bodyLen) > len(raw)-HeaderSize {
		return nil, fmt.Errorf("%w: 帧 body 声明 %d 字节, 实际可用 %d 字节",
			ErrTruncated, bodyLen, len(raw)-HeaderSize)
	}
	body := make([]byte, bodyLen)
	copy(body, raw[HeaderSize:HeaderSize+int(bodyLen)])
	return &Frame{
		SessionID: BE32(raw[4:8]),
		Seq:       BE32(raw[8:12]),
		Flags:     BE32(raw[12:16]),
		Body:      body,
	}, nil
}

// SealBody 加密 plain 并返回 body = IV || 密文 || HMAC。
//
// header20 必须恰好 20 字节, 且 session_id / seq / flags 已填好 (body_len 由本函数回填,
// 回填是就地写入, 调用方持有的同一底层数组会被同步更新 —— 因为 HMAC 覆盖帧头,
// 顺序必须是「先算密文 → 回填 body_len → 再算 HMAC」)。
func SealBody(key, hmacKey []byte, header20 []byte, plain []byte) ([]byte, error) {
	if len(header20) != HeaderSize {
		return nil, fmt.Errorf("proto: 帧头长度 %d 非法 (必须恰好 %d 字节)", len(header20), HeaderSize)
	}
	iv, ct, err := EncryptAESCBC(key, plain)
	if err != nil {
		return nil, err
	}

	bodyLen := AESBlockSize + len(ct) + HMACSize
	PutBE32(header20[16:20], uint32(bodyLen))

	mac := hmacParts(hmacKey, header20, iv, ct)
	body := make([]byte, 0, bodyLen)
	body = append(body, iv...)
	body = append(body, ct...)
	body = append(body, mac...)
	return body, nil
}

// Seal 是 SealBody 的帧级封装: 用 f 的头部字段加密 plain,
// 返回完整帧字节 (帧头 || body), 并把 f.Body 同步为生成的 body。
func (f *Frame) Seal(key, hmacKey []byte, plain []byte) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("proto: 帧为空")
	}
	hdr := f.Header()
	body, err := SealBody(key, hmacKey, hdr, plain)
	if err != nil {
		return nil, err
	}
	f.Body = body

	out := make([]byte, 0, HeaderSize+len(body))
	out = append(out, hdr...)
	out = append(out, body...)
	return out, nil
}

// OpenBody 校验 HMAC 后解密 f.Body, 返回明文。
//
//	flags 含 F_NOHMAC 且 body 为空 → 返回 (nil, nil), 对应协议 2.4 的空应答
//	body 结构不合法 / HMAC 不匹配 → 返回 error, 绝不返回未认证的明文
func OpenBody(key, hmacKey []byte, f *Frame) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("proto: 帧为空")
	}
	if f.Flags&F_NOHMAC != 0 {
		if len(f.Body) != 0 {
			return nil, fmt.Errorf("proto: 帧声明 F_NOHMAC 但 body 有 %d 字节", len(f.Body))
		}
		return nil, nil
	}
	if len(f.Body) == 0 {
		return nil, fmt.Errorf("proto: 帧 body 为空且未声明 F_NOHMAC")
	}
	if len(f.Body) < AESBlockSize+HMACSize {
		return nil, fmt.Errorf("%w: 帧 body 需要至少 %d 字节 (IV+HMAC), 实际 %d",
			ErrTruncated, AESBlockSize+HMACSize, len(f.Body))
	}

	ctLen := len(f.Body) - AESBlockSize - HMACSize
	if ctLen == 0 || ctLen%AESBlockSize != 0 {
		return nil, fmt.Errorf("proto: 帧密文长度 %d 非法 (必须是 %d 的正整数倍)", ctLen, AESBlockSize)
	}
	iv := f.Body[:AESBlockSize]
	ct := f.Body[AESBlockSize : AESBlockSize+ctLen]
	gotMAC := f.Body[AESBlockSize+ctLen:]

	// 帧头原样参与 HMAC。body_len 由 f.Header() 依据 len(f.Body) 重算,
	// 与 ParseFrame 保留的字节数一致, 因此等价于线路上的原始帧头。
	hdr := f.Header()
	wantMAC := hmacParts(hmacKey, hdr, iv, ct)
	// hmac.Equal 为常数时间比较, 避免通过比较耗时侧信道爆破 HMAC
	if !hmac.Equal(gotMAC, wantMAC) {
		return nil, fmt.Errorf("%w: 帧头/IV/密文被篡改或密钥不匹配", ErrHMAC)
	}
	return DecryptAESCBC(key, iv, ct)
}

// ---------------------------------------------------------------- checkin

// CheckinInfo 解析后的 checkin 会话密钥材料 (协议 2.3)。
type CheckinInfo struct {
	AESKey  []byte   // 32 字节会话 AES 密钥
	HMACKey []byte   // 32 字节会话 HMAC 密钥
	Version byte     // 协议版本, 契约要求 0x02
	Meta    []string // host / user / arch / pid / ppid / procname / internal_ip / os_ver
}

// ParseCheckin 用服务端私钥解密并解析 checkin 明文 (协议 2.3)。
// 版本不为 0x02 时返回 error: 版本变化意味着字段偏移可能不同, 不做静默容忍。
func ParseCheckin(priv *rsa.PrivateKey, ct []byte) (*CheckinInfo, error) {
	plain, err := DecryptPKCS1v15(priv, ct)
	if err != nil {
		return nil, err
	}
	if len(plain) < CheckinFixedLen {
		return nil, fmt.Errorf("%w: checkin 明文需要至少 %d 字节, 实际 %d",
			ErrTruncated, CheckinFixedLen, len(plain))
	}

	info := &CheckinInfo{
		AESKey:  append([]byte(nil), plain[0:AESKeySize]...),
		HMACKey: append([]byte(nil), plain[AESKeySize:AESKeySize+HMACKeySize]...),
		Version: plain[AESKeySize+HMACKeySize+IVSeedSize],
	}
	if info.Version != ProtoVersion {
		return nil, fmt.Errorf("proto: checkin 协议版本 0x%02X 不受支持 (期望 0x%02X)",
			info.Version, ProtoVersion)
	}

	metaLen := int(plain[CheckinFixedLen-1])
	if CheckinFixedLen+metaLen > len(plain) {
		return nil, fmt.Errorf("%w: checkin meta 声明 %d 字节, 实际可用 %d 字节",
			ErrTruncated, metaLen, len(plain)-CheckinFixedLen)
	}
	info.Meta = SplitMeta(string(plain[CheckinFixedLen : CheckinFixedLen+metaLen]))
	return info, nil
}

// BuildCheckinPlain 组装 checkin 明文 (生成器与测试用):
//
//	[32B aes_key][32B hmac_key][16B iv_seed 全 0][1B ver=0x02][1B meta_len][meta]
//
// 密钥长度不是 32 字节时右补零 / 截断; meta 超过 255 字节时按完整字段边界截断。
func BuildCheckinPlain(aesKey, hmacKey []byte, meta []string) []byte {
	m := []byte(JoinMeta(meta))
	if len(m) > CheckinMetaMax {
		m = m[:CheckinMetaMax]
		// 丢弃被切断的尾部字段, 保证 meta 始终是完整的字段列表
		if i := lastIndexByte(m, MetaSep); i > 0 {
			m = m[:i]
		}
	}

	out := make([]byte, 0, CheckinFixedLen+len(m))
	out = append(out, fit32(aesKey)...)
	out = append(out, fit32(hmacKey)...)
	out = append(out, make([]byte, IVSeedSize)...) // iv_seed 保留字段, 契约允许全 0
	out = append(out, ProtoVersion)
	out = append(out, byte(len(m)))
	out = append(out, m...)
	return out
}

// JoinMeta 用 0x1F 拼接 meta 字段。
func JoinMeta(meta []string) string {
	return strings.Join(meta, string(rune(MetaSep)))
}

// SplitMeta 按 0x1F 拆分 meta 字段; 空串返回 nil。
func SplitMeta(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, string(rune(MetaSep)))
}

// fit32 把密钥材料规整为 32 字节 (短则右补零, 长则截断)。
func fit32(b []byte) []byte {
	out := make([]byte, AESKeySize)
	copy(out, b)
	return out
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------- 防重放

// SeqGuard 按会话记录已见的最大 seq, 用于丢弃重放/乱序帧 (协议 0 节"防重放")。
// 允许跳号 (网络丢帧), 只拒绝「小于等于已见最大值」的 seq。并发安全。
type SeqGuard struct {
	mu   sync.Mutex
	last map[uint32]uint32
	seen map[uint32]bool
}

// NewSeqGuard 创建空的序号追踪器。
func NewSeqGuard() *SeqGuard {
	return &SeqGuard{last: make(map[uint32]uint32), seen: make(map[uint32]bool)}
}

// Accept 校验并记录 (sessionID, seq)。checkin 帧 (sessionID == 0) 不参与防重放。
func (g *SeqGuard) Accept(sessionID, seq uint32) error {
	if g == nil || sessionID == 0 {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[sessionID] && seq <= g.last[sessionID] {
		return fmt.Errorf("proto: 会话 %d 的帧 seq=%d 重放或乱序 (已见最大 %d)",
			sessionID, seq, g.last[sessionID])
	}
	g.seen[sessionID] = true
	g.last[sessionID] = seq
	return nil
}

// Forget 丢弃某会话的序号状态 (会话结束后调用, 避免 map 无界增长)。
func (g *SeqGuard) Forget(sessionID uint32) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.seen, sessionID)
	delete(g.last, sessionID)
	g.mu.Unlock()
}
