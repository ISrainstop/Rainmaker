// csdev :: proxy_test.go  --  服务端代理通道状态机单元测试
//
// 覆盖范围 (对应交付说明里的"仅单元测试覆盖"项):
//   - 通道建立 / 上行数据回注 / 空载荷关闭 / 未知通道拒绝
//   - ProxyDrain 内联下行 TLV 的字节级编码
//   - 长度字段边界校验 (短帧、超长帧、畸形 TLV)
//   - 真实 v2HandleUpload 分发路径 (AES/HMAC 帧 -> TLV -> 代理分支)
//   - rportfwd 反向通道接驳
//
// 全部测试用 127.0.0.1 上的回环 socket 充当 SOCKS 客户端与目标服务,
// 不需要植入体进程。
package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"csdev/proto"
)

// ---------------------------------------------------------------- 辅助

func testSession(t *testing.T, id string) *V2Session {
	t.Helper()
	s := &V2Session{
		ID:      id,
		Num:     1,
		Impl:    "v2",
		Host:    "TESTHOST",
		AESKey:  make([]byte, 32),
		HMACKey: make([]byte, 32),
	}
	// 注册到全局会话表: proxyEnqueueOpen 需要能查到会话才能下发 open
	v2st.mu.Lock()
	v2st.byID[id] = s
	v2st.mu.Unlock()
	t.Cleanup(func() {
		v2st.mu.Lock()
		delete(v2st.byID, id)
		v2st.mu.Unlock()
	})
	return s
}

// proxyCountChan 统计某通道号在全局运行表中的出现次数 (一次加锁, 避免重入死锁)
func proxyCountChan(id uint32) int {
	proxyMu.Lock()
	runs := make([]*proxyRun, 0, len(proxyRuns))
	for _, r := range proxyRuns {
		runs = append(runs, r)
	}
	proxyMu.Unlock()

	n := 0
	for _, r := range runs {
		r.mu.Lock()
		if r.chans[id] != nil {
			n++
		}
		r.mu.Unlock()
	}
	return n
}

// startEchoTarget 起一个回环 echo 服务。
// 返回: 监听地址、被接入的连接通道 (服务端作为客户端连上来的那一条)、关闭函数。
func startEchoTarget(t *testing.T) (string, <-chan net.Conn, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起 echo 目标失败: %v", err)
	}
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
			go func(c net.Conn) {
				// echo: 读到的原样写回
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), accepted, func() { ln.Close() }
}

// newTestRun 注册一个 proxyRun 并返回 (用于让 ProxyDrain / proxyHandleUp 找到通道)
func newTestRun(sid string, port int) *proxyRun {
	r := &proxyRun{
		sid:   sid,
		port:  port,
		chans: map[uint32]*proxyChan{},
		stop:  make(chan int, 1),
	}
	proxyMu.Lock()
	proxyRuns[proxyRunKey(sid, port)] = r
	proxyMu.Unlock()
	return r
}

func cleanupProxy(t *testing.T) {
	t.Helper()
	proxyMu.Lock()
	for k, r := range proxyRuns {
		r.mu.Lock()
		for _, c := range r.chans {
			c.closed = true
			if c.client != nil {
				c.client.Close()
			}
		}
		r.chans = map[uint32]*proxyChan{}
		r.mu.Unlock()
		if r.ln != nil {
			r.ln.Close()
		}
		delete(proxyRuns, k)
	}
	for k := range rportfwdRuns {
		delete(rportfwdRuns, k)
	}
	for k := range proxyOpenMap {
		delete(proxyOpenMap, k)
	}
	proxyMu.Unlock()
}

func proxyUpFrame(chanID uint32, payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(b[0:], chanID)
	copy(b[4:], payload)
	return b
}

// ------------------------------------------------------- 1. 通道建立与上行

func TestProxyChanEstablishAndUpstream(t *testing.T) {
	defer cleanupProxy(t)
	sess := testSession(t, "B001")
	newTestRun(sess.ID, 1080)

	// 模拟 SOCKS 客户端 (未连接)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	run := proxyRuns[proxyRunKey(sess.ID, 1080)]
	c, err := proxyChanNew(run, c1, bufio.NewReader(c1), "127.0.0.1", 8443)
	if err != nil {
		t.Fatalf("建通道失败: %v", err)
	}
	if c.id == 0 || c.id > 0x3FFF {
		t.Fatalf("服务端通道号必须落在 0x0001..0x3FFF, 得到 %#x", c.id)
	}

	// open 任务应当已入队
	if len(sess.Queue) != 1 {
		t.Fatalf("应入队 1 个 open 任务, 实得 %d", len(sess.Queue))
	}
	open := sess.Queue[0]
	if open.Class != cmdProxy {
		t.Fatalf("open 任务 cmd_class 应为 0x0B, 实得 %#x", open.Class)
	}
	if len(open.Arg) < 11 {
		t.Fatalf("open arg 过短: %d", len(open.Arg))
	}
	if got := binary.BigEndian.Uint32(open.Arg[0:]); got != c.id {
		t.Fatalf("open arg chan_id 应为 %d, 实得 %d", c.id, got)
	}
	if open.Arg[4] != 0x01 {
		t.Fatalf("open op 应为 1, 实得 %d", open.Arg[4])
	}
	hlen := int(binary.BigEndian.Uint16(open.Arg[5:]))
	if hlen != len("127.0.0.1") || string(open.Arg[7:7+hlen]) != "127.0.0.1" {
		t.Fatalf("open arg host 编码错误: hlen=%d host=%q", hlen, open.Arg[7:7+hlen])
	}
	if got := binary.BigEndian.Uint16(open.Arg[7+hlen:]); got != 8443 {
		t.Fatalf("open arg port 应为 8443, 实得 %d", got)
	}

	// 未回执前 acked 应仍阻塞
	select {
	case <-c.acked:
		t.Fatal("未收到植入体回执时 acked 不应关闭")
	default:
	}

	// open 回执 -> 通道建立
	if !ProxyResult(sess, 1, []byte("[+] ok")) {
		t.Fatal("ProxyResult 未命中 open 任务映射")
	}
	select {
	case <-c.acked:
	case <-time.After(time.Second):
		t.Fatal("ProxyResult 后 acked 应关闭")
	}
	if ProxyResult(sess, 1, []byte("[+] ok")) {
		t.Fatal("同一 task 的二次回执不应再命中")
	}

	// 上行数据 -> 应写入客户端
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := c2.Read(buf)
		done <- string(buf[:n])
	}()

	if !ProxyHandleUpstream(sess, tlvProxyData, proxyUpFrame(c.id, []byte("GET / HTTP/1.0\r\n\r\n"))) {
		t.Fatal("ProxyHandleUpstream 对 0x1004 应返回 true")
	}
	select {
	case got := <-done:
		if got != "GET / HTTP/1.0\r\n\r\n" {
			t.Fatalf("客户端收到的上行数据不符: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("上行数据未送达客户端")
	}

	// 非代理 TLV 不应被吞
	if ProxyHandleUpstream(sess, tlvHeartbeat, []byte{0, 0, 0, 0}) {
		t.Fatal("非 0x1004 的 TLV 必须返回 false, 交给既有分支")
	}
}

// ------------------------------------------------------- 2. 空载荷关闭语义

func TestProxyEmptyPayloadClosesChan(t *testing.T) {
	defer cleanupProxy(t)
	sess := testSession(t, "B002")
	run := newTestRun(sess.ID, 1081)

	c1, _ := net.Pipe()
	defer c1.Close()

	c, err := proxyChanNew(run, c1, bufio.NewReader(c1), "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("建通道失败: %v", err)
	}
	ProxyResult(sess, 1, []byte("[+] ok"))
	sess.Queue = nil

	ProxyHandleUpstream(sess, tlvProxyData, proxyUpFrame(c.id, nil))

	if proxyFindChan(c.id) != nil {
		t.Fatal("空载荷应触发通道关闭并从运行表摘除")
	}
	run.mu.Lock()
	n := len(run.chans)
	run.mu.Unlock()
	if n != 0 {
		t.Fatalf("关闭后 run 内通道数应为 0, 实得 %d", n)
	}
}

// --------------------------------------------------- 3. 未知通道: 拒绝并回收

func TestProxyUnknownChanIsRejected(t *testing.T) {
	defer cleanupProxy(t)
	sess := testSession(t, "B003")
	newTestRun(sess.ID, 1082)

	// 低位半区的未知通道 (不属于植入体可自主分配的区间)
	ProxyHandleUpstream(sess, tlvProxyData, proxyUpFrame(0x0123, []byte("orphan")))

	found := false
	for _, task := range sess.Queue {
		if task.Class == cmdProxy && len(task.Arg) == 5 && task.Arg[4] == 0x03 {
			if binary.BigEndian.Uint32(task.Arg[0:]) == 0x0123 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("未知通道的上行数据应回一个 close(0x03) 任务, 避免植入体 fd 泄漏")
	}
}

// --------------------------------------------------- 4. 长度字段边界校验

func TestProxyUpstreamBoundaryChecks(t *testing.T) {
	defer cleanupProxy(t)
	sess := testSession(t, "B004")
	run := newTestRun(sess.ID, 1083)

	c1, _ := net.Pipe()
	defer c1.Close()
	c, err := proxyChanNew(run, c1, bufio.NewReader(c1), "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("建通道失败: %v", err)
	}
	ProxyResult(sess, 1, []byte("[+] ok"))

	// [4B chan_id] 都不够 -> 必须静默忽略, 不得 panic
	ProxyHandleUpstream(sess, tlvProxyData, []byte{0x00, 0x00, 0x00})
	ProxyHandleUpstream(sess, tlvProxyData, nil)
	ProxyHandleUpstream(sess, tlvProxyData, []byte{})

	// 超过 proxyTLVMax 的帧 -> 丢弃
	huge := make([]byte, proxyTLVMax+16)
	binary.BigEndian.PutUint32(huge[0:], c.id)
	ProxyHandleUpstream(sess, tlvProxyData, huge)

	if proxyFindChan(c.id) == nil {
		t.Fatal("畸形帧不应误杀仍然有效的通道")
	}

	// nil session 不得 panic
	if !ProxyHandleUpstream(nil, tlvProxyData, proxyUpFrame(1, []byte("x"))) {
		t.Fatal("nil session 也应消费 0x1004 并返回 true")
	}

	// ProxyDrain 对 nil 的防御
	if n := ProxyDrain(nil); n != 0 {
		t.Fatal("nil session 的 ProxyDrain 应返回 0")
	}
}

// --------------------------------------- 5. 下行数据入队 (CMD_PROXY op=2)

func TestProxyDrainEncodesDataTasks(t *testing.T) {
	defer cleanupProxy(t)
	sess := testSession(t, "B005")
	run := newTestRun(sess.ID, 1084)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	c, err := proxyChanNew(run, c1, bufio.NewReader(c1), "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("建通道失败: %v", err)
	}
	ProxyResult(sess, 1, []byte("[+] ok"))

	// 清掉建通道时产生的 open 任务, 以便单独观察数据任务
	sess.Queue = nil

	// 无数据时必须零入队 (宿主可每轮无条件调用)
	if n := ProxyDrain(sess); n != 0 {
		t.Fatalf("无待发数据时不应入队, 实得 %d", n)
	}
	if len(sess.Queue) != 0 {
		t.Fatalf("无待发数据时队列应为空, 实得 %d", len(sess.Queue))
	}

	// 客户端发 5 字节 -> pump 收进 buf -> drain 入队
	go func() { c2.Write([]byte("hello")) }()

	var n int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && n == 0 {
		n = ProxyDrain(sess)
		if n == 0 {
			runtime.Gosched() // 让后台 pump 有机会把 socket 数据收进通道缓冲
			time.Sleep(10 * time.Millisecond)
		}
	}
	if n == 0 {
		run.mu.Lock()
		bl := len(c.buf)
		run.mu.Unlock()
		t.Fatalf("客户端数据未进入下行任务 (通道缓冲=%d)", bl)
	}
	if len(sess.Queue) != 1 {
		t.Fatalf("应入队 1 个数据任务, 实得 %d", len(sess.Queue))
	}

	task := sess.Queue[0]
	if task.Class != cmdProxy {
		t.Fatalf("数据任务 cmd_class 应为 0x0B, 实得 %#x", task.Class)
	}
	// 逐字节核对 arg = [4B chan_id][1B op=2][payload]
	if len(task.Arg) != 5+5 {
		t.Fatalf("arg 应为 4+1+5=10 字节, 实得 %d", len(task.Arg))
	}
	if got := binary.BigEndian.Uint32(task.Arg[0:]); got != c.id {
		t.Fatalf("arg chan_id 应为 %d, 实得 %d", c.id, got)
	}
	if task.Arg[4] != 0x02 {
		t.Fatalf("arg op 应为 2(data), 实得 %d", task.Arg[4])
	}
	if string(task.Arg[5:]) != "hello" {
		t.Fatalf("arg payload 应为 hello, 实得 %q", string(task.Arg[5:]))
	}

	// 取走后不应有残留
	sess.Queue = nil
	if n2 := ProxyDrain(sess); n2 != 0 {
		t.Fatalf("数据取走后不应再入队, 实得 %d", n2)
	}
}

// 大块下行必须被切成 <= proxyDataChunk 的多个任务 (PEND_ARG_MAX 约束)
func TestProxyDrainChunksLargePayload(t *testing.T) {
	defer cleanupProxy(t)
	sess := testSession(t, "B00C")
	run := newTestRun(sess.ID, 1087)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	c, err := proxyChanNew(run, c1, bufio.NewReader(c1), "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("建通道失败: %v", err)
	}
	ProxyResult(sess, 1, []byte("[+] ok"))

	// 清掉 open 任务后直接往通道缓冲塞大块 (跳过 socket, 聚焦切块逻辑)
	sess.Queue = nil
	big := make([]byte, 200*1024)
	for i := range big {
		big[i] = byte(i)
	}
	run.mu.Lock()
	c.buf = append(c.buf, big...)
	run.mu.Unlock()

	n := ProxyDrain(sess)
	if n < 4 {
		t.Fatalf("200KB 应被切成至少 4 块 (56KB/块), 实得 %d", n)
	}
	// 一次调用内必须把通道缓冲取空
	run.mu.Lock()
	left := len(c.buf)
	run.mu.Unlock()
	if left != 0 {
		t.Fatalf("一次 drain 后通道缓冲应清空, 实得 %d", left)
	}
	if len(sess.Queue) != n {
		t.Fatalf("入队数应与返回值一致: n=%d queue=%d", n, len(sess.Queue))
	}

	total := 0
	for i, task := range sess.Queue {
		if task.Class != cmdProxy || task.Arg[4] != 0x02 {
			t.Fatalf("第 %d 个任务不是 CMD_PROXY data", i)
		}
		payload := task.Arg[5:]
		if len(payload) > proxyDataChunk {
			t.Fatalf("第 %d 块 %d 字节超出 proxyDataChunk=%d", i, len(payload), proxyDataChunk)
		}
		if got := binary.BigEndian.Uint32(task.Arg[0:]); got != c.id {
			t.Fatalf("第 %d 块 chan_id 错误: %d", i, got)
		}
		total += len(payload)
	}
	if total != len(big) {
		t.Fatalf("切块后总字节应为 %d, 实得 %d", len(big), total)
	}
}

// ------------------------------------------- 6. 真实分发路径与上行回注

func TestProxyTLVThroughV2HandleUpload(t *testing.T) {
	defer cleanupProxy(t)

	// 用真实密钥构造一个可加解密的会话
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	for i := range aesKey {
		aesKey[i] = byte(i + 1)
		hmacKey[i] = byte(255 - i)
	}
	sess := &V2Session{ID: "B006", Num: 6, AESKey: aesKey, HMACKey: hmacKey}
	v2st.mu.Lock()
	v2st.byID[sess.ID] = sess
	v2st.mu.Unlock()
	defer func() {
		v2st.mu.Lock()
		delete(v2st.byID, sess.ID)
		v2st.mu.Unlock()
	}()
	run := newTestRun(sess.ID, 1085)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	c, err := proxyChanNew(run, c1, bufio.NewReader(c1), "127.0.0.1", 80)
	if err != nil {
		t.Fatalf("建通道失败: %v", err)
	}
	ProxyResult(sess, 1, []byte("[+] ok"))

	// 构造植入体上行明文: T_PROXY_DATA(0x1004) 一条
	plain := proto.EncodeTLVs(proto.TLV{
		Type: proto.TLVProxyUp,
		Data: proxyUpFrame(c.id, []byte("PING")),
	})

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := c2.Read(buf)
		got <- buf[:n]
	}()

	// 说明: 这里复刻"接线后"在 v2HandleUpload 里的分发顺序 (ParseTLVs ->
	// case tlvProxyData -> ProxyHandleUpstream)。不直接调 v2HandleUpload 是因为
	// 其 switch 尚未接线, 而 v2_core.go 在本任务约束下不可修改。
	tlvs, perr := proto.ParseTLVs(plain)
	if perr != nil || len(tlvs) != 1 {
		t.Fatalf("上行明文不是合法 TLV: %v", perr)
	}
	if tlvs[0].Type != proto.TLVProxyUp {
		t.Fatalf("TLV type 应为 0x1004, 实得 %#x", tlvs[0].Type)
	}
	if len(tlvs[0].Data) < 4 {
		t.Fatalf("0x1004 的 data 至少要有 [4B chan_id], 实得 %d", len(tlvs[0].Data))
	}
	ProxyHandleUpstream(sess, tlvs[0].Type, tlvs[0].Data)

	select {
	case b := <-got:
		if string(b) != "PING" {
			t.Fatalf("经分发路径的上行数据应为 PING, 实得 %q", string(b))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLV 0x1004 未送达客户端")
	}

	// 代理分支不得吞掉非 0x1004 的 TLV
	if ProxyHandleUpstream(sess, proto.TLVHeartbeat, make([]byte, 8)) {
		t.Fatal("非 0x1004 的 TLV 必须交回既有分支")
	}
	// 既有分支本身不受影响
	v2HandleUpload(sess, proto.EncodeTLVs(proto.TLV{Type: proto.TLVHeartbeat, Data: make([]byte, 8)}))

	// 下行: 客户端数据 -> ProxyDrain 入队 -> arg 必须能被植入体侧的解析逻辑读懂。
	// 这里直接写入通道缓冲而不依赖后台 pump 的读取时机 (pump 的 socket->buf
	// 通路已在 TestProxyDrainEncodesDataTasks 里覆盖)。
	sess.Queue = nil
	run.mu.Lock()
	c.buf = append(c.buf, []byte("DATA")...)
	run.mu.Unlock()

	if n := ProxyDrain(sess); n == 0 {
		t.Fatal("未产生下行数据任务")
	}
	var dataTask *proto.Task
	for _, task := range sess.Queue {
		if task.Class == cmdProxy && len(task.Arg) > 5 && task.Arg[4] == 0x02 {
			dataTask = task
			break
		}
	}
	if dataTask == nil {
		t.Fatal("队列里没有 CMD_PROXY data 任务")
	}
	if string(dataTask.Arg[5:]) != "DATA" {
		t.Fatalf("下行 payload 应为 DATA, 实得 %q", string(dataTask.Arg[5:]))
	}
}

// ---------------------------------------- 10. 并发压力 (替代 -race 的并发验证)
//
// 本环境的 go race 运行时无法加载 (0xc0000139, 缺运行库), 因此用高并发压测
// 代替: 多 goroutine 同时 drain 下行 / 回注上行 / 建关通道, 若存在对 c.buf
// 的并发读写, 在 -count 多轮下会以 panic 或数据错乱暴露。

func TestProxyConcurrentStress(t *testing.T) {
	defer cleanupProxy(t)
	sess := testSession(t, "B00B")
	run := newTestRun(sess.ID, 1086)

	const nChan = 8
	// 必须用真实 TCP 环回: net.Pipe 无缓冲, 客户端 Write 会阻塞到 pump 读走,
	// 而 pump 在高水位时故意停读形成背压 -> Write 永久阻塞, 会误判成死锁。
	pipes := make([][2]net.Conn, 0, nChan)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	for i := 0; i < nChan; i++ {
		var server net.Conn
		accepted := make(chan net.Conn, 1)
		go func() {
			c, aerr := ln.Accept()
			if aerr == nil {
				accepted <- c
			}
		}()
		client, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			t.Fatalf("拨号失败: %v", derr)
		}
		select {
		case server = <-accepted:
		case <-time.After(3 * time.Second):
			t.Fatal("accept 超时")
		}
		defer client.Close()
		defer server.Close()
		pipes = append(pipes, [2]net.Conn{server, client})
		c, cerr := proxyChanNew(run, server, bufio.NewReader(server), "127.0.0.1", 80)
		if cerr != nil {
			t.Fatalf("建通道失败: %v", cerr)
		}
		ProxyResult(sess, uint32(i+1), nil)
		_ = c
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 3 个 goroutine 并发 drain + 并发建关通道; 目标是暴露对 buf 的并发访问
	var badState atomic.Int32

	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if n := ProxyDrain(sess); n == 0 {
					time.Sleep(time.Millisecond) // 让出调度, 避免忙循环
				}
			}
		}()
	}

	// 1 个 goroutine 持续消费队列, 模拟宿主每轮 takeQueue
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tasks := sess.takeQueue()
			for _, task := range tasks {
				if task.Class != cmdProxy {
					continue
				}
				if len(task.Arg) < 5 {
					badState.Add(1)
					return
				}
				if task.Arg[4] == 0x02 && len(task.Arg) < 4 {
					badState.Add(1)
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// 2 个 goroutine 并发回注上行
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ids := make([]uint32, 0, nChan)
			proxyMu.Lock()
			for _, r := range proxyRuns {
				r.mu.Lock()
				for id := range r.chans {
					ids = append(ids, id)
				}
				r.mu.Unlock()
			}
			proxyMu.Unlock()
			for i := 0; i < 150; i++ {
				for _, id := range ids {
					ProxyHandleUpstream(sess, tlvProxyData, proxyUpFrame(id, []byte("X")))
				}
			}
		}(w)
	}

	// 客户端持续写, 制造 buf 增长
	for i := 0; i < nChan; i++ {
		wg.Add(1)
		go func(b net.Conn) {
			defer wg.Done()
			for j := 0; j < 60; j++ {
				b.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := b.Write([]byte("payload-payload-payload")); err != nil {
					return
				}
			}
		}(pipes[i][1])
	}

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	if n := badState.Load(); n != 0 {
		t.Fatalf("并发压下产生 %d 次畸形任务", n)
	}

	// 全部通道仍应可正常关闭, 无泄漏
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
			proxyCloseChan(c, sess, false)
		}
	}
	if n := proxyChanTotal(); n != 0 {
		t.Fatalf("压测后通道未清空, 残留 %d 条", n)
	}
}

// ------------------------------------------------- 11. REST 入口参数校验

func TestProxyStartValidation(t *testing.T) {
	defer cleanupProxy(t)

	if _, err := ProxyStart("NOPE", 1080); err == nil {
		t.Fatal("不存在的会话应报错")
	}
	sess := testSession(t, "B008")
	v2st.mu.Lock()
	v2st.byID[sess.ID] = sess
	v2st.mu.Unlock()
	defer func() {
		v2st.mu.Lock()
		delete(v2st.byID, sess.ID)
		v2st.mu.Unlock()
	}()

	if _, err := ProxyStart(sess.ID, 0); err == nil {
		t.Fatal("端口 0 应报错")
	}
	if _, err := ProxyStart(sess.ID, 70000); err == nil {
		t.Fatal("越界端口应报错")
	}

	// 占用一个回环端口再要求同端口启动, 应报"已在运行"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("占位监听失败: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	newTestRun(sess.ID, port)
	if _, err := ProxyStart(sess.ID, port); err == nil {
		t.Fatal("同 sid 同端口重复启动应报错")
	}
	// 端口上的其它 socket 与代理表无关, 这里只验证重复检测
	delete(proxyRuns, proxyRunKey(sess.ID, port))
	ln.Close()

	if err := ProxyStop(sess.ID, 65000); err == nil {
		t.Fatal("停止未运行的入口应报错")
	}
}

// ------------------------------------------------- 9. rportfwd 参数校验

func TestRPortfwdValidation(t *testing.T) {
	defer cleanupProxy(t)

	sess := testSession(t, "B009")
	v2st.mu.Lock()
	v2st.byID[sess.ID] = sess
	v2st.mu.Unlock()
	defer func() {
		v2st.mu.Lock()
		delete(v2st.byID, sess.ID)
		v2st.mu.Unlock()
	}()

	if _, err := RPortfwdStart(sess.ID, 0, ""); err == nil {
		t.Fatal("bind 端口 0 应报错")
	}
	if _, err := RPortfwdStart(sess.ID, 9002, "no-port-here"); err == nil {
		t.Fatal("target 缺少端口应报错")
	}

	if _, err := RPortfwdStart(sess.ID, 9002, "127.0.0.1:8443"); err != nil {
		t.Fatalf("合法参数不应报错: %v", err)
	}
	if len(sess.Queue) != 1 || sess.Queue[0].Class != cmdRPortfwd {
		t.Fatalf("应入队 1 个 0x13 任务, 实得 %d", len(sess.Queue))
	}
	arg := sess.Queue[0].Arg
	if len(arg) != 5 || arg[0] != 1 {
		t.Fatalf("rportfwd arg 应为 [1B op=1][2B bind][2B target], 实得 %v", arg)
	}
	if got := binary.BigEndian.Uint16(arg[1:]); got != 9002 {
		t.Fatalf("bind 端口应为 9002, 实得 %d", got)
	}
	if got := binary.BigEndian.Uint16(arg[3:]); got != 8443 {
		t.Fatalf("协议 target 字段应为 8443, 实得 %d", got)
	}

	if err := RPortfwdStop(sess.ID, 9002); err != nil {
		t.Fatalf("停止已启动的转发不应报错: %v", err)
	}
	if len(sess.Queue) != 2 || sess.Queue[1].Arg[0] != 0 {
		t.Fatal("停止应入队 op=0 的任务")
	}
}
