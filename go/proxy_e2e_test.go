package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestProxyLoopbackFullChain 是全链路回环验证:
//
//	手写 SOCKS5 客户端 -> 服务端 SOCKS 监听 -> CMD_PROXY(open) 任务
//	-> (测试充当植入体) 连到内网 HTTP 目标 -> T_PROXY_DATA 上行回注
//	-> 客户端收到 HTTP 响应
//
// 这是"除真实植入体 socket 转发外"的端到端验证。植入体进程那一跳无法在此
// 覆盖, 因为 beacon2.c 尚未接线 (见交付说明)。但与植入体的全部交互面
// (任务格式、chan_id 分配、TLV 收发、关闭语义) 都在这里真实经过。
func TestProxyLoopbackFullChain(t *testing.T) {
	defer cleanupProxy(t)
	t0 := time.Now()
	mark := func(m string) { t.Logf("T+%6dms %s", time.Since(t0).Milliseconds(), m) }

	mark("start")
	// --- 内网目标: 必须收到 SOCKS 链路上的请求才会返回 200 ---
	const magic = "csdev-proxy-e2e-ok"
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起目标服务失败: %v", err)
	}
	defer origin.Close()
	originHit := make(chan string, 4)

	go func() {
		for {
			c, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, _ := http.ReadRequest(br)
				if req == nil {
					return
				}
				select {
				case originHit <- req.URL.Path:
				default:
				}
				body := magic
				fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"+
					"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()

	mark("origin up")
	// --- 会话与 SOCKS 入口 ---
	sess := testSession(t, "B100")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起 SOCKS 入口失败: %v", err)
	}
	defer ln.Close()
	socksPort := ln.Addr().(*net.TCPAddr).Port

	run := &proxyRun{
		sid:   sess.ID,
		port:  socksPort,
		ln:    ln,
		chans: map[uint32]*proxyChan{},
		stop:  make(chan int, 1),
	}
	proxyMu.Lock()
	proxyRuns[proxyRunKey(sess.ID, socksPort)] = run
	proxyMu.Unlock()
	go proxyAcceptLoop(run)
	proxyPumpStart()

	mark("socks listen")
	// --- 客户端: 完整 SOCKS5 握手 ---
	cli, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("连 SOCKS 入口失败: %v", err)
	}
	defer cli.Close()
	cli.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := cli.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("方法协商写失败: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(cli, sel); err != nil {
		t.Fatalf("读方法协商应答失败: %v", err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		t.Fatalf("方法协商失败: %v", sel)
	}

	oHost, oPortStr, _ := net.SplitHostPort(origin.Addr().String())
	oIP := net.ParseIP(oHost).To4()
	var oPort uint16
	fmt.Sscanf(oPortStr, "%d", &oPort)
	req := []byte{0x05, 0x01, 0x00, 0x01, oIP[0], oIP[1], oIP[2], oIP[3],
		byte(oPort >> 8), byte(oPort & 0xFF)}
	if _, err := cli.Write(req); err != nil {
		t.Fatalf("CONNECT 写失败: %v", err)
	}

	mark("connect sent")
	// --- 测试充当植入体: 取出 open 任务并解析 ---
	openTask := waitProxyTask(t, sess, 10*time.Second)
	if openTask.Class != cmdProxy || len(openTask.Arg) < 11 || openTask.Arg[4] != 0x01 {
		t.Fatalf("不是合法的 open 任务: class=%#x arglen=%d", openTask.Class, len(openTask.Arg))
	}
	chanID := binary.BigEndian.Uint32(openTask.Arg[0:])
	hlen := int(binary.BigEndian.Uint16(openTask.Arg[5:]))
	host := string(openTask.Arg[7 : 7+hlen])
	port := binary.BigEndian.Uint16(openTask.Arg[7+hlen:])
	if host != oHost || port != oPort {
		t.Fatalf("open 目标应为 %s:%d, 实得 %s:%d", oHost, oPort, host, port)
	}
	t.Logf("植入体侧收到 open: chan=%d -> %s:%d", chanID, host, port)

	// 植入体回执 (真实路径: 宿主在 v2HandleResult 里按 task_id 调 ProxyResult)
	proxyMu.Lock()
	proxyOpenMap[openTask.ID] = chanID
	proxyMu.Unlock()
	if !ProxyResult(sess, openTask.ID, nil) {
		t.Fatal("ProxyResult 未命中 open 任务映射")
	}

	mark("open task got")
	// 客户端应收到 SOCKS 成功应答
	reply := make([]byte, 10)
	if _, err := io.ReadFull(cli, reply); err != nil {
		t.Fatalf("读 CONNECT 应答失败: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT 被拒: REP=0x%02X", reply[1])
	}
	t.Log("客户端收到 SOCKS5 CONNECT 成功")

	mark("socks ok")
	// --- 客户端发 HTTP 请求 (经 SOCKS 隧道) ---
	httpReq := fmt.Sprintf("GET /e2e HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", origin.Addr().String())
	if _, err := cli.Write([]byte(httpReq)); err != nil {
		t.Fatalf("写 HTTP 请求失败: %v", err)
	}

	mark("http req sent")
	// --- 测试充当植入体: 把下行数据取出并送到真目标, 再把响应回注 ---
	targetConn, err := net.DialTimeout("tcp", origin.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("植入体侧连目标失败: %v", err)
	}
	defer targetConn.Close()

	respText := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		var all []byte
		for {
			n, rerr := targetConn.Read(buf)
			if n > 0 {
				all = append(all, buf[:n]...)
				// 目标响应原样上行回注给服务端
				ProxyHandleUpstream(sess, tlvProxyData, proxyUpFrame(chanID, buf[:n]))
			}
			if rerr != nil {
				break
			}
		}
		respText <- string(all)
	}()

	// 把下行数据 (channel buf -> 任务) 交给"植入体", 再由它写到目标
	deadline := time.Now().Add(15 * time.Second)
	done := false
	for time.Now().Before(deadline) && !done {
		if n := ProxyDrain(sess); n > 0 {
			for _, task := range sess.takeQueue() {
				if task.Class != cmdProxy || len(task.Arg) < 6 || task.Arg[4] != 0x02 {
					continue
				}
				if binary.BigEndian.Uint32(task.Arg[0:]) != chanID {
					continue
				}
				if _, werr := targetConn.Write(task.Arg[5:]); werr != nil {
					t.Fatalf("植入体写目标失败: %v", werr)
				}
				done = true
			}
		}
		if !done {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !done {
		t.Fatal("HTTP 请求未通过 SOCKS 隧道到达目标")
	}

	mark("relayed to target")
	// --- 客户端应收到 HTTP 响应 ---
	// 读到完整响应即可判定 (按 Content-Length 收满), 不要等对端关闭:
	// 上游的关闭通知是否及时到达取决于 pump 时序, 等它只会白等一个读超时。
	var got []byte
	cli.SetReadDeadline(time.Now().Add(10 * time.Second))
	for len(got) < 4096 {
		buf := make([]byte, 4096)
		n, rerr := cli.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		gs := string(got)
		head := indexOf(gs, "\r\n\r\n")
		clen := -1
		if head >= 0 {
			if h := indexOf(gs, "Content-Length: "); h >= 0 && h < head {
				fmt.Sscanf(gs[h+len("Content-Length: "):], "%d", &clen)
			}
		}
		if head >= 0 && clen >= 0 && len(got) >= head+4+clen {
			break
		}
		if rerr != nil {
			break
		}
	}
	gotStr := string(got)
	if !contains(gotStr, "200 OK") || !contains(gotStr, magic) {
		t.Fatalf("客户端未收到预期的 HTTP 响应, 实得 %d 字节: %q", len(got), truncate(gotStr, 300))
	}
	mark("http resp read")
	t.Logf("全链路通过: 客户端收到 %d 字节 HTTP 响应, 目标被访问路径=%s",
		len(got), <-originHit)
	mark("done")
}

// waitProxyTask 等到会话队列里出现一个 CMD_PROXY 任务 (跳过其它类别)
func waitProxyTask(t *testing.T, sess *V2Session, timeout time.Duration) *protoTaskAlias {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, task := range sess.takeQueue() {
			if task.Class == cmdProxy {
				return &protoTaskAlias{ID: task.ID, Class: task.Class, Arg: task.Arg}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("等待 CMD_PROXY 任务超时")
	return nil
}

type protoTaskAlias struct {
	ID    uint32
	Class byte
	Arg   []byte
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
