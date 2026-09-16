//go:build !windows

// csdev :: smb_listener_stub.go  --  非 Windows 平台上的 SMB 承载占位
//
// SMB 命名管道是 Windows 独有的 IPC 机制, Linux/macOS 上**不存在对等物** ——
// 所以这里不提供"替代实现", 只提供一组**签名与 windows 版完全相同、调用即报不支持**
// 的桩, 让服务端在 Linux 上完整编译并正常运行其余五种承载层
// (http / tcp / dns / extc2 / https)。
//
// 桩必须导出与 smb_listener.go 同名的符号 (SMBListener / gSMBListeners /
// startSMBListener), 否则 listener_admin.go 在 Linux 上会报 undefined —— 实测就是这样炸的。
//
// 设计取舍: 报错文案要说明"为什么不可用", 而不是含糊的"启动失败"。操作员在 Linux 上
// 点"新建 SMB 监听器"时应当立刻明白这是平台限制, 并且知道该改用哪种承载。

package main

import (
	"crypto/rsa"
	"errors"
	"sync"
)

// SMBListener 在非 Windows 平台上的占位类型。
//
// 字段与 windows 版**保持同名同类型** (Pipe / mu / conns) —— listener_admin.go 会读
// l.Pipe 做地址比对、读 l.mu/l.conns 报连接数, 这两条路径在 Linux 上照样会被走到
// (统计接口与删除接口不区分平台)。少一个字段就编译不过。
type SMBListener struct {
	Pipe  string     // 管道名, 供按地址定位实例
	mu    sync.Mutex // 与 windows 版同名, 保证 listener_admin.go 的加锁代码两平台一致
	conns int        // 连接数, 桩上恒为 0
}

// Stop 在桩上是空操作 —— 这个平台上根本不存在监听器, 没有东西需要停。
func (l *SMBListener) Stop() {}

// gSMBListeners 在非 Windows 平台上**恒为空**。
//
// listener_admin.go 会遍历它做统计与删除: 空切片让那些代码路径自然走
// "没有 SMB listener"的分支, 于是无需在调用方到处写平台判断 —— 把平台差异
// 收敛在这一个文件里, 而不是散到业务逻辑里。
var gSMBListeners []*SMBListener

// errSMBNotSupported 明确说明平台限制与替代方案。
var errSMBNotSupported = errors.New(
	"SMB 命名管道是 Windows 专有机制, 当前平台不支持; " +
		"Linux/macOS 上请改用 http / tcp / dns / extc2 承载层")

// startSMBListener 在非 Windows 平台上直接返回不支持。
//
// 刻意返回 error 而不是 nil: 静默成功会让操作员以为监听器起来了,
// 而后面的植入体永远连不上 —— 那种"看起来正常"的失败最难排查。
func startSMBListener(pipe string, priv *rsa.PrivateKey) error {
	return errSMBNotSupported
}
