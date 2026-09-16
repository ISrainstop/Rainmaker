// csdev :: aggressor_builtins.go  --  脚本引擎内置函数与 C2 桥接
//
// 分两层:
//   核心内置 (registerCoreBuiltins) —— 纯字符串/数值/流程, 不依赖 C2
//   C2 桥接 (AttachC2)             —— btask/bof/bsleep 等, 通过接口注入避免循环依赖
package main

import (
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------- C2 桥接接口

// C2Bridge 是脚本引擎访问 C2 能力的唯一通道。
// 由服务端实现 (见 aggressor_c2.go), 引擎本身不 import 任何 C2 内部符号。
type C2Bridge interface {
	Task(sid, cmd string) error
	Ids() []string
	Info(sid string) map[string]string
	Sleep(sid string, ms int, jitter int) error
	Exit(sid string) error
	BOF(sid, path string, args []string) error
	Print(msg string)
	/* PrintSession 把一段文本追加到**某个会话**的输出流里。
	 * 插件的 blog/berror/binput 需要它: 那些文本本来就是给操作员看的提示,
	 * 不该混进脚本控制台的全局输出。sid 为空或不存在时退化为全局输出。 */
	PrintSession(sid, msg string)
}

func (a *Aggressor) AttachC2(b C2Bridge) {
	a.mu.Lock()
	a.c2 = b
	a.mu.Unlock()
}

func (a *Aggressor) bridge() C2Bridge {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.c2
}

// ---------------------------------------------------------------- 核心内置

func (a *Aggressor) registerCoreBuiltins() {
	a.builtins["print"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		var sb strings.Builder
		for _, v := range args {
			sb.WriteString(toStr(v))
		}
		a.print(sb.String())
		return int64(sb.Len()), nil
	}
	a.builtins["println"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		var sb strings.Builder
		for _, v := range args {
			sb.WriteString(toStr(v))
		}
		a.print(sb.String())
		return int64(sb.Len()), nil
	}
	a.builtins["warn"] = a.builtins["println"]
	a.builtins["berror"] = a.builtins["println"]

	a.builtins["strlen"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 1 {
			return int64(0), nil
		}
		return int64(len(toStr(args[0]))), nil
	}
	a.builtins["str"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		var sb strings.Builder
		for _, v := range args {
			sb.WriteString(toStr(v))
		}
		return sb.String(), nil
	}
	a.builtins["toupper"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 1 {
			return "", nil
		}
		return strings.ToUpper(toStr(args[0])), nil
	}
	a.builtins["tolower"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 1 {
			return "", nil
		}
		return strings.ToLower(toStr(args[0])), nil
	}
	a.builtins["substr"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return "", nil
		}
		s := toStr(args[0])
		start := int(toInt(args[1]))
		length := -1
		if len(args) >= 3 {
			length = int(toInt(args[2]))
		}
		if start < 0 || start >= len(s) {
			return "", nil
		}
		if length < 0 || start+length > len(s) {
			return s[start:], nil
		}
		return s[start : start+length], nil
	}
	a.builtins["strrep"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 3 {
			return "", nil
		}
		return strings.ReplaceAll(toStr(args[0]), toStr(args[1]), toStr(args[2])), nil
	}
	a.builtins["strsplit"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return []ScriptValue{}, nil
		}
		sep := toStr(args[1])
		if sep == "" {
			sep = " "
		}
		parts := strings.Split(toStr(args[0]), sep)
		out := make([]ScriptValue, 0, len(parts))
		for _, p := range parts {
			out = append(out, p)
		}
		return out, nil
	}
	a.builtins["stridx"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return int64(-1), nil
		}
		return int64(strings.Index(toStr(args[0]), toStr(args[1]))), nil
	}
	a.builtins["atoi"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 1 {
			return int64(0), nil
		}
		return toInt(args[0]), nil
	}
	a.builtins["itoa"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 1 {
			return "0", nil
		}
		return fmt.Sprintf("%d", toInt(args[0])), nil
	}
	a.builtins["array"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		return args, nil
	}
	a.builtins["size"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 1 {
			return int64(0), nil
		}
		if arr, ok := args[0].([]ScriptValue); ok {
			return int64(len(arr)), nil
		}
		return int64(len(toStr(args[0]))), nil
	}
	a.builtins["push"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return int64(0), nil
		}
		arr, ok := args[0].([]ScriptValue)
		if !ok {
			arr = []ScriptValue{}
		}
		arr = append(arr, args[1])
		return arr, nil
	}
	a.builtins["sleep"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 1 {
			return int64(0), nil
		}
		ms := toInt(args[0])
		if ms < 0 {
			ms = 0
		}
		if ms > 5000 {
			ms = 5000 // 脚本内 sleep 上限, 防止阻塞服务端
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return ms, nil
	}
	a.builtins["ticks"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		return time.Now().UnixMilli(), nil
	}
}

// ---------------------------------------------------------------- C2 桥接内置

// RegisterC2Builtins 注入依赖 C2 的函数。由服务端在 AttachC2 后调用。
func (a *Aggressor) RegisterC2Builtins() {
	a.builtins["btask"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		b := a.bridge()
		if b == nil {
			return int64(0), fmt.Errorf("btask: 未接入 C2 桥")
		}
		if len(args) < 2 {
			return int64(0), fmt.Errorf("btask: 需要 (sid, 命令)")
		}
		sid, cmd := toStr(args[0]), toStr(args[1])
		if sid == "" {
			return int64(0), fmt.Errorf("btask: sid 为空")
		}
		if err := b.Task(sid, cmd); err != nil {
			return int64(0), err
		}
		return int64(1), nil
	}
	a.builtins["bcommand"] = a.builtins["btask"]

	a.builtins["beacon_ids"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		b := a.bridge()
		if b == nil {
			return []ScriptValue{}, nil
		}
		ids := b.Ids()
		out := make([]ScriptValue, 0, len(ids))
		for _, id := range ids {
			out = append(out, id)
		}
		return out, nil
	}
	a.builtins["beacon_info"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		b := a.bridge()
		if b == nil || len(args) < 1 {
			return "", nil
		}
		info := b.Info(toStr(args[0]))
		if len(args) >= 2 {
			return info[toStr(args[1])], nil
		}
		parts := []string{}
		for k, v := range info {
			parts = append(parts, k+"="+v)
		}
		return strings.Join(parts, " "), nil
	}
	a.builtins["bsleep"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		b := a.bridge()
		if b == nil || len(args) < 2 {
			return int64(0), nil
		}
		ms := int(toInt(args[1]))
		jitter := 0
		if len(args) >= 3 {
			jitter = int(toInt(args[2]))
		}
		if err := b.Sleep(toStr(args[0]), ms, jitter); err != nil {
			return int64(0), err
		}
		return int64(1), nil
	}
	a.builtins["bexit"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		b := a.bridge()
		if b == nil || len(args) < 1 {
			return int64(0), nil
		}
		if err := b.Exit(toStr(args[0])); err != nil {
			return int64(0), err
		}
		return int64(1), nil
	}
	a.builtins["bof"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		b := a.bridge()
		if b == nil || len(args) < 2 {
			return int64(0), fmt.Errorf("bof: 需要 (sid, 本地.o路径, [参数...])")
		}
		extra := []string{}
		for _, v := range args[2:] {
			extra = append(extra, toStr(v))
		}
		if err := b.BOF(toStr(args[0]), toStr(args[1]), extra); err != nil {
			return int64(0), err
		}
		return int64(1), nil
	}
}
