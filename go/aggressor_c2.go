// csdev :: aggressor_c2.go  --  脚本引擎到 C2 的桥接实现 + 全局脚本运行时
//
// 把 v2 会话能力暴露给 Aggressor 脚本, 并把脚本注册的命令接入控制台命令分发。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ---------------------------------------------------------------- 桥接实现

type v2Bridge struct{}

func (v2Bridge) Task(sid, cmd string) error {
	sess := v2st.lookup(sid)
	if sess == nil {
		return fmt.Errorf("会话 %s 不存在或不是 v2 会话", sid)
	}
	_, err := v2SendCommand(sess, cmd)
	return err
}

func (v2Bridge) Ids() []string {
	out := []string{}
	for _, s := range v2st.list() {
		out = append(out, s.ID)
	}
	return out
}

func (v2Bridge) Info(sid string) map[string]string {
	m := map[string]string{}
	if s := v2st.lookup(sid); s != nil {
		m["sid"] = s.ID
		m["host"] = s.Host
		m["user"] = s.User
		m["arch"] = s.Arch
		m["pid"] = fmt.Sprintf("%d", s.PID)
		m["ppid"] = fmt.Sprintf("%d", s.PPID)
		m["proc"] = s.Proc
		m["os"] = s.OSVer
		m["addr"] = s.Addr
		m["sleep"] = fmt.Sprintf("%d", s.SleepMS)
		m["jitter"] = fmt.Sprintf("%d", s.Jitter)
		return m
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	if s, ok := st.byID[sid]; ok {
		m["sid"] = s.ID
		m["host"] = s.Host
		m["user"] = s.User
		m["arch"] = s.Arch
		m["addr"] = s.Addr
		m["proto"] = "v1"
	}
	return m
}

func (v2Bridge) Sleep(sid string, ms, jitter int) error {
	sess := v2st.lookup(sid)
	if sess == nil {
		return fmt.Errorf("会话 %s 不存在", sid)
	}
	if ms < 100 {
		ms = 100
	}
	if jitter < 0 || jitter > 99 {
		jitter = 10
	}
	sess.SleepMS = uint32(ms)
	sess.Jitter = uint8(jitter)
	arg := make([]byte, 5)
	arg[0] = byte(ms >> 24)
	arg[1] = byte(ms >> 16)
	arg[2] = byte(ms >> 8)
	arg[3] = byte(ms)
	arg[4] = byte(jitter)
	sess.enqueue(cmdSetSleep, "sleep", arg)
	return nil
}

func (v2Bridge) Exit(sid string) error {
	sess := v2st.lookup(sid)
	if sess == nil {
		return fmt.Errorf("会话 %s 不存在", sid)
	}
	sess.enqueue(cmdExit, "exit", nil)
	return nil
}

func (v2Bridge) BOF(sid, path string, args []string) error {
	sess := v2st.lookup(sid)
	if sess == nil {
		return fmt.Errorf("会话 %s 不存在或不是 v2 会话", sid)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取 BOF 失败: %w", err)
	}
	packed := bofPack(args)
	arg := make([]byte, 0, len(data)+len(packed)+8)
	hdr := make([]byte, 8)
	hdr[0] = byte(len(data) >> 24)
	hdr[1] = byte(len(data) >> 16)
	hdr[2] = byte(len(data) >> 8)
	hdr[3] = byte(len(data))
	hdr[4] = byte(len(packed) >> 24)
	hdr[5] = byte(len(packed) >> 16)
	hdr[6] = byte(len(packed) >> 8)
	hdr[7] = byte(len(packed))
	arg = append(arg, hdr...)
	arg = append(arg, data...)
	arg = append(arg, packed...)
	sess.enqueue(cmdInjBOF, "bof", arg)
	logf("[script] %s <- BOF %s (%d 字节)", sid, filepath.Base(path), len(data))
	return nil
}

func (v2Bridge) Print(msg string) {
	logf("[script] %s", msg)
}

/* PrintSession 把脚本产出的一段文本写进**某个会话**的输出流。
 * 插件的 blog / berror / binput 走这里 —— 它们在 CS 里就是往该 beacon 的输出窗口写。
 * sid 为空或会话不存在时退化为脚本控制台输出, 不静默丢弃。 */
func (v2Bridge) PrintSession(sid, msg string) {
	if msg == "" {
		return
	}
	if sid != "" {
		if sess := v2st.lookup(sid); sess != nil {
			sess.pushOut(msg)
			return
		}
	}
	scriptOut(strings.TrimRight(msg, "\r\n"))
}

// ---------------------------------------------------------------- 全局运行时

var (
	gScriptMu    sync.RWMutex
	gAggressor   *Aggressor
	gScriptLines []string
)

func scriptOut(line string) {
	gScriptMu.Lock()
	gScriptLines = append(gScriptLines, line)
	if len(gScriptLines) > 2000 {
		gScriptLines = gScriptLines[len(gScriptLines)-1000:]
	}
	gScriptMu.Unlock()
}

// initAggressor 建立脚本运行时: scripts/*.cna + --scripts 附加脚本 + 已选中的插件包。
// 选中的插件集合持久化在 data/plugins.json, 由 plugins.go 负责。
func initAggressor(extra []string) {
	pluginExtraScripts = extra
	pluginLoadState()
	if err := pluginRebuild(); err != nil {
		logf("[!] 脚本运行时初始化失败: %v", err)
	}
}

func aggressorInstance() *Aggressor {
	gScriptMu.RLock()
	defer gScriptMu.RUnlock()
	return gAggressor
}

// ---------------------------------------------------------------- 命令分发接入

// scriptTryCommand 先让脚本命令接管; 命中返回 true。
// 调用点在 handleCommand 里, 位于内置命令路由之前。
func scriptTryCommand(w http.ResponseWriter, sid, cmd string) bool {
	a := aggressorInstance()
	if a == nil {
		return false
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	name := fields[0]

	// 只有注册过的脚本命令才拦截, 避免吞掉正常命令
	hit := false
	for _, n := range a.CommandNames() {
		if n == name {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}

	args := []ScriptValue{sid}
	for _, f := range fields[1:] {
		args = append(args, f)
	}
	ok, err := a.RunCommand(name, args)
	if !ok {
		return false
	}
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return true
	}
	writeJSON(w, map[string]interface{}{"ok": true, "mapped": "script:" + name})
	return true
}

// scriptSummary 供 /api/state 轻量展示脚本状态 (不含输出全文)
func scriptSummary() map[string]interface{} {
	a := aggressorInstance()
	if a == nil {
		return map[string]interface{}{"loaded": 0, "commands": []string{}}
	}
	names := a.CommandNames()
	return map[string]interface{}{
		"loaded":   len(a.LoadedScripts()),
		"commands": names,
		"menus":    len(a.Menus()),
	}
}

// ---------------------------------------------------------------- REST

func handleScripts(w http.ResponseWriter, r *http.Request) {
	a := aggressorInstance()
	if a == nil {
		writeJSON(w, map[string]interface{}{"ok": true, "loaded": []string{}, "commands": []string{}})
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			Path string `json:"path"`
			Code string `json:"code"`
			Name string `json:"name"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		var err error
		if req.Code != "" {
			nm := req.Name
			if nm == "" {
				nm = "<inline>"
			}
			err = a.Load(req.Code, nm)
		} else if req.Path != "" {
			err = a.LoadFile(req.Path)
		} else {
			writeJSON(w, map[string]interface{}{"ok": false, "error": "需要 path 或 code"})
			return
		}
		if err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		a.Fire("ready")
		eventLog("system", "", "脚本加载", req.Path+req.Name)
		writeJSON(w, map[string]interface{}{"ok": true})
		return
	}

	gScriptMu.RLock()
	lines := make([]string, len(gScriptLines))
	copy(lines, gScriptLines)
	gScriptMu.RUnlock()

	writeJSON(w, map[string]interface{}{
		"ok":       true,
		"loaded":   a.LoadedScripts(),
		"commands": a.CommandNames(),
		"menus":    menuSummary(a),
		"menubar":  a.Menubar(),
		"missing":  a.MissingFuncs(),
		// missing 按类别拆分: Beacon API(该适配) vs 客户端 UI(不可能实现)
		"missing_detail": a.MissingFuncsDetailed(),
		"diag":           a.Diag(),
		"output":         lines,
	})
}

func menuSummary(a *Aggressor) []map[string]interface{} {
	out := []map[string]interface{}{}
	var walk func(items []*menuItem) []map[string]interface{}
	walk = func(items []*menuItem) []map[string]interface{} {
		res := []map[string]interface{}{}
		for _, it := range items {
			m := map[string]interface{}{"name": it.Name, "action": it.Body != nil, "kind": it.Kind}
			if len(it.Children) > 0 {
				m["children"] = walk(it.Children)
			}
			res = append(res, m)
		}
		return res
	}
	for _, md := range a.Menus() {
		out = append(out, map[string]interface{}{
			"parent": md.Parent,
			"items":  walk(md.Items),
		})
	}
	return out
}

// handleScriptRun 执行一个脚本命令 (供 GUI 调用)
func handleScriptRun(w http.ResponseWriter, r *http.Request) {
	a := aggressorInstance()
	if a == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "脚本引擎未启用"})
		return
	}
	var req struct {
		Name string   `json:"name"`
		SID  string   `json:"sid"`
		Args []string `json:"args"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	args := []ScriptValue{req.SID}
	for _, x := range req.Args {
		args = append(args, x)
	}
	ok, err := a.RunCommand(req.Name, args)
	if !ok {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "未找到脚本命令 " + req.Name})
		return
	}
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}

/* handleScriptMenu 执行一个插件菜单项的 body。
 *
 * 为什么需要它: 菜单项的名字只存在于脚本里(popup 体内的 item(...)),
 * 不是命令表成员 —— 实测原版 default.cna 的 86 个可执行菜单项里
 * 没有一个名字命中命令表, 所以 /api/script/run 那条路点不动插件菜单。
 * 这里按 (popup 名, 菜单项名) 定位菜单项并直接跑它的 body, $1 = 会话号。
 */
func handleScriptMenu(w http.ResponseWriter, r *http.Request) {
	a := aggressorInstance()
	if a == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "脚本引擎未启用"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅支持 POST"})
		return
	}
	var req struct {
		Parent string   `json:"parent"`
		Name   string   `json:"name"`
		SID    string   `json:"sid"`
		Args   []string `json:"args"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	it := a.FindMenuItem(req.Parent, req.Name)
	if it == nil {
		writeJSON(w, map[string]interface{}{
			"ok":    false,
			"error": fmt.Sprintf("在 popup %q 下没有可执行的菜单项 %q", req.Parent, req.Name),
			"hint":  "可用项可用 /api/scripts 的 menus 字段核验",
		})
		return
	}
	args := []ScriptValue{req.SID}
	for _, x := range req.Args {
		args = append(args, x)
	}
	skipped, err := a.RunMenuItem(it, args...)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	logf("[*] 执行脚本菜单项 %s/%s (会话 %s)%s", req.Parent, req.Name, req.SID,
		func() string {
			if len(skipped) > 0 {
				return fmt.Sprintf(" 跳过未实现函数 %d 个", len(skipped))
			}
			return ""
		}())
	eventLog("script", req.SID, "菜单项", req.Parent+"/"+req.Name)
	writeJSON(w, map[string]interface{}{
		"ok":       true,
		"skipped":  skipped,
		"warnings": skipWarnings(skipped),
	})
}

// skipWarnings 把被跳过的未实现函数翻译成给操作员看的提示(带分类)
func skipWarnings(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		switch MissingKind(n) {
		case "Beacon API 未适配", "Beacon/BOF API 未适配":
			// 这类是"本来该适配的", 提示要指向问题本身, 而不是推给"客户端 UI"
			out = append(out, fmt.Sprintf("%s 未适配 —— 它是 Beacon API(不是客户端 UI), 本引擎暂无对应命令面", n))
		case "客户端显示格式函数":
			out = append(out, fmt.Sprintf("%s 是 CS 客户端的显示格式函数, 本引擎没有该界面", n))
		default:
			out = append(out, fmt.Sprintf("%s 未实现(本引擎没有 CS 客户端 UI)", n))
		}
	}
	return out
}

// decodeJSONBody 小工具: 供本文件与其它 handler 复用
func decodeJSONBody(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}
