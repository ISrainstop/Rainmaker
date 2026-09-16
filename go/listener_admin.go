// csdev :: listener_admin.go  --  运行时 listener 注册表 (增删)
//
// 背景: 六种承载层 (HTTP/HTTPS/TCP/SMB/DNS/ExternalC2) 原来只能由启动参数决定,
// 服务端起好之后就无法再动。本文件把"当前存在的 listener"统一登记成一张表, 并
// 提供运行期 Add / Remove —— 启动参数路径与 REST 路径写的是同一张表, 因此:
//
//   - 启动参数 (--tcp/--smb/--dns/--extc2) 创建的 listener 同样出现在
//     GET /api/listeners, 也能被 POST /api/listener/remove 删掉
//   - REST 新建的 listener 与参数创建的完全同质 (共用 v2ProcessFrame, 协议零改动)
//
// 统一描述: {id, kind, addr, created, sessions, status}
//   kind ∈ http / https / tcp / smb / dns / extc2
//
// 三条硬约束:
//  1. 主 HTTP/HTTPS listener 是控制台入口 —— 不允许删除; 删它等于切断 /api 控制面。
//  2. 绑定失败如实报错: 端口被占用时 net.Listen 的错误原样返回, 绝不假装成功。
//  3. kind=http/https 的运行期新增不支持 —— 控制台 mux / profile URI 池 / TLS
//     证书都在启动期固化, 后开的 HTTP 口接不到同一个 mux; 明确报错, 不静默降级。
package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- 注册表

// listenerEntry 是注册表里的一行。stop 是真实句柄 —— Remove 调它释放端口/管道,
// 而不是只把表里的行删掉了事。
type listenerEntry struct {
	ID       string
	Kind     string
	Addr     string
	Cre      int64
	Name     string // 展示名 (与改造前的 name 字段逐字一致)
	mainEntr bool   // 控制台入口 (HTTP/HTTPS 主 listener), 受保护
	legacy   bool   // v1 legacy 入口 (与主入口共用同一 HTTP 端口, 不同 URI)

	stop  func()
	stats func() int
}

// listenerRegistry 是唯一数据源: GET /api/listeners 的 8 个既有字段
// (name/type/proto/host/port/uri/ssl/up) 全部由它派生, 其余为追加字段。
type listenerRegistry struct {
	mu      sync.RWMutex
	m       map[string]*listenerEntry
	seq     int
	pinned  []string // 启动参数登记的 id (保序), 列表优先展示
	postAdd func(e *listenerEntry)
	postDel func(e *listenerEntry)
}

var listenerReg = &listenerRegistry{m: map[string]*listenerEntry{}}

// listenerPriv 服务端 RSA 私钥, 由 main 在密钥就绪后设置。
var listenerPriv *rsa.PrivateKey

// ---------------------------------------------------------------- 校验与地址规范化

// 支持的 kind —— 用 map 而不是 switch, 错误信息里要能列出全部合法值
var listenerKinds = map[string]bool{
	"http": true, "https": true, "tcp": true,
	"smb": true, "dns": true, "extc2": true,
}

func kindInList() string { return "http/https/tcp/smb/dns/extc2" }

// prepHostPort 校验并规范化 "ip:port" (host 可省略)。返回 (host, effectiveAddr, err)
func prepHostPort(spec string) (string, string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", fmt.Errorf("地址为空")
	}
	host, portStr, err := net.SplitHostPort(spec)
	if err != nil {
		return "", "", fmt.Errorf("地址格式应为 ip:port (如 0.0.0.0:8444): %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", "", fmt.Errorf("端口非法: %q", portStr)
	}
	if host == "" {
		host = "0.0.0.0"
		spec = "0.0.0.0:" + portStr
	}
	return host, spec, nil
}

// prepSMBPipe 校验并规范化命名管道路径 (允许只给名字)
func prepSMBPipe(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", fmt.Errorf("管道名为空, 形如 \\\\.\\pipe\\csdev_pipe 或 csdev_pipe")
	}
	if !strings.HasPrefix(spec, `\\.\pipe\`) && !strings.HasPrefix(spec, `\\?\pipe\`) {
		spec = `\\.\pipe\` + spec
	}
	name := strings.TrimPrefix(strings.TrimPrefix(spec, `\\.\pipe\`), `\\?\pipe\`)
	if name == "" {
		return "", fmt.Errorf("管道名为空: %q", spec)
	}
	return spec, nil
}

// prepAddr 按 kind 做地址规范化, 返回 (host, effectiveAddr, err)
func prepAddr(kind, addr string) (string, string, error) {
	switch kind {
	case "tcp", "dns", "extc2":
		return prepHostPort(addr)
	case "smb":
		p, err := prepSMBPipe(addr)
		if err != nil {
			return "", "", err
		}
		return "-", p, nil
	case "http", "https":
		if strings.TrimSpace(addr) == "" {
			return "", "", fmt.Errorf("地址为空")
		}
		return "", strings.TrimSpace(addr), nil
	}
	return "", "", fmt.Errorf("未知 listener 类型 %q (支持 %s)", kind, kindInList())
}

// ---------------------------------------------------------------- Add / Remove / List

// listenerAdd 创建并 Start 一个 listener, 只有成功才写进注册表。
// 失败时如实返回错误 (端口占用 / 管道建不出来 / kind 不支持)。
func listenerAdd(kind, addr string, priv *rsa.PrivateKey) (string, error) {
	if !listenerKinds[kind] {
		return "", fmt.Errorf("未知 listener 类型 %q (支持 %s)", kind, kindInList())
	}
	_, eff, err := prepAddr(kind, addr)
	if err != nil {
		return "", err
	}
	if priv == nil {
		return "", fmt.Errorf("服务端密钥未就绪, 无法创建承载 listener")
	}

	e := &listenerEntry{Kind: kind, Addr: eff, Cre: time.Now().Unix()}

	switch kind {
	case "http", "https":
		// 控制台 mux / profile URI 池 / TLS 证书在启动期固化, 运行期再开 HTTP 口
		// 接不到同一个 mux。如实报错, 不给"看似成功"的空壳。
		return "", fmt.Errorf("运行期不支持新增 %s listener: 控制台 mux/TLS 在启动期已固化, "+
			"新 HTTP 口无法共享路由表。HTTP(S) 承载请用启动参数 --port / -tls", kind)
	case "tcp":
		l, err := startTCPListener(eff, priv)
		if err != nil {
			return "", fmt.Errorf("TCP listener 绑定 %s 失败: %w", eff, err)
		}
		e.Addr = l.BoundAddr() // 端口 0 时取内核分配的实端口
		e.stop = l.Stop
		e.stats = l.connCount
	case "smb":
		if err := startSMBListener(eff, priv); err != nil {
			return "", err
		}
		e.Addr = eff
		e.stop = func() { deleteSMBSink(eff) }
		e.stats = smbConnCount(eff)
	case "dns":
		if err := startDNSListener(eff, priv); err != nil {
			return "", err
		}
		e.Addr = dnsSinkAddr(eff)
		e.stop = func() { deleteDNSSink(eff) }
		// DNS 是 UDP, 没有"连接"概念 —— 不给假数字
	case "extc2":
		if err := startExtC2Listener(eff, priv); err != nil {
			return "", err
		}
		e.Addr = eff
		e.stop = func() { deleteExtC2Sink(eff) }
		e.stats = extC2ConnCount(eff)
	}

	e.Name = nameForKind(e.Kind, e.Addr)

	a := listenerReg
	a.mu.Lock()
	a.seq++
	e.ID = fmt.Sprintf("L%03d", a.seq)
	for {
		if _, exists := a.m[e.ID]; !exists {
			break
		}
		a.seq++
		e.ID = fmt.Sprintf("L%03d", a.seq)
	}
	a.m[e.ID] = e
	a.mu.Unlock()

	eid := e.ID
	listenerEvent("add", e, "")
	return eid, nil
}

// listenerRemove 停掉 listener 并从注册表移除。真的停: 关监听 socket / 管道句柄,
// 端口随即释放; 该 listener 上已建立的长连接会被一并关闭。
func listenerRemove(id string) error {
	a := listenerReg
	a.mu.Lock()
	e, ok := a.m[id]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("listener 不存在: %q", id)
	}
	if e.mainEntr {
		a.mu.Unlock()
		return fmt.Errorf("拒绝删除: %s 是主 %s listener (控制台入口 %s), 删掉它等于切断 /api 控制面",
			e.ID, strings.ToUpper(e.Kind), e.Addr)
	}
	delete(a.m, id)
	keep := a.pinned[:0]
	for _, p := range a.pinned {
		if p != id {
			keep = append(keep, p)
		}
	}
	a.pinned = keep
	post := a.postDel
	stop := e.stop
	a.mu.Unlock()

	if post != nil {
		post(e)
	}
	if stop != nil {
		stop()
	}
	return nil
}

// listenerList 生成 /api/listeners 的数组。
// 前 8 个字段 (name/type/proto/host/port/uri/ssl/up) 与改造前逐字一致 —— GUI 在用;
// 之后追加统一描述字段, 只增不改。
func listenerList() []ListenerInfo {
	es := listenerEntries()
	out := make([]ListenerInfo, 0, len(es))
	for _, x := range es {
		host, port := splitHostPortSafe(x.Addr)
		typ, proto, uri := x.Kind, "v2", "-"
		switch x.Kind {
		case "http", "https":
			// 主入口沿用启动期判定: 8443/443 视为 https 型 (pickType)
			typ = pickType(port)
			uri = "/submit"
			if x.legacy {
				proto, uri = "v1", "/report"
			}
		case "smb":
			host, port, uri = "-", 0, x.Addr
		case "dns":
			uri = "TXT"
		case "extc2":
			typ, uri = "external", extc2Magic
		}
		info := ListenerInfo{
			Name: x.Name, Type: typ, Proto: proto,
			Host: host, Port: port, URI: uri,
			SSL: x.Kind == "https", Up: true,
			// ---- 追加字段 (GUI 只读前 8 个, 多出来的被忽略) ----
			ID: x.ID, Kind: x.Kind, Addr: x.Addr, Created: x.Cre,
			Status: "up", Protected: x.mainEntr, Manageable: !x.mainEntr,
		}
		if x.stats != nil {
			info.Conns = x.stats()
		}
		out = append(out, info)
	}
	return out
}

// listenerEntries 快照: 启动参数登记的在前 (保序), 其余按 id 升序。
func listenerEntries() []*listenerEntry {
	a := listenerReg
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]*listenerEntry, 0, len(a.m))
	seen := map[string]bool{}
	for _, id := range a.pinned {
		if e, ok := a.m[id]; ok && !seen[id] {
			out = append(out, e)
			seen[id] = true
		}
	}
	for _, id := range sortedIDs(a.m) {
		if !seen[id] {
			out = append(out, a.m[id])
			seen[id] = true
		}
	}
	return out
}

func listenerGet(id string) *listenerEntry {
	a := listenerReg
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.m[id]
}

func listenerCount() int {
	a := listenerReg
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.m)
}

// sortedIDs 插排: 表规模个位数, 不值得为它引 sort 包
func sortedIDs(m map[string]*listenerEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func nameForKind(kind, addr string) string {
	if kind == "tcp" {
		_, port := splitHostPortSafe(addr)
		return fmt.Sprintf("csdev-tcp-%d", port)
	}
	switch kind {
	case "http":
		return "csdev-v2"
	case "https":
		return "csdev-v2"
	case "smb":
		return "csdev-smb"
	case "dns":
		return "csdev-dns"
	case "extc2":
		return "csdev-extc2"
	}
	return "csdev-" + kind
}

// splitHostPortSafe 从 addr 取 host/port, 解析不了就把整串当 host。
func splitHostPortSafe(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portStr)
	if host == "" {
		host = "0.0.0.0"
	}
	return host, port
}

// ---------------------------------------------------------------- 参数路径接线

// registerMainListener 登记启动期固化的 HTTP(S) 入口 (受保护, 不可 API 删除)。
func registerMainListener(name, typ, proto, host string, port int, uri string, tls bool) {
	kind := "http"
	if tls {
		kind = "https"
	}
	e := &listenerEntry{
		Kind:     kind,
		Addr:     net.JoinHostPort(host, strconv.Itoa(port)),
		Cre:      time.Now().Unix(),
		Name:     name,
		mainEntr: true,
		legacy:   proto == "v1",
	}
	_ = typ

	a := listenerReg
	a.mu.Lock()
	id := "main"
	if e.legacy {
		a.seq++
		id = fmt.Sprintf("L%03d", a.seq)
	}
	for {
		if _, exists := a.m[id]; !exists {
			break
		}
		a.seq++
		id = fmt.Sprintf("L%03d", a.seq)
	}
	e.ID = id
	a.m[id] = e
	a.pinned = append(a.pinned, id)
	a.mu.Unlock()

	listenerEvent("add", e, "启动参数")
	logf("  listener 登记: id=%s kind=%s %s (%s %s)", e.ID, e.Kind, e.Addr, proto, uri)
}

// addFromFlag 处理启动参数 (--tcp/--smb/--dns/--extc2): 与 REST 走同一条 Add,
// 因此它们同样出现在 /api/listeners 里, 也能被 /api/listener/remove 删除。
func addFromFlag(kind, spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	_, eff, err := prepAddr(kind, spec)
	if err != nil {
		return err
	}
	id, err := listenerAdd(kind, eff, listenerPriv)
	if err != nil {
		return err
	}
	logf("  %s 入口: %s  (id=%s, 共用 v2 加密与任务协议)", strings.ToUpper(kind), eff, id)
	if e := listenerGet(id); e != nil {
		eventLog("listener", "", "add-param", fmt.Sprintf("id=%s kind=%s addr=%s", e.ID, e.Kind, e.Addr))
	}
	return nil
}

// smb/dns/extc2 的 stop 需要按地址定位实例: 参数路径与 REST 路径都传规范化后的地址,
// 且同一地址重复 Add 会先被 bind 冲突拦住, 所以按地址查是稳定的。
func deleteSMBSink(pipe string) {
	gSMBMu.Lock()
	defer gSMBMu.Unlock()
	for i, l := range gSMBListeners {
		if l.Pipe == pipe {
			l.Stop()
			gSMBListeners = append(gSMBListeners[:i], gSMBListeners[i+1:]...)
			return
		}
	}
}

func deleteDNSSink(addr string) {
	gDNSMu.Lock()
	defer gDNSMu.Unlock()
	for i, l := range gDNSListeners {
		if l.Addr == addr {
			l.Stop()
			gDNSListeners = append(gDNSListeners[:i], gDNSListeners[i+1:]...)
			return
		}
	}
}

// dnsSinkAddr 取 DNS listener 内核实际绑定的地址 (端口 0 时用)。
func dnsSinkAddr(addr string) string {
	gDNSMu.Lock()
	defer gDNSMu.Unlock()
	for _, l := range gDNSListeners {
		if l.Addr == addr {
			return l.boundAddr()
		}
	}
	return addr
}

func deleteExtC2Sink(addr string) {
	gExtC2Mu.Lock()
	defer gExtC2Mu.Unlock()
	for i, l := range gExtC2Listeners {
		if l.Addr == addr {
			l.Stop()
			gExtC2Listeners = append(gExtC2Listeners[:i], gExtC2Listeners[i+1:]...)
			return
		}
	}
}

var (
	gSMBMu   sync.Mutex
	gDNSMu   sync.Mutex
	gExtC2Mu sync.Mutex
)

func smbConnCount(pipe string) func() int {
	return func() int {
		gSMBMu.Lock()
		defer gSMBMu.Unlock()
		for _, l := range gSMBListeners {
			if l.Pipe == pipe {
				l.mu.Lock()
				n := l.conns
				l.mu.Unlock()
				return n
			}
		}
		return 0
	}
}

func extC2ConnCount(addr string) func() int {
	return func() int {
		gExtC2Mu.Lock()
		defer gExtC2Mu.Unlock()
		for _, l := range gExtC2Listeners {
			if l.Addr == addr {
				l.mu.Lock()
				n := len(l.conns)
				l.mu.Unlock()
				return n
			}
		}
		return 0
	}
}

// ---------------------------------------------------------------- 事件日志

// listenerEvent 统一事件格式。postAdd/postDel 钩子在注册表状态改完之后调用,
// 不持注册表锁 —— storeAdd 内部有自己的锁, 避免嵌套。
func listenerEvent(action string, e *listenerEntry, extra string) {
	if e == nil {
		return
	}
	detail := fmt.Sprintf("id=%s kind=%s addr=%s", e.ID, e.Kind, e.Addr)
	if extra != "" {
		detail += " " + extra
	}
	eventLog("listener", "", action, detail)
}

func init() {
	// 只挂删除钩子: 新建事件由调用方记 (REST 记 "add"、启动参数记 "add-param"),
	// 这样同一次新建只落一条事件, 且能区分来源。
	listenerReg.postDel = func(e *listenerEntry) {
		listenerEvent("remove", e, "")
	}
}

// ---------------------------------------------------------------- REST

// decodeListenReq 宽容解析: JSON 为主, 也接受表单/查询串。
// id 同时接受 "id" 与 "name" 两个键名。
func decodeListenReq(r *http.Request) (kind, addr, id string, err error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if perr := r.ParseForm(); perr == nil {
			id = strings.TrimSpace(r.FormValue("id"))
			if id == "" {
				id = strings.TrimSpace(r.FormValue("name"))
			}
			return strings.TrimSpace(r.FormValue("kind")), strings.TrimSpace(r.FormValue("addr")), id, nil
		}
	}
	var req struct {
		Kind string `json:"kind"`
		Addr string `json:"addr"`
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		return "", "", "", fmt.Errorf("请求体不是合法 JSON: %w", derr)
	}
	id = strings.TrimSpace(req.ID)
	if id == "" {
		id = strings.TrimSpace(req.Name)
	}
	return strings.TrimSpace(req.Kind), strings.TrimSpace(req.Addr), id, nil
}

// handleListenerAdd POST /api/listener/add  {"kind":"tcp","addr":"0.0.0.0:8651"}
func handleListenerAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "请用 POST"})
		return
	}
	kind, addr, _, err := decodeListenReq(r)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	if kind == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "缺少 kind (支持 " + kindInList() + ")"})
		return
	}
	if addr == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "缺少 addr"})
		return
	}

	id, aerr := listenerAdd(kind, addr, listenerPriv)
	if aerr != nil {
		// 失败路径也进事件日志 —— 端口冲突这种事运维要能事后查到
		eventLog("listener", "", "add-failed", fmt.Sprintf("kind=%s addr=%s err=%v", kind, addr, aerr))
		writeJSON(w, map[string]interface{}{"ok": false, "kind": kind, "addr": addr, "error": aerr.Error()})
		return
	}
	e := listenerGet(id)
	resp := map[string]interface{}{"ok": true, "id": id, "kind": kind, "addr": addr, "status": "up"}
	if e != nil {
		resp["kind"] = e.Kind
		resp["addr"] = e.Addr
		resp["name"] = e.Name
		resp["created"] = e.Cre
		resp["sessions"] = 0
		resp["protected"] = false
		resp["manageable"] = true
	}
	logf("[api] listener add: id=%s kind=%s addr=%s", id, kind, addr)
	writeJSON(w, resp)
}

// handleListenerRemove POST /api/listener/remove  {"id":"L001"}
func handleListenerRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "请用 POST"})
		return
	}
	_, _, id, err := decodeListenReq(r)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	if id == "" {
		id = strings.TrimSpace(r.URL.Query().Get("id"))
	}
	if id == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "缺少 id"})
		return
	}

	e := listenerGet(id)
	if e == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "id": id, "error": "listener 不存在: " + id})
		return
	}
	if e.mainEntr {
		msg := fmt.Sprintf("拒绝删除: %s 是主 %s listener (控制台入口 %s), 删掉它等于切断 /api 控制面",
			e.ID, strings.ToUpper(e.Kind), e.Addr)
		eventLog("listener", "", "remove-denied",
			fmt.Sprintf("id=%s kind=%s addr=%s", e.ID, e.Kind, e.Addr))
		writeJSON(w, map[string]interface{}{"ok": false, "id": id, "protected": true, "error": msg})
		return
	}

	kind, addr := e.Kind, e.Addr
	if rerr := listenerRemove(id); rerr != nil {
		eventLog("listener", "", "remove-failed", fmt.Sprintf("id=%s err=%v", id, rerr))
		writeJSON(w, map[string]interface{}{"ok": false, "id": id, "error": rerr.Error()})
		return
	}
	logf("[api] listener remove: id=%s kind=%s addr=%s (端口已释放)", id, kind, addr)
	writeJSON(w, map[string]interface{}{
		"ok": true, "id": id, "kind": kind, "addr": addr,
		"removed": true, "port_released": kind != "smb",
	})
}

// listenerSelfCheck 注册表可读快照 (排错用, 与 /api/listeners 同源不同形)。
func listenerSelfCheck() map[string]interface{} {
	rows := []map[string]interface{}{}
	for _, e := range listenerEntries() {
		conns := 0
		if e.stats != nil {
			conns = e.stats()
		}
		rows = append(rows, map[string]interface{}{
			"id": e.ID, "kind": e.Kind, "addr": e.Addr, "created": e.Cre,
			"status": "up", "conns": conns, "protected": e.mainEntr,
		})
	}
	return map[string]interface{}{"ok": true, "count": len(rows), "listeners": rows}
}
