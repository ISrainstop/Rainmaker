#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Rainmaker C2 :: SOCKS5 代理 + 反向端口转发 端到端验证

.DESCRIPTION
  链路: PowerShell 手工 SOCKS5 客户端 -> 服务端 127.0.0.1:<socksPort>
        -> CMD_PROXY open 任务 -> 植入体 (payload2.exe) -> 127.0.0.1:8443 服务端 HTTP

  本脚本验证的是"整套接线完成后"的行为。若 beacon2.c / v2_core.go 尚未接线,
  植入体不会响应 CMD_PROXY open, 脚本会在超时后明确报告 "端到端待接线" 并以退出码 2 结束。

  用法:
    pwsh -File tools/proxy_e2e.ps1
    pwsh -File tools/proxy_e2e.ps1 -Token <bearer>     # 服务端开启鉴权时
#>
[CmdletBinding()]
param(
    [string]$ServerExe = 'go\csdev-server.exe',
    [string]$PayloadExe = 'build\payload2.exe',
    [int]$ServerPort = 18443,
    [int]$SocksPort = 1080,
    [int]$PayloadWaitSec = 45,
    [int]$OpenWaitSec = 30,
    [string]$Token = $env:CSDEV_TOKEN,
    [string]$MinGw = 'D:\mingw64\bin',
    [switch]$AutoBuildPayload = $true,
    [switch]$KeepAlive
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$serverProc = $null
$payloadProc = $null
$exitCode = 0

function Say([string]$m, [string]$c = 'Gray') { Write-Host $m -ForegroundColor $c }
function Step([string]$m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }

function Get-Headers {
    $h = @{}
    if ($Token) { $h['Authorization'] = "Bearer $Token" }
    return $h
}

function Invoke-Api {
    param([string]$Method, [string]$Path, $Body)
    $uri = "http://127.0.0.1:$ServerPort$Path"
    $args = @{ Method = $Method; Uri = $uri; TimeoutSec = 10; Headers = (Get-Headers) }
    if ($Body) {
        $args['Body'] = ($Body | ConvertTo-Json -Compress)
        $args['ContentType'] = 'application/json'
    }
    try {
        return Invoke-RestMethod @args
    } catch {
        return $null
    }
}

function Cleanup {
    foreach ($p in @($payloadProc, $serverProc)) {
        if ($p -and -not $p.HasExited) {
            try { $p.Kill() } catch { }
            try { $p.WaitForExit(3000) | Out-Null } catch { }
        }
    }
}

trap {
    Say ("[!] 脚本异常: " + $_.Exception.Message) 'Red'
    Cleanup
    exit 3
}

try {
    # ---------------------------------------------------------------- 前置检查
    Step '1/7 前置检查'
    if (-not (Test-Path $ServerExe)) {
        Say "[!] 找不到服务端 $ServerExe, 请先运行: cd go; go build -o csdev-server.exe ." 'Red'
        exit 3
    }
    Say "[+] 服务端: $ServerExe" 'Green'

    # 选一个空闲端口: 项目里常有别的实例占着默认端口
    function Get-FreePort([int]$start) {
        for ($p = $start; $p -lt ($start + 200); $p++) {
            $used = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
            if (-not $used) { return $p }
        }
        throw '找不到空闲端口'
    }
    $ServerPort = Get-FreePort $ServerPort
    Say "[+] 选用空闲端口: $ServerPort" 'Green'

    # 植入体必须把 C2_HOST/C2_PORT 编进二进制, 所以按选中端口重新生成
    if ($AutoBuildPayload) {
        Step '   重新生成植入体 (匹配所选端口)'
        $gen = Join-Path $root 'tools\gen_payload2.ps1'
        $genArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gen,
            '-Format', 'win2-exe', '-Host_', '127.0.0.1', '-Port', "$ServerPort",
            '-Sleep', '2000', '-Jitter', '20',
            '-OutFile', $PayloadExe, '-Quiet')
        $g = Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList $genArgs `
            -WorkingDirectory $root -PassThru -Wait -WindowStyle Hidden
        if ($g.ExitCode -ne 0 -or -not (Test-Path $PayloadExe)) {
            Say "[!] 植入体重新生成失败 (exit=$($g.ExitCode)), 请检查 gcc $MinGw" 'Red'
            exit 3
        }
        Say "[+] 植入体已按 :$ServerPort 重新生成" 'Green'
    } elseif (-not (Test-Path $PayloadExe)) {
        Say "[!] 找不到植入体 $PayloadExe, 请加 -AutoBuildPayload 或手工用 gen_payload2.ps1 生成" 'Red'
        exit 3
    }
    Say "[+] 植入体: $PayloadExe" 'Green'

    # ---------------------------------------------------------------- 启动服务端
    Step '2/7 启动服务端'
    $serverProc = Start-Process -FilePath (Resolve-Path $ServerExe) `
        -ArgumentList @('-host', '127.0.0.1', '-port', "$ServerPort") `
        -WorkingDirectory $root -PassThru -WindowStyle Hidden

    $up = $false
    foreach ($i in 1..40) {
        Start-Sleep -Milliseconds 500
        if ($serverProc.HasExited) { break }
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$ServerPort/api/state" -TimeoutSec 3 -UseBasicParsing
            if ($r.StatusCode -eq 200) { $up = $true; break }
        } catch { }
    }
    if (-not $up) {
        Say "[!] 服务端未在 20 秒内就绪 (可能端口被占用或鉴权阻断)" 'Red'
        exit 3
    }
    Say "[+] 服务端已就绪 http://127.0.0.1:$ServerPort" 'Green'

    # ---------------------------------------------------------------- 启动植入体
    Step '3/7 启动植入体'
    $payloadProc = Start-Process -FilePath (Resolve-Path $PayloadExe) `
        -WorkingDirectory $root -PassThru -WindowStyle Hidden

    $sid = $null
    $deadline = (Get-Date).AddSeconds($PayloadWaitSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
        if ($payloadProc.HasExited) {
            Say ("[!] 植入体提前退出, exit=" + $payloadProc.ExitCode) 'Red'
            exit 3
        }
        $st = Invoke-Api -Method GET -Path '/api/sessions'
        if ($st -and $st.sessions) {
            $v2 = @($st.sessions | Where-Object { $_.proto -eq 'v2' })
            if ($v2.Count -gt 0) { $sid = $v2[0].sid; break }
        }
    }
    if (-not $sid) {
        Say "[!] 植入体 $PayloadWaitSec 秒内未上线 (检查 payload2.exe 的 C2_HOST/C2_PORT 是否指向本服务端)" 'Red'
        exit 3
    }
    Say "[+] v2 会话上线: $sid" 'Green'

    # ---------------------------------------------------------------- 路由探测
    Step '4/7 探测 /api/proxy/* 路由是否已注册'
    $routeOk = $false
    try {
        $probe = Invoke-WebRequest -Uri "http://127.0.0.1:$ServerPort/api/proxy/list" `
            -TimeoutSec 5 -UseBasicParsing -Headers (Get-Headers)
        $routeOk = ($probe.StatusCode -eq 200)
    } catch {
        $code = $null
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        Say ("[!] /api/proxy/list 返回 $code (404 = 路由未注册)") 'Yellow'
    }
    if (-not $routeOk) {
        Say '[BLOCKED] 服务端未注册代理路由' 'Red'
        Say '  需要在 go/server.go 的 main() 里加上:' 'Yellow'
        Say '      RegisterProxyRoutes(mux)' 'Yellow'
        Step '结论'
        Say '[PENDING] 端到端待接线 (第 1 步: server.go 路由)' 'Yellow'
        exit 2
    }
    Say '[+] 路由已注册' 'Green'

    # ---------------------------------------------------------------- 启动 SOCKS 入口
    Step '4b/7 启动 SOCKS5 入口'
    $startResp = Invoke-Api -Method POST -Path '/api/proxy/start' -Body @{ sid = $sid; port = $SocksPort }
    if (-not $startResp -or -not $startResp.ok) {
        Say ("[!] /api/proxy/start 失败: " + ($startResp | ConvertTo-Json -Compress)) 'Red'
        exit 3
    }
    Say "[+] $($startResp.message)" 'Green'

    $lst = Invoke-Api -Method GET -Path '/api/proxy/list'
    if (-not $lst -or -not $lst.socks -or @($lst.socks).Count -eq 0) {
        Say '[!] /api/proxy/list 未报告已启动的入口' 'Red'
        exit 3
    }

    # ---------------------------------------------------------------- SOCKS5 客户端
    Step '5/7 手工 SOCKS5 客户端 CONNECT -> 127.0.0.1:' -NoNewline
    Write-Host "$ServerPort" -ForegroundColor Cyan

    $sockResult = 'FAIL'
    $sockDetail = ''
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        # 30s: 一次 CONNECT 要走"下发 open → 植入体建连 → 回执"两轮 beacon,
        # 叠加 sleep/jitter 后最坏可达 ~2 个周期以上, 8s 会稳定误判为失败。
        $client.ReceiveTimeout = 30000
        $client.SendTimeout = 30000
        $client.Connect('127.0.0.1', $SocksPort)
        $stream = $client.GetStream()

        function Send-Raw([byte[]]$bytes) {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        }
        function Read-Exact([int]$n) {
            $buf = New-Object byte[] $n
            $got = 0
            while ($got -lt $n) {
                $r = $stream.Read($buf, $got, $n - $got)
                if ($r -le 0) { throw "连接被对端关闭 (已读 $got/$n 字节)" }
                $got += $r
            }
            return $buf
        }

        # --- 方法协商: VER=5 NMETHODS=1 METHOD=0 (无认证) ---
        Send-Raw ([byte[]]@(0x05, 0x01, 0x00))
        $sel = Read-Exact 2
        if ($sel[0] -ne 0x05) { throw "握手版本错误: 0x{0:X2}" -f $sel[0] }
        if ($sel[1] -ne 0x00) { throw "服务端要求认证或拒绝: method=0x{0:X2}" -f $sel[1] }
        Say '      [+] 方法协商通过 (无认证)' 'Green'

        # --- CONNECT 127.0.0.1:ServerPort (ATYP=IPv4) ---
        $portHi = [byte](($ServerPort -shr 8) -band 0xFF)
        $portLo = [byte]($ServerPort -band 0xFF)
        Send-Raw ([byte[]]@(0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, $portHi, $portLo))

        $reply = Read-Exact 4
        if ($reply[1] -ne 0x00) {
            $sockDetail = "REP=0x{0:X2}" -f $reply[1]
            throw "CONNECT 被拒 $sockDetail"
        }
        switch ($reply[3]) {
            0x01 { $null = Read-Exact 4 }
            0x04 { $null = Read-Exact 16 }
            0x03 { $l = (Read-Exact 1)[0]; $null = Read-Exact ([int]$l) }
        }
        $null = Read-Exact 2
        Say '      [+] CONNECT 成功' 'Green'

        # --- 发 HTTP 请求, 读响应 ---
        $req = "GET /api/state HTTP/1.0`r`nHost: 127.0.0.1:$ServerPort`r`nConnection: close`r`n`r`n"
        Send-Raw ([System.Text.Encoding]::ASCII.GetBytes($req))

        $sb = New-Object System.Text.StringBuilder
        $buf = New-Object byte[] 4096
        $total = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt 20) {
            $r = $stream.Read($buf, 0, $buf.Length)
            if ($r -le 0) { break }
            $total += $r
            $null = $sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $r))
            if ($total -gt 65536) { break }
        }
        $text = $sb.ToString()
        if ($total -gt 0 -and $text -match 'HTTP/1\.[01]\s+200') {
            $sockResult = 'OK'
            Say ("      [+] 收到 HTTP 响应 $total 字节, 首行: " + ($text -split "`r`n")[0]) 'Green'
        } elseif ($total -gt 0) {
            $sockResult = 'PARTIAL'
            $sockDetail = "收到 $total 字节但非 200 响应"
            Say ("      [!] " + $sockDetail) 'Yellow'
        } else {
            $sockDetail = '未收到任何字节'
            Say '      [!] 未收到任何字节' 'Yellow'
        }
    } catch {
        $sockDetail = $_.Exception.Message
        Say ("      [!] SOCKS 链路失败: " + $sockDetail) 'Yellow'
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }

    # ---------------------------------------------------------------- 清理代理入口
    Step '6/7 停止 SOCKS 入口'
    $null = Invoke-Api -Method POST -Path '/api/proxy/stop' -Body @{ sid = $sid; port = $SocksPort }

    # ---------------------------------------------------------------- 结论
    Step '7/7 结论'
    if ($sockResult -eq 'OK') {
        Say '[OK] 端到端通过: PowerShell SOCKS5 -> 服务端 -> 植入体 -> 内网 HTTP 全链路连通' 'Green'
        $exitCode = 0
    } else {
        Say '[PENDING] 端到端待接线' 'Yellow'
        Say '  原因: 服务端已下发 CMD_PROXY(open) 任务, 但植入体侧未把 socket 接通。' 'Yellow'
        Say '  需要完成的接线 (两个文件各一处):' 'Yellow'
        Say '    kits/beacon/beacon2.c : 主循环调 proxy_pump(); run_task 加 CMD_PROXY/CMD_RPORTFWD 两个 case' 'Yellow'
        Say '    go/v2_core.go         : v2HandleUpload 的 switch 加 case tlvProxyData; takeQueue 前调 ProxyDrain' 'Yellow'
        Say ("  本次细节: " + $sockDetail) 'Yellow'

        # 给出可判定的证据: open 任务确实下发过
        $out = Invoke-Api -Method GET -Path "/api/output?sid=$sid&since=0"
        if ($out -and $out.items) {
            $txt = ($out.items | ForEach-Object {
                    try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.text)) } catch { '' }
                }) -join ''
            if ($txt -match '通道\s+\d+\s+已建立') {
                Say '  [证据] 植入体会话输出里出现了通道建立回执, 说明接线已完成, 失败原因在别处。' 'Green'
                $exitCode = 0
            } else {
                Say '  [证据] 植入体会话输出中没有通道建立回执 —— 与"未接线"的判断一致。' 'Yellow'
            }
        }
        if ($exitCode -eq 0 -and $sockResult -ne 'OK') { $exitCode = 2 }
        if ($exitCode -eq 0) { $exitCode = 2 }
    }
}
finally {
    if (-not $KeepAlive) { Cleanup }
    else { Say '[i] -KeepAlive: 服务端与植入体保持运行' 'DarkGray' }
}

exit $exitCode
