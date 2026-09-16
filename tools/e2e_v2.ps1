# csdev :: e2e_v2.ps1  --  协议 v2 多命令回归测试
# ==========================================================================
# 启动服务端 + v2 植入体 -> 上线 -> 逐条下发命令 -> 校验每条回传
#
# 用法:
#   .\tools\e2e_v2.ps1                                  # 跑默认命令集
#   .\tools\e2e_v2.ps1 -Cmds @('whoami','ps','ls C:\')
#   .\tools\e2e_v2.ps1 -Implant build\payload2.exe -KeepServer
#
# 退出码: 0 全部通过 / 2 未上线 / 3 存在失败命令
# ==========================================================================
[CmdletBinding()]
param(
    [string]   $Host_   = '127.0.0.1',
    [int]      $Port    = 8443,
    [string]   $Implant = '',
    [string[]] $Cmds    = @('whoami', 'pwd', 'ls C:\', 'ps', 'token getuid', 'portscan 127.0.0.1 8443'),
    [int]      $WaitSec = 40,
    [int]      $CmdTimeout = 30,
    [ValidateSet('http', 'tcp', 'smb', 'dns')]
    [string]   $Transport = 'http',
    [int]      $AuxPort = 8444,
    [string]   $PipeName = 'csdev_e2e_pipe',
    [int]      $DnsPort = 15353,
    [switch]   $NoStartServer,
    [switch]   $KeepServer
)

$ErrorActionPreference = 'Stop'
$DevDir = Split-Path -Parent $PSScriptRoot
$Server = Join-Path $DevDir 'go\csdev-server.exe'
$LogDir = Join-Path $DevDir 'build\e2e'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# 按承载层推导默认植入体与编译期参数 (三种承载共用同一帧协议)
if (-not $Implant) {
    switch ($Transport) {
        'http'  { $Implant = Join-Path $DevDir 'build\payload2.exe' }
        'tcp'   { $Implant = Join-Path $DevDir 'build\payload2_tcp.exe' }
        'smb'   { $Implant = Join-Path $DevDir 'build\payload2_smb.exe' }
        'dns'   { $Implant = Join-Path $DevDir 'build\payload2_dns.exe' }
    }
}
$serverExtra = @()
switch ($Transport) {
    'tcp' { $serverExtra = @('--tcp', "${Host_}:${AuxPort}") }
    'smb' { $serverExtra = @('--smb', $PipeName) }
    'dns' { $serverExtra = @('--dns', "${Host_}:${DnsPort}") }
}
# DNS 通道带宽低 (每查询约 125 字节), 默认放宽超时
if ($Transport -eq 'dns' -and $CmdTimeout -lt 60) { $CmdTimeout = 60 }

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

function Decode-B64([string]$b64) {
    try {
        $b = [Convert]::FromBase64String($b64)
        try { return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($b) }
        catch { return [System.Text.Encoding]::GetEncoding(936).GetString($b) }
    } catch { return $b64 }
}

$base = "http://${Host_}:${Port}"
$serverProc = $null; $implantProc = $null

try {
    if (-not $NoStartServer) {
        $srvArgs = @('--host', $Host_, '--port', $Port) + $serverExtra
        $serverProc = Start-Process -FilePath $Server -ArgumentList $srvArgs `
            -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $LogDir 'server2.out.log') `
            -RedirectStandardError  (Join-Path $LogDir 'server2.err.log')
        Start-Sleep -Seconds 2
        if ($serverProc.HasExited) { Say "[x] 服务端启动失败" 'Red'; exit 1 }
    }

    $alive = $false
    for ($i = 0; $i -lt 10; $i++) {
        try { $null = Invoke-RestMethod "$base/api/sessions" -TimeoutSec 3; $alive = $true; break } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $alive) { Say "[x] 服务端无响应" 'Red'; exit 1 }

    Say "[*] 投放 $(Split-Path -Leaf $Implant)   承载=$Transport" 'White'
    # 清理可能残留的植入体进程: 多实例会争抢同一会话 (服务端按 host|user 复用会话号,
    # 后上线者会换掉密钥), 表现为命令下发后无回传
    Get-Process -Name 'payload2', 'payload', 'baseline' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
    $implantProc = Start-Process -FilePath $Implant -PassThru -WindowStyle Hidden

    $sid = $null
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 800
        if ($implantProc.HasExited) { Say "[x] 植入体退出 (code $($implantProc.ExitCode))" 'Red'; exit 2 }
        try {
            $r = Invoke-RestMethod "$base/api/sessions" -TimeoutSec 3
            $v2 = @($r.sessions | Where-Object { $_.proto -eq 'v2' })
            if ($v2.Count -gt 0) { $sid = $v2[0].sid; break }
        } catch { }
    }
    if (-not $sid) { Say "[x] v2 会话未上线" 'Red'; exit 2 }

    $info = Invoke-RestMethod "$base/api/session/info?sid=$sid"
    $s = $info.session
    Say "[v] 会话 $sid  $($s.user)@$($s.host)  $($s.proc)  pid=$($s.pid)  os=$($s.os)" 'Green'
    Say ""

    $pass = 0; $fail = 0
    foreach ($cmd in $Cmds) {
        $before = @((Invoke-RestMethod "$base/api/output?sid=$sid&since=0").items)
        # 注意: 不能用 Measure-Object -Maximum, 它返回 double, 纳秒时间戳会被
        # 转成科学计数法导致服务端 ParseInt 失败 (since 退化为 0)
        $maxTs = 0L
        foreach ($it in $before) { if ([long]$it.ts -gt $maxTs) { $maxTs = [long]$it.ts } }
        $since = ($maxTs + 1).ToString()

        Say ">>> $cmd" 'Cyan'
        $null = Invoke-RestMethod -Method Post -Uri "$base/api/command" `
                -Body (@{ sid = $sid; cmd = $cmd } | ConvertTo-Json -Compress) `
                -ContentType 'application/json' -TimeoutSec 5

        $out = @()
        $deadline = (Get-Date).AddSeconds($CmdTimeout)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 900
            try {
                $items = @((Invoke-RestMethod "$base/api/output?sid=$sid&since=$since" -TimeoutSec 3).items)
                if ($items.Count -gt 0) {
                    $txt = $items | ForEach-Object { Decode-B64 $_.text }
                    $real = @($txt | Where-Object { -not $_.StartsWith('> ') })
                    if ($real.Count -gt 0) { $out = $real; break }
                }
            } catch { }
        }

        if ($out.Count -eq 0) {
            Say "    [x] 无回传 (超时 $CmdTimeout s)" 'Red'
            $fail++
        } else {
            $body = ($out -join "`n").Trim()
            $lines = $body -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
            $show = $lines | Select-Object -First 8
            foreach ($l in $show) { Say "    $l" 'DarkGray' }
            if ($lines.Count -gt 8) { Say "    ... (共 $($lines.Count) 行, $($body.Length) 字符)" 'DarkGray' }
            $pass++
        }
        Say ""
    }

    # 若本次测过 screenshot, 额外等待分块传输落盘并校验 BMP 魔数
    if ($Cmds -match '^screenshot') {
        Say "[*] 等待截屏分块传输完成 (最多 120 秒)" 'White'
        $deadline = (Get-Date).AddSeconds(120)
        $shot = $null
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            try {
                $rr = Invoke-RestMethod "$base/api/screenshots" -TimeoutSec 3
                if (@($rr.screenshots).Count -gt 0) { $shot = @($rr.screenshots)[-1]; break }
            } catch { }
        }
        if ($shot) {
            $fi = Get-Item $shot.path -ErrorAction SilentlyContinue
            if ($fi) {
                $bytes = [System.IO.File]::ReadAllBytes($fi.FullName)
                $isBmp = ($bytes[0] -eq 0x42 -and $bytes[1] -eq 0x4D)
                $isJpg = ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8)
                if (($isBmp -or $isJpg) -and $fi.Length -eq $shot.size) {
                    $kind = if ($isJpg) { 'JPEG' } else { 'BMP' }
                    Say ("    [v] 截屏完整: {0}  {1} 字节  {2}" -f $fi.Name, $fi.Length, $kind) 'Green'
                    $pass++
                } else {
                    Say ("    [x] 截屏校验失败: {0} 字节 (记录 {1}) BMP={2} JPEG={3}" -f $fi.Length, $shot.size, $isBmp, $isJpg) 'Red'
                    $fail++
                }
            } else {
                Say "    [x] 截屏记录存在但文件缺失" 'Red'; $fail++
            }
        } else {
            Say "    [x] 未收到截屏" 'Red'; $fail++
        }
        Say ""
    }

    Say ("结果: PASS {0}  FAIL {1}" -f $pass, $fail) $(if ($fail -eq 0) { 'Green' } else { 'Yellow' })
    if ($fail -gt 0) { exit 3 }
    exit 0

} finally {
    if ($implantProc -and -not $implantProc.HasExited) { Stop-Process -Id $implantProc.Id -Force -ErrorAction SilentlyContinue }
    if ($serverProc -and -not $KeepServer -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue }
}
