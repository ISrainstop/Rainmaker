# csdev :: e2e_test.ps1  --  端到端回归测试
# ==========================================================================
# 全链路验证: 启动服务端 -> 投放植入体 -> 上线 -> 下发命令 -> 校验回传
#
# 用法:
#   .\tools\e2e_test.ps1                          # 用默认基线植入体跑 whoami
#   .\tools\e2e_test.ps1 -Cmd "sysinfo"           # 指定命令
#   .\tools\e2e_test.ps1 -Implant <path> -Port 9000
#   .\tools\e2e_test.ps1 -KeepServer              # 保留服务端进程便于手工排障
#
# 退出码: 0 全部通过 / 1 服务端未起 / 2 会话未上线 / 3 命令无回传
# ==========================================================================
[CmdletBinding()]
param(
    [string] $Host_    = '127.0.0.1',
    [int]    $Port     = 8443,
    [string] $Implant  = '',
    [string] $Cmd      = 'whoami',
    [int]    $WaitSec  = 30,
    [switch] $NoStartServer,
    [switch] $KeepServer,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
$DevDir  = Split-Path -Parent $PSScriptRoot
$Server  = Join-Path $DevDir 'go\csdev-server.exe'
$LogDir  = Join-Path $DevDir 'build\e2e'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

if (-not $Implant) { $Implant = Join-Path $DevDir 'build\payload\baseline.exe' }

function Say($m, $c = 'Gray') { if (-not $Quiet) { Write-Host $m -ForegroundColor $c } }

# 双编码解码: 服务端文本 UTF-8, 植入体 (cmd.exe) 输出 GBK
function Decode-B64([string]$b64) {
    try {
        $b = [Convert]::FromBase64String($b64)
        try { return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($b) }
        catch { return [System.Text.Encoding]::GetEncoding(936).GetString($b) }
    } catch { return $b64 }
}

$baseUrl = "http://${Host_}:${Port}"
$serverProc = $null
$implantProc = $null
$result = $null

try {
    # ---------------------------------------------------------------- 1. 服务端
    if (-not $NoStartServer) {
        if (-not (Test-Path $Server)) { throw "服务端未编译: $Server" }
        $srvOut = Join-Path $LogDir 'server.out.log'
        $srvErr = Join-Path $LogDir 'server.err.log'
        Say "[1/5] 启动服务端 $Host_`:$Port" 'White'
        $serverProc = Start-Process -FilePath $Server `
            -ArgumentList @('--host', $Host_, '--port', $Port) `
            -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $srvOut -RedirectStandardError $srvErr
        Start-Sleep -Seconds 2
        if ($serverProc.HasExited) {
            Say "  [x] 服务端启动失败" 'Red'
            if (Test-Path $srvErr) { Get-Content $srvErr | Select-Object -Last 10 | ForEach-Object { Say "      $_" 'DarkGray' } }
            exit 1
        }
        Say "  [v] PID $($serverProc.Id)" 'Green'
    } else {
        Say "[1/5] 跳过服务端启动" 'DarkGray'
    }

    # ---------------------------------------------------------------- 2. 探活
    Say "[2/5] 探活 $baseUrl/api/sessions" 'White'
    $alive = $false
    for ($i = 0; $i -lt 10; $i++) {
        try { $null = Invoke-RestMethod -Uri "$baseUrl/api/sessions" -TimeoutSec 3; $alive = $true; break }
        catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $alive) { Say "  [x] 服务端无响应" 'Red'; exit 1 }
    Say "  [v] 服务端在线" 'Green'

    # ---------------------------------------------------------------- 3. 投放
    if (-not (Test-Path $Implant)) { throw "植入体不存在: $Implant" }
    Say "[3/5] 投放植入体 $(Split-Path -Leaf $Implant)  ($([math]::Round((Get-Item $Implant).Length/1KB,1)) KB)" 'White'
    # 清理残留植入体, 避免多实例争抢同一会话
    Get-Process -Name 'payload2', 'payload', 'baseline' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
    $implantProc = Start-Process -FilePath $Implant -PassThru -WindowStyle Hidden
    Say "  [v] PID $($implantProc.Id)" 'Green'

    # ---------------------------------------------------------------- 4. 上线
    Say "[4/5] 等待上线 (最多 $WaitSec 秒)" 'White'
    $sid = $null
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 800
        if ($implantProc.HasExited) { Say "  [x] 植入体提前退出 (code $($implantProc.ExitCode))" 'Red'; exit 2 }
        try {
            $r = Invoke-RestMethod -Uri "$baseUrl/api/sessions" -TimeoutSec 3
            if ($r.sessions.Count -gt 0) { $sid = $r.sessions[0].sid; break }
        } catch { }
    }
    if (-not $sid) { Say "  [x] 会话未上线" 'Red'; exit 2 }
    $s = $r.sessions | Where-Object { $_.sid -eq $sid }
    Say "  [v] 会话 $sid  $($s.user)@$($s.host)  arch=$($s.arch)" 'Green'

    # ---------------------------------------------------------------- 5. 命令
    Say "[5/5] 下发命令: $Cmd" 'White'
    $body = @{ sid = $sid; cmd = $Cmd } | ConvertTo-Json -Compress
    $null = Invoke-RestMethod -Uri "$baseUrl/api/command" -Method Post -Body $body `
            -ContentType 'application/json' -TimeoutSec 5

    $outputs = @()
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 900
        try {
            $o = Invoke-RestMethod -Uri "$baseUrl/api/output?sid=$sid&since=0" -TimeoutSec 3
            $txt = @($o.items | ForEach-Object { Decode-B64 $_.text })
            $real = $txt | Where-Object { -not $_.StartsWith('> ') -and -not $_.StartsWith('[*]') }
            if ($real.Count -gt 0) { $outputs = $real; break }
        } catch { }
    }

    if ($outputs.Count -eq 0) { Say "  [x] 无回传" 'Red'; exit 3 }

    Say "  [v] 回传 $($outputs.Count) 段:" 'Green'
    ($outputs -join "`n").Trim() -split "`r?`n" | Select-Object -First 25 | ForEach-Object { Say "      $_" 'DarkGray' }

    $result = 'PASS'
    Say ""
    Say "E2E PASS  会话=$sid  命令=$Cmd" 'Green'

} finally {
    if ($implantProc -and -not $implantProc.HasExited) { Stop-Process -Id $implantProc.Id -Force -ErrorAction SilentlyContinue }
    if ($serverProc -and -not $KeepServer -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue }
    if (-not $KeepServer -and -not $NoStartServer) { Say "已清理进程" 'DarkGray' }
}

if ($result -ne 'PASS') { exit 3 }
exit 0
