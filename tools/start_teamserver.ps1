<#
  cs_dev :: start_teamserver.ps1  --  启动 Cobalt Strike Team Server
  ==========================================================================
  TeamServerImage 是自解压的 Linux ELF (自带 JRE), 只能在 Linux 上运行。
  本机通过 WSL 运行, 已实测通过:
      [*] Team Server Version: 4.7 (20220817) Licensed

  要点:
    1. <host> 必须是 beacon 能回连的地址。CS 明确拒绝 127.0.0.1,
       因为它会把这个 IP 用作 DNS Beacon / Covert VPN 的默认值。
    2. WSL2 默认是 NAT 网络, Windows 与外部无法直连 WSL 内的端口。
       需要端口转发 (本脚本 -SetupPortProxy) 或切到镜像网络模式。
    3. 服务端不需要任何 cs_dev 改造 —— payload 生成在客户端完成
       (BaseArtifactUtils._patchArtifact 读的是客户端 jar 里的
       resources/artifact64.exe), teamserver 只负责 listener 与会话。

  用法:
    .\start_teamserver.ps1 -Check                          仅检查环境与 IP
    .\start_teamserver.ps1 -Password "MyPass123"           自动选 IP 并启动
    .\start_teamserver.ps1 -PublicIP 192.168.1.50 -Password "MyPass123"
    .\start_teamserver.ps1 -Password "MyPass123" -SetupPortProxy
#>
[CmdletBinding()]
param(
    [string] $PublicIP = '',
    [string] $Password = '',
    [int]    $Port     = 50050,
    [string] $CsRoot   = '',
    [switch] $SetupPortProxy,
    [switch] $Check
)

$ErrorActionPreference = 'Stop'

if (-not $CsRoot) {
    $probe = $PSScriptRoot
    for ($i = 0; $i -lt 6 -and $probe; $i++) {
        if (Test-Path (Join-Path $probe 'TeamServerImage')) { $CsRoot = $probe; break }
        $parent = Split-Path -Parent $probe
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
}
if (-not $CsRoot -or -not (Test-Path (Join-Path $CsRoot 'TeamServerImage'))) {
    throw "TeamServerImage not found, use -CsRoot"
}

function Say($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }

# WSL 路径转换
function To-WslPath($p) {
    $d = $p.Substring(0,1).ToLower()
    $rest = $p.Substring(2).Replace('\','/')
    return "/mnt/$d$rest"
}
$wslRoot = To-WslPath $CsRoot

Say ""
Say "  cs_dev :: Team Server" 'Cyan'
Say "  ============================================================"
Say "  dir : $CsRoot"
Say "  port : $Port"
Say ""

# ---- 环境检查 -----------------------------------------------------------
Say "[1] check WSL" 'White'
$wslOk = $true
try { $null = & wsl.exe -e bash -c "echo ok" 2>$null } catch { $wslOk = $false }
if (-not $wslOk) { throw "WSL unavailable" }
Say "    ✓ WSL ok" 'Green'

Say "[2] check TeamServerImage" 'White'
$tsi = Join-Path $CsRoot 'TeamServerImage'
Say "    ✓ $([math]::Round((Get-Item $tsi).Length/1MB,1)) MB" 'Green'

Say "[3] detectok IP" 'White'
$winIPs = @()
try {
    $winIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
              Select-Object -ExpandProperty IPAddress
} catch { }
$wslIP = ''
try { $wslIP = (& wsl.exe -e bash -c "hostname -I 2>/dev/null | awk '{print `$1}'" 2>$null | Out-String).Trim() } catch { }

Say "    Windows : $($winIPs -join ', ')"
Say "    WSL     : $wslIP"
Say ""

if ($Check) {
    Say "  [-Check] check only, not started." 'Yellow'
    Say ""
    Say "  usage example:" 'White'
    Say "    .\start_teamserver.ps1 -PublicIP <beacon-reachable-ip> -Password <password>"
    Say ""
    return
}

# ---- 选择 IP ------------------------------------------------------------
if (-not $PublicIP) {
    # 优先用局域网 IP (同网段测试), 否则回退 WSL IP
    $lanIP = $winIPs | Where-Object { $_ -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' } | Select-Object -First 1
    if ($lanIP) { $PublicIP = $lanIP }
    elseif ($winIPs.Count -gt 0) { $PublicIP = $winIPs[0] }
    elseif ($wslIP) { $PublicIP = $wslIP }
    else { throw "cannot auto-detect IP, use -PublicIP" }
    Say "[i] autoselect IP: $PublicIP" 'Yellow'
}
if ($PublicIP -match '^127\.') {
    throw "cannot use 127.0.0.1 -- CS needs a beacon-reachable address"
}

if (-not $Password) {
    $Password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ })
    Say "[i] auto-generated password: $Password" 'Yellow'
}

# ---- 可选: 配置端口转发 ------------------------------------------------
if ($SetupPortProxy) {
    Say "[4] setup Windows -> WSL port proxy (needs admin)" 'White'
    try {
        $listen = "0.0.0.0:$Port"
        $connect = "${wslIP}:$Port"
        & netsh.exe interface portproxy delete v4tov4 listenport=$Port listenaddress=0.0.0.0 2>$null | Out-Null
        & netsh.exe interface portproxy add v4tov4 listenport=$Port listenaddress=0.0.0.0 connectport=$Port connectaddress=$wslIP | Out-Null
        & netsh.exe advfirewall firewall add rule name="cs_dev teamserver $Port" dir=in action=allow protocol=TCP localport=$Port 2>$null | Out-Null
        Say "    ✓ $listen -> $connect" 'Green'
    } catch {
        Say "    [!] port proxy FAILED (need admin): $($_.Exception.Message)" 'Yellow'
        Say "        or switch to mirrored networking: %UserProfile%\.wslconfig add networkingMode=mirrored" 'DarkGray'
    }
}

# ---- 启动 ---------------------------------------------------------------
Say "[5] start Team Server" 'White'
Say "    ./teamserver $PublicIP <password>" 'DarkGray'
Say ""
Say "  ============================================================"
Say "  connection" 'White'
Say "    Host     : $PublicIP"
Say "    Port     : $Port"
Say "    Password : $Password"
Say ""
Say "  client    : start client -> enter above" 'White'
Say "  stop      : Ctrl+C in terminal" 'White'
Say "  ============================================================"
Say ""

$cmd = "cd '$wslRoot' && chmod +x teamserver TeamServerImage 2>/dev/null; ./teamserver $PublicIP '$Password'"
& wsl.exe -e bash -c $cmd
