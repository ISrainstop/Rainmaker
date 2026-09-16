# csdev :: build_clr_stub.ps1  --  编译 execute-assembly 的 CLR 引导程序集
# ==========================================================================
# 产物: build\clr\csdev_clr_stub.dll
#   - 由服务端在 execute-assembly 时附带下发给植入体 (植入体自身不含它)
#   - 必须用 .NET Framework 的 csc 编译, 保证目标机自带的 CLR 4.x 能加载
#
# 用法: .\tools\build_clr_stub.ps1
# ==========================================================================
[CmdletBinding()]
param(
    [string] $OutDir = ''
)

$ErrorActionPreference = 'Stop'
$DevDir = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $DevDir 'build\clr' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$src = Join-Path $DevDir 'kits\packer\csdev_clr_stub.cs'
if (-not (Test-Path $src)) { throw "缺少 stub 源码: $src" }

# 优先 Framework64 (目标进程多为 64 位), 回退 32 位
$cands = @(
    'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe',
    'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe'
)
$csc = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) { throw "找不到 .NET Framework 的 csc.exe" }

$out = Join-Path $OutDir 'csdev_clr_stub.dll'
& $csc /nologo /target:library /optimize+ /out:$out $src 2>&1 | ForEach-Object { Write-Host "    $_" }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { throw "编译失败" }

$fi = Get-Item $out
Write-Host ""
Write-Host "[+] CLR 引导 stub 就绪" -ForegroundColor Green
Write-Host ("    path : {0}" -f $fi.FullName)
Write-Host ("    size : {0} 字节" -f $fi.Length)
Write-Host ("    编译器: {0}" -f $csc)
