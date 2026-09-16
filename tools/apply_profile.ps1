<#
  cs_dev :: apply_profile.ps1  --  从变体库快速切换免杀档案
  ==========================================================================
  与 deploy.ps1 的区别: 本脚本【不编译】, 直接从 library/ 取预编译好的
  加密变体注入 jar, 秒级完成。适合在 CS 客户端菜单里被反复调用。

  用法:
    .\apply_profile.ps1 -Profile stealth
    .\apply_profile.ps1 -Profile basic -CsRoot "D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7"
    .\apply_profile.ps1 -Restore -CsRoot "..."
    .\apply_profile.ps1 -List                    列出库内可用变体
#>
[CmdletBinding()]
param(
    [string] $Profile = '',
    [string] $CsRoot  = '',
    [switch] $Restore,
    [switch] $List
)

$ErrorActionPreference = 'Stop'
$ToolsDir = $PSScriptRoot
$DevDir   = Split-Path -Parent $ToolsDir
$LibDir   = Join-Path $DevDir 'library'
$BackupDir= Join-Path $DevDir 'backup'

# CS 根目录自动推导: 向上查找含 cobaltstrike-client.jar 的目录
# 兼容两种布局: 开发布局 <root>/cs_dev/tools  与 插件布局 <root>/plugin/cs_dev/tools
if (-not $CsRoot) {
    $probe = $DevDir
    for ($i = 0; $i -lt 6 -and $probe; $i++) {
        if (Test-Path (Join-Path $probe 'cobaltstrike-client.jar')) { $CsRoot = $probe; break }
        $parent = Split-Path -Parent $probe
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
    if (-not $CsRoot) { $CsRoot = Split-Path -Parent $DevDir }
}
$Jar = Join-Path $CsRoot 'cobaltstrike-client.jar'

# 库文件名前缀 -> jar 内条目 (显式映射表, 避免正则歧义)
#   sleepmask / injector / udrl : CS 以 sleeve 加密资源读取 (sleeve/<name>.x64.o)
#   artifact*                   : CS 以明文模板读取      (resources/<name>)
#   small 系列供 stager 使用, big 系列供 stageless 使用; 两者都覆盖才能全格式生效
$JAR_MAP = @{
    'sleepmask'        = 'sleeve/sleepmask.x64.o'
    'injector'         = 'sleeve/injector.x64.o'
    'udrl'             = 'sleeve/udrl.x64.o'
    'artifact64'       = 'resources/artifact64.exe'
    'artifact64svc'    = 'resources/artifact64svc.exe'
    'artifact64dll'    = 'resources/artifact64.x64.dll'
    'artifact64big'    = 'resources/artifact64big.exe'
    'artifact64svcbig' = 'resources/artifact64svcbig.exe'
    'artifact64bigdll' = 'resources/artifact64big.x64.dll'
}

function Say($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }

# ---- 列出库内容 ---------------------------------------------------------
if ($List -or (-not $Profile -and -not $Restore)) {
    if (-not (Test-Path $LibDir)) {
        Say "[-] variant librarynot found, run first: build_library.ps1" 'Red'; return
    }
    $profiles = @{}
    Get-ChildItem $LibDir | ForEach-Object {
        if ($_.Name -match '^([a-z0-9]+)\.([a-z]+)\.(.+)$') {
            $profiles[$Matches[2]] = $true
        }
    }
    Say ""
    Say "  cs_dev variant library  ($LibDir)" 'Cyan'
    Say "  ================================================"
    foreach ($p in $profiles.Keys | Sort-Object) {
        $items = Get-ChildItem $LibDir -Filter "*.$p.*"
        Say ""
        Say "  [$p]" 'White'
        foreach ($i in $items) {
            Say ("    {0,-42} {1,7} bytes" -f $i.Name, $i.Length) 'DarkGray'
        }
    }
    Say ""
    $cur = Join-Path $DevDir 'profile.current'
    if (Test-Path $cur) { Say "  current profile: $((Get-Content $cur -First 1).Trim())" 'Green' }
    return
}

# ---- 回滚 ---------------------------------------------------------------
if ($Restore) {
    $bk = Join-Path $BackupDir "$(Split-Path $CsRoot -Leaf).client.jar.orig"
    if (-not (Test-Path $bk)) { $bk = Join-Path $BackupDir 'cobaltstrike-client.jar.orig' }
    if (-not (Test-Path $bk)) { throw "backup not found (expected: $bk)" }
    Copy-Item $bk $Jar -Force
    Say "[+] rolled back: $Jar" 'Green'
    return
}

# ---- 应用档案 -----------------------------------------------------------
if (-not (Test-Path $Jar))  { throw "client jar not found: $Jar" }
if (-not (Test-Path $LibDir)) { throw "variant library not found, run first:  build_library.ps1" }

$variants = Get-ChildItem $LibDir -Filter "*.$Profile.*"
if ($variants.Count -eq 0) { throw "no variants for profile [$Profile]" }

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$bakName = 'cobaltstrike-client.jar.orig'
$bak = Join-Path $BackupDir $bakName
if (-not (Test-Path $bak)) {
    Copy-Item $Jar $bak -Force
    Say "[+] first backup -> $bak" 'Green'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($Jar, 'Update')
$n = 0
try {
    foreach ($v in $variants) {
        # sleepmask.stealth.x64.o.enc  ->  sleeve/sleepmask.x64.o
        # artifact64svc.stealth.exe    ->  resources/artifact64svc.exe
        # artifact64dll.stealth.dll    ->  resources/artifact64.x64.dll
        $base  = ($v.Name -split '\.')[0]
        $entry = $JAR_MAP[$base]
        if (-not $entry) {
            Say ("  [!] unknown variant, skipped: {0}" -f $v.Name) 'Yellow'
            continue
        }
        $old = $zip.GetEntry($entry)
        if ($old) { $old.Delete() }
        $ne = $zip.CreateEntry($entry, [System.IO.Compression.CompressionLevel]::Optimal)
        $os = $ne.Open(); $is = [System.IO.File]::OpenRead($v.FullName)
        $is.CopyTo($os); $is.Close(); $os.Close()
        Say ("  [+] {0,-32} <- {1}" -f $entry, $v.Name) 'Green'
        $n++
    }
} finally { $zip.Dispose() }

# 记录档案
@($Profile, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $CsRoot) |
    Out-File -FilePath (Join-Path $DevDir 'profile.current') -Encoding UTF8

Say ""
Say "[+] profile [$Profile] applied ($n entries) -> $Jar" 'Cyan'
Say "    restart client to take effect" 'Yellow'
