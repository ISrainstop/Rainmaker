# ===========================================================================
#  cs_dev :: deploy.ps1
#  Compile custom kits -> encrypt (CS sleeve format) -> patch client jar.
#
#  Usage:
#    .\deploy.ps1                     # build + deploy all kits
#    .\deploy.ps1 -Kits sleepmask     # single kit
#    .\deploy.ps1 -BuildOnly          # compile only, no jar patch
#    .\deploy.ps1 -Restore            # restore jar from backup
#
#  Layout assumption:
#    <CS root>\cobaltstrike-client.jar   (target)
#    <CS root>\cobaltstrike.auth         (key source)
#    cs_dev\tools\SleeveCrypt.java       (crypto tool)
#    cs_dev\kits\<name>\<name>.c         (kit sources)
# ===========================================================================
[CmdletBinding()]
param(
    [string[]] $Kits = @('sleepmask','injector','udrl'),
    [string[]] $Artifacts = @('artifact64'),   # 明文注入 resources/ (CS 直接读取, 不走 sleeve 加密)
    [string[]] $Defines = @(),                 # 免杀档案编译开关 (由 gen_profile.ps1 传入)
    [switch]   $BuildOnly,
    [switch]   $Restore,
    [string]   $CsRoot = '',
    [string]   $MinGw  = ''
)

$ErrorActionPreference = 'Stop'
$script:Root   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # ...\<CS root>
if (-not $CsRoot) { $CsRoot = $script:Root }
$DevDir        = Split-Path -Parent $PSScriptRoot                        # cs_dev
$BuildDir      = Join-Path $DevDir 'build'
$BackupDir     = Join-Path $DevDir 'backup'
$ToolsDir      = $PSScriptRoot

$Jar           = Join-Path $CsRoot 'cobaltstrike-client.jar'
$AuthFile      = Join-Path $CsRoot 'cobaltstrike.auth'
$PubKey        = Join-Path $DevDir 'build\authkey.pub'
$CryptBuild    = Join-Path $ToolsDir 'build'

if (-not $MinGw) {
    foreach ($c in @((Join-Path $CsRoot '_tools\mingw64\bin'), 'D:\mingw64\bin')) {
        if (Test-Path (Join-Path $c 'gcc.exe')) { $MinGw = $c; break }
    }
}
$Gcc = Join-Path $MinGw 'gcc.exe'
$Java = $null
foreach ($c in @('C:\Program Files\Java\jdk-17\bin\java.exe')) { if (Test-Path $c) { $Java = $c; break } }

function Say($m, $c='Gray') { Write-Host $m -ForegroundColor $c }

# ---------------------------------------------------------------- restore ---
if ($Restore) {
    $bk = Join-Path $BackupDir 'cobaltstrike-client.jar.orig'
    if (-not (Test-Path $bk)) { throw "no backup found at $bk" }
    Copy-Item $bk $Jar -Force
    Say "[+] restored client jar from backup" 'Green'
    return
}

if (-not (Test-Path $Jar))  { throw "client jar not found: $Jar" }
if (-not (Test-Path $Gcc))  { throw "gcc not found: $Gcc" }
New-Item -ItemType Directory -Force -Path $BuildDir, $BackupDir | Out-Null

# ------------------------------------------------------------ master key ---
function Get-MasterKey {
    # extract sleeve master key from cobaltstrike.auth via SleeveCrypt
    if (-not (Test-Path $PubKey)) { throw "authkey.pub missing: $PubKey" }
    $src = Join-Path $ToolsDir 'SleeveCrypt.java'
    if (-not (Test-Path $CryptBuild)) { New-Item -ItemType Directory -Force -Path $CryptBuild | Out-Null }
    $javac = Join-Path (Split-Path $Java -Parent) 'javac.exe'
    if (-not (Test-Path (Join-Path $CryptBuild 'SleeveCrypt.class'))) {
        & $javac -encoding UTF-8 -d $CryptBuild $src | Out-Null
    }
    $out = & $Java -cp $CryptBuild SleeveCrypt key $PubKey $AuthFile 2>&1
    $line = $out | Where-Object { $_ -match 'master key = ([0-9a-f]+)' }
    if (-not $line) { throw "failed to extract master key: $out" }
    return ([regex]::Match($line, 'master key = ([0-9a-f]+)').Groups[1].Value)
}

# --------------------------------------------------------------- compile ---
function Build-Kit($name) {
    $c = Join-Path $DevDir "kits\$name\$name.c"
    if (-not (Test-Path $c)) { Say "  [-] skip $name (source not found)" 'Yellow'; return $null }
    $o = Join-Path $BuildDir "$name.x64.o"
    $dflags = ''
    if ($Defines.Count -gt 0) { $dflags = ($Defines | ForEach-Object { "-D$_" }) -join ' ' }
    Say "  [*] compiling $name.x64.o ...$(if($dflags){" [$dflags]"})"
    $cmdArgs = @('-DWIN_X64') + ($Defines | ForEach-Object { "-D$_" }) + @(
        '-shared','-Wall','-Wno-pointer-arith','-Wno-unused-function',
        '-Wno-unused-variable','-Wno-cast-function-type','-O2',
        '-fno-asynchronous-unwind-tables','-fno-ident','-c',$c,'-o',$o)
    & $Gcc @cmdArgs 2>&1 |
        Where-Object { $_ -notmatch '^\s*$' } | ForEach-Object { Say "      $_" 'DarkGray' }
    if (-not (Test-Path $o)) { Say "  [-] $name build failed" 'Red'; return $null }
    $sz = (Get-Item $o).Length
    Say "  [+] $name.x64.o  ($sz bytes)" 'Green'
    return $o
}

# UDRL 需要无 CRT 依赖 (-nostdlib), 单独处理
function Build-Udrl {
    $c = Join-Path $DevDir 'kits\udrl\udrl.c'
    if (-not (Test-Path $c)) { Say "  [-] skip udrl (source not found)" 'Yellow'; return $null }
    $o = Join-Path $BuildDir 'udrl.x64.o'
    Say "  [*] compiling udrl.x64.o (nostdlib) ..."
    $cmdArgs = @('-DWIN_X64') + ($Defines | ForEach-Object { "-D$_" }) + @(
        '-shared','-Wall','-Wno-pointer-arith','-O2','-nostdlib',
        '-fno-asynchronous-unwind-tables','-fno-ident','-c',$c,'-o',$o)
    & $Gcc @cmdArgs 2>&1 |
        Where-Object { $_ -notmatch '^\s*$|warning: variable|Ignoring changed section' } | ForEach-Object { Say "      $_" 'DarkGray' }
    if (-not (Test-Path $o)) { Say "  [-] udrl build failed" 'Red'; return $null }
    Say "  [+] udrl.x64.o  ($((Get-Item $o).Length) bytes)" 'Green'
    return $o
}

# Artifact 模板: 编译为独立 PE, 明文注入 jar 的 resources/
function Build-Artifact($name) {
    $c = Join-Path $DevDir "kits\artifact\$name.c"
    if (-not (Test-Path $c)) { Say "  [-] skip $name (source not found)" 'Yellow'; return $null }
    $exe = Join-Path $BuildDir "$name.exe"
    Say "  [*] compiling $name.exe ..."
    & $Gcc -DWIN_X64 -O2 -s -mwindows -fno-ident -o $exe $c 2>&1 |
        Where-Object { $_ -notmatch '^\s*$' } | ForEach-Object { Say "      $_" 'DarkGray' }
    if (-not (Test-Path $exe)) { Say "  [-] $name build failed" 'Red'; return $null }
    # 校验 CS 锚点: 必须有 1024 个连续 'A'
    $bytes = [System.IO.File]::ReadAllBytes($exe)
    $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    $anchor = '41' * 1024
    if (-not $hex.Contains($anchor)) { Say "  [-] $name missing 1024-byte 'A' anchor, CS cannot locate" 'Red'; return $null }
    Say "  [+] $name.exe  ($($bytes.Length) bytes, anchor@ $($hex.IndexOf($anchor)/2))" 'Green'
    return $exe
}

# ---------------------------------------------------------------- deploy ---
function Deploy-Resource($objPath, $entryName, $key) {
    $enc = "$objPath.enc"
    & $Java -cp $CryptBuild SleeveCrypt encraw $key $objPath $enc | Out-Null
    if (-not (Test-Path $enc)) { throw "encryption failed for $entryName" }
    return $enc
}

# ================================================================== main ====
Say "=== cs_dev deploy ===" 'Cyan'
Say "CS root : $CsRoot"
Say "client  : $Jar"

$key = Get-MasterKey
Say "[+] sleeve master key: $($key.Substring(0,16))..." 'Green'

# build: Windows kit 模块 (COFF -> 加密注入 sleeve/)
$built = @{}
foreach ($k in $Kits) {
    $o = if ($k -eq 'udrl') { Build-Udrl } else { Build-Kit $k }
    if ($o) { $built[$k] = $o }
}
# build: artifact 模板 (PE -> 明文注入 resources/)
$builtArt = @{}
foreach ($a in $Artifacts) { $o = Build-Artifact $a; if ($o) { $builtArt[$a] = $o } }

if ($built.Count -eq 0 -and $builtArt.Count -eq 0) { throw "nothing built" }
if ($BuildOnly) { Say "[+] build-only done" 'Green'; return }

# backup once
$bak = Join-Path $BackupDir 'cobaltstrike-client.jar.orig'
if (-not (Test-Path $bak)) {
    Copy-Item $Jar $bak -Force
    Say "[+] backup -> $bak" 'Green'
} else {
    Say "[i] backup already exists (kept): $bak" 'DarkGray'
}

# patch jar (in-place via ZipArchive Update mode)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($Jar, 'Update')
try {
    foreach ($k in $built.Keys) {
        $entry = 'sleeve/' + $k + '.x64.o'
        $enc   = Deploy-Resource $built[$k] $entry $key

        $old = $zip.GetEntry($entry)
        if ($old) { $old.Delete(); Say "  [i] replaced existing entry $entry" 'DarkGray' }
        $ne = $zip.CreateEntry($entry, [System.IO.Compression.CompressionLevel]::Optimal)
        $os = $ne.Open(); $is = [System.IO.File]::OpenRead($enc)
        $is.CopyTo($os); $is.Close(); $os.Close()
        Say "  [+] injected $entry  ($((Get-Item $enc).Length) bytes)" 'Green'
    }
    # artifact 模板为明文 (BaseArtifactUtils 直接读 resources/, 不走 sleeve 解密)
    foreach ($a in $builtArt.Keys) {
        $entry = 'resources/' + $a + '.exe'
        $old = $zip.GetEntry($entry)
        if ($old) { $old.Delete(); Say "  [i] replaced existing entry $entry" 'DarkGray' }
        $ne = $zip.CreateEntry($entry, [System.IO.Compression.CompressionLevel]::Optimal)
        $os = $ne.Open(); $is = [System.IO.File]::OpenRead($builtArt[$a])
        $is.CopyTo($os); $is.Close(); $os.Close()
        Say "  [+] injected $entry (plain)  ($((Get-Item $builtArt[$a]).Length) bytes)" 'Green'
    }
} finally { $zip.Dispose() }

# verify: read back and decrypt
$zip = [System.IO.Compression.ZipFile]::OpenRead($Jar)
try {
    foreach ($k in $built.Keys) {
        $entry = 'sleeve/' + $k + '.x64.o'
        $e = $zip.GetEntry($entry)
        if (-not $e) { Say "  [-] verify failed: $entry missing" 'Red'; continue }
        $tmp = Join-Path $BuildDir "$k.verify.enc"
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $tmp, $true)
        & $Java -cp $CryptBuild SleeveCrypt decraw $key $tmp "$BuildDir\$k.verify.o" | Out-Null
        $h1 = (Get-FileHash $built[$k] -Algorithm SHA256).Hash
        $h2 = (Get-FileHash "$BuildDir\$k.verify.o" -Algorithm SHA256).Hash
        if ($h1 -eq $h2) { Say "  [+] verified $entry (roundtrip OK)" 'Green' }
        else              { Say "  [-] MISMATCH on $entry" 'Red' }
        Remove-Item $tmp -Force
    }
} finally { $zip.Dispose() }

# refresh integrity manifest inside container jar (if present)
$containerJar = Join-Path $CsRoot 'cobaltstrike.jar'
if (Test-Path $containerJar) {
    $md5 = (Get-FileHash $Jar -Algorithm MD5).Hash
    Say "[i] new client jar MD5: $md5" 'DarkGray'
    try {
        $cz = [System.IO.Compression.ZipFile]::Open($containerJar, 'Update')
        foreach ($n in @('cobaltstrike-client.md5','cobaltstrike-client.next.md5')) {
            $e = $cz.GetEntry($n)
            if ($e) {
                $e.Delete()
                $ne = $cz.CreateEntry($n)
                $w = New-Object System.IO.StreamWriter($ne.Open())
                $w.Write("$md5  cobaltstrike-client.jar"); $w.Close()
            }
        }
        $cz.Dispose()
        Say "[+] container jar md5 manifest updated" 'Green'
    } catch { Say "[!] md5 manifest update skipped: $($_.Exception.Message)" 'Yellow' }
}

Say ""
Say "=== done ===" 'Cyan'
Say "Run client: java -jar cobaltstrike-client.jar" 'White'
Say "Rollback  : .\deploy.ps1 -Restore" 'White'
