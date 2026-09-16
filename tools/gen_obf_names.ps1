# csdev :: gen_obf_names.ps1
# ==========================================================================
# 从源码里的名字清单生成"编译期混淆字符串表" -> kits/beacon/cs_obf_names.h
#
# 为什么要生成而不是手写: 名字清单会变(BOF API 增删、注入 API 调整),
# 手写的混淆表必然与代码脱节; 让脚本每次构建前扫一遍源码最省心。
#
# 清单来源(任一存在即收集):
#   1) kits/beacon/bof_api.c 里 API_ENT(X) 的 X
#   2) tools/obf_names.txt   每行一个名字(# 开头为注释) —— 放"必须混淆但不来自宏"的名字,
#      例如 kapi("VirtualAllocEx") 这种直接写在调用里的
#
# 输出: kits/beacon/cs_obf_names.h
#   每个名字一个数组: static const unsigned char CS_ENC_<name>[] = { ..., <salt> };
#   最后一个字节是每串独立的盐(见 cs_obf.h)。
#
# 用法: .\tools\gen_obf_names.ps1          生成
#       .\tools\gen_obf_names.ps1 -Check   只检查是否已是最新(CI 用)
# ==========================================================================
[CmdletBinding()]
param(
    [switch] $Check
)

$ErrorActionPreference = 'Stop'
$DevDir   = Split-Path -Parent $PSScriptRoot
$BofApi   = Join-Path $DevDir 'kits\beacon\bof_api.c'
$ExtraList= Join-Path $DevDir 'tools\obf_names.txt'
$OutFile  = Join-Path $DevDir 'kits\beacon\cs_obf_names.h'

function Sanitize([string] $s) {
    # 名字 -> 合法 C 标识符片段
    $t = $s -replace '[^A-Za-z0-9_]', '_'
    return $t
}

$names = New-Object System.Collections.Generic.List[string]

# 1) bof_api.c 的 API_ENT(...)
if (Test-Path $BofApi) {
    $txt = [System.IO.File]::ReadAllText($BofApi)
    foreach ($m in [regex]::Matches($txt, 'API_ENT\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')) {
        $names.Add($m.Groups[1].Value)
    }
}

# 2) 手工清单(必须混淆但不来自宏的名字)
if (Test-Path $ExtraList) {
    foreach ($line in [System.IO.File]::ReadAllLines($ExtraList)) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $names.Add($t)
    }
}

$names = $names | Select-Object -Unique | Sort-Object
if ($names.Count -eq 0) { throw "没有收集到任何需要混淆的名字(检查 $BofApi 与 $ExtraList)" }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('/* 由 tools/gen_obf_names.ps1 自动生成 —— 不要手改。')
[void]$sb.AppendLine(' * 名字清单来自 kits/beacon/bof_api.c 的 API_ENT(...) 与 tools/obf_names.txt。')
[void]$sb.AppendLine(' * 每串独立盐存在数组最后一个字节, 见 cs_obf.h 的说明。 */')
[void]$sb.AppendLine('#ifndef CSDEV_CS_OBF_NAMES_H')
[void]$sb.AppendLine('#define CSDEV_CS_OBF_NAMES_H')
[void]$sb.AppendLine('')

$ascii = [System.Text.Encoding]::ASCII
$idx = 0
foreach ($n in $names) {
    $bytes = $ascii.GetBytes($n)
    $salt  = [byte]((0x37 + ($idx * 29) + ($bytes.Length * 11)) -band 0xFF)
    $out   = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        # 与 cs_obf_key() 完全一致
        $k = [int]$salt + ($i * 7) + 0x5A
        $k = $k -bxor ($k -shr 5)
        $k = $k -band 0xFF
        $out.Add(('0x{0:X2}' -f ($bytes[$i] -bxor $k)))
    }
    $out.Add(('0x{0:X2}' -f $salt))
    $ident = Sanitize $n
    [void]$sb.AppendLine(("static const unsigned char CS_ENC_{0}[] = {{ {1} }}; /* {2} */" -f $ident, ($out -join ','), $n))
    $idx++
}

[void]$sb.AppendLine('')
[void]$sb.AppendLine(('#define CS_OBF_NAME_COUNT {0}' -f $names.Count))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('#endif /* CSDEV_CS_OBF_NAMES_H */')

$new = $sb.ToString()

if ($Check) {
    $old = if (Test-Path $OutFile) { [System.IO.File]::ReadAllText($OutFile) } else { '' }
    if ($old -ne $new) { throw "cs_obf_names.h 不是最新的, 请运行 tools\gen_obf_names.ps1" }
    Write-Output "[OK] cs_obf_names.h 已是最新 ($($names.Count) 个名字)"
    return
}

[System.IO.File]::WriteAllText($OutFile, $new, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "[+] 已生成 $OutFile  ($($names.Count) 个名字)"
Write-Output ("    前几个: " + (($names | Select-Object -First 5) -join ', '))
