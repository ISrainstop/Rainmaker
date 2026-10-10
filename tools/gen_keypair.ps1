# csdev :: gen_keypair.ps1  --  生成/轮换 C2 服务端 RSA-2048 密钥对
# ==========================================================================
# 产物:
#   data\csdev.key          PKCS#8 私钥 (PEM)      —— 服务端持有, 严禁外传
#   data\csdev.pub          PKIX 公钥 (PEM)        —— 存档
#   kits\beacon\pubkey.h    CryptoAPI PUBLICKEYBLOB (C 数组) —— 编译进植入体
#
# 协议依据: docs/protocol_v2.md 第 1.2 节
#
# 用法:
#   .\tools\gen_keypair.ps1              # 已存在则拒绝覆盖
#   .\tools\gen_keypair.ps1 -Force       # 强制轮换 (旧植入体将无法回连)
# ==========================================================================
[CmdletBinding()]
param(
    [switch] $Force,
    [int]    $Bits = 2048
)

$ErrorActionPreference = 'Stop'
$DevDir  = Split-Path -Parent $PSScriptRoot
$KeyDir  = Join-Path $DevDir 'data'
$HdrOut  = Join-Path $DevDir 'kits\beacon\pubkey.h'
$KeyOut  = Join-Path $KeyDir 'csdev.key'
$PubOut  = Join-Path $KeyDir 'csdev.pub'

New-Item -ItemType Directory -Force -Path $KeyDir | Out-Null

if ((Test-Path $KeyOut) -and -not $Force) {
    Write-Host "[!] 密钥已存在: $KeyOut" -ForegroundColor Yellow
    Write-Host "    如需轮换请加 -Force (注意: 已编译的植入体会全部失效)" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] 生成 RSA-$Bits 密钥对 ..." -ForegroundColor White
$rsa = [System.Security.Cryptography.RSA]::Create($Bits)
$p   = $rsa.ExportParameters($true)

# ---------------------------------------------------------------- PEM 落盘
# 兼容性: ExportPkcs8PrivateKeyPem / ExportSubjectPublicKeyInfoPem 是 .NET 5+
# 才有的一步到位 API; Windows PowerShell 5.1(.NET Framework 4.x) 只有返回
# byte[] 的 ExportPkcs8PrivateKey / ExportSubjectPublicKeyInfo, 这里手拼 PEM。
$privDer = $rsa.ExportPkcs8PrivateKey()
$pubDer  = $rsa.ExportSubjectPublicKeyInfo()
[System.IO.File]::WriteAllText($KeyOut,
    "-----BEGIN PRIVATE KEY-----`r`n" + [Convert]::ToBase64String($privDer, 'InsertLineBreaks') + "`r`n-----END PRIVATE KEY-----`r`n")
[System.IO.File]::WriteAllText($PubOut,
    "-----BEGIN PUBLIC KEY-----`r`n" + [Convert]::ToBase64String($pubDer, 'InsertLineBreaks') + "`r`n-----END PUBLIC KEY-----`r`n")

# ---------------------------------------------- CryptoAPI PUBLICKEYBLOB
# BLOBHEADER(8) + RSAPUBKEY(12) + modulus(256, 小端)
$modBE = $p.Modulus                       # 大端
$modLE = [byte[]]::new($modBE.Length)
for ($i = 0; $i -lt $modBE.Length; $i++) { $modLE[$i] = $modBE[$modBE.Length - 1 - $i] }

$bitlen = $Bits
$blob = New-Object System.Collections.Generic.List[byte]
$blob.AddRange([byte[]]@(
    0x06, 0x02, 0x00, 0x00,     # BLOBHEADER: PUBLICKEYBLOB, version 2, reserved
    0x00, 0xA4, 0x00, 0x00      # aiKeyAlg = CALG_RSA_KEYX (0xA400) 小端
))
$blob.AddRange([byte[]]@(
    0x52, 0x53, 0x41, 0x31,     # magic "RSA1"
    [byte]($bitlen -band 0xFF), [byte](($bitlen -shr 8) -band 0xFF), 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00      # pubexp = 65537 小端
))
$blob.AddRange($modLE)
$blobBytes = $blob.ToArray()

# ------------------------------------------------------------- C 头文件
$fingerprint = [System.Security.Cryptography.SHA256]::Create().ComputeHash($modBE)
$fpHex = ($fingerprint[0..7] | ForEach-Object { $_.ToString('x2') }) -join ''

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('/*')
[void]$sb.AppendLine(' * csdev :: pubkey.h  --  自动生成, 请勿手工编辑')
[void]$sb.AppendLine(' * ======================================================================')
[void]$sb.AppendLine(" * 生成时间   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$sb.AppendLine(" * 密钥长度   : RSA-$Bits")
[void]$sb.AppendLine(" * 模数指纹   : sha256(mod)[0:8] = $fpHex")
[void]$sb.AppendLine(' * 生成工具   : tools/gen_keypair.ps1')
[void]$sb.AppendLine(' *')
[void]$sb.AppendLine(' * 轮换密钥后必须重新编译全部植入体, 否则无法回连。')
[void]$sb.AppendLine(' */')
[void]$sb.AppendLine('#ifndef CSDEV_PUBKEY_H')
[void]$sb.AppendLine('#define CSDEV_PUBKEY_H')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("#define CSDEV_PUBKEY_FINGERPRINT `"$fpHex`"")
[void]$sb.AppendLine("static const unsigned char CSDEV_PUBKEY_BLOB[$($blobBytes.Length)] = {")

$line = '    '
for ($i = 0; $i -lt $blobBytes.Length; $i++) {
    $line += ('0x{0:x2}' -f $blobBytes[$i])
    if ($i -lt $blobBytes.Length - 1) { $line += ',' }
    if (($i + 1) % 16 -eq 0) {
        [void]$sb.AppendLine($line)
        $line = '    '
    }
}
if ($line.Trim().Length -gt 0) { [void]$sb.AppendLine($line) }
[void]$sb.AppendLine('};')
[void]$sb.AppendLine("#define CSDEV_PUBKEY_LEN $($blobBytes.Length)")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('#endif /* CSDEV_PUBKEY_H */')

[System.IO.File]::WriteAllText($HdrOut, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "[+] 完成" -ForegroundColor Green
Write-Host ("    私钥 : {0}  ({1} 字节)" -f $KeyOut, (Get-Item $KeyOut).Length)
Write-Host ("    公钥 : {0}" -f $PubOut)
Write-Host ("    头文件: {0}  ({1} 字节, blob {2} 字节)" -f $HdrOut, (Get-Item $HdrOut).Length, $blobBytes.Length)
Write-Host ("    指纹 : {0}" -f $fpHex)
Write-Host ""
$rsa.Dispose()
