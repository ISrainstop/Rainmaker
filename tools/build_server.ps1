# Rainmaker C2 :: 服务端跨平台构建
#
# 一次编出 Windows / Linux / macOS 三个平台的服务端。
# 服务端本身零第三方依赖 (纯 Go 标准库 + golang.org/x/text), 所以交叉编译不需要
# 目标平台的工具链 —— CGO 关掉即可, 产物是静态链接的单一二进制。
#
# 用法:
#   pwsh -File tools\build_server.ps1                 # 全部平台 + 校验
#   pwsh -File tools\build_server.ps1 -Only linux     # 只编 Linux
#   pwsh -File tools\build_server.ps1 -Verify         # 额外跑 go vet 与单元测试
param(
    [ValidateSet('all', 'windows', 'linux', 'darwin')]
    [string]$Only = 'all',
    [switch]$Verify,
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$goDir = Join-Path $root 'go'
if ($OutDir -eq '') { $OutDir = Join-Path $root 'build' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# GOOS / GOARCH -> 输出文件名。取名带平台后缀, 免得三份产物互相覆盖。
$targets = @(
    @{ OS = 'windows'; Arch = 'amd64'; Name = 'csdev-server.exe' },
    @{ OS = 'linux';   Arch = 'amd64'; Name = 'csdev-server-linux-amd64' },
    @{ OS = 'linux';   Arch = 'arm64'; Name = 'csdev-server-linux-arm64' },
    @{ OS = 'darwin';  Arch = 'amd64'; Name = 'csdev-server-darwin-amd64' },
    @{ OS = 'darwin';  Arch = 'arm64'; Name = 'csdev-server-darwin-arm64' }
)

Push-Location $goDir
try {
    if ($Verify) {
        Write-Host "[*] go vet ..." -ForegroundColor Cyan
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "go vet 失败" }
        Write-Host "[*] go test ..." -ForegroundColor Cyan
        go test ./...
        if ($LASTEXITCODE -ne 0) { throw "go test 失败" }
    }

    foreach ($t in $targets) {
        if ($Only -ne 'all' -and $t.OS -ne $Only) { continue }

        $env:GOOS = $t.OS
        $env:GOARCH = $t.Arch
        $env:CGO_ENABLED = '0'      # 关掉 cgo 才能产出无依赖的静态二进制
        $out = Join-Path $OutDir $t.Name

        Write-Host ("[*] {0}/{1} -> {2}" -f $t.OS, $t.Arch, $t.Name) -ForegroundColor Cyan
        go build -trimpath -ldflags "-s -w" -o $out .
        if ($LASTEXITCODE -ne 0) { throw ("构建失败: {0}/{1}" -f $t.OS, $t.Arch) }

        $fi = Get-Item $out
        Write-Host ("    {0:N0} 字节" -f $fi.Length) -ForegroundColor DarkGray
    }
}
finally {
    # 环境变量必须清掉, 否则同一个 shell 里后续的普通 go build 会继续按交叉编译走
    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}

Write-Host ""
Write-Host "[+] 构建完成, 产物在 $OutDir" -ForegroundColor Green
Write-Host "    注意: 载荷生成当前仍依赖 PowerShell 生成器 (tools\gen_payload*.ps1)。" -ForegroundColor Yellow
Write-Host "    在 Linux/macOS 上没有 pwsh 时, 服务端本身可正常运行 (会话/命令/报告/脚本引擎都可用)," -ForegroundColor Yellow
Write-Host "    但 /api/payload/build 会失败 —— 这是下一步要解决的事。" -ForegroundColor Yellow
