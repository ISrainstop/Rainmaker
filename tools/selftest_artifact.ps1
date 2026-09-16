# cs_dev :: selftest_artifact.ps1  --  Artifact 模板全链路自检
# ==========================================================================
# 验证「CS 写入配置 -> 模板解密 -> 执行 stager」四段链路是否真正连通.
#
# 原理: 未 patch 的模板 cfg->size == 0, run_stager() 立即返回;
#       按 CS 格式注入等价 stager 后, payload 必然被执行.
#       两种状态产生可区分的信号, 即证明链路成立.
#
#   artifact64.exe / svc.exe : payload 为 31 C0 C3 (xor eax,eax; ret)
#                              -> 执行完进入保活循环 -> 进程持续存活
#   artifact64dll.dll        : payload 为 EB FE (jmp $) 死循环
#                              -> 独占一个核心 -> 探针进程 CPU 时间飙升
#                              (DLL 在独立线程里跑, 线程存活无法从外部观察, 故用 CPU 信号)
[CmdletBinding()]
param(
    [string] $LibDir  = (Join-Path (Split-Path -Parent $PSScriptRoot) 'library'),
    [string] $Profile = 'stealth',
    [string] $Probe   = (Join-Path $PSScriptRoot 'probe.exe')
)

$ErrorActionPreference = 'Stop'

function Get-Anchor([byte[]]$bytes) {
    for ($i = 0; $i -le $bytes.Length - 1024; $i++) {
        if ($bytes[$i] -ne 0x41) { continue }
        $c = 0
        while ($i + $c -lt $bytes.Length -and $bytes[$i + $c] -eq 0x41) { $c++ }
        if ($c -ge 1024) { return $i }
        $i += $c
    }
    return -1
}

function New-Patched([byte[]]$base, [int]$anchor, [byte[]]$payload) {
    $key = [byte[]](0x11,0x22,0x33,0x44)
    $out = [byte[]]::new($base.Length)
    [Array]::Copy($base, $out, $base.Length)
    [Array]::Copy([BitConverter]::GetBytes([int]($anchor + 16)), 0, $out, $anchor + 0,  4)  # self
    [Array]::Copy([BitConverter]::GetBytes([int]$payload.Length), 0, $out, $anchor + 4,  4)  # size
    [Array]::Copy($key, 0, $out, $anchor + 8, 4)                                             # key
    for ($i = 0; $i -lt $payload.Length; $i++) {
        $out[$anchor + 20 + $i] = $payload[$i] -bxor $key[$i % 4]
    }
    return $out
}

$work = Join-Path $env:TEMP ('csdev_selftest_' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $work | Out-Null

$results = @()
try {
    # 自动扫描库内该档案的全部载体变体 (small stager + big stageless, exe/svc/dll)
    $variants = Get-ChildItem $LibDir -File |
                Where-Object { $_.Name -match ('^artifact64[a-z]*\.' + [regex]::Escape($Profile) + '\.(exe|dll)$') } |
                Sort-Object Name
    if ($variants.Count -eq 0) { Write-Host "[-] 库内没有 $Profile 档案的载体变体" -ForegroundColor Red }

    foreach ($vf in $variants) {
        $t = @{ name = $vf.Name; how = $(if ($vf.Name -like '*.dll') { 'dll' } else { 'process' }) }
        $src = Join-Path $LibDir $t.name
        if (-not (Test-Path $src)) { Write-Host "[-] 缺少 $($t.name)" -ForegroundColor Red; continue }

        $base   = [System.IO.File]::ReadAllBytes($src)
        $anchor = Get-Anchor $base
        if ($anchor -lt 0) { Write-Host "[-] $($t.name) 找不到 1024 个 'A' 锚点" -ForegroundColor Red; continue }

        $plainPath = Join-Path $work $t.name
        [System.IO.File]::WriteAllBytes($plainPath, $base)

        $plainSignal = $null; $patchSignal = $null; $detail = ''

        if ($t.how -eq 'process') {
            $patchedPath = Join-Path $work ('patched_' + $t.name)
            [System.IO.File]::WriteAllBytes($patchedPath, (New-Patched $base $anchor ([byte[]](0x31,0xC0,0xC3))))

            $pr = Start-Process -FilePath $plainPath -PassThru
            $plainSignal = if ($pr.WaitForExit(2500)) { 'exit' } else { 'alive' }
            if ($plainSignal -eq 'alive') { $pr.Kill() }

            $pq = Start-Process -FilePath $patchedPath -PassThru
            $patchSignal = if ($pq.WaitForExit(2500)) { 'exit' } else { 'alive' }
            if ($patchSignal -eq 'alive') { $pq.Kill() }
        }
        else {
            if (-not (Test-Path $Probe)) {
                Write-Host "  [!] $($t.name): 探针缺失 ($Probe), 跳过" -ForegroundColor Yellow; continue
            }
            $patchedPath = Join-Path $work ('spin_' + $t.name)
            [System.IO.File]::WriteAllBytes($patchedPath, (New-Patched $base $anchor ([byte[]](0xEB,0xFE))))

            $ep = Start-Process -FilePath $Probe -ArgumentList $plainPath   -PassThru -WindowStyle Hidden
            $ep.WaitForExit(9000) | Out-Null
            $ecpu = $ep.TotalProcessorTime.TotalSeconds

            $sp = Start-Process -FilePath $Probe -ArgumentList $patchedPath -PassThru -WindowStyle Hidden
            $sp.WaitForExit(9000) | Out-Null
            $scpu = $sp.TotalProcessorTime.TotalSeconds

            # 探针驻留 2s: 未 patch 时线程瞬间结束 -> CPU 几乎为 0; 已 patch 时独占一核 -> CPU 接近 2s
            $plainSignal = if ($ecpu -lt 0.30) { 'idle' } else { 'busy' }
            $patchSignal = if ($scpu -gt 0.80) { 'busy' } else { 'idle' }
            $detail = ('CPU 未patch={0:N3}s 已patch={1:N3}s' -f $ecpu, $scpu)
        }

        $verdict = if ($plainSignal -ne $patchSignal) { '通过' } else { '存疑' }
        $color   = if ($verdict -eq '通过') { 'Green' } else { 'Yellow' }
        Write-Host ("  {0,-30} 未patch={1,-6} 已patch={2,-6} => {3}  {4}" -f `
            $t.name, $plainSignal, $patchSignal, $verdict, $detail) -ForegroundColor $color

        $results += [pscustomobject]@{
            Variant = $t.name; Anchor = $anchor
            Plain = $plainSignal; Patched = $patchSignal
            Verdict = $verdict; Detail = $detail
        }
    }
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($results.Count -gt 0) {
    $ok = ($results | Where-Object { $_.Verdict -eq '通过' }).Count
    Write-Host ("  {0}/{1} 载体通过全链路自检" -f $ok, $results.Count) -ForegroundColor $(if ($ok -eq $results.Count) { 'Green' } else { 'Yellow' })
}
