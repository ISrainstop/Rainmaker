<#
  cs_dev :: gen_profile.ps1  --  免杀档案管理与一键切换
  ==========================================================================
  在生成载荷前选择免杀方式。档案编译开关通过 -D 注入 kit 源码, 决定:

     遥测绕过方式 : 传统内存 patch  vs  硬件断点 patchless (VEH)
     Native 调用  : Win32 API       vs  RecycledGate syscall
     调用栈       : 常规             vs  合法模块 gadget 转发伪造
     镜像头       : 保留             vs  映射后擦除

  用法:
    .\gen_profile.ps1                             列出全部档案与当前生效档案
    .\gen_profile.ps1 -Profile advanced           应用档案 (编译 + 注入 jar)
    .\gen_profile.ps1 -Profile basic -BuildOnly   只编译不注入
    .\gen_profile.ps1 -Profile custom -Defines CS_DEV_LEGACY_PATCH
    .\gen_profile.ps1 -Profile stealth -Kits injector,udrl

  注意: Windows kit 由客户端启动时从 jar 解密加载, 切换档案后需重启客户端。
        Linux 载荷每次生成都重新编译, 免杀选项即时生效 (见 gen_linux.ps1)。
  ==========================================================================
#>
[CmdletBinding()]
param(
    [string] $Profile = '',
    [string[]] $Defines = @(),
    [string[]] $Kits = @('sleepmask','injector','udrl'),
    [switch] $BuildOnly,
    [switch] $SkipDeploy
)

$ErrorActionPreference = 'Stop'
$ToolsDir = $PSScriptRoot
$DevDir   = Split-Path -Parent $ToolsDir
$StateFile = Join-Path $DevDir 'profile.current'

function Say($m, $c='Gray') { Write-Host $m -ForegroundColor $c }

# ==========================================================================
# 档案定义
#   Defines 为空表示全部前沿特性开启 (默认编译路径)
# ==========================================================================
$PROFILES = [ordered]@{
    'basic' = [ordered]@{
        Title   = 'Basic / Compatible'
        Summary = 'legacy mem patch + Win32 API, no syscall'
        Defines = @('CS_DEV_LEGACY_PATCH','CS_DEV_NO_RECYCLEDGATE','CS_DEV_NO_STACKSPOOF')
        When    = 'hosts sensitive to DR/VEH, or max compatibility'
        Tradeoff= 'first byte patched, integrity check can detect'
    }
    'advanced' = [ordered]@{
        Title   = 'Advanced / Recommended'
        Summary = 'HWBP patchless + RecycledGate syscall'
        Defines = @('CS_DEV_NO_STACKSPOOF')
        When    = 'default for most scenarios'
        Tradeoff= 'no mem change; syscall in ntdll; no stack spoof'
    }
    'stealth' = [ordered]@{
        Title   = 'Stealth / All features'
        Summary = 'patchless + RecycledGate + stack spoof + header wipe'
        Defines = @()
        When    = 'target runs memory scan and stack tracing'
        Tradeoff= 'HWBP per-thread max 4; stack spoof <=4 args'
    }
}

# ==========================================================================
# 列出档案
# ==========================================================================
function Show-Profiles {
    $cur = ''
    if (Test-Path $StateFile) { $cur = (Get-Content $StateFile -First 1).Trim() }

    Say ""
    Say "  cs_dev evasion profiles" 'Cyan'
    Say "  ================================================================"
    foreach ($k in $PROFILES.Keys) {
        $p   = $PROFILES[$k]
        $tag = if ($k -eq $cur) { '  <== ACTIVE' } else { '' }
        Say ""
        Say ("  [{0}]{1}" -f $k, $tag) $(if ($k -eq $cur) { 'Green' } else { 'White' })
        Say ("    {0}" -f $p.Title)
        Say ("    desc    : {0}" -f $p.Summary)
        Say ("    when    : {0}" -f $p.When)
        Say ("    tradeoff: {0}" -f $p.Tradeoff) 'DarkGray'
        if ($p.Defines.Count -gt 0) {
            Say ("    defines : {0}" -f (($p.Defines | ForEach-Object { "-D$_" }) -join ' ')) 'DarkGray'
        } else {
            Say "    defines : (none, all features enabled)" 'DarkGray'
        }
    }
    Say ""
    Say "  ================================================================"
    Say "  apply:  .\gen_profile.ps1 -Profile advanced" 'White'
    Say "  custom : .\gen_profile.ps1 -Profile custom -Defines CS_DEV_LEGACY_PATCH" 'White'
    Say ""
}

# ==========================================================================
# 应用档案
# ==========================================================================
function Apply-Profile($name, $extraDefines) {
    $defs = @()
    if ($name -eq 'custom') {
        if ($extraDefines.Count -eq 0) { throw "custom profile requires -Defines" }
        $defs = $extraDefines
        Say "[*] custom profile: $($defs -join ', ')" 'Cyan'
    } else {
        if (-not $PROFILES.Contains($name)) { throw "unknown profile: $name" }
        $p = $PROFILES[$name]
        $defs = $p.Defines
        Say "[*] applyprofile [$name] $($p.Title)" 'Cyan'
        Say "    $($p.Summary)"
        if ($defs.Count -gt 0) {
            Say "    defines: $(($defs | ForEach-Object { "-D$_" }) -join ' ')" 'DarkGray'
        } else {
            Say "    defines: (none, all features enabled)" 'DarkGray'
        }
    }

    # 委托 deploy.ps1 完成 编译 -> 加密 -> 注入 jar -> 校验
    # 用哈希表 splat: 数组 splat 会按位置绑定, 把 '-Kits' 当成参数值导致全盘错位
    $deploy = Join-Path $ToolsDir 'deploy.ps1'
    $deployParams = @{
        Kits    = [string[]]$Kits
        Defines = [string[]]$defs
    }
    if ($BuildOnly -or $SkipDeploy) { $deployParams['BuildOnly'] = $true }
    if ($SkipDeploy) { Say "[i] SkipDeploy: compile only, jar not modified" 'Yellow' }

    & $deploy @deployParams

    # 记录current profile
    $lines = @($name, ($defs -join ','), ($Kits -join ','), (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $lines | Out-File -FilePath $StateFile -Encoding UTF8
    Say ""
    Say "[+] profile [$name] deployed" 'Green'
    Say "    restart client to take effect" 'Yellow'
    Say "    state file: $StateFile" 'DarkGray'
}

# ==========================================================================
# 主流程
# ==========================================================================
if (-not $Profile) {
    Show-Profiles
    return
}

if ($Profile -eq 'custom') {
    Apply-Profile 'custom' $Defines
} else {
    Apply-Profile $Profile @()
}
