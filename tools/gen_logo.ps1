# Rainmaker C2 :: 生成 README 用的 logo (PNG, 高分辨率)
#
# 产出两份:
#   docs\assets\logo.png       横向组合标 (图标块 + 手写体字标), 用于 README 顶部
#   docs\assets\icon.png       应用图标 256px, 用于 README 里单独引用
#
# 字体用 Segoe Script (Windows 自带的手写体)。不用 Gabriola —— 它的花体装饰只在
# 小写上, 单个大写 R 会渲染成普通衬线 (实测确认)。
#
# 注意 GDI+ 的两个坑:
#   1) Font 的单位是**磅**而画布是**像素**, 按像素给字号会大出 4/3 倍, 必须 pt = px*72/96
#   2) 手写体的行高远大于字形本身, 用 DrawString 居中会偏上, 必须取字形边界再定位
param(
    [string]$OutDir = "$PSScriptRoot\..\docs\assets"
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Get-DisplayFont([single]$pt, [System.Drawing.FontStyle]$style) {
    foreach ($n in @('Segoe Script', 'Brush Script MT', 'Lucida Handwriting', 'Georgia')) {
        try {
            $f = New-Object System.Drawing.Font($n, $pt, $style)
            if ($f.Name -eq $n) { return $f }
            $f.Dispose()
        } catch { }
    }
    return New-Object System.Drawing.Font('Georgia', $pt, $style)
}

# 把一串文字按真实字形边界缩放到目标高度并定位到指定基线, 返回绘制好的 GraphicsPath
function New-TextPath([string]$Text, [single]$TargetH, [single]$X, [single]$Y) {
    $pt = [single](200 * 72.0 / 96.0)
    $font = Get-DisplayFont $pt ([System.Drawing.FontStyle]::Bold)
    $gp = New-Object System.Drawing.Drawing2D.GraphicsPath
    $gp.AddString($Text, $font.FontFamily, [int]$font.Style, $font.SizeInPoints,
                  (New-Object System.Drawing.PointF(0, 0)),
                  [System.Drawing.StringFormat]::GenericTypographic)
    $b = $gp.GetBounds()
    $sc = [single]($TargetH / $b.Height)
    $m1 = New-Object System.Drawing.Drawing2D.Matrix
    $m1.Scale($sc, $sc)
    $gp.Transform($m1)
    $b2 = $gp.GetBounds()
    $m2 = New-Object System.Drawing.Drawing2D.Matrix
    $m2.Translate([single]($X - $b2.X), [single]($Y - $b2.Y))
    $gp.Transform($m2)
    $m1.Dispose(); $m2.Dispose(); $font.Dispose()
    return $gp
}

# 画图标方块 (圆角渐变底 + 手写 R + 三道划痕), 可指定尺寸与位置
function Add-IconTile($g, [single]$X, [single]$Y, [single]$S) {
    $rect = New-Object System.Drawing.RectangleF($X, $Y, $S, $S)
    $r = [single]($S * 0.22)
    $d = $r * 2
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $p.AddArc($X, $Y, $d, $d, 180, 90)
    $p.AddArc($X + $S - $d, $Y, $d, $d, 270, 90)
    $p.AddArc($X + $S - $d, $Y + $S - $d, $d, $d, 0, 90)
    $p.AddArc($X, $Y + $S - $d, $d, $d, 90, 90)
    $p.CloseFigure()

    $c1 = [System.Drawing.ColorTranslator]::FromHtml('#1E3A8A')
    $c2 = [System.Drawing.ColorTranslator]::FromHtml('#2563EB')
    $c3 = [System.Drawing.ColorTranslator]::FromHtml('#0E7490')
    $lg = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rect, $c1, $c3, [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
    $bl = New-Object System.Drawing.Drawing2D.ColorBlend(3)
    $bl.Colors = @($c1, $c2, $c3)
    $bl.Positions = [single[]]@(0.0, 0.45, 1.0)
    $lg.InterpolationColors = $bl
    $g.FillPath($lg, $p)

    # 手写 R
    $rPath = New-TextPath 'R' ([single]($S * 0.54)) ([single]($X + $S * 0.30)) ([single]($Y + $S * 0.25))
    $shadow = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(165, 8, 20, 45))
    $rShadow = $rPath.Clone()
    $mm = New-Object System.Drawing.Drawing2D.Matrix
    $mm.Translate([single]($S * 0.016), [single]($S * 0.016))
    $rShadow.Transform($mm)
    $g.FillPath($shadow, $rShadow)
    $g.FillPath([System.Drawing.Brushes]::White, $rPath)

    # 三道划痕
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(215, 255, 255, 255), [single]($S * 0.045))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    foreach ($ln in @(@(0.06,0.22,0.19,0.36), @(0.04,0.47,0.16,0.59), @(0.08,0.72,0.17,0.81))) {
        $g.DrawLine($pen, [single]($X + $S * $ln[0]), [single]($Y + $S * $ln[1]),
                          [single]($X + $S * $ln[2]), [single]($Y + $S * $ln[3]))
    }
    $pen.Dispose(); $mm.Dispose(); $rShadow.Dispose(); $shadow.Dispose()
    $rPath.Dispose(); $lg.Dispose(); $p.Dispose()
}

# ---------------------------------------------------------------- 横向组合标
# 画布按 2x 输出, 便于高分屏。宽高给足, 免得字标的连笔伸出边界被裁。
$W = 1280; $H = 296
$bmp = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.Clear([System.Drawing.Color]::Transparent)

$tileX = 44; $tileY = 42; $tileS = 186
Add-IconTile $g $tileX $tileY $tileS

# 字标: 描边层 + 渐变层 (与界面同一套做法)。
# 先建路径拿到**实际渲染宽度**, 再据此摆放 C2 —— 手写体的宽度无法预估,
# 写死坐标必然重叠 (上一版就是这么撞上的)。
$textX = [single]($tileX + $tileS + 40)
$textY = [single]($tileY + 6)
$textPath = New-TextPath 'Rainmaker' 104 $textX $textY
$tb = $textPath.GetBounds()
$textRight = [single]($tb.X + $tb.Width)

$strokePath = $textPath.Clone()
$mm2 = New-Object System.Drawing.Drawing2D.Matrix
$mm2.Translate(3.0, 3.0)
$strokePath.Transform($mm2)
$g.FillPath((New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#0C1E3E'))), $strokePath)

$gb = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $tb,
    [System.Drawing.ColorTranslator]::FromHtml('#60A5FA'),
    [System.Drawing.ColorTranslator]::FromHtml('#0E7490'),
    [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal)
$g.FillPath($gb, $textPath)

# C2: 摆在字标右侧、贴字标底部基线对齐
$f2 = New-Object System.Drawing.Font('Consolas', [single](38 * 72.0 / 96.0), [System.Drawing.FontStyle]::Bold)
$szC2 = $g.MeasureString('C2', $f2)
$c2x = [single]($textRight + 14)
$c2y = [single]($tb.Y + $tb.Height - $szC2.Height + 4)
$g.DrawString('C2', $f2, (New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#1F2430'))), $c2x, $c2y)

# 副标: 放在字标下方, 与字标左边缘对齐
$f3 = New-Object System.Drawing.Font('Segoe UI', [single](18 * 72.0 / 96.0))
$g.DrawString('command & control framework', $f3,
    (New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#6B7280'))),
    $textX, [single]($tb.Y + $tb.Height + 4))

$logoPath = Join-Path $OutDir 'logo.png'
$bmp.Save($logoPath, [System.Drawing.Imaging.ImageFormat]::Png)
$gb.Dispose(); $strokePath.Dispose(); $textPath.Dispose(); $f2.Dispose(); $f3.Dispose(); $g.Dispose(); $bmp.Dispose()

# ---------------------------------------------------------------- 应用图标 256
$ib = New-Object System.Drawing.Bitmap(256, 256, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$gi = [System.Drawing.Graphics]::FromImage($ib)
$gi.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$gi.Clear([System.Drawing.Color]::Transparent)
Add-IconTile $gi 0 0 256
$iconPath = Join-Path $OutDir 'icon.png'
$ib.Save($iconPath, [System.Drawing.Imaging.ImageFormat]::Png)
$gi.Dispose(); $ib.Dispose()

foreach ($f in @($logoPath, $iconPath)) {
    $fi = Get-Item $f
    "[+] {0}  {1:N0} 字节" -f $fi.Name, $fi.Length
}
