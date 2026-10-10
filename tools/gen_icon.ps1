# Rainmaker C2 :: 生成应用程序图标 (多尺寸 ICO)
#
# 设计: "R" 花体字标 + 三道斜划痕。
#   用 Gabriola 渲染大写 R —— 它是 Win 自带的花体, 大写字母带大量连笔装饰,
#   与界面里的字标同源, 比抽象图形更能一眼认出是哪个项目。
#   三道斜划痕给攻击性, 同时在小尺寸下充当视觉重量。
#   早期版本用的是"雨滴", 按用户要求换掉 (雨滴太温和, 不像攻击性工具的图标)。
#
# 输出: gui\app.ico, 内含 16/24/32/48/64/128/256 七个尺寸 (PNG 压缩, Vista+ 支持)。
# 用法: pwsh -File tools\gen_icon.ps1
param(
    [string]$Out = "$PSScriptRoot\..\gui\app.ico"
)

Add-Type -AssemblyName System.Drawing

$sizes = @(16, 24, 32, 48, 64, 128, 256)

# 花体字体: 优先 Segoe Script —— 它是**真手写体**, 大小写都带连笔;
# Gabriola 虽然更华丽, 但它的大写字母本身是普通衬线形状, 花体装饰只在**小写**上,
# 拿它渲染单个大写 R 会得到一个平平无奇的衬线 R (实测确认)。
function Resolve-DisplayFont([single]$pt, [System.Drawing.FontStyle]$style) {
    foreach ($name in @('Segoe Script', 'Brush Script MT', 'Lucida Handwriting',
                        'Gabriola', 'Palatino Linotype', 'Georgia')) {
        try {
            $f = New-Object System.Drawing.Font($name, $pt, $style)
            if ($f.Name -eq $name) { return $f }
            $f.Dispose()
        } catch { }
    }
    return New-Object System.Drawing.Font('Georgia', $pt, $style)
}

function New-IconBitmap([int]$S) {
    $bmp = New-Object System.Drawing.Bitmap($S, $S, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit

    # 圆角蓝底: 大尺寸留圆角, 16/24 直接满幅方底 —— 圆角在 16px 下只剩几像素弧度, 反而显脏
    $r = if ($S -ge 48) { [int]($S * 0.22) } else { 0 }
    $rect = New-Object System.Drawing.Rectangle(0, 0, $S, $S)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    if ($r -gt 0) {
        $d = $r * 2
        $path.AddArc(0, 0, $d, $d, 180, 90)
        $path.AddArc($S - $d, 0, $d, $d, 270, 90)
        $path.AddArc($S - $d, $S - $d, $d, $d, 0, 90)
        $path.AddArc(0, $S - $d, $d, $d, 90, 90)
        $path.CloseFigure()
    } else {
        $path.AddRectangle($rect)
    }

    # 三段纵向渐变 (深靛 -> 蓝 -> 青); 两段在小尺寸下就是"一块蓝", 三段才有金属感
    $c1 = [System.Drawing.ColorTranslator]::FromHtml('#1E3A8A')
    $c2 = [System.Drawing.ColorTranslator]::FromHtml('#2563EB')
    $c3 = [System.Drawing.ColorTranslator]::FromHtml('#0E7490')
    $lg = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rect, $c1, $c3, [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
    $blend = New-Object System.Drawing.Drawing2D.ColorBlend(3)
    $blend.Colors = @($c1, $c2, $c3)
    $blend.Positions = @(0.0, 0.45, 1.0)
    $lg.InterpolationColors = $blend
    $g.FillPath($lg, $path)

    $white = [System.Drawing.Brushes]::White

    # 底部一道暗角, 让方块有厚度而不是平涂。
    # 注意 ColorBlend 的 Positions 要显式转成 float[], 否则 InterpolationColors
    # 会抛 "Parameter is not valid" (PowerShell 默认给的是 double[])。
    $blend2 = New-Object System.Drawing.Drawing2D.ColorBlend(2)
    $blend2.Colors = @([System.Drawing.Color]::FromArgb(0, 0, 0, 0),
                       [System.Drawing.Color]::FromArgb(80, 0, 0, 0))
    $blend2.Positions = [single[]]@(0.55, 1.0)
    $shade = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rect, [System.Drawing.Color]::FromArgb(0, 0, 0, 0),
        [System.Drawing.Color]::FromArgb(80, 0, 0, 0),
        [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
    $shade.InterpolationColors = $blend2
    $g.FillPath($shade, $path)

    # ---- 主体: 花体大写 R ----
    # **字号单位陷阱**: GDI+ 的 Font 用**磅**, 画布是**像素**。直接按像素给字号会大出
    # 4/3 倍, 256px 画布上会被当成 200pt (约 267px) 整个溢出。换算: pt = px * 72 / 96。
    #
    # **居中陷阱**: Gabriola 这类花体的**行高远大于字形本身**, 用 DrawString +
    # LineAlignment=Center 居中的结果会明显偏上 (实测: R 顶到画布外被裁掉)。
    # 所以改成先用 GraphicsPath 取出**真实字形边界**, 再缩放到目标高度、按边界居中。
    $fontPt = [single]($S * 0.9 * 72.0 / 96.0)
    $font = Resolve-DisplayFont $fontPt ([System.Drawing.FontStyle]::Bold)

    $glyph = New-Object System.Drawing.Drawing2D.GraphicsPath
    $glyph.AddString('R', $font.FontFamily, [int]$font.Style, $font.SizeInPoints,
                     (New-Object System.Drawing.PointF(0, 0)),
                     [System.Drawing.StringFormat]::GenericTypographic)
    $fb = $glyph.GetBounds()

    # 缩放到画布高度的 54%, 再按缩放后的边界居中。
    # 手写体的 R 横向很宽, 给到 0.62 就会和左侧划痕叠在一起 (实测)。
    $targetH = [single]($S * 0.54)
    $scale = [single]($targetH / $fb.Height)
    $m1 = New-Object System.Drawing.Drawing2D.Matrix
    $m1.Scale($scale, $scale)
    $glyph.Transform($m1)
    $fb2 = $glyph.GetBounds()
    # R 居中后往右让一点, 给左侧划痕腾出干净的呼吸区
    $m2 = New-Object System.Drawing.Drawing2D.Matrix
    $m2.Translate([single](($S - $fb2.Width) / 2 - $fb2.X + $S * 0.07),
                  [single](($S - $fb2.Height) / 2 - $fb2.Y))
    $glyph.Transform($m2)

    # 描边: 深色 R 偏移一点垫底, 让白字从渐变底上"切"出来
    $shadow = New-Object System.Drawing.SolidBrush(
        [System.Drawing.Color]::FromArgb(165, 8, 20, 45))
    $gm = New-Object System.Drawing.Drawing2D.Matrix
    $off = [single]([Math]::Max(0.7, $S * 0.016))
    $gm.Translate($off, $off)
    $glyphShadow = $glyph.Clone()
    $glyphShadow.Transform($gm)
    $g.FillPath($shadow, $glyphShadow)
    $g.FillPath($white, $glyph)

    $gm.Dispose(); $m1.Dispose(); $m2.Dispose()
    $glyphShadow.Dispose(); $glyph.Dispose(); $shadow.Dispose(); $font.Dispose()

    # ---- 三道斜划痕: 攻击性 + 小尺寸下的视觉重量 ----
    if ($S -ge 32) {
        $pen = New-Object System.Drawing.Pen(
            [System.Drawing.Color]::FromArgb(220, 255, 255, 255), [float]($S * 0.045))
        $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $lines = @(
            @(0.06, 0.22, 0.19, 0.36),
            @(0.04, 0.47, 0.16, 0.59),
            @(0.08, 0.72, 0.17, 0.81)
        )
        foreach ($ln in $lines) {
            $g.DrawLine($pen,
                [float]($S * $ln[0]), [float]($S * $ln[1]),
                [float]($S * $ln[2]), [float]($S * $ln[3]))
        }
        $pen.Dispose()
    }

    $lg.Dispose(); $shade.Dispose(); $path.Dispose(); $g.Dispose()
    return $bmp
}

# 逐个尺寸渲染成 PNG 字节
$pngs = @()
foreach ($s in $sizes) {
    $bmp = New-IconBitmap $s
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs += , @{ Size = $s; Bytes = $ms.ToArray() }
    $ms.Dispose(); $bmp.Dispose()
}

# 打包成 ICO (ICONDIR + ICONDIRENTRY*n + PNG 数据; PNG 压缩 Vista+ 支持)
$fs = [System.IO.File]::Create($Out)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([UInt16]0)              # reserved
$bw.Write([UInt16]1)              # type = icon
$bw.Write([UInt16]$pngs.Count)    # image count

$offset = 6 + 16 * $pngs.Count
foreach ($p in $pngs) {
    $s = $p.Size
    $bw.Write([Byte]$(if ($s -ge 256) { 0 } else { $s }))   # width  (0 = 256)
    $bw.Write([Byte]$(if ($s -ge 256) { 0 } else { $s }))   # height
    $bw.Write([Byte]0)            # palette
    $bw.Write([Byte]0)            # reserved
    $bw.Write([UInt16]1)          # color planes
    $bw.Write([UInt16]32)         # bits per pixel
    $bw.Write([UInt32]$p.Bytes.Length)
    $bw.Write([UInt32]$offset)
    $offset += $p.Bytes.Length
}
foreach ($p in $pngs) { $bw.Write($p.Bytes) }
$bw.Flush(); $bw.Dispose(); $fs.Dispose()

$fi = Get-Item $Out
"[+] $($fi.FullName)  $($fi.Length) 字节 / $($pngs.Count) 个尺寸: $($sizes -join ', ')"
