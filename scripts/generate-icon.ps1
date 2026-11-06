$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$iconDirectory = Join-Path (Split-Path $PSScriptRoot) 'apps\desktop\src-tauri\icons'
New-Item -ItemType Directory -Force -Path $iconDirectory | Out-Null
$bitmap = [System.Drawing.Bitmap]::new(256, 256, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::Transparent)
$brush = [System.Drawing.SolidBrush]::new([System.Drawing.ColorTranslator]::FromHtml('#008a78'))
$shape = [System.Drawing.Drawing2D.GraphicsPath]::new()
foreach ($corner in @(@(0,0,180),@(192,0,270),@(192,192,0),@(0,192,90))) { $shape.AddArc($corner[0],$corner[1],64,64,$corner[2],90) }
$shape.CloseFigure()
$graphics.FillPath($brush,$shape)
$pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White,17)
$pen.StartCap = $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
# Monoline ghost matching apps/desktop/ui/mark.svg (40-unit grid scaled by 6.4).
function Point([single]$x, [single]$y) { [System.Drawing.PointF]::new($x, $y) }
$ghost = [System.Drawing.Drawing2D.GraphicsPath]::new()
$ghost.AddLine((Point 76.8 188.8), (Point 76.8 121.6))
$ghost.AddArc([single]76.8, [single]70.4, [single]102.4, [single]102.4, [single]180, [single]180)
$ghost.AddLines([System.Drawing.PointF[]]@((Point 179.2 121.6), (Point 179.2 188.8), (Point 162.1 176), (Point 145.1 188.8), (Point 128 176), (Point 110.9 188.8), (Point 93.9 176)))
$ghost.CloseFigure()
$graphics.DrawPath($pen,$ghost)
$eyes = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
$graphics.FillEllipse($eyes,[single]98.56,[single]114.56,[single]20.48,[single]20.48)
$graphics.FillEllipse($eyes,[single]136.96,[single]114.56,[single]20.48,[single]20.48)
$png = Join-Path $iconDirectory 'icon.png'
$bitmap.Save($png,[System.Drawing.Imaging.ImageFormat]::Png)
$bytes = [IO.File]::ReadAllBytes($png)
$writer = [IO.BinaryWriter]::new([IO.File]::Create((Join-Path $iconDirectory 'icon.ico')))
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]1)
    $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$bytes.Length); $writer.Write([uint32]22); $writer.Write($bytes)
} finally { $writer.Dispose(); $graphics.Dispose(); $bitmap.Dispose(); $brush.Dispose(); $pen.Dispose(); $shape.Dispose(); $ghost.Dispose(); $eyes.Dispose() }
