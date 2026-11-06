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
$pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White,18)
$pen.StartCap = $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
$points = [System.Drawing.PointF[]]@([System.Drawing.PointF]::new(64,173),[System.Drawing.PointF]::new(64,83),[System.Drawing.PointF]::new(128,147),[System.Drawing.PointF]::new(192,83),[System.Drawing.PointF]::new(192,173))
$graphics.DrawLines($pen,$points)
$png = Join-Path $iconDirectory 'icon.png'
$bitmap.Save($png,[System.Drawing.Imaging.ImageFormat]::Png)
$bytes = [IO.File]::ReadAllBytes($png)
$writer = [IO.BinaryWriter]::new([IO.File]::Create((Join-Path $iconDirectory 'icon.ico')))
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]1)
    $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$bytes.Length); $writer.Write([uint32]22); $writer.Write($bytes)
} finally { $writer.Dispose(); $graphics.Dispose(); $bitmap.Dispose(); $brush.Dispose(); $pen.Dispose(); $shape.Dispose() }
