param([switch]$SkipCompile)
$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot
Set-Location -LiteralPath $repository
function Assert-Success([string]$Step) { if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)" } }
if (-not $SkipCompile) {
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    & "$PSScriptRoot\cargo.ps1" build --release --locked --workspace
    Assert-Success 'Rust release build'
    & "$PSScriptRoot\cargo.ps1" build --release --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
    Assert-Success 'Desktop release build'
    Push-Location core/outline-worker
    try { & go build -mod=readonly -trimpath -buildvcs=false -tags with_gvisor -ldflags '-s -w' -o '..\..\target\release\myvpn-tunnel.exe' .; Assert-Success 'Managed tunnel worker build' }
    finally { Pop-Location }
}
$stage = Join-Path $repository 'artifacts\windows-x64\MyVPN'
New-Item -ItemType Directory -Force -Path $stage,(Join-Path $stage 'engine'),(Join-Path $stage 'licenses') | Out-Null
foreach ($name in @('myvpn.exe','myvpnd.exe','myvpn-mcp.exe')) { Copy-Item -LiteralPath (Join-Path $repository "target\release\$name") -Destination (Join-Path $stage $name) }
Copy-Item -LiteralPath (Join-Path $repository 'target\release\myvpn-tunnel.exe') -Destination (Join-Path $stage 'engine\myvpn-tunnel.exe')
Copy-Item -LiteralPath (Join-Path $repository 'apps\desktop\src-tauri\target\release\myvpn-desktop.exe') -Destination (Join-Path $stage 'myvpn-desktop.exe')
Copy-Item -LiteralPath (Join-Path $repository 'LICENSE'),(Join-Path $repository 'NOTICE.md') -Destination (Join-Path $stage 'licenses')
Copy-Item -Path (Join-Path $repository 'LICENSES\*') -Destination (Join-Path $stage 'licenses') -Recurse -Force
$wixDirectory = Join-Path $repository '.tools\wix314'
if (-not (Test-Path -LiteralPath (Join-Path $wixDirectory 'candle.exe'))) { throw 'Run scripts/bootstrap-windows.ps1 to obtain the pinned WiX tools.' }
$harvest = Join-Path $repository 'artifacts\windows-x64\licenses.wxs'
& (Join-Path $wixDirectory 'heat.exe') dir (Join-Path $stage 'licenses') -cg LicenseFiles -dr LicensesFolder -ag -sfrag -srd -var var.Licenses -out $harvest
Assert-Success 'License harvest'
$objectDirectory = Join-Path $repository 'artifacts\windows-x64\wix'
New-Item -ItemType Directory -Force -Path $objectDirectory | Out-Null
& (Join-Path $wixDirectory 'candle.exe') -nologo -arch x64 "-dStage=$stage" "-dRoot=$repository" "-dLicenses=$(Join-Path $stage 'licenses')" -out ($objectDirectory + '\') (Join-Path $repository 'packages\windows\MyVPN.wxs') $harvest
Assert-Success 'Installer compilation'
$installer = Join-Path $repository 'artifacts\windows-x64\MyVPN-0.1.0-windows-x64.msi'
& (Join-Path $wixDirectory 'light.exe') -nologo -out $installer (Join-Path $objectDirectory 'MyVPN.wixobj') (Join-Path $objectDirectory 'licenses.wixobj')
Assert-Success 'Installer linking and validation'
Compress-Archive -Path $stage -DestinationPath (Join-Path $repository 'artifacts\windows-x64\MyVPN-0.1.0-windows-x64-portable.zip') -Force
Get-FileHash -LiteralPath $installer -Algorithm SHA256 | Format-List
Write-Output 'Installer compiled. Installation/elevation and real TUN routing still require an authorized Windows test.'
