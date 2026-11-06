param([string]$Version)
$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot
if (-not $Version) {
    # Same authoritative version and consistency check as the release workflow.
    $Version = (& node (Join-Path $PSScriptRoot 'release-version.mjs')).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $Version) { throw 'Version declarations disagree; run node scripts/release-version.mjs' }
}
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $repository 'artifacts\source'))
$sourceDirectory = [IO.Path]::GetFullPath((Join-Path $artifactRoot "ghostlink-outline-worker-$Version"))
if (-not $sourceDirectory.StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Source staging escaped the artifact directory' }
if (Test-Path -LiteralPath $sourceDirectory) {
    $existing = Get-Item -LiteralPath $sourceDirectory -Force
    if ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to clear a linked source staging directory' }
    Remove-Item -LiteralPath $sourceDirectory -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $sourceDirectory | Out-Null
Copy-Item -Path (Join-Path $repository 'core\outline-worker\*.go') -Destination $sourceDirectory
foreach ($file in @('go.mod','go.sum','README.md')) { Copy-Item -LiteralPath (Join-Path $repository "core\outline-worker\$file") -Destination $sourceDirectory }
Copy-Item -LiteralPath (Join-Path $repository 'LICENSES\GPL-3.0.txt') -Destination (Join-Path $sourceDirectory 'COPYING')
Copy-Item -LiteralPath (Join-Path $repository 'NOTICE.md'),(Join-Path $repository 'LICENSES\sing-box.txt'),(Join-Path $repository 'LICENSES\Wintun-0.14.1.txt') -Destination $sourceDirectory
Push-Location (Join-Path $repository 'core\outline-worker')
try {
    & go mod vendor -o (Join-Path $sourceDirectory 'vendor')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency source vendoring failed' }
} finally { Pop-Location }
$instructions = @"
Ghostlink outline worker $Version corresponding source

Build toolchain: Go 1.26.10 (pinned in go.mod).
Windows x64: CGO_ENABLED=0 GOOS=windows GOARCH=amd64
  go build -mod=vendor -trimpath -buildvcs=false -tags with_gvisor -ldflags "-s -w" -o ghostlink-tunnel.exe .
Linux x64: CGO_ENABLED=0 GOOS=linux GOARCH=amd64
  go build -mod=vendor -trimpath -buildvcs=false -tags with_gvisor -ldflags "-s -w" -o ghostlink-tunnel .
Linux arm64: CGO_ENABLED=0 GOOS=linux GOARCH=arm64
  go build -mod=vendor -trimpath -buildvcs=false -tags with_gvisor -ldflags "-s -w" -o ghostlink-tunnel .

Set those variables using your shell's environment syntax. The vendor directory contains
the actual engine/dependency source used by this worker and required embedded resources.
Unmodified Wintun DLL bytes retain the separate prebuilt license in Wintun-0.14.1.txt.
Do not remove upstream notices. Protocol and cryptographic implementations are upstream.
Runtime command: ghostlink-tunnel run -c PRIVATE_CONFIG.json
The parent must keep stdin open; EOF or a stop message triggers graceful Close().
"@
[IO.File]::WriteAllText((Join-Path $sourceDirectory 'BUILD.txt'),$instructions)
$archive = Join-Path $artifactRoot "Ghostlink-$Version-worker-corresponding-source.zip"
Compress-Archive -LiteralPath $sourceDirectory -DestinationPath $archive -Force
Get-FileHash -LiteralPath $archive -Algorithm SHA256 | Format-List
