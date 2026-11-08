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
# Only files under version control go into the public archive: a local checkout can also hold
# ignored files (keys, .env files, local builds) that must never be published.
$tracked = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($path in (& git -C $repository ls-files core/outline-worker ui)) { [void]$tracked.Add($path) }
if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) { throw 'git ls-files listed no source files; build the source bundle from a Git checkout' }
$repositoryRoot = [IO.Path]::GetFullPath($repository).TrimEnd('\', '/')
function Test-Tracked($File) { $tracked.Contains($File.FullName.Substring($repositoryRoot.Length + 1).Replace('\', '/')) }
# The whole Go module: the worker, the server command, every internal package (with tests) and
# embedded files such as the dashboard's web pages. Only vendored copies and built binaries
# are left out; the build check below proves nothing needed is missing.
$moduleRoot = [IO.Path]::GetFullPath((Join-Path $repository 'core\outline-worker'))
$moduleFiles = Get-ChildItem -LiteralPath $moduleRoot -Recurse -File | Where-Object {
    $relative = $_.FullName.Substring($moduleRoot.Length + 1)
    (Test-Tracked $_) -and -not $relative.StartsWith('vendor' + [IO.Path]::DirectorySeparatorChar) -and
        ($_.Extension -notin '.exe', '.dll', '.so', '.test', '.out')
}
foreach ($file in $moduleFiles) {
    $relative = $file.FullName.Substring($moduleRoot.Length + 1)
    $target = Join-Path $sourceDirectory $relative
    New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $target
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceDirectory 'internal\awg\endpoint.go'))) { throw 'internal packages are missing from the source bundle' }
# The source of the embedded dashboard (internal/server/dashboard is its build): the web UI in
# React/TypeScript, without installed packages (package-lock.json pins them).
$uiRoot = [IO.Path]::GetFullPath((Join-Path $repository 'ui'))
$uiFiles = Get-ChildItem -LiteralPath $uiRoot -Recurse -File | Where-Object { (Test-Tracked $_) -and $_.FullName.Substring($uiRoot.Length + 1) -notmatch '^node_modules[\\/]' }
foreach ($file in $uiFiles) {
    $target = Join-Path (Join-Path $sourceDirectory 'web-ui') $file.FullName.Substring($uiRoot.Length + 1)
    New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $target
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceDirectory 'web-ui\package-lock.json'))) { throw 'the web UI source is missing from the source bundle' }
Copy-Item -LiteralPath (Join-Path $repository 'LICENSES\GPL-3.0.txt') -Destination (Join-Path $sourceDirectory 'COPYING')
Copy-Item -LiteralPath (Join-Path $repository 'NOTICE.md'),(Join-Path $repository 'LICENSES\sing-box.txt'),(Join-Path $repository 'LICENSES\Wintun-0.14.1.txt') -Destination $sourceDirectory
Push-Location (Join-Path $repository 'core\outline-worker')
try {
    & go mod vendor -o (Join-Path $sourceDirectory 'vendor')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency source vendoring failed' }
} finally { Pop-Location }
# Prove the bundle is complete: build every command from the staged copy alone.
$verifyDirectory = Join-Path ([IO.Path]::GetTempPath()) ("ghostlink-source-check-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $verifyDirectory | Out-Null
Push-Location $sourceDirectory
$previousGoFlags = $env:GOFLAGS
try {
    $env:GOFLAGS = '-mod=vendor'
    & go build -trimpath -buildvcs=false -tags with_gvisor,with_utls,with_wireguard -o ($verifyDirectory + [IO.Path]::DirectorySeparatorChar) ./...
    if ($LASTEXITCODE -ne 0) { throw 'The staged corresponding source does not build' }
} finally {
    $env:GOFLAGS = $previousGoFlags
    Pop-Location
    Remove-Item -LiteralPath $verifyDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
$instructions = @"
Ghostlink $Version corresponding source: tunnel worker (ghostlink-tunnel), server (ghostlink-server),
IPsec agent (ghostlink-ipsec-agent) and mesh agent (ghostlink-mesh)

Build toolchain: Go 1.26.10 (pinned in go.mod).
Windows x64: CGO_ENABLED=0 GOOS=windows GOARCH=amd64
  go build -mod=vendor -trimpath -buildvcs=false -tags with_gvisor,with_utls,with_wireguard -ldflags "-s -w" -o ghostlink-tunnel.exe .
Linux x64: CGO_ENABLED=0 GOOS=linux GOARCH=amd64
  go build -mod=vendor -trimpath -buildvcs=false -tags with_gvisor,with_utls,with_wireguard -ldflags "-s -w" -o ghostlink-tunnel .
Linux arm64: CGO_ENABLED=0 GOOS=linux GOARCH=arm64
  go build -mod=vendor -trimpath -buildvcs=false -tags with_gvisor,with_utls,with_wireguard -ldflags "-s -w" -o ghostlink-tunnel .
Server (Linux x64/arm64, as above with the matching GOARCH):
  go build -mod=vendor -trimpath -buildvcs=false -tags with_gvisor,with_utls,with_wireguard -ldflags "-s -w" -o ghostlink-server ./cmd/ghostlink-server
  The server image adds this binary and its notices to gcr.io/distroless/static-debian12:nonroot
  (see packages/linux/server/Dockerfile in the Ghostlink repository).
IPsec agent (Linux x64/arm64):
  go build -mod=vendor -trimpath -buildvcs=false -ldflags "-s -w" -o ghostlink-ipsec-agent ./cmd/ghostlink-ipsec-agent
  The IPsec image adds it to files from Alpine Linux 3.24 (packages/linux/server/ipsec.Dockerfile);
  their source is the separate Ghostlink-$Version-ipsec-component-source-<arch>.tar.gz.
Mesh agent (Linux x64/arm64; the ghostlink-mesh .deb/.rpm):
  go build -mod=vendor -trimpath -buildvcs=false -ldflags "-s -w" -o ghostlink-mesh ./cmd/ghostlink-mesh
Server dashboard: the web pages in internal/server/dashboard (embedded in ghostlink-server) are
built from web-ui/ (React, TypeScript, Tailwind CSS) with Node.js 22:
  cd web-ui
  npm ci --ignore-scripts
  npx tsc --noEmit -p tsconfig.json
  npx vite build --config vite.dashboard.config.ts --outDir ../../internal/server/dashboard

Set those variables using your shell's environment syntax. The vendor directory contains
the actual engine/dependency source used by this worker and required embedded resources.
Unmodified Wintun DLL bytes retain the separate prebuilt license in Wintun-0.14.1.txt.
Do not remove upstream notices. Protocol and cryptographic implementations are upstream.
Runtime command: ghostlink-tunnel run -c PRIVATE_CONFIG.json
The parent must keep stdin open; EOF or a stop message triggers graceful Close().
"@
[IO.File]::WriteAllText((Join-Path $sourceDirectory 'BUILD.txt'),$instructions)
$archive = Join-Path $artifactRoot "Ghostlink-$Version-worker-corresponding-source.zip"
# Entry names use "/" so the archive unpacks cleanly everywhere (Windows PowerShell's
# Compress-Archive and ZipFile.CreateFromDirectory write backslashes).
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$archiveBase = Split-Path $sourceDirectory
$zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $sourceDirectory -Recurse -File -Force) {
        $entryName = $file.FullName.Substring($archiveBase.Length + 1).Replace('\', '/')
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName, [IO.Compression.CompressionLevel]::Optimal)
    }
} finally { $zip.Dispose() }
Get-FileHash -LiteralPath $archive -Algorithm SHA256 | Format-List
