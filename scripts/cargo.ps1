$CargoArgs = $args
$ErrorActionPreference = 'Stop'
if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    # Probe cl.exe rather than link.exe: Git for Windows ships an unrelated coreutils link.exe
    # on PATH, which would otherwise skip MSVC setup and break every Rust link step.
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $vswhere)) {
        $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installation) {
            $localSdk = Join-Path (Split-Path $PSScriptRoot) '.tools\winsdk\c'
            if (Test-Path -LiteralPath (Join-Path $localSdk 'um\x64\kernel32.lib')) {
                $toolVersion = (Get-Content -LiteralPath (Join-Path $installation 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt') -Raw).Trim()
                $toolRoot = Join-Path $installation "VC\Tools\MSVC\$toolVersion"
                $env:PATH = (Join-Path $toolRoot 'bin\Hostx64\x64') + ';' + $env:PATH
                $env:LIB = (Join-Path $toolRoot 'lib\x64') + ';' + (Join-Path $localSdk 'um\x64') + ';' + (Join-Path $localSdk 'ucrt\x64')
                $sdkTools = Join-Path (Split-Path $PSScriptRoot) '.tools\winsdk-tools\c'
                $resourceCompiler = Get-ChildItem -LiteralPath $sdkTools -Recurse -Filter rc.exe -ErrorAction SilentlyContinue | Where-Object FullName -match '\\x64\\' | Select-Object -First 1
                if ($resourceCompiler) { $env:PATH = $resourceCompiler.DirectoryName + ';' + $env:PATH }
                $includeVersion = Get-ChildItem -LiteralPath (Join-Path $sdkTools 'Include') -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                if ($includeVersion) {
                    $env:INCLUDE = (Join-Path $toolRoot 'include') + ';' + (Join-Path $includeVersion.FullName 'ucrt') + ';' + (Join-Path $includeVersion.FullName 'shared') + ';' + (Join-Path $includeVersion.FullName 'um') + ';' + (Join-Path $includeVersion.FullName 'winrt')
                }
            } else {
            $developerShell = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
            $developerEnvironment = & $env:ComSpec /d /c "call `"$developerShell`" -no_logo -arch=x64 >nul && set"
            foreach ($entry in $developerEnvironment) {
                $position = $entry.IndexOf('=')
                if ($position -gt 0) { [Environment]::SetEnvironmentVariable($entry.Substring(0, $position), $entry.Substring($position + 1), 'Process') }
            }
            }
        }
    }
}
& cargo @CargoArgs
exit $LASTEXITCODE
