param([switch]$IncludeSdk)
$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot
$toolDirectory = Join-Path $repository '.tools'
New-Item -ItemType Directory -Force -Path $toolDirectory | Out-Null
function Get-VerifiedArchive([string]$Url, [string]$Name, [string]$Hash, [string]$Directory) {
    $archive = Join-Path $toolDirectory $Name
    if (-not (Test-Path -LiteralPath $archive)) { Invoke-WebRequest -Uri $Url -OutFile $archive }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $Hash) { throw "Checksum mismatch: $Name" }
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    Expand-Archive -LiteralPath $archive -DestinationPath $Directory -Force
}
Get-VerifiedArchive 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip' 'wix314.zip' '6AC824E1642D6F7277D0ED7EA09411A508F6116BA6FAE0AA5F2C7DAA2FF43D31' (Join-Path $toolDirectory 'wix314')
if ($IncludeSdk) {
    Get-VerifiedArchive 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x64/10.0.28000.2957/microsoft.windows.sdk.cpp.x64.10.0.28000.2957.nupkg' 'winsdk-x64.zip' '7CA47E7345DCBDF36EC4C3C4CD59AB9CB5C9F620A2E785CC4FA641509647CC5A' (Join-Path $toolDirectory 'winsdk')
    Get-VerifiedArchive 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/10.0.28000.2957/microsoft.windows.sdk.cpp.10.0.28000.2957.nupkg' 'winsdk-tools.zip' 'F0A200DAE58858F418B30DC9E2F52B4188F97EB7837BD4F73074652A01937DDD' (Join-Path $toolDirectory 'winsdk-tools')
}
Write-Output 'Pinned build dependencies verified and extracted locally. No drivers or system services were installed.'
