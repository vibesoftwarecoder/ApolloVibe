<#
.SYNOPSIS
    Assemble the ApolloVibe portable release zip from the build/ directory.

.DESCRIPTION
    Produces apollovibe-v<Version>-windows-x64.zip containing the COMPLETE portable
    Apollo layout: sunshine.exe + assets/ + tools/ (CMake artifacts excluded).

    Background: build_apollovibe.bat only compiles sunshine.exe. The portable zip was
    historically assembled by hand, and releases v2026.5.15-multiseat.1 and
    v2026.6.1-multiseat.1 accidentally shipped sunshine.exe ONLY (missing assets/apps.json
    plus shaders and the web UI), which makes Apollo exit at startup on clean installs
    (GitHub issue #5). This script guards against that: it HARD-FAILS if the staged assets
    are missing, so an exe-only zip can never be produced again.

.PARAMETER Version
    Version string without the leading 'v', e.g. 2026.6.1-multiseat.1

.EXAMPLE
    .\package_apollovibe.ps1 -Version 2026.6.1-multiseat.1
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root  = $PSScriptRoot
$build = Join-Path $root 'build'
$out   = Join-Path $root "apollovibe-v$Version-windows-x64.zip"
$stage = Join-Path $root '_repackage\stage'

function Fail($msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# Guard: every required portable component must be staged in build/.
# These are the files whose absence produced the broken releases. If the build tree
# is incomplete (e.g. only `ninja sunshine` ran without the asset/web targets), stop
# here rather than ship an incomplete zip.
$required = @(
    'sunshine.exe',
    'assets\apps.json',
    'assets\web\index.html',
    'tools\sunshinesvc.exe'
)
foreach ($rel in $required) {
    if (-not (Test-Path (Join-Path $build $rel))) {
        Fail "Required file missing from build/: $rel. The build tree is incomplete; reconfigure and build the asset/web targets before packaging."
    }
}

# Stage a clean portable layout.
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Copy-Item (Join-Path $build 'sunshine.exe') $stage
Copy-Item (Join-Path $build 'assets') (Join-Path $stage 'assets') -Recurse
Copy-Item (Join-Path $build 'tools')  (Join-Path $stage 'tools')  -Recurse

# Drop CMake build artifacts that do not belong in a release.
Remove-Item (Join-Path $stage 'tools\CMakeFiles') -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem (Join-Path $stage 'tools') -Filter *.cmake -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue

# Zip.
if (Test-Path $out) { Remove-Item $out -Force }
Compress-Archive -Path (Join-Path $stage 'sunshine.exe'), (Join-Path $stage 'assets'), (Join-Path $stage 'tools') -DestinationPath $out -CompressionLevel Optimal

# Verify the produced zip actually contains the seed asset.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($out)
try {
    $hasApps = $zip.Entries | Where-Object { $_.FullName -eq 'assets/apps.json' }
    $count   = $zip.Entries.Count
} finally {
    $zip.Dispose()
}
if (-not $hasApps) {
    Fail "Produced zip is missing assets/apps.json - packaging failed."
}

$mb = [math]::Round((Get-Item $out).Length / 1MB, 1)
Write-Host "OK: apollovibe-v$Version-windows-x64.zip - $count entries, $mb MB" -ForegroundColor Green
Write-Host "    $out"
