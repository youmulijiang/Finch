# Finch one-key build script (PowerShell).
#
# Usage:
#   .\build\build.ps1                # build for the current platform
#   .\build\build.ps1 windows        # x86_64-pc-windows-msvc
#   .\build\build.ps1 linux          # x86_64-unknown-linux-gnu
#   .\build\build.ps1 macos          # aarch64-apple-darwin (Apple Silicon)
#   .\build\build.ps1 macos-intel    # x86_64-apple-darwin
#   .\build\build.ps1 all            # every supported target
#   .\build\build.ps1 -h             # print help
#
# The output binary is copied to <repo>\bin\finch-<target>.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Platform = "current",
    [switch]$h,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

function Print-Help {
    $text = @'
Finch one-key build script.

Usage: .\build\build.ps1 [platform] [-h]

Platforms:
  current      Build for the platform the script runs on (default)
  windows      x86_64-pc-windows-msvc
  linux        x86_64-unknown-linux-gnu
  macos        aarch64-apple-darwin (Apple Silicon)
  macos-intel  x86_64-apple-darwin
  all          Build every supported target

Options:
  -h, -Help    Print this help and exit

Output:
  Binaries are copied to <repo>\bin\finch-<target>.

Cross builds need the corresponding toolchain/linker installed locally;
full multi-platform artifacts are also built by CI on release tags
(.github/workflows/release.yml).
'@
    Write-Host $text
}

if ($h -or $Help) { Print-Help; exit 0 }

$Targets = @{
    "windows"     = "x86_64-pc-windows-msvc"
    "linux"       = "x86_64-unknown-linux-gnu"
    "macos"       = "aarch64-apple-darwin"
    "macos-intel" = "x86_64-apple-darwin"
}

$ValidPlatforms = @("current", "windows", "linux", "macos", "macos-intel", "all")
if ($ValidPlatforms -notcontains $Platform) {
    Write-Host "unknown platform '$Platform' (see -h)" -ForegroundColor Red
    exit 1
}

# Resolve the script/repo root.
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$BuildDir = Join-Path $Root "bin"
New-Item -ItemType Directory -Force $BuildDir | Out-Null

function Get-CurrentTarget {
    if ($IsWindows -or $env:OS -eq "Windows_NT") { return "x86_64-pc-windows-msvc" }
    if ($IsMacOS) { return "aarch64-apple-darwin" }
    return "x86_64-unknown-linux-gnu"
}

function Build-Target {
    param([string]$Target)

    Write-Host "==> Building $Target ..." -ForegroundColor Cyan

    # Install the toolchain if missing.
    $installed = rustup target list --installed 2>$null
    if ($LASTEXITCODE -ne 0 -or -not ($installed -contains $Target)) {
        Write-Host "    installing rustup target $Target"
        rustup target add $Target
        if ($LASTEXITCODE -ne 0) { throw "failed to add target $Target" }
    }

    cargo build --release --locked --target $Target
    if ($LASTEXITCODE -ne 0) { throw "build failed for $Target" }

    $bin = Join-Path $Root "target\$Target\release\finch.exe"
    if (-not (Test-Path $bin)) {
        # Unix targets produce a extension-less binary.
        $bin = Join-Path $Root "target\$Target\release\finch"
    }
    if (-not (Test-Path $bin)) { throw "binary not found for $Target" }

    $dest = Join-Path $BuildDir "finch-$Target"
    Copy-Item $bin $dest -Force
    Write-Host "    -> $dest" -ForegroundColor Green
}

switch ($Platform) {
    "current" { Build-Target (Get-CurrentTarget) }
    "all"     { foreach ($p in $Targets.Keys) { Build-Target $Targets[$p] } }
    default   { Build-Target $Targets[$Platform] }
}

Write-Host ""
Write-Host "Done. Artifacts in $BuildDir" -ForegroundColor Cyan
Get-ChildItem $BuildDir | Format-Table Name, Length -AutoSize
