# Builds the release binary reproducibly, on Windows.
#
# PowerShell equivalent of `build-reproducible.sh`. See that file and
# REPRODUCING.md for the reasons; in two sentences: without the remapping,
# `cargo build --release` writes into the binary the absolute path of the
# vendored sources, so two people who compile the same commit in two
# different directories get two different binaries. The published hash then
# proves nothing anymore.
#
# # Usage
#
#   powershell -ExecutionPolicy Bypass -File tools\build-reproducible.ps1
#
# If PowerShell refuses to run the file, that is the Windows execution
# policy, not an error in the script: the `-ExecutionPolicy Bypass` flag
# above bypasses it for this one run.

$ErrorActionPreference = 'Stop'

# The project root: the parent of the directory that contains this script.
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root

# The destination name, `/q21`, must be the same on every platform: it is
# what ends up in the binary. Windows gives backslash paths (`C:\Users\...`);
# rustc receives them as they are, so that is the form to remap.
$Flags = "--remap-path-prefix=$Root=/q21"

if ($env:RUSTFLAGS) {
  Write-Error @"
RUSTFLAGS is already set in the environment:
  $($env:RUSTFLAGS)
It would replace the reproducibility flags: cargo takes one OR the other,
it does not combine them. Clear it:
  Remove-Item Env:\RUSTFLAGS
"@
  exit 1
}

Write-Host "Project root: $Root"
Write-Host "Remapping:    $Root -> /q21"
Write-Host "Toolchain:    $(rustc --version)"
Write-Host ""

$env:RUSTFLAGS = $Flags
try {
  cargo build --locked --release
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
  Remove-Item Env:\RUSTFLAGS
}

$Binary = Join-Path $Root 'target\release\q21.exe'
Write-Host ""
Write-Host "Binary: $Binary"
(Get-FileHash -Algorithm SHA256 $Binary).Hash.ToLower() + "  q21.exe"
