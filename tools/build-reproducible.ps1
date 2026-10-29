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
# Both forms of the directory, as the release passes them: rustc may see
# backslashes or forward slashes, and a form that matches nothing costs nothing.
$RootSlash = $Root -replace '\\', '/'
# Passed as CARGO_ENCODED_RUSTFLAGS, one flag per field: a folder name with a
# space in it (`C:\Users\First Last\...`) would split RUSTFLAGS in two.
$Flags = "--remap-path-prefix=$Root=/q21" + [char]0x1f + "--remap-path-prefix=$RootSlash=/q21"
# The target is always explicit, as in the release (`--target`).
$Target = ((rustc -vV) | Select-String '^host: ').ToString().Substring(6).Trim()
# The release ships the MSVC build: a GNU toolchain would build a binary the
# release never publishes, with nothing to compare it to.
if ($Target -eq 'x86_64-pc-windows-gnu') { $Target = 'x86_64-pc-windows-msvc' }

if ($env:RUSTFLAGS -or $env:CARGO_ENCODED_RUSTFLAGS) {
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
Write-Host "Target:       $Target"
Write-Host ""

$env:CARGO_ENCODED_RUSTFLAGS = $Flags
try {
  cargo build --locked --release --features mldsa --target $Target
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
  Remove-Item Env:\CARGO_ENCODED_RUSTFLAGS
}

$Binary = Join-Path $Root "target\$Target\release\q21.exe"
Write-Host ""
Write-Host "Binary: $Binary"
(Get-FileHash -Algorithm SHA256 $Binary).Hash.ToLower() + "  q21.exe"

# The same hashes, under the names the release and the attestations use
# (attestations/README.md), ready to copy into an attestation.
if ($Target -eq 'x86_64-pc-windows-msvc') {
  $Launcher = Join-Path $Root "target\$Target\release\q21-wallet.exe"
  Write-Host ""
  Write-Host "For an attestation (attestations/README.md):"
  (Get-FileHash -Algorithm SHA256 $Binary).Hash.ToLower() + "  q21-windows-x86_64"
  (Get-FileHash -Algorithm SHA256 $Launcher).Hash.ToLower() + "  q21-wallet-windows-x86_64"
}
