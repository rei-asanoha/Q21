# Construit le binaire de livraison de facon reproductible, sous Windows.
#
# Equivalent PowerShell de `construire-reproductible.sh`. Voir ce fichier et
# REPRODUIRE.md pour le pourquoi ; en deux phrases : sans le remappage,
# `cargo build --release` inscrit dans le binaire le chemin absolu des
# sources vendorisees, donc deux personnes qui compilent le meme commit dans
# deux repertoires differents obtiennent deux binaires differents. Le
# condensat publie ne prouve alors plus rien.
#
# # Emploi
#
#   powershell -ExecutionPolicy Bypass -File outils\construire-reproductible.ps1
#
# Si PowerShell refuse d'executer le fichier, c'est la politique d'execution
# de Windows, pas une erreur du script : le drapeau `-ExecutionPolicy Bypass`
# ci-dessus la contourne pour cette seule execution.

$ErrorActionPreference = 'Stop'

# La racine du projet : le repertoire parent de celui qui contient ce script.
$Racine = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Racine

# Le nom d'arrivee, `/q21`, doit etre le meme sur toutes les plateformes :
# c'est lui qui finit dans le binaire. Windows donne des chemins a
# contre-oblique (`C:\Users\...`) ; rustc les recoit tels quels, et c'est
# donc la forme a remapper.
$Drapeaux = "--remap-path-prefix=$Racine=/q21"

if ($env:RUSTFLAGS) {
  Write-Error @"
RUSTFLAGS est deja defini dans l'environnement :
  $($env:RUSTFLAGS)
Il remplacerait les drapeaux de reproductibilite — cargo prend l'un OU
l'autre, il ne les cumule pas. Videz-le :
  Remove-Item Env:\RUSTFLAGS
"@
  exit 1
}

Write-Host "Racine du projet : $Racine"
Write-Host "Remappage        : $Racine -> /q21"
Write-Host "Chaine d'outils  : $(rustc --version)"
Write-Host ""

$env:RUSTFLAGS = $Drapeaux
try {
  cargo build --locked --release
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
  Remove-Item Env:\RUSTFLAGS
}

$Binaire = Join-Path $Racine 'target\release\q21.exe'
Write-Host ""
Write-Host "Binaire : $Binaire"
(Get-FileHash -Algorithm SHA256 $Binaire).Hash.ToLower() + "  q21.exe"
