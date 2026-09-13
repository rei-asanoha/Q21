#!/bin/sh
# Prouve que la compilation est reproductible : deux repertoires, un condensat.
#
# # Ce que le script fait
#
# 1. copie le projet dans deux repertoires temporaires de **longueur et de
#    profondeur differentes** — c'est ce qui revele le probleme, car un chemin
#    inscrit dans un binaire change la taille du binaire ;
# 2. compile dans chacun avec `construire-reproductible.sh` ;
# 3. compare les deux condensats SHA-256.
#
# Si les deux condensats sont egaux, la compilation est reproductible : une
# tierce personne qui recompile ce commit obtiendra le meme fichier, octet
# pour octet, et pourra le comparer au condensat publie. Elle n'a plus a
# croire personne sur parole.
#
# # Emploi
#
#   ./outils/verifier-reproductible.sh
#
# Comptez deux compilations completes. Sur une machine modeste, c'est long ;
# c'est normal, il n'y a aucun cache partage entre les deux (un cache partage
# invaliderait la preuve).
#
# # Ce que le script NE prouve PAS
#
# Il compare deux compilations sur la **meme** machine, avec le meme systeme
# et le meme compilateur. Il elimine la variable « repertoire ». Il ne dit
# rien de la variable « machine » : pour celle-la, il faut que plusieurs
# personnes compilent chacune chez elle et annoncent leur condensat. C'est
# l'objet du depot d'attestations, decrit dans REPRODUIRE.md.

set -eu

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)

BASE=$(mktemp -d)
A="$BASE/a"
B="$BASE/un/chemin/nettement/plus/long/et/plus/profond/b"

nettoyer() { rm -rf "$BASE"; }
trap nettoyer EXIT INT TERM

echo "Repertoire A : $A"
echo "Repertoire B : $B"
echo

mkdir -p "$A" "$B"

# On copie les sources, jamais `target/` : un artefact deja compile dans
# l'ancien repertoire porterait l'ancien chemin et fausserait la mesure.
copier() {
  tar -C "$RACINE" -cf - \
    --exclude=./target --exclude=./.git --exclude=./q21-data --exclude=./w2 \
    . | tar -C "$1" -xf -
}

echo "Copie vers A..."; copier "$A"
echo "Copie vers B..."; copier "$B"
echo

echo "=== Compilation A ==="
( cd "$A" && ./outils/construire-reproductible.sh )
echo
echo "=== Compilation B ==="
( cd "$B" && ./outils/construire-reproductible.sh )
echo

somme() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

SA=$(somme "$A/target/release/q21")
SB=$(somme "$B/target/release/q21")

echo "=== Resultat ==="
echo "A : $SA"
echo "B : $SB"
echo

if [ "$SA" = "$SB" ]; then
  echo "IDENTIQUES — la compilation est reproductible."
  echo
  echo "Condensat de ce commit :"
  echo "  $SA"
  exit 0
else
  echo "DIFFERENTS — la compilation n'est PAS reproductible."
  echo
  echo "Pour voir d'ou vient l'ecart, cherchez les chemins absolus restants :"
  echo "  strings -n 12 \"$A/target/release/q21\" | grep '$A'"
  exit 1
fi
