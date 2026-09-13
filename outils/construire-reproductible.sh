#!/bin/sh
# Construit le binaire de livraison de facon reproductible.
#
# # Le probleme que ce script resout
#
# `cargo build --release` inscrit dans le binaire le chemin absolu des fichiers
# source des dependances vendorisees, pour que les messages de panique disent
# ou le probleme a eu lieu. Mesure sur un binaire construit sans ce script :
#
#   /home/vous/q21/vendor/ml-dsa/src/signing.rs
#   /home/vous/q21/vendor/ml-dsa/src/sampling.rs
#   ... neuf chemins en tout
#
# Consequence : deux personnes qui compilent le **meme commit** dans deux
# repertoires differents obtiennent deux binaires differents, donc deux
# condensats SHA-256 differents. Personne ne peut alors verifier que le
# fichier publie vient bien de ces sources ; il faut croire celui qui l'a
# construit. C'est exactement le trou que Bitcoin Core a ferme par Gitian
# puis par Guix.
#
# # Ce que le script fait
#
# Il passe a rustc `--remap-path-prefix`, qui remplace le prefixe du
# repertoire de travail par un nom fixe, `/q21`. Le binaire ne sait plus ou
# il a ete construit. Les autres chemins qu'il contient — `/rustc/<empreinte
# du compilateur>/library/...` et `/rust/deps/...` — sont deja neutralises
# par la distribution Rust elle-meme et sont identiques sur toutes les
# machines portant la meme chaine d'outils.
#
# `trim-paths` ferait cela en une ligne dans `Cargo.toml`, mais il n'est pas
# stabilise dans Cargo 1.95.0, la version epinglee par `rust-toolchain.toml`.
# `--remap-path-prefix` est stable depuis 2018.
#
# # Emploi
#
#   ./outils/construire-reproductible.sh
#   ./outils/construire-reproductible.sh x86_64-unknown-linux-gnu
#
# Le second argument facultatif est une cible ; sans lui, la machine courante.
#
# # Verifier que cela marche
#
#   ./outils/verifier-reproductible.sh
#
# Voir REPRODUIRE.md.

set -eu

CIBLE="${1:-}"

# Le repertoire du projet, quel qu'il soit, vu depuis ce script. On ne suppose
# pas que l'utilisateur est a la racine.
RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$RACINE"

# `pwd -P` : le chemin reel, liens symboliques resolus. C'est celui que cargo
# donne a rustc ; remapper le chemin non resolu ne correspondrait a rien.
#
# Le nom d'arrivee, `/q21`, est arbitraire mais doit etre le meme partout :
# c'est lui qui finit dans le binaire. Ne le changez pas sans changer
# REPRODUIRE.md, sinon les condensats publies ne correspondront plus.
DRAPEAUX="--remap-path-prefix=$RACINE=/q21"

# Un `RUSTFLAGS` deja pose dans l'environnement remplacerait le notre en
# silence : cargo ne les cumule pas, il prend l'un OU l'autre. On refuse
# plutot que de produire un binaire qu'on croit reproductible et qui ne l'est
# pas.
if [ -n "${RUSTFLAGS:-}" ]; then
  echo "erreur : RUSTFLAGS est deja defini dans l'environnement :" >&2
  echo "  RUSTFLAGS=$RUSTFLAGS" >&2
  echo "Il remplacerait les drapeaux de reproductibilite. Videz-le :" >&2
  echo "  unset RUSTFLAGS" >&2
  exit 1
fi

echo "Racine du projet : $RACINE"
echo "Remappage        : $RACINE -> /q21"
echo "Chaine d'outils  : $(rustc --version)"
echo

if [ -n "$CIBLE" ]; then
  RUSTFLAGS="$DRAPEAUX" cargo build --locked --release --target "$CIBLE"
  BINAIRE="target/$CIBLE/release/q21"
else
  RUSTFLAGS="$DRAPEAUX" cargo build --locked --release
  BINAIRE="target/release/q21"
fi

[ -f "$BINAIRE" ] || BINAIRE="$BINAIRE.exe"

echo
echo "Binaire : $BINAIRE"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$BINAIRE"
else
  shasum -a 256 "$BINAIRE"
fi
