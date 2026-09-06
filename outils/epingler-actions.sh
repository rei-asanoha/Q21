#!/bin/sh
# Epingle chaque action GitHub des workflows a l'empreinte de commit de son
# etiquette.
#
# Pourquoi : `uses: actions/checkout@v4` suit une etiquette, et une etiquette
# se reecrit. Qui prend la main sur le depot d'une action — ou sur son
# etiquette — fait executer son code dans le processus qui compile le
# portefeuille, donc dans le binaire qui garde les clefs. Une empreinte de
# commit, elle, ne bouge pas : c'est ce qu'on inscrit ici, avec l'etiquette
# en commentaire pour rester lisible.
#
# A lancer depuis la racine du depot, sur une machine qui a acces a
# api.github.com (curl et python3 suffisent). Puis relire le diff, et
# publier. A refaire quand on veut suivre une nouvelle version d'une action :
# on change l'etiquette en commentaire, on relance le script.
set -eu

api() {
  curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/$1"
}

# Rend l'empreinte de commit designee par `proprietaire/depot@etiquette`.
# Une etiquette annotee pointe sur un objet etiquette, qu'on deroule.
empreinte() {
  depot="$1"; etiquette="$2"
  ref=$(api "repos/$depot/git/ref/tags/$etiquette")
  type=$(printf '%s' "$ref" | python3 -c 'import json,sys; print(json.load(sys.stdin)["object"]["type"])')
  sha=$(printf '%s' "$ref" | python3 -c 'import json,sys; print(json.load(sys.stdin)["object"]["sha"])')
  if [ "$type" = "tag" ]; then
    sha=$(api "repos/$depot/git/tags/$sha" | python3 -c 'import json,sys; print(json.load(sys.stdin)["object"]["sha"])')
  fi
  printf '%s' "$sha"
}

for f in .github/workflows/*.yml; do
  tmp="$f.epingle"
  cp "$f" "$tmp"
  # Chaque ligne `uses: proprietaire/depot@etiquette` (sans commentaire, donc
  # pas encore epinglee) ou `uses: proprietaire/depot@<40 hexa> # etiquette`
  # (deja epinglee : on suit l'etiquette du commentaire).
  grep -n 'uses: *[A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*@' "$f" | while IFS=: read -r num ligne; do
    depot=$(printf '%s' "$ligne" | sed -n 's/.*uses: *\([A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]*\)@.*/\1/p')
    cible=$(printf '%s' "$ligne" | sed -n 's/.*uses: *[A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]*@\([^ #]*\).*/\1/p')
    commentaire=$(printf '%s' "$ligne" | sed -n 's/.*# *\([^ ]*\).*/\1/p')
    if printf '%s' "$cible" | grep -qE '^[0-9a-f]{40}$'; then
      etiquette="${commentaire:-}"
      [ -n "$etiquette" ] || { echo "  $depot : deja epingle sans etiquette en commentaire, laisse tel quel"; continue; }
    else
      etiquette="$cible"
    fi
    case "$etiquette" in
      master|main) echo "  $depot@$etiquette : une branche, pas une version — a remplacer a la main"; continue ;;
    esac
    sha=$(empreinte "$depot" "$etiquette") || { echo "  $depot@$etiquette : introuvable"; continue; }
    indent=$(printf '%s' "$ligne" | sed -n 's/^\( *-\{0,1\} *\)uses:.*/\1/p')
    sed -i "${num}s|.*|${indent}uses: ${depot}@${sha} # ${etiquette}|" "$tmp"
    echo "  $depot@$etiquette -> $sha"
  done
  if cmp -s "$f" "$tmp"; then
    rm -f "$tmp"
  else
    mv "$tmp" "$f"
    echo "$f : epingle"
  fi
done
echo "Relisez le diff (git diff .github/workflows), puis publiez."
