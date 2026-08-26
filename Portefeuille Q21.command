#!/bin/sh
# ---------------------------------------------------------------------------
#  Portefeuille Q21 — double-cliquez sur ce fichier.
# ---------------------------------------------------------------------------
#
#  Pourquoi ce fichier existe
#
#  `q21` attend qu'on lui dise quoi faire : `init`, `mine`, `wallet`. Le
#  double-cliquer n'ouvrait donc rien d'utile. Un premier utilisateur y a bute,
#  et il avait raison : il attendait une application.
#
#  Ce fichier lui dit `wallet`, et rien d'autre.
#
#  Ce qu'il ne fait plus
#
#  Il portait vingt lignes de preparation : detecter l'absence de portefeuille,
#  annoncer qu'une phrase secrete allait etre demandee, lancer `init`, attendre
#  que l'utilisateur confirme avoir recopie un code affiche dans le Terminal.
#  Tout cela se passe maintenant dans des ecrans, a l'ouverture du navigateur —
#  voir src/installation.rs.
#
#  Sur macOS, l'extension `.command` rend ce fichier double-cliquable dans le
#  Finder. Si macOS refuse de l'ouvrir : clic droit, puis « Ouvrir ».
# ---------------------------------------------------------------------------
cd "$(dirname "$0")" || exit 1

./q21 wallet
