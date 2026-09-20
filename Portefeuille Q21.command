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
#  Ce qu'il fait en plus, sur macOS : lever la quarantaine
#
#  Tout fichier telecharge par un navigateur recoit de macOS une marque de
#  quarantaine, et un programme non notarie qui la porte est refuse au
#  lancement avec « est endommage et ne peut pas etre ouvert » — un message
#  qui accuse le fichier alors que rien n'est abime. Notarier demanderait un
#  compte Apple Developer, donc une identite verifiee par Apple, ce que ce
#  projet ne fait pas. On leve donc la marque ici, une fois, sur tout le
#  dossier : c'est exactement le geste que RESEAU.md demandait de faire a la
#  main dans le Terminal, et il n'y a aucune raison de le laisser a
#  l'utilisateur. `xattr` echoue en silence quand il n'y a rien a lever —
#  Linux, ou une archive ouverte depuis le Terminal — et le lanceur continue.
#
#  Ce lanceur-ci porte la meme marque, et macOS le bloque une fois : « d'un
#  developpeur non identifie ». C'est le seul geste qui reste a l'utilisateur,
#  et il est documente dans REJOINDRE.md. Une fois autorise, tout le reste
#  passe par ici.
# ---------------------------------------------------------------------------
cd "$(dirname "$0")" || exit 1

# Lever la quarantaine sur tout le dossier, sans bruit si rien n'est a lever.
xattr -dr com.apple.quarantine . 2>/dev/null || true
# L'archive conserve le droit d'execution ; on le remet par surete.
chmod +x ./q21 2>/dev/null || true

./q21 wallet
