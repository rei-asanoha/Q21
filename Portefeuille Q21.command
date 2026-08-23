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
#  Sur macOS, l'extension `.command` rend ce fichier double-cliquable dans le
#  Finder. Si macOS refuse de l'ouvrir : clic droit, puis « Ouvrir ».
# ---------------------------------------------------------------------------
cd "$(dirname "$0")" || exit 1

if [ ! -f q21-data/wallet.dat ]; then
    echo
    echo "  Aucun portefeuille dans ce dossier. On va en creer un."
    echo
    echo "  Une phrase secrete vous sera demandee. Elle ne s'affichera pas"
    echo "  pendant la frappe : c'est voulu, pour que personne ne la lise"
    echo "  par-dessus votre epaule. Tapez-la, puis Entree."
    echo
    echo "  Un code de sauvegarde s'affichera ensuite. RECOPIEZ-LE SUR PAPIER."
    echo "  C'est le seul moyen de retrouver vos fonds si ce dossier disparait."
    echo
    printf "  Appuyez sur Entree pour continuer..."
    read -r _
    if ! ./q21 init testnet; then
        echo
        echo "  La creation a echoue. Rien n'a ete ecrit."
        printf "  Appuyez sur Entree pour fermer..."
        read -r _
        exit 1
    fi
    echo
    printf "  Avez-vous recopie le code de sauvegarde sur papier ? Entree pour continuer..."
    read -r _
fi

./q21 wallet
