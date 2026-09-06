#!/bin/sh
# Surveillance d'un noeud Q21 : la hauteur avance-t-elle ?
#
# Un noeud qui s'arrete a trois heures du matin ne previent personne. Ce
# script lit la hauteur sur le RPC local, la compare a celle notee au passage
# precedent, et agit si rien n'a bouge depuis trop longtemps : il relance le
# service, et — si un sujet ntfy est configure — envoie une notification sur
# le telephone (https://ntfy.sh : gratuit, sans compte, une application).
#
# A lancer toutes les dix minutes par un minuteur systemd (voir SERVEUR.md),
# sous un compte qui a le droit de relancer le service.
#
# Variables, toutes facultatives :
#   Q21_RPC       adresse du RPC local        (defaut : 127.0.0.1:21080)
#   Q21_SERVICE   nom du service systemd      (defaut : q21)
#   Q21_ETAT      fichier ou noter la hauteur (defaut : /var/tmp/q21-surveillance)
#   Q21_SEUIL     minutes sans bloc avant d'agir (defaut : 30)
#   Q21_NTFY      sujet ntfy, par exemple q21-mon-serveur-a7f3 (defaut : aucun)
set -u
RPC="${Q21_RPC:-127.0.0.1:21080}"
SERVICE="${Q21_SERVICE:-q21}"
ETAT="${Q21_ETAT:-/var/tmp/q21-surveillance}"
SEUIL="${Q21_SEUIL:-30}"
NTFY="${Q21_NTFY:-}"

maintenant=$(date +%s)
reponse=$(curl -s -m 10 -X POST "http://$RPC/rpc" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{}}' 2>/dev/null)
hauteur=$(printf '%s' "$reponse" | sed -n 's/.*"hauteur":\([0-9]*\).*/\1/p')

prevenir() {
  logger -t q21-surveillance "$1"
  if [ -n "$NTFY" ]; then
    curl -s -m 10 -H "Title: Q21" -d "$1" "https://ntfy.sh/$NTFY" >/dev/null 2>&1
  fi
}

# Le RPC ne repond pas : le processus est mort ou fige.
if [ -z "$hauteur" ]; then
  prevenir "noeud injoignable sur $RPC : relance du service $SERVICE"
  systemctl restart "$SERVICE"
  printf '0 %s\n' "$maintenant" > "$ETAT"
  exit 0
fi

# Premiere mesure : on note, et on attend.
if [ ! -f "$ETAT" ]; then
  printf '%s %s\n' "$hauteur" "$maintenant" > "$ETAT"
  exit 0
fi

read -r derniere_hauteur depuis < "$ETAT"
if [ "$hauteur" -gt "$derniere_hauteur" ]; then
  printf '%s %s\n' "$hauteur" "$maintenant" > "$ETAT"
  exit 0
fi

# La hauteur n'a pas bouge : depuis combien de temps ?
minutes=$(( (maintenant - depuis) / 60 ))
if [ "$minutes" -ge "$SEUIL" ]; then
  prevenir "hauteur figee a $hauteur depuis $minutes min : relance du service $SERVICE"
  systemctl restart "$SERVICE"
  printf '%s %s\n' "$hauteur" "$maintenant" > "$ETAT"
fi
