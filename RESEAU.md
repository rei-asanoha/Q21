# Ouvrir et rejoindre le réseau d'essai Q21

Deux marches à suivre. La première pour celui qui tient un point d'entrée, la
seconde pour celui qui arrive.

---

# Partie 1 — Rejoindre le réseau

## 1 · Vérifier la genèse, avant tout le reste

```
q21 genese testnet
```

```
  testnet
    identifiant   02140e8ad7f3d57d3ebb3936d380e37f0192a27b99dd894ca409a75db498a921
    port P2P      21121
```

**Cette valeur ne vient d'aucun serveur.** Elle se recalcule à partir du code,
sur votre machine. Si la vôtre diffère de celle publiée, vous n'êtes pas sur la
même chaîne — et aucune synchronisation n'y changera quoi que ce soit.

C'est le seul acte de confiance de tout le processus, et il ne demande de croire
personne : il demande de comparer deux nombres.

## 1 bis · Sur macOS : lever la quarantaine, une fois

Les fichiers livrés ne sont pas signés — cela demande un compte Apple Developer
payant. macOS met donc en quarantaine tout ce qui vient d'un navigateur, et
propose de le **mettre à la corbeille**. Ce n'est pas une panne, et le refuser
est le bon réflexe de sa part.

Deux choses à savoir, dans cet ordre :

**`q21` ne se double-clique pas.** C'est un programme en ligne de commande. Le
double-cliquer dans le Finder est précisément ce qui déclenche ce dialogue.

**La quarantaine se lève depuis le Terminal**, en une fois, pour tout le dossier :

```bash
cd <le dossier décompressé>
xattr -dr com.apple.quarantine .
chmod +x q21
./q21 genese testnet
```

Pour obtenir le `cd` sans se tromper : tapez `cd ` — avec l'espace — puis **faites
glisser le dossier depuis le Finder dans la fenêtre du Terminal**. Le chemin
s'écrit tout seul. Entrée.

> Sur macOS 15 (Sequoia), le contournement historique « clic droit → Ouvrir » a
> été retiré. Si vous préférez tout de même passer par l'interface : lancez le
> programme une fois, laissez-vous refuser, puis allez dans **Réglages
> Système → Confidentialité et sécurité**, descendez tout en bas, et cliquez sur
> **Ouvrir quand même**.

## 2 · Un nœud simple, sans portefeuille

```
q21 --datadir q21-testnet node --reseau testnet --amorce <hôte du réseau>
```

Le dossier peut être vide : le nœud écrit la genèse lui-même — elle est
déterministe — puis télécharge et **valide** chaque bloc. Rien n'est cru sur
parole.

Aucune phrase secrète n'est demandée, aucune clef n'est gardée, et aucune
méthode capable de déplacer des fonds n'est servie.

## 3 · Avec un portefeuille

```
q21 --datadir q21-testnet init testnet
q21 --datadir q21-testnet wallet --amorce <hôte du réseau>
```

Le portefeuille s'ouvre dans le navigateur et se synchronise avec le réseau.
Tant que la synchronisation n'est pas finie, un bandeau le dit — un solde
calculé sur une chaîne incomplète est un solde faux, et il vaut mieux le savoir.

## 4 · Miner

Ajoutez `--mine`. Sur un réseau où d'autres minent, la difficulté s'ajuste : ce
n'est plus un bloc par seconde comme en local, mais un bloc toutes les deux
minutes pour l'ensemble du réseau, partagé entre tous ceux qui cherchent.

---

# Partie 2 — Tenir un point d'entrée

Un réseau public a besoin d'au moins une machine joignable en permanence. Sans
elle, personne ne peut entrer.

## Ce qu'il faut

Un petit serveur loué, cinq à dix euros par mois. Un cœur, un gigaoctet de
mémoire et dix gigaoctets de disque suffisent pour un réseau d'essai. Une
adresse IP fixe, et de préférence un **nom** qui pointe dessus : un nom se
repointe en une minute, une adresse écrite dans un binaire ne se change plus.

> **Pas à pas complet, pour qui n'a jamais administré un serveur :
> [SERVEUR.md](SERVEUR.md).** Création du compte, clé d'accès, durcissement
> SSH, pare-feu, service, nom de domaine — treize étapes, avec le détail de ce
> qu'on doit voir à chaque fois.

## Installer

```bash
# sur le serveur, en tant qu'utilisateur ordinaire
sudo mv ~/q21 /opt/q21/q21
sudo chmod +x /opt/q21/q21
sudo -u q21 /opt/q21/q21 genese testnet    # vérifiez l'identifiant
```

> ⚠️ **Le binaire livré est compilé pour x86_64.** Une machine ARM — la gamme
> CAX de Hetzner, la moins chère — le refuserait avec
> `cannot execute binary file`. Prenez une CX ou une CPX.

## Le service qui redémarre seul

Un point d'entrée qui s'arrête après une coupure de courant n'est pas un point
d'entrée. Fichier `/etc/systemd/system/q21.service` :

```ini
[Unit]
Description=Nœud d'amorçage Q21 (testnet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=q21
WorkingDirectory=/opt/q21
ExecStart=/opt/q21/q21 --datadir /opt/q21/donnees \
          node --reseau testnet --listen 21121 --sans-amorces
Restart=always
RestartSec=10
# Le nœud n'a besoin d'écrire que dans son dossier de données.
ProtectSystem=strict
ReadWritePaths=/opt/q21/donnees
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now q21
journalctl -u q21 -f          # pour regarder ce qu'il fait
```

`--sans-amorces` parce que ce nœud **est** l'amorce : sans cela, deux points
d'entrée d'un même réseau passeraient leur temps à se rappeler l'un l'autre.

## Le pare-feu

Un seul port ouvert, et un seul.

```bash
sudo ufw allow 21121/tcp      # P2P : doit être joignable
sudo ufw enable
```

**Le port du RPC ne s'ouvre pas.** Un nœud d'amorçage n'a aucune raison
d'exposer son interface de consultation, et le programme refuse d'ailleurs de
servir un RPC hors de la boucle locale sans jeton :

```
erreur : refus : --rpc 0.0.0.0:21080 sort de la boucle locale et aucun jeton
         n'est fourni. Toute machine qui vous atteint pourrait interroger ce nœud.
```

Pour regarder ce nœud à distance, passez par un tunnel SSH plutôt que par une
ouverture de port :

```bash
ssh -L 21080:127.0.0.1:21080 q21@votre-serveur
```

## Ce que ce nœud ne fait pas

- **Il ne mine pas.** Sans portefeuille, la subvention irait à une clef qui
  mourrait avec le processus ; le programme refuse `--mine`. Un point d'entrée
  et un mineur sont deux rôles, et les séparer évite qu'une panne de l'un
  emporte l'autre.
- **Il ne garde aucune clef.** Rien à voler sur cette machine.
- **Il ne décide de rien.** Il donne un premier contact ; ce que vous croyez
  vient de la preuve de travail et de la genèse que vous avez écrite vous-même.

## Publier le point d'entrée

Une fois le nœud en marche, annoncez son nom. Ceux qui rejoignent l'écrivent
soit en ligne de commande, soit dans `amorces.txt` de leur dossier de données —
une par ligne, les lignes vides et celles commençant par `#` sont ignorées :

```
# les amorces du réseau d'essai Q21
amorce1.exemple.fr
amorce2.exemple.fr:21121
```

Quand plusieurs points d'entrée existent et qu'ils tiennent, ils peuvent être
inscrits dans le binaire lui-même — `amorces_integrees` dans `src/amorce.rs`.
Tant qu'aucun ne répond de façon fiable, cette liste **reste vide** : annoncer
des noms morts serait pire que rien, chaque démarrage attendrait une réponse qui
ne vient pas. Une épreuve le vérifie, et elle tombera le jour où on l'ouvrira —
c'est voulu.

---

# Ce que l'amorçage ne donne pas comme pouvoir

Celui qui tient les points d'entrée décide **à qui vous parlez en premier**, pas
ce que vous croyez.

Un pair, quel qu'il soit, ne peut vous faire accepter que des blocs valides,
prolongeant la genèse que vous avez calculée vous-même, et portant la preuve de
travail. Il peut vous cacher des choses ; il ne peut pas vous en inventer.

La défense contre le fait d'être isolé — l'éclipse — n'est pas la confiance dans
l'amorçage. C'est le carnet d'adresses : des seaux par groupe réseau /16, et un
sel propre à chaque nœud, de sorte qu'un adversaire détenant une seule plage
d'adresses ne puisse pas occuper toutes vos places. Voir `net::addr`.

---

# Ce qu'un portable a appris au protocole

Le premier essai entre deux machines réelles — un PC Windows et un MacBook — a
sorti un défaut qu'aucune épreuve en boucle locale ne pouvait produire.

On referme l'écran du portable, on le rouvre : **la chaîne ne bouge plus.**
Hauteur 442, définitivement, pendant que l'autre machine minait jusqu'à 455.

Une connexion TCP peut survivre à la machine d'en face. Un portable qui
s'endort ne dit rien en partant — ni `FIN`, ni `RST` — et la socket reste
ouverte du côté qui reste. Le nœud croyait donc avoir un pair, ne cherchait
personne, et attendait pour toujours des messages qui ne viendraient jamais.

Trois mesures, dans cet ordre :

| Silence | Ce qui se passe |
|---|---|
| 45 s | On envoie un `Ping` : « es-tu là ? » |
| 100 s | Sans aucune trame reçue entre-temps, la place est libérée et les amorces retentées |
| Un tour de boucle qui dure plus d'une minute | La machine a dormi : on coupe tout de suite, sans attendre les 100 s |

Le troisième point rend le réveil quasi immédiat. Mesuré : un nœud endormi 75
secondes retrouve son pair et rattrape 59 blocs en moins de vingt secondes après
le réveil.

Sur un réseau public, le même défaut était une voie d'éclipse : ouvrir des
connexions puis se taire suffisait à occuper toutes les places d'un nœud.

---

# Ce que ce réseau d'essai va servir à mesurer

Il n'est pas ouvert pour faire joli. Trois choses ne peuvent se mesurer nulle
part ailleurs :

| Question | Pourquoi seul un réseau réel répond |
|---|---|
| Le coût de saturer le réservoir mord-il vraiment ? | En local, personne n'essaie |
| La difficulté s'ajuste-t-elle proprement à plusieurs mineurs ? | Un seul mineur ne fait pas varier grand-chose |
| Que se passe-t-il lors d'une vraie réorganisation ? | Il en faut deux qui minent en même temps, loin l'un de l'autre |

Et le point le plus important reste ouvert : **la preuve de travail n'a reçu
aucune cryptanalyse externe.** Un réseau d'essai public est aussi une invitation
à venir la casser.

**Aucun Q21 de ce réseau n'a la moindre valeur, et n'en aura jamais.** C'est un
réseau d'essai : il peut être remis à zéro à tout moment.
