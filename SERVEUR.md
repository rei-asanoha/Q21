# Monter le point d'entrée Q21, pas à pas

Pour quelqu'un qui n'a jamais administré un serveur. Comptez une heure et demie,
sans se presser, et environ **4 € par mois** plus une dizaine d'euros par an pour
le nom de domaine.

Tout se pilote depuis le **Terminal du Mac**. Rien à installer.

> **Vous préférez piloter depuis Windows ?**
> [SERVEUR-WINDOWS.md](SERVEUR-WINDOWS.md) refait le même chemin de bout en
> bout, depuis PowerShell. Suivez l'un **ou** l'autre, pas les deux : ce qui
> change est justement ce qu'on tape sur sa propre machine.

---

## Ce qu'on construit, et pourquoi c'est sûr

Une petite machine louée, allumée en permanence, qui fait une seule chose :
**donner un premier contact** aux gens qui rejoignent le réseau.

Trois propriétés à garder en tête, parce qu'elles expliquent chaque décision qui
suit :

1. **Ce serveur ne garde aucune clé.** Il tourne sans portefeuille. Il n'y a
   rien à y voler — ni graine, ni phrase secrète, ni fonds.
2. **Un seul port est ouvert vers le monde**, celui du protocole Q21. Le reste
   est fermé, y compris l'interface de consultation.
3. **On ne se connecte jamais par mot de passe.** Uniquement par une clé
   cryptographique qui reste sur votre Mac.

Un serveur qui ne détient rien et n'expose qu'une porte est un serveur dont la
compromission ne coûte presque rien. C'est le but.

---

# Étape 1 — Fabriquer votre clé d'accès

**Sur le Mac, et avant de créer le serveur.** L'ordre compte : le serveur naîtra
avec votre clé déjà installée, et n'aura donc jamais eu de mot de passe à
deviner.

Ouvrez **Terminal** (⌘ + Espace, tapez `Terminal`).

```bash
ssh-keygen -t ed25519 -C "q21-amorce"
```

Trois questions :

| Question | Quoi répondre |
|---|---|
| `Enter file in which to save the key` | **Entrée** — l'emplacement par défaut est le bon |
| `Enter passphrase` | **Mettez-en une**, et notez-la. Elle protège le fichier si le Mac est volé |
| `Enter same passphrase again` | La même |

Vous obtenez deux fichiers :

- `~/.ssh/id_ed25519` — la clé **privée**. Elle ne quitte jamais votre Mac.
- `~/.ssh/id_ed25519.pub` — la clé **publique**. Celle-là se donne.

Affichez la publique pour pouvoir la copier :

```bash
cat ~/.ssh/id_ed25519.pub
```

Une ligne apparaît, qui commence par `ssh-ed25519` et finit par `q21-amorce`.
**Sélectionnez-la entièrement et copiez-la.**

> ⚠️ **Ne partagez jamais le fichier sans `.pub`.** C'est la clé privée. Celui
> qui l'obtient entre chez vous. La publique, elle, peut être affichée partout
> sans le moindre risque — c'est tout son intérêt.

---

# Étape 2 — Créer le compte Hetzner

Allez sur **console.hetzner.com** → **Sign up**.

Adresse électronique, mot de passe, validation par courriel. Hetzner demande
souvent une vérification d'identité au premier paiement : carte bancaire, parfois
une pièce d'identité. C'est normal chez tous les hébergeurs européens.

Une fois connecté, créez un **projet** — le bouton **New Project**. Appelez-le
`q21`. Un projet est simplement un tiroir qui regroupe vos machines.

---

# Étape 3 — Déposer votre clé publique

Dans le projet : menu de gauche → **Security** → onglet **SSH Keys** →
**Add SSH Key**.

Collez la ligne copiée à l'étape 1. Donnez-lui un nom : `mac`.

Hetzner affiche une *empreinte* — une suite de caractères. C'est normal : c'est
un résumé de votre clé, pas un secret.

---

# Étape 4 — Créer le serveur

Menu de gauche → **Servers** → **Add Server**.

### Location

**Falkenstein**, **Nuremberg** ou **Helsinki**. Prenez le plus proche de vous ;
pour un réseau d'essai, cela ne change rien.

### Image

**Ubuntu 24.04**.

### Type ⚠️ — l'endroit où l'on se trompe

Choisissez un modèle dont le nom commence par **CX** ou **CPX**.

> **Ne prenez surtout pas un modèle CAX.** C'est la gamme la moins chère, et
> c'est un piège ici : les CAX sont des processeurs **ARM**, alors que le
> programme fabriqué par GitHub est compilé pour **x86_64**. Sur une CAX, `q21`
> refuserait de démarrer avec un message incompréhensible
> (`cannot execute binary file`).

Le plus petit CX suffit largement : 2 cœurs, 4 Go de mémoire, 40 Go de disque.

### Networking

Laissez **IPv4** et **IPv6** cochés.

### SSH Keys

**Cochez la clé `mac`** déposée à l'étape 3.

> C'est ce qui fait qu'aucun mot de passe root ne sera jamais créé ni envoyé par
> courriel. Si vous oubliez cette case, Hetzner vous enverra un mot de passe par
> message — exactement ce qu'on veut éviter.

### Name

`q21-amorce`.

Cliquez **Create & Buy now**. Une minute plus tard, la machine existe.

**Notez son adresse IPv4**, affichée dans la liste. Elle ressemble à
`5.75.xxx.xxx`. Dans la suite, remplacez `VOTRE_IP` par cette valeur.

---

# Étape 5 — La première connexion

Dans le Terminal du Mac :

```bash
ssh root@VOTRE_IP
```

**Première question :**

```
The authenticity of host '5.75.xxx.xxx' can't be established.
ED25519 key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Tapez `yes`, Entrée. C'est votre Mac qui note l'identité du serveur pour ne plus
jamais avoir à la redemander — et pour vous prévenir si elle changeait.

**Deuxième question :** la phrase secrète de votre clé. macOS propose de la
retenir dans le trousseau — acceptez, c'est sans risque.

Vous devez arriver sur une bannière Ubuntu et une invite qui finit par `#`.
**Vous êtes sur le serveur.**

---

# Étape 6 — Mettre à jour, et créer les comptes

Toujours dans cette fenêtre, sur le serveur.

### Les mises à jour

```bash
apt update && apt upgrade -y
```

Puis les correctifs de sécurité automatiques — un serveur qu'on oublie de mettre
à jour est la première cause de compromission :

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

Répondez **Yes** à la question posée.

### Votre compte d'administration

On n'administre pas en `root` au quotidien.

```bash
adduser --gecos "" q21op
```

Il demande un mot de passe — **mettez-en un solide et notez-le**. Il ne servira
pas à se connecter (on se connecte par clé), mais à confirmer les commandes
d'administration.

Donnez-lui le droit d'administrer, et recopiez-lui votre clé :

```bash
usermod -aG sudo q21op
rsync --archive --chown=q21op:q21op ~/.ssh /home/q21op/
```

### Le compte du service

Le programme Q21 tournera sous un compte à lui, **sans mot de passe, sans shell,
incapable de se connecter** :

```bash
adduser --system --group --home /opt/q21 --shell /usr/sbin/nologin q21
```

---

# Étape 7 — Fermer la porte de service ⚠️

C'est l'étape où l'on peut se verrouiller dehors. **Suivez l'ordre exactement.**

### 7.1 — D'abord vérifier que le nouveau compte marche

**Ouvrez une DEUXIÈME fenêtre de Terminal** (⌘ + N). Ne fermez pas la première.

Dans la nouvelle :

```bash
ssh q21op@VOTRE_IP
sudo -v
```

Il demande la phrase de votre clé, puis le mot de passe de `q21op` pour `sudo`.
Si les deux passent, continuez. **Si l'un des deux échoue, arrêtez-vous ici** et
corrigez depuis la première fenêtre, encore ouverte en `root`.

### 7.2 — Interdire le mot de passe et la connexion root

Dans la deuxième fenêtre, en tant que `q21op` :

```bash
sudo nano /etc/ssh/sshd_config.d/99-q21.conf
```

Un éditeur de texte s'ouvre, vide. Tapez ces trois lignes :

```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
```

Pour enregistrer : **Ctrl + O**, Entrée, puis **Ctrl + X**.

### 7.3 — Vérifier la syntaxe AVANT de redémarrer

```bash
sudo sshd -t
```

**Si cette commande n'affiche rien, c'est bon.** Si elle affiche une erreur,
rouvrez le fichier et corrigez — ne redémarrez pas.

```bash
sudo systemctl restart ssh
```

### 7.4 — Vérifier depuis une TROISIÈME fenêtre

```bash
ssh q21op@VOTRE_IP
```

Doit passer. Et :

```bash
ssh root@VOTRE_IP
```

Doit être **refusé**. C'est le résultat attendu.

Maintenant seulement, vous pouvez fermer les fenêtres.

> **Si vous vous verrouillez dehors malgré tout :** Hetzner fournit une console
> web. Dans la fiche du serveur, bouton **Console** en haut à droite. Elle donne
> un accès écran-clavier directement à la machine, sans passer par le réseau. On
> ne se retrouve donc jamais définitivement bloqué.

---

# Étape 8 — Le pare-feu

On emploie le pare-feu **de Hetzner**, pas celui de la machine. Raison : il est
**en dehors** du serveur. Une erreur se corrige depuis le navigateur, et ne peut
pas vous enfermer.

Menu de gauche → **Firewalls** → **Create Firewall**.

Nom : `q21-amorce`.

**Inbound rules** — deux règles, et deux seulement :

| Protocole | Port | Source | À quoi ça sert |
|---|---|---|---|
| TCP | `22` | `Any IPv4`, `Any IPv6` | Votre accès d'administration |
| TCP | `21121` | `Any IPv4`, `Any IPv6` | Le protocole Q21 |

**Outbound rules** : laissez tout autorisé. Le nœud doit pouvoir sortir vers ses
pairs.

En bas, section **Apply to** : cochez le serveur `q21-amorce`. Puis
**Create Firewall**.

> **Le port de l'interface de consultation ne s'ouvre pas**, jamais. Le
> programme refuse d'ailleurs de la servir hors de la machine sans jeton. Pour
> la regarder à distance, on passe par un tunnel — voir la fin de ce document.

---

# Étape 9 — Envoyer le programme

Le fichier se télécharge **sur le Mac** (GitHub demande d'être connecté, ce que
le serveur ne peut pas faire), puis se pousse vers le serveur.

### Sur le Mac

Sur `github.com/reiasanoha/q21` → **Actions** → **Livraison** → la dernière
exécution verte → section **Artifacts** → **`q21-linux-x86_64.tar.gz`**.

Décompressez-le (double-clic, éventuellement deux fois). Vous obtenez un dossier
contenant un fichier `q21`.

Dans le Terminal, placez-vous dans ce dossier — tapez `cd ` puis glissez le
dossier depuis le Finder — et envoyez :

```bash
scp q21 q21op@VOTRE_IP:~/
```

### Sur le serveur

```bash
ssh q21op@VOTRE_IP
sudo mv ~/q21 /opt/q21/q21
sudo chown q21:q21 /opt/q21/q21
sudo chmod +x /opt/q21/q21
```

**Vérifiez que le programme tourne, et qu'il est sur la bonne chaîne :**

```bash
sudo -u q21 /opt/q21/q21 genese testnet
```

L'identifiant affiché doit être **exactement** celui de votre PC et de votre Mac.
S'il diffère, ou si vous lisez `cannot execute binary file`, arrêtez-vous : dans
le second cas, vous avez pris une machine ARM (voir l'étape 4).

---

# Étape 10 — Le service qui redémarre tout seul

Un point d'entrée qui s'arrête après une coupure n'est pas un point d'entrée.

```bash
sudo nano /etc/systemd/system/q21.service
```

Collez exactement ceci :

```ini
[Unit]
Description=Noeud d'amorcage Q21 (testnet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=q21
Group=q21
WorkingDirectory=/opt/q21
ExecStart=/opt/q21/q21 --datadir /opt/q21/donnees node --reseau testnet --listen 21121 --sans-amorces
Restart=always
RestartSec=10

# Le noeud n'a besoin d'ecrire que dans son dossier de donnees.
ProtectSystem=strict
ReadWritePaths=/opt/q21/donnees
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
```

**Ctrl + O**, Entrée, **Ctrl + X**.

Créez le dossier de données et démarrez :

```bash
sudo mkdir -p /opt/q21/donnees
sudo chown q21:q21 /opt/q21/donnees
sudo systemctl daemon-reload
sudo systemctl enable --now q21
```

### Vérifier

```bash
sudo systemctl status q21
```

Vous devez lire **`active (running)`** en vert.

```bash
sudo journalctl -u q21 -f
```

Vous devez voir la genèse écrite, puis l'écoute :

```
  genese ecrite : 02140e8ad7f3d57d3ebb...
  sans portefeuille : aucune methode de portefeuille servie
  ecoute sur 0.0.0.0:21121
```

**Ctrl + C** pour arrêter de regarder — cela n'arrête pas le service.

> `--sans-amorces` parce que ce nœud **est** l'amorce. Sans cela, deux points
> d'entrée d'un même réseau passeraient leur temps à se rappeler l'un l'autre.

---

# Étape 11 — Le nom de domaine

Une adresse IP écrite quelque part ne se change plus. Un nom se repointe en une
minute — c'est ce qui vous permettra de changer de serveur sans que personne
n'ait rien à refaire.

Achetez un domaine chez le bureau d'enregistrement de votre choix (OVH, Gandi,
Cloudflare, Namecheap…). Une dizaine d'euros par an.

Dans son interface, créez un **enregistrement A** :

| Champ | Valeur |
|---|---|
| Type | `A` |
| Nom / Host | `amorce` |
| Valeur / Points to | `VOTRE_IP` |
| TTL | laissez la valeur par défaut |

> ⚠️ **Si vous êtes chez Cloudflare** : le petit nuage à côté de la ligne doit
> être **gris** (« DNS only »), pas orange. Le mandataire orange ne relaie que du
> web, et casserait le protocole Q21 sans le moindre message d'erreur.

### Vérifier, depuis le Mac

```bash
dig +short amorce.VOTREDOMAINE.fr
```

Doit afficher votre adresse IP. Comptez quelques minutes de propagation.

---

# Étape 12 — Vérifier depuis l'extérieur

C'est le moment de vérité. **Depuis le Mac**, dans le dossier où se trouve votre
`q21` :

```bash
./q21 --datadir essai-reseau node --reseau testnet --amorce amorce.VOTREDOMAINE.fr
```

Vous devez voir :

```
  genese ecrite : 02140e8a...
  connexion vers amorce.VOTREDOMAINE.fr (5.75.xxx.xxx:21121)
```

puis la ligne d'état afficher `pairs 1`.

**Votre réseau est ouvert.** N'importe qui, n'importe où, peut désormais entrer
avec cette seule ligne.

---

# Étape 13 — Y brancher vos deux machines

Sur le **PC**, dans le dossier du portefeuille :

```
q21 wallet --mine --amorce amorce.VOTREDOMAINE.fr
```

Sur le **Mac** :

```bash
./q21 --datadir portefeuille wallet --amorce amorce.VOTREDOMAINE.fr
```

Les deux passent maintenant par le serveur au lieu de se parler directement — et
n'ont plus besoin d'être sur le même réseau local.

---

# Surveiller, au quotidien

```bash
ssh q21op@VOTRE_IP

sudo systemctl status q21      # est-il vivant ?
sudo journalctl -u q21 -n 50   # les 50 dernieres lignes
sudo journalctl -u q21 -f      # regarder en direct
```

Pour consulter l'explorateur du serveur sans ouvrir aucun port, ouvrez un
**tunnel** depuis le Mac :

```bash
ssh -L 21080:127.0.0.1:21080 q21op@VOTRE_IP
```

Tant que cette fenêtre reste ouverte, `http://127.0.0.1:21080` sur votre Mac
atteint le serveur. Rien n'est exposé à personne d'autre.

*(Le service actuel ne sert pas d'interface — il faudrait lui ajouter
`--rpc 127.0.0.1:21080 --rpc-token <secret>`. À faire seulement si vous en avez
besoin.)*

## Être prévenu sans regarder

Un nœud qui s'arrête à trois heures du matin ne prévient personne. Le script
`outils/surveiller.sh` du dépôt lit la hauteur sur le RPC local toutes les
dix minutes ; si elle n'a pas bougé depuis trente minutes, ou si le RPC ne
répond plus, il relance le service et — si vous lui donnez un **sujet ntfy** —
envoie une notification sur votre téléphone. [ntfy](https://ntfy.sh) est
gratuit et sans compte : installez l'application, abonnez-vous à un sujet de
votre choix (long et imprévisible, par exemple `q21-serveur-k8s2m7x`), et
mettez le même nom ci-dessous.

Le script a besoin d'un RPC local : le service doit porter `--rpc
127.0.0.1:21080` (c'est le cas d'un explorateur public, voir
`EXPLORATEUR-PUBLIC.md`).

Le sujet ntfy est un secret partagé faible — qui le connaît lit vos alertes
et peut en publier de fausses. Il ne va donc pas dans le fichier d'unité, que
tout le monde peut lire, mais dans un fichier d'environnement à `root` seul.

```bash
sudo cp outils/surveiller.sh /opt/q21/surveiller.sh && sudo chmod +x /opt/q21/surveiller.sh
sudo mkdir -p /etc/q21 && sudo tee /etc/q21/surveillance.env > /dev/null <<'EOF'
Q21_RPC=127.0.0.1:21080
Q21_NTFY=
EOF
sudo chmod 600 /etc/q21/surveillance.env
sudo tee /etc/systemd/system/q21-surveillance.service > /dev/null <<'EOF'
[Unit]
Description=Surveillance du noeud Q21

[Service]
Type=oneshot
EnvironmentFile=/etc/q21/surveillance.env
RuntimeDirectory=q21-surveillance
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true
ExecStart=/opt/q21/surveiller.sh
EOF
sudo tee /etc/systemd/system/q21-surveillance.timer > /dev/null <<'EOF'
[Unit]
Description=Surveillance du noeud Q21, toutes les dix minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now q21-surveillance.timer
```

`Q21_NTFY=` vide : le script relance seulement, et l'écrit dans le journal
(`journalctl -t q21-surveillance`). Avec un sujet, vous recevez aussi le
message. Le fichier d'état vit dans `/run/q21-surveillance/`, que systemd
crée pour ce service seul : personne d'autre ne peut y déposer quoi que ce
soit.

---

# Ce que ce serveur ne risque pas, et ce qu'il risque

### Ce qu'il ne risque pas

- **Le vol de fonds.** Il n'a pas de portefeuille, pas de graine, pas de clé.
- **Le vol de votre identité Q21.** Rien qui vous concerne n'y est écrit.
- **De vous faire mentir.** Un pair, quel qu'il soit, ne peut faire accepter à
  personne que des blocs valides prolongeant la genèse que chacun a calculée
  chez lui, et portant la preuve de travail. Il peut cacher des choses ; il ne
  peut pas en inventer.

### Ce qu'il risque

- **D'être saturé.** C'est le point ouvert que ce réseau d'essai doit
  précisément mesurer. Si cela arrive, on le verra dans le journal.
- **De tomber.** Le service redémarre seul ; la machine aussi après une
  intervention de l'hébergeur. Mais si elle disparaît, plus personne ne peut
  entrer — d'où l'intérêt d'en avoir un second, plus tard, chez un autre
  hébergeur.

---

# Si quelque chose ne va pas

| Symptôme | Cause la plus probable |
|---|---|
| `Permission denied (publickey)` | La clé n'a pas été cochée à la création du serveur. Utilisez la **Console** web de Hetzner |
| `cannot execute binary file` | Machine ARM (gamme CAX). Il faut une CX ou CPX |
| `Connection refused` depuis l'extérieur | Le port 21121 n'est pas ouvert dans le pare-feu Hetzner, ou le service ne tourne pas |
| `dig` ne renvoie rien | L'enregistrement A n'est pas encore propagé, ou le nom est mal orthographié |
| Le nœud tourne mais personne ne se connecte | Nuage orange chez Cloudflare : passez-le en gris |
| `Failed to start q21.service` | `sudo journalctl -u q21 -n 50` dira pourquoi. Souvent un chemin ou un droit |
