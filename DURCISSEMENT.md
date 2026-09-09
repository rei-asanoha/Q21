# Durcir une machine qui garde des Q21

Le protocole protège ce qu'il peut : personne ne dépense vos fonds sans votre
clé. Il ne protège pas la machine qui garde cette clé. Ce document dit ce
qu'un audit adverse a trouvé sur ce terrain, et ce qu'il faut faire — pour un
Raspberry qui mine, pour un serveur, pour un poste partagé.

---

## Le Raspberry qui mine sans personne devant

### La phrase dans un fichier annule le chiffrement du portefeuille

Un mineur qui démarre tout seul lit sa phrase secrète dans un fichier
(`--phrase-fichier`). Ce fichier vit sur la même carte SD que `wallet.dat`.
Le scellement Argon2id est solide — **quand l'attaquant n'a pas la phrase**.
Ici, qui prend la carte a les deux : la phrase d'un côté, le fichier de
l'autre, et la graine se descelle en une seconde.

**Ce n'est pas un défaut à corriger, c'est un compromis à connaître.** La
règle qui en découle :

> Sur une machine qui lit sa phrase dans un fichier, **ne gardez qu'un
> portefeuille de minage**. Transférez régulièrement les récompenses vers un
> portefeuille dont la phrase n'est écrite nulle part. Le vol de la carte ne
> coûte alors que ce qui n'a pas encore été transféré.

Le fichier de phrase doit appartenir au seul compte qui fait tourner le
nœud, en `chmod 600`. Le programme avertit s'il est lisible par d'autres.

### Un compte pour le service, une clé pour l'accès

Le compte de connexion par défaut (`pi`), le nom d'hôte par défaut
(`raspberrypi`) et un mot de passe tapé à la main forment une cible
prévisible sur un réseau local. Trois mesures, dans l'ordre :

1. **SSH par clé, jamais par mot de passe.** Au moment d'écrire la carte,
   l'outil d'installation propose de coller une clé publique à la place du
   mot de passe : faites-le. Sinon, après coup :

   ```bash
   sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
   sudo systemctl restart ssh
   ```

2. **Un compte système pour le nœud**, sans shell, propriétaire de ses seuls
   fichiers :

   ```bash
   sudo useradd --system --home /var/lib/q21 --create-home --shell /usr/sbin/nologin q21
   sudo chmod 700 /var/lib/q21
   ```

   Le service tourne sous `User=q21`, ses données et sa phrase vivent dans
   `/var/lib/q21` : le compte de connexion, lui, ne peut plus les lire.

3. **Un pare-feu qui n'ouvre rien d'entrant**, et un frein aux essais :

   ```bash
   sudo apt install -y ufw fail2ban
   sudo ufw default deny incoming && sudo ufw default allow outgoing
   sudo ufw allow from 192.168.0.0/16 to any port 22 proto tcp comment 'ssh, reseau local seulement'
   sudo ufw --force enable
   sudo systemctl enable --now fail2ban
   ```

   Un mineur n'a pas besoin de port entrant : il appelle les pairs, on ne
   l'appelle pas.

### L'unité systemd

```ini
[Unit]
Description=Noeud Q21 (mineur)
After=network-online.target
Wants=network-online.target

[Service]
User=q21
Group=q21
WorkingDirectory=/var/lib/q21
ExecStart=/opt/q21/q21 --datadir /var/lib/q21/donnees --phrase-fichier /var/lib/q21/phrase.txt node --reseau testnet --mine --amorce <amorce> --elaguer
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/q21
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

### L'horloge

Un Raspberry n'a pas d'horloge conservée hors tension. Un bloc daté de plus
de dix minutes dans le futur est refusé par tout le réseau ; un mineur à
l'heure fausse produit donc des blocs que personne ne prend. Vérifiez que la
synchronisation est active : `timedatectl` doit dire `System clock
synchronized: yes` avant de miner.

---

## Le serveur public

Il n'a pas de portefeuille — c'est la première règle, et le programme la fait
respecter : `--rpc-public` refuse de démarrer si un portefeuille est présent.
Le reste est dans `SERVEUR.md` : compte dédié, unité durcie, clé SSH,
`fail2ban`, mises à jour automatiques.

Deux points viennent de l'audit :

- **Les recherches coûteuses sont budgétées, par adresse.** Une recherche de
  montant ou de transaction sans résultat d'index relit jusqu'à deux mille
  blocs sous le verrou de la chaîne. En mode public, le nœud n'en accorde
  qu'un nombre borné par minute **à chaque adresse** que le portier lui
  transmet, plus un filet pour l'ensemble ; au-delà, il répond de réessayer,
  et continue de valider. Le premier budget était commun à tous : un seul
  visiteur le vidait pour tout le monde. Le portier, lui, doit borner les
  connexions par adresse — `EXPLORATEUR-PUBLIC.md`, étape 4.2 bis — parce
  que le nœud ne borne que ce qu'on lui fait calculer, pas ce qu'on lui fait
  attendre.
- **La veille ne partage rien.** Son fichier d'état vit dans un répertoire
  que systemd crée pour elle seule, et son sujet de notification dans un
  fichier à `root` seul. Voir `SERVEUR.md`, « Être prévenu sans regarder ».

---

## Le portefeuille sur un poste partagé

Le portefeuille écoute sur la boucle locale et exige un jeton. L'adresse que
le programme donne au navigateur passe par la ligne de commande du lanceur,
que **tout compte de la machine** peut lire — `/proc/<pid>/cmdline` sous
Linux, `ps` sous macOS — et qui y reste tant que le navigateur vit.

Deux défenses, indépendantes :

- **Ce qui est dans l'adresse ne vaut qu'une fois.** Le fragment ne porte
  plus le jeton de session, mais un jeton d'*amorçage* : la page l'échange
  au premier chargement contre le vrai jeton, qui ne quitte jamais le
  programme ni l'onglet, et l'amorce est détruite. Elle expire d'elle-même
  au bout de dix minutes si personne ne l'a ouverte. Ce qui traîne ensuite
  dans la ligne de commande n'ouvre plus rien, sur tous les systèmes. Un
  autre compte qui l'aurait lue avant la page ne gagne qu'une course d'une
  seconde — et s'il la gagne, la page légitime affiche « ce lien a déjà
  servi » au lieu de fonctionner à côté d'un intrus silencieux. Un lien ne
  sert qu'une fois, mais un onglet se rouvre tant que le programme tourne :
  le jeton de session est rangé dans le navigateur, sous cette origine, et
  meurt avec le processus qui l'a tiré.
- **Sous Linux, le nœud refuse les autres comptes.** Il demande au noyau
  quel compte tient l'autre bout de chaque connexion locale, et refuse tout
  compte autre que le sien — ce qui ferme aussi la course ci-dessus. Cette
  garde est fermée : une connexion locale que la table du noyau ne liste pas
  est refusée, elle n'est plus admise « dans le doute ». Elle ne s'ouvre que
  là où il n'y a rien à lire — macOS, Windows —, et le programme le dit à
  l'écran.

Sur macOS et Windows, le lien à usage unique est donc la barrière, et la
règle reste celle de tout logiciel qui garde des clés — **un compte par
personne, et pas de portefeuille sur un poste où d'autres ont un compte**.

---

## Ce que vous installez

Chaque livraison est signée ; vérifiez la signature avant d'installer, sur
chaque machine. C'est l'objet de `SIGNATURE.md`, et c'est la seule défense
contre un binaire substitué — la porte par laquelle toutes les autres
défenses tombent.
