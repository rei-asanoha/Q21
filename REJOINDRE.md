# Rejoindre Q21 en dix minutes

Ce guide s'adresse à quelqu'un qui n'a jamais ouvert un terminal. Il ne
demande aucune connaissance préalable, et il tient ses dix minutes si l'on suit
les étapes dans l'ordre.

Il y a deux façons de rejoindre le réseau, et la première suffit à presque tout
le monde.

**Participer** — avoir un portefeuille, et miner si l'on veut. Votre machine
télécharge la chaîne, la vérifie elle-même bloc par bloc, et ne fait confiance
à personne. C'est déjà un nœud complet. Derrière une box internet, il *sort*
vers le réseau mais n'accepte pas de connexions entrantes, et c'est très bien
ainsi. Partie 1.

**Être un point d'entrée** — ce que ce guide appelle un *portier*. Un nouveau
venu ne connaît personne ; il lui faut une première adresse où frapper. Un
portier est un nœud joignable de l'extérieur, allumé en permanence, dont
l'adresse est connue. Le réseau n'a besoin que d'une poignée de portiers, chez
des personnes différentes, pour ne dépendre de personne — pas même de celui qui
a écrit le programme. Partie 2, pour ceux qui veulent aider à cela.

---

## Partie 1 — Participer

### 1. Télécharger le bon fichier

Sur la page des versions du projet, chaque livraison propose une archive par
type de machine :

| Votre machine | Fichier |
|---|---|
| Windows | `q21-windows-x86_64.zip` |
| Mac Apple Silicon (M1 et suivants) | `q21-macos-arm64.tar.gz` |
| Mac Intel | `q21-macos-x86_64.tar.gz` |
| Linux, PC ordinaire | `q21-linux-x86_64.tar.gz` |
| Raspberry Pi 5, Linux ARM | `q21-linux-arm64.tar.gz` |

Téléchargez aussi le petit fichier `SHA256SUMS` qui les accompagne.

### 2. Vérifier ce que vous avez téléchargé

Un logiciel qui garde des clés ne s'installe pas sans vérification. Ouvrez une
fenêtre de commandes dans le dossier de téléchargement — sur Windows,
PowerShell ; sur Mac et Linux, Terminal — et tapez la ligne de votre machine :

```
Windows      Get-FileHash q21-windows-x86_64.zip
Mac          shasum -a 256 q21-macos-arm64.tar.gz
Linux        sha256sum q21-linux-x86_64.tar.gz
```

La suite de lettres et de chiffres affichée doit être **identique** à celle
qui figure, pour ce fichier, dans `SHA256SUMS`. Si elle diffère, n'allez pas
plus loin : le fichier n'est pas celui qui a été publié.

`SIGNATURE.md` explique comment vérifier, en plus, que `SHA256SUMS` lui-même
est bien signé par le projet. C'est un cran de confiance supplémentaire, et il
vaut la peine d'être franchi une fois.

### 3. Décompresser — et savoir où le programme va frapper

Décompressez l'archive où vous voulez — sur le Bureau, dans Documents. Vous
obtenez un dossier contenant le programme (`q21.exe` sur Windows, `q21`
ailleurs), un lanceur à double-cliquer, quelques documents, et un sous-dossier
`q21-data`.

**Vous n'avez rien à faire ici.** Cette étape se lit, elle ne s'exécute pas :
le point d'entrée est déjà en place, et vous pouvez passer à l'étape 4. Elle
existe parce qu'un jour vous voudrez peut-être en changer, et qu'il vaut mieux
savoir comment avant d'en avoir besoin.

Voici ce qui s'y joue. **Le programme ne contient l'adresse d'aucun serveur**,
et c'est voulu : une adresse gravée dans un logiciel distribué deviendrait une
dépendance permanente envers celui qui la tient, et un protocole censé survivre
à son auteur ne doit pas naître avec l'adresse de son auteur dedans. L'adresse
se donne donc **à côté**, dans un fichier ordinaire que vous pouvez lire et
modifier : `q21-data/amorces.txt`. Ouvrez-le, il s'explique lui-même.

La différence n'est pas un détail de forme. Une adresse dans le binaire ne se
change qu'en redistribuant le binaire — donc par celui qui le signe. Une
adresse dans un fichier texte vous appartient à la seconde où vous l'avez :
ajoutez des lignes, remplacez-les toutes, videz le fichier. Le protocole ne
dépend d'aucune de ces adresses ; elles ne servent qu'à frapper à une première
porte. Ce que votre machine croira ensuite viendra de la preuve de travail et
de la genèse qu'elle calcule elle-même.

Une adresse par ligne, `hôte` ou `hôte:port`. Les lignes vides et celles
commençant par `#` sont ignorées. Le jour où d'autres portiers existent, on
ajoute leurs adresses ici ; `RESEAU.md` tient la liste à jour.

**Si le fichier manque** — vous l'avez supprimé, ou l'archive a été recopiée à
moitié — le portefeuille vous le dira en clair au lancement, et vous rappellera
quoi écrire dedans. Pour le recréer à la main, une ligne suffit, depuis le
dossier du programme :

```
Windows      mkdir q21-data ; Set-Content q21-data\amorces.txt "amorce.q21.dev:21121"
Mac, Linux   mkdir -p q21-data && echo amorce.q21.dev:21121 > q21-data/amorces.txt
```

Sur Windows, le Bloc-notes ajoute parfois `.txt` une seconde fois sans le dire,
ce qui donne `amorces.txt.txt` et un fichier que le programme ne voit pas. Au
moment d'enregistrer, choisissez « Type : Tous les fichiers » et tapez le nom
complet. Sur Mac, TextEdit doit être en « Format → Convertir au format Texte »
avant d'enregistrer, sinon il produit un document enrichi. La ligne de commande
ci-dessus évite les deux pièges.

### 4. Lancer

- **Windows** : double-cliquez sur `Portefeuille Q21.bat`.
- **Mac** : double-cliquez sur `Portefeuille Q21.command`.
- **Linux et Raspberry Pi** : dans le Terminal, placé dans le dossier,
  `./q21 wallet`.

Une fenêtre noire s'ouvre et reste ouverte — c'est le nœud, laissez-la. Puis
votre navigateur s'ouvre sur une page qui vous guide : créer un portefeuille,
ou restaurer le vôtre à partir de son code de sauvegarde. Rien à taper dans la
fenêtre noire.

**Recopiez le code de sauvegarde sur papier.** C'est le seul moyen de retrouver
vos fonds si ce disque disparaît — et il suffit : sur une machine neuve, ce
code seul redonne l'intégralité du portefeuille.

Deux avertissements sont normaux au premier lancement. Windows affiche un écran
SmartScreen : cliquez « Informations complémentaires », puis « Exécuter quand
même ». Mac refuse d'ouvrir « un développeur non identifié » : faites un clic
droit sur le lanceur, « Ouvrir », puis confirmez. Ces messages disent qu'aucun
certificat commercial n'a été acheté ; c'est le cas, et c'est la vérification
de l'étape 2 qui le remplace.

### 5. Savoir que vous êtes dedans

Dans la fenêtre noire, une ligne se met à jour régulièrement, du genre :

```
hauteur 1240 (+3)  pairs 4  mempool 0  ...
```

`pairs 4` veut dire que votre nœud parle à quatre autres. Dès que ce nombre
est supérieur à zéro, vous êtes dans le réseau, et la hauteur grimpe jusqu'à
rattraper la chaîne. La première synchronisation prend de quelques minutes à
une heure selon l'âge de la chaîne.

Si `pairs` reste à `0`, relisez l'étape 3 : dans presque tous les cas, le
fichier `amorces.txt` n'est pas au bon endroit, ou porte un autre nom.

L'onglet **Infos** de la page affiche la version du programme que vous faites
tourner, et `q21 version` répond la même chose depuis une fenêtre de commandes.
C'est la première chose à donner si vous demandez de l'aide quelque part.

### 6. Miner, si vous le voulez

Miner, c'est prêter la mémoire de votre machine au réseau, et être payé pour
chaque bloc trouvé. La carte graphique ne sert à rien : c'est la mémoire qui
travaille, et `MINAGE.md` explique pourquoi.

**Sur le réseau d'essai — le seul qui existe aujourd'hui — n'importe quelle
machine ordinaire suffit.** La table du mineur y part de **32 Mio** et plafonne
à **128 Mio** : un vieux portable, un Raspberry Pi 4, conviennent. Les chiffres
que vous lirez ailleurs dans le projet — 2 Gio de table, 8 Go de mémoire vive —
sont ceux de la **chaîne principale**, dimensionnés pour qu'une machine
spécialisée n'ait aucun avantage sur la vôtre. Le réseau d'essai sert à
éprouver le protocole, pas à défendre une monnaie : il n'a aucune raison de
demander autant, et exiger une grosse machine pour y participer écarterait
précisément les gens dont il a besoin.

Ajoutez `--mine` au lancement :

- **Windows** : ouvrez `Portefeuille Q21.bat` avec le Bloc-notes (clic droit →
  Modifier), et remplacez la ligne `q21.exe wallet` par `q21.exe wallet --mine`.
- **Mac** : même chose dans `Portefeuille Q21.command`, avec TextEdit.
- **Linux et Raspberry Pi** : `./q21 wallet --mine`.

Au premier lancement en minage, le programme construit sa table en mémoire —
quelques secondes sur le réseau d'essai, une seule fois par période de 71 jours.
Ensuite, il mine tant que la fenêtre est ouverte, avec tous les cœurs ; `--fils
2` en limite le nombre si vous voulez garder la machine confortable.

L'onglet **Miner** du portefeuille affiche la mémoire réellement occupée. C'est
cette valeur qui fait foi, pas ce guide : elle est calculée par votre machine.

---

## Partie 2 — Être un portier

### Ce que cela demande

Trois choses, et aucune n'est technique au sens où l'on pourrait le craindre.

Une **machine qui reste allumée** : un ordinateur qu'on n'éteint pas, un
Raspberry Pi dans un placard, ou un petit serveur loué pour quelques euros par
mois. Un portier qui s'éteint la nuit n'est pas un portier.

Une **porte ouverte** : le réseau d'essai parle sur le port `21121`. Il faut
que ce port, depuis internet, arrive à votre machine. Derrière une box, cela
s'appelle une *redirection de port* ; sur un serveur loué, le port est
généralement ouvert d'office ou en un clic.

Une **adresse connue** : il faut le dire au projet, pour que les nouveaux venus
sachent où frapper.

Sur le réseau d'essai, la mémoire n'est pas un obstacle : un nœud qui se
contente de vérifier tient dans **1 Mio** de table, et un nœud qui mine dans
**32 Mio**. Un Raspberry Pi, même ancien, fait l'affaire dans les deux cas. Ces
chiffres grandissent de 5 % toutes les 71 jours et plafonnent à 128 Mio.

Sur la chaîne principale, le jour où elle existera, ce sera 64 Mio pour
vérifier et 2 Gio pour miner — voir `MINAGE.md`.

### 1. Écouter

Reprenez le lancement de la partie 1 et ajoutez `--listen 21121` :

```
Windows      q21.exe wallet --listen 21121
Mac          q21 wallet --listen 21121
Linux, Pi    ./q21 wallet --listen 21121
```

Avec `--mine` en plus si vous minez aussi. Sur une machine sans écran — un
serveur, un Pi — on préférera le nœud seul, sans portefeuille ni navigateur :
`./q21 node --reseau testnet --listen 21121`. `SERVEUR.md` montre comment le
faire démarrer tout seul avec la machine et se relancer s'il tombe.

### 2. Ouvrir la porte sur votre box

Chaque box a sa page d'administration, en général sur `192.168.1.1` ou
`192.168.1.254` dans un navigateur, avec le mot de passe inscrit sous la box.
Cherchez « Redirection de ports », « NAT » ou « Port forwarding », et ajoutez
une règle :

- protocole **TCP**
- port externe **21121**
- vers l'adresse locale de votre machine, port **21121**

L'adresse locale de la machine s'obtient par `ipconfig` (Windows) ou
`ip a` (Linux) ; elle ressemble à `192.168.1.x`. Il est prudent de la rendre
fixe dans la box (« bail statique » ou « DHCP réservé »), sinon elle peut
changer et la règle ne mène plus nulle part.

Certains fournisseurs d'accès ne donnent plus d'adresse publique à chaque
abonné (on parle de *CGNAT*) : dans ce cas, aucune redirection ne fonctionnera,
et un petit serveur loué est la seule voie. `SERVEUR.md` en décrit une, de bout
en bout.

### 3. Vérifier de l'extérieur

Ne croyez pas la box sur parole. Depuis un site de test de port —
`yougetsignal.com/tools/open-ports`, par exemple —, entrez votre adresse
publique (celle que le site affiche lui-même) et le port `21121`. Il doit
répondre **ouvert**. Tant qu'il ne le fait pas, personne ne peut entrer chez
vous.

### 4. Le dire au projet

Ouvrez une *Issue* sur le dépôt, `github.com/rei-asanoha/Q21/issues`,
intitulée par exemple `Nouveau portier : 203.0.113.7:21121` — avec un nom de
domaine à la place de l'adresse si vous en avez un, c'est plus durable. Elle
sera ajoutée à la liste de `RESEAU.md`, et à celle que le nom `amorce.q21.dev`
renvoie.

C'est cette étape qui fait la différence entre un réseau qui dépend d'une
personne et un réseau qui n'en dépend d'aucune. Cinq portiers, chez cinq
personnes, chez cinq hébergeurs, et le serveur d'origine peut s'éteindre sans
que quiconque s'en aperçoive : ceux qui sont déjà dedans ont leur carnet
d'adresses, écrit sur leur disque, et n'interrogent plus personne ; ceux qui
arrivent frappent chez les autres.

---

## Si quelque chose ne va pas

**« Aucune adresse de départ : ce nœud ne cherche personne »**, dans la page —
ou **« aucune amorce : ce nœud ne cherchera personne »**, dans la fenêtre
noire. Les deux disent la même chose : le fichier `amorces.txt` n'est pas dans
`q21-data`, ou s'appelle autrement. Il est livré avec le programme ; s'il a
disparu, l'étape 3 donne la ligne qui le recrée.

**`pairs 0` qui ne bouge pas, sans ce message** — le nœud a donc une adresse et
frappe pour de bon, mais personne n'ouvre. Ce n'est plus la même panne : soit le
point d'entrée est momentanément arrêté, soit votre réseau bloque les connexions
sortantes vers le port `21121` — rare chez soi, fréquent en entreprise. Pour
trancher depuis votre machine : `Test-NetConnection amorce.q21.dev -Port 21121`
sous Windows, `nc -vz amorce.q21.dev 21121` sur Mac ou Linux.

**Windows demande « Terminer le programme de commandes (O/N) ? »** — vous
avez fait Ctrl-C dans la fenêtre noire. Le portefeuille s'est déjà arrêté
proprement ; répondez ce que vous voulez. Pour fermer, préférez le bouton
« Fermer le portefeuille » de la page.

**Le port est fermé de l'extérieur alors que la règle existe** — l'adresse
locale a changé, ou le pare-feu de la machine elle-même bloque : sur Windows,
au premier lancement, une fenêtre demande d'autoriser `q21.exe` sur les
réseaux privés *et* publics ; cochez les deux.

## Pour aller plus loin

- `PORTEFEUILLE.md` — ce que le portefeuille protège, et comment le sauvegarder
- `MINAGE.md` — ce que mine votre machine, et pourquoi une machine ordinaire
  suffit
- `RESEAU.md` — les points d'entrée du réseau d'essai, et comment en tenir un
- `SERVEUR.md` — un nœud sur une machine louée, qui redémarre tout seul
- `SIGNATURE.md` — vérifier qu'une livraison vient bien du projet
