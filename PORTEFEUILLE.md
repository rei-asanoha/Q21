# Le portefeuille Q21

Un logiciel de bureau pour recevoir et envoyer du Q21, sur macOS, Windows et
Linux.

## En deux commandes

```bash
./q21 init testnet     # cree le portefeuille, affiche le code de sauvegarde
./q21 wallet           # ouvre l'interface dans le navigateur
```

La première commande demande une phrase secrète, puis affiche un **code de
sauvegarde** de 66 caractères. Recopiez-le sur papier avant d'aller plus loin :
c'est le seul moyen de retrouver vos fonds si le fichier disparaît.

---

## Trois décisions, et pourquoi

### Le portefeuille embarque un nœud complet

Un client léger demande à un serveur ce que contient la chaîne. C'est-à-dire
qu'il **fait confiance à quelqu'un** pour connaître son propre solde — dans un
système conçu précisément pour ne faire confiance à personne.

Ici, le portefeuille *est* un nœud. Il valide chaque bloc lui-même. Ce que
l'écran affiche, cette machine l'a vérifié.

Le prix : au premier lancement, il télécharge et vérifie la chaîne. Sur le
testnet c'est instantané ; sur un réseau mature ce sera long. C'est le même
arbitrage que Bitcoin Core, et il penche du même côté.

### L'interface est une page servie localement

Le binaire sert une page sur `127.0.0.1` et ouvre le navigateur dessus. Aucune
bibliothèque graphique, aucun cadre applicatif, aucune dépendance nouvelle dans
un logiciel qui garde des clés privées. C'est ce que font Electrum et la plupart
des portefeuilles matériels, pour la même raison.

La page ne charge **aucune ressource externe** : ni police, ni script, ni image
venue d'ailleurs. Tout est dans le fichier, et une épreuve le vérifie.

### Le jeton voyage dans le fragment de l'adresse

L'interface a besoin d'un jeton pour parler au nœud. Le mettre dans la requête —
`?token=...` — le ferait entrer dans l'historique du navigateur, dans les
journaux de tout mandataire, et dans l'en-tête `Referer` de la première ressource
externe chargée. Un secret qui voyage dans une adresse n'est plus un secret :
c'est une faille que l'audit de la phase 8b a relevée puis fermée.

Le **fragment** — ce qui suit le `#` — n'est jamais envoyé au serveur. Le
navigateur le garde pour lui. La page le lit, l'efface aussitôt de la barre
d'adresse, et l'envoie ensuite en `Authorization`. Il ne laisse aucune trace
ailleurs que dans la mémoire de l'onglet.

Ni `localStorage`, ni cookie : les deux survivent à la fermeture du navigateur, et
un jeton qui survit à la session qu'il ouvrait est un jeton de trop. Le jeton vit
dans une variable JavaScript, doublée de `sessionStorage` — cloisonné par port,
effacé à la fermeture de l'onglet — pour la seule raison qu'un `F5` ne doit pas
couper l'utilisateur de son propre portefeuille.

---

## Ce qui protège le portefeuille

| Défense | Ce qu'elle empêche |
|---|---|
| Contrôle d'origine, de `Referer` et de `Sec-Fetch-Site` | Une page web hostile qui dépenserait vos fonds à votre insu |
| `Content-Type: application/json` exigé | La CSRF par formulaire HTML, qui ne demande aucun JavaScript |
| Contrôle de l'en-tête `Host` | La réassociation DNS, qui rendrait une page hostile de même origine |
| Jeton exigé sur toute méthode RPC | Un autre programme de la machine |
| Écoute sur la boucle locale uniquement | Le reste du réseau |

Ces cinq verrous ont été éprouvés par 42 attaques réelles, en TCP, dans
`tests/audit_rpc.rs`. Chacune était un exploit qui fonctionnait.

---

## Ce qu'un premier utilisateur a trouvé

Le portefeuille a été mis entre les mains de quelqu'un qui ne l'avait pas écrit.
En quelques heures, onze défauts sont sortis. Aucun n'aurait été trouvé
autrement. Deux autres sont apparus en reproduisant l'un de ces scénarios de
bout en bout — et deux de plus, dont le pire de la liste, le jour où le
portefeuille a tourné sur **deux machines réelles** au lieu d'une.

| # | Ce qui clochait | Correction |
|---|---|---|
| 1 | Une transaction envoyée disparaissait à l'arrêt | Le réservoir est écrit sur disque (`mempool.dat`) et revalidé à la reprise |
| 2 | **Aucun gestionnaire de Ctrl-C** : le processus était tué sans rien écrire | `src/arret.rs` — le chemin d'arrêt testé n'était pas le chemin emprunté |
| 3 | `q21 mine` ignorait le réservoir et minait des blocs vides | Les transactions en attente entrent dans les blocs minés |
| 4 | Il fallait une fenêtre de commande | *Portefeuille Q21* se double-clique |
| 5 | Rafraîchir la page cassait la session | Le jeton survit dans `sessionStorage`, cloisonné par port |
| 6 | Les lignes d'état noyaient l'adresse à ouvrir | Mode silencieux dans le portefeuille |
| 7 | L'historique n'affichait pas la somme sortie | Colonne **Sorti**, et la page ne contredit plus le nœud |
| 8 | `q21.exe` double-cliqué affichait l'aide et se refermait | Sans argument, `q21` ouvre le portefeuille |
| 9 | L'adresse n'était affichée que si le navigateur n'était pas ouvert | Elle l'est toujours |
| 10 | La phrase secrète était demandée **après** la bannière, sans rien qui l'annonce | Le déverrouillage passe avant tout le reste |
| 11 | Le seul arrêt possible était Ctrl-C, et Windows posait alors une question qui ressemblait à une panne | Bouton **Fermer le portefeuille**, méthode `arreter` |
| 12 | Deux écritures simultanées du portefeuille laissaient `wallet.seq` en avance sur `wallet.dat` — le portefeuille refusait de s'ouvrir | Verrou d'écriture en processus, et `src/verrou.rs` entre processus |
| 13 | `wallet.dat` était tronqué avant d'être réécrit : une coupure au mauvais moment perdait la graine | Écriture dans un fichier temporaire, puis renommage atomique |
| 14 | La tuile **État** affichait son propre balisage en clair | Constructeur `badge()`, et une épreuve sur chaque tuile des deux pages |
| 15 | **Un pair mort n'était jamais coupé** : le nœud restait bloqué à sa hauteur, pour toujours | `Ping` après 45 s de silence, coupure après 100 s, et reprise des amorces |
| 16 | Au réveil d'une mise en veille, il fallait attendre le délai de silence | Un tour de boucle qui dure une minute trahit une veille : on coupe tout de suite |

Le quinzième est le plus grave de toute la liste, et il n'a pu apparaître que
sur du matériel réel.

L'utilisateur a refermé l'écran de son MacBook, l'a rouvert, et **la chaîne n'a
plus jamais bougé** : hauteur 442, pendant que l'autre machine minait
jusqu'à 455. Trois virements envoyés dans l'intervalle n'y sont jamais arrivés.

La cause tient en une ligne. La boucle de lecture posait un délai de 120
secondes sur la socket, et traitait son expiration ainsi :

```rust
Err(e) if e.kind() == WouldBlock => continue,
```

C'est-à-dire : elle recommençait à attendre, indéfiniment. Un pair qui cesse
d'émettre n'était donc **jamais** retiré. Le compte de pairs restait à un, et la
boucle de maintien — qui ne cherche personne tant qu'il ne manque pas de
pairs — n'avait rien à faire.

Une connexion TCP peut survivre à la machine d'en face. Un portable qu'on
referme ne dit rien en partant : ni `FIN`, ni `RST`. Le seul signe fiable de vie
est **une trame reçue**, et c'est désormais ce qu'on mesure.

Sur un réseau public, le même défaut était une voie d'éclipse : ouvrir des
connexions puis se taire suffisait à occuper toutes les places d'un nœud.

Les douzième et treizième sont sortis d'une reproduction, pas d'un rapport. Ils
méritent d'être racontés parce qu'ils illustrent la même erreur.

Écrire le portefeuille se fait en quatre temps : lire le numéro de série,
sceller le contenu, écrire `wallet.dat`, écrire `wallet.seq`. Le scellement
coûte une dérivation Argon2id — quelques centaines de millisecondes
pendant lesquelles le numéro lu au départ vieillit. Deux
écritures concurrentes s'entrelacent alors ainsi :

```text
  fil A  lit seq=5, série=6, commence à sceller ......................
  fil B  lit seq=5, série=6, scelle, écrit wallet(6), écrit seq=6
  fil B  lit seq=6, série=7, scelle, écrit wallet(7), écrit seq=7
  fil A  ..... termine et écrit wallet(6)   <-- écrase la version 7
```

Il reste un `wallet.seq` à 7 et un `wallet.dat` à 6. Au démarrage suivant, la
protection anti-rejeu **fait exactement ce qu'on lui demande** : elle refuse
d'ouvrir le portefeuille, en annonçant une restauration depuis une sauvegarde
ancienne. Le portefeuille est intact ; l'utilisateur, lui, lit qu'il a
peut-être révélé ses clefs à usage unique.

Le même scénario existe entre deux **processus** — le portefeuille dans sa
fenêtre, `q21 mine` dans une autre — et là, ce ne sont pas seulement les deux
fichiers du portefeuille qui divergent, mais aussi `blocks.dat` et son index.
D'où deux verrous : un mutex pour les fils d'un même processus, un verrou de
fichier posé par le système (`flock`, `LockFileEx`) pour les processus entre
eux. Le second est relâché par le système quel que soit le genre de mort du
processus — c'est la raison de ne pas le fabriquer à la main avec un fichier
`.lock` portant un numéro de processus, qui laisserait un verrou fantôme après
chaque arrêt brutal.

> **Si vous rencontrez le message d'incohérence de série** sur une version
> antérieure : effacez `wallet.seq` dans le dossier de données. La graine et les
> fonds sont intacts — c'est le compteur qui a divergé, pas le portefeuille.

Le onzième mérite qu'on s'y arrête, parce qu'il n'est pas dans le code.

Un `Ctrl-C` reçu pendant un fichier `.bat` fait poser par l'interpréteur de
commandes sa propre question — « Terminer le programme de commandes (O/N) ? » —
à laquelle les deux réponses ferment la fenêtre. Elle arrive **avant** que le
script ait la main : aucune ligne du fichier ne peut l'empêcher.

Le gestionnaire d'arrêt faisait son travail. Les lignes « Arret demande.
Ecriture en cours... » puis « Arret. Hauteur finale » le prouvaient, à l'écran,
juste au-dessus. Mais l'utilisateur a lu la question de Windows comme une
erreur, et a cessé d'oser arrêter son portefeuille. Un logiciel dont on n'ose
plus se servir est cassé, quoi qu'en dise le code.

La correction n'est donc pas de faire taire Windows — c'est impossible — mais de
ne plus passer par là : une application se ferme par un bouton. Il lève le même
drapeau que `Ctrl-C`, la boucle principale le voit au tour suivant, écrit et rend
la main. Rien n'est interrompu, l'interpréteur n'a aucune question à poser.

Le deuxième est le plus instructif sur le plan technique. La persistance du
réservoir avait été écrite
**et testée** — mais uniquement sur le chemin d'arrêt des épreuves, l'expiration
de `--seconds`. Personne n'arrête un logiciel ainsi : on fait Ctrl-C. Sur ce
chemin-là, rien n'était écrit, et la correction n'aurait servi à rien.

## Ce que le portefeuille ne fait toujours pas

- **L'historique est borné.** Sans index par adresse, il remonte 5 000 blocs.
  La réponse le dit, et l'écran l'affiche.
- **Le portefeuille et le minage ne cohabitent qu'avec `--mine`.** Sans cette
  option, une transaction attend qu'on mine, et miner demande d'arrêter le
  portefeuille. `q21 wallet --mine` fait les deux à la fois.
- **Il n'y a pas de code QR** pour l'adresse de réception. La politique de
  sécurité du contenu interdit les images externes, et le dessiner en SVG reste
  à faire.
- **Les fichiers livrés ne sont ni signés ni notariés.** macOS et Windows
  afficheront un avertissement. Le contourner demande un compte Apple Developer
  payant et un certificat Authenticode. En attendant, le condensat SHA-256 de
  chaque fichier est publié avec lui.

---

## Compiler soi-même

```bash
cargo build --release --features mldsa
```

Les sources de `ml-dsa` sont dans `vendor/`, et `.cargo/config.toml` y redirige
crates.io : la compilation ne dépend d'aucun réseau, et deux compilations à deux
mois d'intervalle emploient exactement le même code de signature.

Sans la caractéristique `mldsa`, le binaire compile mais ne sait signer qu'en
Lamport — utilisable sur un réseau de test, jamais ailleurs.

## Compilation automatique

`.github/workflows/livraison.yml` construit les quatre fichiers — macOS Apple
Silicon, macOS Intel, Windows, Linux — sur de vraies machines, à chaque étiquette
de version. Aucune compilation croisée : rien n'est supposé.

`.github/workflows/essais.yml` fait tourner les épreuves sur les trois systèmes à
chaque poussée. Les trois fichiers d'audit encore ouverts — arithmétique,
difficulté, réservoir — tournent à part, sans bloquer, et leur sortie est
publiée : quiconque ouvre l'exécution voit exactement ce qui reste.

---

## Avertissement

Code de recherche. La preuve de travail memory-hard n'a reçu **aucune
cryptanalyse externe**, et l'audit qui a fermé 21 failles a été mené par les
auteurs du code sur leur propre code. Cela prouve son utilité ; cela ne prouve
rien sur ce qu'il n'a pas trouvé.

Ne confiez à ce logiciel aucune valeur réelle.
