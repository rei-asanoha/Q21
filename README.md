# q21-core

Protocole **Q21** — phases 1 à 10 de la feuille de route du livre blanc.

Une monnaie électronique pair-à-pair conçue pour survivre à l'algorithme de Shor,
et pour être minée sur la machine que vous avez déjà.

```
Plafond absolu     21 000 001 unités
Signatures         ML-DSA (FIPS 204), adresses à schéma versionné
Preuve de travail  memory-hard à deux niveaux — 2 Gio côté mineur, 64 Mio côté nœud
Émission           décroissance continue, demi-vie ~4 ans, rampe de 20 000 blocs
Fourche            travail cumulé, finalité glissante à 720 blocs
Réseau             TCP nu, relais compact, carnet d'adresses anti-éclipse
Consultation       JSON-RPC + explorateur servis par votre propre nœud
```

**582 épreuves (597 avec ML-DSA). Zéro avertissement clippy sur la bibliothèque.
Zéro dépendance obligatoire.**

---

## Essayer

```bash
cargo build --release
Q=<chemin>/target/release/q21

mkdir a b
(cd a && $Q init regtest && $Q mine 40)
(cd b && $Q init regtest)

# terminal 1
$Q --datadir a node --listen 127.0.0.1:21031 --mine
# terminal 2
$Q --datadir b node --connect 127.0.0.1:21031

# explorateur local, dans un navigateur : http://127.0.0.1:21080
$Q --datadir a node --rpc 127.0.0.1:21080 --mine
```

Résultat observé :

```
hauteur 40 (+40)  pairs 1  mempool 0  blocs recus 0  compacts 40 dont 40 sans aller-retour
```

Quarante blocs synchronisés, **entièrement par relais compact, sans un seul
aller-retour**. Aucun message `block` n'a circulé.

---

## Phase 5 : consulter la chaîne sans faire confiance à personne

Pour consulter une chaîne, presque tout le monde ouvre aujourd'hui le site d'un
tiers. On fait donc confiance à un serveur pour savoir ce que contient un système
bâti pour ne faire confiance à personne — et ce serveur peut mentir, se tromper,
disparaître, ou être contraint.

L'explorateur de Q21 est **servi par votre nœud**, sur le bouclage local, et
n'affiche que ce que votre machine a validé. Il ne charge **aucune ressource
externe** : ni police, ni feuille de style, ni script distant. Un explorateur qui
appelle un CDN transmet à ce CDN la liste de tout ce que vous consultez. Un test
vérifie l'absence de toute URL externe dans la page.

Il affiche aussi, en clair, ce que le protocole **ne** protège **pas**. Un
explorateur qui ne montre que ce qui rassure ment par omission.

Un seul champ de recherche, qui reconnaît une hauteur, un identifiant de bloc,
un identifiant de transaction ou une adresse&nbsp;; quatre vues reliées entre
elles. La recherche d'adresse est complète quand l'index est actif, bornée
sinon — **et la page dit toujours laquelle des deux a servi**. Voir
[EXPLORATEUR.md](EXPLORATEUR.md).

```bash
./q21 explorateur      # consultation seule, index d'adresses actif
./q21 wallet           # le portefeuille sert le meme explorateur, meme port
```

### Trois décisions de sécurité, prises à la liaison et pas au premier appel

| Décision | Pourquoi |
|---|---|
| Bouclage local par défaut | Des milliers de nœuds ont été vidés parce qu'un port d'administration écoutait sur `0.0.0.0` |
| Écouter ailleurs **exige** un jeton | Le refus arrive au démarrage, pas la nuit où le port a déjà été trouvé |
| Portefeuille **désactivé** par défaut | Un port de consultation ne doit jamais devenir un port de dépense par inadvertance |

Le jeton est comparé en temps constant : une comparaison naïve laisse fuir son
préfixe par le temps de réponse.

```console
$ q21 node --rpc 0.0.0.0:21099
erreur : refus d'ecouter sur 0.0.0.0:21099 sans jeton : un port RPC accessible
depuis l'exterieur donne acces au noeud.

$ curl -sX POST localhost:21080/rpc -d '{"jsonrpc":"2.0","id":1,"method":"getbalance"}'
{"error":{"code":-2,"message":"methodes de portefeuille desactivees..."}}
```

### Aucun montant ne transite en flottant

`0.1 + 0.2 != 0.3` en IEEE 754. Un client qui relit un solde en `double` perd des
unités, et personne ne s'en aperçoit avant qu'il soit trop tard. Chaque montant
sort deux fois — entier d'unités indivisibles **et** chaîne formatée :

```json
"emis": { "unites": 1631733514, "q21": "16.31733514" }
```

Le module `json` **refuse** les flottants à l'analyse. Un test passe chaque
réponse de l'API dans cet analyseur : si l'encodeur en produisait un, le
round-trip échouerait.

### Chaînes de transactions non confirmées

La limite de la phase 4 est levée. Une transaction peut dépenser une sortie créée
par une autre transaction encore au mempool — sans quoi on ne peut pas envoyer
deux fois de suite sans attendre un bloc. Trois conséquences, toutes traitées :
validation contre une vue superposée sans copier le jeu confirmé, éviction en
paquet (retirer un parent emporte ses descendants), et sélection **topologique**
pour un bloc — un enfant placé avant son parent produirait un bloc invalide que
le mineur ne découvrirait qu'après avoir dépensé son électricité.

---

## Phase 4 : le réseau, et pourquoi le relais compact y est central

Un bloc Q21 est énorme. Une signature ML-DSA-65 pèse 3 309 octets, une clé
publique 1 952 : le témoin représente **99 %** d'une transaction. Mesuré sur une
transaction réelle à 4 entrées : 98 584 octets, dont 98 328 de témoin.

La chaîne causale que cela déclenche est le sujet du projet :

```
propagation lente → plus d'orphelins → le mineur le mieux connecté gagne les
courses → il touche PLUS que sa part de puissance → centralisation
```

C'est le rendement super-linéaire que le levier C du livre blanc cherche à
supprimer. Les récompenses d'oncles en pansent la conséquence ; **le relais
compact en attaque la cause.**

Le principe : un pair a déjà, dans son mempool, l'essentiel des transactions du
bloc qu'on lui annonce. On lui envoie donc l'en-tête et, par transaction, un
identifiant court de **six octets**. Un bloc de 200 transactions Q21 pèse ~5 Mio ;
son annonce compacte, moins de 2 Kio. Trois ordres de grandeur.

### Pourquoi l'identifiant court est à clé

Six octets, donc collisions possibles. Sans clé, un adversaire fabriquerait à
l'avance des transactions entrant en collision avec les blocs à venir et
bloquerait la reconstruction chez tout le monde. La clé dérive de l'en-tête —
donc du nonce de minage, inconnu avant que le bloc existe — **et** d'un nonce
d'émetteur, pour qu'une collision ne se reproduise pas d'un pair à l'autre.

La reconstruction se termine toujours par une vérification de la racine de
Merkle. Une collision non détectée, ou un pair malveillant, échoue là et
déclenche une redemande du bloc entier.

---

## Deux bugs trouvés en lançant de vrais nœuds

Les tests unitaires passaient tous. Le premier lancement de deux processus
séparés a affiché ceci :

```
hauteur 0 (+0)  pairs 1  blocs recus 29850
```

**29 850 blocs reçus, hauteur restée à zéro.** Deux défauts distincts.

### 1. La genèse n'était pas déterministe

`init` tirait une graine aléatoire, et la genèse était payée à une adresse de ce
portefeuille. Chaque nœud fabriquait donc **une genèse différente**, donc une
chaîne incompatible. Un test unitaire ne pouvait pas le voir : il construisait
les deux nœuds à partir du même objet genèse.

Corrigé : `genesis_block(network)` est entièrement déterministe. Le bénéficiaire
est une constante du réseau, et cette constante est l'**empreinte nulle** —
personne n'en connaît la préimage, donc la pièce de genèse est définitivement
indépensable.

Ce n'est pas un pis-aller. Le chiffre 21 000 001 dit que le compte n'est pas
soldé, et l'unité qui dépasse n'appartient à personne — surtout pas à celui qui a
lancé la chaîne. Un fondateur qui se pré-attribue la première pièce commence mal
une monnaie sans autorité.

### 2. La synchronisation bouclait à l'infini

Un bloc au parent inconnu déclenchait une redemande d'en-têtes, qui déclenchait
une demande de corps, qui arrivaient avec un parent inconnu. Boucle, à pleine
vitesse, sur du CPU et de la bande passante — un déni de service contre soi-même.

Corrigé par une synchronisation par en-têtes **stricte** : on ne demande jamais
un corps avant d'avoir vérifié que la suite d'en-têtes se rattache à la chaîne
connue *et* que chaque en-tête pointe bien sur le précédent. Un pair dont les
en-têtes ne se rattachent pas trois fois de suite est sur une autre chaîne : on
se sépare.

Les deux défauts ont maintenant leurs tests de non-régression, dont
`deux_noeuds_aux_geneses_differentes_se_separent`.

---

## Attaque à 51 % : la réponse honnête

Une protection à 100 % est **mathématiquement impossible** — un théorème, pas une
limite d'implémentation. Le consensus définit la chaîne valide comme celle qui
porte le plus de travail ; un majoritaire en produit plus que tous les autres.
Refuser sa chaîne supposerait de savoir que c'est lui : une identité, donc une
autorité. Quiconque vend une immunité au 51 % vend une autorité déguisée.

`q21 securite` détaille. En résumé :

**Il peut** réorganiser les blocs récents (annuler ses propres paiements) et
censurer.

**Il ne peut pas, même avec 99 %** : voler une pièce dont il n'a pas la clé
(protégé par la signature, pas le consensus) ; fabriquer une unité au-delà de la
subvention (chaque nœud vérifie la coinbase, seul) ; relever le plafond ; changer
une règle.

**Q21 ajoute** : choix par travail cumulé jamais par longueur, finalité glissante
à 720 blocs, pénalité de profondeur (+1 % de travail par bloc au-delà de 6),
récompenses d'oncles, et une preuve de travail pour laquelle aucun marché de
location de puissance n'existe.

**Le coût, dit franchement** : la finalité glissante ne supprime pas l'attaque,
elle en change la nature. Une partition réseau de plus de 24 h produit deux
chaînes irréconciliables. On échange une réécriture silencieuse contre une
scission visible — qui se diagnostique et se répare.

---

## Les deux mesures qui ont invalidé ma preuve de travail

**Première fois.** La version d'origine hachait à chaque accès mémoire. Le banc a
rendu **1,63×** : miner sans table ne coûtait presque rien, parce qu'un condensat
coûte autant qu'un accès DRAM aléatoire. Corrigé — le mélange ne fait plus qu'une
addition modulo 2²⁵⁶ par accès, et le rapport est monté à 6,46×.

**Deuxième fois.** Ce 6,46× avait été mesuré sur 32 Mio, qui tiennent en cache
processeur. Sur la vraie table de 2 Gio, la phase 6 a rendu un tout autre verdict :

| fraction détenue | mémoire | coût relatif |
|---|---:|---:|
| 1/1 | 2048 Mio | 1,00× |
| 1/2 | 1024 Mio | 1,98× |
| 1/8 | 256 Mio | 2,85× |
| 0 | 0 Mio | **2,86×** |

Se passer entièrement de mémoire ne coûtait que 2,86×, et au-delà de 256 Mio la
mémoire n'achetait plus rien. Un circuit dédié dont le condensat est trois fois
plus rapide qu'un processeur avait donc intérêt à n'embarquer aucune DRAM — et un
circuit SHA-256 dépasse un processeur d'un facteur ~10⁸.

La correction reprend la structure à deux niveaux d'Ethash : un **cache** généré
en chaîne (64 Mio), et des éléments de table qui ne se calculent qu'en le
parcourant 256 fois. Refuser la table ne fait plus économiser de mémoire — cela
multiplie par 256 les accès, donc la bande passante, que le silicium ne fabrique
pas.

**Le prix, dit franchement** : un nœud devait zéro octet, il doit maintenant
64 Mio, et vérifier un bloc passe de ~45 µs à ~660 µs. Rattraper dix ans de
chaîne coûte une demi-heure de preuve de travail — moins que la vérification des
signatures de la même période. C'est le compromis exact qu'a fait Ethereum.

`q21 pow mainnet` refait toute la mesure sur votre machine ; `q21 pow mainnet
--sans-table` ne mesure que le coût côté nœud. Le détail est dans `PHASE6.md`.

---

## L'erreur d'émission trouvée par le premier test

Récompense initiale annoncée : 13,847118 Q21, dérivée d'une décroissance
*continue*. Or Q21 décroît par paliers : somme de Riemann par la gauche, qui
surestime. La somme infinie théorique tombait à 21 029 899 Q21, **au-dessus du
plafond**. L'arrondi l'aurait sauvée — dépendre d'un accident arithmétique n'est
pas une garantie.

```
R0 = floor( plafond × (DEN − NUM) / (DEN × époque) ) = 1 382 743 055
```

Vérifié **à la compilation**.

---

## État

| Phase | État | Contenu |
|---|---|---|
| 1 | ✅ | Types, émission, SHA-256, Merkle, Bech32m, adresses, transactions, blocs |
| 2 | ✅ | Genèse, UTXO, validation, LWMA, mineur, stockage, portefeuille, CLI |
| 3 | ✅ | PoW memory-hard, travail cumulé, anti-réorg, oncles, banc de mesure |
| 4 | ✅ | SipHash, mempool, relais compact, TCP, sync en-têtes, nœud CLI |
| 5 | ✅ | JSON, HTTP, JSON-RPC, explorateur local, chaînes non confirmées |
| 6 | ✅ | **Mesure anti-ASIC sur 2 Gio** — verdict, correction à deux niveaux, remesure |
| 7 | ✅ | **Durabilité** : démarrage incrémental, mémoire bornée, mineur multi-fils, anti-éclipse |
| 8 | ✅ | **Audit adverse** : 11 failles réelles corrigées, portefeuille chiffré, aléa multiplateforme |
| 8b | ⬜ | Audit **humain externe** : cryptanalyse de la PoW, relecture du consensus |
| 9 | 🔨 | **Réseau d'essai ouvert** : nœud sans portefeuille, amorçage par noms, ports par réseau, vérification de la genèse. Reste à ouvrir un point d'entrée public |
| 10 | ✅ | **Une application, pas une ligne de commande** : installation et restauration dans des écrans, minage commandé depuis la page, adresses multiples, état du réseau mesuré, trois états de connexion nommés |
| 11 | ⬜ | Réseau principal — préalable : engagement UTXO (MuHash) et audit externe |

---

## Organisation

```
src/
  consensus.rs   Tous les paramètres. Invariants vérifiés à la compilation.
  emission.rs    Calendrier d'émission. Arithmétique entière stricte.
  amount.rs      Montants. Aucune conversion depuis un flottant, jamais.
  uint.rs        Entiers 256 bits, division longue comprise
  sha256.rs      SHA-256 (FIPS 180-4), vecteurs NIST
  siphash.rs     SipHash-2-4, vecteurs de référence Aumasson/Bernstein
  hash.rs        Hachage taggé, séparation de domaine (BIP-340)
  merkle.rs      Arbre de Merkle et preuves d'inclusion
  bech32.rs      Bech32m (BIP-350)
  address.rs     Adresses versionnées — mainnet / testnet / regtest
  sig.rs         Registre des schémas. Règle de consensus par réseau.
  lamport.rs     Signatures de Lamport à usage unique (testnet)
  ser.rs         Sérialisation déterministe, varints canoniques
  tx.rs          Transactions, modèle UTXO, sighash
  block.rs       En-têtes et blocs, engagement sur oncles et mineur
  memhard.rs     Preuve de travail memory-hard à table croissante
  pow.rs         Cible compacte, moteurs, calcul du travail
  utxo.rs        Jeu d'UTXO, application et annulation
  validate.rs    Règles de consensus. Une règle, un nom, un test.
  chain.rs       Genèse, LWMA, index à branches, choix de fourche, mineur
  mempool.rs     Réservoir de transactions, priorité au poids pondéré
  compact.rs     Relais de blocs compacts (BIP-152 dans l'esprit)
  wire.rs        Cadrage et messages. Toute donnée y est hostile.
  net.rs         TCP, pairs, sync en-têtes stricte, score de bannissement
  store.rs       Fichier de blocs en ajout seul, et son index de positions
  state.rs       Instantané d'état, écriture atomique, cache d'adresses
  addr.rs        Carnet d'adresses par groupe réseau, défense anti-éclipse
  rng.rs         Entropie du système, multiplateforme — échoue plutôt que
                 de rendre un aléa de qualité inconnue
  kdf.rs         HMAC-SHA256, PBKDF2, chiffrement authentifié du portefeuille
  prompt.rs      Saisie de phrase secrète sans écho
  wallet.rs      Clés déterministes, construction et signature
  json.rs        JSON minimal. Aucun flottant, par choix.
  http.rs        HTTP/1.1. Bouclage local par défaut, jeton en temps constant.
  rpc.rs         API JSON-RPC. Lecture et portefeuille strictement séparés.
  explorer.rs    Explorateur : recherche, bloc, transaction, adresse.
                 Aucune ressource externe, routage dans le fragment.
  index.rs       Index d'adresses et de transactions, facultatif.
                 Journal par bloc, chaque enregistrement contrôlé.
  amorce.rs      Par où l'on entre dans un réseau : ports, noms, amorces
  verrou.rs      Un seul q21 par dossier de données (flock, LockFileEx)
  arret.rs       Arrêt propre sur Ctrl-C, fermeture de fenêtre, SIGTERM
  bin/q21.rs     Nœud, portefeuille, explorateur et bancs en ligne de commande

PHASE6.md        Le verdict anti-ASIC : la mesure, ce qu'elle a détruit,
                 et la correction à deux niveaux
PHASE7.md        Ce qui permet à une chaîne de durer : les cinq murs du
                 démarrage, de la mémoire, du minage et de la découverte
AUDIT.md         L'audit adverse : onze failles réelles, dont le plafond
                 de 21 000 001 qui n'en était pas un — et la fabrique de clés
PORTEFEUILLE.md  Le portefeuille, et les treize défauts qu'un premier
                 utilisateur a trouvés en s'en servant vraiment
EXPLORATEUR.md   L'explorateur, l'index d'adresses, et pourquoi il est
                 facultatif
RESEAU.md        Rejoindre le réseau d'essai, et tenir un point d'entrée
SERVEUR.md       Monter le point d'entrée pas à pas, depuis le Mac, pour
                 qui n'a jamais administré un serveur
SERVEUR-WINDOWS.md  Le même chemin, depuis PowerShell
MINAGE.md        Miner du Q21 expliqué sans jargon : ce qu'il faut, ce que
                 ça coûte, et pourquoi une machine ordinaire suffit
PROJECTION.md    La vie de la chaîne, calculée par le code de consensus :
                 émission sur cent ans, capacité, et le mur des 4,74 tx/s
AUDIT-2026.md    La chaîne face à l'état de l'art 2026 : où elle est devant,
                 où est le mur de la vitesse, et les axes classés par horizon
LIVRE-BLANC.md   Ce que Q21 corrige, comment, et ce qui reste supposé

outils/
  verif-mldsa/   Programme jetable pour découvrir l'API réelle du crate ml-dsa

vendor/          Sources de ml-dsa et de ses 25 dépendances transitives,
                 apportées par `cargo vendor`. Compilation hors ligne,
                 sommes de contrôle vérifiées par cargo à chaque build.
```

---

## L'API en deux commandes

```bash
q21 node --rpc 127.0.0.1:21080

curl -sX POST localhost:21080/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"listmethods"}'
```

Quatorze méthodes. `getsecurity` renvoie, en données structurées, ce qu'un
attaquant majoritaire peut et ne peut pas faire — y compris
`"protection_100_pourcent_possible": false`.

---

## Les signatures sont du ML-DSA

```bash
cargo build --release --features mldsa
q21 init regtest mldsa65
```

Le protocole reconnaît quatre schémas, dont l'identifiant est inscrit dans
l'adresse elle-même — ajouter un schéma est une évolution, jamais une rupture :

| id | schéma | clé publique | signature | réseau principal |
|---:|--------|-------------:|----------:|:-----------------|
| 1 | ML-DSA-65 | 1 952 o | 3 309 o | oui, par défaut |
| 2 | ML-DSA-87 | 2 592 o | 4 627 o | oui |
| 3 | SPHINCS+ | — | — | déclaré, non implémenté |
| 4 | Lamport OTS | 16 384 o | 8 192 o | **interdit** |

ML-DSA n'est pas implémenté ici : écrire soi-même un schéma à réseaux
euclidiens est une faute professionnelle. Le noyau se limite à l'interface et
s'adosse au crate `ml-dsa` 0.1.1 de RustCrypto, sans ses features `getrandom` ni
`pkcs8` — un nœud vérifie, il ne signe pas.

Les tailles ci-dessus ne sont plus annoncées mais mesurées, et la clé dérivée
d'une graine connue est comparée octet pour octet au fichier PKCS#8 publié par
RustCrypto (`sig::epreuves_mldsa::la_clef_derivee_correspond_au_vecteur_externe`).

Vérification, sur un cœur : **5 200 signatures/s** en ML-DSA-65, 3 300 en
ML-DSA-87. Un bloc de 2 Mio en porte au plus ~380 : environ 73 ms de
vérification, loin devant le temps de propagation.

Lamport (1979) reste disponible sur les réseaux de test. Il signe **une fois** —
réutiliser une clé révèle la clé privée — et son interdiction sur le réseau
principal est une règle de consensus, pas une recommandation :
`SchemeId::allowed_on(Network::Mainnet) == false`.

---

## Ce qui permet à la chaîne de durer

Démarrer un nœud revalidait toute la chaîne. Sur 60 000 blocs de test :
**31,4 secondes**, et des heures sur un million. Trois murs successifs, chacun
désigné par la mesure et non par l'intuition :

| | avant | après |
|---|---:|---:|
| démarrage, 60 000 blocs | 31,4 s | **0,83 s** |
| dont dérivation du portefeuille | 20,9 s | 0,02 s |
| dont chaîne | 10,3 s | 0,53 s |
| corps de blocs en mémoire | toute la chaîne | 1 008 blocs |

L'état obtenu est **identique** — hauteur, tête, travail cumulé, émission,
solde — que l'on reprenne sur instantané ou que l'on revalide depuis la genèse.
Un test le vérifie.

Le mineur de référence utilise désormais tous les cœurs, **en rendant le même
nonce qu'une boucle séquentielle** : 1,95× sur deux cœurs, 97,5 % d'efficacité.
Un mineur mono-fil aurait offert un facteur huit à quiconque écrit le sien.

Et le nœud sait enfin trouver ses pairs — sans se laisser isoler. Le carnet
d'adresses est rangé par groupe réseau `/16`, et la sélection n'en retient jamais
deux du même groupe. Dix mille adresses insérées dans une seule plage face à
quatre pairs honnêtes :

```
sélection : 5 adresses — les quatre honnêtes, plus UNE de l'attaquant
```

Le détail, et le défaut sérieux que seuls deux vrais processus ont pu révéler,
sont dans `PHASE7.md`.

---

## Ce que l'audit adverse a trouvé

Deux auditeurs indépendants ont reçu une consigne unique : **casser Q21**, et
démontrer chaque trouvaille par un test exécutable. Ils ont trouvé **onze failles
réelles**. Les deux plus graves :

**Un oncle ne coûtait aucun travail.** Sa preuve de travail était vérifiée contre
une difficulté que son auteur choisissait lui-même. Un en-tête à `nonce` zéro se
faisait payer : *« bloc 5 émet 725 937 au lieu de 345 685, ×2,10 »*.

**Le plafond de 21 000 001 n'était pas un plafond.** Les parts d'oncles étaient
*ajoutées* à la subvention, et rien ne comparait jamais l'émission cumulée au
plafond. L'émission maximale réelle du protocole était de **44 099 999 Q21** —
même sans attaquant.

Les deux sont corrigées, et le plafond tient maintenant à deux niveaux : un bloc
émet **exactement** sa subvention quoi qu'il contienne, et une règle de consensus
refuse tout bloc qui porterait l'émission cumulée au-delà de `MAX_SUPPLY`. Elle
ne dépend d'aucun calendrier : même si une règle économique se révélait fausse,
aucun bloc ne peut franchir 21 000 001 Q21.

Chaque exploit est devenu une épreuve de non-régression. Le détail des onze
failles — dont deux amplifications réseau, une scission silencieuse par collision
d'identifiants de coinbase, et une boucle infinie de réorganisation — est dans
`AUDIT.md`.

---

## La fabrique de clés

Une clé privée ne vaut que son aléa. C'est le maillon le plus court de toute la
chaîne, et celui qu'on regarde le moins.

| | avant | après |
|---|---|---|
| générateur | `/dev/urandom` — **échouait sous Windows** | API système sur chaque plateforme, et **échec plutôt qu'aléa douteux** |
| graine sur disque | **en clair**, permissions par défaut | chiffrée, authentifiée, `0600` |
| sauvegarde | 64 caractères hexadécimaux, aucun contrôle | Bech32m, somme de contrôle |

```
rq21seed18zpjwkqmz5kvhxk2vw6fnzek3js5dzk3w7stkx66jfugyfsflemsjlt3za
```

Un test substitue chaque caractère du code par sept autres : les 400 fautes de
frappe sont détectées, aucune ne passe. `q21 restore <code>` reconstitue le
portefeuille — vérifié de bout en bout.

Le chiffrement n'invente aucune primitive : PBKDF2-HMAC-SHA256 et un flot HMAC en
mode compteur, au-dessus d'un SHA-256 vérifié. HMAC passe quatre vecteurs
officiels du RFC 4231, PBKDF2 celui du RFC 7914. Un test modifie **chaque octet**
du fichier scellé : tous sont détectés.

---

## Limites connues

- **ML-DSA repose sur un crate non audité formellement.** `ml-dsa` 0.1.1 est une version 0.x. Elle passe les vecteurs de la référence, mais aucune revue de canaux auxiliaires publique ne la couvre. Le côté signature vit dans le portefeuille, pas dans le consensus, ce qui limite l'exposition — mais ne l'annule pas.
- **SPHINCS+ est déclaré et non implémenté.** Le parachute n'existe pour l'instant que dans la table des identifiants. Un portefeuille qui le demande est refusé à la construction, pas à la dépense.
- **PBKDF2 n'est pas memory-hard.** Un attaquant équipé de circuits dédiés teste les phrases secrètes bien plus vite qu'un processeur. La vraie défense reste la longueur de la phrase.
- **L'incitation à inclure les oncles est faible.** Dans une monnaie à plafond fixe, une récompense d'oncle est soit inflationniste, soit prélevée sur le mineur. Le plafond est le projet ; c'est une question économique ouverte.
- **Aucun nœud d'amorçage n'est câblé.** La découverte de pairs fonctionne, mais la première adresse doit venir de `--connect`. Ce sera une décision de lancement, pas de code.
- **L'archive de blocs ne s'élague pas.** La mémoire est bornée depuis la phase 7, le disque ne l'est pas encore.
- **Pas de limite par groupe réseau sur les connexions entrantes.** La diversité est imposée aux connexions sortantes seulement.
- **PoW sans cryptanalyse externe.** La phase 6 a mesuré 2 Gio et corrigé une faille réelle, mais la mesure reste celle de son auteur, sur une machine, contre une implémentation de référence — pas contre une implémentation optimisée par quelqu'un dont le métier est de la battre.
- **Minage en rafale.** Au-delà de ~7 200 blocs d'un coup, les horodatages dépassent la tolérance de 2 h.

---

## Avertissement

Code de recherche. Non audité. Ne protège aucune valeur réelle. Le réseau
principal n'existe pas et `q21 init mainnet` refuse volontairement de le créer.

Licence : MIT OR Apache-2.0.
