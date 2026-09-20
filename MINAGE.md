# Miner du Q21, expliqué simplement

Ce document s'adresse à quelqu'un qui n'a jamais miné et qui ne veut pas
apprendre l'informatique pour commencer. Aucune connaissance préalable n'est
supposée. Les chiffres qu'il contient ont été **mesurés**, sauf ceux marqués
comme estimés — et ils sont marqués.

---

## 1 · Miner, c'est quoi ?

Toutes les deux minutes, quelqu'un dans le réseau écrit une nouvelle page du
grand livre de comptes de Q21. Cette page s'appelle un **bloc** : elle contient
les virements que les gens se sont faits depuis la page précédente.

La question, c'est : **qui a le droit d'écrire la page ?**

Si n'importe qui pouvait, n'importe qui pourrait mentir. Alors on organise un
concours. Tous ceux qui veulent écrire la page cherchent en même temps la
solution d'une devinette. Le premier qui trouve écrit la page — et reçoit des
Q21 tout neufs en récompense.

**Miner, c'est participer à ce concours.** Rien d'autre. Votre ordinateur
cherche, en boucle, la solution de la devinette du moment.

Deux choses en découlent, et elles sont importantes :

- **On ne gagne pas à tous les coups.** On gagne parfois. Plus votre machine
  cherche vite, plus vous gagnez souvent — mais c'est du hasard, comme une
  loterie où l'on achète des billets en continu.
- **Le gagnant ne peut pas tricher.** Écrire une fausse page ne sert à rien :
  toutes les autres machines la vérifient et la rejettent. Gagner le concours
  donne le droit d'écrire une page **vraie**, pas n'importe quelle page.

---

## 2 · Pourquoi Q21 ne fait pas comme Bitcoin

C'est le cœur du projet, alors prenons le temps.

### La devinette de Bitcoin est un calcul pur

Chez Bitcoin, la devinette est un exercice de calcul mental géant : essayer des
nombres, un par un, jusqu'à en trouver un bon. Rien à retenir, rien à aller
chercher. Juste calculer, très vite.

Le problème, c'est qu'**une machine peut être construite pour ne faire que ça**.
On appelle ça un ASIC : une puce qui ne sait faire qu'un seul calcul, mais qui
le fait environ **cent millions de fois plus vite** qu'un ordinateur normal.

Le résultat est connu de tous : en 2009 on minait du Bitcoin sur son portable, en
2026 il faut un hangar climatisé, des milliers de machines spécialisées et un
contrat d'électricité industriel. Le particulier a été éjecté. Pas par une
décision, par la physique du concours.

### La devinette de Q21 est une chasse dans un dictionnaire

Q21 change la nature de la devinette.

> **Imaginez un dictionnaire de deux gigaoctets** — environ 67 millions de
> pages. Pour tenter votre chance une fois, il ne suffit pas de calculer : il
> faut **aller chercher des pages au hasard dans ce dictionnaire**, plusieurs
> fois de suite, et chaque page vous dit quelle sera la suivante à consulter.

Le calcul, lui, est rapide. Ce qui prend du temps, c'est **d'aller chercher les
pages**. Et là, quelque chose change complètement :

- Une puce spécialisée ne sait pas aller chercher une page plus vite. Aller
  chercher une donnée en mémoire prend le même temps pour tout le monde. C'est
  une limite physique, pas une question de finesse de gravure.
- Pour être rapide, la puce devrait **embarquer le dictionnaire entier**. Deux
  gigaoctets de mémoire rapide sur une puce, c'est très cher — et à ce moment-là,
  le fabricant a essentiellement construit… un ordinateur normal.

C'est ce qu'on appelle une preuve de travail **« gourmande en mémoire »**.
Ethereum a employé le même principe pendant sept ans, et il a fonctionné : on y a
miné sur des cartes graphiques ordinaires jusqu'au bout.

### Et le dictionnaire grossit

Dernière défense, et elle est automatique : **tous les 71 jours environ, le
dictionnaire grandit de 5 %.** Il part de 2 gigaoctets et monte jusqu'à 8, atteints
vers la cinquième ou sixième année.

Une machine spécialisée est conçue autour d'une quantité de mémoire figée. Quand
le dictionnaire dépasse cette quantité, la machine devient mauvaise — toute
seule, sans que personne ait rien décidé.

> Monero, une autre monnaie, a dû s'infliger quatre changements de règles en
> urgence entre 2018 et 2019 pour chasser les machines spécialisées qui
> arrivaient. Ici, c'est prévu dès le départ et cela se fait sans intervention.

### La ruse des deux niveaux

Un mineur malin pourrait dire : « je ne garde pas le dictionnaire, je recalcule
chaque page quand j'en ai besoin — j'économise 2 gigaoctets ».

Q21 rend ce calcul perdant. Le dictionnaire est fabriqué à partir d'un **petit
carnet de 64 mégaoctets**, et reconstruire **une seule page** du dictionnaire
demande de consulter le carnet **256 fois**.

Donc celui qui veut économiser de la mémoire multiplie son travail par 256. Il
n'économise rien : il paie autrement, et plus cher.

---

## 3 · Ce qu'il vous faut, concrètement

### Le logiciel

**Le même que le portefeuille.** Il n'y a pas de logiciel de minage séparé à
télécharger, pas de configuration à écrire, pas de « pool » où s'inscrire. Le
portefeuille Q21 mine.

*(L'onglet **Miner** de la page du portefeuille l'allume et l'éteint sans rien
relancer, et affiche le débit, les blocs trouvés et la mémoire réellement
occupée. L'option `--mine` au lancement reste disponible pour une machine sans
écran.)*

### La machine

> **Les chiffres de cette section sont ceux de la chaîne principale**, la seule
> pour laquelle la taille de la table est un enjeu : elle est dimensionnée pour
> qu'une machine spécialisée n'ait aucun avantage sur un ordinateur ordinaire.
>
> Sur le **réseau d'essai** — le seul ouvert aujourd'hui — la table part de
> 32 Mio et plafonne à 128 Mio. N'importe quelle machine y mine, y compris un
> Raspberry Pi ancien. Un réseau d'essai sert à éprouver le protocole, pas à
> défendre une monnaie ; lui imposer les exigences de la chaîne principale
> n'écarterait que des participants.

| Ce qu'il faut | Détail |
|---|---|
| **N'importe quel PC ou Mac** | De bureau ou portable, Windows, macOS ou Linux |
| **4 Go de mémoire vive au minimum** | 8 Go sont confortables. C'est le dictionnaire qui les mange |
| **Pas de carte graphique** | Elle ne sert à rien ici. C'est la mémoire qui travaille |
| **Une connexion internet ordinaire** | Le trafic est modeste |

C'est tout. Pas de matériel à acheter, pas de machine dédiée. L'ordinateur sur
lequel vous lisez cette page convient probablement.

> ⚠️ **Prévoyez de la mémoire pour l'avenir.** Le dictionnaire grandit de 5 %
> tous les 71 jours et **plafonne à 4 Go**, atteints vers la troisième année.
> Une machine à 8 Go de mémoire vive suffit donc pour toujours. Une machine qui
> ne mine pas, elle, n'aura jamais besoin que du petit carnet — 64 Mo
> aujourd'hui, 128 Mo au maximum.
>
> | Quand | Taille du dictionnaire |
> |---|---|
> | au lancement | 2,0 Go |
> | après 1 an | 2,6 Go |
> | après 2 ans | 3,3 Go |
> | à partir de 3 ans | 4,0 Go — et plus jamais davantage |

### Est-ce que ma machine peut miner ? Cas par cas

| La machine | Ça mine ? | Pourquoi |
|---|---|---|
| **PC de bureau, Windows 10 ou 11** | ✅ oui | Le cas normal. Plus il a de cœurs, mieux c'est |
| **Portable Windows** | ✅ oui | Voir la réserve sur les portables plus bas |
| **Mac Apple Silicon (M1 et suivants)** | ✅ oui | Mémoire unifiée très rapide : c'est du bon matériel pour ça |
| **Mac Intel** | ✅ oui | Un binaire lui est destiné |
| **PC sous Linux** | ✅ oui | Binaire `q21-linux-x86_64` |
| **Raspberry Pi 5, 16 Go** | ⚠️ oui, mais lentement | Voir plus bas |
| **Raspberry Pi 5, 8 Go** | ⚠️ oui, mais lentement | 4 Go de table, 4 Go pour le reste : ça tient, pour toujours |
| **Raspberry Pi 5, 4 Go ou moins** | ❌ non | La table seule remplit toute la mémoire |
| **Raspberry Pi 4 ou antérieur** | ❌ non | 8 Go maximum, et une mémoire bien trop lente |
| **Windows XP, Vista, 7, 8** | ❌ non | Deux raisons, toutes deux définitives — voir plus bas |
| **Un téléphone** | ❌ non | Ni la mémoire, ni le refroidissement, ni l'autorisation du système |

### Windows XP : non, et ce n'est pas une question de bonne volonté

Deux raisons indépendantes, dont chacune suffirait.

**Le langage.** Q21 est écrit en Rust, et Rust exige **Windows 10 au minimum**
pour ses cibles Windows officielles. Windows 7 et 8 sont sortis du support en
2024 ; XP l'a quitté il y a bien plus longtemps. Il n'existe donc aucun moyen
simple de fabriquer un `q21.exe` qui démarrerait sous XP.

**La mémoire.** XP est, en pratique, un système 32 bits : un programme n'y
dispose que de 2 Go d'espace d'adressage, parfois 3. La table de Q21 en réclame
**2 Go à elle seule**, et ira jusqu'à 8. Même en réécrivant tout, ça ne rentre
pas. Ce n'est pas un problème de version de système, c'est un problème
d'arithmétique.

Une machine de l'époque XP peut en revanche parfaitement recevoir un Linux 64
bits récent — et alors, si elle a assez de mémoire, elle mine.

### Le Raspberry Pi : oui, et c'est intéressant

Depuis cette version, un binaire **`q21-linux-arm64`** est fabriqué à chaque
livraison, sur une vraie machine ARM. Un Raspberry Pi 5 en 16 Go peut donc miner
sans rien compiler.

Mais soyons précis sur ce qu'il faut en attendre :

- **Sa mémoire est lente.** Le Pi 5 emploie de la LPDDR4X sur un bus étroit —
  quelques gigaoctets par seconde, là où un PC de bureau récent en fait dix fois
  plus. Or c'est exactement la ressource que la devinette consomme. Un Pi minera
  donc, mais **plusieurs fois moins vite** qu'un PC ordinaire.
- **8 Go suffisent, pour toujours.** La table plafonne à 4 Gio dès la
  troisième année, ce qui laisse autant au système et au reste.
- **Sa carte SD n'est pas infinie.** Lancez-le avec **`--elaguer`** : le
  disque ne garde alors que les huit derniers jours de blocs, et le reste se
  résume dans un instantané. Le nœud vérifie toujours tout ; il ne garde
  simplement pas ce qu'il ne relira jamais. Un explorateur, lui, doit tout
  garder — c'est le rôle du serveur, pas du Pi.
- **En revanche, pour faire tourner un nœud qui ne mine pas, un Pi est parfait**,
  et le restera : un vérificateur n'a jamais besoin que du petit carnet, 128 Mo
  au maximum, pour toujours.

C'est d'ailleurs le meilleur usage d'un Pi dans ce réseau : un point de
vérification permanent, silencieux, à trois watts.

### Le portable : oui, avec une réserve

Un portable mine très bien. Trois choses à savoir :

- **Il va chauffer et ventiler.** C'est bruyant, et cela use la machine plus vite
  qu'une bureautique tranquille.
- **Il va se brider.** Un portable réduit sa fréquence quand il chauffe. Le débit
  affiché au bout de dix minutes est le vrai, pas celui de la première minute.
- **Refermer l'écran endort la machine**, et le minage s'arrête. C'est normal.
  *(Ce geste avait aussi révélé un vrai défaut du protocole, désormais corrigé —
  voir `RESEAU.md`.)*

### Le premier démarrage est lent, et c'est normal

Au tout premier lancement, le programme **fabrique le dictionnaire**. Cela prend
plusieurs minutes, pendant lesquelles il semble ne rien faire.

Mesuré sur une machine modeste à **2 cœurs** :

| Étape | Temps |
|---|---|
| Fabriquer le petit carnet (64 Mo) | **12 secondes** |
| Fabriquer le dictionnaire (2 Go) | **9 minutes 43** |

Sur un ordinateur de bureau récent à 8 cœurs, comptez plutôt **deux à trois
minutes**. Et cela ne se refait **qu'une fois tous les 71 jours**, quand le
dictionnaire change.

---

## 4 · Combien ça rapporte ?

### Ce qui est distribué

Le réseau crée **13,82 Q21 par bloc** au démarrage, et un bloc tombe toutes les
deux minutes. Soit environ **9 955 Q21 par jour**, pour le monde entier.

Cette récompense diminue en continu : elle est multipliée par 0,9971555 tous les
6 jours environ. Pas de division brutale par deux comme chez Bitcoin — une
décroissance douce, tous les six jours, jusqu'à la limite de **21 000 001**
unités.

### Ce que vous en touchez

**Votre part, c'est la puissance de votre machine divisée par la puissance de
tout le réseau.** Rien d'autre.

Si dix personnes minent avec des machines comparables, chacune reçoit à peu près
un dixième. Si mille personnes s'y mettent, chacune reçoit un millième — la
récompense totale, elle, ne change pas.

C'est la seule chose honnête qu'on puisse dire aujourd'hui, parce que **personne
ne sait combien de gens mineront**. Toute promesse de rendement chiffré serait
une invention.

### La difficulté s'ajuste

Si beaucoup de machines arrivent, la devinette devient plus dure automatiquement,
pour que les blocs continuent à tomber toutes les deux minutes. Si des machines
partent, elle redevient plus facile.

Conséquence : **on ne peut pas accélérer le réseau en achetant du matériel.** On
peut seulement augmenter *sa propre part* du gâteau.

---

## 5 · Comment augmenter sa puissance

Dans l'ordre d'efficacité réelle :

| Ce qui aide | Pourquoi |
|---|---|
| **Plus de cœurs de processeur** | Le programme les utilise tous. Deux fois plus de cœurs ≈ deux fois plus d'essais |
| **De la mémoire plus rapide** | La devinette passe son temps à lire la mémoire. C'est le vrai goulot |
| **Une deuxième machine** | Un vieux portable qui traîne compte autant que la moitié d'un neuf |
| **Laisser tourner plus longtemps** | Miner 24 h rapporte 24 fois plus que miner 1 h |

### La mémoire : combien, et à quelle vitesse ?

C'est la question qui revient toujours, alors répondons dans l'ordre.

**Combien de mémoire faut-il ?** Ce n'est pas un chiffre fixe : le dictionnaire
grandit de 5 % tous les 71 jours, jusqu'à un plafond de 8 Gio.

| Quand | Le dictionnaire pèse | Mémoire vive à avoir |
|---|---:|---|
| Aujourd'hui | 2,0 Gio | 4 Go tient, 8 Go est confortable |
| Dans 3 ans | 4,2 Gio | **8 Go devient juste** |
| Dans 5 ans | 6,8 Gio | 8 Go ne suffit plus vraiment |
| Dans 6 ans et au-delà | 8,0 Gio (plafond) | **16 Go, définitivement** |

Autrement dit : **si vous achetez une machine pour miner sur la durée, prenez
16 Go et n'y pensez plus.** Le plafond de 8 Gio est atteint vers la sixième
année et ne bouge plus jamais ; 16 Go de mémoire vive couvrent donc toute la vie
du réseau, dictionnaire plus système.

**Faut-il beaucoup de barrettes ?** Non — il en faut **deux**, et c'est plus
important qu'on ne croit.

Les processeurs de bureau lisent la mémoire par deux canaux en parallèle. Avec
une seule barrette, un seul canal travaille et la moitié du débit est perdue.
Avec deux barrettes identiques, les deux canaux travaillent.

> **Deux barrettes de 8 Go valent mieux qu'une seule de 16 Go**, à quantité
> égale et à prix comparable. C'est le conseil le plus rentable de cette page.

Au-delà de deux, on ne gagne presque rien : les machines grand public n'ont que
deux canaux, et remplir les quatre emplacements oblige souvent la mémoire à
tourner *moins* vite. Deux barrettes est le bon compte.

**La vitesse compte-t-elle ?** Oui, et c'est probablement la variable la plus
importante après le nombre de cœurs.

Toute la conception de Q21 repose sur le fait que la devinette **attend la
mémoire** plutôt qu'elle ne calcule. De la DDR5 rapide devrait donc battre de la
DDR4 lente, à processeur égal. Deux détails techniques, pour qui veut :
c'est la **latence** qui pèse le plus (le temps d'aller chercher *une* donnée au
hasard), avant le **débit** (la quantité totale par seconde).

> ⚠️ **Ceci est une prédiction, pas une mesure.** L'effet exact de la vitesse de
> mémoire sur le débit de minage de Q21 n'a jamais été mesuré : il faudrait la
> même machine avec deux jeux de barrettes différents, ce que le banc d'essai
> actuel ne permet pas. Ce qui est mesuré, c'est le débit par cœur (84 053
> essais/s) ; ce qui est déduit de la conception, c'est que la mémoire commande.
>
> Si vous avez deux jeux de barrettes sous la main, lancer
> `cargo run --release --example banc_minage` avec l'un puis l'autre produirait
> le premier chiffre réel sur la question. Ce serait une contribution utile.

Et ce qui **n'aide pas**, contrairement à l'intuition :

- **Une carte graphique.** Elle est conçue pour calculer beaucoup en parallèle,
  pas pour aller chercher des pages au hasard dans un grand dictionnaire.
- **Un disque SSD très rapide.** Le dictionnaire vit en mémoire vive, pas sur le
  disque.
- **Acheter une machine de minage spécialisée.** Il n'en existe pas pour Q21, et
  toute la conception vise à ce qu'il n'en existe jamais.

### Ce que ça donne, mesuré

Sur la machine à 2 cœurs du banc d'essai :

```
  84 053 essais par seconde et par cœur
 191 715 essais par seconde sur les 2 cœurs
```

Un ordinateur de bureau à 8 cœurs ferait donc autour de **700 000 essais par
seconde** — quatre fois plus, pour quelques centaines d'euros de machine, et non
quelques dizaines de milliers.

*(Ces mesures viennent de `cargo run --release --example banc_minage`, que
n'importe qui peut relancer sur sa propre machine.)*

---

## 6 · Ce que ça coûte en électricité

Miner, c'est faire tourner son processeur à fond, en continu. La dépense, c'est
donc de l'électricité — et rien d'autre, puisqu'il n'y a pas de matériel à
acheter.

**Estimations** — pas des mesures, parce que la consommation dépend de votre
machine :

| Machine | Puissance en charge | Par mois, 24 h/24 | Coût mensuel (0,25 €/kWh) |
|---|---|---|---|
| Portable ordinaire | ~35 W | ~25 kWh | **~6 €** |
| PC de bureau | ~100 W | ~72 kWh | **~18 €** |
| Gros PC de bureau | ~200 W | ~144 kWh | **~36 €** |

Pour comparaison, une machine de minage Bitcoin actuelle consomme environ
**3 500 W** — soit trente-cinq fois le PC de bureau ci-dessus, à elle seule. Et
il en faut des milliers pour peser quelque chose.

Quelques remarques honnêtes :

- **Miner chauffe.** En hiver, cette chaleur remplace un peu de chauffage. En
  été, elle s'ajoute à la chaleur de la pièce.
- **Le ventilateur va tourner.** Un portable qui mine est un portable bruyant.
- **Rien n'oblige à miner en continu.** Miner le jour et arrêter la nuit
  fonctionne parfaitement ; on gagne simplement moitié moins souvent.

---

## 7 · Ce qu'il faut savoir avant de commencer

### Aucun Q21 n'a de valeur, et n'en aura jamais

Le réseau actuel est un **réseau d'essai**. Il peut être remis à zéro à tout
moment. Ce qui s'y mine n'est ni une monnaie, ni un placement, ni un actif.

Quiconque vous propose d'acheter, de vendre ou d'échanger des Q21 aujourd'hui
vous trompe.

### La preuve de travail n'a pas été relue par des experts extérieurs

C'est le point le plus important de ce document, et il est inconfortable.

Tout ce qui est expliqué en section 2 — la résistance aux machines spécialisées —
repose sur des mesures faites **par l'auteur du programme, sur sa propre
machine**, contre sa propre implémentation. Personne dont c'est le métier n'a
encore essayé de la casser.

Concevoir une preuve de travail est un exercice où l'on se trompe facilement, et
ce projet s'est déjà trompé une fois : une première version affichait des
résultats rassurants… parce qu'elle était mesurée sur un dictionnaire trop petit
pour révéler le défaut. Corrigée, elle a révélé que se passer entièrement de
mémoire ne coûtait que 2,86 fois plus cher — bien trop peu. C'est la
construction à deux niveaux décrite plus haut qui a porté ce coût à 47,8 fois.

**Donc : la résistance aux ASIC de Q21 est une hypothèse étayée, pas un fait
acquis.** L'ouverture du réseau d'essai public est aussi une invitation à venir
la casser.

### Miner ne vous fait courir aucun risque pour vos fonds

Le programme qui mine est le même que celui qui tient votre portefeuille, sur
votre machine, et vos clés n'en sortent jamais. Miner n'expose rien de plus que
faire tourner le portefeuille.

En revanche, **votre antivirus va peut-être protester**. Beaucoup d'antivirus
signalent tout logiciel qui mine comme suspect, par principe, sans distinguer
celui que vous avez lancé volontairement de celui qu'un intrus aurait installé à
votre insu. Ce n'est pas le signe d'un problème — c'est le signe qu'un antivirus
fait son travail avec une règle grossière.

---

## 8 · Résumé en dix lignes

1. Miner, c'est faire chercher à son ordinateur la solution d'une devinette.
2. Le gagnant écrit la page suivante du grand livre et reçoit des Q21 neufs.
3. Chez Bitcoin, la devinette est un calcul pur — les machines spécialisées ont
   tout emporté.
4. Chez Q21, elle oblige à fouiller un dictionnaire de 2 Go en mémoire.
5. Aller chercher une donnée en mémoire prend le même temps pour tout le monde :
   c'est ce qui protège le particulier.
6. Le dictionnaire grossit de 5 % tous les 71 jours, ce qui périme le matériel
   dédié tout seul.
7. Il faut : un PC ou un Mac ordinaire, 4 Go de mémoire, le portefeuille Q21.
8. Le premier démarrage prend quelques minutes — il fabrique le dictionnaire.
9. Le coût, c'est l'électricité : entre 6 et 36 € par mois selon la machine.
10. Rien de tout cela n'a de valeur aujourd'hui, et la résistance aux ASIC reste
    à faire vérifier par d'autres.

---

*Pour le détail technique : [LIVRE-BLANC.md](LIVRE-BLANC.md) section 5, et
`src/memhard.rs`, qui porte lui-même l'avertissement de la section 7.*
