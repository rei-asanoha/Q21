# Phase 6 — la mesure, et ce qu'elle a détruit

## Ce que cette phase devait établir

Q21 repose sur une promesse : **être miné par des gens, pas par des fonderies.**
Tout le reste — le plafond, les signatures post-quantiques, la défense contre
l'attaquant majoritaire — suppose que la puissance de minage reste distribuée.

Cette promesse n'avait jamais été mesurée sur la vraie taille de table. La
phase 6 avait un seul mandat : la mesurer, et dire la vérité sur le résultat.

## Méthode

Trois choses ont été construites avant de mesurer quoi que ce soit.

**La vraie table.** 2^26 éléments, 2 Gio, celle du réseau principal — pas les
32 Mio du testnet, qui tiennent dans le cache d'un processeur et donnent des
chiffres flatteurs.

**Une mesure à budget de temps constant.** Entre la stratégie la plus rapide et
la plus lente il y a deux ordres de grandeur ; un nombre d'essais fixe finit soit
en microsecondes soit en heures.

**Un attaquant paramétrable.** `PartialTable` modélise un mineur ne détenant
qu'une fraction *f* de la table et recalculant le reste. C'est le point
essentiel : comparer « table complète » à « aucune table » ne dit presque rien,
puisque aucun concepteur de circuit ne choisit l'un de ces deux extrêmes. Il
choisit la quantité de mémoire qui maximise son débit par euro dépensé. La
question pertinente est la **courbe**.

Comme les indices d'accès sont uniformes, conserver les *f·N* premiers éléments
donne un taux de succès de *f* : aucun élément n'est plus utile qu'un autre.

## Verdict sur la conception d'origine

```
fraction détenue   mémoire      tentatives/s   coût relatif
      1/1          2048 Mio        66 805         1,00 x
      1/2          1024 Mio        33 804         1,98 x
      1/4           512 Mio        27 596         2,42 x
      1/8           256 Mio        23 404         2,85 x
     1/16           128 Mio        23 974         2,79 x
     1/64            32 Mio        23 441         2,85 x
      0/1             0 Mio        23 372         2,86 x
```

Deux lectures, toutes deux mauvaises.

**Se passer entièrement de mémoire ne coûtait que 2,86×.** Un circuit dédié dont
le condensat est trois fois plus rapide qu'un processeur avait donc intérêt à
n'embarquer aucune DRAM. Or un circuit SHA-256 dépasse un processeur d'un facteur
de l'ordre de 10⁸. La marge était de trois. La propriété anti-ASIC n'existait
pas.

**La courbe s'aplatissait dès 256 Mio.** Au-delà, acheter de la mémoire
n'achetait plus rien. Le seuil de 2 Gio était décoratif.

La cause tient en une ligne de l'ancienne conception :

```rust
element(i) = H(graine, i)
```

Chaque élément se recalculait par un condensat unique, en O(1), sans mémoire.
C'était exactement ce qui rendait la vérification légère — et exactement ce qui
rendait la preuve de travail contournable. La même propriété servait les deux
camps, et servait mieux l'attaquant.

Le 6,46× annoncé jusque-là avait été mesuré sur 32 Mio. Tout tenait en cache
processeur. Le chiffre était vrai et ne mesurait rien.

## La correction

Structure à deux niveaux, celle d'Ethash.

**Niveau 1 — le cache.** `N / 32` éléments, soit 64 Mio sur le réseau principal.
Généré **en chaîne** : l'élément *i* dérive de *i-1*, puis trois passes de
mélange lient chaque élément à un autre désigné par son propre contenu
(RandMemoHash, Lerner 2014). On ne peut pas en reconstruire un fragment sans
reconstruire tout ce qui le précède.

**Niveau 2 — la table.** `N` éléments, 2 Gio. Chaque élément se calcule par
**256 accès aléatoires dépendants** au cache.

Refuser la table ne fait donc plus économiser de la mémoire. Cela multiplie par
256 le nombre d'accès — donc la bande passante mémoire, la seule ressource qu'un
circuit ne peut pas fabriquer avec du silicium.

| | avec table | sans table |
|---|---:|---:|
| accès mémoire par tentative | 32 | 8 192 |
| trafic mémoire par tentative | 1 Kio | 256 Kio |

## Mesure après correction

Même machine, même table de 2 Gio.

```
fraction détenue   mémoire      tentatives/s   coût relatif
      1/1          2048 Mio        73 390         1,0 x
      1/2          1024 Mio         3 265        22,5 x
      1/4           512 Mio         2 165        33,9 x
      1/8           256 Mio         1 847        39,7 x
     1/16           128 Mio         1 738        42,2 x
     1/64            32 Mio         1 663        44,1 x
      0/1             0 Mio         1 534        47,8 x
```

**2,86× → 47,8×**, soit un facteur 16,7 sur la propriété qui justifie tout le
module. Et la courbe ne s'aplatit plus prématurément : diviser la mémoire par
deux coûte déjà 22,5×.

Le palier résiduel en bas de tableau n'est pas une faiblesse : sous 64 Mio,
l'attaquant devrait régénérer le cache lui-même, ce qui est séquentiel et donc
sans commune mesure. Le plancher de mémoire réel du protocole est 64 Mio, et
c'est voulu.

## Le calibrage de POW_J

`POW_J` — le nombre d'accès au cache par élément — est le curseur. Mesuré sur la
vraie table :

| POW_J | pénalité sans table | vérification / bloc | rattrapage de 10 ans |
|---:|---:|---:|---:|
| 64 | 22,7× | 315 µs | 14 min |
| 128 | 29,8× | 413 µs | 18 min |
| 256 | **47,8×** | 658 µs | 29 min |

256 a été retenu. C'est aussi la valeur d'Ethash, ce qui n'est pas un argument
mais une convergence rassurante. Le coût de vérification reste très inférieur à
celui des signatures : rattraper dix ans de chaîne représente 29 minutes de
preuve de travail, quand la vérification des signatures ML-DSA de la même période
en demande davantage.

## Le prix, dit franchement

Ce qui a été perdu doit être écrit aussi clairement que ce qui a été gagné.

| | avant | après |
|---|---:|---:|
| mémoire d'un nœud | **0** | 64 Mio |
| vérification d'un bloc | ~45 µs | ~660 µs |
| mémoire d'un mineur | 2 Gio | 2 Gio |
| construction de la table | 95 s | 1 436 s (2 cœurs) |

Le README affirmait : *« un nœud complet n'a jamais besoin des 2 Gio »*. C'était
vrai, et c'était le problème. La gratuité de la vérification était l'exacte
mesure de la faiblesse de la preuve de travail. On ne peut pas avoir les deux.

La construction de la table est le coût du mineur, une fois par époque —
environ 71 jours. Elle se parallélise sur tous les cœurs : 24 minutes sur deux
cœurs, environ cinq sur huit.

Un test de régression verrouille désormais la propriété :
`calculer_un_element_coute_bien_plus_cher_que_le_lire` échoue si la dérivation
redevient bon marché.

## Ce que cette mesure ne prouve pas

Elle a été faite par l'auteur de la fonction, sur une seule machine, contre une
implémentation de référence — pas contre une implémentation optimisée par
quelqu'un dont le métier est de la battre.

Ce qu'elle établit : la conception précédente était réfutée, et celle-ci ne l'est
pas par la même attaque. Ce qu'elle n'établit pas : qu'aucune autre attaque
n'existe. C'est deux fois de suite qu'une mesure a détruit une conception de ce
module ; il serait naïf de supposer que la troisième n'arrivera pas.

Les deux relectures qui vaudraient plus que tout code supplémentaire :

1. **Un cryptanalyste** sur la fonction de mélange et la génération du cache.
2. **Un concepteur de circuits** sur le rapport bande passante / silicium, qui
   est le vrai terrain de la propriété anti-ASIC.

## Reproduire

```bash
cargo build --release
q21 pow mainnet                 # toute la courbe (prévoir ~30 min)
q21 pow mainnet --sans-table    # coût côté nœud seul (~15 s)
q21 pow testnet                 # version rapide, chiffres non représentatifs
```

## Paramètres gelés par cette phase

```
POW_K              32      accès à la table par tentative
POW_J             256      accès au cache par élément de table
POW_CACHE_RATIO    32      table / cache  →  2 Gio / 64 Mio
POW_CACHE_ROUNDS    3      passes de mélange à la génération du cache
```

Ces quatre valeurs sont consensuelles. Les changer après la genèse exige une
rupture de chaîne.
