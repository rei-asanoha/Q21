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

*(Aujourd'hui, cela se déclenche encore par une option au lancement. Un bouton
« Miner » dans la page du portefeuille est en cours de construction — c'est
précisément ce document qui explique pourquoi il est important.)*

### La machine

| Ce qu'il faut | Détail |
|---|---|
| **N'importe quel PC ou Mac** | De bureau ou portable, Windows, macOS ou Linux |
| **4 Go de mémoire vive au minimum** | 8 Go sont confortables. C'est le dictionnaire qui les mange |
| **Pas de carte graphique** | Elle ne sert à rien ici. C'est la mémoire qui travaille |
| **Une connexion internet ordinaire** | Le trafic est modeste |

C'est tout. Pas de matériel à acheter, pas de machine dédiée. L'ordinateur sur
lequel vous lisez cette page convient probablement.

> ⚠️ **Prévoyez de la mémoire pour l'avenir.** Le dictionnaire monte à 8 Go en
> cinq à six ans. Une machine à 8 Go de mémoire vive suffira longtemps, mais pas
> éternellement. Une machine qui ne mine pas, elle, n'aura jamais besoin que du
> petit carnet — 64 Mo aujourd'hui, 256 Mo au maximum.

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
