# La vie de Q21, calculée

Ce document ne raconte rien : il imprime ce que rendent les fonctions de
consensus, appelées hauteur par hauteur. Tous les chiffres viennent de
`cargo run --release --example projection`, qui appelle **le même code que le
validateur**. Une divergence entre ce tableau et le réseau serait un défaut du
réseau, pas du tableau.

Deux exceptions, marquées comme telles : le débit d'une machine « moyenne »
(400 000 essais/s) et sa consommation (80 W) sont des hypothèses. Tout ce qui en
dépend est signalé.

---

## 1 · Combien de temps la chaîne émet-elle ?

Q21 n'a pas de division par deux tous les quatre ans. La récompense est
multipliée par 0,99715550 **tous les 4 320 blocs**, soit environ tous les six
jours. Une décroissance douce, sans marche d'escalier.

L'effet cumulé est pourtant familier :

> **La récompense est divisée par deux tous les 4,01 ans.**

Presque exactement le rythme de Bitcoin — mais étalé, au lieu d'être concentré
sur un instant qui secoue tout le marché du minage d'un coup.

### Année par année

| Année | Par bloc | En circulation | Du plafond |
|---:|---:|---:|---:|
| 1 | 11,6551 | 3 205 422 | 15,26 % |
| 2 | 9,7961 | 6 016 430 | 28,65 % |
| 3 | 8,2336 | 8 379 918 | 39,90 % |
| 4 | 6,9203 | 10 367 132 | 49,37 % |
| 5 | 5,8165 | 12 037 975 | 57,32 % |
| 8 | 3,4536 | 15 617 136 | 74,37 % |
| 10 | 2,4467 | 17 154 241 | 81,69 % |
| 15 | 1,0263 | 19 304 086 | 91,92 % |
| 20 | 0,4317 | 20 207 445 | 96,23 % |
| 30 | 0,0762 | 20 746 536 | 98,79 % |
| 50 | 0,0024 | 20 858 520 | 99,33 % |
| 100 | 0 | 20 862 102 | 99,34 % |

### Les seuils

| Étape | Bloc | Date |
|---|---:|---:|
| Moitié du plafond émise | 1 071 360 | **4,1 ans** |
| Trois quarts | 2 147 040 | **8,2 ans** |
| 90 % | 3 598 560 | **13,7 ans** |
| 99 % | 8 605 440 | **32,7 ans** |
| Récompense de bloc nulle | 23 902 560 | **90,9 ans** |

### Le plafond n'est jamais atteint, et c'est net

À l'année 91, la récompense de base tombe sous l'unité indivisible et devient
**zéro**. À cet instant, **20 862 102 Q21** ont été émis sur 21 000 001.

**137 899 Q21 ne seront jamais créés**, soit 0,66 % du plafond.

Ce n'est pas un défaut, c'est la conséquence arithmétique d'une décroissance
géométrique tronquée à l'entier : la somme tend vers le plafond sans l'atteindre,
et la troncature arrête le processus avant l'asymptote. La constante
`MAX_SUPPLY` est donc bien ce qu'elle annonce — un **plafond**, une borne que
rien ne peut franchir — et non une prédiction de ce qui existera.

Après l'année 91, un mineur ne vit plus que des frais de transaction. C'est le
même horizon que Bitcoin, à quelques décennies près, et le même problème ouvert :
personne ne sait encore si les frais seuls suffisent à payer la sécurité d'une
chaîne.

---

## 2 · Quinze millions de personnes : ce qui tient, ce qui casse

C'est le scénario demandé : adoption très forte, Q21 dans les dix cryptomonnaies
les plus minées. Trois choses se passent, et elles ne vont pas dans le même sens.

### Ce qui tient très bien : la sécurité

| Mineurs | Puissance du réseau | Puissance électrique |
|---:|---:|---:|
| 1 000 | 4,0 × 10⁸ essais/s | 0,08 MW |
| 100 000 | 4,0 × 10¹⁰ essais/s | 8 MW |
| 1 000 000 | 4,0 × 10¹¹ essais/s | 0,08 GW |
| **15 000 000** | **6,0 × 10¹² essais/s** | **1,20 GW** |

*(Hypothèse : 400 000 essais/s et 80 W par machine.)*

1,20 GW en continu, soit environ **10,5 TWh par an**. Pour comparaison, le réseau
Bitcoin consommait **138 TWh par an** en juillet 2026 selon l'indice de
Cambridge. Q21 à quinze millions de mineurs consommerait donc **treize fois
moins que Bitcoin aujourd'hui**, tout en étant miné par bien plus de monde.

La raison est la même que celle de tout le projet : une machine à miner du
Bitcoin brûle 3 500 W parce qu'elle ne fait que calculer. Une machine qui attend
sa mémoire ne consomme pas grand-chose — elle attend.

Et attaquer une telle chaîne demanderait de rassembler l'équivalent de quinze
millions de machines **avec leur mémoire**. C'est précisément ce qu'on ne peut
pas acheter en une commande de puces dédiées.

### Ce qui change de nature : le minage solitaire disparaît

| Mineurs | Un bloc à soi tous les |
|---:|---:|
| 1 000 | 1,4 jour |
| 100 000 | 139 jours |
| 1 000 000 | 3,8 ans |
| **15 000 000** | **57 ans** |

À quinze millions de participants, un particulier seul gagne un bloc **tous les
cinquante-sept ans**. Ce n'est plus un revenu, c'est un billet de loterie.

La réponse universelle à ce problème est le regroupement : mille, dix mille,
cent mille mineurs mettent leur puissance en commun et partagent les gains au
prorata. Un groupement de cent mille membres gagne un bloc toutes les cinq
heures et verse à chacun sa part, petite mais régulière.

> ⚠️ **C'est le risque de centralisation qui reste, et il est réel.** La
> conception de Q21 empêche qu'une fonderie de puces prenne le réseau. Elle
> n'empêche pas que trois ou quatre grands groupements finissent par diriger la
> majorité de la puissance — c'est exactement ce qui est arrivé à Bitcoin, sans
> ASIC pour l'expliquer.
>
> Ce problème n'est pas résolu dans Q21 aujourd'hui. Il est identifié, et il
> devra l'être avant tout réseau principal.

### Ce qui casse : la capacité

C'est le mur, et il faut le regarder en face.

Une signature ML-DSA-87 pèse **4 627 octets** là où une signature ECDSA en pèse
71. Une transaction simple, mesurée en construisant une vraie transaction signée,
pèse **7 361 octets** — soit environ **trente fois** une transaction Bitcoin.

| Grandeur | Valeur |
|---|---:|
| Taille maximale d'un bloc | 4 Mio |
| Transactions par bloc | **569** |
| Transactions par seconde | **4,74** |
| Transactions par jour | 409 680 |

À ce débit :

| Porteurs | Une transaction chacun tous les |
|---:|---:|
| 1 000 000 | 2,4 jours |
| **15 000 000** | **36,6 jours** |
| 100 000 000 | 244 jours |

**Quinze millions de personnes ne peuvent pas se servir de cette chaîne comme
d'un moyen de paiement.** Une transaction par personne et par mois, c'est le
rythme d'un notaire, pas celui d'un porte-monnaie.

Et le prix de l'élargir est brutal. Pour que quinze millions de personnes fassent
une transaction par semaine, il faudrait des blocs de **21 Mio** — et la chaîne
grossirait de **5,2 Tio par an**. Aucune machine domestique ne suivrait, et le
réseau se réduirait aux quelques-uns capables de la stocker : la centralisation
par le stockage, qui est exactement ce que Bitcoin a refusé en gardant ses blocs
petits.

### Le disque, aujourd'hui

Avec les blocs actuels et s'ils étaient pleins :

| | |
|---|---:|
| Par jour | 2,81 Gio |
| Par an | **1,00 Tio** |
| Corps de blocs conservés (fenêtre de réorganisation) | 3,94 Gio |

Un nœud qui ne garde que ce qui est nécessaire à la validation vit donc avec
quelques gigaoctets ; un nœud d'archive paie un téraoctet par an de pleine
charge.

### La conclusion honnête

**Q21, tel qu'il est aujourd'hui, est une couche de règlement, pas une couche de
paiement.** À quinze millions d'utilisateurs, il peut servir à déplacer des
sommes qui justifient d'attendre, pas à payer un café.

Trois voies existent pour dépasser ce mur, et aucune n'est écrite :

1. **Agréger les signatures.** ML-DSA ne s'agrège pas ; il faudrait un autre
   schéma post-quantique, et le protocole a été conçu pour pouvoir en changer —
   c'est tout le sens de l'identifiant de schéma inscrit dans chaque adresse.
2. **Une seconde couche**, où l'essentiel des échanges se règle hors chaîne.
3. **Des blocs plus gros**, au prix du stockage et de la centralisation qu'il
   entraîne.

Le choix n'a pas à être fait maintenant. Il doit être fait **avant** de
prétendre à quinze millions d'utilisateurs, et pas après.

---

## 3 · Ce que le mineur doit détenir, année par année

La table de preuve de travail grandit de 5 % par époque de 71,1 jours, jusqu'à un
plafond de 8 Gio.

| Année | Époque | Table (mineur) | Cache (tout nœud) |
|---:|---:|---:|---:|
| 0 | 0 | 2,00 Gio | 64 Mio |
| 1 | 5 | 2,55 Gio | 82 Mio |
| 2 | 10 | 3,26 Gio | 104 Mio |
| 3 | 15 | 4,16 Gio | 133 Mio |
| 4 | 20 | 5,31 Gio | 170 Mio |
| 5 | 25 | 6,77 Gio | 217 Mio |
| **6** | 30 | **8,00 Gio** | **256 Mio** |
| 10 et au-delà | — | 8,00 Gio | 256 Mio |

Deux lectures :

- **Une machine à 8 Go de mémoire vive devient juste vers la quatrième année**,
  et insuffisante vers la sixième. Qui veut miner sur dix ans prend 16 Go.
- **Un nœud qui ne mine pas n'atteint jamais que 256 Mio.** Vérifier reste à la
  portée de n'importe quoi, y compris d'un Raspberry Pi, pour toujours.

C'est une asymétrie voulue : le coût d'entrée du minage monte, celui de la
vérification presque pas. Une chaîne dont la vérification devient chère est une
chaîne dont plus personne ne vérifie.

---

## 4 · Les cinq âges, en une page

| Âge | Quand | Ce qui domine |
|---|---|---|
| **L'amorçage** | 28 premiers jours | La rampe : la récompense monte linéairement de zéro sur 20 000 blocs. Personne ne peut se précipiter sur une émission facile |
| **La jeunesse** | Jusqu'à 4 ans | La moitié des Q21 est émise. La subvention paie tout ; les frais ne comptent pas |
| **La maturité** | 4 à 14 ans | 90 % émis. La table atteint son plafond de 8 Gio à l'année 6. Les frais commencent à peser dans le revenu du mineur |
| **La longue queue** | 14 à 91 ans | Les 10 % restants s'étalent. Le revenu du mineur bascule progressivement vers les frais |
| **Après la subvention** | Au-delà de 91 ans | Plus un seul Q21 créé. 20 862 102 en circulation, définitivement. La sécurité repose entièrement sur les frais — question ouverte, ici comme ailleurs |

---

## 5 · Ce que cette projection ne dit pas

- **Le prix.** Il n'y en a pas, il n'y en aura pas sur ce réseau d'essai, et rien
  ici ne prédit quoi que ce soit à ce sujet.
- **Le nombre réel de mineurs.** Toute la section 2 dépend d'un chiffre qu'on
  choisit ; elle montre des rapports de grandeur, pas un avenir.
- **La tenue de la preuve de travail sous attaque.** Elle n'a reçu aucune
  cryptanalyse externe. Si elle tombait, toute la section 2 tomberait avec elle.
- **Les frais.** Aucun marché des frais n'a été observé, et leur évolution
  décide de tout après l'année 91.

---

*Refaire ces chiffres : `cargo run --release --example projection`.
Mesurer la taille réelle d'une transaction :
`cargo run --release --features mldsa --example bench_sig`.
Mesurer le débit de minage : `cargo run --release --example banc_minage`.*
