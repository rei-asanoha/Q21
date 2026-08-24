# Q21 — livre blanc

**Une chaîne de blocs à signatures post-quantiques, minable par des gens.**

Version de travail. Code de recherche, non audité par un tiers. Aucun Q21
n'a de valeur, et n'en aura aucune avant que ce document cesse de porter cet
avertissement.

---

## 1. Ce qui est en cause

Bitcoin a résolu un problème que personne n'avait résolu : se mettre d'accord,
sans autorité, sur qui possède quoi. Cette partie tient, et Q21 ne la retouche
pas.

Trois choses, en revanche, ne sont pas des défauts de conception mais des dettes
d'époque — des choix faits en 2008, corrects alors, devenus des impasses depuis.

| Ce qui coince | Pourquoi ce n'est plus réparable dans Bitcoin |
|---|---|
| Les signatures ECDSA tombent devant l'algorithme de Shor | Le format d'adresse d'origine n'a jamais envisagé qu'un autre schéma existe |
| Le minage est passé aux fonderies de silicium | SHA-256 est exactement ce qu'un circuit dédié fait le mieux |
| Le plafond de 21 000 000 est arrivé par tâtonnement | Il est devenu un totem qu'on ne peut plus discuter |

Q21 n'est pas une bifurcation de Bitcoin. C'est une chaîne écrite depuis zéro,
qui reprend ses fondements et corrige ces trois points-là.

---

## 2. Ce que Q21 ne change pas

Il faut le dire aussi clairement que le reste, parce qu'un projet qui prétend
tout réinventer ne réinvente rien.

- **La preuve de travail** comme mécanisme d'accord. Pas de preuve d'enjeu :
  celle-ci fait dépendre le droit de décider de ce qu'on possède déjà.
- **Le modèle UTXO** : des pièces, pas des comptes.
- **La chaîne la plus travaillée l'emporte.**
- **Chaque nœud valide tout lui-même.** Un client léger demande à un serveur ce
  que contient la chaîne — c'est-à-dire qu'il fait confiance à quelqu'un, dans
  un système bâti pour ne faire confiance à personne.

---

## 3. Le plafond : 21 000 001

Vingt et un millions **et une unité**.

La pièce supplémentaire est frappée une seule fois, dans le bloc de genèse, hors
du calendrier d'émission. Elle n'a aucune fonction technique.

Elle dit une chose, et une seule : **ce nombre est un paramètre, pas une
révélation.** Un plafond doit être fini, connu à l'avance, et vérifiable par
quiconque ; il n'a pas à être sacré. La pièce en trop est là pour empêcher qu'il
le devienne.

Les invariants, eux, sont vérifiés en permanence : la somme des sorties non
dépensées ne dépasse jamais ce qui a été émis, et ce qui a été émis ne dépasse
jamais le calendrier théorique à cette hauteur.

---

## 4. Les signatures : sortir de la prison

### Le problème

ECDSA repose sur la difficulté du logarithme discret. L'algorithme de Shor le
résout — en temps polynomial, sur une machine quantique suffisante. Personne ne
sait quand une telle machine existera ; tout le monde sait qu'une chaîne conçue
pour durer ne peut pas parier dessus.

Bitcoin ne peut pas simplement « changer de schéma » : ses adresses n'encodent
pas de quel schéma elles relèvent. Ajouter ML-DSA à Bitcoin demande une rupture
de chaîne et un déménagement de tous les fonds.

### La correction

**Q21 encode l'identifiant du schéma dans l'adresse elle-même.** Ajouter un
schéma devient une évolution compatible, jamais une rupture.

Le schéma retenu est **ML-DSA-87** — FIPS 204, niveau NIST 5, de l'ordre
d'AES-256. C'est le paramétrage le plus élevé que la norme définisse.

| | ECDSA | ML-DSA-87 |
|---|---|---|
| Clé publique | 33 o | 2 592 o |
| Signature | 71 o | 4 627 o |
| Résiste à Shor | non | oui |

Le prix est réel : une signature pèse 47 fois celle d'ECDSA. Il est payé
sciemment, et il commande plusieurs autres paramètres de ce document — la taille
des blocs en particulier.

### Ce que Q21 n'écrit pas lui-même

Le noyau **n'implémente pas** ML-DSA. Écrire soi-même une signature à réseaux
euclidiens est une faute professionnelle : les canaux auxiliaires,
l'échantillonnage de rejet et l'arithmétique en temps constant sont exactement le
terrain où une implémentation maison paraît correcte, passe tous les tests
fonctionnels, et fuit la clé privée.

Rappel utile : en février 2022, **Rainbow** — finaliste du concours NIST — est
tombé en un week-end sur un ordinateur portable. Quelques mois plus tard,
**SIKE** tombait en une heure sur un seul cœur. Ces schémas avaient survécu à
cinq ans d'examen public par des cryptographes professionnels.

Q21 définit l'interface et branche une implémentation auditée.

### Sur les clés de 512 bits

FIPS 204 fixe la graine à **trente-deux octets pour les trois niveaux de
sécurité**. Une graine de 512 bits demanderait de réécrire ML-DSA à la main —
précisément la seule chose que ce projet refuse de faire. La sécurité se règle
par le niveau de paramétrage, pas par la taille de la graine : c'est pourquoi
Q21 retient le niveau 5.

---

## 5. Le minage accessible : trois leviers

C'est le cœur du projet, et la partie où l'on se trompe le plus facilement.

### Le constat

Une preuve de travail dont le calcul est pur — SHA-256 — est exactement ce qu'un
circuit dédié fait le mieux. Un circuit SHA-256 dépasse un processeur d'un
facteur de l'ordre de **10⁸**. Le résultat n'est pas une hypothèse : le minage de
Bitcoin s'est concentré dans quelques fonderies et quelques régions à
électricité bon marché.

Reprendre SHA-256 comme preuve de travail reviendrait à relancer cette course.
Q21 emploie SHA-256 comme fonction de hachage — pour les identifiants, l'arbre
de Merkle, les adresses — mais **la preuve de travail est autre chose**.

### Levier A — une preuve de travail limitée par la mémoire

Le principe : rendre le calcul dépendant d'une grande table en mémoire, de sorte
que la ressource rare ne soit plus le silicium mais la **bande passante
mémoire** — la seule chose qu'un circuit dédié ne peut pas fabriquer, parce
qu'il l'achète sur le même marché que tout le monde.

**La première version était fausse, et c'est la mesure qui l'a montré.**

Chaque élément de table était dérivé par un condensat indépendant,
`élément(i) = H(graine, i)`. Sur la vraie table de 2 Gio :

| Fraction détenue | Mémoire | Coût relatif d'une tentative |
|---|---|---|
| 1/1 | 2 048 Mio | 1,00 × |
| 1/8 | 256 Mio | 2,85 × |
| **0/1** | **0 Mio** | **2,86 ×** |

Se passer **entièrement** de mémoire ne coûtait que 2,86 ×. Un circuit dont le
condensat est trois fois plus rapide qu'un processeur avait donc intérêt à
n'embarquer aucune mémoire. La propriété anti-ASIC était fausse.

Elle avait été « vérifiée » sur une table de 32 Mio, qui tenait entièrement en
cache et affichait un rassurant 6,46 ×. **Seule la mesure à la vraie taille
disait la vérité.**

### La correction, à deux niveaux

La structure reprend celle d'Ethash :

- **Le cache** — table / 32, soit 64 Mio. Généré **en chaîne** : l'élément `i`
  dépend de `i-1`, puis l'ensemble est mélangé trois fois. On ne peut pas en
  reconstruire un fragment sans reconstruire tout ce qui précède.
- **La table** — 2 Gio. Chaque élément se calcule par **256 accès aléatoires
  dépendants** au cache.

Miner sans la table ne fait donc plus économiser de la mémoire : cela multiplie
par 256 le nombre d'accès, donc la bande passante.

| Fraction détenue | Mémoire | Avant | Après |
|---|---|---|---|
| 1/1 | 2 048 Mio | 1,0 × | 1,0 × |
| 1/8 | 256 Mio | 2,85 × | 39,7 × |
| **0/1** | **0 Mio** | **2,86 ×** | **47,8 ×** |

**2,86 × → 47,8 ×**, soit un facteur 16,7 sur la propriété qui justifie tout le
reste.

### La table grandit

Sa taille croît de **5 % par époque** — une époque vaut 51 200 blocs, soit
environ 71 jours. Elle part de 2 Gio et plafonne à 8 Gio, atteints vers cinq ou
six ans.

Un circuit conçu autour d'une quantité de mémoire fixe devient médiocre dès que
la table la dépasse. **Le matériel dédié se périme donc tout seul**, sans qu'on
ait besoin de convoquer une rupture de chaîne défensive tous les six mois — ce
que Monero a dû s'infliger quatre fois entre 2018 et 2019.

### Le prix, dit franchement

Un nœud qui vérifie ne devait auparavant détenir **aucune** mémoire. Il doit
maintenant détenir le cache : **64 Mio**. Vérifier un bloc passe de ~45 µs à
~660 µs. C'est le coût exact de la correction, et c'est le même compromis
qu'Ethereum a fait.

Un mineur détient 2 Gio et reconstruit sa table une fois par époque — environ 24
minutes sur deux cœurs, tous les 71 jours.

### Levier B — une émission qui ne récompense pas d'être arrivé le premier

Les récompenses de Bitcoin sont divisées par deux d'un coup, tous les quatre
ans. Chaque division est une falaise : un choc économique daté, prévisible, et
propice à la spéculation.

Q21 décroît **en continu** : la récompense est multipliée par 0,9971555 toutes
les 4 320 blocs (~6 jours), soit une demi-vie de quatre ans. La même trajectoire
de long terme, sans falaise.

Le facteur est stocké en fraction entière — `99 715 550 / 100 000 000` — jamais
en flottant : `récompense × NUM / DEN` est reproductible bit à bit sur toute
plateforme, `récompense × 0,9971555` ne l'est pas.

S'y ajoute une **rampe de démarrage** de 20 000 blocs (~28 jours) pendant
laquelle la récompense monte linéairement depuis zéro. Sans elle, les quelques
mineurs présents la première semaine capteraient une part disproportionnée de la
masse totale.

### Levier C — payer le travail perdu

Un gros mineur gagne les courses de propagation, et touche donc **plus** que sa
part de puissance. Ce rendement super-linéaire concentre le minage sans que
personne n'attaque quoi que ce soit.

Deux mesures :

- **Le relais compact** attaque la cause : un pair a déjà la plupart des
  transactions d'un bloc dans son réservoir ; on ne lui envoie que ce qui
  manque. Mesuré sur trois nœuds réels : 200 blocs relayés sur 219 annonces sans
  aucun aller-retour.
- **Les récompenses d'oncle** pansent la conséquence : un bloc valide arrivé
  second est référencé par un bloc suivant, et son mineur reçoit **25 %** de la
  subvention. Cette part est **prélevée sur** la subvention, jamais ajoutée : le
  plafond ne bouge pas.

---

## 6. La finalité

Une réorganisation profonde est bornée à 720 blocs. Au-delà de 6 blocs de
profondeur, une branche concurrente doit apporter un surplus de travail
croissant.

Ce surplus porte sur **le travail de la fourche**, pas sur le travail cumulé
depuis la genèse. La première version faisait l'inverse : dès la hauteur 71 400
— trois mois après un lancement — aucune réorganisation de profondeur 7 ne
pouvait plus aboutir, même avec 100 % de la puissance. La finalité réelle était
de six blocs, pas de 720.

---

## 7. Les paramètres provisoires, et pourquoi ils le sont

Trois valeurs sont explicitement marquées provisoires dans le code, et le
resteront jusqu'à ce qu'un réseau réel les tranche.

| Paramètre | Valeur | Ce qui décidera |
|---|---|---|
| Intervalle de bloc | 120 s | Le taux d'orphelins mesuré. Deux minutes divisent la variance par cinq par rapport à Bitcoin, mais alourdissent la propagation — d'autant que les signatures pèsent 47 fois plus |
| Taille maximale d'un bloc | 4 Mio | 1 Mio limiterait un bloc à ~300 transactions, à cause du poids des signatures |
| Marché des frais | rudimentaire | L'usage réel |

**Ces valeurs seront confirmées par la mesure, pas par le raisonnement.** C'est
la leçon du levier A, et elle a coûté assez cher pour être appliquée partout.

---

## 8. Ce qui est mesuré, ce qui est supposé

C'est la section la plus importante de ce document.

### Mesuré

- Le coût relatif du minage sans mémoire : 47,8 ×, sur la vraie table de 2 Gio.
- L'accord entre deux systèmes d'exploitation : un PC Windows et un MacBook,
  binaires compilés séparément, d'accord au bit près sur 438 blocs, chacun
  ayant recalculé chaque signature ML-DSA-87 et chaque preuve de travail de
  l'autre.
- Le relais par un intermédiaire : trois nœuds, celui du bout n'ayant jamais
  parlé au mineur, 0 orphelin et 0 bloc invalide.
- L'amplification mémoire à la lecture d'un message : ramenée de 61 115 × à
  **zéro**.
- La conformité de bech32m aux vecteurs publiés de BIP-350, et de SipHash-2-4
  aux siens.

### Supposé

- **La preuve de travail n'a reçu aucune cryptanalyse externe.** Les mesures
  ci-dessus ont été faites par son auteur, sur une seule machine, contre une
  implémentation de référence — et non contre une implémentation optimisée par
  quelqu'un dont le métier est de la battre. Tant que cette relecture n'existe
  pas, **la propriété anti-ASIC est une hypothèse étayée, pas un acquis.**
- Le comportement sous un réseau réellement hostile.
- Le marché des frais sous charge.

### Ce qui manque avant un réseau principal

- Un **engagement sur le jeu d'UTXO** dans l'en-tête de bloc — un accumulateur
  de type MuHash. Il rendrait tout instantané vérifiable contre la preuve de
  travail. Il demande une arithmétique modulaire sur 3 072 bits, donc du code de
  consensus neuf : ce n'est pas une chose à bâcler la veille d'un lancement.
- Un **audit humain externe**.

---

## 9. La tension assumée

Une monnaie plafonnée finit par ne plus payer ses mineurs qu'avec des frais.
Personne ne sait si un marché des frais suffit à financer la sécurité d'une
chaîne sur le long terme. Bitcoin a le même problème et le repousse.

Q21 ne prétend pas l'avoir résolu. Il le note, et il le note ici plutôt que de
laisser croire qu'il n'existe pas.

---

## 10. Où en est le projet

| Phase | État | Contenu |
|---|---|---|
| 1 – 5 | fait | Types, émission, adresses, transactions, blocs, UTXO, difficulté, réseau P2P, RPC |
| 6 | fait | **Mesure anti-ASIC sur 2 Gio** — verdict, correction à deux niveaux, remesure |
| 7 | fait | Durabilité : démarrage incrémental, mémoire bornée, anti-éclipse |
| 8 | fait | **Audit adverse** : failles réelles corrigées, portefeuille chiffré |
| — | fait | Portefeuille de bureau, explorateur de chaîne, index d'adresses |
| 9 | en cours | **Réseau d'essai ouvert** — le code est prêt, il manque un point d'entrée public |
| 8b | ouvert | **Audit humain externe** : cryptanalyse de la preuve de travail |
| 10 | ouvert | Réseau principal — préalables : engagement UTXO, et l'audit ci-dessus |

---

## En une phrase

**Q21 reprend les fondements de Bitcoin, les protège contre l'ordinateur
quantique, et remet le minage à portée d'une machine ordinaire — en disant
partout ce qui est mesuré et ce qui ne l'est pas.**
