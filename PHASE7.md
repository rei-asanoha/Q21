# Phase 7 — ce qui permet à une chaîne de durer

## Ce que cette phase devait établir

Les phases précédentes ont produit un protocole correct. Cette phase répond à une
autre question : **est-ce qu'on peut le faire tourner pendant dix ans ?**

La différence n'est pas théorique. Un nœud qu'on ne peut pas redémarrer en
quelques secondes ne sera jamais mis à jour. Un nœud dont la mémoire croît avec
la chaîne finira par mourir sur une machine ordinaire. Un mineur de référence
mono-fil offre un facteur huit à quiconque écrit le sien. Et un nœud qui ne sait
pas trouver ses pairs dépend pour toujours de qui lui a donné la première
adresse.

Quatre murs. Ils sont tombés dans cet ordre, et chacun a été **désigné par la
mesure**, jamais par l'intuition.

## Mur 1 — le démarrage revalidait tout

Jusqu'ici, démarrer signifiait rejouer la chaîne depuis la genèse. Sur 60 000
blocs de test : **31,4 secondes**. Sur un million, avec 660 µs de preuve de
travail par bloc depuis la phase 6, cela devenait des heures.

La correction reprend la séparation de Bitcoin Core entre *block files* et
*chainstate* :

- **`state.dat`** — le jeu d'UTXO, la tête, la hauteur, le total émis. Écriture
  atomique : fichier temporaire, `sync_all`, renommage. Une coupure de courant
  laisse soit l'ancien instantané, soit le nouveau, jamais un mélange.
- **`store::scan_headers`** — l'index se reconstruit en ne décodant que les 160
  octets d'en-tête de chaque enregistrement. Aucune transaction n'est lue.

**L'instantané est pris en retrait de la tête**, d'une fenêtre entière. Ce n'est
pas un détail : rejouer cette fenêtre au démarrage reconstruit les
enregistrements d'annulation, sans lesquels le nœud aurait perdu toute capacité
de réorganisation — il aurait démarré vite et incapable de suivre une fourche.

Ce que cet instantané **n'est pas** : une preuve. Le charger, c'est faire
confiance à son propre disque. La somme de contrôle attrape une corruption
accidentelle, pas un adversaire ayant accès aux fichiers — mais quiconque peut
réécrire vos fichiers a déjà gagné. Tout bloc arrivé *après* l'instantané est
validé intégralement, et un instantané illisible fait retomber sur la
revalidation complète, jamais sur une acceptation silencieuse.

## Mur 2 — le portefeuille dérivait soixante mille clés

Une fois la chaîne devenue incrémentale, la mesure a désigné un autre coupable :

```
[chrono] portefeuille       20,86 s
[chrono] balayage en-tetes   0,18 s
[chrono] chaine prete        0,53 s
```

La chaîne était réglée. Le portefeuille, lui, redérivait ses 60 001 adresses à
chaque démarrage — et une dérivation ML-DSA n'est pas un condensat.

`addresses.dat` met en cache les empreintes déjà dérivées. Ce fichier ne contient
aucun secret — une empreinte de clé publique est publique — et il n'est pas cru
sur parole : le portefeuille **resonde la première et la dernière**. Deux
dérivations au lieu de soixante mille, et un cache issu d'une autre graine ou
d'un autre schéma est rejeté.

**20,86 s → 0,02 s.**

## Mur 3 — le solde était quadratique

Il restait vingt secondes, cette fois *après* le chargement. `spendable_for`
parcourait tout le jeu d'UTXO pour **chaque** adresse interrogée : soixante mille
adresses sur soixante mille sorties, soit plusieurs milliards de comparaisons
pour afficher un solde.

Un index dérivé — empreinte de clé publique vers sorties — a supprimé le
problème. Il est entièrement reconstructible et n'entre pas dans l'égalité de
deux jeux d'UTXO : deux ensembles identiques le restent quel que soit l'ordre de
construction.

### Le bilan des trois premiers murs

| | avant | après |
|---|---:|---:|
| démarrage, 60 000 blocs | 31,4 s | **0,83 s** |
| dont portefeuille | 20,9 s | 0,02 s |
| dont chaîne | 10,3 s | 0,53 s |
| corps de blocs en mémoire | toute la chaîne | 1 008 blocs |

Et l'état obtenu est **identique** — hauteur, tête, travail cumulé, émission,
solde — que l'on reprenne sur instantané ou que l'on revalide depuis la genèse.
C'est vérifié par un test, pas par une inspection.

## Le défaut que seuls deux vrais processus pouvaient montrer

Borner la mémoire a introduit un défaut sérieux, et invisible en test unitaire.

L'index des positions de blocs sur disque était construit **une fois au
démarrage**. Les blocs minés ou reçus ensuite n'y entraient jamais. Tant qu'ils
restaient dans la fenêtre mémoire, tout allait bien ; dès qu'ils en sortaient, le
nœud ne savait plus les servir.

Symptôme observé en lançant deux vrais processus : un nœud rejoignant une chaîne
en cours de minage recevait des milliers de blocs, **tous orphelins**, et restait
indéfiniment à la hauteur zéro. Son pair ne pouvait plus lui fournir les premiers
blocs, donc rien ne pouvait s'attacher.

```
hauteur 0 (+0)  compacts 3346 dont 3346 sans aller-retour  orphelins 3346
```

La correction est un type, `BlockArchive`, qui possède le fichier **et** son
index, et où écrire et indexer ne sont plus deux gestes séparables. Après :

```
hauteur 7229 (+2)  compacts 21189  orphelins 983
```

Le nœud rattrape une chaîne minée à 250 blocs/s, et le compteur d'orphelins se
stabilise au lieu de s'emballer. Ce compteur est d'ailleurs l'un des ajouts de
cette phase : sans instrumentation, ce défaut se serait présenté comme « ça ne
marche pas ».

C'est la quatrième fois sur ce projet qu'un défaut sérieux n'apparaît qu'en
exécutant de vrais processus. Les tests unitaires ne mentent pas sur ce qu'ils
testent ; ils se taisent sur le reste.

## Mur 4 — le mineur de référence était mono-fil

Sur une machine à huit cœurs, un mineur mono-fil laisse sept huitièmes de la
machine inutilisés. Quiconque prend une après-midi pour écrire un mineur
parallèle obtient huit fois le débit des gens ordinaires. Pour un projet dont la
raison d'être est que le minage reste accessible, c'est une contradiction, pas
une optimisation manquante.

Un mineur parallèle naïf rend le premier nonce trouvé — donc un nonce qui dépend
de l'ordonnancement des fils, et deux exécutions produisent deux blocs
différents. Ici la recherche avance par **vagues** : les fils balaient ensemble
un intervalle contigu de nonces, on attend la fin de la vague, et l'on retient le
**plus petit** nonce gagnant. Le résultat est exactement celui d'une boucle
séquentielle.

```
coeurs disponibles : 2
1 fil(s) :     156 741 tentatives/s   accélération 1,00 x   nonce 183386
2 fil(s) :     305 382 tentatives/s   accélération 1,95 x   nonce 183386
```

97,5 % d'efficacité, et **le même nonce**. C'est cette propriété qui permet aux
épreuves de comparer deux chaînes minées indépendamment.

## Mur 5 — le nœud ne savait pas trouver ses pairs

Une attaque par éclipse ne casse aucune cryptographie : elle **isole**. Si toutes
les connexions d'un nœud aboutissent à des machines contrôlées par la même
personne, ce nœud ne voit plus le vrai réseau. On peut lui cacher des blocs, lui
montrer une chaîne fabriquée, lui faire accepter un paiement déjà dépensé
ailleurs. Il vérifiera parfaitement des blocs qui ne sont adressés qu'à lui.

C'est l'attaque la plus rentable contre une petite chaîne, et Q21 en sera une.

Jusqu'ici, les adresses reçues étaient purement et simplement ignorées
(`Message::Addr(_) => {}`). Un nœud ne connaissait que ce qu'on lui avait donné à
la main.

La défense suit l'asymétrie réelle : un adversaire obtient facilement des
milliers d'adresses IP, mais rarement dans des milliers de plages différentes.

- le carnet est **rangé par groupe réseau** (`/16`), plafonné par groupe ;
- la sélection ne rend **jamais deux adresses du même groupe**, ni une adresse
  d'un groupe déjà représenté parmi les pairs connectés.

Un test le vérifie sur l'attaque elle-même : dix mille adresses insérées dans un
seul `/16` face à quatre pairs honnêtes dans quatre plages distinctes.

```
sélection : 5 adresses — les quatre honnêtes, plus UNE de l'attaquant
```

Détenir dix mille adresses dans une plage vaut donc exactement autant que d'en
détenir une. Pour peser, il faut posséder des plages entières : cela se compte en
argent et en traces administratives, pas en scripts.

Le carnet survit à l'arrêt (`peers.dat`). Sans cela, chaque redémarrage
repartirait du point d'amorçage — et donnerait à qui contrôle ce point un pouvoir
qu'il ne devrait pas avoir.

**Ce que cela ne garantit pas** : un adversaire disposant de plages réellement
diverses — un grand hébergeur, un opérateur — reste dangereux. La diversité par
groupe relève le coût, elle ne le rend pas infini. Et un nœud dont *toutes* les
adresses de départ viennent de l'attaquant est perdu d'avance.

## Vérifications

- **341 tests** avec ML-DSA (326 sans), zéro avertissement clippy.
- Reprise sur instantané et revalidation intégrale donnent un état identique.
- Défaire s'arrête **exactement** à l'instantané, sans corrompre le jeu d'UTXO.
- Un instantané corrompu d'un seul octet est détecté et fait revalider.
- Un bloc ajouté après l'ouverture de l'archive reste servable.
- Le minage parallèle rend le même nonce pour 1, 2, 3, 5 et 8 fils.
- Trois nœuds réels : le troisième, à qui l'on n'a donné qu'une seule adresse,
  découvre les autres et se synchronise.

## Instrumentation

```bash
Q21_CHRONO=1 q21 info        # décomposition du temps de démarrage
```

La ligne d'état d'un nœud porte désormais les groupes réseau des pairs, la taille
du carnet, et les compteurs de blocs orphelins et invalides — les deux chiffres
qui distinguent « lent » de « en boucle ».

## Nouvelles options

```
q21 node --fils <n>     fils de minage (défaut : tous les cœurs)
q21 node --pairs <n>    connexions sortantes visées, toutes de groupes distincts
```

## Ce qui reste ouvert

- **Aucun nœud d'amorçage n'est câblé.** Le carnet fonctionne, mais la première
  adresse doit encore venir de `--connect`. C'est une décision de lancement,
  pas de code : les adresses d'amorçage n'existeront qu'avec le réseau.
- **L'archive ne s'élague pas.** La mémoire est bornée, le disque ne l'est pas
  encore.
- **La preuve de travail n'a toujours reçu aucune cryptanalyse externe.** C'est,
  depuis la phase 6, le point ouvert le plus important du projet.
- **Pas de gestion des pairs entrants hostiles au-delà du score de bannissement**
  — pas de limite par groupe réseau sur les connexions entrantes.
