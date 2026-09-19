# Troisième campagne d'attaque Q21 — rapport de criticité

*Troisième passage adverse, sous un angle neuf et un objectif unique : **créer de
la monnaie qui ne devrait pas exister, dupliquer un bloc ou une transaction pour
la faire avaler par la chaîne, ou faire diverger deux nœuds honnêtes — c'est-à-dire
bloquer la chaîne.** Là où la première campagne visait l'économie des oncles et la
seconde la synchronisation et le stockage, celle-ci attaque le cœur monétaire :
la conservation de la valeur, l'unicité des transactions, l'engagement d'état, la
signature, et les coutures entre ces modules.*

*Comme les deux fois précédentes, aucune affirmation grave n'est décrite sans être
prouvée contre le vrai code. Trois attaques ont été menées de bout en bout contre
une vraie chaîne — pas décrites, exécutées — et le fichier
`tests/attaque_campagne3.rs` les rejoue.*

---

## En une page

Cette campagne **n'a trouvé aucune faille exploitable** de création de monnaie,
de duplication ni de scission. Ce n'est pas une formule de politesse : c'est le
résultat après lecture ligne à ligne des onze modules de consensus et trois
attaques exécutées jusqu'au bout. Le cœur monétaire — bâti et durci au fil des
deux campagnes précédentes — a tenu sous un angle qu'il n'avait pas encore
essuyé.

Deux points mineurs seulement, **aucun n'affecte la monnaie ni le consensus** :
une hygiène de protocole réseau entre réseaux de test, et une inexactitude de
commentaire. Le premier est laissé à votre décision (il touche un réseau de test,
jamais la production) ; le second est corrigé.

Il reste, comme après chaque campagne, **un seul vrai préalable ouvert**, et il
n'est pas dans ce rapport parce qu'aucune campagne d'auto-audit ne peut le
fermer : la cryptanalyse externe de la fonction de mélange de la preuve de
travail.

| # | Criticité | Sujet | État |
|---|---|---|---|
| 1 | ✅ néant | Création de monnaie (subvention, frais, débordement, plafond) | Repoussée — épreuve de bout en bout |
| 2 | ✅ néant | Duplication de bloc / transaction (Merkle, txid, BIP30/34, malléabilité) | Repoussée — analyse + épreuves existantes |
| 3 | ✅ néant | Rejeu de signature (entre entrées, entre réseaux) | Repoussée — épreuve de bout en bout |
| 4 | ✅ néant | Scission de consensus (timewarp, débordements, non-déterminisme) | Repoussée — déjà durcie, revérifiée |
| 5 | 🟢 BASSE | Testnet et regtest partagent la magie réseau P2P | Documenté, sans impact monnaie/consensus |
| 6 | 🟢 BASSE | Commentaire « 92 octets » pour un en-tête de 160 | Corrigé |

---

## 1. Création de monnaie — la cible principale

L'objectif le plus grave, attaqué en premier. Trois leviers possibles pour faire
exister une unité imméritée : réclamer plus que la subvention, réclamer des frais
que personne ne paie, ou faire déborder une addition. Les trois sont fermés, et
la fermeture est prouvée par une chaîne réelle.

**Subvention excessive.** Une coinbase qui réclame une seule unité indivisible de
plus que sa subvention est refusée (`SubventionExcessive`). Épreuve :
`une_coinbase_qui_reclame_une_unite_de_trop_est_refusee`.

**Frais fantômes.** Un bloc porte une vraie transaction à frais `F` ; sa coinbase
a droit à `subvention + F`. Réclamer `subvention + F + 1` — empocher un frais que
le bloc ne porte pas — est refusé. La borne est exacte, à l'unité, parce que le
nœud recalcule les frais lui-même à partir du jeu d'UTXO et ne croit pas la
coinbase sur parole. Épreuve : `une_coinbase_ne_peut_pas_reclamer_de_frais_fantomes`.

**Débordement et plafond.** Toute l'arithmétique de montant est vérifiée
(`Amount::checked_*`, `checked_sum`) ; une somme de sorties qui déborde `u64` est
refusée avant tout, et un dernier rempart — indépendant de la subvention, des
frais et des oncles — refuse tout bloc qui porterait l'émission cumulée au-delà de
21 000 001 Q21. Le calendrier d'émission lui-même est borné *par construction* :
la somme géométrique infinie théorique tient sous le plafond avant même le moindre
arrondi, et une implémentation de référence conservée dans le code garantit
l'égalité bit à bit. Déjà couvert par `integration.rs`, `emission.rs` et
`audit_arith.rs` ; revérifié ligne à ligne.

*Ce qui rend cette famille close :* la conservation de la valeur est vérifiée par
transaction, la borne de subvention par bloc, et le plafond absolu par-dessus le
tout — trois verrous indépendants, dont le dernier tient même si les deux autres
se révélaient faux. C'est déjà arrivé, deux fois, et le plafond a tenu.

---

## 2. Duplication de bloc ou de transaction

L'objectif : faire accepter deux corps différents sous un même en-tête, ou faire
recréer un identifiant déjà utilisé pour corrompre le jeu d'UTXO.

**Racine de Merkle (CVE-2012-2459).** Q21 **promeut** le nœud impair au lieu de le
dupliquer, et étiquette distinctement feuilles et branches : deux listes de
transactions différentes ne peuvent pas produire la même racine, et un nœud
interne ne peut pas se faire passer pour une feuille. Refermé à la conception.

**Identifiant de transaction.** Le `txid` ignore le témoin (leçon SegWit : un
tiers ne peut pas changer l'identifiant d'une transaction en retouchant sa
signature), mais la **feuille de Merkle engage le témoin** (`txid` **et**
`wtxid`) : retoucher une signature dans un bloc en transit change la racine, donc
l'en-tête refuse le bloc. On ne peut ni malléabiliser un txid, ni glisser un
témoin substitué sous un en-tête valide.

**BIP 30 / BIP 34.** La coinbase engage sa hauteur (son témoin commence par la
hauteur en 8 octets, et le `txid` d'une coinbase inclut ce témoin) : deux
coinbases de hauteurs différentes ont forcément des identifiants différents. Deux
coinbases identiques ne peuvent coexister que sur des branches concurrentes,
jamais dans la chaîne active, et étant identiques elles ne corrompent aucun état
lors d'une réorganisation. La couture réorg × coinbase, la plus subtile, a été
suivie pas à pas.

**Encodage.** La sérialisation n'admet qu'une forme par objet : varints
canoniques (forme longue d'un petit nombre refusée), aucun octet en trop
(`expect_end`), comptes bornés par ce que la trame peut contenir et convertis sans
troncature 32 bits. Aucun vecteur de malléabilité au niveau du fil. Couvert par
`ser.rs` et `fuzz_decodeurs.rs`.

---

## 3. Rejeu de signature

L'objectif : faire valoir une signature pour ce qu'elle n'a jamais signé.

**Entre entrées d'une même transaction.** Le condensat signé engage l'indice de
l'entrée. Attaque menée de bout en bout : deux sorties verrouillées par la **même
clef**, une transaction qui les dépense toutes deux, et la signature de l'entrée 0
recopiée sur l'entrée 1. La dépense honnête (chaque entrée signée à son indice)
est acceptée ; le rejeu est refusé (`SignatureInvalide`). Épreuve :
`une_signature_ne_se_rejoue_pas_d_une_entree_sur_l_autre`.

**Entre réseaux.** Le condensat signé engage le réseau (par son préfixe
d'adresse). Une signature du réseau de test ne vaut rien sur le réseau principal,
ni sur l'autre branche d'une scission. Couvert par
`le_sighash_engage_le_reseau_et_la_sortie_depensee`.

**La signature elle-même.** La vérification ML-DSA est déléguée au crate
`ml-dsa` de RustCrypto — écrire soi-même un schéma à réseaux euclidiens serait la
faute professionnelle que la section 4 du livre blanc s'interdit. Le nœud échoue
**bruyamment** (`SchemaNonDisponible`) plutôt que d'accepter ce qu'il n'a pas su
vérifier, et l'empreinte de clef lie la clef à son schéma. SPHINCS+, déclaré mais
non implémenté, est refusé partout tant qu'aucun dos-arrière n'existe (sans quoi
il brûlerait des fonds indépensables — corrigé en 2ᵉ campagne).

---

## 4. Scission de consensus — bloquer la chaîne

L'objectif : faire répondre deux nœuds honnêtes différemment à « ce bloc est-il
valide ? ». C'était le terrain des deux campagnes précédentes ; cette campagne l'a
réexaminé plutôt que supposé acquis.

- **Timewarp / difficulté.** Le temps de résolution de LWMA est **signé** et borné
  **dissymétriquement** (`[-6T, +4T]`) : une manipulation d'horodatage se retourne
  contre son auteur au lieu d'effondrer la difficulté. La borne d'horodatage futur
  est de dix minutes, pas deux heures. Durci et mesuré en 2ᵉ campagne, revérifié.
- **Débordements sous `overflow-checks` + `panic=abort`.** Un débordement
  arithmétique dans le consensus avorterait le processus — un plantage à distance.
  Les chemins critiques (émission, travail cumulé, frais, capacité de vecteur à
  l'adoption) saturent ou refusent au lieu de déborder. Le seul plantage de cette
  classe trouvé en 2ᵉ campagne (capacité d'instantané démesurée) est fermé.
- **Non-déterminisme.** Aucune décision de consensus ne dépend de l'ordre
  d'itération d'une table de hachage : les transactions et les oncles se parcourent
  dans l'ordre du vecteur, et les ensembles ne servent qu'à des tests
  d'appartenance. Deux nœuds au même état rendent le même verdict.
- **Cohérence des chemins.** Le contrôle d'en-tête seul introduit en 2ᵉ campagne
  (`verifier_entete`) est un **sous-ensemble strict** des contrôles de `submit`,
  extrait dans des fonctions partagées : il ne peut pas diverger du chemin complet.
  La relecture d'un corps sur disque exige identifiant et forme concordants — un
  corps forgé vaut « absent », jamais une vérité qui ferait diverger le nœud.

---

## 5. 🟢 BASSE — Testnet et regtest partagent la magie réseau P2P

`magic_for` rend la magie du réseau principal pour Mainnet, et **la magie de
testnet pour testnet comme pour regtest**. Deux nœuds, l'un en testnet l'autre en
regtest, peuvent donc tenter de se parler au niveau du fil.

**Pourquoi c'est sans conséquence pour la monnaie ou le consensus :** les deux
réseaux ont des **genèses différentes** (leurs paramètres de preuve de travail
diffèrent : table de 32 Mio contre 32 Kio), des **préfixes d'adresse différents**
(`tq21` contre `rq21`), et le condensat signé engage ce préfixe. Un bloc de l'un
échoue la vérification de travail chez l'autre ; une transaction de l'un a une
signature invalide chez l'autre. Aucune monnaie, aucun bloc ne traverse.

**L'effet réel** se limite à des poignées de main gaspillées et d'éventuels
bannissements réciproques entre un nœud regtest et un nœud testnet — et le regtest
est local et jetable par nature : les deux ne se rencontrent quasiment jamais.

**Recommandation :** donner à regtest sa propre magie réseau (une constante et une
ligne dans `magic_for`) fermerait proprement le résidu. Je ne l'ai **pas**
appliqué de moi-même : la magie fait partie du protocole de fil, et un changement
de protocole — même sur un réseau de test — relève d'une décision délibérée, pas
d'un correctif glissé dans une campagne. Le dire, et vous laisser trancher, est la
bonne place du curseur.

---

## 6. 🟢 BASSE — Un commentaire inexact *(corrigé)*

Le commentaire de `BlockHeader` annonçait « 92 octets » ; l'en-tête en fait 160
(`BlockHeader::SIZE = 4+32+32+32+32+8+4+8+8`). Aucune conséquence de code — la
taille réelle vient de la constante, pas du commentaire — mais un auditeur qui
lit l'en-tête mérite un chiffre juste. Corrigé.

---

## Ce qui a tenu — vérifié, pas supposé

- **La conservation de la valeur et le plafond** résistent à l'unité près, prouvés
  par une chaîne réelle qui tente de créer une unité de trop et échoue.
- **L'engagement d'état (MuHash 3072 bits)** lie chaque sortie par son point de
  sortie, sa valeur, son schéma, sa clef, sa hauteur et son caractère de coinbase :
  aucun déplacement de propriété, aucune altération de valeur ne laisse l'empreinte
  immobile. Depuis la 2ᵉ campagne, l'empreinte que l'on recopie lie aussi le total
  émis.
- **La signature** est déléguée à une implémentation professionnelle, échoue
  bruyamment quand elle ne sait pas, et lie chaque signature à son entrée, sa
  sortie dépensée et son réseau.
- **La sérialisation** n'admet qu'une forme par objet : ni malléabilité, ni
  allocation dictée par un inconnu, ni divergence 32/64 bits.
- **Le mempool** refuse le relais gratuit, la poussière, le conflit de dépense et
  l'inminable, et calcule les frais avant toute cryptographie.

---

## Recommandation

Pour la troisième fois, le cœur a tenu, et cette fois sous l'angle le plus direct :
l'argent lui-même. Aucune faille de création de monnaie, de duplication ou de
scission n'a résisté à l'examen — parce qu'aucune n'a été trouvée. Les deux points
restants sont mineurs et sans effet sur la production : l'un est corrigé, l'autre
attend votre décision sur un réseau de test.

La chaîne est, du point de vue de ce que ce type d'audit peut établir, **prête pour
une mise en production** sur ses règles de consensus et sa monnaie.

Restent deux préalables qui ne relèvent pas de l'auto-audit, et qui doivent être
tenus **avant** la genèse :

1. **La cryptanalyse externe de la fonction de mélange de la preuve de travail.**
   Aucune campagne interne ne la remplace ; le livre blanc la marque, à juste
   titre, comme le dernier verrou avant une genèse sereine.
2. **La signature des livraisons (minisign)** et la reproductibilité du binaire,
   pour que personne n'ait à faire confiance à l'auteur pour ce qu'il exécute.

Et une note pour le jour du lancement : quand les tables d'ancrages
(`synchro_rapide::ancrages_integres`, aujourd'hui vides) seront remplies, leurs
empreintes doivent être des **empreintes d'état** (MuHash + total émis liés,
`state::empreinte_etat`), et non le MuHash nu — le code de vérification l'attend
déjà ainsi.
