# Q21 face à l'état de l'art 2026

Audit de la chaîne contre ce qui se fait de mieux aujourd'hui, avec un angle
assumé : **la vitesse**. Rien de ce qui suit ne change ce qui est construit —
ce sont des axes d'amélioration, classés par horizon, chacun adossé soit à une
mesure faite ici, soit à une source extérieure datée.

La leçon de départ est celle que ce document doit garder en tête : Bitcoin n'a
pas prévu son propre succès. En 2023, une vague d'inscriptions a fait grimper
ses frais de plus de 4 000 % et laissé des centaines de milliers de
transactions en attente pendant des jours. L'engorgement n'est pas un accident :
c'est ce qui arrive à toute chaîne dont la demande dépasse le débit, et la
seule question est de l'avoir anticipé.

---

## 1 · Où Q21 est déjà au niveau — ou devant

| Standard 2026 | Bitcoin aujourd'hui | Q21 aujourd'hui |
|---|---|---|
| Signatures post-quantiques | BIP-360/361 : **propositions** en cours de débat, migration non commencée | **Livré** : ML-DSA-87 (FIPS 204, niveau 5) par défaut, adresses à schéma versionné pour en changer sans casser |
| Relais compact des blocs | Compact blocks (BIP-152), déployé | **Livré**, mesuré : annonce < 2 Kio pour un bloc de ~5 Mio, 200 blocs synchronisés sans un aller-retour |
| Anti-éclipse | Seaux par groupe réseau, déployé | **Livré** : seaux /16 salés par nœud, détection des pairs morts < 20 s |
| Anti-ASIC | Aucun (SHA-256, fonderies) | **Livré** : table de 2 Gio qui croît de 5 %/71 j — hypothèse étayée, cryptanalyse externe encore due |
| Émission exacte | ~979 satoshis jamais émis, assumé | **Livré** : plancher de queue + écrêtage, 21 000 001 atteint à l'unité près (bloc 26 273 578) |
| Portefeuille sans terminal | Standard depuis longtemps | **Livré** cette phase : écrans, restauration guidée, minage commandé |

Le point qui mérite d'être dit sans fausse modestie : sur les signatures,
Q21 est **en avance sur Bitcoin**, qui en est aux propositions (BIP-360
« P2QRH » et BIP-361) pendant que Q21 signe déjà chaque transaction en
ML-DSA-87. C'est l'avantage de naître après la norme FIPS 204 au lieu de
devoir migrer vers elle.

## 2 · La vitesse, chiffrée honnêtement

Deux grandeurs distinctes, que le langage courant confond :

**La latence** — combien de temps avant que mon paiement soit confirmé.
Q21 vise un bloc toutes les **2 minutes**, contre 10 pour Bitcoin : première
confirmation en ~2 min en moyenne, cinq fois plus vite. Et l'interface montre
la transaction dès son entrée au réservoir, en la marquant honnêtement comme
non confirmée.

**Le débit** — combien de paiements par seconde la chaîne accepte. C'est ici
que le mur est réel et documenté (PROJECTION.md) : une transaction ML-DSA-87
pèse 7 361 octets, un bloc en porte 569, soit **4,74 tx/s**. C'est le prix de
la résistance quantique, et aucune incantation ne le fait disparaître.

Ce qui suit classe les leviers qui font reculer ce mur, du plus immédiat au
plus lointain.

---

## 3 · Axes immédiats — sans toucher au consensus

### 3.1 Le paiement groupé : de 4,7 à 300+ paiements par seconde

La mesure qui change la perspective : dans une transaction Q21, **la signature
pèse tout, une sortie ne pèse que 41 octets**. Payer cent personnes dans une
seule transaction coûte donc à peine plus que d'en payer une :

| Destinataires par transaction | Octets par destinataire | Paiements par seconde |
|---:|---:|---:|
| 1 | 7 361 | 4,7 |
| 10 | 773 | 45 |
| 100 | 114 | **306** |
| 500 | 56 | 625 |

Un service qui verse des gains — groupement de minage, place d'échange —
multiplie le débit utile par 60 en groupant. Le protocole le permet déjà ;
ce qui manque est **l'outillage** : `sendmany` dans le RPC et l'écran d'envoi
multiple dans le portefeuille. C'est l'axe au meilleur rapport effort/effet
de tout ce document.

### 3.2 Le marché des frais : l'anti-engorgement, et il est déjà audité

L'engorgement de Bitcoin en 2023 n'a pas cassé la chaîne : il a cassé
l'*expérience* — des frais imprévisibles et des attentes de plusieurs jours.
La défense s'appelle un marché des frais sain : un réservoir qui évince les
transactions les moins payantes, estime le taux nécessaire, et refuse
l'inacceptable tôt et à bas coût.

Le nôtre a déjà été audité de l'intérieur, et les découvertes sont connues :
**8 constats ouverts dans `audit_mempool`** (filtre de frais appliqué après la
vérification de signature — donc coûteux à saturer pour nous et pas pour
l'attaquant ; transactions plus grosses qu'un bloc acceptées puis jamais
minées ; éviction des honnêtes par des transactions non minables ;
`revalidate` quadratique) et **1 dans `audit_difficulte`**. Aucun ne menace
les fonds ; tous concernent exactement ce que l'engorgement exploiterait.
Les corriger est le deuxième axe immédiat — c'est le travail « Satoshi
n'avait pas prévu » fait à l'avance.

### 3.3 Le relais des transactions : Erlay comme modèle

Les blocs voyagent déjà en compact. Les **transactions**, elles, sont
annoncées à chaque pair — c'est le poste de bande passante qui explosera avec
le nombre de pairs. Bitcoin a conçu Erlay (réconciliation d'ensembles,
~40 % de bande passante en moins, toujours en cours d'intégration dans Core
après des années). Q21 n'en a pas besoin à dix pairs ; le testnet dira à
partir de combien il en faut un. À noter comme dette, pas comme urgence.

---

## 4 · Axes préparés par la conception — activables plus tard

### 4.1 L'agrégation de signatures : la sortie par le haut du mur des 4,74 tx/s

L'état de la recherche, daté : la **demi-agrégation** de signatures à réseaux
euclidiens est publiée (eprint 2023/159), des schémas d'agrégation
non interactive dans le paradigme Fiat-Shamir apparaissent en 2024-2025, et
la sécurité sous corruptions adaptatives est un sujet actif (eprint
2025/1955). **Rien n'est encore standardisé ni éprouvé en production.** Une
agrégation mûre diviserait le poids des témoins d'un bloc — donc
multiplierait le débit — sans toucher à la sécurité visée.

Q21 n'a pas à parier aujourd'hui : chaque adresse porte l'identifiant de son
schéma, précisément pour qu'un futur schéma agrégeable s'ajoute à côté de
ML-DSA-87 sans casser l'existant. L'axe consiste à **surveiller cette
littérature chaque année** et à garder l'agilité intacte — ne jamais rien
livrer qui suppose « le schéma » unique.

### 4.2 La synchronisation en minutes : MuHash puis instantanés

Le standard 2026 est AssumeUTXO (Bitcoin Core 28) : charger un instantané de
l'ensemble UTXO et être utilisable en minutes pendant que l'historique se
vérifie en arrière-plan. Q21 a déjà la brique de vérification bon marché
(cache de 64 Mio, ~660 µs par en-tête) ; il lui manque **l'engagement UTXO
(MuHash)** — déjà prérequis du réseau principal dans la feuille de route —
pour que l'instantané soit vérifiable et non cru. Ordre imposé : MuHash
d'abord, instantanés ensuite.

### 4.3 Des blocs plus rapides, si le testnet le permet

Deux minutes est un choix marqué PROVISOIRE dans le code, et c'est le levier
de latence le plus direct. Ce qui interdit de le raccourcir à l'aveugle : des
blocs plus fréquents font plus d'orphelins, et les orphelins favorisent le
mineur le mieux connecté — la centralisation par la course. Q21 a justement
livré les deux amortisseurs : le relais compact (la cause) et les récompenses
d'oncles à 25 % (la conséquence). **La décision se prendra sur la mesure du
taux d'orphelins du testnet public**, pas sur le raisonnement — c'est écrit
dans `consensus.rs` depuis le premier jour.

### 4.4 La deuxième couche : après le testnet, pas avant

À l'échelle de millions d'utilisateurs, aucune chaîne de base ne paie un café
— Bitcoin a Lightning, Ethereum ses rollups. Q21 y viendra, mais une couche 2
se construit sur des fondations mesurées : marché des frais sain,
réorganisations observées en conditions réelles, formats de transaction
stabilisés. L'inscrire maintenant serait de l'architecture sur du sable.

---

## 5 · L'ordre recommandé

1. **`sendmany` + envoi multiple dans le portefeuille** — le débit ×60 pour
   les payeurs en gros, quelques jours de travail, zéro risque consensus.
2. **Corriger les 9 constats mempool/difficulté** — l'anti-engorgement,
   les épreuves existent déjà et échouent en le documentant.
3. **Ouvrir le point d'entrée public** (SERVEUR.md) — toutes les mesures qui
   décident du reste (orphelins, frais, saturation) en dépendent.
4. **MuHash**, puis instantanés de synchronisation.
5. Réévaluer chaque année : agrégation ML-DSA, intervalle de bloc, Erlay,
   couche 2 — sur mesures et littérature, jamais sur l'air du temps.

Ce que cet audit ne couvre pas, et qui reste la dette la plus sérieuse du
projet : **la preuve de travail n'a reçu aucune cryptanalyse externe.** Aucun
axe de vitesse ne passe devant celle-là le jour où le réseau principal se
discute.
