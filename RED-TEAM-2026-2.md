# Deuxième campagne d'attaque Q21 — rapport de criticité

*Second passage adverse, sous un angle neuf. Deux consignes ont guidé cette
campagne, différentes de la première : attaquer en priorité le **code qui
vient de changer** — les correctifs de la première campagne, fraîchement
écrits, sont l'endroit le plus probable pour un nouveau défaut — et creuser des
surfaces moins visitées : décodeurs, économie du mempool, couche de stockage et
synchronisation rapide, arithmétique de validation.*

*Comme la première fois, chaque affirmation grave a été vérifiée contre le vrai
code, pas seulement décrite. Une l'a été par la mesure — et cette mesure a fait
tomber la « faille critique » annoncée d'un facteur cinquante. C'est le cœur de
ce rapport : sans vérification, on corrige des fantômes.*

---

## En une page

Cette campagne a trouvé **un vrai plantage à distance** (gravité haute) et **un
déni de service par surcharge** (gravité moyenne — après correction d'une
erreur d'un facteur cinquante dans l'estimation initiale). Les deux sont
**corrigés et validés**, le plantage avec une épreuve d'attaque à l'appui. Un
troisième défaut mineur (une adoption qui traitait un plantage comme un succès)
est corrigé aussi.

Les durcissements de gravité moyenne à basse (points 4 à 6) ont été appliqués
dans un second temps, chacun avec une épreuve qui rejoue l'attaque : **rien
dans ce rapport ne reste ouvert.** Les vingt-cinq suites d'épreuves du dépôt
passent, dont quatre nouvelles épreuves d'attaque.

| # | Criticité | Faille | État |
|---|---|---|---|
| 1 | 🟠 HAUTE | Plantage à distance d'un nœud en synchronisation rapide | ✅ Corrigé + épreuve |
| 2 | 🟡 MOYENNE | Déni de service par vérification de signature | ✅ Corrigé (gravité recalibrée) |
| 3 | 🟢 BASSE | Adoption traitant un plantage comme un succès | ✅ Corrigé |
| 4 | 🟡 MOYENNE | Bloc compact reconstruit avant vérification du travail | ✅ Corrigé + épreuve |
| 5 | 🟡 MOYENNE | Adoption par fichier sans vérifier les corps | ✅ Corrigé + épreuve |
| 6 | 🟢 BASSE | Cinq durcissements divers | ✅ Les cinq appliqués |

---

## 1. 🟠 HAUTE — Un pair peut faire planter tout nœud qui se synchronise

### En clair

Un nouveau nœud peut démarrer vite en téléchargeant un **instantané** de l'état
auprès d'un pair, puis en l'adoptant si une empreinte correspond à une valeur
que l'utilisateur a vérifiée. L'instantané contient un champ « hauteur » — le
numéro du dernier bloc.

Le défaut : le code **réservait de la mémoire d'après cette hauteur avant de
l'avoir vérifiée**. La ligne fautive préparait un tableau de taille
« hauteur + 1 ». Un pair malveillant annonçant une hauteur maximale
(≈18 milliards de milliards) faisait déborder cette addition — et comme le
programme est compilé pour **s'arrêter net à tout débordement** (une protection
contre les erreurs de calcul monétaires, ici retournée contre lui), le nœud
**plantait**. Fiable, à distance, pour tout nouveau nœud se synchronisant
depuis ce pair.

### Pourquoi c'est grave

Ce n'est pas un vol ni une prise de contrôle, mais c'est une arme de **déni de
service sur l'arrivée de nouveaux participants** : un seul pair hostile,
servant des instantanés piégés, empêche quiconque de rejoindre le réseau par
lui — et le réseau pair-à-pair n'authentifie pas ses pairs, donc n'importe qui
peut en être un. Pour une chaîne jeune qui a besoin que des gens la rejoignent,
c'est une nuisance sérieuse.

### La preuve, et la correction

Une épreuve fabrique un instantané de hauteur maximale et appelle la fonction
d'adoption : avant correction, le processus avortait sur cette ligne ; après,
il retourne un refus propre. La correction borne la réservation au **nombre
d'en-têtes réellement fournis** — une quantité que le pair ne peut pas gonfler,
puisque chaque pas de la vérification exige un en-tête présent. L'épreuve
`attaque_instantane_hauteur` reste en gardienne.

**État : corrigé, prouvé (commit `85851a9`).**

---

## 2. 🟡 MOYENNE — Surcharge par vérification de signature *(et une leçon sur la vérification)*

### Ce que l'analyse a d'abord cru, et ce que la mesure a montré

Une transaction fait vérifier au nœud **une signature post-quantique par
entrée** (par pièce dépensée), et ce travail se fait sous le verrou qui protège
tout le nœud. Rien ne limitait le nombre d'entrées d'une transaction autrement
que par son poids total — soit environ 271 entrées. Et le compteur qui limite
le débit d'un pair comptait **les transactions, pas les vérifications**.

L'analyse initiale, en s'appuyant sur un **commentaire du code** qui annonçait
« seize millisecondes » par vérification, en concluait à un gel de 4,3 secondes
par transaction et à un blocage total du nœud — une faille *critique*.

**La mesure a corrigé cela d'un facteur cinquante.** Sur le banc, une
vérification ML-DSA-87 prend en réalité **0,33 milliseconde**, pas seize. Le
commentaire était cinquante fois trop pessimiste. Le pire cas réel n'est donc
pas un gel de 4,3 s, mais une surcharge d'environ **90 ms** pour une
transaction à 271 entrées, et une baisse de régime — pas un arrêt — sous un flot
soutenu de telles transactions (l'attaquant devant par ailleurs détenir des
pièces à dépenser pour les fabriquer). La faille descend de *critique* à
*moyenne*.

C'est la raison d'être de la vérification : la gravité annoncée reposait
entièrement sur une constante fausse. Un rapport qui ne mesure pas corrige des
fantômes.

### La correction

Le compteur de débit est désormais **denominé en vérifications**, pas en
transactions : une transaction coûte autant que son nombre d'entrées. Le plafond
couvre la plus grosse transaction valide possible, de sorte qu'aucune
transaction honnête — une consolidation de nombreuses pièces, par exemple — ne
soit jamais refusée. Au-delà du budget, une **grosse** transaction est
*différée* sans sanction (elle peut être honnête, et un score de sanction ne
redescend jamais — bannir un relais légitime serait injuste), tandis qu'un
*flot* de petites transactions reste sanctionné comme l'abus qu'il est. Au
passage, cela ferme aussi un sur-bannissement des doublons relayés que la
première campagne avait laissé ouvert.

**État : corrigé (commit `85851a9`).**

---

## 3. 🟢 BASSE — Une adoption traitait un plantage comme un succès

Lors d'une synchronisation rapide, la vérification du travail de la chaîne
téléchargée est répartie sur plusieurs fils d'exécution. Si l'un de ces fils
**plantait**, le code comptait son résultat comme « vérifié » au lieu de
« échec ». Un segment dont la vérification fait planter le vérificateur passait
donc pour valide. Corrigé : un fil qui plante est désormais un échec. Défense
en profondeur — corrigé (commit `85851a9`).

---

## 4. 🟡 MOYENNE — Un bloc compact est reconstruit avant qu'on vérifie son travail

*Corrigé, avec une épreuve d'attaque (`tests/attaque_bloc_compact_sans_travail.rs`).*

Pour économiser de la bande passante, un pair peut annoncer un bloc sous forme
« compacte » (les identifiants des transactions plutôt que les transactions).
Le nœud reconstruit alors le bloc en piochant dans son réservoir. Le défaut :
cette reconstruction — un balayage du réservoir, potentiellement coûteux —
se fait **avant** de vérifier que le bloc porte une vraie preuve de travail. Un
pair pourrait donc faire travailler le nœud avec un bloc non miné.

**Pourquoi ce n'était pas plus grave :** le code exigeait déjà la poignée de
main, exigeait de **connaître le bloc parent**, et appliquait un **compteur de
débit** avec sanction sur les annonces compactes. Ces trois barrières bornaient
déjà fortement l'abus.

**La correction :** une quatrième barrière, celle que prescrit le standard
BIP 152 — l'en-tête d'abord. Avant la moindre fouille du réservoir, l'en-tête
du bloc compact est vérifié **seul** : parent, hauteur, finalité, difficulté
attendue, horodatage, et enfin la preuve de travail (par le chemin léger, sans
la table). Ce sont exactement les contrôles que la soumission du bloc entier
applique — extraits dans des fonctions partagées pour qu'il n'existe qu'une
seule règle — simplement avancés. Un en-tête faux vaut au pair la sanction d'un
bloc invalide, et son corps n'est pas redemandé.

**Preuve :** l'épreuve envoie un bloc compact dont l'en-tête est celui d'un vrai
bloc miné, au nonce changé jusqu'à ce que le travail soit faux. Sans la
correction, le nœud entamait une reconstruction (mesurée : `1 reconstruction
entamée`) ; avec elle, aucune (`0`), l'en-tête est compté refusé, et le vrai
bloc, par le même pair, passe exactement comme avant. Un second en-tête faux
coupe le pair. L'épreuve du seau de la première campagne a été adaptée pour
annoncer un en-tête vrai, afin de continuer à mesurer le seau et non ce
nouveau contrôle.

---

## 5. 🟡 MOYENNE — L'adoption d'un instantané par fichier ne vérifie pas les corps

*Corrigé aux deux endroits, avec une épreuve d'attaque
(`tests/attaque_corps_forge_sur_disque.rs`).*

Il existe deux façons d'adopter un instantané : par le réseau, et par un dossier
de fichiers copié à la main. La voie **réseau** vérifie les corps de blocs
téléchargés ; la voie **fichier** les copie tels quels sans les revérifier.
Conséquence : un dossier d'instantané dont les corps portent des listes
« d'oncles » forgées (des blocs concurrents inventés) pourrait, après adoption,
faire diverger le nœud et le figer sur une fausse branche jusqu'à ce qu'on
efface le dossier.

C'était borné : il fallait que l'utilisateur adopte un dossier fourni par un
tiers, et l'empreinte d'état, elle, restait vérifiée.

**La correction, en deux endroits :** la voie **fichier** vérifie désormais
les corps exactement comme la voie réseau (chaque corps doit avoir une forme
juste et porter l'identifiant de l'en-tête de même hauteur), avant d'écrire un
seul octet ; et, en profondeur, la **relecture d'un corps sur disque** exige
que le bloc relu porte l'identifiant demandé et une forme juste (racines de
Merkle recalculées), faute de quoi il vaut « absent » — cas déjà géré
proprement : le bloc est redemandé au réseau, qui livrera le vrai. Un fichier
de blocs forgé, quelle que soit la façon dont il est arrivé là, ne peut donc
plus servir de vérité au nœud.

**Preuve :** l'épreuve fabrique un dossier d'amorce aux vrais en-têtes, au vrai
instantané, et à un corps portant un oncle inventé. `q21 instantane adopter` le
refuse (« corps de hauteur 15 malformé ») sans rien écrire ; le même dossier,
aux corps intacts, s'adopte. Et l'archive, face à un fichier de blocs dont un
corps contredit son en-tête, relit tous les corps honnêtes et rend le corps
forgé comme absent.

---

## 6. 🟢 BASSE — Cinq durcissements

Aucun n'était exploitable à distance en l'état ; c'étaient des angles à
nettoyer. **Les cinq sont appliqués.**

**a.** La taille maximale d'un message réseau (8 Mio) valait le double de celle
d'un bloc (4 Mio) : un message surdimensionné était entièrement décodé avant
d'être rejeté pour excès de taille. *Appliqué :* la borne vaut désormais un
bloc et quart (5 Mio), ce qui couvre le plus gros message licite — un bloc
entier, ou un bloc compact qui en préfigurerait toutes les transactions — et
rien de plus ; deux assertions de compilation gardent cet encadrement.

**b.** L'en-tête `X-Forwarded-For` : la correction de la première campagne (lire
la dernière valeur) est juste pour **un** mandataire, mais dégrade le comptage
si l'on empile plusieurs mandataires (un CDN devant le proxy). *Appliqué :*
la règle « un seul saut de confiance » est documentée dans le code et dans le
guide de l'explorateur public, avec la marche à suivre derrière un CDN (c'est
au mandataire local de réécrire l'en-tête avec l'adresse que le CDN lui
transmet). Le nœud ne devine pas le nombre de sauts : chaque saut cru sur
parole serait un saut qu'un visiteur peut imiter.

**c.** Le total émis n'était pas couvert par l'empreinte de l'instantané : un
pair pouvait l'annoncer à n'importe quelle valeur dans une plage, ce qui
touchait un affichage et une borne anti-inflation. *Appliqué :* l'empreinte que
l'on recopie — celle de `--empreinte`, de l'explorateur, de l'annonce d'amorce
et de la fiche de revalidation — est désormais l'**empreinte d'état**, qui lie
le MuHash et le total émis sous une étiquette propre. Le MuHash reste ce qu'il
est et le format de l'instantané ne change pas ; seule la valeur comparée en
dérive. L'épreuve `tests/attaque_instantane_emis.rs` le prouve : un instantané
au total émis réécrit, au MuHash identique, est refusé sous l'empreinte de
confiance, et l'instantané honnête s'adopte. La revalidation d'un nœud adopté
compare elle aussi cette valeur : un total émis menti ne lui survivrait plus.

**d.** Un nœud gardait en mémoire les mille derniers corps de blocs décodés : un
mineur produisant de gros blocs pouvait faire enfler cette réserve au-delà de
l'hypothèse « 8 Go suffisent » (mille corps de 4 Mio : 4 Gio). *Appliqué :*
une seconde borne, en octets (1 Gio), tenue au fil de l'eau ; la première
atteinte l'emporte, les corps partent du plus ancien au plus récent, la genèse
jamais, et le disque garde tout ce que la mémoire lâche. Avec des blocs pleins,
la mémoire retient 256 blocs — huit heures — au lieu de quatre gigaoctets.
Une épreuve unitaire vérifie le compte et l'ordre d'éviction.

**e.** Deux recopies inutiles de blocs entiers à chaque raccordement (une liste
d'oncles toujours vide était lue en clonant neuf blocs complets ; un parcours
de réorganisation était quadratique). *Appliqué :* sans oncle possible, la
lecture est court-circuitée (elle reprend d'elle-même si le protocole rouvre
les oncles) ; le parcours de réorganisation lit la chaîne active par hauteur
au lieu de la balayer. Conséquence saine, verrouillée par une épreuve : un
nœud repris sur instantané sans fournisseur de corps rend désormais le même
verdict qu'un nœud complet sur le bloc qui prolonge sa tête, au lieu d'un refus
que rien ne justifiait plus.

---

## Ce qui a tenu — vérifié, pas supposé

Un point rassurant de cette campagne : **les correctifs de la première ont
résisté à l'examen adverse**, et le reste du code s'est confirmé solide là où on
l'a poussé le plus fort.

- **La correction de la faille critique d'inflation** (la première campagne)
  n'a pas de faille de bord : la seule façon qu'une pièce soit à la fois
  préexistante et recréée dans un bloc serait une collision d'identifiant, que
  l'engagement de hauteur dans la transaction de récompense rend impossible.
- **Les décodeurs** — le point d'entrée de tout attaquant — n'ont livré **aucun
  plantage, aucune allocation non bornée** : les longueurs annoncées sont
  toujours bornées par ce que la trame contient, les encodages non canoniques
  sont refusés, l'arithmétique 256 bits ne déborde pas.
- **L'empreinte d'état (MuHash)** lie bien l'ensemble complet des pièces ; une
  collision reviendrait à un problème mathématique tenu pour infaisable, et
  l'insertion-puis-retrait ne laisse aucun résidu (ce que la correction
  d'annulation de la première campagne a rendu vrai).
- **L'arithmétique de validation** — difficulté, émission, frais, travail
  cumulé — est gardée partout par des opérations qui saturent ou refusent au
  lieu de déborder.
- **Le mempool** ne permet ni relais gratuit, ni poussière, ni contournement du
  tarif minimal ; son coût de nettoyage est linéaire, plus quadratique.

---

## Recommandation

Les deux défauts qui comptaient — le plantage à distance et la surcharge par
vérification — sont fermés et validés. Les points 4 à 6, des durcissements,
ont été appliqués posément dans un second temps, chacun avec son épreuve ; ce
rapport ne laisse rien d'ouvert dans le code.

Et, pour la troisième fois, la seule chose qui reste vraiment ouverte n'est pas
dans ce rapport : la **cryptanalyse externe de la fonction de mélange de la
preuve de travail**, qu'aucune campagne d'auto-audit ne peut remplacer. C'est le
préalable que le livre blanc marque, à juste titre, comme le dernier avant une
genèse sereine.
