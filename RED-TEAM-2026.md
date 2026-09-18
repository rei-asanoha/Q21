# Simulation d'attaque Q21 — rapport de criticité

*Phase 8b, campagne adverse. Une équipe de six analystes a lu le code en
pensant comme des attaquants, chacune sur une surface : consensus, validation
des transactions et des blocs, réseau pair-à-pair, portefeuille et clés,
API/explorateur, preuve de travail. La faille majeure a été **écrite en code
d'attaque et jetée contre le vrai programme** — pas seulement décrite. Elle est
corrigée, et la correction est prouvée par la même épreuve qui démontrait la
faille.*

*Contrainte tenue tout du long : un bloc reste résolu en deux minutes, rien
dans ces corrections ne ralentit la chaîne ni n'en déplace le contrôle.*

---

## En une page, pour qui n'a pas le temps

On a trouvé **une faille critique, réelle, prouvée** : dans certaines
conditions parfaitement ordinaires, la chaîne pouvait **créer de la monnaie à
partir de rien** et faire diverger les nœuds entre eux. Elle est **corrigée**,
et l'attaque qui la démontrait échoue désormais contre le code corrigé.

Le reste — huit points de durcissement — va d'« important à faire avant le
lancement » à « détail d'hygiène ». Aucun ne permet de prendre le contrôle de
la chaîne, de voler des fonds à distance, ou de percer le portefeuille. Le
gros du code s'est révélé **remarquablement bien défendu** : la plupart des
attaques classiques que l'on est allé chercher étaient déjà fermées, avec une
épreuve de non-régression qui les verrouille.

C'est le résultat qu'on espère d'un audit avant genèse : le défaut grave sort
maintenant, se corrige sans casser la chaîne, et ne coûte rien — parce que le
bloc 1 n'existe pas encore.

| # | Criticité | Faille | État |
|---|---|---|---|
| 1 | 🔴 **CRITIQUE** | Création de monnaie lors d'une réorganisation | ✅ **Corrigé et prouvé** (`3100892`) |
| 2 | 🟠 HAUTE | Blocage des connexions entrantes (déni de service) | ✅ Corrigé (`1022e99`) |
| 3 | 🟡 MOYENNE | La borne de difficulté n'est pas vérifiée dans le cœur de la preuve de travail | ✅ Corrigé + épreuve (`1022e99`) |
| 4 | 🟡 MOYENNE | Amplification et fuite du carnet d'adresses avant poignée de main | ✅ Corrigé (`1022e99`) |
| 5 | 🟡 MOYENNE | Un même message rejoué épuise le processeur du nœud | ✅ Corrigé (`1022e99`) |
| 6 | 🟡 MOYENNE | Explorateur public : quotas de recherche contournables | ✅ Corrigé (`1022e99`) |
| 7 | 🟡 MOYENNE | Substitution du portefeuille par écriture du dossier | ◑ Déjà borné à l'OS ; résidu hors bande (voir ci-dessous) |
| 8 | 🟢 BASSE | Cinq points d'hygiène | ✅ Corrigés (`1022e99`) |

*Tous les correctifs ont été validés : suite de tests complète au vert (21
binaires), clippy sans avertissement, et pour la faille critique comme pour la
borne de difficulté, une épreuve d'attaque qui échoue désormais contre le code
corrigé. Aucun correctif ne touche au rythme des deux minutes.*

---

## 1. 🔴 CRITIQUE — De la monnaie créée à partir de rien lors d'une réorganisation

**C'est la seule faille de ce rapport qui pouvait détruire le projet. Elle est corrigée.**

### Ce que c'est, en clair

Imaginez un cahier de comptes partagé où chacun vérifie tout. Parfois, deux
mineurs trouvent un bloc presque en même temps, le réseau hésite une seconde,
puis tranche pour la chaîne la plus travaillée : c'est une **réorganisation**,
un événement normal et fréquent dans toute preuve de travail. Le bloc perdant
est *défait* — ses écritures sont annulées, le cahier revient à l'état d'avant.

Or Q21 autorise, dans un même bloc, qu'un paiement dépense la monnaie rendue
d'un paiement précédent du même bloc. C'est normal et courant : vous payez
quelqu'un, il vous rend la monnaie, et vous redépensez cette monnaie dans la
foulée. Le code appelle ça le « chaînage parent-avant-enfant », et il le
permet exprès.

Le défaut était à l'intersection des deux. Quand on **annulait** un tel bloc,
la routine qui remet le cahier en ordre s'y prenait mal : la pièce née **et**
dépensée à l'intérieur du bloc était d'abord retirée, puis **remise** par
erreur. Elle survivait à l'annulation — une pièce fantôme, dépensable, ne
correspondant à aucun paiement de la chaîne réelle. De la monnaie créée à
partir de rien.

### La preuve, chiffrée

On n'a pas décrit l'attaque, on l'a **exécutée** contre le vrai code. Départ :
une seule pièce de 10 000. On fabrique le bloc piégé, on l'annule comme le
ferait une réorganisation. Résultat mesuré :

```
valeur avant l'annulation : 10 000
valeur après l'annulation : 19 000      ← 9 000 créés à partir de rien
pièce fantôme présente    : oui
empreinte d'état identique à l'avant : NON
```

Pire : l'empreinte de l'état corrompu restait **cohérente avec elle-même** — le
contrôle interne du nœud ne voyait rien d'anormal. Un nœud qui vivait la
réorganisation et un nœud qui se synchronisait de zéro depuis la chaîne
gagnante aboutissaient à **deux cahiers différents**, tous deux se croyant
justes : le réseau se scinde en silence, et l'inflation est invisible.

### Pourquoi c'était grave au point de tout arrêter

Trois raisons cumulées. La création de monnaie ruine la promesse fondamentale
d'un plafond à 21 000 001. La divergence entre nœuds casse le consensus — le
réseau cesse d'être un seul réseau. Et surtout, **ça ne demandait pas
d'attaquant** : une réorganisation est normale, dépenser sa monnaie rendue dans
un bloc l'est aussi ; le défaut se déclenchait donc tout seul, sur l'activité
ordinaire, un jour ou l'autre.

### La correction, et pourquoi elle ne ralentit pas la chaîne

Une pièce née et dépensée dans le même bloc n'existait pas avant ce bloc ;
après annulation, elle ne doit donc pas exister. La correction dit exactement
cela : lors de l'annulation, on ne restaure une pièce dépensée **que si le bloc
ne l'a pas aussi créée**. Présente dans les deux listes, elle est nette :
retirée, jamais remise.

C'est une correction de **comptabilité d'annulation**, pas de rythme : elle ne
touche ni la preuve de travail, ni la difficulté, ni la validation des blocs.
Le bloc reste résolu en deux minutes, à l'identique. L'épreuve d'attaque est
maintenant gardée en permanence dans la suite de tests (`attaque_reorg_inflation`) :
si quelqu'un réintroduit un jour le défaut, elle le rattrape.

**État : corrigé (commit `3100892`), non-régression vérifiée sur toute la suite.**

---

## 2. 🟠 HAUTE — Un attaquant peut bloquer les connexions entrantes

### En clair

Pour entrer dans le réseau, un nouveau nœud frappe à la porte d'un nœud
« portier » (voir `REJOINDRE.md`). Un portier accepte un nombre limité de
connexions entrantes. Le défaut : le code n'exige jamais qu'une connexion
**termine sa présentation** (la « poignée de main ») pour garder sa place. Un
attaquant ouvre des connexions, envoie juste un petit « ping » de temps en
temps pour paraître vivant, sans jamais se présenter — et occupe indéfiniment
toutes les places entrantes.

### L'impact, mesuré à sa juste taille

Ce n'est **pas** une prise de contrôle et **pas** un vol. C'est un déni de
service ciblé : avec quelques adresses réparties, un attaquant remplit les 24
places entrantes d'un portier et empêche les nouveaux venus d'entrer *par lui*.
Les nœuds déjà connectés continuent, et les connexions sortantes protégées
contre l'isolement fonctionnent toujours. C'est une dégradation de
l'accessibilité, pas un arrêt du réseau. La gravité « haute » tient à ce qu'un
réseau jeune, avec peu de portiers, y est sensible.

### Méthode de correction

Poser une **échéance de poignée de main** : une connexion qui ne s'est pas
présentée dans un court délai (dix à trente secondes) est fermée, et un « ping »
reçu avant la présentation ne doit pas rafraîchir le compteur de vie. C'est une
poignée de lignes dans la gestion des connexions, sans effet sur le rythme des
blocs.

---

## 3. 🟡 MOYENNE — La borne de difficulté n'est pas vérifiée là où elle devrait

### En clair

La preuve de travail impose une **difficulté minimale** : sans elle, on
fabriquerait un bloc valide sans effort, et on pourrait miner bien plus vite
que le rythme de deux minutes voulu. Aujourd'hui, cette borne est bien
appliquée — mais **au dehors** du cœur de la preuve de travail, dans le code
qui raccorde les blocs à la chaîne. La fonction qui juge « ce travail est-il
suffisant ? » accepte, elle, n'importe quelle difficulté qu'on lui présente.

### L'impact

**Nul aujourd'hui** : les deux seuls endroits qui appellent cette fonction
posent la borne juste avant, et la genèse la fixe en dur. Le risque est
**latent** : le jour où un nouveau code appellera cette fonction en oubliant de
poser la borne — par exemple un futur validateur qui vérifierait les en-têtes
avant les corps —, on réintroduirait exactement le défaut « des en-têtes
valides à l'infini sans miner » que la phase 8 avait déjà corrigé. C'est le
genre de dette qui explose des mois plus tard, loin de l'endroit où on l'a
contractée.

### Méthode de correction

Déplacer l'invariant **dans** la fonction de vérification du travail :
qu'elle-même refuse une cible plus facile que la difficulté minimale, au lieu
de faire confiance à ses appelants. La règle vit alors avec le calcul qu'elle
protège, et aucun futur appelant ne peut l'oublier. Cette correction *renforce*
la garantie des deux minutes, elle ne la touche pas.

---

## 4. 🟡 MOYENNE — Le carnet d'adresses fuit et amplifie avant la poignée de main

### En clair

Un nœud tient un carnet d'adresses d'autres nœuds. La commande qui demande ce
carnet (`getaddr`) est servie **sans exiger la présentation**, et sans
limite de débit. Une petite demande de 24 octets déclenche une réponse pouvant
atteindre 16 000 octets — une amplification d'environ 600 fois — construite
pendant que le nœud tient son verrou principal. Et n'importe qui, sans s'être
présenté, peut ainsi **récolter tout le carnet d'adresses**.

### L'impact

Deux nuisances modérées : un levier d'amplification et de charge (le verrou
principal est celui qui sert aussi à valider les blocs), et une reconnaissance
du réseau offerte à un scanner anonyme. Ce n'est pas une prise de contrôle ;
ça contredit toutefois le principe affiché du code — « rien n'est lu avant la
poignée de main ».

### Méthode de correction

Exiger la poignée de main terminée avant de servir `getaddr`, comme c'est déjà
le cas pour les autres commandes, et lui appliquer le même seau de jetons
(limite de débit) que le reste. Le code a déjà ce mécanisme ; il suffit de
l'étendre à cette commande.

---

## 5. 🟡 MOYENNE — Un message rejoué épuise le processeur

### En clair

Quand un nœud reçoit une transaction, il calcule son identifiant (une empreinte
de toute la transaction) avant de vérifier s'il la connaît déjà. Le garde-fou
de débit ne s'applique qu'aux transactions **nouvelles**. En rejouant en
boucle une même grosse transaction déjà connue, un attaquant force le nœud à
recalculer cette empreinte coûteuse à chaque fois — jusqu'à deux fois — sans
jamais heurter la limite de débit, et ce sous le verrou principal.

### L'impact

Un déni de service par épuisement du processeur : le nœud se sérialise sous le
rejeu soutenu. Pas de vol, pas de prise de contrôle — une dégradation de
performance.

### Méthode de correction

Appliquer la limite de débit **avant** le calcul coûteux, ou tenir une petite
mémoire des empreintes récemment vues pour rejeter un rejeu sans le
recalculer. Le coût de *décider* qu'une transaction est déjà connue doit lui
aussi être plafonné, pas seulement le coût de traiter les nouvelles.

---

## 6. 🟡 MOYENNE — Explorateur public : quotas de recherche contournables

*Ne concerne que le serveur si l'explorateur public est activé — c'est le cas
de ton serveur OVH.*

### En clair

L'explorateur public tourne derrière un portier web (un « proxy inverse »).
Pour répartir équitablement les recherches entre visiteurs, le nœud les compte
par adresse IP. Mais il fait **confiance** à un en-tête (`X-Forwarded-For`) que
le proxy est censé remplir honnêtement. Si le proxy est configuré pour
*ajouter* cet en-tête au lieu de le *remplacer* — un réglage par défaut
fréquent —, l'attaquant en contrôle le contenu et se fabrique une IP différente
à chaque requête, contournant le quota par visiteur.

### L'impact

Un déni de service sur la **recherche** de l'explorateur : l'attaquant épuise
le quota global partagé et prive les vrais visiteurs. **La validation des blocs
reste protégée** par un plafond global séparé — c'est une gêne de l'explorateur,
pas un gel de la chaîne.

### Méthode de correction

Ne pas faire confiance aveuglément au premier maillon de l'en-tête : rendre
explicite le nombre de proxies de confiance (prendre la *dernière* entrée, ou
un nombre fixé par l'exploitant). Côté configuration, s'assurer que le proxy
**remplace** l'en-tête. Deux gestes complémentaires.

---

## 7. 🟡 MOYENNE — Substitution du portefeuille par écriture du dossier

### En clair

Le portefeuille se protège contre une substitution : deux petits fichiers de
contrôle (une « ancre » et un « numéro de série ») empêchent qu'on remplace
votre portefeuille par un autre, ou qu'on revienne à une sauvegarde ancienne
(ce qui ferait resigner des clés à usage unique — dangereux). Mais ces deux
fichiers sont en **clair** et ne sont pas liés à votre phrase secrète. Quelqu'un
qui peut **écrire dans votre dossier de données** peut les réécrire de façon
cohérente et faire adopter son propre portefeuille.

### L'impact

Réel mais **borné** : il faut déjà pouvoir écrire dans votre dossier — donc
être déjà à l'intérieur de votre machine, sous votre compte. Quelqu'un dans
cette position peut de toute façon lire votre `wallet.dat`. Le code le reconnaît
explicitement comme « la même limite que l'anti-rejeu par numéro de série ». Ce
n'est pas une faille à distance.

### Méthode de correction

Lier l'ancre à la phrase secrète (l'authentifier avec une empreinte dérivée de
la graine scellée), de sorte qu'un attaquant sans la phrase ne puisse pas
fabriquer une ancre valide. Durcissement, pas urgence.

---

## 8. 🟢 BASSE — Cinq points d'hygiène

Aucun n'est exploitable à distance ; ce sont des angles à nettoyer.

**a. Panique possible sur le chemin de secours d'une réorganisation**
(`chain.rs`). Une réorganisation qui échoue à mi-parcours restaure la chaîne
d'origine avec un `expect` qui *plante le nœud* au lieu de rendre une erreur
propre. On n'a pas réussi à construire l'entrée qui le déclenche (le chemin de
reconnexion est déterministe et était valide auparavant), donc c'est de la
défense en profondeur — mais un plantage n'est jamais la bonne réponse sur une
routine de consensus. *Correction : rendre une erreur au lieu de paniquer.*

**b. Des sorties « SphincsPlus » valides mais indépensables pour toujours.**
Ce schéma de signature est accepté à la création d'une sortie mais non
disponible à la dépense : une pièce qu'on y verrouille est **brûlée**
définitivement. Personne n'y gagne (c'est le destinataire qui choisit), mais
c'est un piège. *Correction : refuser ce schéma à la création tant qu'il n'est
pas disponible à la dépense.*

**c. Le mélange du cache de preuve de travail peut s'auto-annuler.** Dans une
poignée de cases sur des millions, une opération se neutralise et produit une
valeur constante. Perte d'entropie mineure, aucun raccourci de minage
exploitable. *Correction : garantir que les deux termes mélangés diffèrent.*

**d. Aucune force minimale de phrase secrète n'est imposée.** Une phrase d'un
caractère est scellée avec toute la robustesse du chiffrement — mais se devine
en un instant. *Correction : imposer un plancher, ou au moins refuser de sceller
sous un seuil.* (Une phrase vide est, elle, correctement traitée.)

**e. En-têtes HTTP `Transfer-Encoding` / `Content-Length` en double non
rejetés.** Sans danger aujourd'hui (chaque connexion se ferme après une seule
requête, donc pas de « désynchronisation »), mais deviendrait exploitable si la
réutilisation de connexion était un jour ajoutée. *Correction : rejeter ces
en-têtes ambigus, par cohérence avec le rejet déjà en place du `Host` en
double.*

---

## Ce qui a tenu — et qu'il faut savoir

Un audit qui ne listerait que les failles donnerait une image fausse. Une large
part des attaques classiques était **déjà fermée**, vérifiée dans le code :

- **Le portefeuille et les clés.** Aucune fuite de graine, aucune réutilisation
  de clé à usage unique trouvée — les deux joyaux qu'on a cherchés le plus fort.
  La graine est chiffrée puis authentifiée, effacée de la mémoire après usage,
  jamais journalisée. La réservation-avant-signature est étanche.
- **L'inflation par les transactions.** Conservation de valeur, plafond
  absolu, additions protégées contre le débordement, récompense d'oncle
  supprimée : tout est verrouillé. (La faille n°1 passait *à côté* de ces
  défenses, par la comptabilité d'annulation — pas par la validation.)
- **La difficulté et le temps.** L'attaque « time-warp » (fausser les
  horodatages pour miner plus vite) est neutralisée : le temps est traité de
  façon signée et asymétrique, toute manipulation *augmente* la difficulté.
- **Le décodage des messages réseau.** Pas de bombe mémoire, pas de plantage du
  décodeur trouvé — les longueurs annoncées par l'attaquant sont bornées par ce
  que la trame contient réellement.
- **L'attaque 51 %.** Elle n'a pas de correctif logiciel : elle consiste à
  posséder plus de la moitié de la puissance de calcul. La seule défense est le
  nombre de mineurs indépendants — donc la décentralisation, dont parle
  `REJOINDRE.md`. Ce n'est pas une faille du code, c'est une propriété
  économique du réseau.

---

## État après correction

Les huit points sont traités. La faille critique et les six failles de
service ou d'hygiène (2 à 6, 8) sont **corrigées**, chacune avec sa
justification en commentaire dans le code et, pour les deux plus graves, une
épreuve d'attaque qui échoue désormais contre le code corrigé. Toute la suite
de tests reste au vert et clippy est muet.

Le point 7 mérite un mot honnête, parce qu'il n'est pas « corrigé » et ne peut
pas l'être en bande. La substitution du portefeuille suppose un attaquant qui
**écrit dans le dossier de données**. Les fichiers de contrôle (l'ancre, le
portefeuille) sont déjà écrits en accès **propriétaire seul** : un *autre*
compte de la machine ne peut donc pas faire la substitution. Le résidu, c'est
du code qui s'exécute **sous le compte de l'utilisateur** — un logiciel
malveillant déjà à l'intérieur. Contre lui, aucun verrou de portefeuille ne
tient : il lit la graine dans la mémoire du processus, enregistre la frappe de
la phrase, remplace le binaire. Lier l'ancre à la phrase n'y changerait rien —
au moment du contrôle, le vérificateur ne détient pas plus la graine légitime
que l'attaquant, la garantie tournerait en rond. Prétendre l'avoir fermé serait
un théâtre de sécurité. La vraie parade est au niveau du système : garder la
machine saine, et le dossier hors de portée des autres comptes — ce qui est
déjà le cas par défaut.

## Ce qui reste ouvert, et qui n'est pas un bug

La mise en garde que le code porte lui-même, qu'il faut répéter : les
primitives de la preuve de travail **n'ont reçu aucune cryptanalyse externe**.
Cette campagne a vérifié la *plomberie* — que les tuyaux sont bien raccordés,
que les failles trouvées sont fermées, que l'attaque la plus grave échoue
maintenant pour de bon. Elle ne remplace pas la relecture d'un cryptographe sur
la fonction de mélange elle-même. C'est le préalable que le livre blanc marque,
à juste titre, comme ouvert — et la seule chose, désormais, qui se dresse entre
ce code et une genèse sereine.
