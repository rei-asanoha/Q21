# Phase 8 — audit adverse, et la fabrique de clés

## La méthode

Deux auditeurs indépendants ont reçu une consigne unique : **casser Q21**. Pas
relire, pas commenter le style — trouver ce qui permet de créer de la monnaie,
de dépenser deux fois, de faire diverger deux nœuds honnêtes, ou de figer un
nœud à distance. Et démontrer chaque trouvaille par un test exécutable, parce
qu'une faille qu'on ne sait pas reproduire est une hypothèse.

Ils ont trouvé **onze failles réelles**, dont deux critiques. Toutes sont
corrigées, et chaque exploit est devenu une épreuve de non-régression : le test
qui prouvait l'attaque vérifie désormais qu'elle échoue.

---

## Les deux failles critiques

### 1. Un oncle ne coûtait aucun travail

`pow.check(oncle)` vérifiait la preuve de travail contre `oncle.bits` — un champ
que l'auteur de l'oncle remplit lui-même. Pour un bloc ordinaire, la difficulté
attendue était comparée ; **pour un oncle, cette comparaison n'existait pas**.

Un attaquant fabriquait donc un en-tête avec une cible quasi maximale, `nonce`
à zéro, et se le faisait payer. Aucun calcul. Deux oncles par bloc, à chaque
bloc, indéfiniment — chaque faux oncle ayant un identifiant neuf, la règle
anti-double-paiement ne le voyait jamais.

Mesure de l'auditeur : *« bloc 5 émet 725 937 au lieu de 345 685, ×2,10 »*.

**Correction** : un oncle doit porter la difficulté que la chaîne imposait à sa
hauteur. La même règle ferme aussi la porte à l'inondation de branches latérales
(faille 7).

### 2. Le plafond de 21 000 001 n'était pas un plafond

C'est la faille qui touche le cœur du projet, et elle existait **même sans
attaquant**.

Les parts d'oncles étaient **ajoutées** à la subvention, plus une prime
d'inclusion. Un bloc pouvait donc émettre 210 % de son dû, et rien dans le code
ne comparait jamais l'émission cumulée au plafond. L'émission maximale réelle du
protocole s'établissait à **44 099 999 Q21**, pour un plafond annoncé à
21 000 001.

Mesure de l'auditeur : *« émission maximale réelle 44 099 999 Q21 contre un
plafond annoncé de 21 000 001 »*.

**Correction, en deux temps.**

D'abord la structure : les parts d'oncles sont désormais **prélevées sur** la
subvention. `part_mineur + n × par_oncle == subvention(hauteur)`, toujours. Un
bloc émet exactement sa subvention, quoi qu'il contienne. Le plafond tient par
construction.

Ensuite le dernier rempart : une règle de consensus refuse tout bloc qui
porterait l'émission cumulée au-delà de `MAX_SUPPLY`. Elle ne dépend d'aucun
calendrier, d'aucun oncle, d'aucun calcul de frais. **Même si une règle
économique se révélait fausse — c'est arrivé deux fois sur ce projet — aucun bloc
ne peut franchir 21 000 001 Q21.**

**Le prix, dit franchement.** Inclure un oncle coûte désormais au mineur ce qu'il
verse. Dans une monnaie à plafond fixe il n'y a pas d'échappatoire : une
récompense d'oncle est soit inflationniste, soit prélevée sur le mineur. Le
plafond est le projet ; l'incitation monétaire à inclure les oncles est donc
faible, et c'est une question économique ouverte, pas un oubli. Bitcoin, lui,
n'a aucune récompense d'oncle.

---

## Les failles graves

### 3. Deux coinbases pouvaient partager un identifiant (BIP 30)

L'identifiant d'une coinbase ne dépendait d'**aucun** élément d'unicité : ni
hauteur, ni extranonce. Deux blocs du même mineur pour le même montant
produisaient le même `txid`. La seconde sortie écrasait la première dans le jeu
d'UTXO, et défaire la seconde détruisait la sortie de la première.

Résultat mesuré : *« même tête, UTXO A = 100 414 822 vs B = 100 415 822 »*. Deux
nœuds honnêtes, la même chaîne, des soldes différents — une scission silencieuse.

**Correction** : la hauteur est engagée dans l'identifiant de la coinbase, et une
règle de consensus vérifie qu'elle y est. C'est la leçon de BIP 30 et BIP 34,
réapprise ici par un audit.

### 4. `try_reorg` pouvait boucler indéfiniment

La boucle de restauration jetait la valeur de retour de `disconnect()`. Après une
reprise sur instantané — où la fenêtre d'annulation est courte — cette boucle ne
progressait jamais : le nœud tournait en rond, **verrou de chaîne tenu**. Le fil
de l'auditeur n'a jamais rendu la main.

**Correction** : la profondeur de réorganisation est vérifiée contre la fenêtre
d'annulation **avant** de toucher à quoi que ce soit, et aucune boucle ne
s'appuie plus sur une fonction qui peut refuser.

### 5. `disconnect` corrompait l'émission quand il échouait

Il écrasait le compteur d'émission **avant** de constater qu'aucune annulation
n'était disponible. Après une reprise sur instantané, le compteur tombait à zéro.

**Correction** : ordre inversé. On ne mute rien tant qu'on n'est pas certain
d'aller au bout.

### 6. Un oncle déjà payé redevenait payable après un redémarrage

La règle anti-double-paiement lisait les corps de blocs **en mémoire**. Après une
reprise sur instantané ils sont absents : l'ensemble était incomplet, et un nœud
fraîchement redémarré acceptait ce qu'un nœud complet refusait.

**Correction** : la règle relit les corps sur disque, et **échoue bruyamment** si
un corps manque. Valider à l'aveugle une règle anti-fraude est pire que ne pas la
valider : on se croit protégé.

### 7. Amplification réseau, deux fois

`getdata` : vingt mille fois le même hachage → vingt mille copies du bloc.
660 Kio de requête pour 6,8 Mio de réponse, et pour un bloc compact tous les
identifiants courts recalculés à chaque copie. Sur des blocs réels de 4 Mio :
80 Gio.

`getblocktxn` : cent mille fois le même indice → une trame de 15,5 Mio, qui
dépassait même le `MAX_PAYLOAD` du protocole. Fabriquer une réponse que personne
ne peut lire est la définition d'un déni de service.

Et les deux fonctionnaient **sans poignée de main** : leur coût pour l'attaquant
se résumait à un `connect()`.

**Correction** : poignée de main exigée, items dédoublonnés, budget d'octets en
sortie.

### 8. Un bloc compact de 170 octets clonait tout le réservoir

Chaque annonce compacte déclenchait une copie intégrale du mempool — jusqu'à
64 Mio — **sous le verrou global**, donc en sérialisant tout le nœud.

**Correction** : on ne retient que les transactions dont l'identifiant court
figure dans l'annonce, et on refuse le message avant toute dépense si le parent
du bloc est inconnu.

### 9. Aucun délai d'écriture

Un pair qui n'accueillait jamais ses octets bloquait indéfiniment le fil qui lui
écrivait, en tenant le verrou de son flux. Comme les diffusions écrivent vers
tous les pairs, un seul pair silencieux finissait par bloquer la propagation
entière.

**Correction** : trente secondes, puis la connexion tombe et le réseau continue.

---

## La régression que j'ai introduite en corrigeant

Mon garde-fou de poignée de main **coupait** la connexion. Au premier essai réel,
deux nœuds honnêtes se sont coupés immédiatement — hauteur bloquée à zéro.

La cause : un nœud qui mine annonce ses blocs dès qu'il a un pair. Le pair
demande le bloc, et sa requête arrive avant son `verack`. Une course parfaitement
bénigne, que je punissais d'une rupture. Un garde-fou qui provoque une partition
réseau est pire que la faille qu'il ferme.

**Correction** : on ne sert rien avant la poignée de main, mais on ne coupe pas —
et on n'annonce plus rien à un pair dont la poignée de main n'est pas achevée.

C'est la cinquième fois sur ce projet qu'un défaut sérieux n'apparaît qu'en
lançant deux vrais processus.

---

## Ce que l'audit n'a **pas** trouvé

Dit aussi clairement que le reste, parce qu'un audit qui ne trouve rien quelque
part est une information :

- **CVE-2012-2459** (collision Merkle par duplication de la dernière feuille) :
  absente. Les étiquettes distinctes feuille/branche la rendent structurellement
  impossible. Vérifié pour toutes les tailles de 1 à 64.
- **Malléabilité de `txid`** : impossible pour un tiers. Le témoin est hors du
  `txid`, et les varints sont canoniques avec refus explicite.
- **Rejeu de signature** entre entrées ou entre transactions : impossible, le
  sighash lie l'indice de l'entrée et toute la transaction dépouillée.
- **Dépense intra-bloc** et **maturité de coinbase** : les deux règles tiennent.
- **Dépassements arithmétiques** sur les montants : `checked_add` partout,
  `overflow-checks` actif sur les trois profils. Rien d'exploitable.

---

## La fabrique de clés

Vous avez demandé si j'avais travaillé l'élément qui crée les portefeuilles. Je
ne l'avais pas fait, et il y avait trois défauts sérieux.

### Le générateur d'aléa échouait sous Windows

```rust
std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?
```

Ce fichier n'existe pas sous Windows. `q21 init` y échouait purement et
simplement — sur le système le plus répandu.

Et rien ne vérifiait ce qui en sortait. Une source dégradée aurait produit une
graine prévisible sans qu'aucun message ne l'indique. Une clef privée ne vaut
que son aléa : c'est le maillon le plus court de toute la chaîne, et celui qu'on
regarde le moins.

Le module `rng` interroge désormais le générateur du système sur chaque
plateforme — `/dev/urandom` sur les systèmes POSIX, `BCryptGenRandom` sur
Windows — et **échoue plutôt que de rendre un aléa de qualité inconnue**. Il ne
mélange rien : ajouter une horloge à une source cassée ne renforce rien, cela
masque la panne.

### La graine vivait en clair sur le disque

Soixante-quatre caractères hexadécimaux dans `wallet.dat`, avec les permissions
par défaut. Toute personne ayant lu ce fichier une fois — une sauvegarde, un
disque revendu, un dossier partagé — détenait définitivement les fonds.

Le portefeuille est désormais **chiffré et authentifié** par une phrase secrète :
PBKDF2-HMAC-SHA256 à 600 000 itérations, flot chiffrant HMAC en mode compteur,
chiffrer-puis-authentifier. Aucune primitive nouvelle — uniquement des
constructions standard au-dessus de SHA-256, et HMAC est vérifié contre quatre
vecteurs officiels du RFC 4231, PBKDF2 contre celui du RFC 7914. Le fichier est
en `0600`, même sans phrase secrète, et l'absence de phrase est signalée en
capitales.

Un test modifie **chaque octet du fichier scellé, un par un** : tous sont
détectés, en-tête compris — sans quoi un attaquant ramènerait le nombre
d'itérations à un.

### La sauvegarde n'avait aucune somme de contrôle

La graine était rendue en hexadécimal brut. Recopier soixante-quatre caractères à
la main est une opération où l'on se trompe, et une seule faute de frappe donne
une graine parfaitement valide qui n'ouvre rien. La perte est silencieuse et
définitive.

Le code de sauvegarde est désormais en **Bech32m** — le même encodage que les
adresses : alphabet sans caractères confondables, et somme de contrôle qui
détecte jusqu'à quatre erreurs.

```
rq21seed18zpjwkqmz5kvhxk2vw6fnzek3js5dzk3w7stkx66jfugyfsflemsjlt3za
```

Un test substitue **chaque caractère** du code par sept autres : les 400 fautes
de frappe sont détectées, aucune ne passe. Le préfixe désigne le réseau — une
graine de test ne peut pas être prise pour une graine du réseau principal.

Et un code qu'on ne peut pas rejouer ne sert à rien : `q21 restore`
reconstitue le portefeuille. Vérifié de bout en bout — les adresses dérivées sont
identiques, caractère pour caractère. *(Le code se saisissait alors en argument ;
l'audit v2 a montré qu'il finissait dans l'historique du terminal, et il est
depuis demandé au terminal sans écho ou lu par `--code-fichier`.)*

### Ce qui a aussi été ajouté

- Saisie de la phrase secrète **sans écho** — API console sous Windows, `stty`
  sous POSIX — avec confirmation, et un avertissement explicite si l'écho n'a pas
  pu être coupé plutôt qu'un faux-semblant.
- La graine est effacée de la mémoire à la destruction du portefeuille
  (`write_volatile`, que l'optimiseur n'a pas le droit de supprimer).

### Ce qui reste ouvert

**PBKDF2 n'est pas memory-hard.** Un attaquant équipé de circuits dédiés teste
les phrases bien plus vite qu'un processeur. Argon2 ou scrypt seraient meilleurs,
et les écrire soi-même serait exactement le genre d'initiative que ce projet
refuse. La vraie défense reste la **longueur de la phrase secrète**, et le module
le dit plutôt que de le taire.

---

## Tableau de vérification — une preuve par faille

Chaque ligne renvoie à un test exécutable. Une correction sans test n'est pas une
correction : c'est un pari sur le fait que personne ne réintroduira le défaut.

| # | Faille | Correction | Épreuve |
|---|---|---|---|
| 1 | Oncle sans travail | Difficulté imposée à la hauteur de l'oncle | `un_oncle_sans_travail_est_refuse` |
| 2 | Plafond franchissable | Oncles prélevés sur la subvention **+** rempart absolu | `un_bloc_emet_exactement_sa_subvention…`, `l_emission_reelle_ne_depasse_jamais…`, `aucun_bloc_ne_franchit_le_plafond_absolu` |
| 3 | Coinbases au même `txid` | Hauteur engagée dans le `txid`, et vérifiée | `deux_coinbases_de_hauteurs_differentes…`, `une_coinbase_sans_hauteur_est_refusee` |
| 4 | `try_reorg` en boucle | Fenêtre d'annulation vérifiée avant toute mutation | `une_reorganisation_impossible_echoue_au_lieu_de_boucler` |
| 5 | `disconnect` corrompt l'émission | Ordre inversé : rien n'est muté avant certitude | `un_disconnect_refuse_ne_touche_a_rien` |
| 6 | Oncle repayable après reprise | Corps relus sur disque, échec bruyant sinon | `un_oncle_deja_paye_reste_refuse_apres_une_reprise` |
| 7 | Branches latérales gratuites | Difficulté vérifiée avant indexation | `une_branche_laterale_sans_travail_est_refusee` |
| 8 | `getdata` amplifié | Dédoublonnage + budget d'octets | `getdata_a_hachages_repetes_n_amplifie_plus` |
| 9 | `getblocktxn` amplifié | Idem, plus indices dédoublonnés | `getblocktxn_a_indices_repetes_n_amplifie_plus` |
| 10 | Servi sans poignée de main | Rien n'est servi avant `verack` | `rien_n_est_servi_avant_la_poignee_de_main` |
| 11 | Bloc compact clonant le mempool | Filtrage par identifiant court, refus si parent inconnu | `un_bloc_compact_orphelin_ne_declenche_aucun_travail` |

Deux corrections n'ont **pas** de test dédié, et il faut le dire :

- le **délai d'écriture** de trente secondes vers un pair : le vérifier
  demanderait un pair qui n'accueille jamais ses octets pendant une demi-minute,
  soit un test d'une demi-minute par exécution. La correction tient en une ligne
  et se lit ;
- la **borne dérivée** du nombre de transactions par bloc est vérifiée **à la
  compilation** (`const _: () = assert!(…)`), ce qui est plus fort qu'un test.

## Vérifications

- **480 tests** au total, dont **340** de bibliothèque, zéro avertissement
  clippy sur `src/`.
- **11 épreuves de non-régression consensus** et **4 réseau**, chacune issue d'un
  exploit qui fonctionnait.
- Deux nœuds réels : le second rejoint une chaîne minée à 250 blocs/s et
  rattrape 7 221 blocs.
- Restauration depuis code de sauvegarde : adresses identiques.
- Portefeuille chiffré : mine, envoi, redémarrage — et une phrase fausse donne le
  même message qu'un fichier altéré.

## Seconde vague — l'état sur disque (phase 8b)

Cinq auditeurs ont attaqué cinq axes que la première vague n'avait pas couverts.
Celui qui a le plus rapporté est le plus prosaïque : **ce qu'un nœud relit au
démarrage**. La chaîne était défendue ; ses fichiers ne l'étaient pas.

| # | Faille | Ce qu'elle permettait | Correction | Épreuve |
|---|---|---|---|---|
| 12 | `state.dat` cru sur parole | Ajouter une sortie d'un milliard d'unités au nom de l'attaquant, somme de contrôle recalculée : le nœud repartait avec de la monnaie jamais minée | Confrontation au **calendrier d'émission** : total émis ≤ ce que le calendrier permet à cette hauteur, somme des UTXO ≤ total émis, aucune sortie datée d'un bloc futur | `g_instantane_fabrique_credite_des_fonds_inexistants` |
| 13 | `emis` non lié à la chaîne | Un `emis` forgé faisait **refuser un bloc que tout nœud complet acceptait** — deux verdicts sur le même bloc, donc scission | Même contrôle : un `emis` impossible fait rejeter l'instantané et revalider | `ba_emis_forge_fait_refuser_un_bloc_valide`, `bb_…` |
| 14 | Fichier d'état importable | Un « instantané de synchronisation rapide » venu d'ailleurs était adopté | **Sceau** HMAC-SHA256 par clef propre au répertoire (`node.key`, 0600) | `un_fichier_quelconque_n_est_pas_un_instantane` |
| 15 | Genèse étrangère adoptée | Un `blocks.dat` fabriqué — sans preuve de travail, prémine de 21 M vers l'attaquant — devenait la racine | Le premier enregistrement doit porter **l'identifiant de genèse du réseau** | `f_un_fichier_de_blocs_etranger_est_adopte_comme_genese` |
| 16 | Cache d'adresses forgé | Une seule empreinte substituée : solde faux, fonds propres masqués, et une clef Lamport **brûlée** pour une transaction que le réseau rejette | Trois barrières : cache **scellé** par une clef dérivée de la graine ; ré-dérivation intégrale sous 1 024 adresses, échantillon √n au-delà ; et surtout, `create_transaction` vérifie que la clef ouvre le verrou **avant** de signer | `m_…`, `n_…`, `o_cache_forge_brule_une_clef_lamport` |
| 17 | Carnet de pairs épinglable | 512 groupes remplis d'adresses jamais jointes, `last_seen = u64::MAX` : plus aucune adresse honnête ne pouvait entrer, la sélection ne rendait que celles de l'attaquant — **éclipse complète sans posséder une machine** | Horodatage borné à l'ajout ; un groupe qui n'a jamais répondu cède sa place ; l'ordre de sélection tient à un **sel local**, pas à un champ que l'adversaire écrit | `p_carnet_hostile_epingle_tous_les_groupes` |
| 18 | Succès des pairs oubliés | Le carnet était réécrit à zéro à chaque arrêt : un nœud oubliait à chaque redémarrage quels pairs lui avaient réellement répondu | Les entrées sont écrites telles quelles (`save_entrees`) | `aller_retour_sur_le_disque` |
| 19 | Blocs reçus jamais écrits | Seuls les blocs **minés par soi** atteignaient le disque. Un nœud qui minait en se synchronisant produisait un fichier troué et repartait sept blocs en arrière, sans un mot | Trait `Journal` branché sur la chaîne : accepter un bloc et le conserver sont la même décision. Les branches latérales aussi, sans quoi aucune réorganisation ne survit à un redémarrage | `d_bis_le_noeud_ne_redemarre_plus_apres_avoir_mine_en_se_synchronisant` |

### La dette assumée : l'engagement sur le jeu d'UTXO

Les contrôles de cohérence attrapent toute falsification qui **crée** de la
monnaie. Ils n'attrapent pas celle qui la **déplace** : réécrire l'empreinte
d'une sortie existante respecte tous les invariants d'émission.

Le sceau du répertoire ferme le cas réaliste — un fichier venu d'ailleurs. Il ne
ferme pas le cas d'un adversaire qui a déjà les droits d'écriture sur le
répertoire, et sur ce point la position est celle de Bitcoin Core, énoncée
franchement : qui peut réécrire vos fichiers peut aussi réécrire le binaire.

La réponse définitive est un **engagement sur le jeu d'UTXO inscrit dans
l'en-tête de bloc** — un accumulateur homomorphe de type MuHash, mis à jour en
temps constant à chaque sortie créée ou dépensée. Il rendrait tout instantané
vérifiable en O(1) contre une donnée portée par la preuve de travail. Il demande
une arithmétique modulaire sur 3 072 bits, donc du code de consensus neuf : ce
n'est pas une ligne à ajouter, et ce n'est pas une chose à bâcler la veille d'un
lancement. **C'est inscrit comme préalable au réseau principal, pas au testnet.**

## Le lancement reel — ce que le circuit ferme n'avait pas vu

Toutes les epreuves ci-dessus tournent dans le meme processus. Un lancement
reel, lui, fait tourner de vrais binaires, sur de vrais fichiers, avec de vrais
sockets. Il a trouve en quinze minutes deux defauts que 480 tests n'avaient pas
vus — dont un que **je venais d'introduire en corrigeant autre chose**.

### Le deroule

| Etape | Resultat |
|---|---|
| Deux portefeuilles neufs, meme genese | `8e16a638…` des deux cotes |
| Alice mine 205 blocs | 0,66 s — 79 673 condensats/s |
| Alice envoie 0,005 Q21 a Bob | transaction `fca8d6ec…`, temoin Lamport 98 Kio (99 % de la taille) |
| Bob se synchronise par TCP | 206 blocs, 205 blocs compacts **sans aucun aller-retour** |
| Bob recoit | 0,00500000 Q21, survit au redemarrage |
| Bob renvoie 0,002 Q21 a Alice | aller-retour complet |
| Deux noeuds minent l'un contre l'autre, 30 s | 1 095 blocs, **0 orphelin, 0 invalide** |
| Consensus | bloc 1300 identique octet pour octet des deux cotes |
| Invariant monetaire | emis = somme des UTXO = 586,55780008 Q21, **exactement** |
| Rejeu d'un ancien `wallet.dat` | refuse, avec la marche a suivre |
| Instantane corrompu | ignore, chaine revalidee, meme tete |
| Fichier de blocs d'une autre chaine | refuse en nommant les deux genese |
| CSRF, reliaison DNS, jeton dans l'URL | 403, 403, 401 |

### Faille 20 — le repli de securite ne fonctionnait plus

Corriger la faille 19 — consigner **aussi** les branches laterales, sans quoi
aucune reorganisation ne survit a un redemarrage — a casse le rejeu integral.
Celui-ci appelait `connect`, qui exige que chaque bloc prolonge la tete active.
Le fichier n'est plus une ligne droite depuis qu'il contient les branches
concurrentes que produit toute course entre mineurs.

Le noeud refusait de redemarrer :
`bloc 853 refuse au rejeu : HauteurIncorrecte { attendu: 853, recu: 218 }`.

Et ce chemin est precisement le **repli** : celui qu'on emprunte quand
l'instantane est perdu ou suspect. Le defaut le rendait inutilisable au moment
ou il compte. `submit` remplace `connect` ; l'ordre du fichier est celui de
l'acceptation, donc un parent y precede toujours ses enfants.
Epreuve : `un_fichier_contenant_des_branches_laterales_se_rejoue`.

**Ce qu'il faut en retenir** : ce defaut etait invisible en circuit ferme parce
qu'aucune epreuve ne produisait de branche laterale *puis* ne redemarrait sans
instantane. Il a fallu deux processus, deux mineurs et trente secondes de course
pour le faire apparaitre.

### Faille 21 — la protection rendait le noeud inutilisable

Exiger le jeton pour la page de l'explorateur donnait un `401` en texte brut :
la page ne pouvait plus se charger, donc plus demander le jeton. Le noeud etait
protege et hors d'usage. La coquille statique — qui ne porte aucune donnee — est
desormais servie librement, par une liste de chemins **nommes explicitement**,
vide par defaut ; toute methode RPC reste derriere l'authentification.

### Deux corrections apportees pendant ce lancement

- **`hote_local` comparait un prefixe de texte.** `127.0.0.1.evil.example` est un
  nom de domaine qu'on enregistre en cinq minutes, et il franchissait les quatre
  verrous d'un coup : la reliaison DNS etait entierement rouverte. Le filtre
  analyse desormais une adresse. Epreuve :
  `un_nom_qui_ressemble_a_du_bouclage_n_en_est_pas`.
- **L'echeance globale ne descendait pas jusqu'a la lecture.** `lire_ligne` lit
  octet par octet ; un octet toutes les vingt-cinq secondes tenait une connexion
  des dizaines d'heures. Soixante-quatre suffisaient a fermer le service.

### Ce qui reste ouvert apres le lancement reel

Rien qui vole des fonds, rien qui casse le consensus. Ce qui reste est du
**deni de service** et de la **qualite du marche des frais** :

| Constat | Nature | Pourquoi ce n'est pas bloquant pour un testnet |
|---|---|---|
| Cout de saturer le reservoir (t03, t06, t08) | Ressources d'un noeud | Aucun fonds en jeu. Un testnet est l'endroit ou l'on mesure si cela mord vraiment |
| CPFP casse par l'eviction (t12) | Marche des frais | Une transaction bien payante peut etre evincee avec son parent. Genant, pas dangereux |
| ~~Malleabilite de message (4 constats)~~ | **Ferme** | Un decodeur refuse desormais ce qu'il ne sait pas representer, au lieu de tronquer |
| ~~Amplification memoire a la lecture~~ | **Ferme** | 61 115 fois ce qui est recu, ramene a zero. Voir ci-dessous |

### La lecture d'un message n'amplifie plus rien

Le rapport d'allocation etait mesure par `rapport_allocation_par_message`, et
personne ne l'avait jamais lu : l'outil de mesure lui-meme debordait — il
soustrayait la taille de blocs liberes pendant la mesure mais alloues avant
elle, le compteur passait sous zero, et l'addition suivante paniquait.

Une fois l'outil repare, le rapport est sans appel :

```
inv          :    27 octets envoyes -> pic   1650003 octets alloues (x61111)
getdata      :    27 octets envoyes -> pic   1650007 octets alloues (x61111)
headers      :    27 octets envoyes -> pic    320007 octets alloues (x11852)
block        :   189 octets envoyes -> pic    262149 octets alloues (x1387)
```

Vingt-sept octets annoncant cinquante mille inventaires — cinquante mille est
la borne du protocole, le controle passait — faisaient reserver un million six
cent cinquante mille octets avant d'echouer sur une fin prematuree. Pour le
prix d'un envoi, et sur soixante-quatre connexions.

Plafonner la reservation par `with_capacity(n.min(1024))` attenuait sans
fermer : il restait un facteur mille.

La regle qui ferme cela tient en une phrase, et vaut pour tout decodeur :
**on ne reserve jamais de place pour plus d'elements que le reste de l'entree
ne peut en contenir.** Chaque element ayant une taille minimale connue sur le
fil — trente-trois octets pour un inventaire, quarante pour une entree de
transaction, quarante et un pour une sortie — la comparaison est exacte et ne
coute rien.

Apres correction, le pire rapport de tous les messages est **zero**.

## Le niveau de securite retenu : ML-DSA-87

La question posee etait celle d'une clef privee de 512 bits. La reponse tient en
deux faits, et le second decide.

**FIPS 204 fixe la graine a trente-deux octets pour les trois niveaux.** La
bibliotheque le dit dans son propre code : *« ML-DSA seeds are signing (private)
keys, which are consistently 32-bytes across all security levels »*. Une graine
de 512 bits demanderait de reecrire ML-DSA a la main — la seule chose que ce
projet s'interdit, et pour de bonnes raisons.

**Et elle n'apporterait rien.** La resistance quantique de ML-DSA ne vient pas
de la longueur de la graine mais du probleme sur reseaux euclidiens. Une graine
de 256 bits face a Grover vaut 2^128 : un mur que rien n'atteindra.

Le levier reel est le niveau de la norme, et la mesure a tranche :

| | ML-DSA-65 | ML-DSA-87 |
|---|---|---|
| Niveau NIST | 3 (~AES-192) | **5 (~AES-256)** |
| Verifications par seconde | 3 944 | 2 494 |
| Clef publique | 1 952 o | 2 592 o |
| Signature | 3 309 o | 4 627 o |
| Transaction complete | 5 403 o | 7 361 o |
| Transactions par bloc de 2 Mo | 370 | 271 |
| **Bloc plein verifie en** | **94 ms** | **109 ms** |

Le bloc vise cent vingt secondes. Le niveau maximal coute **quinze
millisecondes par bloc**. Ce qui se paie vraiment est le debit — 27 % de
transactions en moins pour la meme taille — et cet arbitrage penche du cote de
la marge : une chaine se lance une fois, et les adresses qu'elle emet vivent des
decennies.

**ML-DSA-87 est donc le defaut de Q21.** Verrouille par
`le_defaut_est_le_niveau_maximal_de_la_norme` : le schema entre dans
l'identifiant du bloc de genese, le faire glisser changerait la chaine.

### Ce qui n'a pas ete fait, et pourquoi

**Les condensats restent en 256 bits.** Passer SHA-256 a SHA-512 toucherait 273
endroits du code — tout le consensus, tout le stockage, et le reglage
memory-hard de la phase 6. Le prix se paierait sur l'utilisateur : une adresse
de **113 caracteres au lieu de 62**, un code de sauvegarde de 117, un en-tete de
bloc de 288 octets au lieu de 160. Le gain serait nul : Grover sur SHA-256 donne
2^128, le meme mur inatteignable. C'est le choix de Bitcoin, et il n'est pas
conteste.

### Verifie sur un lancement reel

Testnet, deux noeuds, ML-DSA-87 de bout en bout : genese `02140e8a…` identique
des deux cotes, 205 blocs mines, transaction de 7 361 octets, synchronisation
par TCP, reception de 0,005 Q21, aller-retour vers l'expediteur. Le banc de
mesure des signatures est conserve : `cargo run --release --features mldsa
--example bench_sig`.

## Ce qui reste, et qui compte davantage que tout le reste

**La preuve de travail n'a toujours reçu aucune cryptanalyse externe.** Depuis la
phase 6, c'est le point ouvert le plus important du projet.

Et cet audit a été mené par des auditeurs que j'ai instruits, sur du code que
j'ai écrit. Il a trouvé onze failles réelles, ce qui prouve son utilité — et ne
prouve rien sur ce qu'il n'a pas trouvé. **Un audit humain externe reste
nécessaire avant qu'un seul Q21 ait la moindre valeur.**

---

## Troisième vague — la revue de septembre 2026

Relecture complète, en lecture seule d'abord : toute la suite d'épreuves
rejouée, deux simulations écrites à côté pour chiffrer ce que les épreuves ne
mesuraient pas, puis un bilan classé par gravité. Les corrections ont suivi,
une par commit, chacune avec son épreuve. Le réseau vivant étant le réseau de
test, les règles ont changé sans activation différée : nouvelle genèse,
nouvelle magie réseau, protocole version 2.

### Ce qui touchait le cœur du projet

**Le parcours mémoire de la preuve de travail tenait sur 32 bits.** L'indice
de chaque lecture venait des 32 bits bas de l'accumulateur, et l'addition n'y
faisait jamais remonter de retenue : les trente-deux lectures d'une tentative
ne dépendaient que d'un mot de 32 bits. Une table de 2³² sommes — 128 Gio,
calculée une fois par époque — remplaçait le parcours par une seule lecture,
et la croissance de la table ne protégeait plus de rien. Vérifié par
simulation : sur mille paires d'états de mêmes bits bas, aucune ne divergeait.
L'indice dépend désormais des quatre mots de l'état, et chaque lecture est
suivie de quatre tours de Feistel sur la finalisation de SplitMix64 — une
vingtaine de nanosecondes, pour un accès DRAM qui en coûte une centaine.
Épreuves : `deux_etats_de_memes_bits_bas_ne_parcourent_pas_les_memes_adresses`,
`une_lecture_se_diffuse_sur_tout_l_etat`.

**Une partition à puissance égale devenait définitive en deux heures.** La
majoration de réorganisation croissait sans plafond ; chaque moitié du réseau
se voyait majorée contre l'autre. Simulation avec la règle réelle : dernière
réunification possible à 66 blocs en médiane pour une minorité à 50 %, 153 à
40 % — la documentation annonçait vingt-quatre heures. Plafond à 25 % : toute
majorité au-delà de 56 % réunifie dans la fenêtre. Épreuve `a7`.

**Créer une sortie ne coûtait rien.** Ni plancher, ni tarif au-delà d'une
unité par millier d'unités de poids : vingt gigaoctets de mémoire vive par
jour imposés à chaque nœud pour quelques milliers d'unités, et un mineur, qui
se paie ses propres frais, n'était freiné par rien. Plancher de consensus à
10 000 unités par sortie, coinbase comprise ; 400 unités de poids par sortie
créée au relais ; plancher de relais à 10 ; le portefeuille refuse la
poussière avant de signer et laisse aux frais une monnaie sous le plancher.

**La table plafonne à 4 Gio, plus 8.** Une machine à 8 Go suffit pour
toujours ; c'était la promesse.

### Ce qui figeait ou trompait le nœud

- Chaque transaction reçue et chaque bloc connecté **recopiaient tout le jeu
  d'UTXO** sous le verrou global. Le réservoir lit une référence.
- L'empreinte MuHash était **recalculée intégralement** — une multiplication
  de 3 072 bits par sortie, 19 µs chacune — à chaque affichage de
  l'explorateur public et à chaque instantané. Tenue au fil de l'eau ;
  `commitment()` coûte une division, quelle que soit la taille.
- La difficulté du bloc suivant recopiait **tous les en-têtes depuis la
  genèse** à chaque connexion. Elle lit la fenêtre.
- Le mineur **minait sous le verrou de la chaîne**, deux millions d'essais
  par tour, et y construisait sa table au changement d'époque : des secondes,
  puis des minutes, sans un bloc traité ni un pair servi. Il mine dehors.
- Une branche latérale n'était **pas contrôlée sur l'horodatage** : la
  difficulté baissait le long de la branche, et des corps de 4 Mio entraient
  à bon compte. Même contrôle que sur la chaîne active.
- Les corps d'une amorce adoptée **atteignaient le disque sans être
  confrontés aux en-têtes**. Ils le sont, avant le moindre octet écrit.
- La borne symétrique des temps de résolution laissait encore **un tiers de
  blocs en plus** à qui avançait ses horodatages avec la moitié de la
  puissance. Borne dissymétrique `[-6T, +4T]` : la manipulation augmente la
  difficulté et coûte à son auteur ; tolérance future ramenée à dix minutes.

### Ce qui touchait le portefeuille

- Une **confirmation de phrase qui différait** était traitée comme « pas de
  phrase » : graine en clair pour une faute de frappe. Redemandée, puis refus.
- Les indices Lamport consommés étaient écrits **après** la signature et via
  un rappel sans résultat : une coupure au mauvais moment faisait resigner
  avec une clef morte. Écriture anticipée, `fsync`, refus si le disque refuse.
- Le message signé n'engageait **ni le réseau ni la sortie dépensée** : une
  signature du réseau de test valait sur l'autre. Le condensat engage les
  deux, comme BIP-143.
- La feuille de Merkle n'engageait que le `txid` : une signature pouvait
  être **remplacée en transit**. Elle engage aussi le `wtxid`.
- Secrets effacés à leur destruction, `Q21_PASSPHRASE` retirée de
  l'environnement après lecture, aucun vidage mémoire sous Unix.

### Ce qui a été retiré

**Les oncles.** Leur part était prélevée sur le mineur qui les incluait :
personne ne le faisait, le mineur du binaire ne l'a jamais fait, et le
mécanisme avait déjà porté trois défauts. Un bloc qui en porte est refusé.

### La chaîne de livraison

Chaîne d'outils figée (`rust-toolchain.toml`), attestation de provenance
signée par GitHub pour chaque archive, `SHA256SUMS` unique signé par
`minisign` quand le dépôt détient la clef, `cargo deny` sur chaque poussée.
L'épreuve `audit_difficulte`, entièrement verte depuis la réécriture de son
dernier constat périmé, bloque désormais la livraison comme les autres.

### Ce qui reste

**La preuve de travail n'a toujours reçu aucune cryptanalyse externe.** Sa
boucle de mélange vient d'être refaite ; c'est une raison de plus, pas une de
moins. Les ancrages compilés sont vides tant qu'aucune chaîne n'a assez
d'histoire pour en mériter un. Et cette revue, comme les précédentes, ne
prouve rien sur ce qu'elle n'a pas trouvé.

### Suite immédiate — la serrure du portefeuille

Le fichier de portefeuille était scellé par PBKDF2, qui ne coûte que du
calcul : le README le disait depuis la phase 8, et le bilan de septembre le
classait parmi ce qui protège directement les gens. La dérivation est
désormais **Argon2id** (RFC 9106, 64 Mio, trois passes), écrite d'après la
norme avec BLAKE2b (RFC 7693), vérifiée contre les trois vecteurs officiels
puis contre-vérifiée par une implémentation indépendante sur la forme exacte
qu'emploie le portefeuille. Les fichiers de l'ancien format s'ouvrent et sont
rescellés à l'ouverture ; ouvrir un portefeuille coûte 0,19 s sur un petit
processeur, moins qu'avant, pour une résistance sans commune mesure face au
matériel dédié.

### Suite immédiate — le disque, et la veille

**Le fichier de blocs s'élague** (`node --elaguer`) : un nœud qui valide pour
lui ne garde que la genèse et les six mille derniers corps — la fenêtre
d'historique du portefeuille plus la fenêtre de réorganisation, huit jours —
et résume le reste dans l'instantané, comme un nœud parti d'une amorce.
L'ordre des écritures est prouvé par une épreuve qui élague une chaîne puis
la redémarre exactement comme le fait le binaire : même tête, même jeu
d'UTXO, même émission, et elle continue. Un nœud élagué refuse de servir
d'explorateur. L'archive sérialise désormais ajouts, lectures et réécriture
sous un seul verrou.

**Une veille sans regarder** (`outils/surveiller.sh`) : la hauteur est relue
toutes les dix minutes ; figée trente minutes, ou RPC muet, le service est
relancé et le téléphone prévenu. Rien de plus qu'un script et un minuteur —
mais c'est la différence entre un réseau et un projet.

## Quatrième vague — l'audit adverse, et ses correctifs

Une revue menée en attaquant, sur cinq axes lus ligne à ligne — consensus,
réseau, portefeuille, preuve de travail et disque, exploitation — avec des
épreuves écrites pour reproduire chaque piste. Le verdict d'abord : **aucune
voie d'inflation, de double dépense ni d'exfiltration de clé à distance** ;
les invariants monétaires tiennent, et les décodeurs, le scellement, le
sighash, la difficulté et l'instantané ont résisté. Les failles étaient
ailleurs, et toutes sont fermées par cette vague.

| Faille | Ce qui est fermé, et comment on le sait |
|---|---|
| Une transaction à signature fausse, poussée par un inconnu sans poignée de main, forçait une vérification post-quantique **sous le verrou global** : soixante par seconde figeaient un nœud | `Tx` et `Block` exigent la poignée de main ; budget par pair (64, puis 8/s) ; une transaction invalide en soi coûte des points. Épreuves `rien_n_est_lu_avant_la_poignee_de_main_meme_pousse`, `le_budget_de_transactions_par_pair_finit_par_couper` |
| Une chaîne parent→enfant dans un même bloc était refusée par le validateur mais empaquetée par le mineur : bloc invalide, travail perdu, production figée | `check_block` valide contre une vue superposant les sorties créées plus tôt dans le bloc. `regression_chainage.rs` : la chaîne passe, la double dépense et l'enfant-avant-parent restent refusés |
| Le jeton du portefeuille passait par la ligne de commande du navigateur, lisible par tout compte de la machine | Sous Linux, le compte qui tient l'autre bout de chaque connexion locale est demandé au noyau ; tout autre compte est refusé. Épreuve `la_connexion_locale_est_attribuee_a_notre_compte` |
| Une seule IP occupait les trente-deux places | Huit places réservées aux sortantes, quatre entrantes par groupe `/16`. Épreuve `l_ecoute_reserve_des_places_aux_sortantes` |
| Des adresses muettes glissées dans le carnet faisaient durer un tour de boucle plus d'une minute, et le nœud se coupait de tous ses pairs — la veille était déduite de la durée du tour | Le détecteur de veille vit sur son propre fil et ne regarde que l'horloge murale ; connexion bornée à quatre secondes |
| La réparation d'une queue tronquée jetait jusqu'à 64 Mio — un bit retourné au milieu du fichier effaçait des dizaines de blocs valides | Bornée à un bloc du consensus ; ce qui est coupé est copié à côté. Épreuves `une_queue_plus_longue_qu_un_bloc_n_est_pas_coupee`, copie vérifiée |
| Un arrêt brutal pendant le minage laissait `next_index` en retard sur la chaîne : des récompenses invisibles, sans réparation | Portefeuille écrit après chaque bloc trouvé ; **rattrapage** au chargement des adresses distribuées au-delà du fichier ; balayage des clés à usage unique relancé après toute découverte. Épreuve `le_rattrapage_retrouve_les_adresses_distribuees_apres_la_derniere_ecriture` |
| Reconstructions compactes en attente sans borne ; corps demandés jamais surveillés | Quatre en vol par pair ; un corps non livré en soixante secondes est redemandé ailleurs et coûte cinquante points |
| Scans de deux mille corps sous le verrou, sans jeton, en mode public | Budget de balayages : trente, puis douze par minute, toutes requêtes confondues |
| Livraison non signée ; action de chaîne d'outils suivie sur une branche mouvante | Signature `minisign` à chaque livraison, **obligatoire** ; `rustup` à la place de l'action ; script d'épinglage des actions par empreinte |
| Genèse abîmée rangée comme chaîne étrangère ; corps corrompu hors queue rendant tout démarrage impossible ; corps non `fsync` ; borne Argon2id à 1 Gio ; fichier de veille dans `/var/tmp` | Genèse canonique recopiée ; coupe au dernier bloc sain ; `sync_all` ; 256 Mio ; `RuntimeDirectory` et lien symbolique refusé |

Ce que la vague ne change pas, et qu'elle a redit : la propriété anti-ASIC
reste une hypothèse tant que la preuve de travail n'a pas reçu de
cryptanalyse externe — le commentaire de `POW_K` qui parlait de latence
« sans avantage décisif » a été ramené à ce que la construction garantit,
la bande passante mémoire. Et sur une machine qui lit sa phrase dans un
fichier, le scellement ne protège pas contre le vol du support : c'est un
compromis à connaître, écrit dans `DURCISSEMENT.md`, pas un défaut à
corriger.
