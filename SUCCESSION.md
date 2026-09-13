# Succession — ce qui arrive à Q21 sans son mainteneur

Ce document existe pour une raison simple : un protocole qui dépend d'une
personne n'est pas un protocole, c'est un service. Il est écrit **avant** que
la question se pose, parce qu'une règle de succession improvisée le jour où
elle est nécessaire ne vaut rien — n'importe qui peut alors se déclarer
successeur, et personne n'a de critère pour trancher.

Il répond à quatre questions, dans cet ordre :

1. qu'est-ce qui survit au mainteneur, et qu'est-ce qui meurt avec lui ;
2. comment on reconnaît un nouveau mainteneur ;
3. comment on repart, techniquement, sans lui ;
4. pourquoi il n'y a pas de clé maîtresse, et pourquoi il n'y en aura pas.

---

## 1 · Ce qui survit, ce qui meurt

Il faut séparer deux choses qu'on confond souvent : le **protocole** et la
**chaîne**.

### Le protocole survit entièrement

| Pièce | Pourquoi elle ne dépend de personne |
|---|---|
| le code | publié, licence MIT OU Apache-2.0, clonable, modifiable, redistribuable |
| les dépendances | embarquées dans `vendor/`, vérifiées identiques à crates.io par la tâche `vendor` — aucun téléchargement à faire, aucun serveur à joindre |
| le compilateur | épinglé par `rust-toolchain.toml` à `1.95.0` |
| la genèse | `genesis_block(reseau)` est **entièrement déterministe** : aucune donnée extérieure, aucune date de compilation, aucun aléa. Deux machines la calculent identique, pour toujours |
| le point d'entrée | **aucun** domaine n'est compilé dans le binaire (`amorces_integrees` rend trois listes vides, et la tâche de test `aucun_domaine_n_est_compile_dans_le_binaire` l'exige). Le binaire ne joint aucune infrastructure du mainteneur, jamais |
| la télémétrie | il n'y en a pas. Aucun appel sortant vers quoi que ce soit qui appartienne au mainteneur : ni statistiques, ni vérification de mise à jour, ni « ping » |
| la vérifiabilité du binaire | reproductible : n'importe qui recompile et retrouve le condensat (REPRODUIRE.md) |

Conséquence pratique : le jour où le mainteneur disparaît — volontairement,
accidentellement, définitivement — **rien ne casse dans le code**. Un nœud
déjà lancé continue. Un binaire déjà construit continue. Une personne qui a
une copie du dépôt peut compiler, lancer un nœud, et reprendre le protocole
sans rien demander à personne.

### La chaîne meurt si personne ne garde de copie

C'est la limite honnête, et elle n'a pas de contournement élégant.

Une blockchain est une donnée, pas seulement un programme. Si le serveur du
mainteneur s'arrête, que le Raspberry est débranché, que le PC et le Mac
cessent de miner, et qu'**aucune autre machine** ne détient de copie des
blocs, alors l'historique est perdu. Le protocole survit ; la chaîne, non.
Quelqu'un pourra relancer Q21 — mais depuis la genèse, avec un historique
vide, et les soldes de l'ancienne chaîne n'existeront plus.

Il n'y a qu'une manière de fermer ce trou, et elle ne s'écrit pas dans du
code : **plusieurs nœuds complets, sur plusieurs machines, chez plusieurs
personnes.** Un nœud complet suffit à sauver la chaîne ; deux la rendent
robustes ; dix la rendent difficile à tuer.

Ce que Q21 offre pour que cela reste simple :

- un nœud complet garde tout l'historique par défaut (l'élagage est un choix,
  pas le réglage de base) ;
- `q21 revalider` permet à n'importe qui de **revérifier toute la chaîne
  depuis la genèse** à partir du fichier de blocs d'un autre nœud, sans avoir
  à croire ce nœud (section 3.4) ;
- aucun nœud n'a de statut particulier. Il n'y a pas de « nœud du
  mainteneur » privilégié dans le protocole.

**La phrase à retenir** : le code est sauvé par sa publication, la chaîne est
sauvée par sa réplication. La première est faite. La seconde demande d'autres
personnes.

---

## 2 · Comment on reconnaît un nouveau mainteneur

### La règle, déclarée ici et d'avance

Q21 n'a **pas** de mécanisme de succession dans le protocole. Aucun nœud ne
demande à aucune autorité qui est le mainteneur ; aucune clé ne confère de
pouvoir sur le réseau. La succession est donc un fait social, pas un fait
technique — et la seule chose qu'on puisse faire d'utile est de dire d'avance
à quoi on reconnaîtra qu'elle a eu lieu.

Trois critères, qui doivent être réunis :

**1. La continuité par la chaîne d'étiquettes signées.** Chaque version
publiée est une étiquette git signée. Le successeur est la personne dont la
clé signe l'étiquette suivante, **et** dont la clé a été annoncée dans une
étiquette signée par la clé précédente, avant la transition. C'est un
chaînage : chaque clé est introduite par la précédente, de sorte qu'une clé
qui apparaît sans avoir été présentée n'est pas une succession, c'est une
revendication.

Le format de cette annonce, dans le message de l'étiquette :

```
Q21 v0.3.0

Cette version introduit une clé de mainteneur supplémentaire :
  minisign RWQf6lcT0yJ0...  <pseudonyme>
Elle est habilitée à signer les étiquettes à partir de v0.4.0.
```

**2. La reproductibilité, qui rend le chaînage vérifiable sans la clé.** Même
si toutes les clés étaient perdues ou compromises, une version reste
vérifiable : ses sources sont publiques, sa compilation est reproductible, et
n'importe qui peut constater que le binaire publié sort de ces sources
(REPRODUIRE.md). La clé prouve **qui** ; la reproductibilité prouve **quoi**.
La seconde est la plus importante, et c'est volontaire.

**3. L'adoption, qui tranche en dernier ressort.** Aucun document ne peut
imposer un mainteneur. Ce qui fait qu'une version est *la* version est que les
nœuds la fassent tourner. Si deux personnes se déclarent successeurs, le
réseau ne choisit pas par arbitrage : il se scinde, et les deux chaînes
existent tant que des nœuds les suivent. C'est désagréable à écrire, et c'est
la vérité de tout protocole décentralisé, Bitcoin compris.

### Si la chaîne d'étiquettes est rompue

Cas réel et prévisible : le mainteneur disparaît sans avoir présenté de
successeur. Alors il n'y a pas de successeur légitime, et il ne faut pas en
fabriquer un.

Ce qui se fait à la place — un **embranchement déclaré**, honnêtement nommé :

1. quelqu'un clone le dépôt et le publie sous son propre nom, en disant
   clairement que c'est une continuation et non la même main ;
2. il produit sa propre clé, la dépose dans
   `attestations/clefs-constructeurs/`, et signe ses étiquettes avec elle ;
3. il ne prétend pas à la continuité de la clé précédente, et ne réécrit pas
   l'histoire du dépôt pour en donner l'apparence ;
4. les opérateurs de nœuds décident, un par un, de suivre ou non. Le protocole
   n'a pas besoin qu'ils soient d'accord : la chaîne ne change pas de règles,
   seul le dépôt d'où viennent les binaires change de main.

Le point à ne pas rater : **il n'y a rien à récupérer.** Pas de compte à
reprendre, pas de domaine à transférer, pas de clé à retrouver pour que le
réseau fonctionne. C'est précisément parce que le binaire ne contient aucun
domaine et ne joint aucune infrastructure qu'une succession peut se passer de
tout héritage.

### Signer les commits et les étiquettes — comment faire

Cette partie est optionnelle pour le code (le code se vérifie par
reproductibilité), mais elle est ce qui rend la chaîne d'étiquettes de la
section précédente possible. Elle se fait avec une clé **pseudonyme**, sans
nom réel ni adresse réelle.

La voie la plus simple est une clé SSH, que git sait employer depuis la
version 2.34 et qui évite toute l'infrastructure GPG.

```bash
# 1 · créer la clé, avec un commentaire qui ne dit rien de personnel
ssh-keygen -t ed25519 -C "Q21" -f ~/.ssh/q21-signature
```

**Ce que vous devez voir**

```
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/vous/.ssh/q21-signature
Your public key has been saved in /home/vous/.ssh/q21-signature.pub
```

```bash
# 2 · dire a git de signer avec elle, pour ce depot seulement
git config gpg.format ssh
git config user.signingkey ~/.ssh/q21-signature.pub
git config commit.gpgsign true
git config tag.gpgsign true

# 3 · declarer la clef comme habilitee, dans un fichier du depot
printf 'Q21 %s\n' "$(cat ~/.ssh/q21-signature.pub)" > .git/clefs-autorisees
git config gpg.ssh.allowedSignersFile .git/clefs-autorisees
```

```bash
# 4 · verifier qu'un commit est bien signe
git log --show-signature -1
```

**Ce que vous devez voir** : une ligne `Good "git" signature for Q21`.

**Si vous voyez** `No principal matched` : le fichier des clés autorisées
n'est pas trouvé ou ne contient pas cette clé. Refaites l'étape 3.

Deux avertissements qui comptent pour ce projet :

- la clé de signature ne doit porter **aucun** nom réel, aucune adresse
  réelle, aucun nom de machine. Le commentaire `-C "Q21"` remplace le
  `utilisateur@machine` que `ssh-keygen` met par défaut, et qui serait une
  fuite d'identité permanente et publique ;
- si vous poussez la clé publique dans les paramètres GitHub pour obtenir le
  badge *Verified*, elle est liée à ce compte. C'est un choix, pas une
  obligation : une signature se vérifie parfaitement sans GitHub, avec le
  fichier `.git/clefs-autorisees` ci-dessus. Le badge n'ajoute qu'un avis de
  GitHub sur une preuve qui existe déjà.

---

## 3 · Repartir sans le mainteneur — pas à pas

Cette section s'adresse à la personne qui, un jour, reprend Q21. Elle suppose
qu'elle a une copie du dépôt et rien d'autre.

### 3.1 · Compiler

```bash
git clone <votre copie du depot> q21 && cd q21
rustup show                       # doit annoncer 1.95.0 via rust-toolchain.toml
./outils/construire-reproductible.sh
```

**Ce que vous devez voir**, à la fin :

```
Binaire : target/release/q21
85092844...  target/release/q21
```

Rien à télécharger : `vendor/` porte toutes les sources des dépendances.

### 3.2 · Vérifier que la genèse est bien celle attendue

```bash
./target/release/q21 --datadir /tmp/q21-verif mainnet
./target/release/q21 --datadir /tmp/q21-verif info
```

**Ce que vous devez voir** : une hauteur `0` et l'empreinte du bloc de genèse.
Cette empreinte est **déterminée par le code seul**. Elle sera identique sur
votre machine et sur toute autre compilant le même commit — c'est ce qui rend
inutile de faire confiance à quiconque pour savoir où la chaîne commence.

```bash
./target/release/q21 --datadir /tmp/q21-verif block --hauteur 0
```

Le bloc de genèse porte un message inscrit le jour du lancement. C'est un
horodatage invérifiable à l'avance : personne, pas même l'auteur, ne pouvait
avoir miné des blocs avant que ce texte existe.

### 3.3 · Retrouver un point d'entrée dans le réseau

Le binaire ne contient **aucune** adresse de nœud. C'est délibéré : un domaine
compilé dedans serait une dépendance permanente à une infrastructure, donc à
son propriétaire. Deux façons d'en fournir un à l'exécution :

```bash
# à la ligne de commande
./target/release/q21 node --amorce <adresse:port>

# ou par un fichier, lu au demarrage
echo "<adresse:port>" >> <datadir>/amorces.txt
```

Voir RESEAU.md. Si plus aucun nœud ne répond, il n'y a pas de réseau à
joindre : vous êtes dans le cas de la section 1, « la chaîne meurt ».

### 3.4 · Revérifier toute la chaîne depuis zéro, sans croire personne

C'est la commande qui rend la reprise sûre. Elle rejoue l'intégralité de
l'historique à partir du fichier de blocs d'un autre nœud, en appliquant
**toutes** les règles de consensus, et refuse ce qui ne les respecte pas.

```bash
./target/release/q21 --datadir <votre datadir> revalider \
  --corps <chemin vers le blocks.dat d'un noeud complet>
```

**Ce que vous devez voir** : une progression par hauteur, puis un verdict. Le
point important est que le nœud qui vous a donné ce fichier **n'a pas besoin
d'être honnête** : s'il a modifié un bloc, la revalidation le rejette. Vous ne
faites confiance qu'au code que vous avez compilé vous-même.

**Si la revalidation échoue à une hauteur donnée**, le fichier fourni est
corrompu ou falsifié à partir de là. Demandez-en un autre à un autre nœud et
comparez les hauteurs de rejet : deux sources qui rejettent au même endroit
désignent un problème réel de la chaîne ; une seule qui rejette désigne cette
source.

### 3.5 · Reprendre les livraisons

1. créez votre clé `minisign` (SIGNATURE.md, section 1) ;
2. publiez la clé publique dans le README, et son empreinte par un second
   canal que vous contrôlez ;
3. créez l'environnement GitHub `livraison` avec les deux secrets
   (SIGNATURE.md, section 2) ;
4. déposez votre clé de constructeur dans
   `attestations/clefs-constructeurs/` et attestez votre première version
   (`attestations/LISEZ-MOI.md`, section 3) ;
5. **ne réutilisez pas la clé du mainteneur précédent**, même si vous en avez
   hérité. Une clé qui change de main sans que cela se voie est pire qu'une
   clé nouvelle : elle fait passer une transition pour une continuité.

---

## 4 · Il n'y a pas de clé maîtresse, et il n'y en aura pas

Bitcoin a eu une **clé d'alerte**. Satoshi l'avait introduite pour pouvoir
diffuser à tous les nœuds un message d'urgence, affiché dans l'interface.
L'intention était bonne : prévenir en cas de défaut grave.

Ce qu'elle est devenue, en pratique :

- un **point de compromission unique** : qui détient la clé peut faire
  afficher n'importe quel message à tout le réseau, y compris « cette version
  est dangereuse, installez celle-ci » ;
- un **pouvoir que personne n'aurait dû détenir**, exercé sans mandat ni
  contrôle ;
- une clé dont on a fini par ne plus savoir avec certitude qui en avait eu
  copie au fil des années.

Le système d'alerte a été retiré de Bitcoin Core en 2016, et la clé publiée
pour la neutraliser définitivement. C'est un des rares cas où un projet a
reconnu publiquement qu'une de ses fonctions de sécurité était en réalité une
vulnérabilité d'architecture.

**Q21 n'en a pas, et cette absence est une décision, pas un oubli.** Elle
implique, et il faut l'assumer :

- aucun message ne peut être poussé à tous les nœuds. Une alerte de sécurité
  se diffuse comme pour n'importe quel logiciel : par une publication qu'on va
  lire, pas par un canal dans le protocole ;
- aucune mise à jour ne peut être imposée. Chaque opérateur décide, ce qui
  rend les corrections plus lentes à se répandre ;
- aucune transaction ne peut être annulée, aucun fonds gelé, aucune adresse
  mise sur liste. Il n'existe aucune clé capable de cela, donc aucune clé à
  voler, à réclamer, ou à contraindre de produire.

Ce que Q21 met à la place, et qui ne confère de pouvoir à personne :

| Au lieu de | Q21 emploie |
|---|---|
| une clé d'alerte | des publications signées, qu'on choisit de lire |
| une clé de mise à jour | une compilation reproductible, que chacun vérifie |
| une autorité qui dit quel binaire est bon | plusieurs constructeurs qui annoncent le même condensat |
| une clé de récupération sur les fonds | rien. Un portefeuille perdu est perdu, et le code de sauvegarde papier est le seul recours |

La limite déclarée ailleurs et rappelée ici, parce qu'elle relève du même
sujet : `MAX_REORG_DEPTH = 720` (vingt-quatre heures) empêche une réécriture
plus profonde que ce seuil. Ce n'est **pas** une protection contre une
attaque à 51 % — le code le dit dans ses propres commentaires — cela change
la nature de l'attaque : au lieu de réécrire l'histoire, l'attaquant scinde le
réseau. Aucune clé ne peut arbitrer cette scission. C'est cohérent avec tout
ce qui précède : là où il n'y a pas d'autorité, il n'y a pas de secours.

---

## 5 · Résumé

| Question | Réponse courte |
|---|---|
| Le mainteneur peut-il tuer Q21 en s'arrêtant ? | Le code, non : il est publié, autonome, reproductible. La chaîne, oui — s'il est le seul à en détenir une copie. |
| Que faut-il pour que la chaîne survive ? | Un seul autre nœud complet, chez quelqu'un d'autre. C'est tout, et rien ne peut le remplacer. |
| Comment reconnaît-on un successeur ? | Une clé présentée d'avance par une étiquette signée, une compilation reproductible, et l'adoption par les nœuds. Dans cet ordre d'importance inverse : c'est l'adoption qui tranche. |
| Et si la chaîne d'étiquettes est rompue ? | Embranchement déclaré, nouvelle clé, aucune prétention à la continuité. Il n'y a rien à hériter pour que le protocole fonctionne. |
| Y a-t-il une clé capable d'imposer quelque chose ? | Non. Jamais. Bitcoin en a eu une et l'a retirée en 2016. |
