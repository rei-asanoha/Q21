# Reproduire le binaire Q21, et vérifier ce qu'on installe

Un condensat SHA-256 publié à côté d'un fichier ne prouve presque rien. Il est
produit sur la même machine que le fichier, publié au même endroit, et
remplacé avec lui par quiconque prend la main sur le dépôt ou sur une étape de
la chaîne de construction. Une signature `minisign` (voir SIGNATURE.md) prouve
davantage — elle dit **qui** a construit le fichier — mais elle ne dit pas que
ce fichier corresponde aux sources publiées. Une clé volée signe un binaire
piégé aussi bien qu'un binaire honnête.

La seule vérification qui ne demande de faire confiance à personne est
celle-ci : **recompiler les sources soi-même et retrouver exactement le même
fichier, octet pour octet.** Si dix personnes le font chez elles et annoncent
le même condensat, aucune clé, aucun compte, aucun serveur n'a plus à être cru
sur parole.

C'est la propriété que Bitcoin Core s'est donnée en 2011 avec Gitian, puis en
2021 avec Guix, et le dépôt `bitcoin-core/guix.sigs` où chaque constructeur
dépose le condensat qu'il a obtenu. Q21 fait la même chose, en plus petit.

---

## 1 · Pourquoi une compilation n'est pas reproductible par défaut

`cargo build --release` inscrit dans le binaire le chemin absolu des fichiers
source des dépendances, pour que les messages de panique disent où le problème
a eu lieu. Mesuré sur un binaire Q21 construit sans précaution :

```
/home/vous/q21/vendor/ml-dsa/src/signing.rs
/home/vous/q21/vendor/ml-dsa/src/sampling.rs
/home/vous/q21/vendor/ml-dsa/src/algebra.rs
/home/vous/q21/vendor/hybrid-array/src/iter.rs
... neuf chemins en tout
```

Deux conséquences, la seconde plus grave que la première :

1. le binaire publié raconte où il a été construit — donc le nom de compte de
   la machine qui l'a produit ;
2. **deux personnes qui compilent le même commit dans deux répertoires
   différents obtiennent deux binaires différents.** Leurs condensats
   diffèrent. La vérification par recompilation devient impossible : on ne
   peut plus distinguer « le fichier a été modifié » de « je n'ai pas le même
   chemin que toi ».

Les autres chemins que contient le binaire — `/rustc/<empreinte du
compilateur>/library/...` et `/rust/deps/...` — sont déjà neutralisés par la
distribution Rust elle-même. Ils sont identiques sur toutes les machines
portant la même version du compilateur. C'est pour cela que
`rust-toolchain.toml` épingle `1.95.0` : sans cette épingle, « stable »
désigne une version différente toutes les six semaines, et rien n'est
comparable.

---

## 2 · Ce que Q21 a mis en place

| Pièce | Fichier | Ce qu'elle garantit |
|---|---|---|
| chaîne d'outils figée | `rust-toolchain.toml` | le même compilateur, aujourd'hui et dans six mois |
| dépendances figées | `Cargo.lock` + `--locked` | les mêmes versions, au patch près |
| sources embarquées | `vendor/` | aucun téléchargement, donc aucune source qui change sous vos pieds |
| `vendor/` vérifié | tâche `vendor` de `essais.yml` | `vendor/` est identique, octet pour octet, à ce que crates.io fournit pour ce `Cargo.lock` |
| chemins retirés | `outils/construire-reproductible.sh` | le binaire ne sait plus dans quel répertoire il a été construit |
| preuve automatique | tâche `reproductible` de `essais.yml` | deux compilations, deux répertoires, un seul condensat — vérifié à chaque poussée |
| garde-fou de livraison | étape « Aucun chemin de construction » de `livraison.yml` | une livraison qui aurait perdu le remappage ne part pas |

Le réglage `trim-paths` de Cargo ferait le travail en une ligne dans
`Cargo.toml`. Il n'est **pas** stabilisé dans Cargo 1.95.0, la version
épinglée :

```
feature `trim-paths` is required
The package requires the Cargo feature called `trim-paths`, but that
feature is not stabilized in this version of Cargo (1.95.0)
```

Q21 emploie donc `--remap-path-prefix`, stable depuis 2018, et le pose par
script plutôt que dans `Cargo.toml` — parce que le chemin à remapper dépend de
la machine et ne peut pas être écrit d'avance dans un fichier du dépôt.

---

## 3 · Reproduire le binaire — pas à pas

Vous n'avez besoin de rien d'autre que `git` et la chaîne Rust. Comptez une
minute de compilation sur une machine de bureau, une dizaine sur un
Raspberry Pi.

### Étape 1 · Récupérer les sources à la version exacte

```bash
git clone https://github.com/<compte>/q21.git
cd q21
git checkout v0.1.0        # ou l'empreinte de commit publiée
```

**Ce que vous devez voir**

```
Note: switching to 'v0.1.0'.
You are in 'detached HEAD' state. ...
HEAD is now at ac6e6ee aucun domaine dans le binaire, ...
```

`detached HEAD` n'est pas une erreur. Cela signifie « tu regardes une version
figée et non une branche qui avance », ce qui est exactement ce qu'on veut.

**Si cela échoue** — `pathspec 'v0.1.0' did not match` : l'étiquette n'existe
pas encore. Prenez l'empreinte de commit publiée avec la livraison :
`git checkout ac6e6ee`.

### Étape 2 · Installer la chaîne d'outils annoncée

```bash
rustup show
```

**Ce que vous devez voir** — `rustup` lit `rust-toolchain.toml` et installe
tout seul la bonne version si elle manque :

```
active toolchain
----------------
name: 1.95.0-x86_64-unknown-linux-gnu
active because: overridden by '/home/vous/q21/rust-toolchain.toml'
```

**Le point à vérifier** : `1.95.0`, et la mention `rust-toolchain.toml`. Si
vous voyez `stable-x86_64-...` sans cette mention, votre `rustup` est trop
ancien pour lire le fichier ; mettez-le à jour (`rustup self update`) et
recommencez.

### Étape 3 · Compiler

```bash
./outils/construire-reproductible.sh
```

Sous Windows, dans PowerShell, à la racine du dépôt :

```powershell
powershell -ExecutionPolicy Bypass -File outils\construire-reproductible.ps1
```

**Ce que vous devez voir** — d'abord les trois lignes d'en-tête, qui disent ce
que le script va faire :

```
Racine du projet : /home/vous/q21
Remappage        : /home/vous/q21 -> /q21
Chaine d'outils  : rustc 1.95.0 (59807616e 2026-04-14)

   Compiling zeroize v1.9.0
   Compiling hybrid-array v0.4.14
   ...
   Compiling ml-dsa v0.1.1
   Compiling q21-core v0.1.0 (/home/vous/q21)
    Finished `release` profile [optimized] target(s) in 37.49s

Binaire : target/release/q21
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  target/release/q21
```

La dernière ligne est le résultat. C'est ce condensat qu'il faut comparer.

Les 64 caractères montrés ici sont ceux d'une version précise ; **ils changent
à chaque commit**, puisque le binaire change. Ne les comparez jamais à ce
document : comparez-les au `SHA256SUMS` publié avec la livraison que vous
cherchez à vérifier, et aux attestations du dossier `attestations/`.

**Si cela échoue**

| Message | Ce que cela veut dire | Que faire |
|---|---|---|
| `erreur : RUSTFLAGS est deja defini` | une variable d'environnement remplacerait les drapeaux de reproductibilité — cargo prend l'un **ou** l'autre, il ne les cumule pas | `unset RUSTFLAGS`, puis relancer |
| `error: the lock file needs to be updated` | `Cargo.lock` ne correspond pas aux sources | vous n'êtes pas sur le commit publié ; refaites l'étape 1 |
| `error: failed to get 'ml-dsa'` … `offline` | `vendor/` manque ou est incomplet | `git status` ; le dossier `vendor/` fait partie du dépôt et doit être là |
| `error[E0658]` | le compilateur n'est pas le bon | refaites l'étape 2 |

### Étape 4 · Comparer au condensat publié

Le condensat de référence est publié à deux endroits qui ne dépendent pas l'un
de l'autre : dans le fichier `SHA256SUMS` de la livraison, signé par
`SHA256SUMS.minisig`, et dans le dépôt d'attestations
(`attestations/`, section 5 ci-dessous).

```bash
sha256sum target/release/q21
```

**Ce que vous devez voir** : la même suite de 64 caractères que celle
publiée. Caractère pour caractère — un condensat qui diffère d'un seul signe
désigne un fichier entièrement différent.

**Si les condensats diffèrent**, dans cet ordre :

1. vérifiez que vous êtes sur le même commit : `git rev-parse HEAD` ;
2. vérifiez la version du compilateur : `rustc --version` ;
3. vérifiez que le remappage a bien pris — il ne doit rester **aucune**
   occurrence de votre chemin dans le binaire :

```bash
strings -a target/release/q21 | grep "$(pwd -P)" | head
```

**Ce que vous devez voir** : rien du tout. La commande ne rend aucune ligne.

Et ce qui les remplace :

```bash
strings -a target/release/q21 | grep '^/q21' | sort -u
```

**Ce que vous devez voir** : huit ou neuf lignes commençant par `/q21/vendor/`,
identiques sur toute machine.

4. si tout cela concorde et que les condensats diffèrent encore, **dites-le
   publiquement** : ouvrez une question sur le dépôt en donnant votre système,
   votre architecture, `rustc --version` et le condensat obtenu. Un désaccord
   reproductible est une information précieuse — soit le binaire publié ne
   vient pas de ces sources, soit la compilation dépend encore d'une variable
   qu'on n'a pas vue. Les deux méritent d'être sus.

---

## 4 · Vérifier la reproductibilité vous-même, sans rien publier

Le dépôt porte le banc d'essai :

```bash
./outils/verifier-reproductible.sh
```

Il copie les sources dans deux répertoires temporaires de longueur et de
profondeur différentes, compile dans chacun sans cache partagé, et compare.

**Ce que vous devez voir**, à la fin :

```
=== Resultat ===
A : 85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5
B : 85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5

IDENTIQUES — la compilation est reproductible.
```

**Ce que ce banc ne prouve pas.** Il compare deux compilations sur la **même**
machine, avec le même système et le même compilateur. Il élimine la variable
« répertoire », qui était la seule variable restante mesurée sur Q21. Il ne
dit rien de la variable « machine » : une distribution différente, une
bibliothèque C différente, une architecture différente peuvent encore produire
un binaire différent — et c'est normal, un binaire Linux x86-64 n'a aucune
raison d'égaler un binaire macOS ARM. La comparaison est **par plateforme**,
et elle demande plusieurs personnes. D'où la section suivante.

---

## 5 · Attester : plusieurs personnes, un condensat

Un seul constructeur, même honnête, même prudent, reste un point unique de
confiance. Si sa machine est compromise, son binaire est piégé et son
condensat l'est aussi. La réponse de Bitcoin Core est de faire construire par
plusieurs personnes indépendantes et de publier ce que **chacune** obtient :
le dépôt `bitcoin-core/guix.sigs` contient un dossier par version, un
sous-dossier par constructeur, et le condensat signé que ce constructeur a
obtenu. Quand douze constructeurs sur douze annoncent la même suite de 64
caractères, il faudrait compromettre douze machines à la fois pour tromper
quelqu'un.

Q21 porte la même structure, vide, prête à recevoir des attestations :
`attestations/`. Sa marche à suivre est dans `attestations/LISEZ-MOI.md` :
comment déposer sa clé publique, comment produire une attestation, comment
vérifier celles des autres.

La règle honnête à retenir, et elle vaut d'être dite clairement : **tant que
le seul constructeur est le mainteneur, la reproductibilité est un outil
disponible, pas une garantie obtenue.** Elle devient une garantie le jour où
une deuxième personne, qui ne dépend pas de la première, dépose une
attestation concordante. Le travail fait ici rend ce jour possible ; il ne le
remplace pas.

---

## 6 · Ce qui reste hors de portée

Trois limites, dites d'avance plutôt que découvertes plus tard.

**La chaîne d'outils elle-même n'est pas reproduite.** Q21 fait confiance aux
binaires `rustc` distribués par le projet Rust. Les reconstruire depuis leurs
sources — ce que Guix fait pour Bitcoin Core — demanderait une infrastructure
que ce projet n'a pas. Le compromis est explicite : le compilateur est épinglé
et vérifiable par son empreinte, mais il est cru.

**La compilation croisée n'est pas employée.** Chaque plateforme est construite
sur sa propre machine (`livraison.yml`), ce qui évite de supposer, mais
signifie qu'on ne peut pas vérifier un binaire Windows depuis un Linux. Pour
vérifier le binaire de votre système, il faut ce système.

**Le déterminisme n'est mesuré que sur ce projet.** Une mise à jour de
dépendance peut introduire un `build.rs` qui inscrit une date, un chemin, un
nom de machine. La tâche `reproductible` de `essais.yml` est là pour que ce
jour-là la fusion s'arrête au lieu de passer.

---

## 7 · Résumé en quatre commandes

```bash
git clone https://github.com/<compte>/q21.git && cd q21
git checkout <étiquette ou empreinte publiée>
./outils/construire-reproductible.sh
sha256sum target/release/q21        # à comparer au condensat publié
```

Si la suite de 64 caractères concorde, vous avez la preuve — et non
l'assurance — que le binaire publié sort de ces sources.
