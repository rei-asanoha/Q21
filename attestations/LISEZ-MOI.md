# Attestations de construction

Ce dossier recueille, pour chaque version publiée de Q21, le condensat
SHA-256 que **chaque** personne ayant recompilé les sources a obtenu, et sa
signature.

Il est vide au départ. C'est normal, et c'est même le point : il n'appartient
pas au mainteneur de le remplir seul.

---

## 1 · À quoi ça sert, en une page

Trois vérifications sont possibles sur un binaire publié, de la plus faible à
la plus forte.

| Vérification | Ce qu'elle prouve | Ce qu'elle ne prouve pas |
|---|---|---|
| le condensat SHA-256 joint | le fichier est arrivé intact | rien sur son origine — il est produit et publié par la même personne que le fichier |
| la signature `minisign` du `SHA256SUMS` | **qui** a construit le fichier | que le fichier corresponde aux sources publiées : une clé volée signe un binaire piégé aussi bien qu'un binaire honnête |
| **plusieurs attestations concordantes** | le fichier sort bien de ces sources, et il faudrait compromettre toutes ces machines à la fois pour en publier un autre | rien sur la qualité du code lui-même |

La troisième est la seule qui ne demande de faire confiance à personne en
particulier. Elle exige deux choses :

1. que la compilation soit **reproductible** — deux personnes qui compilent le
   même commit obtiennent le même fichier. C'est fait : voir REPRODUIRE.md,
   et la tâche `reproductible` de `essais.yml` qui le vérifie à chaque
   poussée ;
2. que **plusieurs personnes indépendantes** le fassent et publient leur
   résultat. C'est l'objet de ce dossier.

C'est la mécanique de `bitcoin-core/guix.sigs`, transposée en plus petit.

**Ce qui est vrai aujourd'hui, dit sans détour :** tant que le seul
constructeur est le mainteneur, la reproductibilité est un outil disponible,
pas une garantie obtenue. Une attestation déposée par une personne qui ne
dépend pas du mainteneur — pas sa machine, pas son compte, pas sa clé — est ce
qui transforme l'un en l'autre.

---

## 2 · Disposition du dossier

```
attestations/
├── LISEZ-MOI.md                  ← ce fichier
├── clefs-constructeurs/
│   ├── LISEZ-MOI.md              ← comment déposer sa clé
│   └── <pseudonyme>.pub          ← une clé publique minisign par constructeur
└── <version>/
    └── <pseudonyme>/
        ├── SHA256SUMS            ← les condensats obtenus par ce constructeur
        └── SHA256SUMS.minisig    ← sa signature de ce fichier
```

Exemple de ce à quoi cela ressemble une fois deux personnes passées :

```
attestations/
├── clefs-constructeurs/
│   ├── rei-asanoha.pub
│   └── quelquun-dautre.pub
└── v0.1.0/
    ├── rei-asanoha/
    │   ├── SHA256SUMS
    │   └── SHA256SUMS.minisig
    └── quelquun-dautre/
        ├── SHA256SUMS
        └── SHA256SUMS.minisig
```

Les deux `SHA256SUMS` doivent être **identiques ligne pour ligne**. C'est tout
l'intérêt.

### Le format de `SHA256SUMS`

Exactement ce que rend `sha256sum` : le condensat, deux espaces, le nom du
fichier. Une ligne par binaire, le nom sans chemin, triées par nom.

```
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  q21-linux-x86_64
d3f1...                                                            q21-linux-arm64
```

N'attestez que des plateformes que vous avez **réellement** compilées. Un
binaire Linux x86-64 n'a aucune raison d'égaler un binaire macOS ARM : la
comparaison se fait par plateforme, jamais entre plateformes.

---

## 3 · Déposer une attestation — pas à pas

### Étape 1 · Recompiler, et obtenir un condensat

Suivez REPRODUIRE.md, sections 3.1 à 3.3. À la fin, vous avez :

```
Binaire : target/release/q21
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  target/release/q21
```

### Étape 2 · Créer votre clé, une seule fois

```bash
minisign -G -p <pseudonyme>.pub -s <pseudonyme>.key
```

**Ce que vous devez voir**

```
Please enter a password to protect the secret key.
Password:
Password (one more time):
Deriving a key from the password in order to encrypt the secret key... done
The secret key was saved as <pseudonyme>.key - Keep it secret!
The public key was saved as <pseudonyme>.pub - That one can be public!
```

Le fichier `.key` ne quitte jamais votre machine. Le fichier `.pub` est fait
pour être publié.

### Étape 3 · Écrire le fichier des condensats

Dans un dossier de travail, un fichier nommé `SHA256SUMS` :

```
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  q21-linux-x86_64
```

### Étape 4 · Signer ce fichier

```bash
minisign -S -s <pseudonyme>.key -m SHA256SUMS \
  -t "Q21 v0.1.0 <empreinte du commit> reproduit par <pseudonyme>"
```

**Ce que vous devez voir** : la demande du mot de passe, puis rien — le
silence est le succès. Un fichier `SHA256SUMS.minisig` apparaît à côté.

Le texte du `-t` est un commentaire de confiance, inscrit dans la signature
et signé avec elle. Mettez-y la version et l'empreinte du commit : cela évite
qu'une signature soit rejouée pour une autre version.

### Étape 5 · Vérifier votre propre signature avant de la publier

```bash
minisign -Vm SHA256SUMS -p <pseudonyme>.pub
```

**Ce que vous devez voir**

```
Signature and comment signature verified
Trusted comment: Q21 v0.1.0 ac6e6ee reproduit par <pseudonyme>
```

**Si vous voyez** `Signature verification failed` : le fichier `SHA256SUMS` a
changé depuis la signature. Refaites l'étape 4.

### Étape 6 · Proposer les fichiers au dépôt

Trois fichiers, aux trois emplacements décrits en section 2 :

```
attestations/clefs-constructeurs/<pseudonyme>.pub
attestations/v0.1.0/<pseudonyme>/SHA256SUMS
attestations/v0.1.0/<pseudonyme>/SHA256SUMS.minisig
```

Puis une demande de fusion (*pull request*) intitulée par exemple
« attestation v0.1.0 — <pseudonyme> ».

**Ne modifiez jamais** un dossier portant le pseudonyme de quelqu'un d'autre.
Une demande de fusion qui touche à l'attestation d'un tiers doit être refusée
par principe, même si elle paraît anodine.

---

## 4 · Vérifier les attestations des autres

Vous n'avez besoin d'aucun droit sur le dépôt pour cela, et c'est le geste le
plus utile qu'un tiers puisse faire.

```bash
cd attestations/v0.1.0
for D in */; do
  P="../clefs-constructeurs/${D%/}.pub"
  printf '%-24s ' "${D%/}"
  minisign -Vm "$D/SHA256SUMS" -p "$P" >/dev/null 2>&1 \
    && echo "signature valide" || echo "SIGNATURE INVALIDE"
done
```

Puis, la vérification qui compte — tous les fichiers `SHA256SUMS` doivent être
identiques :

```bash
sha256sum */SHA256SUMS
```

**Ce que vous devez voir** : la même empreinte à gauche pour toutes les lignes.

```
9b1c...e7  quelquun-dautre/SHA256SUMS
9b1c...e7  rei-asanoha/SHA256SUMS
```

**Si une empreinte diffère**, l'un des constructeurs a obtenu un binaire
différent des autres. Ce n'est pas nécessairement une malveillance — ce peut
être une plateforme mal étiquetée, un commit différent, un compilateur
différent. Mais cela doit être **dit publiquement** et élucidé avant qu'une
version soit recommandée. Ouvrez une question sur le dépôt avec les deux
fichiers côte à côte.

---

## 5 · La règle sur les clés, déclarée d'avance

Une clé déposée dans `clefs-constructeurs/` **n'autorise rien**. Elle ne
permet ni de publier, ni de fusionner, ni de décider. Elle sert uniquement à
lier une attestation à une identité stable, pour qu'on puisse constater qu'une
même personne atteste plusieurs versions de suite.

Il n'existe donc pas de « clé de confiance » dans Q21, et il n'en existera
pas. Voir SUCCESSION.md, section sur l'absence de clé maîtresse : une clé
capable d'imposer quelque chose au réseau est un défaut d'architecture, pas une
sécurité. Bitcoin en a eu une — la clé d'alerte — et l'a retirée en 2016 après
avoir constaté qu'elle était un point de compromission unique et un pouvoir
que personne n'aurait dû détenir.

Ce qui vaut pour la confiance ici est arithmétique, pas hiérarchique : le
nombre de personnes indépendantes qui annoncent le même condensat.
