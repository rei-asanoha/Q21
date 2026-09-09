# Signer les livraisons, et vérifier ce qu'on installe

Un condensat SHA-256 prouve qu'un fichier est arrivé intact. Il ne prouve pas
**qui** l'a construit : produit sur la même machine que l'archive, publié au
même endroit, il est remplacé avec elle par quiconque prend la main sur le
dépôt ou sur une action de la chaîne de construction. Avant d'installer un
binaire qui garde des clés, il faut une preuve que personne d'autre ne peut
fabriquer : une **signature** faite avec une clé qui ne quitte jamais
l'opérateur.

Q21 emploie [minisign](https://jedisct1.github.io/minisign/) : un seul
fichier, aucune infrastructure, une clé publique de 56 caractères qui tient
dans un README. La livraison **échoue** si la clé n'est pas configurée : une
livraison non signée n'est pas une livraison.

---

## 1 · Créer la clé, une fois, hors ligne

Sur une machine de confiance — le Raspberry convient, ou un Mac :

```bash
sudo apt install -y minisign        # Debian, Raspberry Pi OS
# brew install minisign             # macOS
minisign -G -p q21-livraison.pub -s q21-livraison.key
```

`minisign` demande un mot de passe pour la clé secrète : choisissez-le long,
notez-le sur papier. Deux fichiers sortent :

| Fichier | Ce que c'est | Où il va |
|---|---|---|
| `q21-livraison.pub` | la clé **publique** | dans le README (section ci-dessous), et par un second canal — un message, une page que vous contrôlez |
| `q21-livraison.key` | la clé **secrète**, chiffrée par le mot de passe | dans les secrets du dépôt, puis nulle part d'autre qu'une copie hors ligne |

## 2 · Confier la clé à la livraison — dans un environnement protégé

Un secret **de dépôt** est lu par toute exécution lancée depuis le dépôt, sur
n'importe quelle branche : quiconque peut pousser une branche et cliquer
« Run workflow » — un collaborateur, un jeton fuité, un compte repris — fait
signer ce qu'il veut, ou remplace l'étape de signature par un envoi de la clé
ailleurs. C'est pourquoi la clé ne vit pas dans les secrets du dépôt, mais
dans un **environnement** GitHub que le travail `signer` est seul à employer,
et qui n'accepte que `main` et les étiquettes `v*`.

Dans le dépôt GitHub : *Settings → Environments → New environment*, nom
**`livraison`**, puis :

| Réglage | Valeur |
|---|---|
| *Required reviewers* | vous-même — chaque livraison attend votre clic |
| *Deployment branches and tags* | *Selected branches and tags* : `main`, et le motif `v*` |
| *Environment secrets* → *Add secret* | `MINISIGN_KEY` : le contenu intégral de `q21-livraison.key` (deux lignes) |
| *Environment secrets* → *Add secret* | `MINISIGN_PASSWORD` : le mot de passe choisi à la création |

Si les deux secrets existaient déjà **au niveau du dépôt**, supprimez-les de
là une fois recopiés dans l'environnement : tant qu'ils y restent, la
protection n'est qu'apparente.

Puis effacez `q21-livraison.key` de la machine, ou rangez-le sur un support
hors ligne. La clé publique, elle, est faite pour être vue : collez sa
seconde ligne dans le README.

Le compte GitHub qui détient cet environnement doit avoir **deux facteurs**
activés : c'est lui, en dernier ressort, qui commande la signature. Une
adresse de récupération de compte est une clé de signature de plus.

## 3 · Ce que la livraison produit

À chaque livraison, le travail **Signature** rassemble les condensats de
toutes les archives dans `SHA256SUMS` et le signe : `SHA256SUMS.minisig`. Les
deux sont déposés ensemble, dans l'artefact `SHA256SUMS-signe`.

## 4 · Vérifier avant d'installer

Sur la machine qui va installer — serveur, Raspberry, PC, Mac —, avec la clé
publique du README (`RW…`, 56 caractères) :

```bash
minisign -Vm SHA256SUMS -P <clé publique>
sha256sum -c SHA256SUMS --ignore-missing
```

La première commande doit dire `Signature and comment signature verified`,
et son commentaire de confiance porte l'étiquette, le commit de la
construction et le nom qui signe le projet :

```
Trusted comment: Q21 main <empreinte du commit> -- Rei Asanoha
```

Ce commentaire est **couvert par la signature** : il ne peut être ni réécrit
ni usurpé sans la clé secrète. Le nom ne confère aucune autorité — Q21 n'a pas
de gouvernance — il atteste seulement d'une origine constante d'une livraison
à l'autre.

**Lisez-le, et refusez tout ce qui ne lui ressemble pas.** Le deuxième mot
doit être `main` ou une étiquette `v…` ; le troisième, l'empreinte du commit
que vous attendiez (celle affichée en tête de l'exécution dans l'onglet
Actions). Un commentaire qui nomme une autre branche, ou un commit que vous
n'avez pas relu, est une signature valide de quelque chose que vous n'avez
pas voulu : **n'installez pas**. Et n'installez jamais depuis une exécution
rouge, même si les archives y sont — une exécution rouge est une exécution
dont la signature a échoué. La
seconde doit dire `OK` pour l'archive que vous avez téléchargée. **Si l'une
des deux échoue, n'installez pas** : ce n'est pas votre livraison.

Sous Windows, `minisign` se télécharge depuis la page des versions de son
auteur ; la vérification est la même dans PowerShell.

## 5 · Les actions de la chaîne de construction

Les workflows appellent des actions tierces (`actions/checkout`,
`Swatinem/rust-cache`…). Suivies par une étiquette (`@v4`), elles peuvent
être réécrites ; épinglées à une empreinte de commit, non. Le script
`outils/epingler-actions.sh`, lancé depuis une machine qui a accès à
`api.github.com`, réécrit chaque `uses:` avec l'empreinte de son étiquette.
Relisez le diff, publiez. La chaîne d'outils Rust, elle, est installée par
`rustup` à la version de `rust-toolchain.toml`, sans action tierce.
