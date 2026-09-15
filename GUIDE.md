# Mettre Q21 sur GitHub et obtenir les logiciels Mac et Windows

Aucune commande à taper. Aucun jeton. Environ vingt minutes, dont quinze
d'attente.

---

## Ce qu'on va faire, en une phrase

Tu vas installer un petit logiciel gratuit qui envoie le projet sur ton compte
GitHub en trois clics. Ensuite, les serveurs de GitHub fabriqueront tout seuls
le logiciel pour Mac et pour Windows, et tu n'auras plus qu'à le télécharger.

---

# Étape 1 — Ranger le dossier

Tu as téléchargé un fichier qui s'appelle `q21-depot.tar.gz`.

**Sur Mac :** double-clique dessus. Un dossier `q21` apparaît à côté.

**Sur Windows :** clic droit → *Extraire tout* → *Extraire*. Si Windows n'y
arrive pas (il n'aime pas toujours le `.tar.gz`), installe 7-Zip
(https://www.7-zip.org) et refais un clic droit → *7-Zip* → *Extraire ici*. Il
faudra peut-être le faire **deux fois** : une fois pour retirer le `.gz`, une
fois pour le `.tar`.

Retiens où se trouve ce dossier `q21`. Le Bureau est un bon endroit.

> **Comment savoir que c'est le bon dossier ?** Il contient un dossier `src`, un
> fichier `Cargo.toml`, et des fichiers `.md`.

---

# Étape 2 — Installer GitHub Desktop

C'est le logiciel officiel de GitHub. Gratuit, et il évite complètement le
terminal.

**https://desktop.github.com**

Télécharge, installe, ouvre-le.

---

# Étape 3 — Te connecter

Au premier lancement, GitHub Desktop propose **Sign in to GitHub.com**.

Clique. Ton navigateur s'ouvre sur le site de GitHub, tu confirmes, et c'est
fini.

> **C'est ici que le jeton disparaît.** GitHub Desktop se connecte par le
> navigateur, comme un site normal. Il n'y a rien à copier, rien à coller, rien
> à garder.

Il demandera ensuite ton nom et ton adresse e-mail : ils apparaîtront comme
auteur des modifications. Mets ce que tu veux.

---

# Étape 4 — Ajouter le projet

Dans le menu du haut : **File** → **Add local repository…**

*(Sur Windows, si tu ne vois pas le menu, appuie sur `Alt`.)*

Une fenêtre s'ouvre. Clique **Choose…**, va chercher ton dossier `q21`, et
valide.

GitHub Desktop affiche alors quelque chose comme :

> **Q21** — This repository has no remote

C'est normal, et c'est exactement ce qu'on veut : le projet est reconnu, il n'est
juste pas encore relié à ton compte.

> **Si à la place il dit « this directory does not appear to be a Git
> repository »**, c'est que tu as choisi le mauvais dossier — probablement un
> dossier qui *contient* `q21` au lieu de `q21` lui-même. Ressaie en descendant
> d'un niveau.

---

# Étape 5 — Envoyer sur GitHub

Un bouton bleu **Publish repository** apparaît en haut à droite. Clique.

Une petite fenêtre s'ouvre :

| Champ | Ce que tu mets |
|---|---|
| **Name** | `Q21` |
| **Description** | laisse vide |
| **Keep this code private** | **coché** |

Clique **Publish repository**.

Ça prend une à deux minutes : il y a 1 140 fichiers à envoyer.

> **Si GitHub dit que le nom `Q21` est déjà pris**, c'est ton dépôt vide de tout
> à l'heure. Va sur https://github.com/rei-asanoha/Q21 → **Settings** → tout en bas
> → **Delete this repository**. Puis recommence l'étape 5.

**C'est fait.** Ton code est sur GitHub. Va voir : https://github.com/rei-asanoha/Q21

---

# Étape 6 — Lancer la fabrication

Sur la page de ton dépôt, en haut, il y a des onglets : *Code*, *Issues*,
*Pull requests*, **Actions**…

Clique sur **Actions**.

Dans la colonne de gauche, deux lignes apparaissent : **Epreuves** et
**Livraison**.

1. Clique sur **Livraison**
2. À droite, un bouton gris **Run workflow** apparaît. Clique dessus.
3. Un petit menu s'ouvre. Clique sur le bouton vert **Run workflow**.

Rafraîchis la page après quelques secondes : une ligne apparaît avec un rond
jaune qui tourne. La fabrication a commencé.

---

# Étape 7 — Attendre, puis télécharger

Compte **dix à vingt minutes**. GitHub compile ton logiciel sur quatre vraies
machines en même temps : un Mac Apple Silicon, un Mac Intel, un PC Windows, une
machine Linux.

Clique sur la ligne pour suivre. Quand les quatre ronds sont verts, descends en
bas de la page : une section **Artifacts** contient quatre fichiers.

| Fichier | Pour qui |
|---|---|
| `q21-macos-arm64.tar.gz` | Mac récent (M1, M2, M3, M4) |
| `q21-macos-x86_64.tar.gz` | Mac ancien, à processeur Intel |
| `q21-windows-x86_64.zip` | Windows |
| `q21-linux-x86_64.tar.gz` | Linux |

Télécharge celui de ta machine.

> **Quel Mac as-tu ?** Menu Pomme → *À propos de ce Mac*. Si tu lis « Puce
> Apple M… », prends `arm64`. Si tu lis « Processeur Intel », prends `x86_64`.

---

# Étape 8 — Ouvrir le portefeuille

Décompresse l'archive. Tu obtiens un fichier `q21` (ou `q21.exe`).

Ouvre un terminal **dans ce dossier** :

- **Mac** : clic droit sur le dossier → *Nouveau terminal au dossier*
- **Windows** : dans la barre d'adresse de l'explorateur, tape `cmd` puis Entrée

Puis, deux commandes — les seules de tout ce document :

```
q21 init testnet
q21 wallet
```

*(Sur Mac et Linux, écris `./q21` au lieu de `q21`.)*

La première crée ton portefeuille. Elle demande une phrase secrète, puis affiche
un **code de sauvegarde** de 66 caractères. **Recopie-le sur papier.** C'est le
seul moyen de retrouver tes fonds si le fichier disparaît.

Le jour où tu en as besoin, sur une machine neuve : `q21 restore testnet`, et
le code t'est demandé au clavier, sans s'afficher. Ne le tape **jamais** dans
la commande elle-même — le terminal garde l'historique de tout ce que tu tapes,
et ce code, c'est ton portefeuille entier. Le programme refuse d'ailleurs de le
prendre ainsi, et t'explique pourquoi.

La seconde ouvre le portefeuille dans ton navigateur.

---

## Les deux avertissements que tu vas voir, et pourquoi

**Sur Mac :** « impossible d'ouvrir, le développeur ne peut pas être vérifié ».
→ Clic droit sur le fichier `q21` → **Ouvrir** → **Ouvrir** encore.

**Sur Windows :** un écran bleu SmartScreen.
→ **Informations complémentaires** → **Exécuter quand même**.

Ces avertissements sont normaux et attendus. Ils apparaissent parce que le
logiciel n'est pas signé par un certificat d'éditeur. En obtenir un coûte un
abonnement Apple Developer annuel et un certificat Windows payant. Tant que ce
n'est pas fait, ton système ne peut pas savoir d'où vient le fichier — et il a
raison de le dire.

---

# Si quelque chose bloque

**GitHub Desktop refuse le dossier** → tu as choisi le dossier parent. Descends
dans `q21` lui-même, celui qui contient `src` et `Cargo.toml`.

**L'onglet Actions est vide** → attends une minute et rafraîchis. Si rien
n'apparaît, c'est que le dossier `.github` n'a pas été envoyé. Dis-le-moi.

**Un rond rouge au lieu de vert** → clique dessus, puis sur l'étape en rouge.
Copie-moi le message d'erreur : je te dirai ce que c'est.

**Ça dure plus de trente minutes** → c'est anormal. Envoie-moi une capture de la
page.

---

# Plus tard, quand tu voudras une vraie « version »

L'étape 6 dépose les fichiers sur la page de l'exécution, ce qui est parfait
pour essayer. Pour une version publiée, avec une page de téléchargement propre :

Sur ton dépôt → **Releases** (colonne de droite) → **Create a new release** →
dans *Choose a tag*, tape `v0.1.0` et clique *Create new tag* → **Publish
release**.

La fabrication repart toute seule, et les quatre fichiers apparaissent cette
fois sur une vraie page de version.
