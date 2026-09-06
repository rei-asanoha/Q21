# Publier Q21 sur GitHub

Trois commandes, sur **ta** machine.

Le dépôt est déjà prêt : l'historique git est fait, le premier enregistrement
est écrit, `.gitignore` exclut tout ce qui touche aux clés. Il ne reste qu'à
l'envoyer.

---

## Ce qu'il te faut

**Git.** Vérifie dans un terminal :

```bash
git --version
```

Si la commande est inconnue :

- **macOS** — tape simplement `git` dans le Terminal : macOS proposera de
  l'installer.
- **Windows** — https://git-scm.com/download/win, puis ouvre *Git Bash*.

---

## Les trois commandes

Décompresse `q21-depot.tar.gz`, puis, dans le dossier obtenu :

```bash
cd q21
git remote set-url origin https://github.com/VOTRE-COMPTE/VOTRE-DEPOT.git
git push -u origin main
```

Git demandera :

- **Username** : `VOTRE-COMPTE`
- **Password** : **le jeton**, pas ton mot de passe GitHub

> GitHub n'accepte plus les mots de passe pour ce genre d'opération depuis 2021.
> Le champ s'appelle « password » mais attend un jeton d'accès. Colle-le tel
> quel — il ne s'affichera pas pendant la frappe, c'est normal.

Le premier envoi prend une minute environ : 1 140 fichiers, dont les sources
vendorisées de `ml-dsa`.

---

## Puis déclenche les compilations

```bash
git tag v0.1.0
git push origin v0.1.0
```

C'est cette étiquette qui lance la chaîne de livraison. Va ensuite sur
**https://github.com/VOTRE-COMPTE/VOTRE-DEPOT/actions** : tu verras quatre compilations
démarrer.

Compter environ dix à quinze minutes. À la fin, sur
**https://github.com/VOTRE-COMPTE/VOTRE-DEPOT/releases**, quatre archives :

| Fichier | Pour |
|---|---|
| `q21-macos-arm64.tar.gz` | Mac Apple Silicon (M1 et suivants) |
| `q21-macos-x86_64.tar.gz` | Mac Intel |
| `q21-windows-x86_64.zip` | Windows |
| `q21-linux-x86_64.tar.gz` | Linux |

Chacune accompagnée de son condensat SHA-256.

---

## Il te faut un nouveau jeton

Celui de tout à l'heure doit être révoqué — il a circulé dans une conversation
enregistrée. Le nouveau ne quittera jamais ta machine.

**https://github.com/settings/personal-access-tokens/new**

| Champ | Valeur |
|---|---|
| Token name | `q21-local` |
| Expiration | `30 days` |
| Repository access | *Only select repositories* → **Q21** |
| Permissions → **Contents** | **Read and write** |
| Permissions → **Workflows** | **Read and write** |

La permission **Workflows** n'est pas facultative : sans elle, GitHub refuse
l'envoi dès qu'un fichier se trouve dans `.github/workflows/`, et c'est
précisément là que vivent les deux chaînes de compilation.

---

## Pour ne pas le retaper à chaque fois

Après le premier envoi réussi :

```bash
git config --global credential.helper store     # Linux
git config --global credential.helper osxkeychain   # macOS
git config --global credential.helper manager       # Windows
```

Sur macOS et Windows, le jeton va dans le trousseau du système. Sur Linux,
`store` l'écrit en clair dans `~/.git-credentials` — acceptable pour un jeton
limité à un dépôt et daté, moins pour autre chose.

---

## Si quelque chose refuse

**`Permission denied` ou `403`** — le jeton n'a pas la permission *Contents:
Read and write*, ou il ne vise pas le bon dépôt.

**`refusing to allow a Personal Access Token to create or update workflow`** —
c'est la permission *Workflows* qui manque. Refais un jeton avec les deux.

**`Updates were rejected because the remote contains work`** — le dépôt n'est
pas vide. Tu as probablement ajouté un README à la création. Le plus simple :
supprime le dépôt sur GitHub et recrée-le en laissant les trois options du bas
sur « rien ».

**`Authentication failed`** — tu as collé ton mot de passe GitHub et non le
jeton. Ce sont deux choses différentes.

---

## Vérifier ce que tu envoies

Avant de pousser, si tu veux voir ce qui part :

```bash
git log --stat -1 | head -30      # le contenu du premier enregistrement
git ls-files | wc -l              # 1140 fichiers
git ls-files | grep -c '^vendor/' # 1078, les sources de ml-dsa
```

Aucun `wallet.dat`, aucune clé, aucune donnée de chaîne n'en fait partie : le
`.gitignore` les exclut explicitement. Un chiffrement se casse avec le temps ;
un dépôt ne s'oublie jamais.
