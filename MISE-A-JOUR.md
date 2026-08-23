# Mettre à jour ton portefeuille

Cinq minutes. Aucune commande.

---

## 1 · Verse le nouveau contenu **dans** le dossier existant

> ### ⚠ Ne supprime jamais le dossier `Q21` lui-même
>
> Il contient un sous-dossier **caché** nommé `.git`. Ce `.git` **est** le dépôt :
> c'est lui qui connaît l'historique et le lien vers GitHub. Cette archive ne le
> contient pas — volontairement, car un second `.git` provoquerait l'erreur
> « unrelated histories ».
>
> Supprimer le dossier pour mettre celui de l'archive à la place détruit donc le
> dépôt, et GitHub Desktop affiche **« Can't find Q21 »**.
>
> On **verse** le nouveau contenu dedans. On ne remplace pas le contenant.

Tu as téléchargé `q21-depot.zip`. Décompresse-le : tu obtiens un dossier `q21`.

1. Dans GitHub Desktop : menu **Repository** → **Show in Explorer**
   → l'Explorateur s'ouvre sur ton dossier de dépôt
2. Ouvre le dossier `q21` issu de l'archive, dans une **autre** fenêtre
3. Dedans : `Ctrl` + `A` (tout sélectionner), puis `Ctrl` + `C`
4. Reviens sur la fenêtre du dépôt : `Ctrl` + `V`
5. Windows demande quoi faire → **Remplacer les fichiers dans la destination**

Retourne dans GitHub Desktop : il affiche les fichiers modifiés dans l'onglet
*Changes*.

> **Si GitHub Desktop affiche déjà « Can't find Q21 »** — c'est que le dossier a
> été supprimé. Clique sur **Clone Again** : GitHub Desktop retélécharge le dépôt
> depuis ton compte, avec son `.git`. Reprends ensuite à l'étape 2 ci-dessus.
>
> Si un dossier `Q21` existe encore à cet endroit sans être un dépôt, renomme-le
> en `Q21-ancien` avant de cliquer sur **Clone Again**, puis supprime-le une fois
> l'opération finie.

---

## 2 · Envoie sur GitHub

En bas à gauche, dans le champ **Summary**, écris :

```
Un bouton pour fermer le portefeuille
```

Clique sur **Commit to main**, puis sur **Push origin** en haut.

---

## 3 · Relance la fabrication

Sur `github.com/golboy03/Q21` :

**Actions** → **Livraison** (colonne de gauche) → **Run workflow** ▾ → bouton vert **Run workflow**

Dix à vingt minutes. Puis télécharge `q21-windows-x86_64.zip` en bas de la page.

---

# Ce qui change pour toi

## Tu n'as plus besoin de Ctrl-C

Dans le portefeuille, onglet **Informations**, tout en bas : un bouton
**« Fermer le portefeuille »**.

Un premier clic demande confirmation, un second ferme. Le nœud écrit ses
transactions en attente, son état et ton portefeuille, puis s'arrête. La fenêtre
noire se referme toute seule.

**Fermer la fenêtre noire** avec la croix marche aussi : c'est intercepté de la
même façon.

## Le message « Terminer le programme de commandes (O/N) ? »

C'est ce qui t'a bloqué, et **ce n'était pas une panne**.

Ce message ne vient pas de Q21. Il vient de Windows : quand tu fais `Ctrl` + `C`
pendant qu'un fichier `.bat` tourne, l'interpréteur de commandes pose *sa* propre
question avant de rendre la main. Aucune ligne du fichier ne peut l'en empêcher —
elle arrive avant que le script ait son mot à dire.

À ce moment-là, **tout est déjà enregistré**. La preuve est juste au-dessus, à
l'écran :

```
  Arret demande. Ecriture en cours...
Arret. Hauteur finale : ...
```

Ces deux lignes veulent dire que Q21 a intercepté ton `Ctrl` + `C`, écrit ce
qu'il devait écrire, et s'est arrêté proprement. La question de Windows arrive
**après**.

**Réponds `O`.** Tu ne perds rien.

Et maintenant tu n'as plus à le faire : le bouton existe.

## La phrase secrète est demandée en premier

Avant, l'écran affichait l'adresse, « laissez cette fenêtre ouverte », puis
d'un coup une ligne nue :

```
Phrase secrete du portefeuille :
```

Sans rien qui l'annonce, après t'avoir dit que tout tournait. C'était le mauvais
ordre. Maintenant :

```
Portefeuille Q21

  Ce portefeuille est protege par une phrase secrete.
  Tapez-la puis Entree. Elle ne s'affiche pas pendant la frappe :
  c'est voulu, pour que personne ne la lise par-dessus votre epaule.

Phrase secrete du portefeuille :
```

Et l'adresse ne s'affiche qu'**après** — quand le portefeuille est réellement
ouvert. Une phrase fausse échoue tout de suite, au lieu d'ouvrir un navigateur
sur une page qui ne servirait à rien.

## La fenêtre dit comment l'arrêter

Les trois voies, écrites noir sur blanc au démarrage :

```
  Pour arreter, au choix :
    - le bouton « Fermer le portefeuille », onglet Informations ;
    - fermer cette fenetre ;
    - Ctrl-C ici. Windows demande alors « Terminer le programme
      de commandes (O/N) ? » : repondez O. Ce n'est pas une erreur,
      tout est deja enregistre quand cette question s'affiche.
```

---

# La commande qui t'évitera des allers-retours

```
q21 wallet --mine
```

Le portefeuille **et** le minage en même temps. Tes transactions se confirment
toutes seules en quelques secondes, sans rien arrêter.

Si tu passes par le fichier à double-cliquer, le minage n'est pas actif — c'est
volontaire, il ferait tourner ton processeur en permanence.

---

# Ce qui reste imparfait

- Pas de code QR pour les adresses de réception
- L'historique remonte 5 000 blocs, pas davantage — la page le dit quand elle
  s'arrête là
- Les fichiers ne sont toujours pas signés : Windows et macOS afficheront leur
  avertissement, et ils ont raison de le faire
