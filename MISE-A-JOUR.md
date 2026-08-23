# Mettre à jour ton portefeuille

Cinq minutes. Aucune commande.

---

## 1 · Remplace le dossier

Tu as téléchargé `q21-depot.tar.gz`. Décompresse-le : tu obtiens un dossier `q21`.

**Dans GitHub Desktop :**

1. Menu **Repository** → **Show in Explorer** (ou *Show in Finder*)
   → l'Explorateur s'ouvre sur ton ancien dossier `q21`
2. Ferme GitHub Desktop
3. **Supprime** l'ancien dossier `q21`
4. **Mets le nouveau à la place**, exactement au même endroit
5. Rouvre GitHub Desktop

Il devrait afficher **« 1 changed file »** ou plus, dans l'onglet *Changes*.

> **S'il dit que le dépôt a disparu** : menu **File** → **Add local repository** →
> choisis le nouveau dossier `q21`.

---

## 2 · Envoie sur GitHub

En bas à gauche, dans le champ **Summary**, écris :

```
Sept corrections trouvees a l'usage
```

Clique sur **Commit to main**, puis sur **Push origin** en haut.

---

## 3 · Relance la fabrication

Sur `github.com/golboy03/Q21` :

**Actions** → **Livraison** (colonne de gauche) → **Run workflow** ▾ → bouton vert **Run workflow**

Dix à vingt minutes. Puis télécharge `q21-windows-x86_64.zip` en bas de la page.

---

# Ce qui change pour toi

## Tu double-cliques, c'est tout

Dans la nouvelle archive, à côté de `q21.exe`, il y a **`Portefeuille Q21.bat`**.

**Double-clique dessus.** Il crée le portefeuille s'il n'existe pas, puis ouvre
le navigateur. Plus de fenêtre de commande à manipuler.

*(Sur Mac, c'est `Portefeuille Q21.command` — clic droit → Ouvrir la première fois.)*

## Ctrl-C n'efface plus rien

Avant, `Ctrl` + `C` **tuait le programme sur place**. Tout ce qu'il devait
écrire en s'arrêtant — les transactions en attente, l'état de la chaîne, le
carnet de pairs — était perdu.

C'est ce qui a réellement fait disparaître ta transaction. Le problème n'était
pas seulement que le réservoir n'était pas sauvegardé : **même écrit, il ne
l'aurait jamais été**, parce que le code d'arrêt n'était jamais atteint.

Maintenant tu verras :

```
  Arret demande. Ecriture en cours...
  1 transaction(s) en attente conservee(s)
```

## Ta transaction survit

Envoie, arrête, mine, relance : elle est toujours là, et `q21 mine` la met
dans le bloc qu'il trouve. Vérifié sur ton scénario exact.

## Tu peux rafraîchir la page

F5 ne casse plus rien.

## L'historique dit ce qui est sorti

Une colonne **Sorti** apparaît à côté de **Reçu**. Sur un envoi, tu vois enfin
les deux : ce qui est parti, et la monnaie qui t'est revenue.

## La fenêtre ne défile plus

Elle affiche l'adresse, et se tait.

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
