# Clés publiques des constructeurs

Un fichier par personne ayant recompilé Q21 et déposé au moins une
attestation :

```
<pseudonyme>.pub
```

Le contenu est une clé publique `minisign` — deux lignes, dont la seconde fait
56 caractères :

```
untrusted comment: minisign public key 8F2A1C...
RWQf6lcT0yJ0Zm9uZGF0aW9uIHBvdXIgbGEgZGVtb25zdHJhdGlvbiBzZXVsZQ==
```

Une clé **GPG** est acceptée à la place (`<pseudonyme>.gpg`, armure ASCII) si
c'est l'outil que vous employez déjà ; dans ce cas la signature de votre
`SHA256SUMS` est un fichier `.asc` détaché. `minisign` est préféré parce qu'il
tient en un exécutable et n'exige aucune infrastructure, mais l'important est
qu'on puisse vérifier, pas quel outil a servi.

---

## Ce que déposer une clé ici ne donne pas

Aucun droit. Ni publier, ni fusionner, ni décider, ni voter. Une clé déposée
ici sert uniquement à ce qu'on puisse constater qu'une même personne atteste
plusieurs versions de suite — c'est-à-dire à donner un sens à la phrase « trois
constructeurs indépendants ont obtenu le même condensat ».

Il n'existe pas de clé de confiance, de clé maîtresse ni de clé d'alerte dans
Q21, et il n'en existera pas. Voir SUCCESSION.md.

---

## Changer ou révoquer votre clé

Déposez la nouvelle clé sous un nom qui dit la transition
(`<pseudonyme>-2.pub`) et laissez l'ancienne en place : les attestations déjà
déposées ont été signées avec elle et doivent rester vérifiables. Supprimer
une ancienne clé rendrait invérifiables des attestations passées, ce qui est
exactement l'inverse du but.

Si votre clé secrète est perdue ou compromise, dites-le dans une question
publique sur le dépôt, avec la date à partir de laquelle elle n'est plus à
croire. Un fichier `<pseudonyme>-revoquee.txt` déposé ici, signé par la
nouvelle clé, rend la déclaration durable.

---

## Marche à suivre complète

Voir `../LISEZ-MOI.md`, section 3.
