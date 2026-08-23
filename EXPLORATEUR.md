# L'explorateur Q21

Voir la chaîne — blocs, transactions, adresses — dans un navigateur, servi par
votre propre nœud.

## En une commande

```bash
./q21 explorateur
```

Le navigateur s'ouvre. Un seul champ de recherche, qui accepte quatre choses :

| Ce que vous collez | Ce que vous obtenez |
|---|---|
| `276` | Le bloc à cette hauteur |
| `5aabc886d907…` (64 caractères) | Le bloc, ou la transaction, portant cet identifiant |
| `tq211qssljt322rlk…` | L'adresse : son solde, et tous ses mouvements |

Le portefeuille sert déjà cet explorateur, au même endroit et sur le même port :
lien en bas de la page, ou `http://127.0.0.1:<port>/`. La commande ci-dessus est
pour le cas inverse — consulter la chaîne **sans** ouvrir de portefeuille. Les
méthodes qui déplacent des fonds ne sont alors pas désactivées par un réglage :
elles sont absentes.

---

## Pourquoi il n'est pas hébergé ailleurs

Pour consulter une chaîne, presque tout le monde ouvre le site d'un tiers. On
fait donc confiance à un serveur pour savoir ce que contient un système bâti
pour ne faire confiance à personne — et ce serveur peut se tromper, mentir,
disparaître, ou être contraint.

Cette page est servie par votre nœud, sur la boucle locale, et n'affiche que ce
que votre machine a validé elle-même. Elle ne charge **aucune ressource
externe** : ni police, ni feuille de style, ni script distant. Une page
d'exploration qui appelle un CDN lui annonce chaque chose que vous consultez.

Elle affiche aussi, en clair, ce que le protocole **ne** protège **pas**. Un
explorateur qui ne montre que ce qui rassure ment par omission.

---

## L'index d'adresses

« Montre-moi toutes les transactions de cette adresse » n'a pas de réponse bon
marché dans une chaîne de blocs. Rien, dans la structure, ne relie une adresse à
ses transactions : il faut les parcourir toutes.

Sans index, le nœud balaie donc en arrière et s'arrête au bout de 2 000 blocs.
La réponse n'est pas fausse — elle est incomplète, **et elle le dit** :

> **Historique borné.** Recherche remontée jusqu'au bloc 12 400 sur 14 400.
> Le solde affiché reste exact : il vient de l'ensemble des sorties non
> dépensées, pas de cette liste.

`q21 explorateur` active l'index par défaut ; `q21 node` et `q21 wallet` ne
l'activent que si on le demande, par `--index-adresses`. Un index se paie deux
fois, en disque et en écriture à chaque bloc, et un nœud qui valide la chaîne
n'en a aucun besoin : il ne cherche que ses propres adresses, et il sait
lesquelles. Bitcoin Core a tranché de la même façon avec `txindex`, pour la même
raison.

### Ce que l'index permet, et ce qu'il coûte

|  | Sans index | Avec index |
|---|---|---|
| Recherche d'adresse | 2 000 derniers blocs | Toute la chaîne |
| Montants **envoyés** par une adresse | Non résolus | Résolus |
| Recherche par identifiant de transaction | 2 000 derniers blocs | Immédiate |
| Solde d'une adresse | Exact | Exact |
| Disque | rien | un journal qui croît avec la chaîne |
| Premier démarrage | rien | un balayage complet |

Le **solde** ne dépend d'aucun index, et c'est voulu : il vient de l'ensemble
des sorties non dépensées que le nœud tient à jour de toute façon. Il reste
exact même quand l'historique affiché ne l'est pas.

### La moitié difficile

Indexer ce qu'une adresse **reçoit** est immédiat : une sortie porte l'empreinte
de la clef autorisée à la dépenser.

Ce qu'elle **envoie** est une autre affaire. Une entrée de transaction ne
désigne que la sortie qu'elle consomme — pas son montant, pas son propriétaire.
Le témoin ne suffit pas : l'empreinte de clef dépend du schéma de signature, et
le schéma est inscrit sur la sortie, pas sur l'entrée.

L'index tient donc une table des sorties **non dépensées** — mêmes clefs que
l'ensemble UTXO, dont la taille dépend de l'économie et non de la longueur de la
chaîne. Une sortie y entre quand elle est créée, en sort quand elle est
dépensée, et répond au passage à la question « à qui était-elle ».

Conséquence : **l'index colle exactement au sommet de la chaîne, ou bien il est
reconstruit depuis zéro.** Rien entre les deux. Un index en retard de quelques
blocs aurait perdu les sorties créées avant ce retard et dépensées pendant lui ;
les envois correspondants seraient attribués à personne, et l'écran d'une
adresse montrerait ses réceptions sans ses envois. Un index faux ne se voit pas
— un index reconstruit se paie une fois.

---

## Ce que l'index garantit malgré une coupure

Le journal est écrit à la suite, un enregistrement par bloc, **chacun portant sa
propre somme de contrôle**. Une écriture coupée en deux — plus de place, arrêt
brutal — laisse un dernier enregistrement illisible, qu'on ignore.

L'index repart alors quelques blocs en arrière, constate qu'il ne colle plus au
sommet, et se reconstruit. Il ne s'agit pas de données vitales : l'index se
dérive entièrement de la chaîne, qui est la seule source.

Quatre épreuves verrouillent ce comportement dans `src/index.rs` : journal
tronqué, octet modifié, hauteurs qui sautent, réorganisation.

---

## Le jeton, et le fragment qu'il partage avec le routage

Le nœud exige un jeton sur toute méthode RPC. Il arrive dans le **fragment** de
l'adresse — ce qui suit le `#` — que le navigateur ne transmet jamais au
serveur. La page le lit, l'efface aussitôt de la barre d'adresse, et l'envoie
ensuite en `Authorization: Bearer`.

Ce même fragment sert au routage des quatre vues. Les deux ne se confondent
pas : **une route commence toujours par une barre oblique, un jeton jamais.**

Conséquences agréables et gratuites : le bouton « page précédente » du
navigateur fonctionne, chaque page a une adresse qu'on peut mettre en signet, et
changer de vue ne demande aucune requête au serveur — la page reste un fichier
unique, servi tel quel.

---

## Un défaut trouvé par le premier utilisateur

La tuile **État** d'une transaction affichait ceci, en clair, à l'écran :

```
<span class="badge">confirmée</span>
```

Le balisage était passé à la fonction d'affichage sans être marqué comme tel.
Cette fonction échappe par défaut — **c'est la bonne direction**, celle qui
protège contre l'injection — et elle a donc fait exactement ce qu'on lui
demandait.

Aucune épreuve ne pouvait l'attraper : celles qui existaient cherchaient le
défaut inverse, du balisage inséré *sans* échappement. Il fallait regarder dans
l'autre sens.

La correction n'est pas d'ajouter le marquage à cet endroit-là, mais de donner
une fonction — `badge()` — qui fabrique l'étiquette et se charge du marquage.
Une épreuve parcourt désormais chaque appel des deux pages, en équilibrant les
parenthèses, et refuse tout argument portant un chevron suivi d'une lettre sans
passer par `brut()`. Elle a été vérifiée en réintroduisant le défaut.

---

## Ce que l'explorateur ne fait pas

- **Les frais d'une transaction ne sont pas affichés.** Il faudrait résoudre
  chaque entrée pour connaître sa valeur. La page préfère se taire plutôt
  qu'afficher un chiffre qu'elle n'a pas vérifié.
- **Aucune courbe.** Émission, difficulté, taille des blocs : les chiffres sont
  là, les graphiques non.
- **Il est prévu pour la boucle locale.** Aucune limitation de débit, aucun
  cache : l'exposer publiquement demanderait les deux.
- **Il ne pagine pas.** Une adresse affiche ses 100 mouvements les plus récents,
  et annonce le total.
