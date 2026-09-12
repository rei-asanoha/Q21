# Audit d'intrusion : l'explorateur public

Mené avant toute mise en ligne, contre un nœud réel en mode public — chaîne de
1 224 blocs, index d'adresses actif, port de bouclage, nom déclaré
`explorateur.example.org`.

La question posée était unique et non négociable : **un visiteur peut-il faire
autre chose que lire ?**

La réponse est non. Elle ne l'était pas au début de cet audit.

---

## Ce qui a été trouvé, et corrigé

Cinq constats. Aucun ne permettait de déplacer des fonds — l'architecture y
pourvoyait déjà — mais quatre ouvraient une porte qui n'avait aucune raison
d'exister, et un rendait le service trivialement inutilisable.

### 1 · La page du portefeuille était servie publiquement — corrigé

`https://explorateur.example.org/portefeuille` rendait **200** et affichait
l'interface complète du portefeuille Q21.

Elle ne pouvait rien déplacer : le nœud publié n'a pas de portefeuille, et
toutes les méthodes correspondantes sont refusées. Mais c'est le décor exact
d'un hameçonnage, **monté par nous, sur le domaine officiel du projet**. Un
visiteur y voit une interface authentique et prend l'habitude de saisir des
choses sur un site web — précisément ce qu'un porteur de Q21 ne doit jamais
apprendre à faire.

Une surface qui ne sert à rien se retire : ces chemins rendent désormais **404**
en mode public, et le portier les bloque aussi.

### 2 · Au-delà de 64 en-têtes, le reste devenait le corps — corrigé

L'analyseur s'arrêtait à la limite **sans rien dire**, et la lecture du corps
reprenait là où elle en était : les en-têtes excédentaires devenaient
silencieusement le début du corps.

Aucune fuite ne s'ensuivait — les connexions se ferment après chaque réponse —
mais une requête dont le découpage dépend de l'émetteur est la définition de la
*contrebande de requêtes*, et cette tolérance deviendrait une faille le jour où
l'on ajouterait la réutilisation des connexions. Le dépassement est maintenant
un refus, `400`.

### 3 · Un `Host` en double passait selon l'ordre — corrigé

`Host: evil.example` suivi de `Host: explorateur.example.org` était **accepté** : la
table conserve la dernière valeur, alors qu'un intermédiaire lit la première.
Deux machines qui ne lisent pas la même valeur pour le même champ, c'est
exactement ce qu'exploite la contrebande de requêtes.

Aucun navigateur n'en envoie deux et la norme l'interdit. Le refus est
désormais explicite, `400`, **quel que soit l'ordre**.

### 4 · Une requête sans `Host` était servie — corrigé

Un service publié ne répond que sous le nom qu'on lui a donné. L'absence
d'en-tête `Host` rend maintenant `403` en mode public. En local, la tolérance
reste : la garde y protège d'un navigateur, et un navigateur envoie toujours cet
en-tête.

### 5 · Slowloris rendait le service indisponible — corrigé par l'architecture

Deux cents connexions ouvertes et **jamais terminées** saturaient les
soixante-quatre fils du serveur. Pendant l'attaque, tout autre visiteur recevait
`503`. Reproduit en deux lignes de Python.

Un serveur à un fil par connexion ne gagne pas seul contre cette attaque : la
parade appartient au portier, conçu pour tenir des milliers de connexions
lentes, et qui n'ouvre une connexion vers le nœud qu'une fois la requête
complète.

Le correctif est donc double, et il est structurel :

- **Le nœud refuse de démarrer en mode public ailleurs que sur la boucle
  locale.** Ce n'est plus une recommandation dans un document : c'est un refus
  du programme.
- **Le portier impose `read_header 5s`**, ce qui coupe une connexion muette
  avant qu'elle ne coûte quoi que ce soit.

---

## Ce qui a résisté, et qui n'a pas eu besoin d'être corrigé

### Les méthodes qui modifieraient quelque chose

Onze méthodes essayées, onze refus — y compris `arreter`, qui éteindrait le
serveur :

```
arreter, sendtoaddress, getnewaddress, setminage, setaddresslabel,
getbalance, listtransactions, preparersend, getwalletinfo,
listaddresses, estimatefee
    -> "methodes de portefeuille desactivees"
```

Et le garde-fou est en amont : **le binaire refuse de démarrer en mode public si
un portefeuille est servi**, avec un message qui dit comment faire autrement.

### La reliaison DNS

Sept en-têtes `Host` hostiles, sept refus — dont
`explorateur.example.org.evil.example`, le genre de sous-chaîne qui trompe une
comparaison paresseuse.

Cinq origines tierces, cinq refus — dont `null`,
`https://evil.example/#explorateur.example.org`, et l'origine **en clair** du nom
légitime.

### Les chemins

Traversée de répertoire (`/../../etc/passwd`, encodée ou non), `/.git/config`,
`/wallet.dat` : **404**, aucune fuite. Sept verbes HTTP inattendus : **404**.

### L'analyseur JSON

Imbrication de 100 000 niveaux, objet de 50 000 accolades, nombre de 4 000
chiffres, identifiant de 500 000 caractères, unicode brisé, `NaN`, clés
dupliquées : chaque cas répond en moins d'un centième de seconde, sans
consommation notable, et le nœud reste vivant.

Les **clés dupliquées** sont rejetées comme document illisible — le bon
comportement : `{"method":"getinfo","method":"arreter"}` ne doit pas avoir à
choisir.

### L'amplification par lot

Bornée par un audit précédent, et vérifiée à nouveau : 101 appels dans un lot
sont refusés, 5 000 aussi, et la taille cumulée des réponses est plafonnée.

### Le coût de calcul

Sur une chaîne de 1 224 blocs, avec index :

| Méthode | Temps médian |
|---|---:|
| `getinfo` | 0,3 ms |
| `getblock` | 0,2 ms |
| `gettransaction` (inconnu) | 3,3 ms |
| `rechercher` | 0,2 ms |
| `getsecurity` | 0,1 ms |

La plus coûteuse — chercher une transaction qui n'existe pas — vaut 3 ms pour
143 octets envoyés. L'amplification existe mais reste modeste ; elle sera
réévaluée quand la chaîne aura grandi, car ce coût croît avec la hauteur.

### Les bornes de taille

Corps de 2 Mio : refusé. `Content-Length` mensonger dans les deux sens : refusé
ou sans effet. Ligne de requête de 20 Kio : refusée. En-tête de 20 Kio :
refusée. Injection de retour chariot dans une valeur d'en-tête : sans effet,
aucun en-tête falsifié dans la réponse.

### Les en-têtes de réponse

Déjà en place, et vérifiés : `Content-Security-Policy: default-src 'none'`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`.

### La confiance dans le mandataire

`X-Forwarded-Host: explorateur.example.org` avec `Host: evil.example` est **refusé**.
Le nœud ne fait confiance à aucun en-tête réécrit — ce qui est la bonne règle
quand le mandataire est le seul à pouvoir en poser.

---

## Ce qui reste, et qui est assumé

**La saturation par le volume.** N'importe qui peut demander des blocs en
boucle. Sur un réseau d'essai, c'est acceptable et même instructif : c'est une
mesure qu'on veut. Le portier sait limiter le débit par adresse si cela devient
gênant ; ce n'est pas activé aujourd'hui, faute de savoir à quel seuil.

**Le coût qui croît avec la chaîne.** `gettransaction` sur un identifiant
inconnu balaie une fenêtre de blocs. À 1 224 blocs il coûte 3 ms ; à un million,
il faudra un index ou une borne. C'est noté comme dette, pas comme faille.

**Ce que l'explorateur révèle est ce qu'il doit révéler** : hauteur, blocs,
transactions, difficulté, émission. Un explorateur qui cacherait la chaîne
n'aurait aucun sens. Le nombre de pairs est rendu **sans leurs adresses** — ce
qui a été vérifié, et qui est le bon compromis.

---

## Les épreuves qui gardent ces corrections

Des épreuves nouvelles, dans `src/http.rs`, qui échouent si l'une des portes se
rouvre :

- le nom déclaré est accepté, un autre non, y compris celui qui le contient ;
- l'origine déclarée est acceptée, une origine tierce ou en clair non ;
- le `Content-Type` reste exigé en mode public ;
- un `Host` en double est refusé dans les deux ordres ;
- une requête sans `Host` est refusée en mode public ;
- le mode public refuse d'écouter hors de la boucle locale ;
- l'excès d'en-têtes est un refus, pas une réinterprétation.

Elles tournent à chaque livraison.

---

## Second passage : simulations d'attaque, plus en profondeur

Reprise après coup, avec une seule question de plus : **si un jour un texte
choisi par un inconnu atteignait la page, resterait-il inerte ?** Et une
deuxième surface, jamais éprouvée jusque-là : **le port pair-à-pair public**.

### Ce que la chaîne peut injecter — rien, aujourd'hui

Le seul champ d'un bloc qu'un inconnu remplit à sa guise est le message de la
transaction de récompense. On a vérifié, réponse brute à l'appui, qu'**aucune
méthode de l'explorateur ne l'expose** : ni `getblock`, ni `gettransaction` ne
le rendent. Tout ce que la page affiche est de l'hexadécimal, un nombre ou une
adresse bech32 — trois alphabets sans le moindre caractère actif.

Chaque valeur qui traverse tout de même la page passe par un échappement
unique, et les messages d'erreur sont posés en `textContent`, jamais en HTML.
Chaque page ne porte qu'**un seul** script, celui qu'on a écrit, et **aucun**
gestionnaire en ligne.

### Le durcissement quand même : un jeton par réponse

Une porte fermée aujourd'hui peut se rouvrir le jour où l'on ajoute un champ
sans y penser. La politique de sécurité du contenu disait
`script-src 'unsafe-inline'` — elle autorisait donc n'importe quel script en
ligne, y compris un script glissé dans la page. Elle porte désormais un **jeton
tiré au hasard à chaque réponse**, inscrit sur la balise `<script>` et dans
l'en-tête. Le navigateur n'exécute que ce script-là ; un script injecté n'a pas
le jeton, et reste mort. Deux pages servies coup sur coup n'ont pas le même
jeton : il ne se devine pas. Sans aléa sûr, la page part avec une politique qui
interdit **tout** script — le bon échec.

Cinq épreuves nouvelles gardent ce point : le jeton diffère d'une réponse à
l'autre, la balise porte celui de l'en-tête, une réponse JSON n'autorise aucun
script, et `'unsafe-inline'` ne revient pas dans la politique.

### Le port pair-à-pair, éprouvé pour la première fois

C'est la première chose que touche un octet venu d'un inconnu, et il est
public. **1 930 trames malformées** lui ont été envoyées : octets purement
aléatoires, bonne magie avec commande inconnue, commandes connues aux charges
absurdes, en-têtes annonçant quatre milliards d'éléments, trames tronquées puis
coupées net, sommes de contrôle fausses, rembourrage non nul, envoi octet par
octet puis abandon.

Le nœud a **tout encaissé sans une seule panique**, mémoire stable à 4,5 Mio,
et il répondait encore normalement à la fin. C'est la promesse écrite en tête
du fichier de protocole — *aucune allocation avant contrôle, aucune panique* —
tenue à l'épreuve.

### Les trois batteries, rejouées contre la nouvelle version

Les batteries du premier passage — traversée de chemin, reliaison DNS, méthodes
qui modifieraient quelque chose, bornes de taille, analyseur JSON,
amplification par lot, coût par requête, Slowloris — ont été **rejouées à
l'identique** contre la version au jeton. Même verdict : chaque porte tient. Le
seul résidu reste le même, et il est assumé : deux cents connexions muettes
saturent un serveur à un fil par connexion. La parade n'est pas dans le nœud —
elle est dans le portier, et dans le refus du nœud de s'exposer ailleurs que
sur la boucle locale. Les deux sont en place.

**Verdict du second passage : rien de nouveau à corriger sur le fond, un cran
de durcissement ajouté par prudence.** Le coffre tient.
