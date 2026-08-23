# Le portefeuille Q21

Un logiciel de bureau pour recevoir et envoyer du Q21, sur macOS, Windows et
Linux.

## En deux commandes

```bash
./q21 init testnet     # cree le portefeuille, affiche le code de sauvegarde
./q21 wallet           # ouvre l'interface dans le navigateur
```

La première commande demande une phrase secrète, puis affiche un **code de
sauvegarde** de 66 caractères. Recopiez-le sur papier avant d'aller plus loin :
c'est le seul moyen de retrouver vos fonds si le fichier disparaît.

---

## Trois décisions, et pourquoi

### Le portefeuille embarque un nœud complet

Un client léger demande à un serveur ce que contient la chaîne. C'est-à-dire
qu'il **fait confiance à quelqu'un** pour connaître son propre solde — dans un
système conçu précisément pour ne faire confiance à personne.

Ici, le portefeuille *est* un nœud. Il valide chaque bloc lui-même. Ce que
l'écran affiche, cette machine l'a vérifié.

Le prix : au premier lancement, il télécharge et vérifie la chaîne. Sur le
testnet c'est instantané ; sur un réseau mature ce sera long. C'est le même
arbitrage que Bitcoin Core, et il penche du même côté.

### L'interface est une page servie localement

Le binaire sert une page sur `127.0.0.1` et ouvre le navigateur dessus. Aucune
bibliothèque graphique, aucun cadre applicatif, aucune dépendance nouvelle dans
un logiciel qui garde des clés privées. C'est ce que font Electrum et la plupart
des portefeuilles matériels, pour la même raison.

La page ne charge **aucune ressource externe** : ni police, ni script, ni image
venue d'ailleurs. Tout est dans le fichier, et une épreuve le vérifie.

### Le jeton voyage dans le fragment de l'adresse

L'interface a besoin d'un jeton pour parler au nœud. Le mettre dans la requête —
`?token=...` — le ferait entrer dans l'historique du navigateur, dans les
journaux de tout mandataire, et dans l'en-tête `Referer` de la première ressource
externe chargée. Un secret qui voyage dans une adresse n'est plus un secret :
c'est une faille que l'audit de la phase 8b a relevée puis fermée.

Le **fragment** — ce qui suit le `#` — n'est jamais envoyé au serveur. Le
navigateur le garde pour lui. La page le lit, l'efface aussitôt de la barre
d'adresse, et l'envoie ensuite en `Authorization`. Il ne laisse aucune trace
ailleurs que dans la mémoire de l'onglet.

Ni `localStorage`, ni `sessionStorage`, ni cookie. Le jeton vit dans une variable
JavaScript et meurt avec l'onglet.

---

## Ce qui protège le portefeuille

| Défense | Ce qu'elle empêche |
|---|---|
| Contrôle d'origine, de `Referer` et de `Sec-Fetch-Site` | Une page web hostile qui dépenserait vos fonds à votre insu |
| `Content-Type: application/json` exigé | La CSRF par formulaire HTML, qui ne demande aucun JavaScript |
| Contrôle de l'en-tête `Host` | La réassociation DNS, qui rendrait une page hostile de même origine |
| Jeton exigé sur toute méthode RPC | Un autre programme de la machine |
| Écoute sur la boucle locale uniquement | Le reste du réseau |

Ces cinq verrous ont été éprouvés par 42 attaques réelles, en TCP, dans
`tests/audit_rpc.rs`. Chacune était un exploit qui fonctionnait.

---

## Ce qu'un premier utilisateur a trouvé

Le portefeuille a été mis entre les mains de quelqu'un qui ne l'avait pas écrit.
En une heure, sept défauts sont sortis. Aucun n'aurait été trouvé autrement.

| # | Ce qui clochait | Correction |
|---|---|---|
| 1 | Une transaction envoyée disparaissait à l'arrêt | Le réservoir est écrit sur disque (`mempool.dat`) et revalidé à la reprise |
| 2 | **Aucun gestionnaire de Ctrl-C** : le processus était tué sans rien écrire | `src/arret.rs` — le chemin d'arrêt testé n'était pas le chemin emprunté |
| 3 | `q21 mine` ignorait le réservoir et minait des blocs vides | Les transactions en attente entrent dans les blocs minés |
| 4 | Il fallait une fenêtre de commande | *Portefeuille Q21* se double-clique |
| 5 | Rafraîchir la page cassait la session | Le jeton survit dans `sessionStorage`, cloisonné par port |
| 6 | Les lignes d'état noyaient l'adresse à ouvrir | Mode silencieux dans le portefeuille |
| 7 | L'historique n'affichait pas la somme sortie | Colonne **Sorti**, et la page ne contredit plus le nœud |

Le deuxième est le plus instructif. La persistance du réservoir avait été écrite
**et testée** — mais uniquement sur le chemin d'arrêt des épreuves, l'expiration
de `--seconds`. Personne n'arrête un logiciel ainsi : on fait Ctrl-C. Sur ce
chemin-là, rien n'était écrit, et la correction n'aurait servi à rien.

## Ce que le portefeuille ne fait toujours pas

- **L'historique est borné.** Sans index par adresse, il remonte 5 000 blocs.
  La réponse le dit, et l'écran l'affiche.
- **Le portefeuille et le minage ne cohabitent qu'avec `--mine`.** Sans cette
  option, une transaction attend qu'on mine, et miner demande d'arrêter le
  portefeuille. `q21 wallet --mine` fait les deux à la fois.
- **Il n'y a pas de code QR** pour l'adresse de réception. La politique de
  sécurité du contenu interdit les images externes, et le dessiner en SVG reste
  à faire.
- **Les fichiers livrés ne sont ni signés ni notariés.** macOS et Windows
  afficheront un avertissement. Le contourner demande un compte Apple Developer
  payant et un certificat Authenticode. En attendant, le condensat SHA-256 de
  chaque fichier est publié avec lui.

---

## Compiler soi-même

```bash
cargo build --release --features mldsa
```

Les sources de `ml-dsa` sont dans `vendor/`, et `.cargo/config.toml` y redirige
crates.io : la compilation ne dépend d'aucun réseau, et deux compilations à deux
mois d'intervalle emploient exactement le même code de signature.

Sans la caractéristique `mldsa`, le binaire compile mais ne sait signer qu'en
Lamport — utilisable sur un réseau de test, jamais ailleurs.

## Compilation automatique

`.github/workflows/livraison.yml` construit les quatre fichiers — macOS Apple
Silicon, macOS Intel, Windows, Linux — sur de vraies machines, à chaque étiquette
de version. Aucune compilation croisée : rien n'est supposé.

`.github/workflows/essais.yml` fait tourner les épreuves sur les trois systèmes à
chaque poussée. Les trois fichiers d'audit encore ouverts — arithmétique,
difficulté, réservoir — tournent à part, sans bloquer, et leur sortie est
publiée : quiconque ouvre l'exécution voit exactement ce qui reste.

---

## Avertissement

Code de recherche. La preuve de travail memory-hard n'a reçu **aucune
cryptanalyse externe**, et l'audit qui a fermé 21 failles a été mené par les
auteurs du code sur leur propre code. Cela prouve son utilité ; cela ne prouve
rien sur ce qu'il n'a pas trouvé.

Ne confiez à ce logiciel aucune valeur réelle.
