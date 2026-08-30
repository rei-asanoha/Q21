# Publier l'explorateur de chaîne, en HTTPS

Pour rendre `explorateur.q21.dev` consultable par n'importe qui, depuis
n'importe quel navigateur, avec un certificat obtenu et renouvelé tout seul.

Comptez **une heure**, sans se presser. Aucun coût supplémentaire : le serveur
et le domaine existent déjà, et le certificat est gratuit.

Tout se pilote depuis **PowerShell** sur votre PC, comme la mise en place du
serveur.

> **Rappel des deux fenêtres.** Quand l'invite affiche
> `ubuntu@vps-92a55479:~$`, vous êtes **sur le serveur** — j'écris FENÊTRE
> SERVEUR. Quand elle affiche `PS C:\Users\Tibou>`, vous êtes **sur votre PC** —
> j'écris FENÊTRE PC.

---

## Ce qu'on construit, et pourquoi c'est sûr

Trois pièces, et une seule nouveauté par rapport à ce qui tourne déjà :

1. **Le nœud** publie sa page d'explorateur et son API de lecture, mais
   **uniquement sur la boucle locale** du serveur. Rien n'est joignable
   directement de l'extérieur.
2. **Un portier web** (Caddy) écoute sur les ports du web, obtient le
   certificat, le renouvelle seul, et transmet au nœud.
3. **Le pare-feu** ouvre deux ports de plus : 80 et 443.

### Pourquoi ce nœud ne peut pas coûter un centime

Le serveur d'accueil **n'a pas de portefeuille**. Ce n'est pas une précaution
d'usage, c'est vérifié par le programme : `--rpc-public` refuse de démarrer si
un portefeuille est servi, et le message dit pourquoi.

Concrètement, un visiteur qui appelle une méthode qui déplacerait des fonds — ou
même celle qui arrête le nœud — reçoit :

```
methodes de portefeuille desactivees. Elles peuvent deplacer des fonds
et doivent etre demandees explicitement au demarrage.
```

Il ne reste que la lecture : blocs, transactions, émission, difficulté.

### Pourquoi il faut déclarer le nom au nœud

Le nœud refuse par défaut toute requête dont l'en-tête `Host` n'est pas locale.
C'est la défense contre la **reliaison DNS** : sans elle, une page hostile
ouverte dans un onglet quelconque atteindrait un portefeuille par la boucle
locale.

Un explorateur public est l'exact inverse : on l'expose exprès, et les
navigateurs enverront son nom de domaine. On aurait pu réécrire cet en-tête dans
le portier — c'est ce que font beaucoup de tutoriels. Ce serait désactiver un
contrôle de sécurité par un artifice de configuration, sans que le programme
sache qu'il est exposé.

On **déclare** donc le nom au nœud, avec `--rpc-public`. Il l'accepte pour lui
seul : un autre nom, une origine tierce, un `Content-Type` inattendu restent
refusés, et `explorateur.q21.dev.autre-chose.example` aussi.

---

# Étape 1 — Le nom de domaine

Dans l'espace client OVH : **Web Cloud** → **Noms de domaine** → `q21.dev` →
onglet **Zone DNS** → **Ajouter une entrée**.

| Champ | Valeur |
|---|---|
| Type | `A` |
| Sous-domaine | `explorateur` |
| Cible (IPv4) | `92.222.86.135` |
| TTL | par défaut |

Validez, puis vérifiez dans une **FENÊTRE PC** :

```powershell
Resolve-DnsName explorateur.q21.dev -Type A
```

La colonne `IPAddress` doit afficher `92.222.86.135`. Comptez quelques minutes
de propagation.

> **Ne passez pas à la suite tant que cette commande ne répond pas.** Le portier
> demandera le certificat en prouvant qu'il détient ce nom : si le nom ne pointe
> pas encore vers le serveur, la demande échoue et l'autorité impose une pause
> avant le prochain essai.

---

# Étape 2 — Ouvrir les deux ports du web

Dans la **FENÊTRE SERVEUR** :

```bash
sudo ufw allow 80/tcp
```

```bash
sudo ufw allow 443/tcp
```

```bash
sudo ufw status
```

Vous devez maintenant lire quatre lignes : `22`, `80`, `443`, `21121`.

Le port 80 sert uniquement à la vérification du certificat et à rediriger les
visiteurs vers la version chiffrée. Rien n'y est servi en clair.

---

# Étape 3 — Le nœud publie sa page, en local seulement

Le service tourne déjà ; on lui ajoute deux options. Dans la **FENÊTRE
SERVEUR** :

```bash
sudo nano /etc/systemd/system/q21.service
```

Trouvez la ligne qui commence par `ExecStart=` et remplacez-la par celle-ci —
c'est la **seule** modification du fichier :

```ini
ExecStart=/opt/q21/q21 --datadir /opt/q21/donnees node --reseau testnet --listen 21121 --sans-amorces --index-adresses --rpc 127.0.0.1:21080 --rpc-public explorateur.q21.dev
```

Trois ajouts, et rien d'autre :

- `--index-adresses` construit l'index qui permet de **chercher par adresse**
  dans l'explorateur. Il coûte un peu de disque et se reconstruit tout seul.
- `--rpc 127.0.0.1:21080` sert la page et l'API, **sur la boucle locale
  uniquement** : personne ne peut l'atteindre directement.
- `--rpc-public explorateur.q21.dev` déclare le nom sous lequel le nœud accepte
  d'être joint à travers le portier.

**Ctrl + O**, **Entrée**, **Ctrl + X**. Puis :

```bash
sudo systemctl daemon-reload && sudo systemctl restart q21
```

```bash
sudo systemctl status q21
```

Vous devez lire **`active (running)`**. Appuyez sur **q** pour sortir.

Vérifiez que la page se sert bien en local :

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:21080/ -H "Host: explorateur.q21.dev"
```

Doit afficher **`200`**.

> **Si le service refuse de démarrer** avec un message parlant de portefeuille,
> c'est que le dossier `/opt/q21/donnees` en contient un. Ce n'est pas censé
> arriver — le serveur a toujours tourné sans. `sudo journalctl -u q21 -n 30`
> dira quoi.

---

# Étape 4 — Le portier web

C'est lui qui obtient le certificat et le renouvelle sans qu'on y pense.

Dans la **FENÊTRE SERVEUR**, installez-le :

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
```

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
```

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
```

```bash
sudo apt update && sudo apt install -y caddy
```

Puis sa configuration, qui tient en quatre lignes :

```bash
sudo nano /etc/caddy/Caddyfile
```

Effacez tout ce qui s'y trouve (**Ctrl + K** répété efface ligne par ligne) et
mettez exactement ceci :

```
{
	servers {
		timeouts {
			read_header 5s
			read_body   10s
			idle        30s
		}
	}
}

explorateur.q21.dev {
	encode gzip
	request_body {
		max_size 1MB
	}
	@portefeuille path /portefeuille* /bienvenue*
	respond @portefeuille 404
	reverse_proxy 127.0.0.1:21080
}
```

Chaque ligne a une raison, et elle vient de l'audit d'intrusion :

- **`read_header 5s`** — c'est la parade à *Slowloris*. Le nœud traite une
  connexion par fil, soixante-quatre au plus : deux cents connexions ouvertes et
  jamais terminées suffisaient à le rendre indisponible. L'audit l'a reproduit en
  deux lignes. Le portier, lui, est fait pour tenir des milliers de connexions
  lentes, et il n'ouvre une connexion vers le nœud qu'une fois la requête
  complète. C'est la raison d'être de cette architecture.
- **`max_size 1MB`** — la même borne que celle du nœud, appliquée un cran plus
  tôt.
- **Le blocage de `/portefeuille`** — le nœud refuse déjà ces chemins en mode
  public. C'est une deuxième serrure sur la même porte : si un jour quelqu'un
  lance le service sans `--rpc-public`, le portier refusera quand même.

**Ctrl + O**, **Entrée**, **Ctrl + X**. Puis :

```bash
sudo systemctl reload caddy
```

Le certificat est demandé dans la foulée. Pour regarder :

```bash
sudo journalctl -u caddy -n 30 --no-pager
```

Cherchez une ligne contenant `certificate obtained successfully`. Comptez
quelques dizaines de secondes.

> **Pourquoi Caddy et pas les outils habituels.** Il obtient le certificat,
> l'installe et le renouvelle **sans aucune tâche planifiée à écrire**. Un
> certificat qui expire parce qu'un renouvellement automatique a été oublié est
> la panne la plus banale du web, et la plus évitable.

---

# Étape 5 — Vérifier depuis l'extérieur

Dans une **FENÊTRE PC** :

```powershell
Invoke-WebRequest https://explorateur.q21.dev -UseBasicParsing | Select-Object StatusCode
```

Doit afficher **200**.

Puis ouvrez simplement **https://explorateur.q21.dev** dans votre navigateur.
Vous devez voir la hauteur de la chaîne, les derniers blocs, l'émission, la
difficulté — et le cadenas dans la barre d'adresse.

Essayez la recherche : une hauteur de bloc, un identifiant de transaction, une
de vos adresses.

---

# Ce que ce service risque, et ce qu'il ne risque pas

### Ce qu'il ne risque pas

- **Le vol de fonds.** Il n'y a pas de portefeuille, et le programme refuse de
  démarrer en mode public s'il y en avait un.
- **L'arrêt à distance.** La méthode qui arrête le nœud est classée parmi
  celles du portefeuille : elle est refusée.
- **La falsification.** Un explorateur ne fait que montrer ce que le nœud a
  vérifié lui-même. Il ne peut rien inventer.

### Ce qu'il risque

- **D'être saturé.** N'importe qui peut demander des blocs en boucle. Sur un
  réseau d'essai, c'est acceptable et instructif — c'est même une mesure qu'on
  veut. Si cela devient gênant, Caddy sait limiter le débit par adresse.
- **De révéler le rythme du réseau.** C'est le but d'un explorateur.

---

# Surveiller

```bash
sudo systemctl status caddy      # le portier
sudo systemctl status q21        # le nœud
sudo journalctl -u caddy -f      # le web, en direct
sudo journalctl -u q21 -f        # la chaîne, en direct
```

Le certificat se renouvelle seul, environ un mois avant son échéance. Vous n'avez
rien à faire, et rien à noter dans un agenda.

---

# Si quelque chose ne va pas

| Symptôme | Cause la plus probable |
|---|---|
| `Resolve-DnsName` ne répond pas | L'entrée `A` n'est pas propagée. Attendez, puis réessayez |
| Le navigateur affiche une erreur de certificat | La demande a échoué faute de DNS au moment de l'essai. `sudo systemctl reload caddy` relance la demande |
| `502 Bad Gateway` | Le nœud n'écoute pas sur 21080. `sudo systemctl status q21` |
| `403` sur toutes les pages | Le nom passé à `--rpc-public` ne correspond pas à celui du Caddyfile. Ils doivent être identiques, caractère pour caractère |
| Le service q21 refuse de démarrer | Un portefeuille se trouve dans le dossier de données. Le refus est volontaire |
| `Connection refused` depuis l'extérieur | Les ports 80 et 443 ne sont pas ouverts. `sudo ufw status` |
