# Publier l'explorateur de chaîne, en HTTPS

Pour rendre `explorateur.q21.dev` consultable par n'importe qui, depuis n'importe
quel navigateur, avec un certificat obtenu et renouvelé tout seul.

Comptez **une heure et demie**, sans se presser. Aucun coût supplémentaire : le
serveur et le domaine existent déjà, et le certificat est gratuit.

Écrit pour quelqu'un qui n'a jamais publié un site. Chaque commande dit ce
qu'elle fait et ce que vous devez voir en retour.

> **Les deux fenêtres.** Quand l'invite affiche `ubuntu@vps-92a55479:~$`, vous
> êtes **sur le serveur** — j'écris FENÊTRE SERVEUR. Quand elle affiche
> `PS C:\Users\Tibou>`, vous êtes **sur votre PC** — j'écris FENÊTRE PC.

---

## Ce qu'on construit

Trois pièces, et une seule vraiment nouvelle :

1. **Le nœud** sert sa page d'explorateur et son API de lecture, **uniquement
   sur la boucle locale** du serveur. Rien n'est joignable directement.
2. **Un portier web** (Caddy) écoute sur les ports du web, obtient le
   certificat, le renouvelle seul, et transmet au nœud.
3. **Le pare-feu** ouvre deux ports de plus.

```
   navigateur  ──HTTPS 443──▶  Caddy  ──HTTP local──▶  nœud Q21
   (n'importe où)              (le serveur)            (127.0.0.1:21080)
```

Le nœud n'a **pas de portefeuille**, et le programme refuse de démarrer en mode
public s'il en trouvait un. Un visiteur ne peut donc que lire — c'est vérifié
par un audit d'intrusion dont le détail est dans `AUDIT-EXPLORATEUR.md`.

---

# Audit de la couche HTTPS

Ce que j'ai vérifié avant d'écrire ce guide, et les décisions qui en découlent.
Lisez-le une fois : chaque ligne de configuration plus bas vient d'ici.

### Le certificat, et qui a le droit d'en émettre

Le portier obtient un certificat auprès d'une autorité gratuite. Rien
n'empêche, en théorie, **une autre autorité** d'en émettre un pour votre domaine
si quelqu'un l'y trompait. La parade tient en deux lignes de DNS : un
enregistrement **CAA** qui nomme les seules autorités autorisées. C'est à
l'étape 1, et c'est une protection que la plupart des sites n'ont pas.

### Le nom devient public, définitivement

Tout certificat émis est inscrit dans les **journaux publics de transparence**.
Dès la première émission, `explorateur.q21.dev` est connu du monde entier et le
restera. Ce n'est pas un défaut — c'est ce qui permet de détecter un certificat
frauduleux — mais il faut le savoir : **il n'y a pas de sous-domaine discret**.

### Les limites de l'autorité, et pourquoi on ne réessaie pas au hasard

Let's Encrypt compte les échecs : **cinq échecs de validation par heure** pour
un même nom, et **cinq certificats identiques par semaine**. Relancer en boucle
un certificat qui échoue vous bloque pour la journée. D'où l'ordre du guide :
**le DNS d'abord, vérifié, avant de demander quoi que ce soit**.

### La poignée de main, et le post-quantique

Q21 signe ses transactions en ML-DSA-87 pour résister à un ordinateur
quantique. Il serait incohérent que la page qui montre cette chaîne soit servie
derrière une poignée de main que le même ordinateur casserait.

Depuis 2025, les navigateurs et les serveurs récents négocient
**X25519MLKEM768** — un échange de clés hybride qui combine la cryptographie
classique et ML-KEM, la cousine post-quantique de ML-DSA. Caddy 2.10 et
au-delà, compilé avec Go 1.24 ou plus récent, le propose. L'étape 5 vous montre
comment **le vérifier vous-même** plutôt que de me croire.

Si votre version ne le fait pas encore, ce n'est pas une faille : c'est une
élégance qui manque, et elle viendra avec une mise à jour.

### Ce qu'on n'ouvre pas

Le protocole HTTP/3 passe par UDP. On ne l'active pas : ouvrir un port de plus
pour gagner quelques millisecondes n'en vaut pas la peine ici, et **on
n'annonce jamais ce qu'on n'ouvre pas** — un serveur qui propose une voie
bloquée fait perdre du temps à chaque visiteur.

### Les journaux, et la vie privée

Un portier web enregistre par défaut l'adresse de chaque visiteur. Pour un
projet dont la raison d'être est qu'on ne puisse pas relier les paiements entre
eux, tenir la liste de qui consulte la chaîne serait une contradiction. **Les
journaux d'accès sont désactivés.** Les erreurs, elles, restent tracées.

### Ce qui était déjà en place, et que j'ai revérifié

Le nœud envoie déjà les en-têtes qui comptent :
`Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store`. Le portier les transmet sans y toucher. Il manquait
**HSTS**, qu'on ajoute — même si le domaine `.dev` l'impose déjà à l'échelle de
son extension, un site ne doit pas dépendre de la bonne volonté de son voisin.

La compression est activée. Elle n'expose à rien ici : l'attaque qui l'exploite
suppose un secret dans la page et un cookie de session, et cet explorateur n'a
ni l'un ni l'autre.

---

# Étape 0 — Mettre le programme du serveur à jour

**Indispensable.** Le serveur tourne avec une version qui ne connaît pas encore
l'option `--rpc-public`. Sans cette étape, l'étape 3 échouera.

### Sur votre PC

1. Poussez la dernière archive dans votre dossier Q21 avec GitHub Desktop.
2. Attendez que **Actions → Livraison** soit verte.
3. Téléchargez l'artefact **`q21-linux-x86_64.tar.gz`** — celui avec `linux`.

Dans une **FENÊTRE PC**, décompressez (adaptez le chemin) :

```powershell
cd "C:\Users\Tibou\Documents\Q21\Serveur\serveur linux"
```

```powershell
Expand-Archive .\q21-linux-x86_64.tar.gz.zip -DestinationPath .\maj -Force
```

```powershell
cd .\maj
```

```powershell
tar -xzf .\q21-linux-x86_64.tar.gz
```

```powershell
dir
```

Vous devez voir un fichier **`q21`**, sans extension. Envoyez-le :

```powershell
scp .\q21 ubuntu@92.222.86.135:~/q21-neuf
```

### Sur le serveur

Dans la **FENÊTRE SERVEUR** :

```bash
sudo systemctl stop q21
```

```bash
sudo mv ~/q21-neuf /opt/q21/q21 && sudo chown q21:q21 /opt/q21/q21 && sudo chmod +x /opt/q21/q21
```

Vérifiez que la nouvelle option existe **avant** d'aller plus loin :

```bash
/opt/q21/q21 --help | grep rpc-public
```

Vous devez voir la ligne `--rpc-public <nom>`. Si elle n'apparaît pas, le
fichier envoyé n'est pas le bon — reprenez l'étape 0.

```bash
sudo systemctl start q21 && sudo systemctl status q21
```

**`active (running)`** attendu. **q** pour sortir.

---

# Étape 1 — Le nom de domaine, et qui a le droit de le certifier

Dans l'espace client OVH : **Web Cloud** → **Noms de domaine** → `q21.dev` →
onglet **Zone DNS**.

### 1.1 — L'adresse de l'explorateur

**Ajouter une entrée**, type **A** :

| Champ | Valeur |
|---|---|
| Sous-domaine | `explorateur` |
| Cible (IPv4) | `92.222.86.135` |
| TTL | par défaut |

### 1.2 — Les autorités autorisées

Toujours **Ajouter une entrée**, type **CAA**, **deux fois** :

| Sous-domaine | Flags | Tag | Valeur |
|---|---|---|---|
| *(laisser vide)* | `0` | `issue` | `letsencrypt.org` |
| *(laisser vide)* | `0` | `issue` | `sectigo.com` |

Sous-domaine vide = la règle vaut pour `q21.dev` **et tous ses sous-domaines**.

Ces deux lignes disent : *seules ces deux autorités peuvent émettre un
certificat pour ce domaine.* Toute autre demande sera refusée par l'autorité
elle-même. Les deux sont nécessaires : le portier essaie la première et se
rabat sur la seconde en cas d'incident.

> ⚠️ **N'en mettez pas qu'une seule.** Si vous n'autorisez que
> `letsencrypt.org` et que celle-ci a une panne, votre certificat ne se
> renouvellera pas et votre site tombera — un dimanche, comme toujours.

### 1.3 — Vérifier, et ne pas aller plus loin sans cela

Dans une **FENÊTRE PC** :

```powershell
Resolve-DnsName explorateur.q21.dev -Type A
```

La colonne `IPAddress` doit afficher **`92.222.86.135`**.

```powershell
Resolve-DnsName q21.dev -Type CAA
```

Vous devez voir vos deux autorités.

> **Ne passez à l'étape suivante que lorsque ces deux commandes répondent.** Le
> portier prouvera qu'il détient ce nom pour obtenir le certificat : si le nom
> ne pointe pas encore, la demande échoue, et cinq échecs vous bloquent une
> heure. Comptez de quelques minutes à une heure de propagation.

---

# Étape 2 — Ouvrir les deux ports du web

Dans la **FENÊTRE SERVEUR** :

```bash
sudo ufw allow 80/tcp comment 'validation du certificat et redirection'
```

```bash
sudo ufw allow 443/tcp comment 'explorateur HTTPS'
```

```bash
sudo ufw status
```

Vous devez lire quatre règles : `22`, `80`, `443`, `21121` — chacune en deux
exemplaires, IPv4 et IPv6.

Le port 80 ne sert qu'à prouver que vous détenez le nom, et à renvoyer les
visiteurs vers la version chiffrée. **Rien n'y est servi en clair.**

---

# Étape 3 — Le nœud sert sa page, en local seulement

Dans la **FENÊTRE SERVEUR** :

```bash
sudo cp /etc/systemd/system/q21.service /etc/systemd/system/q21.service.avant
```

Cette copie est votre marche arrière. Puis :

```bash
sudo nano /etc/systemd/system/q21.service
```

Trouvez la ligne qui commence par `ExecStart=` et remplacez-la **entièrement**
par celle-ci — c'est la seule modification du fichier :

```ini
ExecStart=/opt/q21/q21 --datadir /opt/q21/donnees node --reseau testnet --listen 21121 --sans-amorces --index-adresses --rpc 127.0.0.1:21080 --rpc-public explorateur.q21.dev
```

Trois ajouts, et rien d'autre :

- **`--index-adresses`** construit l'index qui permet de **chercher par
  adresse** dans l'explorateur.
- **`--rpc 127.0.0.1:21080`** sert la page et l'API **sur la boucle locale
  uniquement**. Personne ne peut l'atteindre directement, et le programme
  refuserait d'écouter ailleurs en mode public.
- **`--rpc-public explorateur.q21.dev`** déclare le nom sous lequel le nœud
  accepte d'être joint à travers le portier.

**Ctrl + O**, **Entrée**, **Ctrl + X**. Puis :

```bash
sudo systemctl daemon-reload && sudo systemctl restart q21
```

```bash
sudo systemctl status q21
```

**`active (running)`** attendu. **q** pour sortir.

Vérifiez que la page se sert bien en local :

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:21080/ -H "Host: explorateur.q21.dev"
```

Doit afficher **`200`**.

Et vérifiez que la page de portefeuille est bien absente :

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:21080/portefeuille -H "Host: explorateur.q21.dev"
```

Doit afficher **`404`**. C'est voulu : un explorateur public n'a pas à montrer
une interface de portefeuille.

> **Si le service refuse de démarrer**, `sudo journalctl -u q21 -n 30` dira
> pourquoi. Pour revenir en arrière :
> `sudo cp /etc/systemd/system/q21.service.avant /etc/systemd/system/q21.service && sudo systemctl daemon-reload && sudo systemctl restart q21`

---

# Étape 4 — Le portier web

### 4.1 — L'installer

Quatre commandes, dans la **FENÊTRE SERVEUR** :

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

Vérifiez la version — elle décide du post-quantique :

```bash
caddy version
```

**2.10 ou plus récent** : la poignée de main hybride sera disponible. Plus
ancien : tout fonctionnera, sans cette élégance.

### 4.2 — Le configurer

```bash
sudo nano /etc/caddy/Caddyfile
```

Effacez tout le contenu existant — maintenez **Ctrl + K** enfoncé jusqu'à ce que
l'écran soit vide — puis collez exactement ceci (**clic droit** pour coller) :

```
{
	servers {
		protocols h1 h2
		timeouts {
			read_header 5s
			read_body   10s
			idle        30s
		}
	}
}

explorateur.q21.dev {
	log {
		output discard
	}

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		-Server
	}

	request_body {
		max_size 1MB
	}

	@interdit path /portefeuille* /bienvenue*
	respond @interdit 404

	encode gzip
	reverse_proxy 127.0.0.1:21080
}
```

**Ctrl + O**, **Entrée**, **Ctrl + X**.

Chaque bloc, et sa raison :

| Ligne | Pourquoi |
|---|---|
| `protocols h1 h2` | N'annonce pas HTTP/3, dont le port UDP n'est pas ouvert |
| `read_header 5s` | Coupe une connexion muette avant qu'elle ne coûte quoi que ce soit — c'est la parade à Slowloris, reproduite pendant l'audit |
| `log { output discard }` | Ne tient pas la liste de qui consulte la chaîne |
| `Strict-Transport-Security` | Interdit au navigateur de revenir en clair, pendant un an |
| `-Server` | N'annonce pas quel logiciel tourne ici |
| `max_size 1MB` | La même borne que celle du nœud, un cran plus tôt |
| `@interdit … 404` | Deuxième serrure sur la porte du portefeuille |

### 4.3 — Vérifier la configuration AVANT de l'appliquer

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

**Si cette commande affiche `Valid configuration`, c'est bon.** Si elle affiche
une erreur, rouvrez le fichier et corrigez — n'appliquez pas.

```bash
sudo systemctl reload caddy
```

Le certificat est demandé dans la foulée. Pour regarder :

```bash
sudo journalctl -u caddy -n 40 --no-pager | grep -i certificate
```

Cherchez **`certificate obtained successfully`**. Comptez quelques dizaines de
secondes.

### 4.4 — Vérifier que la clé privée est bien gardée

```bash
sudo find /var/lib/caddy -name '*.key' -exec ls -l {} \;
```

Chaque ligne doit commencer par **`-rw-------`** — lisible par le seul compte du
portier, et par personne d'autre.

---

# Étape 5 — Vérifier depuis l'extérieur

### 5.1 — Le plus simple

Ouvrez **https://explorateur.q21.dev** dans votre navigateur.

Vous devez voir la hauteur de la chaîne, les derniers blocs, l'émission — et
**un cadenas** dans la barre d'adresse. Essayez la recherche : une hauteur de
bloc, un identifiant de transaction, une de vos adresses.

### 5.2 — La redirection et les en-têtes

Dans une **FENÊTRE PC** :

```powershell
Invoke-WebRequest https://explorateur.q21.dev -UseBasicParsing | Select-Object StatusCode
```

Doit afficher **200**.

```powershell
(Invoke-WebRequest https://explorateur.q21.dev -UseBasicParsing).Headers | Format-List
```

Vous devez y lire `Strict-Transport-Security`, `Content-Security-Policy`,
`X-Frame-Options`, et **aucun** en-tête `Server`.

Et la version en clair doit renvoyer vers la version chiffrée :

```powershell
curl.exe -sI http://explorateur.q21.dev | Select-String "301|Location"
```

### 5.3 — La poignée de main post-quantique

Dans **Chrome ou Edge**, sur `https://explorateur.q21.dev` :

1. **F12** pour ouvrir les outils de développement.
2. Onglet **Security** (ou **Sécurité**).
3. Cliquez sur **View certificate** / la ligne de connexion.

Cherchez la ligne « Key exchange » ou « Échange de clés ». Si elle mentionne
**`X25519MLKEM768`**, la poignée de main est déjà résistante au quantique — la
chaîne et le site qui la montre le sont alors tous les deux.

Si elle affiche `X25519` seul, c'est correct et sûr aujourd'hui ; ce sera
amélioré par une mise à jour du portier.

### 5.4 — Le contrôle indépendant

Allez sur **ssllabs.com/ssltest** et demandez l'analyse de
`explorateur.q21.dev`. Comptez deux minutes. Une note **A** ou **A+** est
attendue.

C'est un avis extérieur, produit par des gens dont c'est le métier. Il vaut
mieux que ma parole.

---

# Étape 6 — Vérifier vous-même que la porte est fermée

Trois commandes dans une **FENÊTRE PC**. Ce sont des extraits de l'audit
d'intrusion : vous les rejouez sur votre propre serveur.

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" https://explorateur.q21.dev/portefeuille
```

→ **404** attendu. Pas d'interface de portefeuille sur le domaine public.

```powershell
curl.exe -s -X POST https://explorateur.q21.dev/rpc -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"arreter\"}"
```

→ **`methodes de portefeuille desactivees`** attendu. Personne ne peut arrêter
votre serveur à distance.

```powershell
curl.exe -s -X POST https://explorateur.q21.dev/rpc -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\"}"
```

→ La hauteur de la chaîne. **La lecture, et rien d'autre.**

---

# Surveiller, au quotidien

```bash
sudo systemctl status caddy      # le portier
sudo systemctl status q21        # le nœud
sudo journalctl -u caddy -f      # le web, en direct
sudo journalctl -u q21 -f        # la chaîne, en direct
```

Pour voir quand le certificat expire :

```bash
echo | openssl s_client -connect explorateur.q21.dev:443 -servername explorateur.q21.dev 2>/dev/null | openssl x509 -noout -dates
```

Il se renouvelle seul, environ un mois avant l'échéance. **Vous n'avez rien à
faire, et rien à noter dans un agenda** — c'est précisément pourquoi ce portier
a été choisi : le certificat expiré faute de renouvellement automatique oublié
est la panne la plus banale du web.

---

# Ce que ce service risque, et ce qu'il ne risque pas

### Ce qu'il ne risque pas

- **Le vol de fonds.** Pas de portefeuille, et le programme refuse de démarrer
  en mode public s'il en trouvait un.
- **L'arrêt à distance.** La méthode qui arrête le nœud est classée parmi
  celles du portefeuille : refusée.
- **La falsification.** Un explorateur ne montre que ce que le nœud a vérifié
  lui-même. Il ne peut rien inventer.
- **Un certificat émis par un tiers.** Les enregistrements CAA de l'étape 1 le
  refusent à la source.

### Ce qu'il risque

- **D'être saturé par le volume.** N'importe qui peut demander des blocs en
  boucle. Sur un réseau d'essai c'est acceptable, et c'est même une mesure
  qu'on veut. Si cela devient gênant, le portier sait limiter le débit par
  adresse.
- **De révéler le rythme du réseau.** C'est le but d'un explorateur.

---

# Si quelque chose ne va pas

| Symptôme | Cause la plus probable |
|---|---|
| `--rpc-public` inconnu au démarrage | L'étape 0 n'a pas été faite : le programme du serveur est l'ancien |
| `Resolve-DnsName` ne répond pas | L'entrée `A` n'est pas propagée. Attendez, n'insistez pas |
| Erreur de certificat dans le navigateur | La demande a échoué faute de DNS au bon moment. `sudo systemctl reload caddy` la relance — **une seule fois**, puis attendez une heure |
| `502 Bad Gateway` | Le nœud n'écoute pas sur 21080. `sudo systemctl status q21` |
| `403` sur toutes les pages | Le nom de `--rpc-public` et celui du Caddyfile diffèrent. Ils doivent être identiques, caractère pour caractère |
| Le service q21 refuse de démarrer | Un portefeuille se trouve dans le dossier de données. Le refus est volontaire |
| `Connection refused` de l'extérieur | Les ports 80 et 443 ne sont pas ouverts. `sudo ufw status` |
| `caddy validate` refuse le fichier | Une accolade ou une tabulation manque. Le message donne la ligne |
| La note SSL Labs est basse | Notez ce qu'elle reproche et dites-le-moi : c'est un signal, pas une fatalité |

---

# Revenir en arrière, si vous le voulez

Rien de ce guide n'est irréversible :

```bash
sudo systemctl stop caddy && sudo systemctl disable caddy
```

```bash
sudo cp /etc/systemd/system/q21.service.avant /etc/systemd/system/q21.service
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart q21
```

```bash
sudo ufw delete allow 80/tcp && sudo ufw delete allow 443/tcp
```

Le serveur d'accueil retrouve exactement son état d'avant, et le réseau Q21
continue sans s'en apercevoir.
