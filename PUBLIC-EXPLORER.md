# Publishing the chain explorer, over HTTPS

To make `explorer.example.org` viewable by anyone, from any browser, with a
certificate obtained and renewed automatically.

> 📌 **`example.org` is an example**, reserved for that purpose by the
> standard, and leads nowhere. Throughout this guide, replace it with your own
> domain. The guide names no real domain: a name written into public
> documentation becomes a permanent dependency on whoever holds it.

Allow **an hour and a half**, without rushing. No extra cost: the server and
the domain already exist, and the certificate is free.

Written for someone who has never published a website. Each command says what
it does and what you should see in return.

> **The two windows.** When the prompt shows `ubuntu@vps-XXXXXXXX:~$`, you are
> **on the server** — I write SERVER WINDOW. When it shows
> `PS C:\Users\YourName>`, you are **on your PC** — I write PC WINDOW.

---

## What we are building

Three pieces, and only one that is really new:

1. **The node** serves its explorer page and its read API, **only on the
   server's loopback**. Nothing is directly reachable.
2. **A reverse proxy** (Caddy) listens on the web ports, obtains the
   certificate, renews it on its own, and forwards to the node.
3. **The firewall** opens two more ports.

```
   browser     ──HTTPS 443──▶  Caddy  ──local HTTP──▶  Q21 node
   (anywhere)                  (the server)            (127.0.0.1:21080)
```

The node has **no wallet**, and the program refuses to start in public mode if
it finds one. A visitor can therefore only read — this was checked by a
penetration audit, detailed in [AUDIT-EXPLORER.md](AUDIT-EXPLORER.md).

---

# Audit of the HTTPS layer

What I checked before writing this guide, and the decisions that follow from
it. Read it once: every configuration line further down comes from here.

### The certificate, and who is allowed to issue one

The reverse proxy obtains a certificate from a free authority. In theory,
nothing prevents **another authority** from issuing one for your domain if
someone tricked it into doing so. The countermeasure fits in two DNS lines: a
**CAA** record that names the only authorities allowed. It is in step 1, and
it is a protection most websites do not have.

### The name becomes public, permanently

Every certificate issued is recorded in the public **Certificate Transparency
logs**. From the first issuance, `explorer.example.org` is known to the whole
world and will remain so. This is not a defect — it is what makes it possible
to detect a fraudulent certificate — but you need to know it: **there is no
such thing as a discreet subdomain**.

### The authority's limits, and why you do not retry at random

Let's Encrypt counts failures: **five validation failures per hour** for the
same name, and **five identical certificates per week**. Retrying a failing
certificate in a loop locks you out for the day. Hence the order of this
guide: **DNS first, checked, before asking for anything**.

### The handshake, and post-quantum cryptography

Q21 signs its transactions with ML-DSA-87 to resist a quantum computer. It
would be inconsistent for the page that shows this chain to be served behind a
handshake that the same computer would break.

Since 2025, recent browsers and servers negotiate **X25519MLKEM768** — a hybrid
key exchange that combines classical cryptography and ML-KEM, the post-quantum
cousin of ML-DSA. Caddy 2.10 and later, built with Go 1.24 or newer, offers
it. Step 5 shows you how to **check it yourself** rather than take my word for
it.

If your version does not do it yet, this is not a vulnerability: it is a
refinement that is missing, and it will come with an update.

### What we do not open

The HTTP/3 protocol runs over UDP. We do not enable it: opening one more port
to gain a few milliseconds is not worth it here, and **you never advertise
what you do not open** — a server that offers a blocked path wastes every
visitor's time.

### Logs, and privacy

A web reverse proxy records every visitor's address by default. For a project
whose reason for being is that payments cannot be linked to one another,
keeping a list of who looks at the chain would be a contradiction. **Access
logs are disabled.** Errors, however, are still logged.

### What was already in place, and that I checked again

The node already sends the headers that matter:
`Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store`. The reverse proxy passes them on untouched. What
was missing was **HSTS**, which we add — even if the `.dev` domain already
enforces it across its whole extension, a site should not depend on the
goodwill of its neighbor.

Compression is enabled. It exposes nothing here: the attack that exploits it
assumes a secret in the page and a session cookie, and this explorer has
neither.

---

# Step 0 — Update the server's program

**Required.** The server is running a version that does not yet know the
`--rpc-public` option. Without this step, step 3 will fail.

### On your PC

1. Push the latest archive into your Q21 folder with GitHub Desktop.
2. Wait until **Actions → Release** is green.
3. Download **two** artifacts: **`q21-linux-x86_64.tar.gz`** — the one with
   `linux` — and **`SHA256SUMS-signed`**.

In a **PC WINDOW**, open the two GitHub `.zip` files — and only those: the
`.tar.gz` they contain stays closed, it is what the signature covers (adjust
the path):

```powershell
cd "C:\Users\YourName\Documents\Q21\Server\linux server"
```

```powershell
Expand-Archive .\q21-linux-x86_64.tar.gz.zip -DestinationPath .\update -Force; Expand-Archive .\SHA256SUMS-signed.zip -DestinationPath .\update -Force
```

```powershell
cd .\update; dir
```

You should see **three** files: `q21-linux-x86_64.tar.gz`, `SHA256SUMS`,
`SHA256SUMS.minisig`. Send them:

```powershell
scp .\q21-linux-x86_64.tar.gz .\SHA256SUMS .\SHA256SUMS.minisig ubuntu@SERVER-IPV4-ADDRESS:~/
```

### On the server

In the **SERVER WINDOW**, check the signature **before** installing
(`sudo apt install -y minisign` the first time; `RW…` is the public key from
the README):

```bash
minisign -Vm ~/SHA256SUMS -P 'RW…' && cd ~ && sha256sum -c SHA256SUMS --ignore-missing
```

Expected: `Signature and comment signature verified`, a comment
`Trusted comment: Q21 main <commit hash> -- Rei Asanoha`, and
`q21-linux-x86_64.tar.gz: OK`. ⛔ A branch other than `main`, a commit hash
other than that of the run you started, a red run: **do not install** (see
[SIGNING.md](SIGNING.md)).

```bash
tar -xzf ~/q21-linux-x86_64.tar.gz && sudo systemctl stop q21
```

```bash
sudo install -o root -g root -m 0755 ~/q21 /opt/q21/q21
```

The program belongs to `root`, not to the account that runs it: a service
that can rewrite its own executable no longer has a barrier between an
execution flaw and persistence.

Check that the new option exists **before** going any further:

```bash
/opt/q21/q21 --help | grep rpc-public
```

You should see the line `--rpc-public <name>`. If it does not appear, the file
you sent is not the right one — go back to step 0.

```bash
sudo systemctl start q21 && sudo systemctl status q21
```

**`active (running)`** expected. **q** to exit.

---

# Step 1 — The domain name, and who is allowed to certify it

In the OVH customer area: **Web Cloud** → **Domain names** → `example.org` →
**DNS zone** tab.

### 1.1 — The explorer's address

**Add an entry**, type **A**:

| Field | Value |
|---|---|
| Subdomain | `explorer` |
| Target (IPv4) | `SERVER-IPV4-ADDRESS` |
| TTL | default |

### 1.2 — The authorities allowed

Again **Add an entry**, type **CAA**, **twice**:

| Subdomain | Flags | Tag | Value |
|---|---|---|---|
| *(leave empty)* | `0` | `issue` | `letsencrypt.org` |
| *(leave empty)* | `0` | `issue` | `sectigo.com` |

Empty subdomain = the rule applies to `example.org` **and all its
subdomains**.

These two lines say: *only these two authorities may issue a certificate for
this domain.* Any other request will be refused by the authority itself. Both
are needed: the reverse proxy tries the first one and falls back to the second
if there is an incident.

> ⚠️ **Do not put only one.** If you allow only `letsencrypt.org` and it has
> an outage, your certificate will not renew and your site will go down — on
> a Sunday, as always.

### 1.3 — Check, and go no further without it

In a **PC WINDOW**:

```powershell
Resolve-DnsName explorer.example.org -Type A
```

The `IPAddress` column must display **`SERVER-IPV4-ADDRESS`**.

```powershell
Resolve-DnsName example.org -Type CAA
```

You should see your two authorities.

> **Only move on to the next step once both commands answer.** The reverse
> proxy will prove that it holds this name to obtain the certificate: if the
> name does not point to the server yet, the request fails, and five failures
> lock you out for an hour. Allow from a few minutes to an hour for
> propagation.

---

# Step 2 — Open the two web ports

In the **SERVER WINDOW**:

```bash
sudo ufw allow 80/tcp comment 'certificate validation and redirect'
```

```bash
sudo ufw allow 443/tcp comment 'HTTPS explorer'
```

```bash
sudo ufw status
```

You should read four rules: `22`, `80`, `443`, `21121` — each one twice, IPv4
and IPv6.

Port 80 only serves to prove that you hold the name, and to redirect visitors
to the encrypted version. **Nothing is served over it in the clear.**

---

# Step 3 — The node serves its page, locally only

In the **SERVER WINDOW**:

```bash
sudo cp /etc/systemd/system/q21.service /etc/systemd/system/q21.service.before
```

This copy is your way back. Then:

```bash
sudo nano /etc/systemd/system/q21.service
```

Find the line that starts with `ExecStart=` and replace it **entirely** with
this one — it is the only change to the file:

```ini
ExecStart=/opt/q21/q21 --datadir /opt/q21/data node --network testnet --listen 21121 --no-bootstrap --address-index --rpc 127.0.0.1:21080 --rpc-public explorer.example.org
```

Three additions, and nothing else:

- **`--address-index`** builds the index that makes it possible to **search by
  address** in the explorer.
- **`--rpc 127.0.0.1:21080`** serves the page and the API **on the loopback
  only**. No one can reach it directly, and the program would refuse to
  listen anywhere else in public mode.
- **`--rpc-public explorer.example.org`** declares the name under which the
  node agrees to be reached through the reverse proxy.

**Ctrl + O**, **Enter**, **Ctrl + X**. Then:

```bash
sudo systemctl daemon-reload && sudo systemctl restart q21
```

```bash
sudo systemctl status q21
```

**`active (running)`** expected. **q** to exit.

Check that the page is indeed served locally:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:21080/ -H "Host: explorer.example.org"
```

Must display **`200`**.

And check that the wallet page is indeed absent:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:21080/wallet -H "Host: explorer.example.org"
```

Must display **`404`**. This is intended: a public explorer has no business
showing a wallet interface.

> **If the service refuses to start**, `sudo journalctl -u q21 -n 30` will say
> why. To go back:
> `sudo cp /etc/systemd/system/q21.service.before /etc/systemd/system/q21.service && sudo systemctl daemon-reload && sudo systemctl restart q21`

---

# Step 4 — The reverse proxy

### 4.1 — Install it

Four commands, in the **SERVER WINDOW**:

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

Check the version — it determines post-quantum support:

```bash
caddy version
```

**2.10 or newer**: the hybrid handshake will be available. Older: everything
will work, without that refinement.

### 4.2 — Configure it

```bash
sudo nano /etc/caddy/Caddyfile
```

Delete all the existing content — hold **Ctrl + K** down until the screen is
empty — then paste exactly this (**right-click** to paste):

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

explorer.example.org {
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

	@blocked path /wallet* /welcome*
	respond @blocked 404

	encode gzip
	reverse_proxy 127.0.0.1:21080
}
```

**Ctrl + O**, **Enter**, **Ctrl + X**.

Each block, and why it is there:

| Line | Why |
|---|---|
| `protocols h1 h2` | Does not advertise HTTP/3, whose UDP port is not open |
| `read_header 5s` | Cuts a silent connection before it costs anything — this is the countermeasure to Slowloris, reproduced during the audit |
| `log { output discard }` | Does not keep a list of who looks at the chain |
| `Strict-Transport-Security` | Forbids the browser from coming back in the clear, for one year |
| `-Server` | Does not advertise which software runs here |
| `max_size 1MB` | The same limit as the node's, one step earlier |
| `@blocked … 404` | A second lock on the wallet's door |

The reverse proxy passes each visitor's address to the node in the
`X-Forwarded-For` header — that is its default behavior, and it erases
whatever a visitor might have written there themselves. The node uses it to
give **each address** its own search budget (see "What the node bounds on its
own", further down). Do not put a `header_up X-Forwarded-For` in this block:
you would replace that address with a fixed value, and all visitors would
become a single client again.

The node only trusts **the last hop**: the last address in the header, the one
Caddy adds itself. If you place a second intermediary in front of Caddy (a
CDN, for example), that last address becomes the CDN's, and all visitors then
share a single budget — the counting degrades, it does not become forgeable.
In that setup, it is up to Caddy to rewrite the header with the address the CDN
passes to it (`header_up X-Forwarded-For {header.CF-Connecting-IP}` at
Cloudflare, the equivalent elsewhere), and to accept only connections coming
from the CDN's addresses. The node itself will never guess how many hops are
trusted: every hop taken at its word is a hop a visitor can imitate.

### 4.2a — Limit connections per address

The Caddyfile above limits neither the number of connections nor the rate of
an address. The node behind it only accepts sixty-four connections at a time,
one per thread: a single machine that opens that many, slowly, leaves the
other visitors with a `503`. The node's search budget bounds what an address
can make it **compute**; it does not bound what it can make it **wait for**.
That limit is set one step earlier.

Caddy as installed by the package **does not** have rate limiting: the
`rate_limit` directive comes from a third-party module, absent from the
standard binary. Two ways, from the simplest to the finest.

**Way A — the firewall, without installing anything.** `ufw` accepts rules
added by hand in `/etc/ufw/before.rules`. They count connections per source
address and new connections per minute, and have no idea what goes through
them — which is exactly the level at which you want to stop a connection
flood.

```bash
sudo cp /etc/ufw/before.rules /etc/ufw/before.rules.before && sudo nano /etc/ufw/before.rules
```

Find the line `# End required lines` and add **right after it**:

```
# Q21 — explorer: at most 32 open connections per address,
# and at most 60 new connections per minute per address (burst of 120).
-A ufw-before-input -p tcp --dport 443 --syn -m connlimit --connlimit-above 32 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
-A ufw-before-input -p tcp --dport 443 --syn -m hashlimit --hashlimit-name q21-https --hashlimit-mode srcip --hashlimit-above 60/minute --hashlimit-burst 120 -j DROP
```

**Ctrl + O**, **Enter**, **Ctrl + X**. Then the same for IPv6, where you count
per `/64` block — that is what an internet provider assigns to a subscriber,
and counting each of its addresses separately would limit nothing:

```bash
sudo cp /etc/ufw/before6.rules /etc/ufw/before6.rules.before && sudo nano /etc/ufw/before6.rules
```

After `# End required lines`:

```
# Q21 — explorer, IPv6: same limits, per /64 block.
-A ufw6-before-input -p tcp --dport 443 --syn -m connlimit --connlimit-above 32 --connlimit-mask 64 -j REJECT --reject-with tcp-reset
-A ufw6-before-input -p tcp --dport 443 --syn -m hashlimit --hashlimit-name q21-https6 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-above 60/minute --hashlimit-burst 120 -j DROP
```

Then:

```bash
sudo ufw reload && sudo ufw status verbose
```

If `ufw reload` refuses, a line was copied wrong: put the backup back
(`sudo cp /etc/ufw/before.rules.before /etc/ufw/before.rules`) and start over.
The figures are generous for a human — a browser opens a handful of
connections, never thirty — and tight for a program that opens hundreds.

**Way B — the `rate_limit` module, to count requests.** The firewall counts
connections; with HTTP/2, a single connection carries thousands of requests.
To limit **requests** per address, you need the `caddy-ratelimit` module, so a
Caddy binary built with it. It is finer, and more work: to be done once way A
is in place, not instead of it.

Building the binary requires the `xcaddy` tool and a Go toolchain, **on
another machine** preferably — the host server does not need a compiler. Then,
on the server, the Debian package provides for substituting a binary without
breaking updates:

```bash
xcaddy build --with github.com/mholt/caddy-ratelimit
```

```bash
sudo dpkg-divert --divert /usr/bin/caddy.default --rename /usr/bin/caddy
sudo mv ./caddy /usr/bin/caddy.custom
sudo update-alternatives --install /usr/bin/caddy caddy /usr/bin/caddy.default 10
sudo update-alternatives --install /usr/bin/caddy caddy /usr/bin/caddy.custom 50
```

And in the Caddyfile — the directive has no default order, so you have to give
it one in the global block, then place it in the site:

```
{
	order rate_limit before basicauth
	servers {
		protocols h1 h2
		timeouts {
			read_header 5s
			read_body   10s
			idle        30s
		}
	}
}

explorer.example.org {
	rate_limit {
		zone visitors {
			key    {client_ip}
			events 120
			window 1m
		}
	}
	# … the rest of the block, unchanged
}
```

A hundred and twenty requests per minute per address: an explorer that
refreshes every five seconds makes a dozen. Beyond that, the reverse proxy
answers `429` without disturbing the node. Check with `caddy version` that the
active binary is indeed yours, and with `sudo caddy validate` that the
directive is recognized — if it is not, the standard binary is still running.

### 4.3 — Check the configuration BEFORE applying it

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

**If this command displays `Valid configuration`, all is well.** If it
displays an error, reopen the file and fix it — do not apply.

```bash
sudo systemctl reload caddy
```

The certificate is requested right away. To watch:

```bash
sudo journalctl -u caddy -n 40 --no-pager | grep -i certificate
```

Look for **`certificate obtained successfully`**. Allow a few dozen seconds.

### 4.4 — Check that the private key is well guarded

```bash
sudo find /var/lib/caddy -name '*.key' -exec ls -l {} \;
```

Each line must start with **`-rw-------`** — readable by the reverse proxy's
account alone, and by no one else.

---

# Step 5 — Check from the outside

### 5.1 — The simplest check

Open **https://explorer.example.org** in your browser.

You should see the chain height, the latest blocks, the emission — and **a
padlock** in the address bar. Try the search: a block height, a transaction
identifier, one of your addresses.

### 5.2 — The redirect and the headers

In a **PC WINDOW**:

```powershell
Invoke-WebRequest https://explorer.example.org -UseBasicParsing | Select-Object StatusCode
```

Must display **200**.

```powershell
(Invoke-WebRequest https://explorer.example.org -UseBasicParsing).Headers | Format-List
```

You should read `Strict-Transport-Security`, `Content-Security-Policy`,
`X-Frame-Options`, and **no** `Server` header.

And the plain-text version must redirect to the encrypted one:

```powershell
curl.exe -sI http://explorer.example.org | Select-String "301|Location"
```

### 5.3 — The post-quantum handshake

In **Chrome or Edge**, on `https://explorer.example.org`:

1. **F12** to open the developer tools.
2. The **Security** tab.
3. Click **View certificate** / the connection line.

Look for the "Key exchange" line. If it mentions **`X25519MLKEM768`**, the
handshake is already quantum-resistant — the chain and the site that shows it
are then both resistant.

If it shows `X25519` alone, that is correct and safe today; it will be
improved by an update of the reverse proxy.

### 5.4 — The independent check

Go to **ssllabs.com/ssltest** and request the analysis of
`explorer.example.org`. Allow two minutes. A grade of **A** or **A+** is
expected.

It is an outside opinion, produced by people whose job this is. It is worth
more than my word.

---

# Step 6 — Check for yourself that the door is closed

Three commands in a **PC WINDOW**. They are excerpts from the penetration
audit: you replay them against your own server.

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" https://explorer.example.org/wallet
```

→ **404** expected. No wallet interface on the public domain.

```powershell
curl.exe -s -X POST https://explorer.example.org/rpc -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stop\"}"
```

→ **`wallet methods disabled`** expected. No one can stop your server
remotely.

```powershell
curl.exe -s -X POST https://explorer.example.org/rpc -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\"}"
```

→ The chain height. **Reading, and nothing else.**

---

# Monitoring, day to day

```bash
sudo systemctl status caddy      # the reverse proxy
sudo systemctl status q21        # the node
sudo journalctl -u caddy -f      # the web, live
sudo journalctl -u q21 -f        # the chain, live
```

To see when the certificate expires:

```bash
echo | openssl s_client -connect explorer.example.org:443 -servername explorer.example.org 2>/dev/null | openssl x509 -noout -dates
```

It renews on its own, about a month before expiry. **You have nothing to do,
and nothing to note in a calendar** — that is precisely why this reverse proxy
was chosen: a certificate that expired because someone forgot to renew it is
the most common outage on the web.

---

# What this service risks, and what it does not

### What it does not risk

- **Theft of funds.** No wallet, and the program refuses to start in public
  mode if it finds one.
- **Remote shutdown.** The method that stops the node is classified among the
  wallet methods: refused.
- **Falsification.** An explorer only shows what the node has verified itself.
  It cannot invent anything.
- **A certificate issued by a third party.** The CAA records of step 1 refuse
  it at the source.

### What it risks

- **Being saturated by volume.** Anyone can request blocks in a loop. On a
  testnet that is acceptable, and it is even a measurement we want. If it
  becomes a nuisance, the reverse proxy can limit the rate per address.
- **Revealing the network's pace.** That is what an explorer is for.

---

# If something goes wrong

| Symptom | Most likely cause |
|---|---|
| `--rpc-public` unknown at startup | Step 0 was not done: the server's program is the old one |
| `Resolve-DnsName` does not answer | The `A` entry has not propagated. Wait, do not insist |
| Certificate error in the browser | The request failed because DNS was not ready in time. `sudo systemctl reload caddy` retries it — **only once**, then wait an hour |
| `502 Bad Gateway` | The node is not listening on 21080. `sudo systemctl status q21` |
| `403` on every page | The `--rpc-public` name and the Caddyfile name differ. They must be identical, character for character |
| The q21 service refuses to start | A wallet is in the data directory. The refusal is intentional |
| `Connection refused` from the outside | Ports 80 and 443 are not open. `sudo ufw status` |
| `caddy validate` rejects the file | A brace or a tab is missing. The message gives the line |
| The SSL Labs grade is low | Note what it complains about and tell me: it is a signal, not a fate |

---

# Going back, if you want to

Nothing in this guide is irreversible:

```bash
sudo systemctl stop caddy && sudo systemctl disable caddy
```

```bash
sudo cp /etc/systemd/system/q21.service.before /etc/systemd/system/q21.service
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart q21
```

```bash
sudo ufw delete allow 80/tcp && sudo ufw delete allow 443/tcp
```

The host server returns exactly to its previous state, and the Q21 network
carries on without noticing.

---

## What the node bounds on its own

Searches without an index result — an amount, an unknown transaction, an
address without an index — reread up to two thousand blocks under the chain
lock. Exposed without a token, they were the cheapest way to freeze the entry
point: a visitor looping over nonexistent identifiers. In public mode, the
node grants a **scan budget**, and beyond it answers "try again in a minute",
without ceasing to validate.

This budget is **per visitor address**: a reserve of thirty, then twelve per
minute, for each address the reverse proxy passes in `X-Forwarded-For` (a
`/64` block counts as one address in IPv6). The first version kept only one
count for everyone: a single visitor in a loop emptied it, and all the others
read "try again in a minute". A global safety net remains — a hundred and
fifty at once, then sixty per minute, all addresses combined — so that a
thousand coordinated addresses cannot do to the lock what a single one no
longer can. The node only trusts this header on a connection coming from the
loopback, that is, from the reverse proxy: a visitor who wrote it themselves
would not change their budget.

What this budget does not do: bound the number of connections or requests of
an address. That is the purpose of step 4.2a.
