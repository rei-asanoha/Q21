# Setting up the Q21 entry point, step by step

For someone who has never administered a server. Allow an hour and a half,
without rushing, and about **€4 a month** plus around ten euros a year for the
domain name.

Everything is driven from the **Mac's Terminal**. Nothing to install.

> **Would you rather drive it from Windows?**
> [SERVER-WINDOWS.md](SERVER-WINDOWS.md) follows the same path from start to
> finish, from PowerShell. Follow one **or** the other, not both: what differs
> is precisely what you type on your own machine.

---

## What we are building, and why it is safe

A small rented machine, always on, that does a single thing: **provide a first
contact** to the people joining the network.

Three properties to keep in mind, because they explain every decision that
follows:

1. **This server keeps no key.** It runs without a wallet. There is nothing to
   steal on it — no seed, no passphrase, no funds.
2. **A single port is open to the world**, the one for the Q21 protocol.
   Everything else is closed, including the query interface.
3. **You never log in with a password.** Only with a cryptographic key that
   stays on your Mac.

A server that holds nothing and exposes only one door is a server whose
compromise costs almost nothing. That is the goal.

---

# Step 1 — Create your access key

**On the Mac, and before creating the server.** The order matters: the server
will be born with your key already installed, and so will never have had a
password to guess.

Open **Terminal** (⌘ + Space, type `Terminal`).

```bash
ssh-keygen -t ed25519 -C "q21-bootstrap"
```

Three questions:

| Question | What to answer |
|---|---|
| `Enter file in which to save the key` | **Return** — the default location is the right one |
| `Enter passphrase` | **Set one**, and write it down. It protects the file if the Mac is stolen |
| `Enter same passphrase again` | The same one |

You get two files:

- `~/.ssh/id_ed25519` — the **private** key. It never leaves your Mac.
- `~/.ssh/id_ed25519.pub` — the **public** key. That one can be given out.

Display the public one so you can copy it:

```bash
cat ~/.ssh/id_ed25519.pub
```

A line appears, starting with `ssh-ed25519` and ending with `q21-bootstrap`.
**Select all of it and copy it.**

> ⚠️ **Never share the file without `.pub`.** That is the private key. Whoever
> gets it gets into your server. The public one, on the other hand, can be
> shown anywhere without the slightest risk — that is the whole point of it.

---

# Step 2 — Create the Hetzner account

Go to **console.hetzner.com** → **Sign up**.

Email address, password, email confirmation. Hetzner often asks for identity
verification at the first payment: a bank card, sometimes an ID document. That
is normal with all European hosting providers.

Once logged in, create a **project** — the **New Project** button. Name it
`q21`. A project is simply a drawer that groups your machines together.

---

# Step 3 — Upload your public key

In the project: left menu → **Security** → **SSH Keys** tab →
**Add SSH Key**.

Paste the line copied in step 1. Give it a name: `mac`.

Hetzner displays a *fingerprint* — a string of characters. That is normal: it
is a summary of your key, not a secret.

---

# Step 4 — Create the server

Left menu → **Servers** → **Add Server**.

### Location

**Falkenstein**, **Nuremberg** or **Helsinki**. Pick the one closest to you;
for a testnet, it makes no difference.

### Image

**Ubuntu 24.04**.

### Type ⚠️ — where people get it wrong

Choose a model whose name starts with **CX** or **CPX**.

> **Whatever you do, do not pick a CAX model.** It is the cheapest line, and it
> is a trap here: CAX machines have **ARM** processors, whereas the program
> built by GitHub is compiled for **x86_64**. On a CAX, `q21` would refuse to
> start with an incomprehensible message (`cannot execute binary file`).

The smallest CX is more than enough: 2 cores, 4 GB of memory, 40 GB of disk.

### Networking

Leave **IPv4** and **IPv6** checked.

### SSH Keys

**Check the `mac` key** uploaded in step 3.

> This is what ensures that no root password will ever be created or sent by
> email. If you forget this box, Hetzner will send you a password by
> message — exactly what we want to avoid.

### Name

`q21-bootstrap`.

Click **Create & Buy now**. A minute later, the machine exists.

**Write down its IPv4 address**, shown in the list. It looks like
`5.75.xxx.xxx`. In what follows, replace `YOUR_IP` with this value.

---

# Step 5 — The first connection

In the Mac's Terminal:

```bash
ssh root@YOUR_IP
```

**First question:**

```
The authenticity of host '5.75.xxx.xxx' can't be established.
ED25519 key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Type `yes`, Return. Your Mac is recording the server's identity so that it
never has to ask again — and so that it can warn you if it ever changed.

**Second question:** your key's passphrase. macOS offers to remember it in the
keychain — accept, it is safe.

You should land on an Ubuntu banner and a prompt ending in `#`.
**You are on the server.**

---

# Step 6 — Update, and create the accounts

Still in this window, on the server.

### Updates

```bash
apt update && apt upgrade -y
```

Then automatic security fixes — a server that you forget to update is the
leading cause of compromise:

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

Answer **Yes** to the question asked.

### Your administration account

You do not administer as `root` day to day.

```bash
adduser --gecos "" q21op
```

It asks for a password — **choose a strong one and write it down**. It will
not be used to log in (you log in with the key), but to confirm administration
commands.

Give it administration rights, and copy your key over to it:

```bash
usermod -aG sudo q21op
rsync --archive --chown=q21op:q21op ~/.ssh /home/q21op/
```

### The service account

The Q21 program will run under its own account, **with no password, no shell,
and unable to log in**:

```bash
adduser --system --group --home /opt/q21 --shell /usr/sbin/nologin q21
```

---

# Step 7 — Close the service door ⚠️

This is the step where you can lock yourself out. **Follow the order exactly.**

### 7.1 — First check that the new account works

**Open a SECOND Terminal window** (⌘ + N). Do not close the first one.

In the new one:

```bash
ssh q21op@YOUR_IP
sudo -v
```

It asks for your key's passphrase, then for the `q21op` password for `sudo`.
If both go through, continue. **If either one fails, stop here** and fix it
from the first window, still open as `root`.

### 7.2 — Forbid passwords and root login

In the second window, as `q21op`:

```bash
sudo nano /etc/ssh/sshd_config.d/99-q21.conf
```

A text editor opens, empty. Type these three lines:

```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
```

To save: **Ctrl + O**, Return, then **Ctrl + X**.

### 7.3 — Check the syntax BEFORE restarting

```bash
sudo sshd -t
```

**If this command prints nothing, all is well.** If it prints an error,
reopen the file and fix it — do not restart.

```bash
sudo systemctl restart ssh
```

### 7.4 — Check from a THIRD window

```bash
ssh q21op@YOUR_IP
```

Must go through. And:

```bash
ssh root@YOUR_IP
```

Must be **refused**. That is the expected result.

Only now can you close the windows.

> **If you lock yourself out anyway:** Hetzner provides a web console. On the
> server's page, the **Console** button at the top right. It gives screen and
> keyboard access directly to the machine, without going through the network.
> So you can never be permanently locked out.

---

# Step 8 — The firewall

We use **Hetzner's** firewall, not the machine's. The reason: it is
**outside** the server. A mistake can be fixed from the browser, and cannot
lock you in.

Left menu → **Firewalls** → **Create Firewall**.

Name: `q21-bootstrap`.

**Inbound rules** — two rules, and only two:

| Protocol | Port | Source | What it is for |
|---|---|---|---|
| TCP | `22` | `Any IPv4`, `Any IPv6` | Your administration access |
| TCP | `21121` | `Any IPv4`, `Any IPv6` | The Q21 protocol |

**Outbound rules**: leave everything allowed. The node must be able to reach
out to its peers.

At the bottom, in the **Apply to** section: check the `q21-bootstrap` server.
Then **Create Firewall**.

> **The query interface port is never opened.** The program in fact refuses to
> serve it off the machine without a token. To look at it remotely, you go
> through a tunnel — see the end of this document.

---

# Step 8a — Limit login attempts

The firewall says *who* may knock on the door; it does not say *how many
times*. A password or a key can be guessed through persistence, and a public
server receives thousands of attempts a day. `fail2ban` reads the logs and
bans, for one hour, any address that fails five times.

```bash
sudo apt install -y fail2ban
```

```bash
sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF
```

```bash
sudo systemctl enable --now fail2ban && sudo fail2ban-client status sshd
```

**You should see** `Status for the jail: sshd` with a count of banned
addresses (zero at first).

> If this server also hosts mail (Postfix, Dovecot), add to `jail.local` the
> two sections `[postfix]` and `[dovecot]` with `enabled = true`: the mailbox
> password is then also protected against guessing — and it is that password
> which, through account recovery, controls everything that depends on your
> address.

---

# Step 9 — Send the program

The file is downloaded **on the Mac** (GitHub requires you to be logged in,
which the server cannot do), then pushed to the server.

### On the Mac

On `github.com/rei-asanoha/Q21` → **Actions** → **Release** → the latest
**green** run → **Artifacts** section → download **two** artifacts:
**`q21-linux-x86_64.tar.gz`** and **`SHA256SUMS-signed`**.

Unzip each one once (double-click): you get `q21-linux-x86_64.tar.gz` on one
side, `SHA256SUMS` and `SHA256SUMS.minisig` on the other. **Do not unpack the
`.tar.gz` itself**: it is what the signature covers, and it is what you send.

In the Terminal, go to your downloads folder and send the three files:

```bash
scp q21-linux-x86_64.tar.gz SHA256SUMS SHA256SUMS.minisig q21op@YOUR_IP:~/
```

### On the server — check the signature before installing

The hash alone proves that the file arrived whole; it does not prove who built
it. Before installing a program that holds keys, you check the **signature** —
see [SIGNING.md](SIGNING.md). The server has `minisign`
(`sudo apt install -y minisign` the first time). The `RW…` key below is the
project's public key, the same one as in the README:

```bash
minisign -Vm ~/SHA256SUMS -P 'RW…' && cd ~ && sha256sum -c SHA256SUMS --ignore-missing
```

**You should see** `Signature and comment signature verified`, then a line
`Trusted comment: Q21 main <commit hash> -- Rei Asanoha` (or `Q21 v…` for a
tagged release), then `q21-linux-x86_64.tar.gz: OK`.

⛔ **Refuse to install** if the second word of the comment is neither `main`
nor a `v…` tag, if the commit hash is not that of the run you started, or if
the run was red. A valid signature of something you did not want is still
something you did not want.

Then, and only then:

```bash
tar -xzf ~/q21-linux-x86_64.tar.gz
sudo install -o root -g root -m 0755 ~/q21 /opt/q21/q21
```

`install -o root`: the program belongs to `root`, not to the account that runs
it. A service that can rewrite its own executable no longer has any barrier
between an execution flaw and persistence.

**Check that the program runs, and that it is on the right chain:**

```bash
sudo -u q21 /opt/q21/q21 genesis testnet
```

The identifier displayed must be **exactly** the one on your PC and your Mac.
If it differs, or if you read `cannot execute binary file`, stop: in the
second case, you picked an ARM machine (see step 4).

---

# Step 10 — The service that restarts on its own

An entry point that stops after an outage is not an entry point.

```bash
sudo nano /etc/systemd/system/q21.service
```

Paste exactly this:

```ini
[Unit]
Description=Q21 bootstrap node (testnet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=q21
Group=q21
WorkingDirectory=/opt/q21
ExecStart=/opt/q21/q21 --datadir /opt/q21/data node --network testnet --listen 21121 --no-bootstrap
Restart=always
RestartSec=10

# The node only needs to write to its data directory.
ProtectSystem=strict
ReadWritePaths=/opt/q21/data
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
```

**Ctrl + O**, Return, **Ctrl + X**.

Create the data directory and start:

```bash
sudo mkdir -p /opt/q21/data
sudo chown q21:q21 /opt/q21/data
sudo systemctl daemon-reload
sudo systemctl enable --now q21
```

### Check

```bash
sudo systemctl status q21
```

You should read **`active (running)`** in green.

```bash
sudo journalctl -u q21 -f
```

You should see the genesis written, then the listening port:

```
  genesis written: e310676c854f69369300...
  wallet-less: no wallet method served
  listening on 0.0.0.0:21121
```

**Ctrl + C** to stop watching — this does not stop the service.

> `--no-bootstrap` because this node **is** the bootstrap. Without it, two
> entry points of the same network would spend their time calling each other.

---

# Step 11 — The domain name

An IP address written down somewhere can never be changed again. A name can be
repointed in a minute — that is what will let you change servers without
anyone having to redo anything.

Buy a domain from the registrar of your choice (OVH, Gandi, Cloudflare,
Namecheap…). Around ten euros a year.

In its interface, create an **A record**:

| Field | Value |
|---|---|
| Type | `A` |
| Name / Host | `bootstrap` |
| Value / Points to | `YOUR_IP` |
| TTL | leave the default value |

> ⚠️ **If you are with Cloudflare**: the little cloud next to the line must be
> **gray** ("DNS only"), not orange. The orange proxy only relays web traffic,
> and would break the Q21 protocol without the slightest error message.

### Check, from the Mac

```bash
dig +short bootstrap.YOURDOMAIN.com
```

It must display your IP address. Allow a few minutes for propagation.

---

# Step 12 — Check from the outside

This is the moment of truth. **From the Mac**, in the folder where your `q21`
is:

```bash
./q21 --datadir network-test node --network testnet --bootstrap bootstrap.YOURDOMAIN.com
```

You should see:

```
  genesis written: e310676c...
  connecting to bootstrap.YOURDOMAIN.com (5.75.xxx.xxx:21121)
```

then the status line showing `peers 1`.

**Your network is open.** Anyone, anywhere, can now get in with that single
line.

---

# Step 13 — Connect your two machines to it

On the **PC**, in PowerShell, in the wallet folder:

```powershell
.\q21.exe wallet --mine --bootstrap bootstrap.YOURDOMAIN.com
```

On the **Mac**:

```bash
./q21 --datadir wallet wallet --bootstrap bootstrap.YOURDOMAIN.com
```

Both now go through the server instead of talking to each other directly — and
no longer need to be on the same local network.

---

# Monitoring, day to day

```bash
ssh q21op@YOUR_IP

sudo systemctl status q21      # is it alive?
sudo journalctl -u q21 -n 50   # the last 50 lines
sudo journalctl -u q21 -f      # watch live
```

To view the server's explorer without opening any port, open a **tunnel**
from the Mac:

```bash
ssh -L 21080:127.0.0.1:21080 q21op@YOUR_IP
```

As long as this window stays open, `http://127.0.0.1:21080` on your Mac reaches
the server. Nothing is exposed to anyone else.

*(The current service does not serve an interface — you would have to add
`--rpc 127.0.0.1:21080 --rpc-token-file <path>` to it. Do this only if you need
it.)*

## Getting notified without watching

A node that stops at three in the morning warns no one. The repository's
`tools/monitor.sh` script reads the height from the local RPC every ten
minutes; if it has not moved for thirty minutes, or if the RPC no longer
answers, it restarts the service and — if you give it an **ntfy topic** —
sends a notification to your phone. [ntfy](https://ntfy.sh) is free and needs
no account: install the app, subscribe to a topic of your choice (long and
unpredictable, for example `q21-server-k8s2m7x`), and put the same name below.

The script needs a local RPC: the service must carry `--rpc 127.0.0.1:21080`
(which is the case for a public explorer, see
[PUBLIC-EXPLORER.md](PUBLIC-EXPLORER.md)).

The ntfy topic is a weak shared secret — whoever knows it reads your alerts and
can publish fake ones. So it does not go in the unit file, which anyone can
read, but in an environment file readable by `root` alone.

```bash
sudo cp tools/monitor.sh /opt/q21/monitor.sh && sudo chmod +x /opt/q21/monitor.sh
sudo mkdir -p /etc/q21 && sudo tee /etc/q21/monitor.env > /dev/null <<'EOF'
Q21_RPC=127.0.0.1:21080
Q21_NTFY=
EOF
sudo chmod 600 /etc/q21/monitor.env
sudo tee /etc/systemd/system/q21-monitor.service > /dev/null <<'EOF'
[Unit]
Description=Q21 node monitoring

[Service]
Type=oneshot
EnvironmentFile=/etc/q21/monitor.env
RuntimeDirectory=q21-monitor
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true
ExecStart=/opt/q21/monitor.sh
EOF
sudo tee /etc/systemd/system/q21-monitor.timer > /dev/null <<'EOF'
[Unit]
Description=Q21 node monitoring, every ten minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now q21-monitor.timer
```

`Q21_NTFY=` empty: the script only restarts the service, and writes it to the
log (`journalctl -t q21-monitor`). With a topic, you also receive the message.
The state file lives in `/run/q21-monitor/`, which systemd creates for this
service alone: no one else can put anything there.

---

# What this server does not risk, and what it does

### What it does not risk

- **Theft of funds.** It has no wallet, no seed, no key.
- **Theft of your Q21 identity.** Nothing about you is written on it.
- **Making you believe a lie.** A peer, whoever it is, can only get anyone to
  accept valid blocks that extend the genesis each person computed at home,
  and that carry the proof of work. It can hide things; it cannot invent them.

### What it risks

- **Being saturated.** This is the open question that this testnet is meant
  to measure. If it happens, it will show in the log.
- **Going down.** The service restarts on its own; so does the machine after
  an intervention by the hosting provider. But if it disappears, no one can
  get in any more — hence the value of having a second one, later, with
  another hosting provider.

---

# If something goes wrong

| Symptom | Most likely cause |
|---|---|
| `Permission denied (publickey)` | The key was not checked when the server was created. Use Hetzner's web **Console** |
| `cannot execute binary file` | ARM machine (CAX line). You need a CX or CPX |
| `Connection refused` from the outside | Port 21121 is not open in the Hetzner firewall, or the service is not running |
| `dig` returns nothing | The A record has not propagated yet, or the name is misspelled |
| The node runs but no one connects | Orange cloud at Cloudflare: switch it to gray |
| `Failed to start q21.service` | `sudo journalctl -u q21 -n 50` will say why. Often a path or a permission |
