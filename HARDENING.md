# Hardening a machine that holds Q21

The protocol protects what it can: no one spends your funds without your key.
It does not protect the machine that holds that key. This document says what
an adversarial audit found on that front, and what to do about it — for a
Raspberry Pi that mines, for a server, for a shared computer.

---

## The Raspberry Pi that mines with no one in front of it

### A passphrase in a file cancels the wallet's encryption

A miner that starts on its own reads its passphrase from a file
(`--passphrase-file`). That file lives on the same SD card as `wallet.dat`.
The Argon2id sealing is solid — **when the attacker does not have the
passphrase**. Here, whoever takes the card has both: the passphrase on one
side, the file on the other, and the seed is unsealed in a second.

**This is not a defect to fix, it is a trade-off to be aware of.** The rule
that follows from it:

> On a machine that reads its passphrase from a file, **keep only a mining
> wallet**. Regularly transfer the rewards to a wallet whose passphrase is
> written down nowhere. Stealing the card then only costs what has not yet
> been transferred.

The passphrase file must belong to the single account that runs the node,
with `chmod 600`. The program warns if it is readable by others.

### One account for the service, one key for access

The default login account (`pi`), the default hostname (`raspberrypi`) and a
password typed by hand make a predictable target on a local network. Three
measures, in order:

1. **SSH with a key, never with a password.** When writing the card, the
   imaging tool offers to paste a public key instead of the password: do it.
   Otherwise, after the fact:

   ```bash
   sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
   sudo systemctl restart ssh
   ```

2. **A system account for the node**, with no shell, owning only its own
   files:

   ```bash
   sudo useradd --system --home /var/lib/q21 --create-home --shell /usr/sbin/nologin q21
   sudo chmod 700 /var/lib/q21
   ```

   The service runs as `User=q21`, its data and its passphrase live in
   `/var/lib/q21`: the login account can no longer read them.

3. **A firewall that opens nothing inbound**, and a brake on login attempts:

   ```bash
   sudo apt install -y ufw fail2ban
   sudo ufw default deny incoming && sudo ufw default allow outgoing
   sudo ufw allow from 192.168.0.0/16 to any port 22 proto tcp comment 'ssh, local network only'
   sudo ufw --force enable
   sudo systemctl enable --now fail2ban
   ```

   A miner does not need an inbound port: it calls its peers, nobody calls it.

### The systemd unit

```ini
[Unit]
Description=Q21 node (miner)
After=network-online.target
Wants=network-online.target

[Service]
User=q21
Group=q21
WorkingDirectory=/var/lib/q21
ExecStart=/opt/q21/q21 --datadir /var/lib/q21/data --passphrase-file /var/lib/q21/passphrase.txt node --network testnet --mine --bootstrap bootstrap.q21.dev --prune
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/q21
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

### The clock

A Raspberry Pi has no clock that keeps time while powered off. A block dated
more than ten minutes in the future is rejected by the whole network; a miner
with the wrong time therefore produces blocks that no one takes. Check that
time synchronization is active: `timedatectl` must say `System clock
synchronized: yes` before you mine.

---

## The public server

It has no wallet — that is the first rule, and the program enforces it:
`--rpc-public` refuses to start if a wallet is present. The rest is in
[SERVER.md](SERVER.md): dedicated account, hardened unit, SSH key,
`fail2ban`, automatic updates.

Two points come from the audit:

- **Expensive searches are budgeted, per address.** An amount or transaction
  search without an index result rereads up to two thousand blocks under the
  chain lock. In public mode, the node grants only a bounded number per
  minute **to each address** that the reverse proxy passes on to it, plus a
  safety net for all of them together; beyond that, it answers to try again,
  and keeps validating. The first budget was shared by everyone: a single
  visitor emptied it for everybody. The reverse proxy, for its part, must
  limit connections per address — [PUBLIC-EXPLORER.md](PUBLIC-EXPLORER.md),
  step 4.2a — because the node only bounds what it is made to compute, not
  what it is made to wait for.
- **Monitoring shares nothing.** Its state file lives in a directory that
  systemd creates for it alone, and its notification topic in a file readable
  by `root` alone. See [SERVER.md](SERVER.md), "Getting notified without
  watching".

---

## The wallet on a shared computer

The wallet listens on the loopback and requires a token. The address the
program gives the browser goes through the launcher's command line, which
**any account on the machine** can read — `/proc/<pid>/cmdline` on Linux, `ps`
on macOS — and it stays there as long as the browser is running.

Two defenses, independent of each other:

- **What is in the address is only good once.** The fragment no longer carries
  the session token, but a *launch token*: the page exchanges it on first load
  for the real token, which never leaves the program or the tab, and the
  launch token is destroyed. It expires on its own after ten minutes if no one
  has opened it. What lingers afterwards on the command line no longer opens
  anything, on every system. Another account that read it before the page did
  only wins a one-second race — and if it wins, the legitimate page displays
  "this link has already been used" instead of running alongside a silent
  intruder. A link is only good once, but a tab can be reopened as long as the
  program is running: the session token is stored in the browser, under this
  origin, and dies with the process that drew it.
- **On Linux, the node refuses other accounts.** It asks the kernel which
  account holds the other end of each local connection, and refuses any
  account other than its own — which also closes the race above. This guard
  fails closed: a local connection that the kernel table does not list is
  refused, it is no longer let in "when in doubt". It is only lifted where
  there is nothing to read — macOS, Windows — and the program says so on
  screen.

On macOS and Windows, the one-time link is therefore the barrier, and the rule
remains that of any software that holds keys — **one account per person, and
no wallet on a computer where others have an account**.

---

## What you install

Every release is signed; check the signature before installing, on every
machine. That is the subject of [SIGNING.md](SIGNING.md), and it is the only
defense against a substituted binary — the door through which every other
defense falls.
