# Opening and joining the Q21 testnet

Two sets of steps. The first is for whoever runs an entry point, the second
for whoever arrives.

---

# Part 1 — Joining the network

## 1 · Check the genesis, before anything else

```
q21 genesis testnet
```

```
  testnet
    identifier    e310676c854f693693008d7270b583092c065051f73dc33b245676d804d77227
    P2P port      21121
```

**This value comes from no server.** It is recomputed from the code, on your
machine. If yours differs from the published one, you are not on the same
chain — and no amount of syncing will change that.

It is the only act of trust in the whole process, and it asks you to believe
no one: it asks you to compare two numbers.

## 1a · On macOS: remove the quarantine, once

The released files are not notarized — that requires an identity verified by
Apple, and this project has chosen not to have one. macOS therefore
quarantines everything that comes from a browser, and offers to **move it to
the Trash**. This is not a malfunction, and refusing is the right reflex on
its part.

**If you want the wallet**, you have nothing to type: the `Q21 Wallet.command`
launcher removes the quarantine from the whole folder itself before starting.
macOS will block the launcher once — "from an unidentified developer" — and
**System Settings → Privacy & Security → Open Anyway** settles the matter for
good. `JOIN.md` describes this step in detail.

**If you want a wallet-less node**, or just to check the genesis, there are two
things to know, in this order:

**`q21` is not double-clicked.** It is a command-line program. Double-clicking
it in the Finder is precisely what triggers that dialog.

**The quarantine is removed from the Terminal**, in one go, for the whole
folder:

```bash
cd <the unzipped folder>
xattr -dr com.apple.quarantine .
chmod +x q21
./q21 genesis testnet
```

To get the `cd` right: type `cd ` — with the space — then **drag the folder
from the Finder into the Terminal window**. The path writes itself. Press
Return.

> On macOS 15 (Sequoia), the long-standing "right-click → Open" workaround was
> removed. If you would still rather go through the interface: launch the
> program once, let it be refused, then go to **System Settings → Privacy &
> Security**, scroll all the way down, and click **Open Anyway**.

## 2 · A simple, wallet-less node

```
q21 --datadir q21-testnet node --network testnet --bootstrap <network host>
```

The folder can be empty: the node writes the genesis itself — it is
deterministic — then downloads and **validates** every block. Nothing is taken
on faith.

No passphrase is asked for, no key is kept, and no method capable of moving
funds is served.

## 3 · With a wallet

```
q21 --datadir q21-testnet init testnet
q21 --datadir q21-testnet wallet --bootstrap <network host>
```

The wallet opens in the browser and syncs with the network. Until the sync is
finished, a banner says so — a balance computed on an incomplete chain is a
wrong balance, and it is better to know it.

## 4 · Mining

Add `--mine`. On a network where others mine, the difficulty adjusts: it is no
longer one block per second as on a local machine, but one block every two
minutes for the whole network, shared among everyone who is searching.

---

# Part 2 — Running an entry point

A public network needs at least one machine that is reachable at all times.
Without it, no one can get in.

## What it takes

A small rented server, five to ten euros a month. One core, one gigabyte of
memory and ten gigabytes of disk are enough for a testnet. A fixed IP address,
and preferably a **name** that points to it: a name can be repointed in a
minute, an address written into a binary can never be changed again.

> **Complete step-by-step guide, for anyone who has never administered a
> server: [SERVER.md](SERVER.md).** Creating the account, access key, SSH
> hardening, firewall, service, domain name — thirteen steps, with the details
> of what you should see each time.

## Installing

```bash
# on the server, as a regular user
sudo mv ~/q21 /opt/q21/q21
sudo chmod +x /opt/q21/q21
sudo -u q21 /opt/q21/q21 genesis testnet    # check the identifier
```

> ⚠️ **The released binary is compiled for x86_64.** An ARM machine —
> Hetzner's CAX line, the cheapest one — would refuse it with
> `cannot execute binary file`. Pick a CX or a CPX.

## The service that restarts on its own

An entry point that stops after a power outage is not an entry point. File
`/etc/systemd/system/q21.service`:

```ini
[Unit]
Description=Q21 bootstrap node (testnet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=q21
WorkingDirectory=/opt/q21
ExecStart=/opt/q21/q21 --datadir /opt/q21/data \
          node --network testnet --listen 21121 --no-bootstrap
Restart=always
RestartSec=10
# The node only needs to write to its data directory.
ProtectSystem=strict
ReadWritePaths=/opt/q21/data
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now q21
journalctl -u q21 -f          # to watch what it does
```

`--no-bootstrap` because this node **is** the bootstrap: without it, two entry
points of the same network would spend their time calling each other.

## The firewall

One port open, and only one.

```bash
sudo ufw allow 21121/tcp      # P2P: must be reachable
sudo ufw enable
```

**The RPC port is not opened.** A bootstrap node has no reason to expose its
query interface, and the program in fact refuses to serve an RPC off the
loopback without a token:

```
error: refused: --rpc 0.0.0.0:21080 leaves the loopback and no token
                       is provided. Any machine that can reach you could query
                       this node.
```

To look at this node remotely, go through an SSH tunnel rather than opening a
port:

```bash
ssh -L 21080:127.0.0.1:21080 q21@your-server
```

## What this node does not do

- **It does not mine.** Without a wallet, the subsidy would go to a key that
  would die with the process; the program refuses `--mine`. An entry point and
  a miner are two roles, and keeping them apart prevents a failure of one from
  taking the other down with it.
- **It keeps no key.** There is nothing to steal on this machine.
- **It decides nothing.** It provides a first contact; what you believe comes
  from the proof of work and from the genesis you wrote yourself.

## The testnet entry point, today

```
bootstrap.q21.dev:21121
92.222.86.135:21121
```

The name **and** the address are published side by side, on purpose. A domain
name may one day expire and be bought by someone else; an address stays
reachable as long as the machine that holds it exists. Publishing both gives a
choice to whoever joins, and the failure of one isolates no one from the
network — see below for why neither is compiled into the binary.

## Publishing the entry point

Once the node is running, announce its name. Those who join write it either on
the command line or in `bootstrap.txt` in their data directory — one per line;
empty lines and lines starting with `#` are ignored:

```
# the Q21 testnet bootstrap addresses
bootstrap.q21.dev:21121
92.222.86.135:21121
```

A freshly downloaded wallet finds the network **without anyone typing
anything**: the released archive already carries this file, filled in and
commented, in two copies — `bootstrap.txt` flat next to the binary, and
`q21-data/bootstrap.txt`, which the user edits and which takes precedence. The
duplicate is deliberate: a subfolder can get lost during packaging depending
on the tool, a flat file cannot. Its source is `default-bootstrap.txt`, at the
root of the repository, and a test forbids writing into it an address that
this document does not publish — publish first, ship second.

**Even so, no entry point is compiled into the binary**, and
`builtin_bootstrap` in `src/bootstrap.rs` stays empty. That distinction is what
everything rests on: an address hard-coded into a program can only be changed
by redistributing the program, so only by whoever signs it; an address in a
text file belongs to whoever received it, from the second they have it. They
edit it, replace it, or empty the file. It is a first-start convenience, not a
dependency — and a protocol meant to outlive its author must not be born with
its author's address inside it.

The entry point is therefore supplied at run time, in two ways:

```
q21 node --bootstrap <host>               # once, on the command line
echo <host> >> <datadir>/bootstrap.txt    # permanently
```

A name rather than an IP address: an address is tied to a machine, and a
distributed binary does not update itself when it changes. A name can be
repointed in a minute, without redistributing anything. The name of the
network to join is announced with each release.

The listing rule does not change: **only what really answers is written
here**, checked from an outside machine, handshake included. Announcing a dead
name would be worse than nothing — every start would wait for an answer that
never comes. The mainnet, for its part, therefore still has no bootstrap
address, and a test guarantees it.

A single entry point remains a single point of failure: if it goes down, no
one can *get in* any more — those already in the network carry on, their
address book is enough for them. A second one, with another hosting provider,
is the first thing to add.

---

# What bootstrapping does not give as power

Whoever runs the entry points decides **whom you talk to first**, not what you
believe.

A peer, whoever it is, can only make you accept valid blocks, extending the
genesis you computed yourself, and carrying the proof of work. It can hide
things from you; it cannot invent them.

The defense against being isolated — the eclipse attack — is not trust in the
bootstrap. It is the address book: buckets per /16 network group, and a salt
specific to each node, so that an adversary holding a single address range
cannot occupy all your slots. See the `addr` module (`src/addr.rs`).

---

# What a laptop taught the protocol

The first test between two real machines — a Windows PC and a MacBook —
uncovered a defect that no loopback test could produce.

You close the laptop's lid, you open it again: **the chain stops moving.**
Height 442, for good, while the other machine mined up to 455.

A TCP connection can outlive the machine on the other end. A laptop that goes
to sleep says nothing as it leaves — neither `FIN` nor `RST` — and the socket
stays open on the side that remains. The node therefore believed it had a
peer, looked for no one, and waited forever for messages that would never
come.

Three measures, in this order:

| Silence | What happens |
|---|---|
| 45 s | A `Ping` is sent: "are you there?" |
| 100 s | With no frame received in the meantime, the slot is freed and the bootstrap addresses are retried |
| A loop iteration that lasts more than a minute | The machine was asleep: everything is disconnected right away, without waiting for the 100 s |

The third point makes waking up almost immediate. Measured: a node asleep for
75 seconds finds its peer again and catches up 59 blocks in less than twenty
seconds after waking up.

On a public network, the same defect was a path to an eclipse: opening
connections and then going silent was enough to occupy every slot of a node.

---

# What this testnet will be used to measure

It is not open for show. Three things cannot be measured anywhere else:

| Question | Why only a real network answers |
|---|---|
| Does the cost of saturating the mempool really bite? | Locally, no one tries |
| Does the difficulty adjust cleanly with several miners? | A single miner does not make much vary |
| What happens during a real reorg? | It takes two miners mining at the same time, far from each other |

And the most important point remains open: **the proof of work has received no
external cryptanalysis.** A public testnet is also an invitation to come and
break it.

**No Q21 on this network has the slightest value, nor ever will.** It is a
testnet: it can be reset at any time.
