# Running Q21 through Tor

Since 0.4.7, a node or a wallet can send every connection through Tor. The
nodes it talks to then see a Tor relay, not your IP address. On top of that,
a node can be **reachable** without revealing where it is, through a Tor
*onion service*.

Since 0.4.8, **Tor comes with the wallet** on Windows, macOS and Linux
(x86_64): one switch, nothing to install, nothing to keep open. A wallet that
is both on Tor and reachable becomes a hidden node by itself.

Since 0.5.9, **the wallet turns Tor on by itself** when you never chose and
this computer has a Tor it can start itself (the one in the archive, or a
`tor` program installed on the computer), and it makes itself **reachable
through Tor**: a hidden node. It writes `tor=yes` and `reachable=onion` in
`settings.txt`: reachable through Tor only. If you turn Tor off later, the
wallet does not become reachable in the clear; that needs your explicit
choice (`reachable=yes`). A contact who finds you in the directory can call
you, and your internet address is never announced. A choice you made in the
Network tab, "off" included, is kept. A port merely open on 9050 or 9150 does
not count as a Tor for this default: any program of any account on the
computer could be listening there. Without a Tor, the wallet works as
before, without it. A node started from the command line (`q21 node`) never
turns Tor on by itself.

---

## What Tor hides, and what it does not

| | Without Tor | With Tor |
|---|---|---|
| Who sees your IP address | Every node you connect to, and anyone who watches them | Nobody on the Q21 network: they see a Tor relay |
| A payment you send | First seen coming from your address | First seen coming from a Tor relay |
| A block you mine | Same | Same: the miner's address is not tied to an IP |
| Your balance and your payments | Public on the chain, as for everyone | Public on the chain, as for everyone: Tor hides *where* you are, not *what* you do |
| Your provider, your VPN | Sees that you talk to Q21 nodes | Sees that you use Tor, not to whom you talk |

Two limits to keep in mind:

- **Tor is slower.** A connection takes a few seconds to open instead of a
  fraction of one, and a full sync takes longer. Once synced, the difference
  hardly shows: a block is a few kilobytes every two minutes.
- **Tor does not make a reused address private.** The chain is public. What
  you send from an address, everybody sees; Tor only removes the link
  between that address and your network connection.

---

## 1 · Where Tor comes from

| Computer | Tor |
|---|---|
| Windows, macOS (Intel and Apple Silicon), Linux x86_64 | **In the archive**, in the `tor/` folder next to the program. Nothing to install |
| Raspberry Pi, Linux on ARM | `sudo apt install tor`: there is no stable Tor Expert Bundle for this platform yet |

With `--tor` (or the switch in the wallet), the node takes, in this order:

1. the Tor in its own `tor/` folder, which it **starts itself** and stops
   when it closes. Its files (guard relays, onion service key) live in a
   `tor/` folder inside the data directory;
2. a Tor already running on this computer: the Tor service on port 9050,
   Tor Browser on 9150. On Linux, only one run by your own account or by
   the system (0.5.9): a program of another person's account listening
   there is not taken for Tor. On macOS and Windows the port alone is
   checked: on a computer shared with other accounts, prefer the bundled
   Tor;
3. a `tor` on the PATH, started the same way as the bundled one.

If none works, the node says so and **does not connect in the clear**: it
waits for Tor.

The bundled Tor is the Tor Expert Bundle of a stable Tor Browser release,
unchanged. The release workflow downloads it from the Tor Project and refuses
it unless its signature verifies with the Tor Browser Developers key,
fingerprint `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`.
`tor/README.txt` in the archive names the version. Some antivirus programs
flag `tor.exe` by mistake: it is the program published by the Tor Project.

Check a system Tor on Linux:

```bash
systemctl status tor        # "active"
ss -ltn | grep 9050         # Tor listens on 127.0.0.1:9050
```

---

## 2 · The wallet

**Network** tab → **Hide your address with Tor** → switch on. The setting is
saved in `settings.txt` (`tor=yes`) and **takes effect at the next launch**:
close the wallet, open it again.

The card then says *Every connection goes through Tor*, and *Tor is
starting: 45 %* while the bundled Tor builds its first circuits (a few
seconds to a minute). If Tor cannot connect, the card says so, and the wallet
stays without peers until it does.

With Tor on, **reachable** (same tab) makes the wallet a **hidden node**:
the bundled Tor creates an onion address for it, the wallet announces it, and
other nodes reach it there. The wallet never asks your router to open a
port, and listens on the computer itself only (`127.0.0.1`). The card then
says *Hidden node on*. The onion address is kept in `q21-data/tor/onion/`:
as long as that folder is kept, the address stays the same.

Since 0.5.9, **reachable** turned on while Tor is on is written
`reachable=onion`: reachable through Tor only. Turning Tor off later makes
the wallet unreachable, never reachable in the clear; that is a choice made
with Tor off. When the network's port is already taken on the computer (a
second wallet, a node, another program), the wallet listens on another
port, which Tor forwards to: the onion address does not change.

A hidden node checks that it can really be reached (0.5.7): a few minutes
after Tor starts, then every twenty minutes, it calls its own onion address
through Tor, as a contact calling it would. Twice without an answer, and the
log says *this node's onion address does not answer*; the Tor the wallet
started is then started again, at most every half hour. After the computer
slept twenty minutes or more, that Tor is started again at once: a Tor left
as it was after a night of sleep kept running with its onion service
unreachable for hours. The onion address does not change.

Since 0.5.9, the first check after Tor starts, or after the computer wakes,
does not wait for a second failure: when the onion address does not answer
yet, the Tor the wallet started is started again at once, once per start or
wake. A Tor started with a directory of the network more than a day old
could connect out while its own service stayed unpublished. The result of
the last check is in `getinfo` (`onion.check`: `starting`, `reachable` or
`unreachable`) and on the page.

Calling a contact (**Private channel** → **Connect**), the page follows the
call to its end: *Calling this contact…*, then *✓ Connected*, or *This
contact does not answer* when its onion address does not answer — its
wallet closed, its computer asleep, or its Tor not ready.

---

## 3 · A node from the command line

```bash
q21 --datadir q21-testnet node --network testnet --tor
```

The console says, with the bundled Tor (the port is drawn at each start):

```
  Tor: started …/tor/tor — it takes from a few seconds to a minute to connect
  Tor: every outgoing connection goes through 127.0.0.1:41873
```

or, with a Tor already running on the machine:

```
  Tor: using the Tor already running on 127.0.0.1:9050
  Tor: every outgoing connection goes through 127.0.0.1:9050
```

- `--tor` takes its Tor as in section 1.
- `--proxy 127.0.0.1:9150` names the SOCKS5 proxy explicitly.
- `--tor --listen 127.0.0.1` with the bundled Tor (or one on the PATH) is a
  hidden node: Tor creates its onion address, the node announces it.
- With either one, `--upnp` is ignored: asking the router for a port and
  announcing the public address would undo what Tor hides.
- If no Tor answers, the node says `Tor not found` and **does not connect in
  the clear**: every attempt fails until Tor is there.

Names in `bootstrap.txt` and after `--bootstrap` are resolved by Tor, not by
your provider's DNS. An address ending in `.onion` is reachable only this
way: without `--tor`, the node skips it (one line at startup counts them).

---

## 4 · A reachable node that nobody can locate

This is the hidden node: other nodes connect to it, mine through it, sync
from it, and none of them learns where it is.

With the bundled Tor, it is one command (or Tor + reachable in the wallet):

```bash
q21 --datadir q21-testnet node --network testnet --tor --listen 127.0.0.1
```

```
  Tor: this node is reachable as <the address>.onion:21121
```

The rest of this section is for a Raspberry Pi or any Linux machine that
uses the Tor service of its system (section 1).

### 4.1 · Ask Tor for an onion address

Add two lines at the end of `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/q21/
HiddenServicePort 21121 127.0.0.1:21121
```

```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/q21/hostname
```

The last command prints the address, 56 characters followed by `.onion`. Tor
keeps the matching key in `/var/lib/tor/q21/`: as long as that folder is
kept, the address stays the same. Back it up with the node if you want to
keep the address after a reinstall.

Every connection through the onion address reaches the node from
`127.0.0.1`, whoever opened it. The node therefore keeps at most half of its
inbound slots — twelve — for loopback, so that circuits opened by one
person can never take the slots of peers reaching it by IP, and a connection
in the clear never takes a Tor peer's seat. When the twelve are taken, a
newcomer replaces the most recent loopback peer connected for more than a
minute, unless it brought a block or a transaction the node kept in the last
ten minutes, or is among the eight connected longest; four seats always stay
open to newcomers.

The node cannot tell two Tor users apart: someone opening circuits in a loop
can still keep newcomers waiting. Tor itself can make each circuit cost
them. On an entry point, add to the same block of `/etc/tor/torrc` (Tor
0.4.8 or later):

```
HiddenServiceEnableIntroDoSDefense 1
HiddenServicePoWDefensesEnabled 1
HiddenServiceMaxStreams 4
HiddenServiceMaxStreamsCloseCircuit 1
```

The first limits the rate of introductions at the introduction points; the
second asks a client for a small proof of work once the service is under
load; the last two close a circuit that opens more than four streams, so a
loop of connections needs a new circuit each time. `sudo systemctl restart
tor` again: the onion address does not change.

### 4.2 · Start the node behind it

```bash
q21 --datadir q21-testnet node --network testnet \
    --listen 127.0.0.1 --tor --onion <the address>.onion
```

- `--listen 127.0.0.1` listens on the machine itself only: the node is not
  reachable from your network or from the Internet, only through Tor.
- `--onion` tells the node its own name, so that it can announce it.
  It requires `--tor`: a node that connects in the clear would link the name
  to its IP address in the eyes of every peer. The exception is an entry
  point that listens on a public address (`--listen 21121`): its address is
  public anyway, and it may announce its onion name without `--tor`.

The console says:

```
  Tor: this node announces its onion service <the address>.onion:21121
  Tor: every outgoing connection goes through 127.0.0.1:9050
```

### 4.3 · Check that it works

Behind Tor, the status line of the node ends with three numbers:

```
height 2950 (+0)  peers 3 (…)  …  onion 4 known, 1 out, 2 in
```

- **known**: onion addresses learned from the network;
- **out**: connections this node opened to onion services;
- **in**: connections other nodes opened to **this** one, through its onion
  address. Above zero, the hidden node is reachable.

`getinfo` returns the same counts under `onion`, and the wallet shows them
in the Tor card of the Network tab. The address itself is never returned: a
node that also serves a public explorer would otherwise tie it to its
domain.

### 4.4 · How the others find it

The address travels in a new message, `onionaddr`, part of protocol 4
(0.4.7). A node announces its own onion service to each peer it connects to,
and passes on the ones it has learned when asked for addresses. A node with
Tor tries them when it looks for peers. A node without Tor keeps them and
passes them on, so that the addresses spread through the whole network, but
never connects to one. A node keeps at most 1,000 onion addresses, writes
them to `onions.dat` at shutdown so that it finds them again after a restart
even when the entry points are down, and forgets one only when it keeps
failing (five attempts in a row) **and** has not been seen for three days.

The two entry points are onion services too, and `bootstrap.txt` names them
(see NETWORK.md): a node through Tor reaches them without any exit relay,
and still does when their usual addresses are blocked or down.

Nodes from 0.4.5 and earlier (protocol 3) still talk to 0.4.7 nodes: they
are simply never sent `onionaddr`.

### 4.5 · From the wallet

With the bundled Tor, there is nothing to do: Tor **and** reachable in the
Network tab (section 2). With a Tor of the system, a wallet can announce an
onion service set up by hand: add a line to `settings.txt`, in its data
folder,

```
onion=<the address>.onion
```

then turn on Tor **and** reachable in the Network tab. The wallet announces
the address only when both are on. Setting up the onion service itself is
the same as in 4.1, which is simple on Linux and much less so on Windows and
macOS: for those, keeping the wallet not reachable is the reasonable choice.

---

## 5 · Mining behind Tor

Nothing changes: `--mine` with `--tor` mines exactly as before, and the
blocks found leave through Tor. A miner that is reachable without Tor gets
a warning at startup and in the wallet: its blocks first appear coming from
its IP address, which ties that address to the rewards.

---

## 6 · What is not there yet

- **No bundled Tor on the Raspberry Pi** (Linux on ARM): there is no stable
  Tor Expert Bundle for it yet; `apt install tor` (section 1).
- **No bridges.** The bundled Tor has no pluggable transports: on a network
  that blocks Tor, it does not connect, and the wallet waits.
- **No ready-made image** for the Raspberry Pi with Tor set up.
- **Two things still connect directly**, and say so: `q21 diagnostic`, which
  tests the entry points on purpose, and a fast sync with
  `--assume-commitment`, which is refused together with `--tor`.
- **No Dandelion++.** A payment is relayed to every peer at once. Behind
  Tor, that reveals nothing about your address; without Tor, the first node
  to relay it is a good guess of where it comes from.
- **A program on the same computer can link a hidden wallet to it.** Tor
  hands the onion's connections to a port on `127.0.0.1`; any program of
  any account on the computer can connect there without Tor, and the
  wallet greets it with its onion address. On a computer you share, this
  tells the other accounts which onion — and which name — is yours.
- **A name tells where its owner can be reached.** A wallet that owns a name
  signs its onion address, and every node relays the pair: that is how a
  contact finds it. Anyone can therefore list the names and the onion
  address of each, and see when a given wallet answers — not where it is.
  A wallet that does not want to be called keeps no name, or turns
  **reachable** off.
