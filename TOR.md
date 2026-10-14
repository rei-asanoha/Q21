# Running Q21 through Tor

Since 0.4.7, a node or a wallet can send every connection through Tor. The
nodes it talks to then see a Tor relay, not your IP address. On top of that,
a node can be **reachable** without revealing where it is, through a Tor
*onion service*.

Tor is off by default. Nothing changes for anyone who does not turn it on.

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

## 1 · Install Tor

The node does not ship Tor. It looks for one on this computer, on port 9050
(the Tor service) and then 9150 (Tor Browser).

| Computer | Simplest way | Port |
|---|---|---|
| Windows | Install **Tor Browser** from torproject.org, open it, click *Connect*, leave it open | 9150 |
| macOS | Same, with Tor Browser for macOS | 9150 |
| Raspberry Pi, Linux | `sudo apt install tor` — it then runs as a service, also after a restart | 9050 |

Tor Browser must stay open for as long as the wallet runs. Closing it cuts
every connection of the wallet: the wallet does **not** fall back to a
direct connection, it waits for Tor.

Check on Linux:

```bash
systemctl status tor        # "active"
ss -ltn | grep 9050         # Tor listens on 127.0.0.1:9050
```

---

## 2 · The wallet

**Network** tab → **Hide your address with Tor** → switch on. The setting is
saved in `settings.txt` (`tor=yes`) and **takes effect at the next launch**:
close the wallet, open it again.

The card then says *Every connection goes through Tor*. If Tor is not
running, it says so, and the wallet stays without peers until Tor starts.

With Tor on, **reachable** (same tab) changes meaning: the wallet never asks
your router to open a port, and listens on the computer itself only
(`127.0.0.1`). Only an onion service, section 4, can then hand it incoming
connections. Without one, it is simply not reachable, which is the right
default for a wallet.

---

## 3 · A node from the command line

```bash
q21 --datadir q21-testnet node --network testnet --tor
```

The console says:

```
  Tor: every outgoing connection goes through 127.0.0.1:9050
```

- `--tor` finds the local Tor (9050, then 9150).
- `--proxy 127.0.0.1:9150` names the SOCKS5 proxy explicitly.
- With either one, `--upnp` is ignored: asking the router for a port and
  announcing the public address would undo what Tor hides.
- If no Tor answers, the node says `Tor not found` and **does not connect in
  the clear**: every attempt fails until Tor is there.

Names in `bootstrap.txt` and after `--bootstrap` are resolved by Tor, not by
your provider's DNS. An address ending in `.onion` is reachable only this
way: without `--tor`, the node skips it and says so.

---

## 4 · A reachable node that nobody can locate

This is the hidden node: other nodes connect to it, mine through it, sync
from it, and none of them learns where it is. The instructions are for a
Raspberry Pi or any Linux machine with the Tor service (section 1).

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

### 4.2 · Start the node behind it

```bash
q21 --datadir q21-testnet node --network testnet \
    --listen 127.0.0.1 --tor --onion <the address>.onion
```

- `--listen 127.0.0.1` listens on the machine itself only: the node is not
  reachable from your network or from the Internet, only through Tor.
- `--onion` tells the node its own name, so that it can announce it.
  It requires `--tor`: a node that connects in the clear would link the name
  to its IP address in the eyes of every peer.

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
never connects to one. A node keeps at most 1,000 onion addresses, and
forgets one after five failed attempts.

Nodes from 0.4.5 and earlier (protocol 3) still talk to 0.4.7 nodes: they
are simply never sent `onionaddr`.

### 4.5 · From the wallet

A wallet can announce an onion service too: add a line to `settings.txt`, in
its data folder,

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

- **Tor is not bundled.** It is installed separately (section 1).
- **No ready-made image** for the Raspberry Pi with Tor set up.
- **The entry points are not onion services yet.** A node behind Tor
  reaches them through a Tor exit relay, which works but depends on exits
  that accept port 21121.
- **Two things still connect directly**, and say so: `q21 diagnostic`, which
  tests the entry points on purpose, and a fast sync with
  `--assume-commitment`, which is refused together with `--tor`.
- **No Dandelion++.** A payment is relayed to every peer at once. Behind
  Tor, that reveals nothing about your address; without Tor, the first node
  to relay it is a good guess of where it comes from.
