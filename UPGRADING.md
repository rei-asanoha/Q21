# Updating your wallet

Five minutes. No commands.

---

## 1 · Pour the new content **into** the existing folder

> ### ⚠ Never delete the `Q21` folder itself
>
> It contains a **hidden** subfolder named `.git`. That `.git` **is** the
> repository: it is what knows the history and the link to GitHub. This
> archive does not contain one — on purpose, because a second `.git` would
> cause the "unrelated histories" error.
>
> Deleting the folder to put the archive's folder in its place therefore
> destroys the repository, and GitHub Desktop displays **"Can't find Q21"**.
>
> You **pour** the new content into it. You do not replace the container.

You downloaded `q21-repo.zip`. Unzip it: you get a `q21` folder.

1. In GitHub Desktop: **Repository** menu → **Show in Explorer**
   → File Explorer opens on your repository folder
2. Open the `q21` folder that came from the archive, in **another** window
3. Inside it: `Ctrl` + `A` (select all), then `Ctrl` + `C`
4. Go back to the repository window: `Ctrl` + `V`
5. Windows asks what to do → **Replace the files in the destination**

Go back to GitHub Desktop: it shows the modified files in the *Changes* tab.

> **If GitHub Desktop already displays "Can't find Q21"** — the folder has been
> deleted. Click **Clone Again**: GitHub Desktop downloads the repository again
> from your account, with its `.git`. Then pick up again at step 2 above.
>
> If a `Q21` folder still exists at that location without being a repository,
> rename it to `Q21-old` before clicking **Clone Again**, then delete it once
> the operation is finished.

---

## 2 · Push to GitHub

At the bottom left, in the **Summary** field, write:

```
Explorer: search, blocks, transactions, addresses
```

Click **Commit to main**, then **Push origin** at the top.

---

## 3 · Run the build again

On `github.com/rei-asanoha/Q21`:

**Actions** → **Release** (left column) → **Run workflow** ▾ → green **Run workflow** button

Ten to twenty minutes. Then download, at the bottom of the page,
`q21-windows-x86_64.zip` **and** `SHA256SUMS-signed`, and check the signature
before installing — the steps are in [SIGNING.md](SIGNING.md), section 4. A
red run, or a trusted comment that does not say `Q21 main <commit hash>`, is a
file you do not install.

---

# Upgrading from 0.4.0 to 0.4.1

0.4.1 is a drop-in replacement: same protocol (3), same chain, same data
directory. A 0.4.0 node and a 0.4.1 node talk to each other, and nothing is
converted. Replace the program, restart, and read the four changes below.

## Your wallet is a client unless you say otherwise

Up to 0.4.0, a wallet was **reachable by default**: it listened for incoming
connections, asked your router to open a port, and announced your public IP
address to its peers, which passed it on to every node of the network. An
address once announced cannot be called back.

Since 0.4.1, a wallet is reachable **only** if `settings.txt` says
`reachable=yes`, which is what the Network tab writes when you turn the
setting on. Concretely:

| Before the update | After |
|---|---|
| you never touched the setting | **client** (it was reachable) |
| you turned it off (`reachable=no`) | client |
| you turned it on (`reachable=yes`) | reachable, as you chose |

If you want your wallet to stay reachable, turn the setting on again in the
Network tab and restart the wallet. The tab no longer shows your public
address: only whether your router opened the port.

## Servers: the monitoring now keeps its measurement

The monitoring unit published up to 0.4.0 let systemd delete its state file
after every run, so every run took its first measurement again and a stuck
node was never noticed. If you installed it, add one line to the unit:

```bash
sudo sed -i 's/^RuntimeDirectory=q21-monitor$/RuntimeDirectory=q21-monitor\nRuntimeDirectoryPreserve=yes/' /etc/systemd/system/q21-monitor.service
sudo systemctl daemon-reload && sudo systemctl start q21-monitor.service
sudo cat /run/q21-monitor/state
```

The last command prints the height and the time it was recorded. Ten minutes
later, the height must have grown. `tools/monitor.sh` itself did not change,
only its comments: an installed copy can stay.

## A 0.3.x bootstrap file next to the program is read again

The 0.4.0 migration renamed the bootstrap file of the data directory, not the
one that 0.3.x archives put **next to the program**. A server upgraded by
replacing its binary only, with that old file still beside it, started with no
address to contact. 0.4.1 reads it again when no `bootstrap.txt` stands next
to the program, and says so at startup:

```
  bootstrap: reading the 0.3.x file /opt/q21/amorces.txt. Rename it to bootstrap.txt next to the program.
```

Rename it, or replace it with the `bootstrap.txt` of the archive, which names
the current entry points.

## The release page lists only what you need

The archives, `SHA256SUMS` and `SHA256SUMS.minisig`. The separate `.sha256`
files are gone: their content is in `SHA256SUMS`, which is the signed one.

## Updating a server

The service and its options do not change. Download, check the signature as
in [SIGNING.md](SIGNING.md), then:

```bash
sudo systemctl stop q21
sudo install -o root -g root -m 0755 q21 /opt/q21/q21
sudo systemctl start q21
sudo /opt/q21/q21 version
```

---

# Upgrading from 0.3.x to 0.4.0

Version 0.4.0 moves the program to English: file names, options, commands
and messages. It also **restarts the public testnet from a new genesis
block**. Your seed, your passphrase, your backup code and your addresses do
not change; your testnet coins do not carry over, since they belong to the
old chain. Here is what happens, and the one thing you have to do by hand if
you run a node as a service.

## The testnet starts again

The genesis message changed in 0.4.0, so the testnet has a new genesis block:

```
testnet  e310676c854f693693008d7270b583092c065051f73dc33b245676d804d77227
```

`q21 genesis testnet` prints it. On first start, 0.4.0 finds the blocks of the
old chain in your data directory, puts them aside in `old-chain-<id>/` — nothing
is deleted — and starts the new chain at height 0. Your wallet is the same
wallet: the same seed, the same addresses, on a new chain. Testnet coins have
no value; mine again to get some.

## Your data directory is upgraded on first start

Close the 0.3.x program first. Then start 0.4.0 on the same data directory —
`q21-data` next to the program, or the folder you give with `--datadir`. The
folder keeps its name; only the files inside are renamed, once, before
anything else reads them:

| 0.3.x | 0.4.0 |
|---|---|
| `reglages.txt`, `joignable=oui` / `joignable=non` | `settings.txt`, `reachable=yes` / `reachable=no` |
| `wallet.ancre` | `wallet.anchor` |
| `amorces.txt` | `bootstrap.txt` |
| `entetes.dat` | `headers.dat` |
| `ancienne-chaine-<id>/` | `old-chain-<id>/` |
| `.verrou` | `.lock` |
| keys of `adoption.txt` | English keys |

`wallet.dat`, `blocks.dat`, `state.dat` and the other files keep their names.
Each action is printed at startup, for example:

```
  data directory upgraded: reglages.txt -> settings.txt (reachable=no)
  data directory upgraded: amorces.txt -> bootstrap.txt
```

If a 0.3.x program is still running on the same directory, 0.4.0 refuses to
start instead of renaming files under its feet:

```
error: an older q21 (0.3.x) is still running on <directory>. Close it, then start this version again.
```

If both `amorces.txt` and `bootstrap.txt` exist — a new archive unpacked over
the old folder — the addresses you had added yourself are appended to
`bootstrap.txt`, under a `# Carried over from amorces.txt` line.

## Your wallet file is converted the first time you open it

`wallet.dat` is sealed by your passphrase, so it cannot be converted before
you type it. The first time 0.4.0 opens your wallet, it rewrites it in the
0.4 format and says so:

```
  Wallet converted to the 0.4 file format.
```

| 0.3.x | 0.4.0 |
|---|---|
| sealed format `Q21SCEL2` | `Q21SEAL3` (same Argon2id protection) |
| keys `serie=`, `verifie_jusqu_a=`, `consommes=`, `reserves=`, `etiquettes=`, `demandees=` | `serial=`, `verified_up_to=`, `consumed=`, `reserved=`, `labels=`, `requested=` |
| seed fingerprint in `wallet.anchor` | recomputed under the new label |
| `addresses.dat` cache | re-authenticated under the new key |

Your seed, your addresses, your address book and the list of one-time keys
already used are carried over unchanged. **Do not go back to 0.3.x
afterwards**: it cannot read the converted file, and it could not join the
new testnet anyway.

## "Not reachable" stays not reachable

If you had told your wallet not to accept incoming connections (`joignable=non`
in `reglages.txt`), 0.4.0 keeps that choice: it becomes `reachable=no` in
`settings.txt`. Any old value other than `oui` becomes `no`, the more private
choice, and when both files exist, a `no` in either one wins. If the setting
cannot be written, the program stops rather than start with the default — which
would open your router port and publish your address.

## Update your systemd units

0.4.0 keeps no alias for the old names: an old option is now an error, and a service
started with one fails at every restart (`error: unknown option: --reseau`).
Edit `ExecStart=` in your units:

| 0.3.x | 0.4.0 |
|---|---|
| `--reseau` | `--network` |
| `--amorce` | `--bootstrap` |
| `--sans-amorces` | `--no-bootstrap` |
| `--elaguer` | `--prune` |
| `--index-adresses` | `--address-index` |
| `--ouvrir-box` | `--upnp` |
| `--silencieux` | `--quiet` |
| `--fils` | `--threads` |
| `--pairs` | `--peers` |
| `--rpc-token-fichier` | `--rpc-token-file` |
| `--phrase-fichier` | `--passphrase-file` |
| `--code-fichier` | `--backup-code-file` |

The commands follow suit: `genese` → `genesis`, `explorateur` → `explorer`,
`instantane` → `snapshot`, `revalider` → `revalidate`, `securite` →
`security`, and `portefeuille` is gone (use `wallet`). For example, the entry
point's line becomes:

```ini
ExecStart=/opt/q21/q21 --datadir /opt/q21/data node --network testnet --listen 21121 --no-bootstrap
```

Keep your existing `--datadir` and `ReadWritePaths=` as they are: the folder is
upgraded in place, it does not need to move. Then:

```bash
sudo systemctl daemon-reload && sudo systemctl restart q21
```

If you use the monitoring script, it is now `tools/monitor.sh` (formerly
`outils/surveiller.sh`); [SERVER.md](SERVER.md) gives the new unit files.

## 0.3.x and 0.4.0 nodes do not talk to each other

0.4.0 speaks protocol version 3. A 0.3.x node (protocol version 2) is
disconnected at the handshake, without penalty. Upgrade every node you run —
the entry point included — and tell the people who join through yours: a
0.3.x wallet will find no peers on a 0.4.0 network.

## Snapshots exported by 0.3.x must be exported again

The labels of the state commitment changed, so every state commitment
published by 0.3.x changes too. A snapshot exported by 0.3.x
(`instantane exporter` or `instantane exporter-amorce`) no longer loads in
0.4.0: export it again from a 0.4.0 node with `q21 snapshot export` or
`q21 snapshot export-sync`, and publish the new commitment. Your own
`state.dat` is carried over: it is relabeled after a full check, or rebuilt
from the blocks if it cannot be. A node that started from a 0.3.x snapshot
keeps its trusted commitment, and `q21 revalidate` still checks it.

---

# What changes for you

## The explorer: phase 3

A single search field, at the top of the page. Paste anything into it:

| What you paste | What you get |
|---|---|
| `276` | The block at that height |
| A 64-character identifier | The block, or the transaction |
| A `tq211q…` address | Its balance and all its movements |

Four pages linked to one another: from a block you click on a transaction,
from that transaction you click on an address, and the browser's "back" button
takes you back.

**You have nothing more to launch.** Your wallet already serves the explorer,
at the same place and on the same port: the link is at the bottom of the page.

And if you want to look at the chain *without* opening a wallet:

```
q21 explorer
```

No method capable of moving funds is served then — not disabled by a setting,
absent.

## Address search, and its honesty

Finding all the transactions of an address is expensive: nothing in a
blockchain links an address to its transactions. You have to go through all of
them.

`q21 explorer` therefore builds an **index** at startup, and the search is
then complete. Your wallet does not do it by default — that would make you pay
in disk space and in writes for a convenience it does not need. Add
`--address-index` if you want it there too.

In both cases **the page always says which of the two paths was used**:

> **Bounded history.** Search went back to block 12400 of 14400. The balance
> shown stays exact: it comes from the set of unspent outputs, not from this
> list.

The balance itself depends on no index: it comes from the unspent outputs that
your node keeps up to date anyway. It is exact in every case.

## Two Q21 programs can no longer damage the same folder

This is the most important fix in this version, and it comes from a
reproduction: your wallet could become **impossible to open**.

The case is ordinary. The wallet is running in its window; you open a second
window and run `q21 mine` to confirm a transaction. Two programs then write the
same wallet file. They trip over each other, and at the next start you read
this:

```
error: this wallet carries serial number 6, whereas this
             directory has already seen a more recent one (7).
             This is the signature of a restore from an old backup.
```

An alarming message, an intact wallet: it is a **counter** that diverged, not
your funds. But you had no way of knowing that.

Now, the second program is politely refused:

```
error: another q21 is already using this data directory.

  Directory: q21-data

  Two programs that write the same wallet and the same block file
  damage both. Close the other window — the "Close the wallet"
  button on the Info tab, or the window's close button — then start
  this one again.
```

> **If you run into the serial-number message on your current installation**:
> delete the `wallet.seq` file in the `q21-data` folder. Your Q21 and your
> seed are intact. Checked: the wallet reopens with its whole balance.

## Your wallet file can no longer be cut in half

It used to be erased and then rewritten. An interruption between the two — a
dead battery, an abrupt shutdown — left an empty file, in other words a lost
seed. Now it is written next to the old one, then renamed in one go: either
the old version or the new one, never a mix.

## You no longer need Ctrl-C

In the wallet, **Info** tab, at the very bottom: a **"Close the wallet"**
button.

A first click asks for confirmation, a second one closes. The node writes its
pending transactions, its state and your wallet, then stops. The black window
closes on its own.

**Closing the black window** with its close button works too: it is
intercepted the same way.

## The "Terminate batch job (Y/N)?" message

This is what got you stuck, and **it was not a malfunction**.

This message does not come from Q21. It comes from Windows: when you press
`Ctrl` + `C` while a `.bat` file is running, the command interpreter asks
*its own* question before handing control back. No line of the file can
prevent it — it comes before the script has any say.

At that point, **everything is already saved**. The proof is just above it, on
the screen:

```
  Shutdown requested. Writing...
Stopped. Final height: ...
```

These two lines mean that Q21 intercepted your `Ctrl` + `C`, wrote what it had
to write, and stopped cleanly. The Windows question comes **after**.

**Answer `Y`.** You lose nothing.

And now you no longer have to: the button exists.

## The passphrase is asked for first

Before, the screen displayed the address, "leave this window open", then
suddenly a bare line:

```
Wallet passphrase:
```

With nothing to announce it, after telling you that everything was running.
That was the wrong order. Now the window says it right away:

```
Q21 Wallet

  This wallet is protected by a passphrase.
```

and the passphrase is typed into the page that the browser opens, before
anything else. The wallet's address is only displayed **after** — when the
wallet is really open. A wrong passphrase fails right away, on that page,
instead of opening the wallet on a page that would be of no use.

## The window says how to stop it

The three ways, written out in black and white at startup:

```
  To stop, either:
    - the "Close the wallet" button, Info tab;
    - close this window;
    - Ctrl-C here. Windows then asks "Terminate batch job
      (Y/N)?": answer Y. This is not an error,
      everything is already saved when this question appears.
```

---

# The command that will save you round trips

```
q21 wallet --mine
```

The wallet **and** mining at the same time. Your transactions confirm on their
own within a few seconds, without stopping anything.

If you go through the double-click file, mining is not enabled — that is on
purpose, it would keep your processor busy all the time.

---

# What is still imperfect

- No QR code for receiving addresses
- The history goes back 5,000 blocks, no further — the page says so when it
  stops there
- The files are still not code-signed: Windows and macOS will display their
  warning, and they are right to do so
