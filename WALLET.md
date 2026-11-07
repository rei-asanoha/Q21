# The Q21 wallet

Desktop software to receive and send Q21, on macOS, Windows and Linux.

## In two commands

```bash
./q21 init testnet     # creates the wallet, shows the backup code
./q21 wallet           # opens the interface in the browser
```

The first command asks for a passphrase, then shows a 66-character **backup
code**. Copy it onto paper before going any further: it is the only way to
recover your funds if the file disappears.

## Restoring from the backup code

```bash
./q21 --datadir <empty-folder> restore testnet
```

The code is asked for at the terminal, **without echo**. It is never accepted
as an argument: a command argument is written to the terminal history
(`~/.bash_history`, in plain text, often backed up), readable by any account
on the machine in `/proc/<pid>/cmdline` for the whole run, and recorded by
audit logs — and this code *is* the seed: whoever reads it holds the funds,
with no time limit. `q21 restore <code>` is refused, with an explanation of
why and what to do instead.

Without a terminal — a service, a script — the code is read from a file only
you can read, with the same permission check as `--passphrase-file`:

```bash
chmod 600 code.txt
./q21 --backup-code-file code.txt --passphrase-file passphrase.txt restore testnet
rm code.txt
```

The setup page (`q21 wallet` in an empty folder) offers the same restore: the
code goes through the body of a local request, never through an address or a
command line. A code with a single wrong character is not accepted, and the
message says which group of four to check on the sheet.

**What the code restores, and what it does not.** The balance, every address
and the names come back from the code alone. A payment channel lives in its
journal, beside the wallet in the data folder, and the code does not hold it:

- a channel still open when the disk was lost comes back once the other side
  closes it. Its close pays our side to a channel key derived from the seed,
  and the node claims it back to the wallet on its own (`recover_key_outputs`;
  the 200 first keys of each kind are looked at, more if channels went
  further). Ask the other person to close the channel;
- a data folder restored from an **older copy** is recognised the first time
  the channel reconnects: the copy refuses to pay or to close, and says why.
  The other side, which holds the latest state, is told, and its holder
  closes from the page, once they confirm that their own wallet was not
  restored from a backup either (since 0.5.9: a node that closed by itself
  could be led by a peer showing an even older copy to broadcast a revoked
  state); our side then comes back to the wallet. Closing such a copy alone would have broadcast a state
  it had already revoked, and lost the whole channel to the penalty. Since
  0.5.5 the other side proves it: it sends back our own revocation secret of
  the latest state the copy holds, which only we could have revealed. The
  proof makes the refusal final. A claim without a proof holds the copy back
  only while the peer keeps making it: a peer that says we are behind when
  we are not can no longer freeze the channel for good. A peer older than
  0.5.5 proves nothing, and its word is still taken; a peer can also pass
  itself off as older, so this protects against a mistaken peer more than
  against a hostile one. Either way,
  the funds of an older copy come back only through the other side: it must
  be online to close.

  A copy of a data folder is therefore never a backup of a channel: restore
  the wallet from its code, never an old copy of its `channels` folder. A
  peer that answers as an old copy would, or says nothing, cannot be told
  apart from an honest one by the copy itself (red-team campaign 8).

`checkbackup` (the wallet page: Info → Check my backup) checks the sheet
against the wallet at any time, long before the day it is needed.

## What the data directory remembers

Next to `wallet.dat`, the directory holds two small files that contain no
secret:

- `wallet.seq`, the **serial number**: a `wallet.dat` older than what the
  directory has already seen is refused — it is the signature of a restore
  from an old backup, which would make one-time keys sign again.
- `wallet.anchor`, the **anchor**: "this directory has seen a wallet sealed
  by a passphrase" — and that is not forgotten — plus a public fingerprint of
  the seed (`HMAC(seed, "Q21-DATADIR-v1")`, which says nothing about the seed
  but is enough to recognize a different one).

The anchor closes a substitution that the v2 audit demonstrated: a
**plaintext** `wallet.dat`, from another seed, carrying the right serial
number, was adopted without a passphrase and without a word — the process
switched to plaintext, and mining and the balance became those of the
foreign seed. Now:

- an unsealed file in a directory that has known a sealed one is refused:
  "this directory was protected by a passphrase; this file is not";
- a file from a seed other than the one the directory has known is refused,
  unless `--accept-other-seed` is given, to be kept for the case where *you*
  replaced the file — the directory then remembers the new seed.

This is not a defense against someone who can also delete `wallet.anchor`:
it is the same limit, already accepted, as the serial number. An older
directory, without an anchor, acquires one at its first write. A restore into
an empty directory is not affected.

### One-time keys: reserved is not revealed

With Lamport (test networks), the index of a coin being spent is written to
disk **before** signing — that is what prevents signing again after a crash.
But a reserved index carries the coin being spent: counting it as consumed
from the moment of reservation froze that coin forever if the process died
between the reservation and the broadcast, without any signature ever having
existed. The file therefore distinguishes the two: `consumed=` carries the
revealed keys *and* the reserved indices (a binary that does not know
`reserved=` treats them all as consumed, which is the cautious direction), and
`reserved=` says which ones are only reserved, with the height of the
reservation. At startup, and regularly in the node, a reservation is checked against the
chain: if a signature is found in a block, the key is consumed; if nothing
appears after twenty blocks, the index becomes free again and the coin
spendable.

Sending itself happens in three steps: reserve under the chain lock, write
the wallet **outside** that lock (the Argon2id sealing takes a third of a
second, during which the node keeps validating and serving its peers), then
take the lock again to check that the coins are still there, sign, and put
the transaction in the mempool.

ML-DSA signatures are produced in the "hedged" variant (FIPS 204): thirty-two
bytes of system randomness go into each signature, two signatures of the same
message differ, and if randomness is unavailable the wallet **refuses to
sign** rather than fall back to the deterministic variant. The verifier
accepts both; nothing changes for the network.

The directory itself is created with mode `0700`, and tightened at startup if
it is looser; `wallet.dat`, `wallet.seq`, `wallet.anchor`, `addresses.dat`
and `mempool.dat` are `0600`, and the temporary file through which every
wallet write goes is **born** `0600` — it never exists, at any moment, with
another mode. On Windows, the equivalent is set by `icacls` before the first
byte is written.

---

## Three decisions, and why

### The wallet embeds a full node

A light client asks a server what the chain contains. That is, it **trusts
someone** to know its own balance — in a system designed precisely to trust
no one.

Here, the wallet *is* a node. It validates every block itself. What the
screen shows, this machine has verified.

The price: on first launch, it downloads and verifies the chain. On the
testnet it is instant; on a mature network it will take a long time. It is
the same tradeoff as Bitcoin Core, and it leans the same way.

### The interface is a locally served page

The binary serves a page on `127.0.0.1` and opens the browser on it. No
graphics library, no application framework, no new dependency in software
that holds private keys. This is what Electrum and most hardware wallets do,
for the same reason.

The page loads **no external resource**: no font, no script, no image from
anywhere else. Everything is in the file, and a test checks it.

### The token travels in the fragment of the address

The interface needs a token to talk to the node. Putting it in the query —
`?token=...` — would put it in the browser history, in the logs of any
intermediary, and in the `Referer` header of the first external resource
loaded. A secret that travels in an address is no longer a secret: it is a
flaw that the phase 8b audit found and then closed.

The **fragment** — what follows the `#` — is never sent to the server. The
browser keeps it to itself. The page reads it, immediately erases it from the
address bar, and then sends it as `Authorization`. It leaves no trace
anywhere other than in the tab's memory.

This fragment is not the token itself. The address goes through the command
line of the browser launcher, which other accounts on the machine can read;
what it carries is therefore a **one-time launch token**, which the page
exchanges at load time for the session token, and which the node destroys
immediately. See `HARDENING.md`, the section on the wallet on a shared
machine.

**A link works only once, but a tab can be reopened as long as the program is
running.** The session token, once obtained, is stored in the browser's
`localStorage`, partitioned by origin — hence by port, drawn at random at
each launch. Close the tab by mistake, reopen the page from the history: it
picks up where it was, without asking anything. This storage survives
nothing useful: the token is drawn at each run and dies with it; what the
browser keeps after shutdown is an inert string, erased at the node's first
refusal. No cookie, no `indexedDB`, nothing else: the seed and the passphrase
never go through the page.

---

## Adding Q21 to a channel

An open channel holds what was put in at its opening. **Add Q21** (0.5.5)
puts more of either side's coins into the same channel, with the same person:
one transaction spends the channel's funding output and the coins added, and
pays a larger funding output to the same two keys (a *splice*). The channel
keeps its history and its revocations; the page shows the addition in the
channel's history.

How it stays safe:

- the side that adds signs the other side's first commitment on the new
  funding; the other side keeps it, signs the adder's, and only then signs
  the splice's input that spends the old funding. Neither can put the splice
  on chain while the other lacks a commitment it can close with;
- until the splice is buried six blocks past the funding depth (twelve
  blocks on the test network since 0.5.11; the funding depth on regtest),
  neither side revokes the last state on the old funding: a close without
  the other side broadcasts that state while the splice is not on chain, and
  the first new one once it is. A revoked older state is punished on either
  funding;
- no payment moves meanwhile, twelve blocks on the test network: the state
  is in flight until the chain buries it, and both sides then reveal the
  secret of the old state;
- if a coin the splice adds is spent elsewhere before it confirms, the
  addition can never happen: after the funding depth the page says so, and
  offers to close the channel without the other side, which is safe then
  (0.5.11);
- a payment of the other side that crosses the addition wins: the adder
  drops the splice, which nobody can complete without its signature, and the
  page says to add again;
- the adder pays the fee, from its own coins, as for an opening.

Both wallets need 0.5.5 or later; the button shows only then.

---

## Channels, closings and accidents (0.5.10)

- **A closed channel is closed.** Once its close is confirmed on the chain, a
  channel no longer counts toward the eight a contact may have open or in
  progress with you: a new one opens with the same person right away. It
  stays watched for about a day for your safety (a revoked state could still
  appear), and at most 32 closed channels per contact are watched at once;
  past that, the page says "you can open a new one tomorrow".
- **A power cut during a payment** can leave zeros at the end of a channel's
  journal. They are read as an unfinished last write, like the end of the
  block file: the channel loads and is watched as before. Until 0.5.9 it was
  neither loaded nor watched again, and the log said `ALERT … this channel is
  not loaded`.
- **A reorganization that takes a channel's funding off the chain** (rare,
  six blocks or more): the channel pays, signs and closes nothing until its
  funding is buried again to the depth agreed at the opening, and the page
  says so. The side that funded it holds its coins and announces the funding
  transaction again; a payment sent meanwhile goes through once it is back.
  Nothing is lost — unless a coin of the funding is then spent by another
  transaction, buried past any reorganization: the funding can never come
  back, the channel is given up, and it is archived as "given up" (0.5.11).
  The side that funded it keeps its coins, which never stayed in the
  channel; the other side gets nothing back of what it was paid in the
  channel. That takes a reorganization of six blocks or more and the funder
  spending its coins elsewhere.
- **A channel asked to wait for more confirmations than the longest delay**
  (a contact asking for 65,535 blocks, three months) is refused at the
  opening: such a channel never opened and blocked new ones meanwhile.

## The wallet page after the wallet stops

Each answer of the wallet to its page names the run of the program. A page
left open after the wallet stopped says **The wallet has stopped** and asks
nothing more: before 0.5.10 it kept calling its port, and another program of
another account listening there next could show its own receiving address in
it, or receive the backup code typed to check it. Start Q21 Wallet again: it
opens a new page; close the old one.

---

## My contacts

The Send page keeps the addresses you send to under a name of your own —
"Mum", "Exchange" — with a note if you want one (0.5.6). Each address is
checked by the node before it is kept: its checksum, which catches a typo,
and its network, so a testnet contact is never a mainnet address. An address
is kept under one name only, and two contacts cannot share a name — nor two
names drawn alike: "Mum" and "Мum" (a Cyrillic М) are one name, and the
second is refused with the name it copies. Names that differ only by an
accent are both kept, each shown with a warning to check the address
(0.5.7).

Choosing a contact fills in the address; the payment's recap shows the name
next to the address. After a payment to a new address, the page offers to
keep it. Renaming and removing ask first; removing a contact changes nothing
on the chain.

The book is written in `wallet.dat`, sealed with it, and never sent. It is
not in the backup code: a wallet restored from the code starts with an empty
book. It is not the card of the Private channel either, "My verified
contacts", which holds people reached through a channel and checked with
words read aloud.

RPC: `addressbooklist`, `addressbookadd` (`name`, `address`, `note`),
`addressbookupdate` (`address`, `name`, `note`), `addressbookremove`
(`address`).

---

## What protects the wallet

| Defense | What it prevents |
|---|---|
| Check of the origin, `Referer` and `Sec-Fetch-Site` | A hostile web page that would spend your funds behind your back |
| `Content-Type: application/json` required | CSRF through an HTML form, which needs no JavaScript |
| Check of the `Host` header | DNS rebinding, which would make a hostile page same-origin |
| Token required on every RPC method | Another program on the machine |
| Listening on the loopback only | The rest of the network |

These five locks have been put to the test by 42 real attacks, over TCP, in
`tests/audit_rpc.rs`. Each one was an exploit that worked.

**The data folder (0.5.11).** It is made readable by its owner alone, at
every start. On Linux and macOS, the wallet refuses to start on a data folder
that belongs to another account (root excepted), or that holds a file of
another account or a file with a second name (a hard link), in it, in
`channels/` or anywhere under `tor/`: another account could have planted a
peer list or an onion key there. The message names the file; move it out and
start again. Two honest setups meet this too: a folder on a network share
that maps files to `nobody`, and a backup made with hard links (`cp -al`)
inside the data folder. On Windows, a data folder outside your user folder
is restricted to your account; inside it, Windows already keeps others out.
On disks without owners (FAT, exFAT), nothing can be checked.

---

## What a first user found

The wallet was put in the hands of someone who had not written it. Within a
few hours, eleven defects came out. None would have been found otherwise. Two
more appeared while reproducing one of these scenarios end to end — and two
more, including the worst of the list, the day the wallet ran on **two real
machines** instead of one.

| # | What was wrong | Fix |
|---|---|---|
| 1 | A sent transaction disappeared at shutdown | The mempool is written to disk (`mempool.dat`) and revalidated on restart |
| 2 | **No Ctrl-C handler**: the process was killed without writing anything | `src/shutdown.rs` — the tested shutdown path was not the path actually taken |
| 3 | `q21 mine` ignored the mempool and mined empty blocks | Pending transactions go into mined blocks |
| 4 | A command window was needed | *Q21 Wallet* is double-clicked |
| 5 | Refreshing the page, or closing the tab, broke the session | The token survives in the browser, partitioned by port, as long as the program runs |
| 6 | Status lines drowned the address to open | Quiet mode in the wallet |
| 7 | The history did not show the amount sent | **Sent** column, and the page no longer contradicts the node |
| 8 | Double-clicking `q21.exe` showed the help and closed | Without arguments, `q21` opens the wallet |
| 9 | The address was shown only if the browser was not opened | It is always shown |
| 10 | The passphrase was asked for **after** the banner, with nothing announcing it | Unlocking comes before everything else |
| 11 | The only possible shutdown was Ctrl-C, and Windows then asked a question that looked like a failure | **Close the wallet** button, `stop` method |
| 12 | Two simultaneous writes of the wallet left `wallet.seq` ahead of `wallet.dat` — the wallet refused to open | In-process write lock, and `src/lock.rs` between processes |
| 13 | `wallet.dat` was truncated before being rewritten: a power cut at the wrong moment lost the seed | Write to a temporary file, then atomic rename |
| 14 | The **Status** tile displayed its own markup as text | `badge()` constructor, and a test on every tile of both pages |
| 15 | **A dead peer was never disconnected**: the node stayed stuck at its height, forever | `Ping` after 45 s of silence, disconnect after 100 s, and fall back on the bootstrap addresses |
| 16 | On waking from sleep, one had to wait for the silence timeout | A loop iteration that lasts a minute betrays a sleep: everything is disconnected at once |

The fifteenth is the most serious of the whole list, and it could only appear
on real hardware.

The user closed the lid of their MacBook, opened it again, and **the chain
never moved again**: height 442, while the other machine mined up to 455.
Three transfers sent in the meantime never arrived.

The cause comes down to one line. The read loop set a 120-second timeout on
the socket, and handled its expiry like this:

```rust
Err(e) if e.kind() == WouldBlock => continue,
```

That is: it started waiting again, indefinitely. A peer that stops sending
was therefore **never** removed. The peer count stayed at one, and the
maintenance loop — which looks for no one as long as it is not short of
peers — had nothing to do.

A TCP connection can outlive the machine on the other end. A laptop whose lid
is closed says nothing on its way out: no `FIN`, no `RST`. The only reliable
sign of life is **a received frame**, and that is now what is measured.

On a public network, the same defect was an eclipse route: opening
connections and then going silent was enough to occupy all of a node's slots.

The twelfth and thirteenth came out of a reproduction, not a report. They
deserve to be told because they illustrate the same mistake.

Writing the wallet takes four steps: read the serial number, seal the
content, write `wallet.dat`, write `wallet.seq`. Sealing costs an Argon2id
derivation — a few hundred milliseconds during which the number read at the
start grows stale. Two concurrent writes then interleave like this:

```text
  thread A  reads seq=5, serial=6, starts sealing ......................
  thread B  reads seq=5, serial=6, seals, writes wallet(6), writes seq=6
  thread B  reads seq=6, serial=7, seals, writes wallet(7), writes seq=7
  thread A  ..... finishes and writes wallet(6)   <-- overwrites version 7
```

What remains is a `wallet.seq` at 7 and a `wallet.dat` at 6. At the next
startup, the anti-replay protection **does exactly what it is asked to do**:
it refuses to open the wallet, announcing a restore from an old backup. The
wallet is intact; the user, however, reads that they may have revealed their
one-time keys.

The same scenario exists between two **processes** — the wallet in its
window, `q21 mine` in another — and there, it is not only the two wallet
files that diverge, but also `blocks.dat` and its index. Hence two locks: a
mutex for the threads of a single process, and a file lock set by the system
(`flock`, `LockFileEx`) between processes. The second is released by the
system however the process dies — which is the reason not to build it by
hand with a `.lock` file carrying a process number, which would leave a ghost
lock after every abrupt stop.

> **If you run into the serial inconsistency message** on an earlier
> version: delete `wallet.seq` in the data directory. The seed and the funds
> are intact — it is the counter that diverged, not the wallet.

The eleventh deserves a closer look, because it is not in the code.

A `Ctrl-C` received while a `.bat` file is running makes the command
interpreter ask its own question — "Terminate batch job (Y/N)?" — to which
both answers close the window. It comes **before** the script gets control:
no line of the file can prevent it.

The shutdown handler was doing its job. The lines "Shutdown requested.
Writing..." then "Stopped. Final height" proved it, on screen, just above.
But the user read Windows' question as an error, and stopped daring to shut
down their wallet. Software that people no longer dare to use is broken,
whatever the code says.

The fix is therefore not to silence Windows — that is impossible — but to no
longer go that way: an application is closed with a button. It raises the
same flag as `Ctrl-C`, the main loop sees it on the next iteration, writes
and returns. Nothing is interrupted, and the interpreter has no question to
ask.

The second is the most instructive technically. Persistence of the mempool
had been written **and tested** — but only on the shutdown path of the tests,
the expiry of `--seconds`. Nobody stops software that way: people press
Ctrl-C. On that path, nothing was written, and the fix would have been
useless.

## What the wallet still does not do

- **The history is complete only with the address index.** The wallet
  builds it by default since 0.4.2. Started with `--no-index` (or `--prune`),
  it goes back 5,000 blocks. The response says so, and the screen shows it.
- **The wallet and mining only coexist with `--mine`.** Without this option,
  a transaction waits for someone to mine, and mining requires stopping the
  wallet. `q21 wallet --mine` does both at once.
- **There is no QR code** for the receiving address. The content security
  policy forbids external images, and drawing it in SVG remains to be done.
- **The released files are neither signed nor notarized.** macOS and Windows
  will show a warning. Getting around it requires a paid Apple Developer
  account and an Authenticode certificate. In the meantime, the SHA-256 hash
  of each file is published with it.

---

## Building it yourself

```bash
cargo build --release
```

ML-DSA is included by default; `--features mldsa` is still accepted and
changes nothing.

The sources of `ml-dsa` are in `vendor/`, and `.cargo/config.toml` redirects
crates.io there: the build depends on no network, and two builds two months
apart use exactly the same signing code.

Without the `mldsa` feature, the binary compiles but can only sign with
Lamport — usable on a test network, never anywhere else.

## Automatic builds

`.github/workflows/release.yml` builds the five files — macOS Apple Silicon,
macOS Intel, Windows, Linux, Linux ARM 64 — on real machines, for every
version tag. No cross-compilation: nothing is assumed.

`.github/workflows/ci.yml` runs the tests on all three systems on every push.
The three audit files still open — arithmetic, difficulty, mempool — run
separately, without blocking, and their output is published: anyone who
opens the run sees exactly what remains.

---

## Warning

Research code. The memory-hard proof of work has received **no external
cryptanalysis**, and the audit that closed 21 flaws was carried out by the
authors of the code on their own code. That proves its usefulness; it proves
nothing about what it did not find.

Do not entrust any real value to this software.
