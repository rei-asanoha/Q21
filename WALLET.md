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
command line.

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

- **The history is bounded.** Without a per-address index, it goes back 5,000
  blocks. The response says so, and the screen shows it.
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
