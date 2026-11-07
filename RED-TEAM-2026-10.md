# Tenth Q21 campaign — six reviewers on the 0.5.11 candidate (0.5.11)

*The 0.5.11 candidate — 0.5.10 with the two points it left open (C1, a
finished splice undone by a deep reorganization; C7, a channel whose funding
can never come back) and the wallet page's block pace — attacked by six
reviewers, each with one way of thinking: the architect (invariants, trust
boundaries, consensus and the chain), the suspicious one (everything trusted
without checking: the release and update chain, files on disk, the server
guides), the pragmatic one (the cheapest attack with the biggest effect on
the documented deployment), the persevering one (every fix re-attacked,
every restart, kill and truncated file), the tactician (multi-step attacks
across channels, names, contacts and reorganizations) and the regulator
(the money, everywhere, and what the documents promise). They worked alone,
then as a team on one board, in four rounds: each round attacked the binary
built from the previous round's fixes.
Rules: nothing that creates money, takes control of anything, or slows the
real network — every attack ran in a local lab.*

*As in the previous campaigns, a finding is CONFIRMED only when it was run
against the real code or the real binary; every confirmed attack in the node
became a test, checked to fail without its fix, or was run again in the lab
on the next round's binary.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| A1 | 🔴 HIGH | Side-branch blocks were stored after their shape and work only: a branch forking deep below the tip, its difficulty walked down, let a peer store four megabytes on every node's disk for a 2,500th of a block's work, as often as it liked | Fixed; three follow-ups in rounds 2 to 4, closed |
| P1 | 🔴 HIGH | One visitor kept a public explorer down: each input's coin read a whole block, under the node's lock, charged one call | Fixed; five follow-ups in rounds 2 to 4, closed |
| T1 | 🔴 HIGH | A splice undone by a six-block reorganization, its added coin spent elsewhere, froze the other side's whole balance on an old funding where every state was revoked | Narrowed: an addition locks six blocks past the funding depth; residual below |
| M1 | 🟠 MEDIUM | A revoked state on a splice's old funding, mined below the splice's height, went unpunished after a restart | Fixed |
| M2 | 🟠 MEDIUM | An evicted side body stayed known and was never fetched again: the node waited for a restart to follow the majority | Fixed |
| M3 | 🟠 MEDIUM | A lighter chain ramped to sixteen times the honest difficulty, shown to one node, kept it off the heavier chain for good (round 2, from the A1 fix) | Fixed |
| M4 | 🟠 MEDIUM | A node back after more than a day was bound from the old tip it came back with: its first peer could lock it out of the real chain for good (round 4) | Fixed |
| M5 | 🟠 MEDIUM | An addition whose added coin was spent elsewhere waited for good, payments and closes refused | Fixed |
| M6 | 🟠 MEDIUM | The servers ran `tools/monitor.sh` as root, copied from the repository, outside the signature | Fixed |
| M7 | 🟠 MEDIUM | A `bcrypt.dll` left in the folder the Windows archive is extracted into ran at every launch | Fixed for static imports |
| M8 | 🟠 MEDIUM | A data folder created or written by another account was used, its files read back at startup | Fixed |
| M9 | 🟠 MEDIUM | The explorer's charge by size never put a visitor in debt; a search by amount read two thousand blocks in one hold of the lock; debts were shed by rotating addresses; two hundred addresses together kept every turn busy | Fixed |
| L1 | 🟡 LOW-MEDIUM | Rolling finality bound only after one uninterrupted hour in one run: a wallet opened forty minutes a day never bound | Fixed |
| L2 | 🟡 LOW-MEDIUM | `getbalance` counted coins already spent by a pending send of ours, and coins held for a channel | Fixed |
| L3 | 🟡 LOW-MEDIUM | A channel given up (C7) was archived as an ordinary close, the acceptor's lost balance shown as "came back" | Fixed |
| L4 | 🟡 LOW-MEDIUM | "Earned by mining" counted blocks that lost their race | Fixed |
| L5 | 🟡 LOW | C7 did not apply to an acceptor restarted while funded, down at the funding's confirmation, or with a channel opened before 0.5.11 | Fixed |
| L6 | 🟡 LOW | The adder's coins were not held again for a finished splice a reorganization took away | Fixed |
| L7 | 🟡 LOW | A funder's signed `Ready` kept an unfunded inbound channel from expiring | Fixed |
| L8 | 🟡 LOW | A share of a forced close too small for a claim the pools relay was claimed again at every block, the channel closing for good | Fixed |
| L9 | 🟡 LOW | A contact added by its name stayed bound to whoever held it at that moment, and kept showing the name after a reorganization gave it to someone else | Fixed |
| L10 | 🟡 LOW | `getemission.permille_of_cap` was a hundred times too high and saturated; `preparesend` showed a dust change as change; the explorer's texts on maturity, cut lists and unresolved fees | Fixed |
| L11 | 🟡 LOW | The published-release check used the tagged commit's script and key, and never checked the commit was on `main` | Fixed |
| L12 | 🟡 LOW | No warning before the servers' disk is full; the data folder created readable by every account | Fixed |
| L13 | hardening | Way B of the public explorer built Caddy from an unpinned module, never updated again | Documented |

**No money creation, no theft, no signature forgery and no remote takeover
was found.** The emission, the cap of 21,000,001, the UTXO set against the
issued total after reorganizations and restarts, and the release chain held
throughout. The rules of block validity are unchanged since 0.5.6.

---

## A1, M2, M3. Side branches

A branch may fork up to 720 blocks below the tip. Dated four target spacings
after its parent until it reaches the present, every block of it satisfies
the timestamp rules, and its difficulty falls to about a 2,500th of the
network's after some two hundred blocks, for the price of some twenty honest
ones. From there, every sibling of a block of that branch cost the same
2,500th, and a side block was stored after its shape and its work only: its
transactions are checked only when it is connected. Forty-eight junk blocks
of four megabytes each, children of one parent, grew a lab node's
`blocks.dat` by 193 MB, for good.

**Fix.** A block of a branch that does not lead is refused without blame
when its work is under a sixteenth of the active block its branch forks
from — the last difficulty both sides shared. A side block is written to
disk only when its branch is within six blocks of the tip's work; side
bodies otherwise stay in memory under their own 64 MiB, evicted first. A
side body evicted and later needed is forgotten and asked for again; the
blocks of a branch proven heavier than ours are then written to disk as
they come, and so is a block that leaves its branch ahead of ours but is
held back by the depth surcharge.

Round 2 found that the first version, measured against the active block at
the side block's own height, could keep a node off the heavier chain: a
lighter chain of a few blocks ramped to sixteen times the honest difficulty
made every honest block above the fork read as too easy (M3). Round 3 found
that a heavier branch of large blocks outgrew the side budget before its
last block came, at every attempt; round 4, that a deeper one did the same
while its surcharge was not yet paid. Each is closed, and the last was run
again in the lab: a branch 30 blocks deep of 4 MB blocks is adopted at the
second send.

## P1, M9. The public explorer

What an input spent was found by reading the whole block of its coin, once
per input, under the node's lock, charged one call. An address with five
transactions of 242 inputs each cost seven seconds per `getaddress`; six
requests from one address, their sockets closed at once, kept the explorer
at "too many requests" for everyone and slowed the node's intake of blocks.

**Fix, over four rounds.** A block is read once per answer, and only its
outputs are kept; a public answer reads at most 32 MB and 400 blocks, and
its client is charged by what it read, a whole block read for one
transaction included. What exceeds a client's bucket is owed and paid back
before another call; a client that owes is the last to leave the table of
clients, which now holds sixteen thousand. A search by amount and the scans
without an index read block by block, the lock taken for each only. Answers
that read blocks take two of the four turns at most, so the others always
answer. A header is read from the index. The page says when a list is cut,
when waiting payments were looked through in part, and why a fee is
unresolved.

In the last round, two hundred addresses each paying exactly their debt
kept the four turns busy and honest calls waited four to nine seconds; the
turns kept for light answers close that.

## T1, M1, M5, L5, L6, L7. Channels

**T1.** Once a splice is locked, every state on the old funding is revoked.
Locked at the funding depth — six blocks on the test network, where a
reorganization costs no surcharge — a reorganization taking the splice
away while its adder spends the coin it added elsewhere left the other
side's whole balance on an old funding with only revoked states: it could
never close. An addition now locks six blocks past the funding depth, past
the surcharge's threshold, at the price of twelve minutes more without
payments.

**M1.** A restart scanned from the funding's recorded height, which is the
splice's after a splice: a revoked state on the old funding mined below it
went unpunished (lab: 5 Q21 lost, 8 swept by the cheater). The scan starts
below by the deepest reorganization.

**M5.** An adder that spent its added coin before the splice confirmed left
both sides waiting for good. After the funding depth, the addition is said
to be impossible, payments and cooperative closes say why, and the page
offers to close without the other side — safe then, since the last state on
the old funding was never revoked. The flag is set again at once after a
restart.

**L5 to L7.** The acceptor keeps its funding when it restarts as funded,
fetches it at startup when it was down at the confirmation or opened the
channel before 0.5.11; the adder holds the coins of a finished splice again
while a reorganization keeps it out, and releases them once the old funding
is spent; a funder's `Ready` on a channel not yet open journals nothing.

C1 and C7, the points 0.5.10 left open, are in this version: a finished
splice is kept, its old funding watched and a revoked state there punished,
until the new funding is buried past any reorganization; a channel whose
funding left the chain and a coin of which was spent elsewhere, buried past
any reorganization, is given up on both sides and archived as given up.

## M6, M7, M8, L11, L12, L13. The release, the servers, the local computer

`tools/monitor.sh` runs as root every ten minutes on the servers, and was
copied from the repository — the very thing the offline signature exists
not to trust. It now travels in the Linux archives under `server/`, with the
server guides, compared byte for byte by `verify-release.sh`, and
`SERVER.md` installs it from the verified archive. The check after
publication uses `main`'s script and key, on a commit of `main`.

`q21.exe` imports `bcrypt.dll` statically, a library Windows looks for in
the program's folder first. Both Windows programs now resolve their static
imports from `System32` only.

A data folder created by another account, or one that was once open to
others, was used after a warning, its files read back at startup: a planted
`bootstrap.txt` chose the node's peers. A data folder owned by another
account (root excepted), or holding a file of another account or a file
with a second name, is now refused before anything is opened in it; every
data folder is tightened to 0700 at start, and `wallet.dat` to 0600.

`monitor.sh` warns when the data disk is nearly full. Way B of the public
explorer pins Caddy's version and its module's commit, and says the custom
binary must be rebuilt at every Caddy update.

## L1, M4. Rolling finality

Finality binds once a node has held a recent tip for an hour. The hold
counted one uninterrupted stretch of one process: a wallet opened forty
minutes a day never bound. The seconds held now add up across runs. And a
node that comes back with an old tip holds the hold again in that run
before finality binds it: bound from its record, measured from the old tip
it came back with, its first peer could extend that tip by a thousand
blocks of lowered difficulty and lock it out of the real chain for good.

## L2, L3, L4, L8, L9, L10. Money as shown

`getbalance.spendable` is now what a send can spend at once; `committed`
gives what a pending send or a channel holds. A channel given up is
archived as "given up": nothing came back to the side that did not fund it,
and the funder kept its coins; a crash between the two writes, or a later
compaction, no longer turns it into an ordinary close. Blocks that lost their
race are left out of the blocks found and the earnings. A share of a forced
close, or a channel key output, too small for a claim the pools relay is
left on chain as dust and the channel settled. A name is added as a contact
once six blocks deep, and shown only while it belongs to the contact.

---

## Rounds 2 to 4

Each round attacked the binary built from the previous round's fixes; the
findings above marked "follow-ups" came from these rounds. In the last
round the reviewers re-ran their confirmed attacks against the final
candidate: the side branch of large blocks is adopted, the explorer serves
honest calls while two hundred addresses read at their limit, the dead
addition is said right after a restart, the given-up channel survives a
compaction, planted files and links are refused, and the money audit — the
cap, the emission, names, balances against the UTXO set after a reorganization
and a restart, and every row of the 0.5.11 upgrade notes — holds.

## Open

- **A majority of the hash power rewriting twelve blocks** can still undo
  a locked splice and freeze the other side's balance on the old funding
  (T1). It is the model's own limit; both sides must run 0.5.11 for the
  longer lock.
- **Side branches of a weak minority**: a side with less than a sixteenth
  of the other's hash power, mining for hundreds of blocks while the
  stronger side then stops altogether, would be held back — the same kind
  of prolonged partition rolling finality already gives up on.
- **The channel archive's figures** ignore the real close, sweep and claim
  fees, and book an addition by the other side, or one that never
  confirmed, as a payment. `channelopen` and `channelsplice` take no
  `max_fee` and do not return the fee paid; `nameregister` shows the
  registration fee without the funding fee; a cooperative close proposed
  with a tiny balance gives it all to the fee.
- **C7 gives up only open channels**: one in a splice, closing or forcing
  whose funding a reorganization took away for good is still held.
- **A dead addition** is said at once after a restart, even when the
  conflicting spend is a single block deep (a display only: the close it
  suggests is safe).
- **The data folder's ownership** is not checked for `root`, on Windows, or
  on disks that ignore ownership (FAT, exFAT, macOS external volumes); the
  `tor/` subfolder is not looked into (the node makes it 0700). The Windows
  flag covers libraries linked at build time, not those loaded by name.
- **For a release event, GitHub runs the tagged commit's workflow**: the new
  check on `main` lives in the file it guards; the tag rulesets remain the
  real barrier.
- **Two hostile onion services**, answering a Tor wallet first while both
  bootstrap onions are unreachable, keep it away from the entry points'
  clear addresses (lead, not run).
- **The entry point's block requests**: each peer may ask for 32 MiB at once
  then 4 MiB a second; twenty-four seats together (not run).
- **Coinbase maturity (200) is shorter than the reorganization limit
  (720)**: the texts now say so; the parameter is for the review of the
  rules before a main network.
- **`getsupply.spendable`** counts the genesis coin, which no one can spend.
- **On regtest**, the depth at which a finished splice is forgotten equals
  the lock depth: the C1 paths are covered by unit tests, not by the labs.
- Every item of the "Open" sections of RED-TEAM-2026-9.md and
  RED-TEAM-2026-8.md still stands, but the two channel points (C1, C7).

## Sound

The emission, the cap and the issued total against the UTXO set, after
reorganizations and restarts; block and transaction validity, Merkle roots,
undo records and reorganization atomicity; the difficulty adjustment on the
active chain; names across reorganizations; fast-sync anchors and the
snapshot's issued total; the release chain end to end (archives, signature,
verification script, workflows); the local account's guards on the RPC; the
journal's torn tails and atomic writes; the splice lock with a peer still on
0.5.10; the cooperative close, the "older copy" claim and the close alone
during a splice.
