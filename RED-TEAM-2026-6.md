# Sixth Q21 campaign — the whole system, attacked to take it over (0.5.6 → 0.5.7)

*Version 0.5.6, then the 0.5.7 candidate. Seven reviewers, each with a lab of
three to four nodes on a private test chain, attacked one area each —
consensus and money, transaction signatures, the peer network, the wallet,
payment channels, storage, and the operation of public servers — with one
goal: take control of the chain, create money, slip in false data, or send a
payment somewhere it was not meant to go. Every fix was then attacked again,
differently, five rounds in all, until nothing gave.*

*As in the previous campaigns, nothing is claimed without an executable test
against the real code, and every bypass found against a fix became a test
too. Three fuzzers were added for the parts that read untrusted bytes.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| C1 | 🟠 MEDIUM | A peer's unproven claim that our copy is older froze a channel for good | Fixed, re-checked |
| S1 | 🟠 MEDIUM | A one-time (Lamport) key spent after a backup could be derived and signed again | Fixed, re-checked three times |
| S3 | 🟠 MEDIUM | A coin of another scheme paid to one of the wallet's key hashes was counted and chosen | Fixed |
| S4 | 🟠 MEDIUM | A wallet off the channel scheme was paid, by every channel close, an output it can never spend | Fixed, re-checked twice |
| O1 | 🟠 MEDIUM | A public explorer could be slowed for everyone by cheap calls in volume | Fixed, re-checked three times |
| W1 | 🟡 LOW-MEDIUM | Two contacts could bear names drawn alike and point to different addresses | Fixed, re-checked four times |
| R1 | 🟡 LOW | A build job could place a file under another platform's name in a release | Fixed, re-checked twice |
| J1 | 🟡 LOW | Half of an escaped surrogate pair was read as a character | Fixed |
| H1 | hardening | Windows and Unix system programs by full path | Done |
| H2 | hardening | The server unit drops every capability it never uses | Done |
| H3 | hardening | Update guides install signed releases only | Done |

**No consensus defect, no money creation, no signature forgery, no remote
crash and no takeover was found.** The supply, the proof of work, the
signature checks of both schemes, the policies, the names and the snapshot
paths held under every attack and through three fuzzers run to millions of
inputs: no panic, no broken invariant, no block or transaction accepted that
should not be.

---

## C1. Channels: an unproven claim froze the channel

A peer could say, in its reestablish, that our copy of a channel is older
than its own, without proving it. The node then refused to pay or to close
the channel, for good: a peer could hold the funds of the other side hostage
by lying once.

**Fix.** The claim is held for two minutes only (`UNPROVEN_BEHIND`), never
written to disk, and cleared as soon as the peer's state matches. A proven
claim still stops everything, as it must. After the two minutes, closing
alone asks the holder whether this wallet was restored from a backup: only
the holder knows, and a copy really restored from a backup must not
broadcast a state that may be revoked.

## S1. One-time keys after a backup

A wallet on the one-time scheme (a development scheme, refused on mainnet)
restored from a backup did not know the keys it had used since. It could
derive one of them again and sign a second time, which reveals the key.

**Fix.** The wallet looks ahead a thousand keys and recognizes in the chain
every key it spent, following its own outputs beyond the window; a new
address never lands on a consumed index; a consolidation scans first.
*Residual, accepted:* a gap of more than a thousand unpaid addresses between
two payments seen by the wallet. The scheme is not allowed on mainnet.

## S3. A coin of another scheme on our key hash

An address is a scheme and a key hash. Anyone can take an address and pay
the same hash under another scheme; no key of the wallet can spend that
output. The wallet counted it in the balance and could choose it for a send,
which then failed: a cheap way to make a wallet look richer than it is, or
to wedge its sends.

**Fix.** Only outputs of the wallet's own scheme are counted, frozen,
reserved or chosen; the activity lists only those; the explorer's view of an
address counts and lists only its scheme's outputs. The identity coins were
already filtered the same way.

## S4. Channels of a wallet on another scheme

Every close, sweep, claim and penalty of a channel pays a wallet address as
an output of the channel scheme (ML-DSA-87). A wallet on another scheme
could open channels; each close then burned its share.

**Fix.** Such a wallet opens no channel, accepts none and adds no coin to
one. Its channels opened before are closed alone only: it neither proposes
nor signs a cooperative close, whose agreed payout is the unspendable
address; sweeps and claims pay the node's identity address instead, which
`identitysweep` brings back to the wallet.

## O1. The public explorer under load

Cheap calls take the same lock as the application of blocks. Batches of a
hundred digests (each a modular inverse), or many connections looping cheap
reads, slowed block relay for everyone.

**Fix, in layers.**

- A batch holds at most ten calls in public mode; the state digest is
  computed once per tip; the hash rate reads only its window of headers.
- Every public call is counted, per client and in all: a reserve of 120,
  then 20 per second per client, and a net of 600 per second for all
  together. An IPv6 client is counted by its `/48`.
- The refill keeps the time a partial token has earned, to the nanosecond:
  dropping it gave a steady stream about half its rate.
- The explorer page, told to slow down, pauses as a whole and tries again;
  a refresh never stacks on one still running.
- A forwarded address written with its port is read as the address.

*Residual, accepted:* one lock serializes reads and block application; the
limits above bound what a client can take, not the cost of the lock itself.

## W1. Contacts drawn alike

The wallet keeps the addresses one sends to under a name. Two names drawn
alike — a Cyrillic letter for a Latin one, an accent written in two pieces,
an invisible character, a letter of another script that every font draws the
same — could stand side by side and point to different addresses.

**Fix.** Each name is read through two keys: its full canonical
decomposition (Hangul included), with marks in canonical order, invisible
characters dropped, letters drawn alike read as one — from Unicode's data
and from every character of six common fonts drawn and compared pixel for
pixel — once with capitals read as drawn, once lowered first. Two names are
one when either key is the same, and the second is refused, with the name it
copies. Characters made to imitate letters (mathematical letters, letter-like
symbols, compatibility forms, Cherokee, Coptic) and code points newer than
the tables are refused. Names that differ by an accent are both kept and
shown with a warning, as are right-to-left names that differ only by the
order of their parts. At most three marks are kept on a letter; the joiners
of an emoji or a Persian word are kept. A book written before keeps every
entry, shown with a warning.

*Residual, accepted:* sequences of several characters drawn like one
(`rn` and `m`), and letters that differ only slightly in some fonts.

## R1. Release artifacts

The release job merged the files of the four platform builds into one
folder: a build job could place a file under another platform's name.

**Fix.** Each artifact is collected in its own folder and may hold only its
own platform's files; a platform's hash file must hold full hashes and name
its own binary and nothing of another platform, its last line included.

## J1. JSON escapes

An escaped surrogate pair is now the character it encodes, and half a pair
is refused.

---

## Accepted and documented

| Topic | Why it stays |
|---|---|
| A name registration relayed to a miner whose pool is full can be evicted, and a same-name registration raced | The ordinary mempool race on a scarce resource; the registrant's own node keeps and relays its copy |
| Reach announcements replayed while still valid | Signed by the owner, bounded in time and rate |
| Per-process nonces of the authenticated transport linkable | No identity beyond the node id the session already shows |
| The release signing key has never been rotated | A new key before mainnet is recommended (SIGNING.md) |

---

## Tests added

`tests/fuzz_channel_engine.rs`, `tests/fuzz_policy.rs`,
`tests/fuzz_headers.rs` (round counts set by `Q21_CHANNEL_FUZZ_ROUNDS`,
`Q21_POLICY_FUZZ_ROUNDS`, `Q21_HEADER_FUZZ_ROUNDS`); in `tests/channel_node.rs`,
the unproven claim and the wallet off the channel scheme; in the wallet, the
one-time keys after a backup and the coin of another scheme; in the RPC, the
public call budget, its refill rate and the address of another scheme; in the
address book, the look-alikes of rounds one to five; in
`tests/documentation_consistency.rs`, the release's collection of artifacts.
