# Fifth Q21 campaign — names, contacts and reach (0.5.0)

*Version 0.5.0, before release. Four independent reviewers attacked the new
code from four angles — the name registry's consensus, the network and its
denial-of-service surface, the wallet page and its RPC, and the whole value
system with one goal: duplicate money, find a hidden spend path, freeze the
chain or split it. A fifth reviewer then re-attacked every fix, until nothing
gave.*

*As with the previous campaigns, nothing is claimed without an executable
test against the real code. Each bypass found against a fix became a test
too.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| R1 | 🟠 MEDIUM | One peer could silence reach announcements for every other peer | Fixed, re-checked four times |
| R2 | 🟡 LOW-MEDIUM | `getreach` served with no rate limit (×130 amplification) | Fixed |
| R3 | 🟡 LOW | The look-alike rule missed several confusable digits and one pair | Fixed — consensus, before activation |
| R4 | 🟡 LOW | Any payment to the identity address read as a name registration | Fixed |
| R5 | 🟡 LOW | A rise of the fee rate between two attempts paid a registration twice | Fixed, re-checked |
| H1 | hardening | A snapshot could carry name outputs no valid chain holds | Refused at load |
| H2 | hardening | Invisible characters in contact labels | Dropped |

**No consensus defect, no money creation, no hidden spend path, no freeze
and no fork was found.** The price of a name cannot be recovered, by its
registrant or by a miner; neither half of a name is ever spendable; two
registrations of one name, or of two look-alikes, never stand together, in a
block, across blocks, through a reorganization, a snapshot or a fast sync.

---

## R1. Reach announcements: one peer silenced everyone

A reach announcement says where the owner of a name can be reached, signed by
its identity key. The node verified at most five per second, from a budget
shared by all peers — and spent the budget **before** checking the signature.
One peer sending the same forgery fifty times emptied it, and the genuine
announcements of every other peer were then dropped unread. An owner of one
name could do the same without any forgery, re-signing its announcement with
ever newer dates.

**Fix, in layers.**

- Each peer has its own budget for reach messages, announcements and
  requests together: eight up front, then one per second. No peer can spend
  another's.
- The shared budget, which bounds what is kept and relayed, is spent only once
  a signature has checked out.
- One owner is kept and relayed at most once per ten minutes, **by the node's
  own clock**: the dates inside an announcement are the owner's to choose, the
  clock is not. A ladder of back-dated announcements, each "ten minutes newer"
  than the last, therefore gains nothing.
- The spacing survives the eviction of an announcement from a full table, so
  that two owners evicting each other in turn are still held to it.
- A genuine announcement that comes too soon is not dropped: the newest one
  per owner waits, verified, and is kept and relayed once the spacing has
  passed. A copy kept a moment earlier — stale, or the owner's own previous
  one — holds the current one back for ten minutes at most.
- An announcement signed more than six hours ago, the time between two of a
  wallet's own, is replaced by a recent one at once.

Tests:

- `each_peer_has_its_own_reach_budget`;
- `only_a_name_owner_announces_where_it_listens`, extended with a flood of
  forgeries;
- `a_ladder_of_back_dated_announcements_holds_nothing`;
- `a_ladder_of_recent_dates_gains_one_rung`;
- `eviction_does_not_reset_the_spacing` and
  `eviction_with_recent_dates_does_not_reset_the_spacing`;
- `a_stale_announcement_does_not_hold_back_the_current_one`;
- `a_current_announcement_too_soon_is_kept_once_the_spacing_passes`.

## R2. `getreach`: a bucket like every other reply

A request of 56 bytes got a reply of 7,266 bytes, at any rate. Every other
reply of the node had a bucket; this one had none.

**Fix.** Requests draw from the same per-peer budget as announcements.
Test: `each_peer_has_its_own_reach_budget`.

## R3. Look-alikes: the skeleton, completed

Two names cannot share a skeleton, and the skeleton is a rule of the chain:
a wallet warning can be clicked through, a rule cannot. It folded `0`, `1`,
`i`, `5`, `rn` and `vv`, but registered `2ebra` next to `zebra`, `4lice` next
to `alice`, `6ob` and `8ob` next to `bob`, `9ary` next to `gary`, `clave` next
to `dave`.

**Fix.** The skeleton also reads `2` as `z`, `4` as `a`, `6` and `8` as `b`,
`9` as `g`, and `cl` as `d`. The cost is known and accepted: a few distinct
words now share a skeleton (`modern` and `modem`, `clone` and `done`), and the
first registered keeps both. Names open on testnet at block 5,200: no name was
ever registered under the old rule. Left apart on purpose, because folding
them would take too many real words: `u` and `v`, `nn` and `m`, `q` and `g`,
`7` and `t`.

Test: `look_alikes_share_a_skeleton`, which pins the rule byte for byte.

## R4. The history called any payment to the identity address a registration

**Fix.** The wallet remembers the transactions it sends to register a name
(`name_txs=` in the wallet file, the 64 most recent). Only those, and
transactions that carry name outputs, read as registrations; any other payment
to the identity address reads as such.

Tests: `a_wallet_registers_its_name_end_to_end`,
`name_transactions_survive_the_wallet_file`.

## R5. Registrations and the coins of the identity address

A registration funds the identity address, then spends that coin. When an
attempt failed after the funding and the fee rate rose, the next attempt found
the coin too small, funded the address a second time, and the first coin was
left there for good.

**Fix.** A registration spends every coin already on the identity address,
up to eight, and pays only what they lack. The new `identitysweep` brings what
sits there back to the wallet, and the wallet page offers it.

**Bypass found by the re-check, and closed.** Spending every coin there
included a stranger's **pending** payment: its sender could double-spend it
and make the registration vanish, for 0.0001 Q21. A registration and a sweep
now spend only confirmed coins and the wallet's own pending payments, as a
send does.

Tests: `a_wallet_registers_its_name_end_to_end`,
`a_registration_never_rides_on_a_stranger_s_pending_coin`,
`own_pending_payments_to_the_identity_are_used`,
`the_identity_balance_counts_every_coin`.

## H1. Snapshots with impossible names

The name registry is derived from the set of unspent outputs. A forged
snapshot could carry a tag without its owner output, a tag without its price,
an owner output with value, two look-alikes or a fourth name for one owner: a
node loading it would then judge registrations differently from one that
replayed the chain.

**Fix.** `Snapshot::check_consistency` refuses such a set. Test:
`a_snapshot_with_impossible_names_is_refused`.

## H2. Invisible characters in contact labels

A contact label is local, but direction overrides can make "Alice" read
backward, and zero-width characters make two labels that look the same
differ. `clean_label` drops them, with soft hyphens, blank fillers, variation
selectors and line separators. Test: `labels_are_cleaned_and_bounded`.

---

## What held

- **The price of a name.** It is counted in the transaction's outputs, so it
  can be neither change nor fee; it sits in an output that no signature can
  spend; `getsupply` reports it as destroyed.
- **The halves of a name.** Spending either is refused; the owner output
  carries no value; a lone half is refused.
- **Who registers.** An input must spend an ML-DSA-87 output locked to the
  owner, with a valid signature: no one registers in another's name.
- **The registry.** Two hundred scrambled orders of the same outputs rebuild
  the same registry and the same commitment; a restart rebuilds it byte for
  byte.
- **The wallet page.** Labels, names and addresses with markup render inert in
  a real browser; the RPC refuses a missing or wrong token, a foreign origin
  and a form post; fifty malformed calls returned clean errors.
- **The wire.** Ten thousand random `reach` and `getreach` payloads were
  decoded without a panic or an over-allocation; a reach cannot be redirected,
  its signature covers its target.

## Known limits

- The "verified contact" tick is a help on screen, not a control of the
  node: the node cannot know that a phone call took place.
- A snapshot is still bound only to itself until it is anchored to a trusted
  commitment; see `state.rs`.
- The layer-1 transport between nodes is not encrypted; channel sessions are.
