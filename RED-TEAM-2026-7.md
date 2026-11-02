# Seventh Q21 campaign — four ways of thinking, one goal: stop the chain (0.5.8)

*The 0.5.8 candidate. Four reviewers, each with its own way of attacking —
the architect (invariants, trust boundaries, shared resources), the thinker
(edge cases, time, races, restarts), the bypasser (every defense has a way
around) and the pragmatist (what a cheap attacker does today against the
real deployment) — with one goal: slow the chain down, freeze it, split it,
or give it a visible defect. Every fix was attacked again, three rounds in
all.*

*As in the previous campaigns, a finding is CONFIRMED only when it was run
against the real code or the real binary; every confirmed attack became a
test, checked to fail without its fix.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| P1 | 🔴 HIGH | One visitor held every thread of a public explorer with requests whose body never came | Fixed, re-checked three times |
| P2 | 🔴 HIGH | Newcomers could not keep a connection to an entry point | Fixed; residual through Tor, see below |
| P3 | 🔴 HIGH | One Tor client could lock the onion pool of an entry point | Fixed in the node; Tor's own defenses documented |
| C1 | 🟠 MEDIUM | A channel peer could freeze the channel for good by alternating claims | Fixed, re-checked |
| W1 | 🟠 MEDIUM | Phonetic small capitals passed for letters in contact names | Fixed |
| F1 | 🟡 LOW | A flood of empty frames kept two cores busy | Fixed, re-checked twice |
| S1 | 🟡 LOW | The fast-sync snapshot was rebuilt under the node's lock after every block, on any peer's request | Fixed |
| A1 | 🟠 MEDIUM | A minority miner dating its blocks ahead slows the chain | Open: a rule of the chain, see below |
| A2 | 🟡 LOW | A side branch failing its reorganization is not marked as failed | Open: needs more work than the chain |

**No money creation, no theft, no signature forgery, no remote crash, no
chain split was found.** The rules of the chain are unchanged since 0.5.6,
and held: a reorganization across a registered name, run on real nodes,
left every node agreeing.

---

## P1. The public explorer's threads

The node serves at most 64 requests at once. A request announcing a body
and never sending it held its thread for up to forty seconds, and the
per-visitor budgets were only counted once the body had arrived: 64 such
requests from one address shut the explorer for everyone (confirmed: 503
for 48 seconds). Behind Caddy over HTTP/2, all 64 could ride one TLS
connection, under every firewall limit.

**Fix.** No read outlives the request's deadline. A visitor holds at most 8
requests waiting for their body, all visitors together 21; a request whose
body came with its head is never counted. The refusal is a 429 that reads as
a JSON-RPC error, and the explorer page waits and tries again. The
documented Caddyfile now buffers request bodies and holds the node to 48
requests at once. Re-checked: one address, then eight, then the explorer's
own page bursts — every honest visitor served.

## P2, P3. Seats on an entry point

A full node made room for a newcomer by evicting its most recent connection,
whoever it was. An occupant holding the oldest seats and arriving every
fraction of a second evicted each honest newcomer before it could sync
(confirmed: a fresh node held no peer for 105 seconds). Through Tor, where
every connection arrives from the loopback, four occupants that had relayed
one transaction each were protected for good, and locked the onion pool.

**Fix.**

- Protection for having delivered lasts ten minutes; four seats are never
  protected.
- A connection that has not completed its handshake within five seconds
  goes first.
- Then the arrival replaces the most recent peer of its own address group,
  then of another group — never a peer within its first minute.
- A connection in the clear never evicts a Tor peer.
- An address group arrives at most six times a minute.
- Frames: sixteen before the handshake, then 2,000 at once and 1,000 a
  second, per connection.

Re-checked: the newcomer churn, the reconnecting flood (victim CPU from
189 % to 2 %), the settled household, the Tor wallets.

*Residual.* The node cannot tell two Tor users apart: through Tor, an
occupant opening circuits in a loop can still keep a newcomer to its first
minute, or make it wait. Tor's own defenses make each circuit cost:
TOR.md, section 4.1, now lists them for entry points.

## C1. A channel frozen by alternating claims

A peer may claim that our copy of a channel is older, without proof, for two
minutes. An in-step reestablish cleared the clock, so a peer alternating a
claim and an in-step reestablish started the two minutes again each time,
and even the holder's confirmed close alone was refused (confirmed by a
test on two real channel managers).

**Fix.** The two minutes run from the first claim; a close alone the holder
confirms goes through whatever the peer says. The holder still confirms
first, because only the holder knows whether the wallet was restored from a
backup.

## W1. Small capitals in contact names

"nora" written with a small capital N (U+0274) passed for "nora": the
phonetic small capitals G, I, N, OE, R, Y, L, F, Q (U+0262 and its
neighbors) and the Latin alpha (U+0251) were neither refused nor read as
their letter. They
are now read as letters; a second contact named with them is refused.

## F1, S1. Cheap load

Every frame takes the node's lock: a peer sending a million empty pongs a
second kept two cores busy — now a frame budget per connection (above). The
fast-sync snapshot was rebuilt under the node's lock at every new tip, on
any peer's request: now at most every ten minutes, an older snapshot being
as good a start.

## A1. Dating blocks ahead (open)

Under the strict block time rule, a miner dating its blocks ten minutes
ahead pins the chain's time ahead of the clock; honest blocks then count as
one-second intervals, and the difficulty rises for everyone. Simulated with
the real difficulty function: +14 % block time at 10 % of the hash rate,
+26 % at 20 %. The chain slows, it does not stop, and the miner gains
nothing. The cure is a rule of the chain (counting a block's time as at most
its parent's plus the target in the next interval), which needs a scheduled
activation height and every node upgraded first: it is planned for the
review of the chain's rules before mainnet, not for this release.

## A2. A failed reorganization (open)

A side branch that carries more work than the chain but fails when the node
reorganizes onto it is not marked as failed, and the next block on it
starts the same work again. It needs more work than the chain itself, so a
majority of the hash rate or a lead of one or two blocks at the tip. Planned
with A1.

---

## Sound

Consensus and chain progress; names across a reorganization (run on real
nodes); the mempool and orphan bounds; HTTP parsing and the browser guard;
the forwarded address; JSON; reach announcements; the call of a contact;
the onion self-check and Tor restarts; the token buckets; the own-scheme
filters; the frame budget against honest traffic (a full initial block
download, run).
