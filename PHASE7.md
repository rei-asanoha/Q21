# Phase 7 — what lets a chain last

## What this phase was meant to establish

The previous phases produced a correct protocol. This phase answers another
question: **can it be run for ten years?**

The difference is not theoretical. A node that cannot be restarted in a few
seconds will never be updated. A node whose memory grows with the chain will
end up dying on an ordinary machine. A single-threaded reference miner hands
a factor of eight to anyone who writes their own. And a node that cannot find
its peers depends forever on whoever gave it its first address.

Four walls. They fell in this order, and each one was **pointed out by
measurement**, never by intuition.

## Wall 1 — startup revalidated everything

Until now, starting meant replaying the chain from genesis. On 60,000 test
blocks: **31.4 seconds**. On a million, with 660 µs of proof of work per
block since phase 6, it became hours.

The fix takes up Bitcoin Core's separation between *block files* and
*chainstate*:

- **`state.dat`** — the UTXO set, the tip, the height, the total issued.
  Atomic write: temporary file, `sync_all`, rename. A power cut leaves either
  the old snapshot or the new one, never a mix.
- **`store::scan_headers`** — the index is rebuilt by decoding only the 160
  header bytes of each record. No transaction is read.

**The snapshot is taken behind the tip**, by a full window. This is not a
detail: replaying that window at startup rebuilds the undo records, without
which the node would have lost any ability to reorg — it would have started
fast and been unable to follow a fork.

What this snapshot **is not**: a proof. Loading it means trusting your own
disk. The checksum catches accidental corruption, not an adversary with
access to the files — but anyone who can rewrite your files has already won.
Every block arriving *after* the snapshot is fully validated, and an
unreadable snapshot falls back to full revalidation, never to silent
acceptance.

## Wall 2 — the wallet derived sixty thousand keys

Once the chain had become incremental, measurement pointed to another
culprit:

```
[timing] wallet 20.86 s
[timing] header scan 0.18 s
[timing] chain ready 0.53 s
```

The chain was settled. The wallet, however, re-derived its 60,001 addresses
at every startup — and an ML-DSA derivation is not a hash.

`addresses.dat` caches the hashes already derived. This file contains no
secret — a public key hash is public — and it is not taken at its word: the
wallet **re-probes the first and the last**. Two derivations instead of sixty
thousand, and a cache coming from another seed or another scheme is rejected.

**20.86 s → 0.02 s.**

## Wall 3 — the balance was quadratic

Twenty seconds remained, this time *after* loading. `spendable_for` walked
the whole UTXO set for **each** queried address: sixty thousand addresses
over sixty thousand outputs, that is several billion comparisons to display
a balance.

A derived index — public key hash to outputs — removed the problem. It is
entirely rebuildable and does not take part in the equality of two UTXO sets:
two identical sets remain identical whatever the order of construction.

### The outcome of the first three walls

| | before | after |
|---|---:|---:|
| startup, 60,000 blocks | 31.4 s | **0.83 s** |
| of which wallet | 20.9 s | 0.02 s |
| of which chain | 10.3 s | 0.53 s |
| block bodies in memory | the whole chain | 1,008 blocks |

And the resulting state is **identical** — height, tip, cumulative work,
emission, balance — whether one resumes from a snapshot or revalidates from
genesis. This is checked by a test, not by inspection.

## The defect only two real processes could show

Bounding memory introduced a serious defect, invisible in a unit test.

The index of block positions on disk was built **once at startup**. Blocks
mined or received afterwards never went into it. As long as they stayed in
the memory window, all was well; as soon as they left it, the node no longer
knew how to serve them.

Symptom observed by running two real processes: a node joining a chain being
mined received thousands of blocks, **all orphans**, and stayed indefinitely
at height zero. Its peer could no longer supply the first blocks, so nothing
could attach.

```
height 0 (+0)  compacts 3346 of which 3346 without round trip  orphans 3346
```

The fix is a type, `BlockArchive`, which owns the file **and** its index, and
in which writing and indexing are no longer two separable actions. After:

```
height 7229 (+2)  compacts 21189  orphans 983
```

The node catches up with a chain mined at 250 blocks/s, and the orphan
counter levels off instead of running away. This counter is in fact one of
the additions of this phase: without instrumentation, this defect would have
shown up as "it doesn't work".

This is the fourth time on this project that a serious defect only appeared
when running real processes. Unit tests do not lie about what they test;
they are silent about the rest.

## Wall 4 — the reference miner was single-threaded

On an eight-core machine, a single-threaded miner leaves seven eighths of the
machine unused. Anyone who takes an afternoon to write a parallel miner gets
eight times the rate of ordinary people. For a project whose reason for being
is that mining stays accessible, this is a contradiction, not a missing
optimization.

A naive parallel miner returns the first nonce found — hence a nonce that
depends on thread scheduling, and two runs produce two different blocks.
Here the search proceeds in **waves**: the threads sweep a contiguous range
of nonces together, the end of the wave is awaited, and the **smallest**
winning nonce is kept. The result is exactly that of a sequential loop.

```
available cores: 2
1 thread(s):     156741 attempts/s   speedup 1.00 x   nonce 183386
2 thread(s):     305382 attempts/s   speedup 1.95 x   nonce 183386
```

97.5% efficiency, and **the same nonce**. It is this property that lets the
tests compare two independently mined chains.

## Wall 5 — the node could not find its peers

An eclipse attack breaks no cryptography: it **isolates**. If all of a
node's connections lead to machines controlled by the same person, that node
no longer sees the real network. Blocks can be hidden from it, a fabricated
chain shown to it, a payment already spent elsewhere made acceptable to it.
It will perfectly verify blocks addressed to it alone.

It is the most profitable attack against a small chain, and Q21 will be one.

Until now, received addresses were simply ignored
(`Message::Addr(_) => {}`). A node only knew what it had been given by hand.

The defense follows the real asymmetry: an adversary easily obtains thousands
of IP addresses, but rarely in thousands of different ranges.

- the address book is **sorted by network group** (`/16`), capped per group;
- selection **never returns two addresses from the same group**, nor an
  address from a group already represented among the connected peers.

A test checks it against the attack itself: ten thousand addresses inserted
into a single `/16` against four honest peers in four distinct ranges.

```
selection: 5 addresses — the four honest ones, plus ONE from the attacker
```

Holding ten thousand addresses in one range is therefore worth exactly as
much as holding one. To carry weight, one must own entire ranges: that is
counted in money and in administrative traces, not in scripts.

The address book survives shutdown (`peers.dat`). Without it, each restart
would start again from the bootstrap point — and would give whoever controls
that point a power it should not have.

**What this does not guarantee**: an adversary with truly diverse ranges — a
large hosting provider, an operator — remains dangerous. Diversity by group
raises the cost, it does not make it infinite. And a node whose starting
addresses *all* come from the attacker is lost from the start.

## Checks

- **341 tests** with ML-DSA (326 without), zero clippy warnings.
- Resuming from a snapshot and full revalidation give an identical state.
- Undoing stops **exactly** at the snapshot, without corrupting the UTXO set.
- A snapshot corrupted by a single byte is detected and triggers
  revalidation.
- A block added after the archive was opened remains servable.
- Parallel mining returns the same nonce for 1, 2, 3, 5 and 8 threads.
- Three real nodes: the third one, given only a single address, discovers
  the others and syncs.

## Instrumentation

```bash
Q21_TIMING=1 q21 info        # breakdown of the startup time
```

A node's status line now carries the network groups of the peers, the size
of the address book, and the counters of orphan and invalid blocks — the two
figures that tell "slow" from "looping".

## New options

```
q21 node --threads <n>  mining threads (default: all cores)
q21 node --peers <n>    target outbound connections, all from distinct groups
```

## What remains open

- **No bootstrap node is wired in.** The address book works, but the first
  address still has to come from `--connect`. This is a launch decision, not
  a code one: bootstrap addresses will only exist with the network.
- **The archive is not pruned.** Memory is bounded, disk is not yet.
- **The proof of work has still received no external cryptanalysis.** Since
  phase 6, this is the most important open point of the project.
- **No handling of hostile inbound peers beyond the ban score** — no
  per-network-group limit on inbound connections.
