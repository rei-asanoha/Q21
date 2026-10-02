# Second Q21 attack campaign — severity report

*Second adversarial pass, from a fresh angle. Two guidelines drove this
campaign, different from the first: attack first the **code that just
changed** — the fixes from the first campaign, freshly written, are the most
likely place for a new defect — and dig into less-visited surfaces: decoders,
mempool economics, the storage layer and fast sync, validation arithmetic.*

*As the first time, every serious claim was checked against the real code, not
just described. One was checked by measurement — and that measurement brought
the announced "critical flaw" down by a factor of fifty. That is the heart of
this report: without verification, you fix ghosts.*

---

## On one page

This campaign found **a real remote crash** (high severity) and **an overload
denial of service** (medium severity — after correcting a factor-of-fifty
error in the initial estimate). Both are **fixed and validated**, the crash
backed by an attack test. A third, minor defect (an adoption that treated a
crash as a success) is fixed as well.

The medium-to-low severity hardenings (points 4 to 6) were applied in a second
step, each with a test that replays the attack: **nothing in this report
remains open.** All twenty-five test suites in the repository pass, including
four new attack tests.

| # | Severity | Flaw | Status |
|---|---|---|---|
| 1 | 🟠 HIGH | Remote crash of a node doing a fast sync | ✅ Fixed + test |
| 2 | 🟡 MEDIUM | Denial of service through signature verification | ✅ Fixed (severity recalibrated) |
| 3 | 🟢 LOW | Adoption treating a crash as a success | ✅ Fixed |
| 4 | 🟡 MEDIUM | Compact block reconstructed before its work is checked | ✅ Fixed + test |
| 5 | 🟡 MEDIUM | File-based adoption without checking the bodies | ✅ Fixed + test |
| 6 | 🟢 LOW | Five miscellaneous hardenings | ✅ All five applied |

---

## 1. 🟠 HIGH — A peer can crash any node that is syncing

### In plain terms

A new node can start quickly by downloading a **snapshot** of the state from a
peer, then adopting it if a commitment matches a value the user has checked.
The snapshot contains a "height" field — the number of the last block.

The defect: the code **reserved memory based on that height before checking
it**. The faulty line prepared an array of size "height + 1". A malicious peer
announcing the maximum height (≈18 billion billion) made that addition
overflow — and since the program is compiled to **stop dead on any overflow**
(a protection against monetary calculation errors, here turned against it),
the node **crashed**. Reliably, remotely, for any new node syncing from that
peer.

### Why it matters

It is neither theft nor takeover, but it is a **denial-of-service weapon
against new participants arriving**: a single hostile peer, serving
booby-trapped snapshots, prevents anyone from joining the network through it —
and the peer-to-peer network does not authenticate its peers, so anyone can be
one. For a young chain that needs people to join, that is a serious nuisance.

### The proof, and the fix

A test builds a snapshot at the maximum height and calls the adoption
function: before the fix, the process aborted on that line; after it, it
returns a clean refusal. The fix bounds the reservation by the **number of
headers actually supplied** — a quantity the peer cannot inflate, since each
step of the verification requires a header that is present. The test
`tests/attack_snapshot_height.rs` stands guard.

**Status: fixed, proven.**

---

## 2. 🟡 MEDIUM — Overload through signature verification *(and a lesson about verification)*

### What the analysis first believed, and what the measurement showed

A transaction makes the node verify **one post-quantum signature per input**
(per coin spent), and that work is done under the lock that protects the whole
node. Nothing limited the number of inputs in a transaction other than its
total weight — about 271 inputs. And the counter that limits a peer's rate
counted **transactions, not verifications**.

The initial analysis, relying on a **code comment** that announced "sixteen
milliseconds" per verification, concluded there would be a 4.3-second freeze
per transaction and a complete stall of the node — a *critical* flaw.

**The measurement corrected that by a factor of fifty.** On the benchmark, an
ML-DSA-87 verification actually takes **0.33 milliseconds**, not sixteen. The
comment was fifty times too pessimistic. The real worst case is therefore not
a 4.3 s freeze, but an overload of about **90 ms** for a 271-input
transaction, and a slowdown — not a halt — under a sustained flow of such
transactions (the attacker also having to hold coins to spend in order to build
them). The flaw drops from *critical* to *medium*.

This is why verification exists: the announced severity rested entirely on a
wrong constant. A report that does not measure fixes ghosts.

### The fix

The rate counter is now **denominated in verifications**, not in
transactions: a transaction costs as much as its number of inputs. The ceiling
covers the largest possible valid transaction, so that no honest transaction —
a consolidation of many coins, for example — is ever refused. Beyond the
budget, a **large** transaction is *deferred* without penalty (it may be
honest, and a penalty score never goes back down — banning a legitimate relay
would be unfair), while a *flood* of small transactions is still penalized as
the abuse it is. Along the way, this also closes an over-banning of relayed
duplicates that the first campaign had left open.

**Status: fixed.**

---

## 3. 🟢 LOW — An adoption treated a crash as a success

During a fast sync, verifying the work of the downloaded chain is spread over
several threads. If one of these threads **crashed**, the code counted its
result as "verified" instead of "failed". A segment whose verification crashed
the verifier therefore passed as valid. Fixed: a thread that crashes is now a
failure. Defense in depth — fixed.

---

## 4. 🟡 MEDIUM — A compact block is reconstructed before its work is checked

*Fixed, with an attack test (`tests/attack_compact_block_without_work.rs`).*

To save bandwidth, a peer can announce a block in "compact" form (the
transaction identifiers rather than the transactions). The node then rebuilds
the block by drawing from its mempool. The defect: this reconstruction — a
scan of the mempool, potentially expensive — happens **before** checking that
the block carries a real proof of work. A peer could therefore make the node
work with an unmined block.

**Why it was not more serious:** the code already required the handshake,
required **knowing the parent block**, and applied a **rate counter** with a
penalty on compact announcements. These three barriers already bounded the
abuse strongly.

**The fix:** a fourth barrier, the one the BIP 152 standard prescribes —
header first. Before any search of the mempool, the compact block's header is
checked **on its own**: parent, height, finality, expected difficulty,
timestamp, and finally the proof of work (through the light path, without the
table). These are exactly the checks that submitting the full block applies —
extracted into shared functions so that there is only one rule — simply moved
earlier. A false header earns the peer the penalty for an invalid block, and
its body is not requested again.

**Proof:** the test sends a compact block whose header is that of a real mined
block, with the nonce changed until the work is wrong. Without the fix, the
node started a reconstruction (measured: `1 reconstruction(s) started`); with
it, none (`0`), the header is counted as rejected, and the real block, from the
same peer, goes through exactly as before. A second false header disconnects
the peer. The bucket test from the first campaign was adapted to announce a
true header, so that it keeps measuring the bucket and not this new check.

---

## 5. 🟡 MEDIUM — Adopting a snapshot from files does not check the bodies

*Fixed in both places, with an attack test
(`tests/attack_forged_body_on_disk.rs`).*

There are two ways to adopt a snapshot: over the network, and from a folder of
files copied by hand. The **network** path checks the downloaded block bodies;
the **file** path copies them as-is without rechecking them. Consequence: a
snapshot folder whose bodies carry forged "uncle" lists (invented competing
blocks) could, after adoption, make the node diverge and freeze it on a false
branch until the folder was deleted.

It was bounded: the user had to adopt a folder supplied by a third party, and
the state commitment, for its part, was still checked.

**The fix, in two places:** the **file** path now checks the bodies exactly
like the network path (each body must have a correct form and carry the
identifier of the header at the same height), before writing a single byte;
and, in depth, **reading a body back from disk** requires that the block read
carries the requested identifier and a correct form (Merkle roots
recomputed), failing which it counts as "absent" — a case already handled
cleanly: the block is requested again from the network, which will deliver the
real one. A forged block file, however it got there, can therefore no longer
serve as truth for the node.

**Proof:** the test builds a sync snapshot folder with the real headers, the
real snapshot, and a body carrying an invented uncle. `q21 snapshot adopt`
refuses it ("malformed body at height 15") without writing anything; the same
folder, with intact bodies, gets adopted. And the archive, faced with a block
file in which one body contradicts its header, reads back all the honest bodies
and returns the forged body as absent.

---

## 6. 🟢 LOW — Five hardenings

None was remotely exploitable as things stood; these were corners to clean up.
**All five are applied.**

**a.** The maximum size of a network message (8 MiB) was twice that of a block
(4 MiB): an oversized message was fully decoded before being rejected for
excessive size. *Applied:* the bound is now one and a quarter blocks (5 MiB),
which covers the largest legitimate message — a full block, or a compact block
that prefills all of its transactions — and nothing more; two compile-time
assertions guard this range.

**b.** The `X-Forwarded-For` header: the first campaign's fix (read the last
value) is correct for **one** intermediary, but degrades the counting if
several intermediaries are stacked (a CDN in front of the local web server).
*Applied:* the "a single trusted hop" rule is documented in the code and in
the public explorer guide, with the procedure to follow behind a CDN (it is up
to the local intermediary to rewrite the header with the address the CDN
passes to it). The node does not guess the number of hops: each hop taken at
its word would be a hop a visitor can imitate.

**c.** The total issued was not covered by the snapshot's commitment: a peer
could announce it at any value within a range, which affected a display and an
anti-inflation bound. *Applied:* the commitment that gets copied — the one
given to `--commitment`, shown by the explorer, carried in the snapshot
announcement and in the revalidation record — is now the **state commitment**,
which binds the MuHash and the total issued under its own label. The MuHash
stays what it is and the snapshot format does not change; only the compared
value derives from it. The test `tests/attack_snapshot_issued.rs` proves it: a
snapshot with a rewritten total issued, with an identical MuHash, is refused
under the trusted commitment, and the honest snapshot gets adopted.
Revalidating an adopted node also compares this value: a lied-about total
issued would no longer survive it.

**d.** A node kept the last thousand decoded block bodies in memory: a miner
producing large blocks could swell this cache beyond the "8 GB is enough"
assumption (a thousand 4 MiB bodies: 4 GiB). *Applied:* a second bound, in
bytes (1 GiB), maintained as it goes; whichever is reached first wins, bodies
are evicted from oldest to newest, never the genesis, and the disk keeps
everything memory lets go. With full blocks, memory holds 256 blocks — eight
hours — instead of four gigabytes. A unit test checks the count and the
eviction order.

**e.** Two needless copies of entire blocks at each connection (an uncle list
that was always empty was read by cloning nine full blocks; a reorg walk was
quadratic). *Applied:* with no uncle possible, the read is short-circuited (it
resumes by itself if the protocol reopens uncles); the reorg walk reads the
active chain by height instead of scanning it. A healthy consequence, locked in
by a test: a node resumed from a snapshot without a body provider now returns
the same verdict as a full node on the block that extends its tip, instead of a
refusal that nothing justified any more.

---

## What held — checked, not assumed

One reassuring point from this campaign: **the first campaign's fixes withstood
adversarial review**, and the rest of the code proved solid where it was pushed
hardest.

- **The fix for the critical inflation flaw** (the first campaign) has no edge
  case: the only way for a coin to be both preexisting and recreated in a block
  would be an identifier collision, which the height commitment in the reward
  transaction makes impossible.
- **The decoders** — every attacker's entry point — yielded **no crash and no
  unbounded allocation**: announced lengths are always bounded by what the
  frame contains, non-canonical encodings are refused, 256-bit arithmetic does
  not overflow.
- **The state commitment (MuHash)** does bind the complete set of coins; a
  collision would amount to a mathematical problem held to be infeasible, and
  insert-then-remove leaves no residue (which the first campaign's cancellation
  fix made true).
- **Validation arithmetic** — difficulty, emission, fees, cumulative work — is
  guarded everywhere by operations that saturate or refuse instead of
  overflowing.
- **The mempool** allows no free relay, no dust, and no way around the minimum
  fee rate; its cleanup cost is linear, no longer quadratic.

---

## Recommendation

The two defects that mattered — the remote crash and the verification
overload — are closed and validated. Points 4 to 6, hardenings, were applied
carefully in a second step, each with its test; this report leaves nothing
open in the code.

And, for the third time, the only thing that really remains open is not in
this report: **external cryptanalysis of the proof-of-work mixing function**,
which no self-audit campaign can replace. It is the prerequisite the white
paper rightly marks as the last one before a calm genesis.
