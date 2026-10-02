# Phase 8 — adversarial audit, and the key factory

## The method

Two independent auditors received a single instruction: **break Q21**. Not
proofread, not comment on style — find what makes it possible to create money,
spend twice, make two honest nodes diverge, or freeze a node remotely. And
demonstrate each finding with an executable test, because a flaw you cannot
reproduce is a hypothesis.

They found **eleven real flaws**, two of them critical. All are fixed, and each
exploit became a non-regression test: the test that proved the attack now
checks that it fails.

---

## The two critical flaws

### 1. An uncle cost no work

`pow.check(uncle)` checked the proof of work against `uncle.bits` — a field
that the uncle's author fills in themselves. For an ordinary block, the
expected difficulty was compared; **for an uncle, that comparison did not
exist**.

An attacker therefore built a header with a near-maximal target, `nonce` at
zero, and got paid for it. No computation. Two uncles per block, at every
block, indefinitely — each fake uncle having a fresh identifier, the
anti-double-payment rule never saw it.

The auditor's measurement: *"block 5 issues 725,937 instead of 345,685,
×2.10"*.

**Fix**: an uncle must carry the difficulty the chain required at its height.
The same rule also shuts the door on flooding with side branches (flaw 7).

### 2. The 21,000,001 cap was not a cap

This is the flaw that touches the heart of the project, and it existed **even
without an attacker**.

Uncle shares were **added** to the subsidy, plus an inclusion bonus. A block
could therefore issue 210% of what it was due, and nothing in the code ever
compared cumulative emission against the cap. The protocol's real maximum
emission came to **44,099,999 Q21**, for an announced cap of 21,000,001.

The auditor's measurement: *"real maximum emission 44,099,999 Q21 against an
announced cap of 21,000,001"*.

**Fix, in two steps.**

First the structure: uncle shares are now **taken from** the subsidy.
`miner_share + n × per_uncle == subsidy(height)`, always. A block issues
exactly its subsidy, whatever it contains. The cap holds by construction.

Then the last line of defense: a consensus rule refuses any block that would
bring cumulative emission above `MAX_SUPPLY`. It depends on no schedule, no
uncle, no fee calculation. **Even if an economic rule turned out to be wrong —
it has happened twice on this project — no block can cross 21,000,001 Q21.**

**The price, stated frankly.** Including an uncle now costs the miner what it
pays out. In a fixed-cap currency there is no way out: an uncle reward is
either inflationary or taken from the miner. The cap is the project; the
monetary incentive to include uncles is therefore weak, and that is an open
economic question, not an oversight. Bitcoin, for its part, has no uncle
reward at all.

---

## The serious flaws

### 3. Two coinbases could share an identifier (BIP 30)

A coinbase's identifier depended on **no** uniqueness element: neither height
nor extranonce. Two blocks from the same miner for the same amount produced
the same `txid`. The second output overwrote the first in the UTXO set, and
undoing the second destroyed the first one's output.

Measured result: *"same tip, UTXO A = 100,414,822 vs B = 100,415,822"*. Two
honest nodes, the same chain, different balances — a silent split.

**Fix**: the height is committed in the coinbase's identifier, and a consensus
rule checks that it is there. This is the lesson of BIP 30 and BIP 34,
relearned here through an audit.

### 4. `try_reorg` could loop forever

The restore loop discarded the return value of `disconnect()`. After resuming
from a snapshot — where the undo window is short — this loop never made
progress: the node went around in circles, **holding the chain lock**. The
auditor's thread never returned.

**Fix**: the reorg depth is checked against the undo window **before**
touching anything, and no loop relies any more on a function that can refuse.

### 5. `disconnect` corrupted the emission when it failed

It overwrote the emission counter **before** finding that no undo data was
available. After resuming from a snapshot, the counter dropped to zero.

**Fix**: order reversed. Nothing is mutated until we are certain to go all the
way.

### 6. An already-paid uncle became payable again after a restart

The anti-double-payment rule read block bodies **in memory**. After resuming
from a snapshot they are absent: the set was incomplete, and a freshly
restarted node accepted what a full node refused.

**Fix**: the rule reads the bodies back from disk, and **fails loudly** if a
body is missing. Blindly validating an anti-fraud rule is worse than not
validating it: you believe you are protected.

### 7. Network amplification, twice

`getdata`: twenty thousand times the same hash → twenty thousand copies of the
block. A 660 KiB request for a 6.8 MiB response, and for a compact block all
the short identifiers recomputed for each copy. On real 4 MiB blocks: 80 GiB.

`getblocktxn`: a hundred thousand times the same index → a 15.5 MiB frame,
which even exceeded the protocol's `MAX_PAYLOAD`. Building a response that
nobody can read is the definition of a denial of service.

And both worked **without a handshake**: their cost to the attacker came down
to a `connect()`.

**Fix**: handshake required, items deduplicated, outgoing byte budget.

### 8. A 170-byte compact block cloned the whole mempool

Each compact announcement triggered a full copy of the mempool — up to 64 MiB
— **under the global lock**, thereby serializing the whole node.

**Fix**: only the transactions whose short identifier appears in the
announcement are kept, and the message is refused before any expense if the
block's parent is unknown.

### 9. No write timeout

A peer that never took in its bytes blocked the thread writing to it
indefinitely, while holding the lock on its stream. Since broadcasts write to
every peer, a single silent peer ended up blocking all propagation.

**Fix**: thirty seconds, then the connection drops and the network carries
on.

---

## The regression I introduced while fixing

My handshake safeguard **dropped** the connection. On the first real run, two
honest nodes disconnected from each other immediately — height stuck at zero.

The cause: a mining node announces its blocks as soon as it has a peer. The
peer requests the block, and its request arrives before its `verack`. A
perfectly benign race, which I was punishing with a disconnection. A safeguard
that causes a network partition is worse than the flaw it closes.

**Fix**: nothing is served before the handshake, but the connection is not
dropped — and nothing is announced any more to a peer whose handshake is not
complete.

This is the fifth time on this project that a serious defect only showed up
when running two real processes.

---

## What the audit did **not** find

Stated as clearly as the rest, because an audit that finds nothing somewhere
is information too:

- **CVE-2012-2459** (Merkle collision by duplicating the last leaf): absent.
  Distinct leaf/branch tags make it structurally impossible. Checked for every
  size from 1 to 64.
- **`txid` malleability**: impossible for a third party. The witness is outside
  the `txid`, and varints are canonical with explicit rejection.
- **Signature replay** between inputs or between transactions: impossible, the
  sighash binds the input index and the whole stripped transaction.
- **Intra-block spending** and **coinbase maturity**: both rules hold.
- **Arithmetic overflows** on amounts: `checked_add` everywhere,
  `overflow-checks` enabled in all three profiles. Nothing exploitable.

---

## The key factory

You asked whether I had worked on the component that creates wallets. I had
not, and it had three serious defects.

### The random number generator failed on Windows

```rust
std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?
```

This file does not exist on Windows. `q21 init` simply failed there — on the
most widespread system.

And nothing checked what came out of it. A degraded source would have produced
a predictable seed without any message saying so. A private key is only worth
its randomness: it is the weakest link in the whole chain, and the one people
look at least.

The `rng` module now queries the system generator on every platform —
`/dev/urandom` on POSIX systems, `BCryptGenRandom` on Windows — and **fails
rather than return randomness of unknown quality**. It mixes nothing in: adding
a clock to a broken source strengthens nothing, it hides the failure.

### The seed lived in plain text on disk

Sixty-four hexadecimal characters in `wallet.dat`, with default permissions.
Anyone who had read that file once — a backup, a resold disk, a shared folder
— held the funds for good.

The wallet is now **encrypted and authenticated** with a passphrase:
PBKDF2-HMAC-SHA256 at 600,000 iterations, an HMAC keystream in counter mode,
encrypt-then-MAC. No new primitive — only standard constructions on top of
SHA-256, and HMAC is checked against four official RFC 4231 vectors, PBKDF2
against the one from RFC 7914. The file is `0600`, even without a passphrase,
and the absence of a passphrase is flagged in capital letters.

A test modifies **every byte of the sealed file, one by one**: all are
detected, header included — otherwise an attacker could bring the iteration
count down to one.

### The backup had no checksum

The seed was returned as raw hexadecimal. Copying sixty-four characters by
hand is an operation where people make mistakes, and a single typo gives a
perfectly valid seed that opens nothing. The loss is silent and permanent.

The backup code is now in **Bech32m** — the same encoding as addresses: an
alphabet without confusable characters, and a checksum that detects up to four
errors.

```
rq21seed18zpjwkqmz5kvhxk2vw6fnzek3js5dzk3w7stkx66jfugyfsflemsjlt3za
```

A test substitutes **each character** of the code with seven others: all 400
typos are detected, none gets through. The prefix designates the network — a
test seed cannot be mistaken for a mainnet seed.

And a code you cannot replay is useless: `q21 restore` rebuilds the wallet.
Checked end to end — the derived addresses are identical, character for
character. *(The code was then entered as an argument; the v2 audit showed
that it ended up in the shell history, and it has since been prompted for in
the terminal without echo or read with `--backup-code-file`.)*

### What was also added

- Passphrase entry **without echo** — console API on Windows, `stty` on POSIX
  — with confirmation, and an explicit warning if echo could not be turned off
  rather than a pretense.
- The seed is wiped from memory when the wallet is destroyed
  (`write_volatile`, which the optimizer is not allowed to remove).

### What remains open

**PBKDF2 is not memory-hard.** An attacker equipped with dedicated circuits
tests passphrases far faster than a CPU. Argon2 or scrypt would be better, and
writing them yourself would be exactly the kind of initiative this project
refuses. The real defense remains the **length of the passphrase**, and the
module says so rather than keeping quiet about it.

---

## Verification table — one proof per flaw

Each row points to an executable test. A fix without a test is not a fix: it
is a bet that nobody will reintroduce the defect.

| # | Flaw | Fix | Test |
|---|---|---|---|
| 1 | Uncle without work | Difficulty required at the uncle's height | Removed together with uncles (third wave) |
| 2 | Cap could be crossed | Uncles taken from the subsidy **+** absolute last line of defense | `a_block_issues_exactly_its_subsidy_even_with_uncles`, `actual_emission_never_exceeds_the_subsidy`, `no_block_crosses_the_absolute_cap` |
| 3 | Coinbases with the same `txid` | Height committed in the `txid`, and checked | `two_coinbases_at_different_heights_have_different_identifiers`, `a_coinbase_without_height_is_refused` |
| 4 | `try_reorg` looping | Undo window checked before any mutation | `an_impossible_reorg_fails_instead_of_looping` |
| 5 | `disconnect` corrupts the emission | Order reversed: nothing is mutated before certainty | `a_refused_disconnect_touches_nothing` |
| 6 | Uncle payable again after a resume | Bodies read back from disk, loud failure otherwise | Removed together with uncles (third wave) |
| 7 | Free side branches | Difficulty checked before indexing | `a_side_branch_without_work_is_refused` |
| 8 | Amplified `getdata` | Deduplication + byte budget | `getdata_with_repeated_hashes_no_longer_amplifies` |
| 9 | Amplified `getblocktxn` | Same, plus deduplicated indices | `getblocktxn_with_repeated_indices_no_longer_amplifies` |
| 10 | Served without a handshake | Nothing is served before `verack` | `nothing_is_served_before_the_handshake` |
| 11 | Compact block cloning the mempool | Filtering by short identifier, refusal if parent unknown | `an_orphan_compact_block_triggers_no_work` |

Two fixes do **not** have a dedicated test, and that must be said:

- the thirty-second **write timeout** to a peer: checking it would require a
  peer that never takes in its bytes for half a minute, that is, a
  half-minute test on every run. The fix is one line and can be read;
- the **derived bound** on the number of transactions per block is checked
  **at compile time** (`const _: () = assert!(…)`), which is stronger than a
  test.

## Checks

- **480 tests** in total, **340** of them in the library, zero clippy warnings
  on `src/`.
- **11 consensus non-regression tests** and **4 network ones**, each derived
  from an exploit that worked.
- Two real nodes: the second joins a chain mined at 250 blocks/s and catches up
  on 7,221 blocks.
- Restore from a backup code: identical addresses.
- Encrypted wallet: mines, sends, restarts — and a wrong passphrase gives the
  same message as a tampered file.

## Second wave — the on-disk state (phase 8b)

Five auditors attacked five axes the first wave had not covered. The one that
paid off most is the most mundane: **what a node reads back at startup**. The
chain was defended; its files were not.

| # | Flaw | What it allowed | Fix | Test |
|---|---|---|---|---|
| 12 | `state.dat` taken at its word | Adding a one-billion-unit output in the attacker's name, checksum recomputed: the node restarted with money that was never mined | Checked against the **emission schedule**: total issued ≤ what the schedule allows at this height, sum of UTXOs ≤ total issued, no output dated from a future block | `g_crafted_snapshot_credits_nonexistent_funds` |
| 13 | `issued` not tied to the chain | A forged `issued` made the node **refuse a block that every full node accepted** — two verdicts on the same block, hence a split | Same check: an impossible `issued` gets the snapshot rejected and revalidated | `ba_forged_issued_gets_a_valid_block_refused`, `bb_forged_issued_falsifies_the_reported_emission` |
| 14 | Importable state file | A "fast sync snapshot" from elsewhere was adopted | HMAC-SHA256 **seal** with a key specific to the directory (`node.key`, 0600) | `an_arbitrary_file_is_not_a_snapshot` |
| 15 | Foreign genesis adopted | A crafted `blocks.dat` — without proof of work, with a 21 M premine to the attacker — became the root | The first record must carry **the network's genesis identifier** | `f_a_foreign_block_file_is_adopted_as_genesis` |
| 16 | Forged address cache | A single substituted hash: wrong balance, own funds hidden, and a Lamport key **burned** for a transaction the network rejects | Three barriers: cache **sealed** with a key derived from the seed; full re-derivation under 1,024 addresses, a √n sample beyond; and above all, `create_transaction` checks that the key opens the lock **before** signing | `m_forged_address_cache_is_adopted`, `n_forged_cache_falsifies_the_balance_and_hides_the_funds`, `o_forged_cache_burns_a_lamport_key` |
| 17 | Pinnable peer address book | 512 groups filled with never-reached addresses, `last_seen = u64::MAX`: no honest address could get in any more, selection returned only the attacker's — **a complete eclipse without owning a single machine** | Timestamp bounded on insertion; a group that has never answered gives up its place; the selection order depends on a **local salt**, not on a field the adversary writes | `p_hostile_address_book_pins_every_group` |
| 18 | Peer successes forgotten | The address book was rewritten from scratch at every shutdown: a node forgot at each restart which peers had actually answered it | Entries are written as they are (`save_entries`) | `disk_round_trip` |
| 19 | Received blocks never written | Only blocks **mined by the node itself** reached the disk. A node that mined while syncing produced a file with holes and restarted seven blocks back, without a word | `Journal` trait plugged into the chain: accepting a block and keeping it are the same decision. Side branches too, otherwise no reorg survives a restart | `d_bis_the_node_no_longer_restarts_after_mining_while_syncing` |

### The accepted debt: the commitment to the UTXO set

The consistency checks catch any falsification that **creates** money. They do
not catch one that **moves** it: rewriting the hash of an existing output
respects all the emission invariants.

The directory seal closes the realistic case — a file from elsewhere. It does
not close the case of an adversary who already has write access to the
directory, and on that point the position is Bitcoin Core's, stated frankly:
whoever can rewrite your files can also rewrite the binary.

The definitive answer is a **commitment to the UTXO set written into the block
header** — a MuHash-style homomorphic accumulator, updated in constant time for
each output created or spent. It would make any snapshot verifiable in O(1)
against data carried by the proof of work. It requires 3,072-bit modular
arithmetic, hence new consensus code: it is not a line to add, and it is not
something to rush on the eve of a launch. **It is recorded as a prerequisite
for mainnet, not for the testnet.**

## The real launch — what the closed loop had not seen

All the tests above run in the same process. A real launch, by contrast, runs
real binaries, on real files, with real sockets. In fifteen minutes it found
two defects that 480 tests had not seen — one of which **I had just introduced
while fixing something else**.

### The run

| Step | Result |
|---|---|
| Two new wallets, same genesis | `8e16a638…` on both sides |
| Alice mines 205 blocks | 0.66 s — 79,673 hashes/s |
| Alice sends 0.005 Q21 to Bob | transaction `fca8d6ec…`, 98 KiB Lamport witness (99% of the size) |
| Bob syncs over TCP | 206 blocks, 205 compact blocks **without a single round trip** |
| Bob receives | 0.00500000 Q21, survives a restart |
| Bob sends 0.002 Q21 back to Alice | full round trip |
| Two nodes mine against each other, 30 s | 1,095 blocks, **0 orphans, 0 invalid** |
| Consensus | block 1300 identical byte for byte on both sides |
| Monetary invariant | issued = sum of UTXOs = 586.55780008 Q21, **exactly** |
| Replay of an old `wallet.dat` | refused, with the steps to follow |
| Corrupted snapshot | ignored, chain revalidated, same tip |
| Block file from another chain | refused, naming both genesis blocks |
| CSRF, DNS rebinding, token in the URL | 403, 403, 401 |

### Flaw 20 — the safety fallback no longer worked

Fixing flaw 19 — recording side branches **as well**, otherwise no reorg
survives a restart — broke the full replay. The replay called `connect`, which
requires every block to extend the active tip. The file has no longer been a
straight line since it started containing the competing branches that any race
between miners produces.

The node refused to restart:
`block 853 refused on replay: BadHeight { expected: 853, received: 218 }`.

And this path is precisely the **fallback**: the one taken when the snapshot
is lost or suspect. The defect made it unusable at the moment it matters.
`submit` replaces `connect`; the file order is the acceptance order, so a
parent always precedes its children in it. Test:
`a_file_containing_side_branches_replays`.

**The takeaway**: this defect was invisible in a closed loop because no test
produced a side branch *and then* restarted without a snapshot. It took two
processes, two miners and thirty seconds of racing to bring it out.

### Flaw 21 — the protection made the node unusable

Requiring the token for the explorer page returned a plain-text `401`: the
page could no longer load, and therefore could no longer ask for the token.
The node was protected and out of service. The static shell — which carries
no data — is now served freely, through a list of **explicitly named** paths,
empty by default; every RPC method stays behind authentication.

### Two fixes made during this launch

- **`local_host` compared a text prefix.** `127.0.0.1.evil.example` is a
  domain name anyone can register in five minutes, and it got past all four
  locks at once: DNS rebinding was fully reopened. The filter now parses an
  address. Test: `a_name_that_looks_like_loopback_is_not_loopback`.
- **The global deadline did not reach down to the read.** `read_header_line`
  reads byte by byte; one byte every twenty-five seconds held a connection for
  tens of hours. Sixty-four were enough to shut the service down.

### What remains open after the real launch

Nothing that steals funds, nothing that breaks consensus. What remains is
**denial of service** and **fee market quality**:

| Finding | Nature | Why it is not blocking for a testnet |
|---|---|---|
| Cost of saturating the mempool (t03, t06, t08) | A node's resources | No funds at stake. A testnet is where you measure whether this really bites |
| CPFP broken by eviction (t12) | Fee market | A well-paying transaction can be evicted along with its parent. Annoying, not dangerous |
| ~~Message malleability (4 findings)~~ | **Closed** | A decoder now refuses what it cannot represent, instead of truncating |
| ~~Memory amplification on read~~ | **Closed** | 61,115 times what is received, brought down to zero. See below |

### Reading a message no longer amplifies anything

The allocation ratio was measured by `allocation_ratio_per_message`, and
nobody had ever read it: the measuring tool itself overflowed — it subtracted
the size of blocks freed during the measurement but allocated before it, the
counter went below zero, and the next addition panicked.

Once the tool was repaired, the report is unequivocal:

```
inv          :    27 bytes sent -> peak   1650003 bytes allocated (x61111)
getdata      :    27 bytes sent -> peak   1650007 bytes allocated (x61111)
headers      :    27 bytes sent -> peak    320007 bytes allocated (x11852)
block        :   189 bytes sent -> peak    262149 bytes allocated (x1387)
```

Twenty-seven bytes announcing fifty thousand inventory items — fifty thousand
is the protocol's bound, so the check passed — made the node reserve one
million six hundred fifty thousand bytes before failing on a premature end.
For the price of one send, and on sixty-four connections.

Capping the reservation with `with_capacity(n.min(1024))` mitigated without
closing: a factor of a thousand remained.

The rule that closes this fits in one sentence, and applies to every decoder:
**never reserve room for more elements than the rest of the input can
contain.** Each element having a known minimum size on the wire — thirty-three
bytes for an inventory item, forty for a transaction input, forty-one for an
output — the comparison is exact and costs nothing.

After the fix, the worst ratio of all messages is **zero**.

## The chosen security level: ML-DSA-87

The question asked was about a 512-bit private key. The answer comes down to
two facts, and the second one decides.

**FIPS 204 fixes the seed at thirty-two bytes for all three levels.** The
library says so in its own code: *"ML-DSA seeds are signing (private) keys,
which are consistently 32-bytes across all security levels"*. A 512-bit seed
would require rewriting ML-DSA by hand — the one thing this project forbids
itself, and for good reasons.

**And it would bring nothing.** ML-DSA's quantum resistance does not come from
the seed length but from the lattice problem. A 256-bit seed against Grover is
worth 2^128: a wall nothing will reach.

The real lever is the level of the standard, and the measurement settled it:

| | ML-DSA-65 | ML-DSA-87 |
|---|---|---|
| NIST level | 3 (~AES-192) | **5 (~AES-256)** |
| Verifications per second | 3,944 | 2,494 |
| Public key | 1,952 B | 2,592 B |
| Signature | 3,309 B | 4,627 B |
| Full transaction | 5,403 B | 7,361 B |
| Transactions per 2 MB block | 370 | 271 |
| **Full block verified in** | **94 ms** | **109 ms** |

The block targets one hundred twenty seconds. The maximum level costs
**fifteen milliseconds per block**. What is really paid is throughput — 27%
fewer transactions for the same size — and that trade-off leans toward the
margin: a chain is launched once, and the addresses it issues live for
decades.

**ML-DSA-87 is therefore Q21's default.** Locked in by
`the_default_is_the_maximum_level_of_the_standard`: the scheme is part of the
genesis block's identifier, so letting it drift would change the chain.

### What was not done, and why

**Hashes stay at 256 bits.** Moving from SHA-256 to SHA-512 would touch 273
places in the code — all of consensus, all of storage, and the memory-hard
tuning from phase 6. The price would be paid by the user: an address of **113
characters instead of 62**, a backup code of 117, a block header of 288 bytes
instead of 160. The gain would be nil: Grover on SHA-256 gives 2^128, the same
unreachable wall. It is Bitcoin's choice, and it is not disputed.

### Checked on a real launch

Testnet, two nodes, ML-DSA-87 end to end: identical genesis on both sides —
`02140e8a…` at that date, a commitment to the consensus of the time, changed
since; what was being measured there was the agreement of the two machines,
not the value — 205 blocks mined, a 7,361-byte transaction, sync over TCP,
receipt of 0.005 Q21, round trip back to the sender. The signature benchmark
is kept: `cargo run --release --features mldsa --example bench_sig`.

## What remains, and matters more than everything else

**The proof of work has still received no external cryptanalysis.** Since
phase 6, it has been the most important open point of the project.

And this audit was carried out by auditors I instructed, on code I wrote. It
found eleven real flaws, which proves its usefulness — and proves nothing about
what it did not find. **An external human audit remains necessary before a
single Q21 has any value.**

---

## Third wave — the September 2026 review

A full review, read-only at first: the whole test suite replayed, two
simulations written on the side to quantify what the tests did not measure,
then a report ranked by severity. The fixes followed, one per commit, each with
its test. Since the live network is the test network, the rules changed
without delayed activation: new genesis, new network magic, protocol version
2.

### What touched the heart of the project

**The proof-of-work memory walk fit in 32 bits.** The index of each read came
from the low 32 bits of the accumulator, and the addition never carried
anything up into them: the thirty-two reads of an attempt depended only on a
32-bit word. A table of 2³² sums — 128 GiB, computed once per epoch — replaced
the walk with a single read, and the table's growth no longer protected
against anything. Checked by simulation: out of a thousand pairs of states
with the same low bits, none diverged. The index now depends on all four words
of the state, and each read is followed by four Feistel rounds on the
SplitMix64 finalizer — about twenty nanoseconds, for a DRAM access that costs
about a hundred. Tests:
`states_with_same_low_bits_do_not_walk_same_addresses`,
`read_diffuses_over_whole_state`.

**A partition with equal power became permanent in two hours.** The reorg
penalty grew without a ceiling; each half of the network saw itself penalized
against the other. Simulation with the real rule: last possible reunification
at 66 blocks median for a 50% minority, 153 at 40% — the documentation
announced twenty-four hours. Ceiling at 25%: any majority above 56% reunifies
within the window. Test `a7_a_60_40_partition_always_reunifies`.

**Creating an output cost nothing.** Neither a floor nor a rate beyond one unit
per thousand weight units: twenty gigabytes of RAM per day imposed on every
node for a few thousand units, and a miner, who pays its own fees to itself,
was held back by nothing. Consensus floor at 10,000 units per output, coinbase
included; 400 weight units per output created, at relay; relay floor at 10;
the wallet refuses dust before signing and leaves change below the floor to
the fees.

**The table caps at 4 GiB, plus 8.** A machine with 8 GB is enough forever;
that was the promise.

### What froze or misled the node

- Every transaction received and every block connected **copied the whole UTXO
  set** under the global lock. The mempool reads a reference.
- The MuHash commitment was **fully recomputed** — a 3,072-bit multiplication
  per output, 19 µs each — on every public explorer display and every
  snapshot. Now maintained incrementally; `commitment()` costs one division,
  whatever the size.
- The difficulty of the next block copied **every header since genesis** at
  each connection. It reads the window.
- The miner **mined under the chain lock**, two million attempts per round,
  and built its table there at epoch changes: seconds, then minutes, without a
  single block processed or peer served. It mines outside.
- A side branch was **not checked on its timestamp**: difficulty dropped along
  the branch, and 4 MiB bodies got in cheaply. Same check as on the active
  chain.
- The bodies of an adopted sync snapshot **reached the disk without being
  checked against the headers**. They are, before a single byte is written.
- The symmetric bound on solve times still gave **a third more blocks** to
  anyone who pushed their timestamps forward with half the power. Asymmetric
  bound `[-6T, +4T]`: the manipulation increases the difficulty and costs its
  author; future tolerance brought down to ten minutes.

### What touched the wallet

- A **passphrase confirmation that differed** was treated as "no passphrase":
  a plain-text seed for a typo. Asked again, then refused.
- Consumed Lamport indices were written **after** signing and through a
  callback with no result: a power cut at the wrong moment caused signing
  again with a dead key. Written ahead, `fsync`, refusal if the disk refuses.
- The signed message committed to **neither the network nor the spent
  output**: a testnet signature was valid on the other network. The hash
  commits to both, like BIP-143.
- The Merkle leaf committed only to the `txid`: a signature could be
  **replaced in transit**. It also commits to the `wtxid`.
- Secrets wiped when destroyed, `Q21_PASSPHRASE` removed from the process's
  environment variables after reading, no core dumps on Unix.

### What was removed

**Uncles.** Their share was taken from the miner who included them: nobody did
so, the binary's miner never did, and the mechanism had already carried three
defects. A block that carries any is refused.

### The release pipeline

Pinned toolchain (`rust-toolchain.toml`), provenance attestation signed by
GitHub for each archive, a single `SHA256SUMS` signed with `minisign` when the
repository holds the key, `cargo deny` on every push. The `audit_difficulty`
test, fully green since its last outdated finding was rewritten, now blocks the
release like the others.

### What remains

**The proof of work has still received no external cryptanalysis.** Its mixing
loop has just been redone; that is one more reason, not one fewer. The
compiled-in anchors are empty as long as no chain has enough history to
deserve one. And this review, like the previous ones, proves nothing about
what it did not find.

### Immediate follow-up — the wallet lock

The wallet file was sealed with PBKDF2, which costs only computation: the
README had said so since phase 8, and the September report ranked it among
what directly protects people. The derivation is now **Argon2id** (RFC 9106,
64 MiB, three passes), written from the standard with BLAKE2b (RFC 7693),
checked against the three official vectors, then cross-checked by an
independent implementation on the exact form the wallet uses. Files in the old
format open and are resealed on opening; opening a wallet costs 0.19 s on a
small processor, less than before, for incomparably greater resistance to
dedicated hardware.

### Immediate follow-up — the disk, and monitoring

**The block file can be pruned** (`node --prune`): a node that validates for
itself keeps only the genesis and the last six thousand bodies — the wallet
history window plus the reorg window, eight days — and summarizes the rest in
the snapshot, like a node that started from a sync snapshot. The write order is
proven by a test that prunes a chain then restarts it exactly as the binary
does: same tip, same UTXO set, same emission, and it carries on. A pruned node
refuses to serve as an explorer. The archive now serializes appends, reads and
rewrites under a single lock.

**Monitoring without watching** (`tools/monitor.sh`): the height is read again
every ten minutes; if it is frozen for thirty minutes, or the RPC is silent,
the service is restarted and a phone notification is sent. Nothing more than a
script and a timer — but it is the difference between a network and a project.

## Fourth wave — the adversarial audit, and its fixes

A review carried out as an attacker, on five axes read line by line —
consensus, network, wallet, proof of work and disk, operations — with tests
written to reproduce each lead. The verdict first: **no path to inflation,
double spending or remote key exfiltration**; the monetary invariants hold, and
the decoders, sealing, sighash, difficulty and snapshot held up. The flaws were
elsewhere, and all of them are closed by this wave.

| Flaw | What is closed, and how we know |
|---|---|
| A transaction with a false signature, pushed by a stranger without a handshake, forced a post-quantum verification **under the global lock**: sixty per second froze a node | `Tx` and `Block` require the handshake; per-peer budget (64, then 8/s); a transaction that is invalid in itself costs points. Tests `nothing_is_read_before_the_handshake_even_when_pushed`, `the_per_peer_transaction_budget_ends_up_disconnecting` |
| A parent→child chain within the same block was refused by the validator but packed by the miner: invalid block, wasted work, production frozen | `check_block` validates against a view overlaying the outputs created earlier in the block. `regression_chaining.rs`: the chain goes through, double spending and child-before-parent stay refused |
| The wallet token went through the browser's command line, readable by any account on the machine | On Linux, the account holding the other end of each local connection is requested from the kernel; any other account is refused. Test `the_local_connection_is_attributed_to_our_account` |
| A single IP occupied all thirty-two slots | Eight slots reserved for outbound connections, four inbound per `/16` group. Test `listening_reserves_slots_for_outbound` |
| Silent addresses slipped into the address book made one loop iteration last more than a minute, and the node cut itself off from all its peers — sleep was inferred from the iteration's duration | The sleep detector lives on its own thread and only looks at the wall clock; connection bounded to four seconds |
| Repairing a truncated tail threw away up to 64 MiB — a bit flipped in the middle of the file erased dozens of valid blocks | Bounded to one consensus block; what is cut is copied aside. Tests `a_tail_longer_than_a_block_is_not_cut`, copy checked |
| A hard shutdown during mining left `next_index` behind the chain: invisible rewards, with no repair | Wallet written after each block found; **catch-up** at load time of addresses handed out beyond the file; scan of one-time keys restarted after any discovery. Test `catch_up_finds_addresses_handed_out_after_the_last_write` |
| Pending compact reconstructions without a bound; requested bodies never monitored | Four in flight per peer; a body not delivered within sixty seconds is requested elsewhere and costs fifty points |
| Scans of two thousand bodies under the lock, without a token, in public mode | Scan budget: thirty, then twelve per minute, across all requests |
| Unsigned release; toolchain action tracked on a moving branch | `minisign` signature at every release, **mandatory**; `rustup` instead of the action; script pinning actions by hash |
| Damaged genesis filed as a foreign chain; corrupted body outside the tail making any startup impossible; bodies not `fsync`ed; Argon2id bound at 1 GiB; monitoring file in `/var/tmp` | Canonical genesis copied back; cut at the last sound block; `sync_all`; 256 MiB; `RuntimeDirectory` and symbolic link refused |

What the wave does not change, and has restated: the anti-ASIC property
remains a hypothesis as long as the proof of work has not received external
cryptanalysis — the `POW_K` comment that spoke of latency "without a decisive
advantage" has been brought back to what the construction guarantees, memory
bandwidth. And on a machine that reads its passphrase from a file, sealing does
not protect against theft of the storage medium: it is a trade-off to be aware
of, written in `HARDENING.md`, not a defect to fix.
