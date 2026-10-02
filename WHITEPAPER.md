# Q21 — whitepaper

**A blockchain with post-quantum signatures, mineable by people.**

Working draft. The reference edition — describing the protocol as it runs
today — is in [`whitepaper/`](whitepaper/Q21-White-Paper.html), as an HTML
page and a PDF. Research code, not audited by a third party. No Q21
has any value, and none will until this document stops carrying this
warning.

---

## 1. What is at issue

Bitcoin solved a problem no one had solved before: agreeing, without an
authority, on who owns what. That part holds, and Q21 leaves it
untouched.

Three things, however, are not design flaws but debts of their era — choices
made in 2008, correct at the time, that have since become dead ends.

| The sticking point | Why it can no longer be fixed in Bitcoin |
|---|---|
| ECDSA signatures fall to Shor's algorithm | The original address format never anticipated that another scheme might exist |
| Mining has moved to silicon foundries | SHA-256 is exactly what a dedicated circuit does best |
| The 21,000,000 cap was arrived at by trial and error | It has become a totem that can no longer be questioned |

Q21 is not a fork of Bitcoin. It is a chain written from scratch that keeps
Bitcoin's foundations and fixes those three points.

---

## 2. What Q21 does not change

This needs saying as clearly as everything else, because a project that claims
to reinvent everything reinvents nothing.

- **Proof of work** as the consensus mechanism. No proof of stake: it makes
  the right to decide depend on what one already owns.
- **The UTXO model**: coins, not accounts.
- **The chain with the most work wins.**
- **Every node validates everything itself.** A light client asks a server
  what the chain contains — which is to say it trusts someone, in a system
  built to trust no one.

---

## 3. The cap: 21,000,001

Twenty-one million **and one unit**.

The extra coin is minted only once, in the genesis block, outside the
issuance schedule. It has no technical function.

It says one thing, and one thing only: **this number is a parameter, not a
revelation.** A cap must be finite, known in advance, and verifiable by
anyone; it does not have to be sacred. The extra coin is there to keep it from
becoming so.

The invariants, for their part, are checked continuously: the sum of unspent
outputs never exceeds what has been issued, and what has been issued never
exceeds the theoretical schedule at that height.

---

## 4. Signatures: breaking out of the prison

### The problem

ECDSA rests on the hardness of the discrete logarithm. Shor's algorithm
solves it — in polynomial time, on a sufficiently capable quantum computer. No
one knows when such a machine will exist; everyone knows that a chain designed
to last cannot bet on it.

Bitcoin cannot simply "switch schemes": its addresses do not encode which
scheme they belong to. Adding ML-DSA to Bitcoin requires a hard fork and
moving all funds.

### The fix

**Q21 encodes the scheme identifier in the address itself.** Adding a scheme
becomes a compatible upgrade, never a hard fork.

The chosen scheme is **ML-DSA-87** — FIPS 204, NIST level 5, comparable to
AES-256. It is the highest parameter set the standard defines.

| | ECDSA | ML-DSA-87 |
|---|---|---|
| Public key | 33 B | 2,592 B |
| Signature | 71 B | 4,627 B |
| Resistant to Shor | no | yes |

The cost is real: a signature is 47 times the size of an ECDSA one. It is
paid knowingly, and it drives several other parameters in this document —
block size in particular.

### What Q21 does not write itself

The core **does not implement** ML-DSA. Writing a lattice-based signature
yourself is professional malpractice: side channels, rejection sampling, and
constant-time arithmetic are exactly the terrain where a homegrown
implementation looks correct, passes every functional test, and leaks the
private key.

A useful reminder: in February 2022, **Rainbow** — a NIST competition
finalist — was broken over a weekend on a laptop. A few months later, **SIKE**
fell in an hour on a single core. Both schemes had survived five years of
public scrutiny by professional cryptographers.

Q21 defines the interface and plugs in an audited implementation.

### On 512-bit keys

FIPS 204 fixes the seed at **thirty-two bytes for all three security
levels**. A 512-bit seed would require rewriting ML-DSA by hand — precisely the
one thing this project refuses to do. Security is set by the parameter level,
not by the seed size: that is why Q21 uses level 5.

---

## 5. Accessible mining: three levers

This is the heart of the project, and the part where it is easiest to get
things wrong.

### The observation

A proof of work that is pure computation — SHA-256 — is exactly what a
dedicated circuit does best. A SHA-256 circuit outperforms a CPU by a factor on
the order of **10⁸**. The outcome is not hypothetical: Bitcoin mining has
concentrated in a handful of foundries and a handful of regions with cheap
electricity.

Reusing SHA-256 as the proof of work would restart that race. Q21 uses
SHA-256 as a hash function — for identifiers, the Merkle tree, addresses — but
**the proof of work is something else**.

### Lever A — a memory-bound proof of work

The principle: make the computation depend on a large table held in memory, so
that the scarce resource is no longer silicon but **memory bandwidth** — the
one thing a dedicated circuit cannot manufacture, because it buys it on the
same market as everyone else.

**The first version was wrong, and measurement is what revealed it.**

Each table element was derived from an independent hash,
`element(i) = H(seed, i)`. On the real 2 GiB table:

| Fraction held | Memory | Relative cost per attempt |
|---|---|---|
| 1/1 | 2,048 MiB | 1.00 × |
| 1/8 | 256 MiB | 2.85 × |
| **0/1** | **0 MiB** | **2.86 ×** |

Doing **entirely** without memory cost only 2.86 ×. A circuit whose hashing is
three times faster than a CPU's therefore had every incentive to carry no
memory at all. The anti-ASIC property did not hold.

It had been "verified" on a 32 MiB table, which fit entirely in cache and
showed a reassuring 6.46 ×. **Only measurement at the real size told the
truth.**

### The fix, in two tiers

The structure follows that of Ethash:

- **The cache** — table / 32, i.e. 64 MiB. Generated **sequentially**: element
  `i` depends on `i-1`, and the whole cache is then mixed three times. No
  fragment of it can be rebuilt without rebuilding everything that precedes it.
- **The table** — 2 GiB. Each element is computed from **256 dependent random
  accesses** to the cache.

Mining without the table therefore no longer saves memory: it multiplies the
number of accesses by 256, and the bandwidth with it.

| Fraction held | Memory | Before | After |
|---|---|---|---|
| 1/1 | 2,048 MiB | 1.0 × | 1.0 × |
| 1/8 | 256 MiB | 2.85 × | 39.7 × |
| **0/1** | **0 MiB** | **2.86 ×** | **47.8 ×** |

**2.86 × → 47.8 ×**, a factor of 16.7 on the very property that justifies
everything else.

### The table grows

Its size grows by **5% per epoch** — an epoch is 51,200 blocks, or about 71
days. It starts at 2 GiB and caps at 4 GiB, reached around the third year. The
cap was lowered from 8 to 4 GiB: beyond that, the table weighed more heavily on
individuals — a Raspberry Pi 5 or an 8 GB laptop — than on dedicated silicon,
which can buy as much memory as it likes.

A circuit designed around a fixed amount of memory becomes mediocre as soon as
the table outgrows it. **Dedicated hardware thus makes itself obsolete**,
without any need to call a defensive hard fork every six months — something
Monero had to inflict on itself four times between 2018 and 2019.

### The cost, stated plainly

A verifying node previously had to hold **no** memory at all. It must now
hold the cache: **64 MiB**. Verifying a block goes from ~45 µs to ~660 µs. That
is the exact cost of the fix, and it is the same trade-off Ethereum made.

A miner holds 2 GiB and rebuilds its table once per epoch — about 24 minutes
on two cores, every 71 days.

### Lever B — issuance that does not reward arriving first

Bitcoin's rewards are cut in half all at once, every four years. Each halving
is a cliff: an economic shock that is scheduled, predictable, and ripe for
speculation.

Q21 decays **continuously**: the reward is multiplied by 0.9971555 every 4,320
blocks (~6 days), which gives a half-life of four years. The same long-term
trajectory, without the cliff.

The factor is stored as an integer fraction — `99,715,550 / 100,000,000` —
never as a floating-point number: `reward × NUM / DEN` is bit-for-bit
reproducible on every platform; `reward × 0.9971555` is not.

On top of this comes a **startup ramp** of 20,000 blocks (~28 days), during
which the reward rises linearly from zero. Without it, the few miners present
in the first week would capture a disproportionate share of the total supply.

And the curve ends, exactly. A geometric decay truncated to integers never
reaches its cap — computed along the actual trajectory, 137,899 Q21 would have
remained forever uncreated. A **tail floor** of 0.01 Q21 per block takes over
once the decay falls below it (around year 42), and cumulative issuance is
clipped exactly at the cap: the last issuing block, at 99.91 years, receives
the exact remainder, and then nothing more. **Every one of the 21,000,001
units eventually comes into existence** — the number that gives the project its
name is a promise kept, not an asymptote. A test checks the equality down to
the last unit.

### Lever C — paying for lost work

A large miner wins propagation races, and therefore earns **more** than its
share of hash power. This superlinear return concentrates mining without
anyone attacking anything.

Two measures:

- **Compact relay** addresses the cause: a peer already has most of a block's
  transactions in its mempool, so it is sent only what is missing. Measured on
  three real nodes: 200 blocks relayed out of 219 announcements without a
  single round trip.
- **Uncle rewards** were tried, then removed. A block that arrived second would
  have been paid 25% of the subsidy, a share **deducted** from the miner who
  included it so that the cap would not move — and nobody includes an uncle at
  their own expense. The mechanism served only to open up an attack surface; a
  block carrying an uncle is now rejected. Compact relay is enough: at two
  minutes per block, orphan blocks are rare.

---

## 6. Finality

A deep reorganization is capped at 720 blocks. Beyond a depth of 6 blocks, a
competing branch must bring an increasing surplus of work.

This surplus is measured against **the fork's work**, not against the
cumulative work since genesis. The first version did the opposite: from height
71,400 onward — three months after a launch — no reorganization of depth 7
could succeed anymore, even with 100% of the hash power. Actual finality was
six blocks, not 720.

---

## 7. Provisional parameters, and why they are provisional

Three values are explicitly marked as provisional in the code, and will remain
so until a real network settles them.

| Parameter | Value | What will decide |
|---|---|---|
| Block interval | 120 s | The measured orphan rate. Two minutes cut variance by a factor of five compared with Bitcoin, but make propagation heavier — all the more so since signatures are 47 times larger |
| Maximum block size | 4 MiB | 1 MiB would limit a block to ~300 transactions, because of signature size |
| Fee market | rudimentary | Actual usage |

**These values will be confirmed by measurement, not by reasoning.** That is
the lesson of lever A, and it was expensive enough to be applied everywhere.

---

## 8. What is measured, what is assumed

This is the most important section of this document.

### Measured

- The relative cost of mining without memory: 47.8 ×, on the real 2 GiB table.
- Agreement between two operating systems: a Windows PC and a MacBook, with
  separately compiled binaries, agreeing bit for bit on 438 blocks, each having
  recomputed every ML-DSA-87 signature and every proof of work produced by the
  other.
- Relaying through an intermediary: three nodes, the one at the far end never
  having spoken to the miner, 0 orphans and 0 invalid blocks.
- Memory amplification when reading a message: reduced from 61,115 × to
  **zero**.
- Conformance of bech32m to the published BIP-350 test vectors, and of
  SipHash-2-4 to its own.

### Assumed

- **The proof of work has received no external cryptanalysis.** The
  measurements above were made by its author, on a single machine, against a
  reference implementation — not against an implementation optimized by
  someone whose job is to beat it. Until such a review exists, **the anti-ASIC
  property is a well-supported hypothesis, not an established fact.**
- Behavior on a genuinely hostile network.
- The fee market under load.

### What is missing before a mainnet

- A **UTXO set commitment** in the block header — a MuHash-style accumulator.
  It would make any snapshot verifiable against the proof of work. It requires
  3,072-bit modular arithmetic, and therefore new consensus code: not something
  to rush on the eve of a launch.
- An **external human audit**.

---

## 9. The acknowledged tension

A capped currency eventually pays its miners with fees alone. No one knows
whether a fee market is enough to fund a chain's security over the long term.
Bitcoin has the same problem and keeps putting it off.

Q21 does not claim to have solved it. It notes it, and notes it here rather
than letting anyone believe it does not exist.

---

## 10. Project status

| Phase | Status | Contents |
|---|---|---|
| 1 – 5 | done | Types, issuance, addresses, transactions, blocks, UTXO, difficulty, P2P network, RPC |
| 6 | done | **Anti-ASIC measurement on 2 GiB** — verdict, two-tier fix, re-measurement |
| 7 | done | Durability: incremental startup, bounded memory, anti-eclipse |
| 8 | done | **Adversarial audit**: real vulnerabilities fixed, encrypted wallet |
| — | done | Desktop wallet, block explorer, address index |
| 9 | in progress | **Open testnet** — the code is ready; a public entry point is still missing |
| 8b | open | **External human audit**: cryptanalysis of the proof of work |
| 10 | open | Mainnet — prerequisites: UTXO commitment, and the audit above |

---

## In one sentence

**Q21 keeps Bitcoin's foundations, protects them against quantum computers,
and puts mining back within reach of an ordinary machine — while stating
throughout what has been measured and what has not.**
