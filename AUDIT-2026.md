# Q21 against the 2026 state of the art

An audit of the chain against the best of what is done today, with a
deliberate angle: **speed**. Nothing below changes what has been built — these
are directions for improvement, ranked by horizon, each backed either by a
measurement made here or by a dated external source.

The starting lesson is the one this document must keep in mind: Bitcoin did
not plan for its own success. In 2023, a wave of inscriptions drove its fees up
by more than 4,000% and left hundreds of thousands of transactions waiting for
days. Congestion is not an accident: it is what happens to any chain whose
demand exceeds its throughput, and the only question is whether it was
anticipated.

---

## 1 · Where Q21 is already on par — or ahead

| 2026 standard | Bitcoin today | Q21 today |
|---|---|---|
| Post-quantum signatures | BIP-360/361: **proposals** under debate, migration not started | **Shipped**: ML-DSA-87 (FIPS 204, level 5) by default, addresses with a versioned scheme so it can be changed without breaking anything |
| Compact block relay | Compact blocks (BIP-152), deployed | **Shipped**, measured: announcement < 2 KiB for a ~5 MiB block, 200 blocks synced without a single round trip |
| Anti-eclipse | Buckets per network group, deployed | **Shipped**: per-node salted /16 buckets, dead-peer detection < 20 s |
| Anti-ASIC | None (SHA-256, foundries) | **Shipped**: 2 GiB table growing by 5% every 71 days — supported hypothesis, external cryptanalysis still owed |
| Exact emission | ~979 satoshis never issued, accepted | **Shipped**: tail floor + clipping, 21,000,001 reached to the unit (block 26,273,578) |
| Wallet without a terminal | Standard for a long time | **Shipped** this phase: screens, guided restore, mining controls |

The point worth stating without false modesty: on signatures, Q21 is **ahead
of Bitcoin**, which is at the proposal stage (BIP-360 "P2QRH" and BIP-361)
while Q21 already signs every transaction with ML-DSA-87. That is the
advantage of being born after the FIPS 204 standard instead of having to
migrate to it.

## 2 · Speed, quantified honestly

Two distinct quantities, which everyday language confuses:

**Latency** — how long before my payment is confirmed. Q21 targets one block
every **2 minutes**, versus 10 for Bitcoin: first confirmation in ~2 min on
average, five times faster. And the interface shows the transaction as soon as
it enters the mempool, honestly marking it as unconfirmed.

**Throughput** — how many payments per second the chain accepts. This is where
the wall is real and documented (PROJECTION.md): an ML-DSA-87 transaction
weighs 7,361 bytes, a block carries 569 of them, that is **4.74 tx/s**. It is
the price of quantum resistance, and no incantation makes it go away.

What follows ranks the levers that push this wall back, from the most
immediate to the most distant.

---

## 3 · Immediate directions — without touching consensus

### 3.1 Batched payments: from 4.7 to 300+ payments per second

The measurement that changes the perspective: in a Q21 transaction, **the
signature is nearly all the weight; an output weighs only 41 bytes**. Paying a
hundred people in a single transaction therefore costs barely more than paying
one:

| Recipients per transaction | Bytes per recipient | Payments per second |
|---:|---:|---:|
| 1 | 7,361 | 4.7 |
| 10 | 773 | 45 |
| 100 | 114 | **306** |
| 500 | 56 | 625 |

A service that pays out earnings — mining pool, exchange — multiplies useful
throughput by 60 by batching. The protocol already allows it; what is missing
is the **tooling**: `sendmany` in the RPC and a multi-recipient send screen in
the wallet. This is the direction with the best effort-to-effect ratio in the
whole document.

### 3.2 The fee market: the anti-congestion defense, and it has already been audited

Bitcoin's 2023 congestion did not break the chain: it broke the *experience*
— unpredictable fees and waits of several days. The defense is called a
healthy fee market: a mempool that evicts the lowest-paying transactions,
estimates the required rate, and refuses the unacceptable early and cheaply.

Ours has already been audited from the inside, and the findings are known:
**8 open findings in `audit_mempool`** (fee filter applied after signature
verification — hence expensive for us to saturate and not for the attacker;
transactions larger than a block accepted then never mined; eviction of honest
transactions by unminable ones; quadratic `revalidate`) and **1 in
`audit_difficulty`**. None threatens funds; all of them concern exactly what
congestion would exploit. Fixing them is the second immediate direction — it
is the "Satoshi had not planned for it" work done in advance.

### 3.3 Transaction relay: Erlay as a model

Blocks already travel in compact form. **Transactions**, on the other hand,
are announced to every peer — that is the bandwidth item that will explode
with the number of peers. Bitcoin designed Erlay (set reconciliation, ~40%
less bandwidth, still being integrated into Core after years). Q21 does not
need it with ten peers; the testnet will tell from what point one is needed.
To be noted as debt, not as an emergency.

---

## 4 · Directions prepared by the design — can be enabled later

### 4.1 Signature aggregation: the way up and out of the 4.74 tx/s wall

The state of research, dated: **half-aggregation** of lattice-based signatures
is published (eprint 2023/159), non-interactive aggregation schemes in the
Fiat-Shamir paradigm are appearing in 2024-2025, and security under adaptive
corruptions is an active topic (eprint 2025/1955). **Nothing is standardized
or proven in production yet.** Mature aggregation would divide the weight of a
block's witnesses — and therefore multiply throughput — without touching the
target security.

Q21 does not have to bet today: every address carries the identifier of its
scheme, precisely so that a future aggregatable scheme can be added alongside
ML-DSA-87 without breaking what exists. This direction consists of
**monitoring this literature every year** and keeping the agility intact —
never shipping anything that assumes a single "the scheme".

### 4.2 Sync in minutes: MuHash, then snapshots

The 2026 standard is AssumeUTXO (Bitcoin Core 28): load a snapshot of the UTXO
set and be usable within minutes while the history is verified in the
background. Q21 already has the cheap verification building block (64 MiB
cache, ~660 µs per header); what it lacks is **the UTXO commitment (MuHash)**
— already a mainnet prerequisite in the roadmap — so that the snapshot is
verifiable rather than taken on trust. Required order: MuHash first, snapshots
afterwards.

### 4.3 Faster blocks, if the testnet allows it

Two minutes is a choice marked PROVISIONAL in the code, and it is the most
direct latency lever. What forbids shortening it blindly: more frequent blocks
produce more orphans, and orphans favor the best-connected miner —
centralization through the race. Q21 has precisely shipped both shock
absorbers: compact relay (the cause) and uncle rewards at 25% (the
consequence). **The decision will be made on the measured orphan rate of the
public testnet**, not on reasoning — it has been written in `consensus.rs`
since day one.

### 4.4 The second layer: after the testnet, not before

At the scale of millions of users, no base chain pays for a coffee — Bitcoin
has Lightning, Ethereum its rollups. Q21 will get there, but a layer 2 is
built on measured foundations: a healthy fee market, reorgs observed under
real conditions, stabilized transaction formats. Committing to it now would be
building on sand.

---

## 5 · Recommended order

1. **`sendmany` + multi-recipient send in the wallet** — ×60 throughput for
   bulk payers, a few days of work, zero consensus risk.
2. **Fix the 9 mempool/difficulty findings** — the anti-congestion defense;
   the tests already exist and fail, documenting the issue.
3. **Open the public entry node** (SERVER.md) — every measurement that decides
   the rest (orphans, fees, saturation) depends on it.
4. **MuHash**, then sync snapshots.
5. Reassess every year: ML-DSA aggregation, block interval, Erlay, layer 2 —
   based on measurements and literature, never on the mood of the moment.

What this audit does not cover, and which remains the project's most serious
debt: **the proof of work has received no external cryptanalysis.** No speed
direction comes ahead of that one on the day mainnet is discussed.
