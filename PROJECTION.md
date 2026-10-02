# The life of Q21, computed

This document tells no story: it prints what the consensus functions return,
called height by height. All the figures come from
`cargo run --release --example projection`, which calls **the same code as
the validator**. A divergence between this table and the network would be a
defect of the network, not of the table.

Two exceptions, marked as such: the hash rate of an "average" machine
(400,000 attempts/s) and its power draw (80 W) are assumptions. Everything
that depends on them is flagged.

---

## 1 · How long does the chain issue coins?

Q21 has no halving every four years. The reward is multiplied by 0.99715550
**every 4,320 blocks**, that is roughly every six days. A smooth decay, with
no staircase steps.

The cumulative effect is nonetheless familiar:

> **The reward halves every 4.01 years.**

Almost exactly Bitcoin's pace — but spread out, instead of being concentrated
on a single moment that shakes the whole mining market at once.

### Year by year

| Year | Per block | Circulating | Of the cap |
|---:|---:|---:|---:|
| 1 | 11.6551 | 3,205,422 | 15.26% |
| 2 | 9.7961 | 6,016,430 | 28.65% |
| 3 | 8.2336 | 8,379,918 | 39.90% |
| 4 | 6.9203 | 10,367,132 | 49.37% |
| 5 | 5.8165 | 12,037,975 | 57.32% |
| 8 | 3.4536 | 15,617,136 | 74.37% |
| 10 | 2.4467 | 17,154,241 | 81.69% |
| 15 | 1.0263 | 19,304,086 | 91.92% |
| 20 | 0.4317 | 20,207,445 | 96.23% |
| 30 | 0.0762 | 20,746,536 | 98.79% |
| 50 | 0.0100 | 20,868,755 | 99.38% |
| 75 | 0.0100 | 20,934,500 | 99.69% |
| 100 | 0 | **21,000,001** | **100.00%** |

### The milestones

| Milestone | Block | Date |
|---|---:|---:|
| Half of the cap issued | 1,071,360 | **4.1 years** |
| Three quarters | 2,147,040 | **8.2 years** |
| 90% | 3,598,560 | **13.7 years** |
| 99% | 8,605,440 | **32.7 years** |
| 99.9% | 24,174,720 | **91.9 years** |
| **Cap reached, exactly** | 26,273,578 | **99.91 years** |

### The cap is reached — to the block, to the unit

A geometric decay truncated to integers never reaches its cap. Computed on the
first version of the schedule: the reward fell below the indivisible unit in
year 91, and **137,899 Q21 would never have been created**. The number carved
into the project's name would have been an asymptote, not a promise. Bitcoin
accepts that gap; Q21 could not.

The fix comes down to two rules, both in `emission.rs`:

**A tail floor.** The epoch reward is now `max(decay, 0.01 Q21)`. The floor
only bites the tail — the decay only falls below 0.01 around year 42, when
99.3% of the cap has already been issued — and it gives the miner of the long
tail a predictable floor subsidy income, on top of fees.

**An exact clip.** Cumulative emission is bounded by `EMISSION_CAP`, and the
reward of a block is *defined* as the difference of the cumulative totals:
the last issuing block — the **26,273,578th**, at 99.91 years — receives the
exact remainder of **0.00747908 Q21**, then the subsidy is zero forever. A
test checks the equality: at that height, the total supply is
**21,000,001.00000000** — not one unit less.

After the century, a miner lives on transaction fees alone. It is the same
horizon as Bitcoin, and the same open problem: nobody knows yet whether fees
alone are enough to pay for a chain's security.

---

## 2 · Fifteen million people: what holds, what breaks

This is the requested scenario: very strong adoption, Q21 among the ten most
mined cryptocurrencies. Three things happen, and they do not go in the same
direction.

### What holds very well: security

| Miners | Network hash rate | Electrical power |
|---:|---:|---:|
| 1,000 | 4.0 × 10⁸ attempts/s | 0.08 MW |
| 100,000 | 4.0 × 10¹⁰ attempts/s | 8 MW |
| 1,000,000 | 4.0 × 10¹¹ attempts/s | 0.08 GW |
| **15,000,000** | **6.0 × 10¹² attempts/s** | **1.20 GW** |

*(Assumption: 400,000 attempts/s and 80 W per machine.)*

1.20 GW continuously, that is about **10.5 TWh per year**. For comparison, the
Bitcoin network consumed **138 TWh per year** in July 2026 according to the
Cambridge index. Q21 with fifteen million miners would therefore consume
**thirteen times less than Bitcoin today**, while being mined by far more
people.

The reason is the same as for the whole project: a Bitcoin mining machine
burns 3,500 W because all it does is compute. A machine that waits for its
memory does not consume much — it waits.

And attacking such a chain would require gathering the equivalent of fifteen
million machines **with their memory**. That is precisely what cannot be
bought in a single order of dedicated chips.

### What changes in nature: solo mining disappears

| Miners | One block of your own every |
|---:|---:|
| 1,000 | 1.4 days |
| 100,000 | 139 days |
| 1,000,000 | 3.8 years |
| **15,000,000** | **57 years** |

With fifteen million participants, a single individual wins a block **every
fifty-seven years**. It is no longer an income, it is a lottery ticket.

The universal answer to this problem is pooling: a thousand, ten thousand, a
hundred thousand miners pool their power and share the gains pro rata. A pool
of one hundred thousand members wins a block every five hours and pays each
member their share, small but regular.

> ⚠️ **This is the centralization risk that remains, and it is real.** Q21's
> design prevents a chip foundry from taking over the network. It does not
> prevent three or four large pools from ending up directing the majority of
> the hash rate — which is exactly what happened to Bitcoin, with no ASIC to
> explain it.
>
> This problem is not solved in Q21 today. It is identified, and it will have
> to be solved before any mainnet.

### What breaks: capacity

This is the wall, and it has to be faced.

An ML-DSA-87 signature weighs **4,627 bytes** where an ECDSA signature weighs
71. A simple transaction, measured by building a real signed transaction,
weighs **7,361 bytes** — about **thirty times** a Bitcoin transaction.

| Quantity | Value |
|---|---:|
| Maximum block size | 4 MiB |
| Transactions per block | **569** |
| Transactions per second | **4.74** |
| Transactions per day | 409,680 |

At that rate:

| Holders | One transaction each every |
|---:|---:|
| 1,000,000 | 2.4 days |
| **15,000,000** | **36.6 days** |
| 100,000,000 | 244 days |

**Fifteen million people cannot use this chain as a means of payment.** One
transaction per person per month is the pace of a notary, not of a wallet.

And the price of widening it is brutal. For fifteen million people to make one
transaction per week, blocks of **21 MiB** would be needed — and the chain
would grow by **5.2 TiB per year**. No home machine would keep up, and the
network would shrink to the few able to store it: centralization through
storage, which is exactly what Bitcoin refused by keeping its blocks small.

### Disk, today

With the current blocks, if they were full:

| | |
|---|---:|
| Per day | 2.81 GiB |
| Per year | **1.00 TiB** |
| Block bodies kept (reorg window) | 3.94 GiB |

A node that keeps only what validation needs therefore lives with a few
gigabytes; an archive node pays a terabyte per year at full load.

### The honest conclusion

**Q21, as it is today, is a settlement layer, not a payment layer.** With
fifteen million users, it can be used to move sums that justify waiting, not
to pay for a coffee.

Three paths exist to get past this wall, and none is written:

1. **Aggregate signatures.** ML-DSA does not aggregate; another post-quantum
   scheme would be needed, and the protocol was designed to be able to switch
   — that is the whole point of the scheme identifier written into every
   address.
2. **A second layer**, where most exchanges settle off-chain.
3. **Bigger blocks**, at the price of storage and the centralization it
   brings.

The choice does not have to be made now. It has to be made **before**
claiming fifteen million users, not after.

---

## 3 · What the miner must hold, year by year

The proof-of-work table grows by 5% per epoch of 71.1 days, up to a cap of
4 GiB.

| Year | Epoch | Table (miner) | Cache (every node) |
|---:|---:|---:|---:|
| 0 | 0 | 2.00 GiB | 64 MiB |
| 1 | 5 | 2.55 GiB | 82 MiB |
| 2 | 10 | 3.26 GiB | 104 MiB |
| **3** | 15 | **4.00 GiB** | **128 MiB** |
| 10 and beyond | — | 4.00 GiB | 128 MiB |

Two readings:

- **A machine with 8 GB of RAM is enough forever.** The table stops growing
  at 4 GiB, which leaves as much for the system and everything else.
- **A node that does not mine never goes beyond 128 MiB.** Verifying stays
  within reach of anything, including a Raspberry Pi, forever.

This is a deliberate asymmetry: the entry cost of mining rises, that of
verification hardly at all. A chain whose verification becomes expensive is a
chain that nobody verifies anymore.

---

## 4 · The five ages, on one page

| Age | When | What dominates |
|---|---|---|
| **Bootstrap** | First 28 days | The ramp: the reward rises linearly from zero over 20,000 blocks. Nobody can rush in on an easy emission |
| **Youth** | Up to 4 years | Half of the Q21 is issued. The subsidy pays for everything; fees do not count |
| **Maturity** | 4 to 14 years | 90% issued. The table reached its 4 GiB cap as early as year 3. Fees start to weigh in the miner's income |
| **The long tail** | 14 to 91 years | The remaining 10% spreads out. The miner's income gradually shifts toward fees |
| **The tail at the floor** | 42 to 100 years | The decay has fallen below 0.01 Q21: the floor pays, constant, up to the cap |
| **After the subsidy** | Beyond 99.91 years | Not a single new Q21 created. 21,000,001 in circulation, exactly. Security rests entirely on fees — an open question, here as elsewhere |

---

## 5 · What this projection does not say

- **The price.** There is none, there will be none on this test network, and
  nothing here predicts anything about it.
- **The actual number of miners.** All of section 2 depends on a figure that
  is chosen; it shows orders of magnitude, not a future.
- **How the proof of work holds up under attack.** It has received no
  external cryptanalysis. If it fell, all of section 2 would fall with it.
- **Fees.** No fee market has been observed, and how fees evolve decides
  everything after the century of emission.

---

*Recompute these figures: `cargo run --release --example projection`.
Measure the real size of a transaction:
`cargo run --release --features mldsa --example bench_sig`.
Measure the mining rate: `cargo run --release --example mining_bench`.*
