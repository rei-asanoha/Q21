# Phase 6 — the measurement, and what it destroyed

## What this phase was meant to establish

Q21 rests on a promise: **to be mined by people, not by foundries.**
Everything else — the cap, the post-quantum signatures, the defense against
the majority attacker — assumes that mining power stays distributed.

This promise had never been measured on the real table size. Phase 6 had a
single mandate: measure it, and tell the truth about the result.

## Method

Three things were built before measuring anything.

**The real table.** 2^26 elements, 2 GiB, the mainnet one — not the 32 MiB of
the testnet, which fits in a processor's cache and gives flattering figures.

**A measurement with a constant time budget.** Between the fastest and the
slowest strategy there are two orders of magnitude; a fixed number of
attempts ends either in microseconds or in hours.

**A configurable attacker.** `PartialTable` models a miner holding only a
fraction *f* of the table and recomputing the rest. This is the essential
point: comparing "full table" with "no table" says almost nothing, since no
circuit designer chooses either of those two extremes. They choose the amount
of memory that maximizes their throughput per dollar spent. The relevant
question is the **curve**.

Since the access indices are uniform, keeping the first *f·N* elements gives
a hit rate of *f*: no element is more useful than another.

## Verdict on the original design

```
fraction    memory         attempts/s     relative cost
  1/1          2048 MiB         66805         1.00 x
  1/2          1024 MiB         33804         1.98 x
  1/4           512 MiB         27596         2.42 x
  1/8           256 MiB         23404         2.85 x
  1/16          128 MiB         23974         2.79 x
  1/64           32 MiB         23441         2.85 x
  0/1             0 MiB         23372         2.86 x
```

Two readings, both bad.

**Doing entirely without memory cost only 2.86×.** A dedicated circuit whose
hash is three times faster than a processor therefore had an incentive to
carry no DRAM at all. Yet a SHA-256 circuit beats a processor by a factor on
the order of 10⁸. The margin was three. The anti-ASIC property did not exist.

**The curve flattened from 256 MiB.** Beyond that, buying memory bought
nothing more. The 2 GiB threshold was decorative.

The cause comes down to one line of the old design:

```rust
element(i) = H(seed, i)
```

Each element could be recomputed with a single hash, in O(1), without memory.
That was exactly what made verification light — and exactly what made the
proof of work avoidable. The same property served both sides, and served the
attacker better.

The 6.46× announced until then had been measured on 32 MiB. Everything fit in
the processor cache. The figure was true and measured nothing.

## The fix

A two-level structure, the one of Ethash.

**Level 1 — the cache.** `N / 32` elements, that is 64 MiB on mainnet.
Generated **as a chain**: element *i* derives from *i-1*, then three mixing
passes link each element to another one designated by its own content
(RandMemoHash, Lerner 2014). A fragment of it cannot be rebuilt without
rebuilding everything that precedes it.

**Level 2 — the table.** `N` elements, 2 GiB. Each element is computed with
**256 dependent random accesses** to the cache.

Refusing the table therefore no longer saves memory. It multiplies the
number of accesses by 256 — hence the memory bandwidth, the only resource a
circuit cannot manufacture with silicon.

| | with table | without table |
|---|---:|---:|
| memory accesses per attempt | 32 | 8,192 |
| memory traffic per attempt | 1 KiB | 256 KiB |

## Measurement after the fix

Same machine, same 2 GiB table.

```
fraction    memory         attempts/s     relative cost
  1/1          2048 MiB         73390          1.0 x
  1/2          1024 MiB          3265         22.5 x
  1/4           512 MiB          2165         33.9 x
  1/8           256 MiB          1847         39.7 x
  1/16          128 MiB          1738         42.2 x
  1/64           32 MiB          1663         44.1 x
  0/1             0 MiB          1534         47.8 x
```

**2.86× → 47.8×**, a factor of 16.7 on the property that justifies the whole
module. And the curve no longer flattens prematurely: halving the memory
already costs 22.5×.

The residual plateau at the bottom of the table is not a weakness: below
64 MiB, the attacker would have to regenerate the cache themselves, which is
sequential and therefore out of all proportion. The real memory floor of the
protocol is 64 MiB, and that is intended.

## Calibrating POW_J

`POW_J` — the number of cache accesses per element — is the dial. Measured on
the real table:

| POW_J | penalty without table | verification / block | 10-year catch-up |
|---:|---:|---:|---:|
| 64 | 22.7× | 315 µs | 14 min |
| 128 | 29.8× | 413 µs | 18 min |
| 256 | **47.8×** | 658 µs | 29 min |

256 was chosen. It is also Ethash's value, which is not an argument but a
reassuring convergence. The cost of verification stays far below that of the
signatures: catching up on ten years of chain represents 29 minutes of proof
of work, whereas verifying the ML-DSA signatures of the same period takes
more.

## The price, stated plainly

What was lost must be written as clearly as what was gained.

| | before | after |
|---|---:|---:|
| memory of a node | **0** | 64 MiB |
| verification of a block | ~45 µs | ~660 µs |
| memory of a miner | 2 GiB | 2 GiB |
| building the table | 95 s | 1,436 s (2 cores) |

The README claimed: *"a full node never needs the 2 GiB"*. That was true, and
it was the problem. Free verification was the exact measure of the weakness
of the proof of work. You cannot have both.

Building the table is the miner's cost, once per epoch — about 71 days. It
parallelizes over all cores: 24 minutes on two cores, about five on eight.

A regression test now locks the property in:
`computing_element_costs_much_more_than_reading_it` fails if the derivation
becomes cheap again.

## What this measurement does not prove

It was made by the author of the function, on a single machine, against a
reference implementation — not against an implementation optimized by
someone whose job is to beat it.

What it establishes: the previous design was refuted, and this one is not
refuted by the same attack. What it does not establish: that no other attack
exists. Twice in a row a measurement has destroyed a design of this module;
it would be naive to assume a third time will not come.

The two reviews that would be worth more than any additional code:

1. **A cryptanalyst** on the mixing function and the cache generation.
2. **A circuit designer** on the bandwidth / silicon ratio, which is the real
   ground of the anti-ASIC property.

## Reproducing

```bash
cargo build --release
q21 pow mainnet                 # the whole curve (allow ~30 min)
q21 pow mainnet --no-table      # node-side cost only (~15 s)
q21 pow testnet                 # quick version, figures not representative
```

## Parameters frozen by this phase

```
POW_K              32      table accesses per attempt
POW_J             256      cache accesses per table element
POW_CACHE_RATIO    32      table / cache  →  2 GiB / 64 MiB
POW_CACHE_ROUNDS    3      mixing passes when generating the cache
```

These four values are consensus values. Changing them after genesis requires
a chain split.
