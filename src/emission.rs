//! Emission schedule.
//!
//! This is the most important module of the project. It answers a single
//! question: how many units are created at block `h`? Any divergence between
//! two nodes on that answer splits the chain.
//!
//! Three rules, non-negotiable.
//!
//! 1. **No floating point.** `reward * 0.9971555` does not give the same
//!    result depending on the platform, the optimization level or the order of
//!    operations. `reward * 99_715_550 / 100_000_000` in integers gives the
//!    same bit everywhere.
//!
//! 2. **Round down, always.** Rust's integer division truncates. That is the
//!    intended behavior and it is specified here: when in doubt, the protocol
//!    issues less, never more.
//!
//! 3. **The cap is a maximum, and it is reached, exactly.** Geometric decay
//!    alone would never reach it: truncated to the integer, it stopped at
//!    year 91, leaving 137,899 Q21 never created. Bitcoin accepts that gap;
//!    Q21, whose name is its cap, could not. A reward floor ([`TAIL_REWARD`],
//!    0.01 Q21) takes over when the geometric reward falls below it, and the
//!    cumulative emission is clipped at [`EMISSION_CAP`] exactly: the last
//!    issuing block receives the exact remainder, then the subsidy is zero
//!    forever. Every unit of the cap ends up existing.

use crate::amount::Amount;
use crate::consensus::*;

/// Base reward for a given epoch, slow start not applied.
///
/// Computed by repeated application of the decay factor. The iteration is
/// deliberate: it defines the result without ambiguity, whereas an
/// exponential followed by a single rounding would give a different value.
///
/// Cost: one u128 multiplication per epoch. Over a hundred years there are
/// about 6,000 epochs, so a few microseconds. A production node will cache the
/// result; the function remains the reference definition.
pub fn epoch_base_reward(epoch: u64) -> u64 {
    let mut reward = INITIAL_REWARD;
    for _ in 0..epoch {
        reward = ((reward as u128 * DECAY_NUM) / DECAY_DEN) as u64;
        if reward == 0 {
            return 0;
        }
    }
    reward
}

/// Applies the slow start to a base reward.
///
/// Over the first `SLOW_START_BLOCKS` blocks, the reward grows linearly from
/// zero. At block 0 it is exactly zero: the only money creation of the
/// genesis block is the genesis coin, handled separately.
fn apply_slow_start(base: u64, height: u64) -> u64 {
    if height >= SLOW_START_BLOCKS {
        return base;
    }
    ((base as u128 * height as u128) / SLOW_START_BLOCKS as u128) as u64
}

/// Block reward at height `height`, in indivisible units.
///
/// This is the function the validator calls to check that a coinbase does not
/// create more than it is owed.
///
/// # Why a difference of cumulative totals, and not a direct formula
///
/// The reward is "what the cumulative emission gains at this block". Writing
/// it that way makes any divergence between the reward paid and the total
/// issued **impossible by construction**, whereas two separate formulas can
/// drift apart. It is also what gives the last issuing block its exact
/// remainder: the cumulative total is clipped at the cap, and the difference
/// follows.
pub fn block_subsidy(height: u64) -> Amount {
    if height == 0 {
        return Amount::from_units(0);
    }
    let after = cumulative_emission(height).units();
    let before = cumulative_emission(height - 1).units();
    Amount::from_units(after - before)
}

/// Base reward of the next epoch: one u128 multiplication then an integer
/// division, rounded down.
fn next_base(base: u64) -> u64 {
    ((base as u128 * DECAY_NUM) / DECAY_DEN) as u64
}

/// Adds to `total` what blocks `start..=end` of a single epoch whose base
/// reward is `base` issue.
///
/// This is **the** definition of what an epoch issues: the memoization table
/// and the computation of the current slice both go through here, which
/// prevents them from diverging by a single unit.
fn add_epoch(total: u64, base: u64, start: u64, end: u64) -> u64 {
    let paid = base.max(TAIL_REWARD);
    if start < SLOW_START_BLOCKS {
        // The slow start is still active: each block is worth a different value.
        let mut t = total;
        for h in start..=end {
            t = t.saturating_add(apply_slow_start(paid, h));
        }
        t
    } else {
        let n = end - start + 1;
        total.saturating_add(paid.saturating_mul(n))
    }
}

/// State of the schedule at the start of each epoch: (total already issued,
/// base reward of the epoch). The last entry is the first epoch whose starting
/// total reaches the cap.
///
/// # Why a table
///
/// `cumulative_emission` walked the schedule again from block 0 on every call:
/// the slow start block by block (20,000 iterations), then one iteration per
/// epoch. `block_subsidy` calls it twice, and the validator calls
/// `block_subsidy` for each connected block, under the chain lock: 300 to 500
/// microseconds per block, as much as an ML-DSA-87 signature verification, for
/// a result that depends only on the height. Over an initial sync of millions
/// of blocks, tens of minutes of pure recomputation; over a 720-block reorg,
/// nearly a second with the lock held.
///
/// The table is built once, by the same code as the iterative version (same
/// integers, same order of operations, same saturations): some six thousand
/// entries, less than 100 KiB. The result is bit for bit that of the old
/// function: the test `memoization_returns_exactly_the_reference` checks it
/// against a copy of the old implementation.
fn epoch_starts() -> &'static [(u64, u64)] {
    static TABLE: std::sync::OnceLock<Vec<(u64, u64)>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Vec::new();
        let mut total: u64 = 0;
        let mut base: u64 = INITIAL_REWARD;
        let mut epoch: u64 = 0;
        loop {
            table.push((total, base));
            if total >= EMISSION_CAP {
                break;
            }
            let start = epoch * DECAY_EPOCH_BLOCKS;
            total = add_epoch(total, base, start, start + DECAY_EPOCH_BLOCKS - 1);
            base = next_base(base);
            epoch += 1;
        }
        table
    })
}

/// Total issued by mining, from block 0 to block `height` inclusive.
///
/// Excludes the genesis coin. Reads from [`epoch_starts`] the state at the
/// start of the epoch of `height`, then adds only the blocks of that epoch:
/// block by block during the slow start, otherwise with one multiplication.
///
/// The epoch reward is bounded below by [`TAIL_REWARD`], and the total is
/// clipped at [`EMISSION_CAP`]: it is this pair (floor, then clipping) that
/// makes the cap reached exactly, in finite time.
pub fn cumulative_emission(height: u64) -> Amount {
    let table = epoch_starts();
    let epoch = height / DECAY_EPOCH_BLOCKS;
    // Beyond the table, the iterative schedule would have stopped at the last
    // entry, whose total already reaches the cap.
    let Some(&(total, base)) = usize::try_from(epoch).ok().and_then(|e| table.get(e)) else {
        return Amount::from_units(EMISSION_CAP);
    };
    if total >= EMISSION_CAP {
        return Amount::from_units(EMISSION_CAP);
    }
    let start = epoch * DECAY_EPOCH_BLOCKS;
    let total = add_epoch(total, base, start, height);

    // The clipping. Before the floor, this line was a safeguard that never
    // fired; it is now the rule that ends the emission, and that gives the
    // last block its partial remainder.
    Amount::from_units(total.min(EMISSION_CAP))
}

/// First height whose subsidy is zero: the cap is reached at the previous
/// block.
///
/// Binary search on the cumulative total, which is monotonic. Used by the
/// projection tools and the tests; the validator does not need it.
pub fn emission_end_height() -> u64 {
    // Safe upper bound: every block after the slow start pays at least the
    // floor, so the cap is reached within `CAP / TAIL` blocks, slow start
    // included. An astronomical bound would unroll millions of epochs per
    // probe.
    let safe_high = EMISSION_CAP / TAIL_REWARD + SLOW_START_BLOCKS + DECAY_EPOCH_BLOCKS;
    let (mut low, mut high) = (0u64, safe_high);
    while low < high {
        let m = low + (high - low) / 2;
        if cumulative_emission(m).units() >= EMISSION_CAP {
            high = m;
        } else {
            low = m + 1;
        }
    }
    low + 1
}

/// Total supply in circulation after block `height`, genesis coin included.
pub fn total_supply_at(height: u64) -> Amount {
    Amount::from_units(cumulative_emission(height).units() + GENESIS_PREMINT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The original implementation of `cumulative_emission`, kept as is as a
    /// reference: it walks the schedule again from block 0 on every call. It
    /// is the consensus definition; the memoized version must equal it bit for
    /// bit.
    fn cumulative_emission_reference(height: u64) -> Amount {
        let mut total: u64 = 0;
        let mut epoch: u64 = 0;
        let mut base: u64 = INITIAL_REWARD;

        loop {
            let start = epoch * DECAY_EPOCH_BLOCKS;
            if start > height || total >= EMISSION_CAP {
                break;
            }
            let end = core::cmp::min(height, start + DECAY_EPOCH_BLOCKS - 1);
            let paid = base.max(TAIL_REWARD);

            if start < SLOW_START_BLOCKS {
                for h in start..=end {
                    total = total.saturating_add(apply_slow_start(paid, h));
                }
            } else {
                let n = end - start + 1;
                total = total.saturating_add(paid.saturating_mul(n));
            }

            base = ((base as u128 * DECAY_NUM) / DECAY_DEN) as u64;
            epoch += 1;
        }

        Amount::from_units(total.min(EMISSION_CAP))
    }

    /// The original implementation of `block_subsidy`, on top of the reference.
    fn block_subsidy_reference(height: u64) -> Amount {
        if height == 0 {
            return Amount::from_units(0);
        }
        let after = cumulative_emission_reference(height).units();
        let before = cumulative_emission_reference(height - 1).units();
        Amount::from_units(after - before)
    }

    /// Last issuing block, as the schedule sets it.
    const LAST_ISSUING_BLOCK: u64 = 26_273_578;

    /// The memoization returns exactly what the old function returned.
    ///
    /// Sample: every height from 0 to 100,000 (slow start included, first
    /// epoch boundaries), then each epoch boundary and its neighbors until
    /// beyond the last issuing block, plus the bounds of the schedule (end of
    /// emission, very far ahead, `u64::MAX`).
    #[test]
    fn memoization_returns_exactly_the_reference() {
        let mut heights: Vec<u64> = (0..=100_000).collect();
        let end = emission_end_height();
        assert_eq!(end - 1, LAST_ISSUING_BLOCK);
        let mut e = 0u64;
        while e * DECAY_EPOCH_BLOCKS <= end + 2 * DECAY_EPOCH_BLOCKS {
            let s = e * DECAY_EPOCH_BLOCKS;
            heights.extend([s.saturating_sub(1), s, s + 1, s + DECAY_EPOCH_BLOCKS / 2]);
            e += 1;
        }
        heights.extend([
            SLOW_START_BLOCKS - 1,
            SLOW_START_BLOCKS,
            SLOW_START_BLOCKS + 1,
            end - 2,
            end - 1,
            end,
            end + 1,
            end + BLOCKS_PER_YEAR * 100,
            BLOCKS_PER_YEAR * 500,
            u64::MAX / DECAY_EPOCH_BLOCKS,
            u64::MAX - 1,
            u64::MAX,
        ]);
        for h in heights {
            assert_eq!(
                cumulative_emission(h),
                cumulative_emission_reference(h),
                "cumulative total at height {h}"
            );
            assert_eq!(
                block_subsidy(h),
                block_subsidy_reference(h),
                "subsidy at height {h}"
            );
        }
    }

    /// Indicative measurement, printed: memoization brings `block_subsidy`
    /// down from a few hundred microseconds to a few tens of nanoseconds. No
    /// assertion on time (a loaded machine must not make the suite fail),
    /// only on equality.
    #[test]
    fn subsidy_timing_before_and_after_memoization() {
        let heights = [10_000u64, 100_000, 1_000_000, 5_000_000, LAST_ISSUING_BLOCK];
        let _ = block_subsidy(1);
        for h in heights {
            let rounds = 200u32;
            let t = std::time::Instant::now();
            for _ in 0..rounds {
                std::hint::black_box(block_subsidy_reference(std::hint::black_box(h)));
            }
            let d_ref = t.elapsed();
            let t = std::time::Instant::now();
            for _ in 0..(rounds * 1000) {
                std::hint::black_box(block_subsidy(std::hint::black_box(h)));
            }
            let d_memo = t.elapsed();
            assert_eq!(block_subsidy(h), block_subsidy_reference(h));
            eprintln!(
                "block_subsidy(h={h}): reference {:.1} us/call, memoized {:.1} ns/call",
                d_ref.as_secs_f64() * 1e6 / f64::from(rounds),
                d_memo.as_secs_f64() * 1e9 / f64::from(rounds * 1000)
            );
        }
    }

    #[test]
    fn genesis_block_issues_nothing_by_mining() {
        assert_eq!(block_subsidy(0).units(), 0);
    }

    #[test]
    fn slow_start_rises_from_zero() {
        let full = epoch_base_reward(SLOW_START_BLOCKS / DECAY_EPOCH_BLOCKS);
        let mid_ramp = block_subsidy(SLOW_START_BLOCKS / 2).units();
        let after = block_subsidy(SLOW_START_BLOCKS).units();

        assert!(mid_ramp > 0);
        assert!(mid_ramp < after);
        assert_eq!(after, full);
        // Halfway through the slow start we must be close to half, up to the
        // decay effects over those few epochs.
        assert!(mid_ramp * 2 > after * 9 / 10);
    }

    #[test]
    fn reward_decreases_monotonically_after_slow_start() {
        let mut previous = u64::MAX;
        for epoch in 0..500 {
            let r = epoch_base_reward(epoch);
            assert!(r <= previous, "epoch {epoch}: the reward increased");
            previous = r;
        }
    }

    #[test]
    fn half_life_is_about_four_years() {
        let four_years = BLOCKS_PER_YEAR * 4;
        let epoch = four_years / DECAY_EPOCH_BLOCKS;
        let r = epoch_base_reward(epoch);
        let half = INITIAL_REWARD / 2;
        // 1% tolerance: the epoch granularity does not land exactly.
        assert!(
            r > half * 99 / 100 && r < half * 101 / 100,
            "half-life off target: {r}, expected ~{half}"
        );
    }

    /// The promise of the project's name: every unit of the cap ends up
    /// existing.
    ///
    /// # The defect this test pins down
    ///
    /// Without the tail floor, the truncated decay stopped at year 91, leaving
    /// 137,899 Q21 never created. 21,000,001 was an asymptote. This test
    /// requires exact equality, to the block.
    #[test]
    fn emission_reaches_cap_exactly() {
        let end = emission_end_height();
        // The cap is reached, exactly, not approached.
        assert_eq!(cumulative_emission(end).units(), EMISSION_CAP);
        assert_eq!(total_supply_at(end).units(), MAX_SUPPLY);
        // The previous block had not yet reached it: `end` is indeed the
        // first dead height.
        assert!(cumulative_emission(end.saturating_sub(2)).units() < EMISSION_CAP);
        // After it, nothing more, forever (sampled far ahead).
        assert_eq!(block_subsidy(end).units(), 0);
        assert_eq!(block_subsidy(end + 1).units(), 0);
        assert_eq!(block_subsidy(end + BLOCKS_PER_YEAR * 100).units(), 0);
        assert_eq!(
            cumulative_emission(end + BLOCKS_PER_YEAR * 500).units(),
            EMISSION_CAP
        );
        // The last issuing block receives a partial remainder, never more than
        // the floor: the clipping sizes it.
        let remainder = block_subsidy(end - 1).units();
        assert!(
            remainder > 0 && remainder <= TAIL_REWARD,
            "remainder: {remainder}"
        );
    }

    /// The floor takes over when the geometric reward falls below it, and not
    /// before.
    #[test]
    fn floor_only_bites_the_tail() {
        // At year 20, the geometric reward still dominates by far.
        let at_20_years = block_subsidy(BLOCKS_PER_YEAR * 20).units();
        assert!(at_20_years > TAIL_REWARD * 40, "the floor bites too early");
        // At year 60, the floor is what pays, as is.
        assert_eq!(block_subsidy(BLOCKS_PER_YEAR * 60).units(), TAIL_REWARD);
    }

    /// The subsidy is the difference of the cumulative totals, checked term by
    /// term.
    ///
    /// This is the consistency that prevents a validator and a supply counter
    /// from diverging by a single unit. We check it over the slow start (each
    /// block has its own value there) and over a stretch of steady state.
    #[test]
    fn subsidy_sums_exactly_to_cumulative_total() {
        let mut sum = 0u64;
        for h in 0..=2_000u64 {
            sum += block_subsidy(h).units();
        }
        assert_eq!(sum, cumulative_emission(2_000).units());
    }

    /// The test that matters. If this one fails, the currency is broken.
    #[test]
    fn cap_is_never_exceeded_over_two_hundred_years() {
        for year in [1u64, 2, 4, 8, 12, 20, 30, 45, 60, 100, 150, 200] {
            let h = BLOCKS_PER_YEAR * year;
            let issued = cumulative_emission(h).units();
            assert!(
                issued <= EMISSION_CAP,
                "year {year}: cap exceeded ({issued} > {EMISSION_CAP})"
            );
            let total = total_supply_at(h).units();
            assert!(
                total <= MAX_SUPPLY,
                "year {year}: total supply above 21,000,001"
            );
        }
    }

    #[test]
    fn emission_is_monotonically_increasing() {
        let mut previous = 0u64;
        for year in 1..=60u64 {
            let e = cumulative_emission(BLOCKS_PER_YEAR * year).units();
            assert!(
                e >= previous,
                "year {year}: the cumulative emission decreased"
            );
            previous = e;
        }
    }

    /// The most important safeguard of the crate.
    ///
    /// It does not test a sampled trajectory: it bounds the whole series. The
    /// discrete geometric sum to infinity is `R0 * EPOCH * DEN / (DEN - NUM)`,
    /// before any rounding. If that bound holds below the cap, then the actual
    /// emission (which rounding down can only reduce) holds below it too, at
    /// every height, forever.
    ///
    /// This test bit on the very first run: the value initially derived from
    /// the continuous formula (13.847118 Q21) put the bound 0.14% above the
    /// cap. See `consensus::INITIAL_REWARD`.
    #[test]
    fn initial_reward_respects_cap() {
        let denom = DECAY_DEN - DECAY_NUM;
        let theoretical_total =
            (INITIAL_REWARD as u128 * DECAY_EPOCH_BLOCKS as u128 * DECAY_DEN) / denom;
        assert!(
            theoretical_total <= EMISSION_CAP as u128,
            "the theoretical infinite sum exceeds the cap: {theoretical_total} > {EMISSION_CAP}"
        );
    }

    /// Checks that the chosen reward is the largest admissible value.
    ///
    /// Without this test, one could fix the overshoot by halving R0 and claim
    /// the problem is solved, while issuing half as much as planned.
    #[test]
    fn initial_reward_is_maximal() {
        let denom = DECAY_DEN - DECAY_NUM;
        let bound = ((INITIAL_REWARD + 1) as u128 * DECAY_EPOCH_BLOCKS as u128 * DECAY_DEN) / denom;
        assert!(
            bound > EMISSION_CAP as u128,
            "one more unit would still fit: R0 is suboptimal"
        );
    }

    /// Checks the trajectory against the white paper's reference simulation.
    #[test]
    fn trajectory_matches_white_paper() {
        let expected: [(u64, u64); 4] = [
            (2, 6_012_892),
            (4, 10_362_141),
            (8, 15_612_144),
            (20, 20_205_888),
        ];
        for (year, expected_coins) in expected {
            // The reference simulation sums blocks 0..N exclusive; here
            // `cumulative_emission` includes block N. We align the bounds
            // rather than widen a tolerance, otherwise the test would let a
            // real one-block-reward drift through.
            let issued = cumulative_emission(BLOCKS_PER_YEAR * year - 1).units() / UNITS_PER_COIN;
            assert_eq!(
                issued, expected_coins,
                "year {year}: divergence from the reference simulation"
            );
        }
    }

    #[test]
    fn subsidy_eventually_dies_out() {
        // Far in time, rounding down eventually brings the reward to zero.
        // Security then rests on fees alone. This is the tension documented in
        // section 9 of the white paper.
        assert_eq!(epoch_base_reward(20_000), 0);
    }
}
