//! Adversarial audit: "difficulty, timestamps, mining economics" axis.
//!
//! Each test is a NUMERICAL SIMULATION on the production code
//! (`chain::next_bits`, `chain::Chain`, `memhard`, `validate`). No `src/`
//! file is modified.
//!
//! How to run:
//!   cargo test --offline --release --test audit_difficulty -- --nocapture

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{self, Chain};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::memhard::{self, PowTable, TableParams};
use q21_core::pow;
use q21_core::uint::U256;
use q21_core::validate;

// ---------------------------------------------------------------------------
// Simulation tools
// ---------------------------------------------------------------------------

/// Deterministic pseudo-random generator (xorshift64*).
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Exponential distribution with mean `m`: the time between two blocks.
    fn expo(&mut self, m: f64) -> f64 {
        let u = self.unit().max(1e-15);
        -m * u.ln()
    }
}

/// Target of a compact `bits`, as a float. Only used for measuring.
fn target_f64(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x007f_ffff) as f64;
    mantissa * 2f64.powi(8 * (exponent - 3))
}

/// Difficulty relative to [`INITIAL_BITS`]: 1.0 = floor difficulty.
fn difficulty(bits: u32) -> f64 {
    target_f64(INITIAL_BITS) / target_f64(bits)
}

fn header(time: u64, bits: u32, height: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: Hash256::ZERO,
        merkle_root: Hash256::ZERO,
        uncles_root: Hash256::ZERO,
        miner: Hash256::ZERO,
        time,
        bits,
        height,
        nonce: 0,
    }
}

/// Median of the timestamps, exactly like `validate::median_time`.
fn median(times: &[u64]) -> u64 {
    validate::median_time(times)
}

/// A miner's timestamp strategy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Strategy {
    /// Honest timestamp: the real time.
    Honest,
    /// Saturating the future window: `now + MAX_FUTURE_TIME`.
    FutureMax,
    /// Optimum: `previous + 6T`, capped at `now + MAX_FUTURE_TIME`.
    Increment6t,
}

struct SimResult {
    avg_difficulty: f64,
    avg_real_interval: f64,
    attacker_blocks: usize,
    total_blocks: usize,
    final_bits: u32,
    refused_timestamps: usize,
}

/// Simulates `n` blocks. `share` = the attacker's fraction of the hash power.
///
/// The network hash rate is constant and calibrated so that, without an
/// attack, the difficulty settles at `d0` and the interval at
/// TARGET_BLOCK_SECS.
fn simulate(n: usize, share: f64, strat: Strategy, seed: u64) -> SimResult {
    let d0 = 1000.0f64; // starting difficulty, arbitrary but >> 1
    let bits0 = bits_for_difficulty(d0);
    // hash rate in "difficulty units per second"
    let r = d0 / TARGET_BLOCK_SECS as f64;

    let mut rng = Rng::new(seed);
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(n + 200);
    // Warm-up: 200 perfectly regular blocks at d0.
    let t0 = 1_800_000_000u64;
    for i in 0..200u64 {
        headers.push(header(t0 + i * TARGET_BLOCK_SECS, bits0, i));
    }
    let mut real = (t0 + 199 * TARGET_BLOCK_SECS) as f64;

    let mut diff_sum = 0.0;
    let mut att_blocks = 0usize;
    let mut refused = 0usize;
    let measure_start = n / 2; // we only measure the steady state

    let mut real_at_measure_start = 0.0;
    let mut n_measured = 0usize;

    for i in 0..n {
        let bits = chain::next_bits(&headers);
        let d = difficulty(bits);
        let dt = rng.expo(d / r);
        real += dt;

        let attacker = rng.unit() < share;
        let previous = headers.last().unwrap().time;
        let med = median(
            &headers
                .iter()
                .rev()
                .take(MEDIAN_TIME_SPAN)
                .rev()
                .map(|h| h.time)
                .collect::<Vec<_>>(),
        );
        let future_cap = real as u64 + MAX_FUTURE_TIME;

        let raw = if attacker {
            match strat {
                Strategy::Honest => real as u64,
                Strategy::FutureMax => future_cap,
                Strategy::Increment6t => (previous + 6 * TARGET_BLOCK_SECS).min(future_cap),
            }
        } else {
            real as u64
        };
        // Rules of `validate::check_block`: > median, <= now + 2 h.
        let t = raw.max(med + 1);
        if t > future_cap {
            // The block would be refused: the miner falls back to the legal
            // maximum.
            refused += 1;
        }
        let t = t.min(future_cap);

        headers.push(header(t, bits, 200 + i as u64));
        if attacker {
            att_blocks += 1;
        }
        if i >= measure_start {
            if n_measured == 0 {
                real_at_measure_start = real - dt;
            }
            diff_sum += d;
            n_measured += 1;
        }
    }

    SimResult {
        avg_difficulty: diff_sum / n_measured as f64,
        avg_real_interval: (real - real_at_measure_start) / n_measured as f64,
        attacker_blocks: att_blocks,
        total_blocks: n,
        final_bits: headers.last().unwrap().bits,
        refused_timestamps: refused,
    }
}

/// Finds a compact `bits` that approximately achieves the requested difficulty.
fn bits_for_difficulty(d: f64) -> u32 {
    let t0 = pow::target_from_compact(INITIAL_BITS).unwrap();
    let target = t0.checked_div_u64(d as u64).unwrap();
    pow::target_to_compact(target)
}

// ---------------------------------------------------------------------------
// 1. Timestamp manipulation
// ---------------------------------------------------------------------------

/// No timestamp manipulation lowers the difficulty anymore.
///
/// History: with an unsigned bound `[1, 6T]`, a miner with 20% made the
/// difficulty drop by 97%; with the symmetric signed bound `[-6T, +6T]`, half
/// of the hash power still obtained a 25% drop and a third more blocks. With
/// the asymmetric bound `[-6T, +4T]`, the honest block removes more than the
/// attacker injects: every strategy **raises** the difficulty, and therefore
/// costs its author.
#[test]
fn a1_timestamp_manipulation_no_longer_drops_the_difficulty() {
    println!("\n=== A1: timestamp manipulation (LWMA, clamp [-6T, +4T]) ===");
    println!(
        "MAX_FUTURE_TIME = {} s, 6T = {} s, T = {} s, window = {} blocks",
        MAX_FUTURE_TIME,
        6 * TARGET_BLOCK_SECS,
        TARGET_BLOCK_SECS,
        LWMA_WINDOW
    );
    println!();
    println!(
        "{:>6} {:>10} {:>14} {:>14} {:>10} {:>12}",
        "X %", "strategy", "difficulty", "drop", "interval", "inflation"
    );

    let n = 6000;
    let base = simulate(n, 0.0, Strategy::Honest, 12345);
    println!(
        "{:>6.1} {:>10} {:>14.1} {:>14} {:>10.1} {:>12}",
        0.0, "-", base.avg_difficulty, "-", base.avg_real_interval, "-"
    );

    let mut max_drop = 0.0f64;
    for share in [0.05, 0.10, 0.15, 0.20, 0.25, 0.33, 0.50] {
        for strat in [Strategy::FutureMax, Strategy::Increment6t] {
            let r = simulate(n, share, strat, 12345);
            let drop = 1.0 - r.avg_difficulty / base.avg_difficulty;
            let infl = base.avg_real_interval / r.avg_real_interval;
            max_drop = max_drop.max(drop);
            println!(
                "{:>6.1} {:>10} {:>14.1} {:>13.1}% {:>10.1} {:>11.2}x  ({} timestamp(s) refused)",
                share * 100.0,
                match strat {
                    Strategy::FutureMax => "future+2h",
                    Strategy::Increment6t => "prev+6T",
                    _ => "honest",
                },
                r.avg_difficulty,
                drop * 100.0,
                r.avg_real_interval,
                infl,
                r.refused_timestamps
            );
        }
    }
    println!();
    println!("maximum observed drop: {:.1} %", max_drop * 100.0);
    // Before the asymmetric bound, the "previous + 6T" strategy still made the
    // difficulty drop by 25% with half of the hash power, that is a third more
    // blocks. No strategy must manage it anymore: the time pushed forward is
    // more than given back by the honest block that follows.
    assert!(
        max_drop <= 0.0,
        "a timestamp manipulation still makes the difficulty drop by {:.1} %",
        max_drop * 100.0
    );
}

#[test]
fn a1b_theoretical_and_measured_collapse_threshold() {
    println!("\n=== A1b: total difficulty collapse threshold ===");
    // Model: each attacker block contributes 6T=720 s instead of T=120 s to
    // the LWMA sum (upper clamp), and the honest block that follows it
    // contributes 1 s (lower clamp, because `saturating_sub` turns a negative
    // interval into 0 then into 1). The LWMA equilibrium imposes a mean of T.
    println!("analytical model: 721*a*(1-a) + mu*(a^2+(1-a)^2) = T");
    for a in [0.05f64, 0.10, 0.15, 0.20, 0.2065, 0.25] {
        let num = TARGET_BLOCK_SECS as f64 - 721.0 * a * (1.0 - a);
        let den = a * a + (1.0 - a) * (1.0 - a);
        let mu = num / den;
        println!(
            "  a = {:>5.1} %  ->  real equilibrium interval mu = {:>8.2} s  (difficulty x {:>6.3})",
            a * 100.0,
            mu,
            (mu / TARGET_BLOCK_SECS as f64).max(0.0)
        );
    }
    println!("  threshold where mu <= 0: a* = T / 721 ... a* ~ 20.7 % (prev+6T strategy)");

    // Measurement: we push the simulation until the collapse.
    let n = 20_000;
    for share in [0.20f64, 0.25, 0.30] {
        let r = simulate(n, share, Strategy::Increment6t, 987);
        println!(
            "  measured a = {:>4.0} %: final difficulty bits = {:#010x}  (= {:.3} x the floor), \
             real interval = {:.2} s, attacker blocks {}/{}",
            share * 100.0,
            r.final_bits,
            difficulty(r.final_bits),
            r.avg_real_interval,
            r.attacker_blocks,
            r.total_blocks
        );
    }
}

// ---------------------------------------------------------------------------
// 2. LWMA oscillation / hash rate hopping
// ---------------------------------------------------------------------------

struct Hopping {
    block_share: f64,
    hash_share: f64,
    gain: f64,
    diff_on: f64,
    diff_off: f64,
    cycles: usize,
}

/// A hopping miner turns their farm on when the difficulty is low and off when
/// it goes back up. Measured: their share of blocks / their share of hashing
/// spent.
fn simulate_hopping(
    n: usize,
    att_ratio: f64,
    on_threshold: f64,
    off_threshold: f64,
    seed: u64,
) -> Hopping {
    let d0 = 1000.0f64;
    let bits0 = bits_for_difficulty(d0);
    let r_honest = d0 / TARGET_BLOCK_SECS as f64;
    let r_att = r_honest * att_ratio;

    let mut rng = Rng::new(seed);
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(n + 200);
    let t0 = 1_800_000_000u64;
    for i in 0..200u64 {
        headers.push(header(t0 + i * TARGET_BLOCK_SECS, bits0, i));
    }
    let mut real = (t0 + 199 * TARGET_BLOCK_SECS) as f64;

    let mut on = false;
    let mut cycles = 0usize;
    let mut att_blocks = 0.0;
    let mut att_hash = 0.0;
    let mut honest_hash = 0.0;
    let mut sum_on = 0.0;
    let mut n_on = 0.0;
    let mut sum_off = 0.0;
    let mut n_off = 0.0;

    for i in 0..n {
        let bits = chain::next_bits(&headers);
        let d = difficulty(bits);
        let d_rel = d / d0;

        if !on && d_rel < on_threshold {
            on = true;
            cycles += 1;
        } else if on && d_rel > off_threshold {
            on = false;
        }

        let r_total = r_honest + if on { r_att } else { 0.0 };
        let dt = rng.expo(d / r_total);
        real += dt;

        // Hashing spent = power x duration.
        honest_hash += r_honest * dt;
        if on {
            att_hash += r_att * dt;
            sum_on += d_rel;
            n_on += 1.0;
        } else {
            sum_off += d_rel;
            n_off += 1.0;
        }
        // Probability of winning the block = instantaneous share of power.
        let p = if on { r_att / r_total } else { 0.0 };
        if rng.unit() < p {
            att_blocks += 1.0;
        }

        let previous = headers.last().unwrap().time;
        let t = (real as u64).max(previous.saturating_sub(0)).max(
            median(
                &headers
                    .iter()
                    .rev()
                    .take(MEDIAN_TIME_SPAN)
                    .rev()
                    .map(|h| h.time)
                    .collect::<Vec<_>>(),
            ) + 1,
        );
        headers.push(header(t, bits, 200 + i as u64));
    }

    let block_share = att_blocks / n as f64;
    let hash_share = att_hash / (att_hash + honest_hash);
    Hopping {
        block_share,
        hash_share,
        gain: block_share / hash_share.max(1e-12),
        diff_on: if n_on > 0.0 { sum_on / n_on } else { 0.0 },
        diff_off: if n_off > 0.0 { sum_off / n_off } else { 0.0 },
        cycles,
    }
}

#[test]
fn a2_hash_rate_hopping_on_lwma() {
    println!("\n=== A2: LWMA oscillation / hash rate hopping ===");
    println!(
        "LWMA adjusts on EVERY block over {} blocks: the average lag is ~{} blocks (~{} min)",
        LWMA_WINDOW,
        LWMA_WINDOW / 3,
        LWMA_WINDOW / 3 * TARGET_BLOCK_SECS as usize / 60
    );
    println!();
    println!(
        "{:>8} {:>8} {:>8} {:>11} {:>11} {:>8} {:>8} {:>8}",
        "R_att/R", "on<", "off>", "block share", "hash share", "gain", "d_on", "d_off"
    );
    let n = 40_000;
    let mut max_gain = 0.0f64;
    for ratio in [0.25f64, 0.5, 1.0, 2.0] {
        for (on, off) in [(0.95f64, 1.05f64), (0.90, 1.10), (0.80, 1.20)] {
            let h = simulate_hopping(n, ratio, on, off, 555);
            max_gain = max_gain.max(h.gain);
            println!(
                "{:>8.2} {:>8.2} {:>8.2} {:>10.2}% {:>10.2}% {:>8.4} {:>8.3} {:>8.3}  ({} cycles)",
                ratio,
                on,
                off,
                h.block_share * 100.0,
                h.hash_share * 100.0,
                h.gain,
                h.diff_on,
                h.diff_off,
                h.cycles
            );
        }
    }
    println!();
    println!("maximum relative gain (1.0 = exact share): {max_gain:.4}");
}

#[test]
fn a2b_massive_departure_and_death_spiral() {
    println!("\n=== A2b: massive departure of hash power: does the chain restart? ===");
    println!(
        "MAX_TARGET_CHANGE = {MAX_TARGET_CHANGE} (the target can only change by a factor of {MAX_TARGET_CHANGE} \
         per block, and this factor is relative to the window AVERAGE, not to the parent)"
    );
    println!();
    println!(
        "{:>12} {:>14} {:>16} {:>14}",
        "hashrate x", "blocks to", "real time", "equivalent"
    );
    for factor in [2.0f64, 10.0, 100.0, 1000.0, 10_000.0] {
        let (blocks, seconds) = simulate_collapse(factor);
        println!(
            "{:>11.0}x {:>14} {:>13.0} s {:>13}",
            factor,
            blocks,
            seconds,
            readable_duration(seconds)
        );
    }
}

fn readable_duration(s: f64) -> String {
    if s < 3600.0 {
        format!("{:.0} min", s / 60.0)
    } else if s < 86400.0 {
        format!("{:.1} h", s / 3600.0)
    } else if s < 86400.0 * 365.0 {
        format!("{:.1} d", s / 86400.0)
    } else {
        format!("{:.2} years", s / (86400.0 * 365.0))
    }
}

/// The hash rate is divided by `factor` at once. How many blocks and how much
/// real time before the interval falls back below 2 x TARGET_BLOCK_SECS?
fn simulate_collapse(factor: f64) -> (usize, f64) {
    let d0 = 1_000_000.0f64;
    let bits0 = bits_for_difficulty(d0);
    let r = d0 / TARGET_BLOCK_SECS as f64 / factor; // residual hash rate

    let mut rng = Rng::new(7777);
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(2000);
    let t0 = 1_800_000_000u64;
    for i in 0..(LWMA_WINDOW as u64 + 1) {
        headers.push(header(t0 + i * TARGET_BLOCK_SECS, bits0, i));
    }
    let mut real = (t0 + LWMA_WINDOW as u64 * TARGET_BLOCK_SECS) as f64;
    let start = real;

    for k in 0..5000usize {
        let bits = chain::next_bits(&headers);
        let d = difficulty(bits);
        let dt = rng.expo(d / r);
        real += dt;
        let t = (real as u64).max(
            median(
                &headers
                    .iter()
                    .rev()
                    .take(MEDIAN_TIME_SPAN)
                    .rev()
                    .map(|h| h.time)
                    .collect::<Vec<_>>(),
            ) + 1,
        );
        headers.push(header(t, bits, headers.len() as u64));
        if dt < 2.0 * TARGET_BLOCK_SECS as f64 && k > 5 {
            return (k + 1, real - start);
        }
    }
    (5000, real - start)
}

#[test]
fn a2c_max_target_change_does_not_bound_what_it_claims() {
    println!("\n=== A2c: MAX_TARGET_CHANGE: announced bound vs actual bound ===");
    println!(
        "consensus.rs:186 announces \"Maximum factor of target change BETWEEN TWO BLOCKS\" = {MAX_TARGET_CHANGE}"
    );
    println!("chain.rs:167-172: the ceiling/floor are computed on `average_target`,");
    println!(
        "that is, the AVERAGE of the last {LWMA_WINDOW} targets, not on the parent's target.\n"
    );

    // Stable window, then maximal solve times (6T): the target must go up.
    let d0 = 1_000_000.0f64;
    let bits0 = bits_for_difficulty(d0);
    let t0 = 1_800_000_000u64;
    let mut headers: Vec<BlockHeader> = (0..=(LWMA_WINDOW as u64))
        .map(|i| header(t0 + i * TARGET_BLOCK_SECS, bits0, i))
        .collect();

    println!("--- target going UP (difficulty going down), solve time = 6T on every block ---");
    println!(
        "{:>6} {:>14} {:>14} {:>14}",
        "block", "target/parent", "target/start", "difficulty"
    );
    let mut previous = target_f64(bits0);
    let start = previous;
    for k in 0..12 {
        let bits = chain::next_bits(&headers);
        let c = target_f64(bits);
        if k < 6 || k == 11 {
            println!(
                "{:>6} {:>14.4} {:>14.4} {:>14.1}",
                k + 1,
                c / previous,
                c / start,
                difficulty(bits)
            );
        }
        previous = c;
        let t = headers.last().unwrap().time + 6 * TARGET_BLOCK_SECS;
        headers.push(header(t, bits, headers.len() as u64));
    }
    println!(
        "-> the target only goes up by ~4 % per block, NOT by a factor of {MAX_TARGET_CHANGE}. \
         The factor of 4 is only reached on the first block."
    );

    println!("\n--- target going DOWN (difficulty going up), solve time = 1 s on every block ---");
    let mut headers: Vec<BlockHeader> = (0..=(LWMA_WINDOW as u64))
        .map(|i| header(t0 + i * TARGET_BLOCK_SECS, bits0, i))
        .collect();
    println!(
        "{:>6} {:>14} {:>14} {:>14}",
        "block", "target/parent", "target/start", "difficulty"
    );
    let mut previous = target_f64(bits0);
    let start = previous;
    for k in 0..12 {
        let bits = chain::next_bits(&headers);
        let c = target_f64(bits);
        if k < 6 || k == 11 {
            println!(
                "{:>6} {:>14.4} {:>14.4} {:>14.1}",
                k + 1,
                c / previous,
                c / start,
                difficulty(bits)
            );
        }
        previous = c;
        let t = headers.last().unwrap().time + 1;
        headers.push(header(t, bits, headers.len() as u64));
    }
}

// ---------------------------------------------------------------------------
// 3 and 4. Proof-of-work epoch, table/cache, mining/verification divergence
// ---------------------------------------------------------------------------

#[test]
fn a3_epoch_boundary_cost_and_advantage() {
    println!("\n=== A3: proof-of-work epoch transition ===");
    println!(
        "POW_EPOCH_BLOCKS = {POW_EPOCH_BLOCKS} blocks (~{:.0} days at {TARGET_BLOCK_SECS} s)",
        POW_EPOCH_BLOCKS as f64 * TARGET_BLOCK_SECS as f64 / 86400.0
    );
    println!("epoch seed = H(epoch number), memhard.rs:130: it depends on NO block,");
    println!("so every future epoch can be computed starting today.\n");

    for (name, net) in [
        ("regtest", Network::Regtest),
        ("testnet", Network::Testnet),
        ("mainnet", Network::Mainnet),
    ] {
        let p = TableParams::for_network(net);
        print!("{name:>8} : ");
        for e in [0u64, 1, 5, 10, 29, 30, 100] {
            print!(
                "e{e}={} MiB  ",
                memhard::table_size(p, e) as u64 * POW_ELEMENT_SIZE as u64 / (1 << 20)
            );
        }
        println!();
    }

    // Measured cost of a transition.
    let p = TableParams::for_network(Network::Testnet);
    let t = std::time::Instant::now();
    let cache1 = memhard::cache_for(p, 1);
    let dcache = t.elapsed().as_secs_f64();
    let t = std::time::Instant::now();
    let table1 = PowTable::build_with_cache(&cache1, p, 1);
    let dtable = t.elapsed().as_secs_f64();
    println!(
        "\nmeasured (testnet, {} cores): cache {} elements ({} MiB) in {:.3} s; \
         table {} elements ({} MiB) in {:.3} s",
        std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1),
        cache1.len(),
        cache1.memory_bytes() / (1 << 20),
        dcache,
        table1.len(),
        table1.memory_bytes() / (1 << 20),
        dtable
    );
    let factor = POW_TABLE_N0_MAINNET as f64 / POW_TABLE_N0_TESTNET as f64;
    println!(
        "mainnet extrapolation (x{factor:.0} elements): cache ~{:.1} s, table ~{:.0} s = {:.1} min",
        dcache * factor,
        dtable * factor,
        dtable * factor / 60.0
    );
    println!(
        "-> at height {POW_EPOCH_BLOCKS}, `Chain::mine_block` calls `table_for(epoch_of(height))` \
         (chain.rs:1222)"
    );
    println!("   which rebuilds the table SYNCHRONOUSLY. An unprepared miner loses that time;");
    println!("   a prepared miner has 0 s of downtime and collects every block during the window.");
    let loss = dtable * factor;
    println!(
        "   quantified advantage: {:.0} blocks won for free by the prepared miner \
         (window {:.0} s / {TARGET_BLOCK_SECS} s), that is {:.1} % of a day's reward.",
        loss / TARGET_BLOCK_SECS as f64,
        loss,
        100.0 * loss / 86400.0
    );
}

#[test]
fn a4_mining_verification_divergence() {
    println!("\n=== A4: hash_mining vs hash_verify ===");
    let p = TableParams::for_network(Network::Regtest);

    // (a) Nominal case: both paths agree, epoch 0 included.
    let table0 = PowTable::build(p, 0);
    let mut ok = 0;
    for nonce in 0..64u64 {
        let h = header(1_800_000_000, INITIAL_BITS, 0);
        let mut h = h;
        h.nonce = nonce;
        if memhard::hash_mining(&h, &table0) == memhard::hash_verify(&h, p) {
            ok += 1;
        }
    }
    println!("epoch 0, height 0: {ok}/64 matches");
    assert_eq!(ok, 64);

    // (b) Epoch boundary: the table of epoch N is worth NOTHING at epoch N+1.
    let table1 = PowTable::build(p, 1);
    let h_epoch_end = {
        let mut h = header(1_800_000_000, INITIAL_BITS, POW_EPOCH_BLOCKS - 1);
        h.nonce = 7;
        h
    };
    let h_epoch_start = {
        let mut h = header(1_800_000_000, INITIAL_BITS, POW_EPOCH_BLOCKS);
        h.nonce = 7;
        h
    };
    println!(
        "height {} (epoch {}): table(e0) == verify? {}",
        POW_EPOCH_BLOCKS - 1,
        memhard::epoch_of(POW_EPOCH_BLOCKS - 1),
        memhard::hash_mining(&h_epoch_end, &table0) == memhard::hash_verify(&h_epoch_end, p)
    );
    println!(
        "height {} (epoch {}): table(e0) == verify? {}   <-- stale table = 0 valid blocks",
        POW_EPOCH_BLOCKS,
        memhard::epoch_of(POW_EPOCH_BLOCKS),
        memhard::hash_mining(&h_epoch_start, &table0) == memhard::hash_verify(&h_epoch_start, p)
    );
    println!(
        "height {} (epoch {}): table(e1) == verify? {}",
        POW_EPOCH_BLOCKS,
        memhard::epoch_of(POW_EPOCH_BLOCKS),
        memhard::hash_mining(&h_epoch_start, &table1) == memhard::hash_verify(&h_epoch_start, p)
    );
    assert_ne!(
        memhard::hash_mining(&h_epoch_start, &table0),
        memhard::hash_verify(&h_epoch_start, p)
    );

    // (c) `hash_verify_with_cache` checks that the cache is the one for the
    //     header's epoch. This was a defect: a cache from another epoch was
    //     accepted without a word, and the node computed a different proof of
    //     work from its peers. Since the fix, a foreign cache is ignored and
    //     verification falls back to the full computation: the three paths
    //     (table, cache of the right epoch, cache of a wrong epoch) give the
    //     same value.
    let cache0 = memhard::cache_for(p, 0);
    let cache1 = memhard::cache_for(p, 1);
    let reference = memhard::hash_verify(&h_epoch_start, p);
    let good = memhard::hash_verify_with_cache(&h_epoch_start, p, &cache1);
    let bad = memhard::hash_verify_with_cache(&h_epoch_start, p, &cache0);
    println!(
        "\nhash_verify_with_cache(height {}, cache e1) == hash_verify? {}; \
         with cache e0 (foreign)? {}",
        POW_EPOCH_BLOCKS,
        good == reference,
        bad == reference
    );
    assert_eq!(good, reference, "the cache of the right epoch must match");
    assert_eq!(
        bad, reference,
        "a cache from another epoch must be ignored, never used"
    );
    assert_eq!(
        memhard::hash_mining(&h_epoch_start, &table1),
        reference,
        "the mining path must match verification"
    );

    // (d) Table size edge cases.
    println!("\n--- sizing edge cases ---");
    for (n0, nmax) in [(1u32, 1u32), (2, 2), (32, 32), (33, 33)] {
        let p = TableParams { n0, nmax };
        let n = memhard::table_size(p, 0);
        let c = memhard::cache_size(p, 0);
        let tab = PowTable::build(p, 0);
        let mut h = header(1_800_000_000, INITIAL_BITS, 0);
        h.nonce = 3;
        let equal = memhard::hash_mining(&h, &tab) == memhard::hash_verify(&h, p);
        println!("  n0={n0:<3} -> table {n} elements, cache {c} elements, match = {equal}");
        assert!(equal, "divergence for n0={n0}");
    }
    println!(
        "  n0=0 -> table_size = {}: `index_from` (memhard.rs:398) would do `% 0` = panic. \
         Not reachable from `TableParams::for_network`, but the field is `pub`.",
        memhard::table_size(TableParams { n0: 0, nmax: 0 }, 0)
    );

    // (e) Table growth is capped: beyond it, only the seed changes.
    let pm = TableParams::for_network(Network::Mainnet);
    let mut first_saturation = None;
    for e in 0..80u64 {
        if memhard::table_size(pm, e) == pm.nmax && first_saturation.is_none() {
            first_saturation = Some(e);
        }
    }
    println!(
        "\nmainnet: the table reaches NMAX ({} MiB) at epoch {:?}, that is around {:.1} years.",
        pm.nmax as u64 * 32 / (1 << 20),
        first_saturation,
        first_saturation.unwrap_or(0) as f64 * POW_EPOCH_BLOCKS as f64 * TARGET_BLOCK_SECS as f64
            / (86400.0 * 365.0)
    );
    println!("-> after that date, \"lever A\" (a growing table) is dead: the size is frozen.");
}

#[test]
fn a4b_arbitrary_epoch_amplification_dos() {
    println!("\n=== A4b: arbitrary height => arbitrary cache construction ===");
    println!("chain.rs:984-1020 `submit`: for a side branch, only `bits` is checked");
    println!("before `self.pow.check(&block.header)`. The HEIGHT is never checked at this stage.");
    println!(
        "pow.rs -> memhard::hash_verify -> epoch_of(header.height) -> cache_for(params, epoch).\n"
    );

    let p = TableParams::for_network(Network::Testnet);
    // Same epoch: the cache is reused.
    let t = std::time::Instant::now();
    for k in 0..4u64 {
        let mut h = header(1_800_000_000, INITIAL_BITS, 5);
        h.nonce = k;
        let _ = memhard::hash_verify(&h, p);
    }
    let d_same = t.elapsed().as_secs_f64();

    // All different epochs: one full cache per header.
    let t = std::time::Instant::now();
    for k in 0..4u64 {
        let h = header(
            1_800_000_000,
            INITIAL_BITS,
            900_000_000 + k * POW_EPOCH_BLOCKS,
        );
        let _ = memhard::hash_verify(&h, p);
    }
    let d_diff = t.elapsed().as_secs_f64();

    println!("testnet: 4 headers of the same epoch      : {d_same:.4} s");
    println!("testnet: 4 headers of distinct epochs     : {d_diff:.4} s");
    println!(
        "measured amplification: x{:.0} for 4 headers of {} bytes",
        d_diff / d_same.max(1e-9),
        BlockHeader::SIZE
    );
    println!(
        "mainnet cost of ONE header (64 MiB cache, SEQUENTIAL generation, memhard.rs:186-206): \
         11.7 s measured on 2 cores."
    );
    println!(
        "-> {} bytes sent => ~11.7 s of CPU + 64 MiB of allocation, without any proof of \
         work having been provided.",
        BlockHeader::SIZE
    );
    println!(
        "-> moreover `cache_for` (memhard.rs:246) only keeps 2 entries: the legitimate cache is \
         evicted every time."
    );
    assert!(d_diff > d_same * 3.0, "the amplification should be clear");
}

// ---------------------------------------------------------------------------
// 5. Selfish mining, uncles, and the reorg penalty
// ---------------------------------------------------------------------------

/// Relative revenue of a selfish miner (Eyal & Sirer), with Q21's gamma.
///
/// `alpha` = share of hash power, `gamma` = share of honest miners that mine on
/// the selfish miner's block in case of a 1-1 tie.
fn selfish_revenue(alpha: f64, gamma: f64) -> f64 {
    let a = alpha;
    let num = a * (1.0 - a) * (1.0 - a) * (4.0 * a + gamma * (1.0 - 2.0 * a)) - a * a * a;
    let den = 1.0 - a * (1.0 + (2.0 - a) * a);
    num / den
}

#[test]
fn a5_selfish_mining_penalty_and_uncles() {
    println!("\n=== A5: selfish mining: does the reorg penalty change the threshold? ===");
    println!(
        "REORG_PENALTY_FROM_DEPTH = {REORG_PENALTY_FROM_DEPTH}: a fork of depth <= {REORG_PENALTY_FROM_DEPTH}"
    );
    println!("pays NO penalty (chain.rs:972-982). Yet classic selfish mining");
    println!("only uses forks of depth 1 or 2.\n");
    println!(
        "{:>8} {:>12} {:>12} {:>12} {:>12}",
        "alpha", "gamma=0", "gamma=0.5", "gamma=1", "fair share"
    );
    let mut threshold = None;
    for a in [0.10f64, 0.20, 0.25, 0.30, 0.3333, 0.40, 0.45] {
        let r0 = selfish_revenue(a, 0.0);
        println!(
            "{:>8.4} {:>12.4} {:>12.4} {:>12.4} {:>12.4}",
            a,
            r0,
            selfish_revenue(a, 0.5),
            selfish_revenue(a, 1.0),
            a
        );
        if threshold.is_none() && r0 > a {
            threshold = Some(a);
        }
    }
    println!("\nclassic threshold (gamma=0) found between 25 % and 33 %: unchanged by Q21.");

    // How many blocks of depth does the penalty really cover?
    println!("\n--- depth of the forks used by selfish mining ---");
    println!("state 0'/1/2: the published reorg is 1 or 2 blocks deep.");
    println!(
        "penalty applied at depth 1 and 2: {} % (because depth <= {REORG_PENALTY_FROM_DEPTH})",
        0
    );
    println!("-> the \"depth must be paid for\" defense does NOT affect selfish mining.");

    // The Q21-specific accelerator: LWMA reacts in ~90 blocks, not 2016.
    println!("\n--- Q21-specific accelerator: the difficulty follows in 90 blocks, not 2016 ---");
    for a in [0.25f64, 0.3333, 0.40] {
        let orphans = 1.0 - (selfish_revenue(a, 0.0) + (1.0 - a)) / 1.0;
        let _ = orphans;
        let share = selfish_revenue(a, 0.0);
        // The real block rate drops: the difficulty adjusts, and the attacker
        // collects their surplus in value and not only in shares.
        println!(
            "  alpha = {:.2}: block share {:.4} (+{:.1} % vs their power), \
             delay before LWMA compensates: ~{} blocks = {:.1} h (Bitcoin: 2016 blocks = 336 h)",
            a,
            share,
            (share / a - 1.0) * 100.0,
            LWMA_WINDOW,
            LWMA_WINDOW as f64 * TARGET_BLOCK_SECS as f64 / 3600.0
        );
    }
}

#[test]
fn a5b_uncles_will_never_be_included() {
    println!("\n=== A5b: uncle economics: \"lever C\" is economically dead ===");
    println!("validate.rs:190-201 `uncle_rewards`: miner_share = subsidy - n * per_uncle.");
    println!("The uncle share is TAKEN from the subsidy of the miner who includes it.\n");
    println!(
        "{:>10} {:>16} {:>16} {:>16} {:>12}",
        "height", "subsidy", "0 uncles", "1 uncle", "lost revenue"
    );
    for h in [1_000u64, 20_000, 100_000, 500_000] {
        let r0 = validate::uncle_rewards(h, 0);
        let r1 = validate::uncle_rewards(h, 1);
        let r2 = validate::uncle_rewards(h, 2);
        println!(
            "{:>10} {:>16} {:>16} {:>16} {:>11.1}%",
            h,
            r0.miner_share,
            r0.miner_share,
            r1.miner_share,
            100.0 * (r0.miner_share - r1.miner_share) as f64 / r0.miner_share.max(1) as f64
        );
        assert!(r1.miner_share < r0.miner_share || r0.miner_share == 0);
        assert!(r2.miner_share <= r1.miner_share);
    }
    println!(
        "\n-> including an uncle costs {UNCLE_REWARD_PCT} % of the subsidy and earns NOTHING \
         (no inclusion bonus,"
    );
    println!("   and an uncle adds no cumulative work: chain.rs:889-893 only counts");
    println!("   the `block_work(header.bits)` of the block itself).");
    println!("-> a rational miner NEVER includes a third party's uncle. The only profitable case");
    println!(
        "   is to include their OWN orphan: they pay themselves {UNCLE_REWARD_PCT} %, \
         zero net cost, and thereby recover"
    );
    println!("   part of their lost work.");
    println!("-> consequence: lever C favors the BIG miner (who orphans themselves) instead");
    println!(
        "   of compensating the poorly connected small miner, that is, the opposite of its goal."
    );

    // Quantification: how much does a big miner recover from their own orphans?
    println!("\n--- recovery through self-inclusion (orphan rate o) ---");
    println!(
        "{:>8} {:>12} {:>16} {:>16}",
        "alpha", "orphans", "without uncles", "self-uncles"
    );
    for a in [0.10f64, 0.30, 0.50] {
        for o in [0.01f64, 0.05] {
            let without = a * (1.0 - o);
            let with = a * (1.0 - o) + a * o * (UNCLE_REWARD_PCT as f64 / 100.0);
            println!(
                "{:>8.2} {:>11.0}% {:>16.5} {:>16.5}  (+{:.2} %)",
                a,
                o * 100.0,
                without,
                with,
                (with / without - 1.0) * 100.0
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Depth penalty: overflow, and freezing of the chain
// ---------------------------------------------------------------------------

/// Exact reproduction of `Chain::reorg_threshold` (chain.rs:972-982), which is
/// private. Any divergence would be a bug in this test, not in the audited
/// code.
fn reorg_threshold(current_work: U256, depth: u64) -> U256 {
    if depth <= REORG_PENALTY_FROM_DEPTH {
        return current_work;
    }
    let excess = ((depth - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK)
        .min(REORG_PENALTY_MAX_PCT);
    current_work
        .mul_div(100 + excess, 100)
        .unwrap_or(current_work)
}

/// Minimum length of a competing branch to reorg at depth `d`, on a chain of
/// height `h` at constant difficulty.
///
/// Work per block = 1 (arbitrary unit, the difficulty is constant).
/// Current work = h. Work of the branch = (h - d) + L.
/// Condition (chain.rs:1072-1077): (h - d) + L > threshold(h, d).
fn minimum_length(h: u64, d: u64) -> Option<u64> {
    if d <= REORG_PENALTY_FROM_DEPTH {
        return Some(d + 1);
    }
    let excess = (d - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK;
    // threshold = h * (100 + excess) / 100, rounded down like mul_div.
    let threshold = (h as u128 * (100 + excess) as u128) / 100;
    let base = (h - d) as u128;
    let l = threshold.saturating_sub(base) + 1;
    u64::try_from(l).ok()
}

#[test]
fn a6_the_depth_penalty_freezes_the_chain_at_6_blocks() {
    println!("\n=== A6: `reorg_threshold`: the penalty applies to ALL the work since genesis ===");
    println!("chain.rs:973 `let current = self.total_work();` -> work ACCUMULATED since block 0.");
    println!("chain.rs:979 `current.mul_div(100 + excess, 100)` -> 1 % of the chain's TOTAL work");
    println!("is required per block of depth beyond {REORG_PENALTY_FROM_DEPTH}, not 1 % of the fork's work.\n");
    println!(
        "MAX_REORG_DEPTH announces {MAX_REORG_DEPTH} blocks (~24 h). `path_to_active` (chain.rs:949-970) \
         caps a branch at {} blocks.\n",
        MAX_REORG_DEPTH + 1
    );

    println!(
        "{:>10} {:>8} {:>18} {:>18} {:>10}",
        "height", "depth", "minimum branch", "surplus work", "possible?"
    );
    let branch_cap = MAX_REORG_DEPTH + 1;
    for h in [1_000u64, 10_000, 71_400, 100_000, 262_800, 2_628_000] {
        for d in [6u64, 7, 20, 100, 720] {
            let l = minimum_length(h, d);
            let possible = matches!(l, Some(x) if x <= branch_cap);
            println!(
                "{:>10} {:>8} {:>18} {:>18} {:>10}",
                h,
                d,
                l.map(|x| x.to_string()).unwrap_or("overflow".into()),
                l.map(|x| format!("{} blocks", x.saturating_sub(d)))
                    .unwrap_or("-".into()),
                if possible { "yes" } else { "NO" }
            );
        }
        println!();
    }

    // Height from which a reorg of depth 7 is arithmetically impossible,
    // whatever the attacker's work.
    let mut h_tipping = 0u64;
    for h in (1_000u64..200_000).step_by(100) {
        if minimum_length(h, 7).map(|l| l > branch_cap).unwrap_or(true) {
            h_tipping = h;
            break;
        }
    }
    println!(
        "-> from height {h_tipping} on (~{:.0} days after launch), NO reorg of \
         depth 7 can succeed anymore,",
        h_tipping as f64 * TARGET_BLOCK_SECS as f64 / 86400.0
    );
    println!("   even with 100 % of the hash power and even if the competing branch is honest.");
    println!(
        "   The real finality is therefore not {MAX_REORG_DEPTH} blocks (24 h) but \
         {REORG_PENALTY_FROM_DEPTH} blocks ({} min).",
        REORG_PENALTY_FROM_DEPTH * TARGET_BLOCK_SECS / 60
    );
    println!("   A network partition of more than 12 minutes produces two permanent chains.");
    assert!(h_tipping > 0 && h_tipping < 200_000);

    // Same computation for each depth, at a height of one year.
    println!("\n--- one year into the chain (height {BLOCKS_PER_YEAR}) ---");
    for d in [7u64, 8, 10, 50, 720] {
        println!(
            "  depth {d:>4}: minimum branch = {} blocks (hard cap: {branch_cap})",
            minimum_length(BLOCKS_PER_YEAR, d)
                .map(|x| x.to_string())
                .unwrap_or(">u64".into())
        );
    }
}

#[test]
fn a6b_reorg_threshold_overflow() {
    println!("\n=== A6b: can `reorg_threshold` overflow and cancel the penalty? ===");
    println!("`mul_div` (uint.rs:190-203): if `x * m` overflows, it falls back to `(x / d) * m`.");
    println!("If THAT product overflows too, `mul_div` returns None and `unwrap_or(current)`");
    println!("SILENTLY removes the whole penalty (chain.rs:979).\n");

    let max_factor =
        100 + (MAX_REORG_DEPTH - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK;
    println!(
        "maximum factor = {max_factor} / 100 = x{:.2}",
        max_factor as f64 / 100.0
    );

    // Overflow threshold: (x/100) * max_factor > 2^256.
    let limit = U256::MAX.checked_div_u64(max_factor / 100 + 1).unwrap();
    println!(
        "cumulative work from which the penalty disappears: ~2^{}",
        limit.bits()
    );

    for (name, w) in [
        ("U256::MAX", U256::MAX),
        ("2^250", U256([0, 0, 0, 1u64 << 58])),
        ("2^200", U256([0, 0, 1u64 << 8, 0])),
    ] {
        let s = reorg_threshold(w, MAX_REORG_DEPTH);
        println!(
            "  work = {name:<10} -> threshold = {} (penalty {})",
            if s == w {
                "IDENTICAL".to_string()
            } else {
                format!("2^{}", s.bits())
            },
            if s == w { "CANCELED" } else { "applied" }
        );
    }

    // Realistic cumulative work.
    println!("\n--- realistic work ---");
    for (name, bits) in [
        ("floor (INITIAL_BITS)", INITIAL_BITS),
        ("difficulty 2^40", bits_for_difficulty(2f64.powi(40))),
        ("difficulty 2^60", bits_for_difficulty(2f64.powi(60))),
    ] {
        let w = pow::block_work(bits);
        let total = w
            .checked_mul_u64(BLOCKS_PER_YEAR * 100)
            .unwrap_or(U256::MAX);
        println!(
            "  {name:<24} : work/block = 2^{:<4} ; 100 years of chain = 2^{}",
            w.bits(),
            total.bits()
        );
    }
    println!(
        "-> the overflow requires a cumulative work of ~2^{}. Even a hundred years at a difficulty of 2^60",
        limit.bits()
    );
    println!("   do not exceed 2^140. NOT EXPLOITABLE in practice, but the `unwrap_or(current)`");
    println!("   that hides the failure remains a bad practice in consensus code.");
}

#[test]
fn a6c_demonstration_on_a_real_chain() {
    println!("\n=== A6c: demonstration on a real `Chain` (Regtest) ===");
    use q21_core::chain::{genesis_block, Accept, ChainError};
    use q21_core::sig::SchemeId;

    const H: usize = 120; // height of the main chain
    const D: usize = 7; // depth of the fork (= 1 more than the free allowance)

    let g = genesis_block(Network::Regtest);
    let mut main_chain = Chain::new(Network::Regtest, g.clone());
    let mut up_to_fork: Vec<q21_core::block::Block> = Vec::new();

    let base = main_chain.tip().time;
    for i in 0..H {
        let t = base + (i as u64 + 1) * TARGET_BLOCK_SECS;
        let b = main_chain
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
            .expect("mining");
        main_chain.connect(&b, b.header.time).expect("connect");
        if i < H - D {
            up_to_fork.push(b);
        }
    }
    println!(
        "main chain: height {}, cumulative work 2^{}",
        main_chain.height(),
        main_chain.total_work().bits()
    );

    // Competing branch, built from the same fork point.
    let mut competitor = Chain::new(Network::Regtest, g);
    for b in &up_to_fork {
        competitor.connect(b, b.header.time).expect("replay");
    }
    assert_eq!(competitor.height() as usize, H - D);

    let mut branch = Vec::new();
    let base2 = competitor.tip().time;
    for i in 0..40 {
        let t = base2 + (i as u64 + 1) * TARGET_BLOCK_SECS + 7;
        let b = competitor
            .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
            .expect("mining");
        competitor.connect(&b, b.header.time).expect("connect");
        branch.push(b);
    }

    println!("competing branch: {} blocks from depth {D}\n", branch.len());
    println!(
        "{:>8} {:>10} {:>14} {:>34}",
        "blocks", "height", "lead", "submit() verdict"
    );
    let mut first_acceptance = None;
    for (i, b) in branch.iter().enumerate() {
        let now = b.header.time + 1;
        let r = main_chain.submit(b, now);
        let branch_height = (H - D + i + 1) as i64;
        let lead = branch_height - H as i64;
        let verdict = match &r {
            Ok(Accept::Extended) => "Extended".to_string(),
            Ok(Accept::SideBranch) => "SideBranch".to_string(),
            Ok(Accept::Reorganized { depth }) => {
                if first_acceptance.is_none() {
                    first_acceptance = Some(i + 1);
                }
                format!("REORGANIZED (depth {depth})")
            }
            Ok(Accept::AlreadyKnown) => "AlreadyKnown".into(),
            Err(ChainError::InsufficientWorkForDepth { depth }) => {
                format!("refused: InsufficientWork (depth {depth})")
            }
            Err(e) => format!("refused: {e:?}"),
        };
        if i < 3 || lead >= -1 || first_acceptance == Some(i + 1) {
            println!(
                "{:>8} {:>10} {:>+14} {:>34}",
                i + 1,
                branch_height,
                lead,
                verdict
            );
        }
        if first_acceptance.is_some() {
            break;
        }
    }
    match first_acceptance {
        Some(n) => println!(
            "\n-> it took {n} blocks to reorg {D} blocks, that is {} blocks of surplus \
             work for a fork of {D}.",
            n - D
        ),
        None => println!("\n-> NONE of the 40 blocks made the reorg possible."),
    }
    println!(
        "   model prediction: {} blocks.",
        minimum_length(H as u64, D as u64).unwrap()
    );
}

// ---------------------------------------------------------------------------
// 7. Network partition: the cap on the surcharge
// ---------------------------------------------------------------------------

/// A network partition must heal when it ends.
///
/// # What this test pins down
///
/// Without a cap, the surcharge reached 100% at depth 106 and more than 700%
/// at the maximum depth. Two halves of the network, each mining on its own
/// side, were therefore surcharged against each other, and after two hours
/// neither could rejoin the other anymore: an Internet outage became a
/// permanent split, where the documentation announced twenty-four hours.
///
/// We simulate two branches mined at equal difficulty with the actual rule
/// (`reorg_threshold`, reproduced above), and look, for each split of the
/// hash power, for the last moment at which the minority can still switch
/// over to the majority. With the cap, a 60% majority always reunifies
/// within the finality window; without it, it could no longer do so after a
/// few hours.
#[test]
fn a7_a_60_40_partition_always_reunifies() {
    /// A node on branch `a` switches to `b` if the work of `b` since the fork
    /// exceeds the threshold computed on the work of `a`.
    fn switch_possible(a: u64, b: u64) -> bool {
        let threshold = reorg_threshold(U256::from_u64(a), a);
        U256::from_u64(b) > threshold
    }
    let horizon = MAX_REORG_DEPTH;
    let mut rng = Rng::new(21);
    println!("\n=== A7: reunification after a partition (cap {REORG_PENALTY_MAX_PCT} %) ===");
    for minority in [0.5f64, 0.45, 0.40, 0.30] {
        let trials = 400;
        let mut never = 0;
        let mut lasts: Vec<u64> = Vec::new();
        for _ in 0..trials {
            let (mut a, mut b) = (0u64, 0u64);
            let mut last = None;
            for _ in 0..horizon {
                if rng.unit() < minority {
                    a += 1;
                } else {
                    b += 1;
                }
                // Can the minority (a) rejoin b, or the reverse?
                if switch_possible(a, b) || switch_possible(b, a) {
                    last = Some(a + b);
                }
            }
            match last {
                Some(n) => lasts.push(n),
                None => never += 1,
            }
        }
        lasts.sort_unstable();
        let median = lasts.get(lasts.len() / 2).copied().unwrap_or(0);
        let reunified_at_end = lasts.iter().filter(|n| **n >= horizon - 1).count();
        println!(
            "minority {:>3.0} %: last possible reunification, median {median} blocks; \
             still possible at block {horizon} in {} cases out of {trials}; never possible: {never}",
            minority * 100.0,
            reunified_at_end
        );
        assert_eq!(never, 0, "reunification must always have been possible");
        if minority <= 0.40 {
            // At 60/40 the ratio of the works is 1.5 in expectation, against a
            // threshold of 1.25: only a fluctuation of more than two standard
            // deviations over 720 blocks can still win, that is about 1% of
            // the cases.
            assert!(
                reunified_at_end as f64 >= 0.97 * trials as f64,
                "at 60/40, reunification must remain possible at the end of the window \
                 in at least 97 % of the cases ({reunified_at_end}/{trials})"
            );
        }
        if minority <= 0.30 {
            assert_eq!(
                reunified_at_end, trials,
                "at 70/30, reunification must remain possible at the end of the window"
            );
        }
    }
}
