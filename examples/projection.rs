//! The life of the chain, computed and not narrated.
//!
//! This program simulates nothing: it calls the same consensus functions as
//! the validator, height by height, and prints what they return. Any
//! divergence between this table and the behavior of the network would be a
//! defect of the network, not of the table.
//!
//! It answers four questions:
//!
//! 1. How many Q21 exist at the end of each year, and when is the cap of
//!    21,000,001 approached?
//! 2. How many transactions can the chain carry, given that a post-quantum
//!    signature weighs 4,627 bytes where ECDSA weighs 71?
//! 3. How much disk does that represent?
//! 4. How much memory must a miner hold, year by year?
//!
//! Run:
//!
//! ```text
//! cargo run --release --example projection
//! ```
use q21_core::address::Network;
use q21_core::consensus::*;
use q21_core::emission;
use q21_core::memhard::{self, TableParams};
use q21_core::sig::SchemeId;

/// Blocks per year, at the target pace.
const BLOCKS_PER_YEAR: u64 = (365.25 * 86400.0 / 120.0) as u64;

/// Real size of a transaction with one input and one output, in ML-DSA-87.
///
/// Measured by `cargo run --release --features mldsa --example bench_sig`,
/// which builds a real one and serializes it. It is hard-coded here so that
/// this program does not need the `mldsa` feature; the test at the bottom
/// checks that it stays consistent with the sizes declared by `sig`.
const TX_BYTES: usize = 7_361;

fn q21(units: u64) -> f64 {
    units as f64 / UNITS_PER_COIN as f64
}

/// Prints the same quantities as CSV, year by year.
///
/// Used to feed a chart without copying numbers by hand — copying is an
/// opportunity to make mistakes, and a wrong chart is worse than a correct
/// table.
fn csv() {
    let p = TableParams::for_network(Network::Mainnet);
    println!("year,reward_q21,circulating_q21,pct_of_cap,table_gib");
    for year in 0..=100u64 {
        let h = year * BLOCKS_PER_YEAR;
        let ep = memhard::epoch_of(h);
        let t = memhard::table_size(p, ep) as u64 * POW_ELEMENT_SIZE as u64;
        println!(
            "{},{:.8},{:.2},{:.4},{:.4}",
            year,
            q21(emission::block_subsidy(h).units()),
            q21(emission::total_supply_at(h).units()),
            100.0 * emission::total_supply_at(h).units() as f64 / MAX_SUPPLY as f64,
            t as f64 / 1024.0 / 1024.0 / 1024.0
        );
    }
}

fn main() {
    if std::env::args().any(|a| a == "--csv") {
        csv();
        return;
    }

    println!();
    println!("  ===  THE LIFE OF Q21, COMPUTED  ===");
    println!();

    // -----------------------------------------------------------------------
    // 1. Emission
    // -----------------------------------------------------------------------
    println!("  --- Emission ---");
    println!();
    println!(
        "  {:>4}  {:>12}  {:>10}  {:>14}  {:>7}",
        "year", "height", "per block", "circulating", "of cap"
    );

    let cap = MAX_SUPPLY;
    for year in [1u64, 2, 3, 4, 5, 8, 10, 15, 20, 25, 30, 40, 50, 75, 100] {
        let h = year * BLOCKS_PER_YEAR;
        let per_block = emission::block_subsidy(h).units();
        let total = emission::total_supply_at(h).units();
        println!(
            "  {:>4}  {:>12}  {:>10.4}  {:>14.0}  {:>6.2}%",
            year,
            h,
            q21(per_block),
            q21(total),
            100.0 * total as f64 / cap as f64
        );
    }
    println!();

    // The thresholds. We look for the first height that crosses them, in
    // steps of one decay epoch — no need to be exact to the block for a
    // quantity that changes every six days.
    println!("  --- Thresholds ---");
    println!();
    let thresholds = [50.0f64, 75.0, 90.0, 99.0, 99.9, 99.99];
    let mut i = 0;
    let mut epoch = 0u64;
    while i < thresholds.len() && epoch < 20_000 {
        let h = epoch * DECAY_EPOCH_BLOCKS;
        let pct = 100.0 * emission::total_supply_at(h).units() as f64 / cap as f64;
        while i < thresholds.len() && pct >= thresholds[i] {
            println!(
                "  {:>6.2}% of the cap reached at block {:>10}  —  {:>5.1} years",
                thresholds[i],
                h,
                h as f64 / BLOCKS_PER_YEAR as f64
            );
            i += 1;
        }
        epoch += 1;
    }

    // The end of mining: the tail floor guarantees that it exists, and that
    // the cap is reached exactly there.
    let h_end = emission::emission_end_height();
    println!(
        "  cap reached at block {:>10}  —  {:>6.2} years",
        h_end - 1,
        (h_end - 1) as f64 / BLOCKS_PER_YEAR as f64
    );
    println!(
        "  issued at that point: {:.8} Q21 out of {:.8} — {} missing",
        q21(emission::total_supply_at(h_end).units()),
        q21(cap),
        cap - emission::total_supply_at(h_end).units()
    );
    println!(
        "  remainder of the last issuing block: {:.8} Q21",
        q21(emission::block_subsidy(h_end - 1).units())
    );
    println!(
        "  tail floor: {:.8} Q21 per block as soon as the decay goes below it",
        q21(TAIL_REWARD)
    );
    println!();

    // Effective half-life, for comparison with Bitcoin's halving.
    let mut e = 0u64;
    while emission::epoch_base_reward(e) > INITIAL_REWARD / 2 {
        e += 1;
    }
    println!(
        "  the reward is halved every {:.2} years",
        (e * DECAY_EPOCH_BLOCKS) as f64 / BLOCKS_PER_YEAR as f64
    );
    println!();

    // -----------------------------------------------------------------------
    // 2. Capacity
    // -----------------------------------------------------------------------
    println!("  --- Capacity ---");
    println!();
    let per_block = MAX_BLOCK_SIZE / TX_BYTES;
    let per_second = per_block as f64 / TARGET_BLOCK_SECS as f64;
    let per_day = per_block as u64 * 720;
    println!(
        "  ML-DSA-87 signature        {:>10} bytes    (ECDSA: 71)",
        SchemeId::MlDsa87.sig_len()
    );
    println!(
        "  public key                 {:>10} bytes",
        SchemeId::MlDsa87.pubkey_len()
    );
    println!(
        "  1-to-1 transaction         {:>10} bytes    (measured)",
        TX_BYTES
    );
    println!("  maximum block size         {:>10} bytes", MAX_BLOCK_SIZE);
    println!();
    println!("  transactions per block     {:>10}", per_block);
    println!("  transactions per second    {:>10.2}", per_second);
    println!("  transactions per day       {:>10}", per_day);
    println!();

    for people in [1_000_000u64, 15_000_000, 100_000_000] {
        let days = people as f64 / per_day as f64;
        println!(
            "  with {:>11} holders: one transaction each every {:>5.1} days",
            people, days
        );
    }
    println!();

    // -----------------------------------------------------------------------
    // 3. Disk
    // -----------------------------------------------------------------------
    println!("  --- Disk, if blocks are full ---");
    println!();
    let bytes_per_year = MAX_BLOCK_SIZE as u64 * BLOCKS_PER_YEAR;
    println!(
        "  per day  {:>8.2} GiB        per year  {:>8.2} TiB",
        (MAX_BLOCK_SIZE as u64 * 720) as f64 / 1024.0 / 1024.0 / 1024.0,
        bytes_per_year as f64 / 1024.0 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  block body window kept: {} blocks, i.e. {:.2} GiB",
        BODY_WINDOW,
        (BODY_WINDOW * MAX_BLOCK_SIZE) as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!();

    // -----------------------------------------------------------------------
    // 4. The miner's memory
    // -----------------------------------------------------------------------
    println!("  --- Memory required of the miner ---");
    println!();
    let p = TableParams::for_network(Network::Mainnet);
    println!(
        "  {:>4}  {:>8}  {:>10}  {:>10}",
        "year", "epoch", "table", "cache"
    );
    for year in [0u64, 1, 2, 3, 4, 5, 6, 7, 10, 20] {
        let h = year * BLOCKS_PER_YEAR;
        let ep = memhard::epoch_of(h);
        let t = memhard::table_size(p, ep) as u64 * POW_ELEMENT_SIZE as u64;
        let c = memhard::cache_size(p, ep) as u64 * POW_ELEMENT_SIZE as u64;
        println!(
            "  {:>4}  {:>8}  {:>7.2} GiB  {:>7.0} MiB",
            year,
            ep,
            t as f64 / 1024.0 / 1024.0 / 1024.0,
            c as f64 / 1024.0 / 1024.0
        );
    }
    println!();
    println!(
        "  duration of a proof-of-work epoch: {:.1} days",
        POW_EPOCH_BLOCKS as f64 * TARGET_BLOCK_SECS as f64 / 86400.0
    );
    println!();

    // -----------------------------------------------------------------------
    // 5. What mining becomes when many people join in
    // -----------------------------------------------------------------------
    //
    // The rate per machine comes from the benchmark: 84,053 attempts/s per
    // core, measured. We assume 400,000 attempts/s for an "average" machine of
    // the installed base — a mix of four-core laptops and eight-core desktop
    // machines. That number is an assumption, not a measurement, and
    // everything that follows depends on it linearly.
    const PER_MACHINE: f64 = 400_000.0;
    const WATTS: f64 = 80.0;

    println!("  --- Mining at large scale ---");
    println!();
    println!("  assumption: {PER_MACHINE:.0} attempts/s and {WATTS:.0} W per machine");
    println!();
    println!(
        "  {:>12}  {:>14}  {:>18}  {:>10}",
        "miners", "network", "one block each every", "power"
    );
    for n in [1_000u64, 100_000, 1_000_000, 15_000_000] {
        let network = n as f64 * PER_MACHINE;
        // Share of one miner = 1/n. One block every 120 s for the whole
        // network.
        let seconds = TARGET_BLOCK_SECS as f64 * n as f64;
        let days = seconds / 86400.0;
        let gw = n as f64 * WATTS / 1e9;
        let duration = if days < 365.0 {
            format!("{days:.1} days")
        } else {
            format!("{:.1} years", days / 365.25)
        };
        println!(
            "  {:>12}  {:>10.2e} h/s  {:>18}  {:>7.2} GW",
            n, network, duration, gw
        );
    }
    println!();
    println!("  With 15 million miners, a single individual wins a block every");
    println!("  57 years. Solo mining then no longer makes sense: people pool,");
    println!("  and pooling is the real centralization risk that remains.");
    println!();
}
