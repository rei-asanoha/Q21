//! What mining really costs, with the mainnet parameters.
//!
//! This benchmark exists because the question "do you need an expensive
//! machine to mine Q21?" is not answered with an opinion. It measures four
//! things, on the machine where it is run:
//!
//! - the cache build time (what **every** node pays, even one that does not
//!   mine);
//! - the table build time (what the miner pays, once per epoch, i.e. about
//!   every 71 days);
//! - the mining rate, in attempts per second;
//! - the verification time of a header, which is what a node pays for each
//!   block received.
//!
//! Run:
//!
//! ```text
//! cargo run --release --example mining_bench
//! ```
//!
//! The machine needs about 2.2 GiB of free memory: the mainnet table alone
//! takes 2 of them. That is intended, and it is the very subject of the
//! measurement.
use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::hash::Hash256;
use q21_core::memhard::{self, PowCache, PowTable, TableParams};
use std::sync::Arc;
use std::time::Instant;

fn gib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn main() {
    let params = TableParams::for_network(Network::Mainnet);
    let epoch = 0;
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!();
    println!("  Q21 mining benchmark — mainnet parameters, epoch 0");
    println!("  Cores seen by the program: {threads}");
    println!();

    // --- Level 1: the cache -------------------------------------------------
    let t = Instant::now();
    let cache = Arc::new(PowCache::build(params, epoch));
    let cache_time = t.elapsed();
    println!(
        "  Cache   {:>8.0} MiB   built in {:>6.1} s",
        mib(cache.memory_bytes()),
        cache_time.as_secs_f64()
    );

    // --- Level 2: the table -------------------------------------------------
    let t = Instant::now();
    let table = Arc::new(PowTable::build_with_cache(&cache, params, epoch));
    let table_time = t.elapsed();
    println!(
        "  Table   {:>8.2} GiB   built in {:>6.1} s",
        gib(table.memory_bytes()),
        table_time.as_secs_f64()
    );
    println!();

    // --- Mining rate --------------------------------------------------------
    //
    // We do not go through `mine_with_table_parallel`: it stops as soon as the
    // target is reached, and an impossible target makes it return without
    // computing anything. A first draft of this benchmark thus displayed 30
    // billion attempts per second — it was the measurement of a loop that had
    // not run. We therefore count the hashes one by one, which is exactly the
    // work of one attempt.
    let mut header = BlockHeader {
        version: 1,
        prev_block: Hash256([7u8; 32]),
        merkle_root: Hash256([9u8; 32]),
        uncles_root: Hash256([0u8; 32]),
        miner: Hash256([3u8; 32]),
        time: 1_700_000_000,
        bits: 0x1d00_ffff,
        height: 1,
        nonce: 0,
    };

    // One thread first: that is the rate per core.
    let attempts: u64 = 200_000;
    let t = Instant::now();
    for i in 0..attempts {
        header.nonce = i;
        std::hint::black_box(memhard::hash_mining(&header, &table));
    }
    let time = t.elapsed().as_secs_f64();
    let per_core = attempts as f64 / time;
    println!(
        "  Mining  {:>8.0} attempts/s per core  ({} attempts in {:.1} s)",
        per_core, attempts, time
    );

    // Then on all cores, because that is what a miner uses.
    let t = Instant::now();
    let mut handles = Vec::new();
    for f in 0..threads {
        let table = Arc::clone(&table);
        let mut h = header;
        handles.push(std::thread::spawn(move || {
            for i in 0..attempts {
                h.nonce = (f as u64) << 40 | i;
                std::hint::black_box(memhard::hash_mining(&h, &table));
            }
        }));
    }
    for m in handles {
        let _ = m.join();
    }
    let time = t.elapsed().as_secs_f64();
    let rate = (attempts * threads as u64) as f64 / time;
    println!("  Mining  {:>8.0} attempts/s on {} core(s)", rate, threads);

    // --- Verification -------------------------------------------------------
    //
    // What a node that does not mine pays: a single table access, recomputed
    // from the cache. It is the price of the two-level fix.
    let n = 200;
    let t = Instant::now();
    for i in 0..n {
        header.nonce = i;
        let _ = memhard::hash_verify_with_cache(&header, params, &cache);
    }
    let per_verification = t.elapsed().as_secs_f64() / n as f64;
    println!("  Verify  {:>8.0} us per header", per_verification * 1e6);
    println!();

    // --- What this means ----------------------------------------------------
    //
    // One block every 120 seconds. If the whole network had the power of this
    // machine, it would take `rate * 120` attempts to find one.
    println!(
        "  At this rate, this machine makes {:.0} attempts between two blocks (120 s).",
        rate * 120.0
    );
    println!(
        "  The cache is rebuilt every {} blocks, i.e. about every {:.0} days.",
        q21_core::consensus::POW_EPOCH_BLOCKS,
        q21_core::consensus::POW_EPOCH_BLOCKS as f64 * 120.0 / 86400.0
    );
    println!();
}
