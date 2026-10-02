//! Proof of work.
//!
//! # What the chain actually uses
//!
//! Q21's proof of work is [`Q21Pow`]: two-level *memory-hard* with a growing
//! table, described in detail in [`crate::memhard`]. It is what the chain uses
//! both to validate and to mine, and it is the project's anti-ASIC lever: the
//! one that flattens the efficiency curve between an ordinary processor and
//! dedicated hardware, and therefore what decides whether Q21 will be mineable
//! by people or by foundries.
//!
//! [`Sha256Pow`] still exists, but only serves tests that have nothing to do
//! with memory: mining two hundred regtest blocks without building a table.
//! **It has no anti-ASIC property and is wired to no chain.**
//!
//! This note used to say the opposite: it presented this file as scaffolding
//! providing a SHA-256 proof "in the meantime", and warned that a deployment
//! would reproduce the industrial centralization the project fights. That was
//! true before [`crate::memhard`] existed; it has not been true since.
//! Documentation that describes the opposite of the code is worse than no
//! documentation, especially about the property the project's philosophy
//! depends on, and which every reader of the repository comes here to check
//! first.
//!
//! # What splitting along [`PowEngine`] still brings
//!
//! The trait only carries the hash; the comparison to the target is common to
//! all its implementors. There is therefore only one work validity rule, and
//! changing the algorithm cannot make it drift. That is what lets
//! [`Q21PowWithCache`] speed up the verification of a whole chain without
//! rewriting that rule.
//!
//! # Compact target
//!
//! The `bits` field of the header encodes a 256-bit target in 32 bits, in
//! Bitcoin's format: one exponent byte, three mantissa bytes.
//! `target = mantissa * 256^(exponent - 3)`. The format allows a sign bit
//! inherited from an unfortunate choice in 2009; we explicitly refuse it rather
//! than drag it along.

use crate::block::BlockHeader;
use crate::hash::{tagged_hash, Hash256};
use crate::uint::U256;

/// Domain tag of the proof of work.
///
/// Distinct from that of the block id: confusing the id of a block with the
/// value compared to the target is a classic design error.
pub const TAG_POW: &str = "Q21/pow/sha256-provisional";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PowError {
    /// Negative mantissa: the compact format inherits a useless sign bit.
    NegativeTarget,
    ZeroTarget,
    TargetTooLarge,
    /// Target easier than the difficulty floor ([`INITIAL_BITS`]).
    ///
    /// A header can announce as large a target as it wants; without a bound,
    /// announcing a target close to 2^256 would be enough for any hash to pass
    /// with negligible work: "valid headers ad infinitum without mining". Until
    /// now the bound lived only in `chain.rs` (the equality
    /// `header.bits == next_bits(parent)`, which caps at `INITIAL_BITS`). The
    /// work function itself accepted any target. A future caller of `check`
    /// (a headers-first validator, for example) that forgot the bound would
    /// reintroduce the flaw. So we put it in the computation it protects, not
    /// in its callers. Found by the phase 8b red team.
    ///
    /// [`INITIAL_BITS`]: crate::consensus::INITIAL_BITS
    TargetTooEasy,
    InsufficientWork,
}

/// The largest target (the lowest difficulty) a valid header can carry,
/// derived from the floor [`crate::consensus::INITIAL_BITS`].
///
/// A function, not a constant, because `target_from_compact` is not `const`.
/// Decoding `INITIAL_BITS` cannot fail: it is a well-formed compact target,
/// checked by a test.
pub fn floor_target() -> U256 {
    target_from_compact(crate::consensus::INITIAL_BITS)
        .expect("INITIAL_BITS is a valid compact target")
}

/// Decodes a compact target into its 256-bit value.
pub fn target_from_compact(bits: u32) -> Result<U256, PowError> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;

    if bits & 0x0080_0000 != 0 {
        return Err(PowError::NegativeTarget);
    }
    if mantissa == 0 {
        return Err(PowError::ZeroTarget);
    }

    let target = if exponent <= 3 {
        U256::from_u64((mantissa >> (8 * (3 - exponent))) as u64)
    } else {
        let mut v = U256::from_u64(mantissa as u64);
        for _ in 0..(exponent - 3) {
            v = v.checked_mul_u64(256).ok_or(PowError::TargetTooLarge)?;
        }
        v
    };

    if target.is_zero() {
        return Err(PowError::ZeroTarget);
    }
    Ok(target)
}

/// Encodes a 256-bit target into its compact form.
pub fn target_to_compact(target: U256) -> u32 {
    if target.is_zero() {
        return 0;
    }
    let bytes = target.to_be_bytes();
    let mut exponent = (target.bits() as usize).div_ceil(8);

    // The three most significant bytes of the value form the mantissa.
    let start = 32 - exponent;
    let mut mantissa: u32 = if exponent <= 3 {
        let mut v: u32 = 0;
        for o in &bytes[start..32] {
            v = (v << 8) | *o as u32;
        }
        v << (8 * (3 - exponent))
    } else {
        ((bytes[start] as u32) << 16) | ((bytes[start + 1] as u32) << 8) | bytes[start + 2] as u32
    };

    // The most significant bit of the mantissa would be read as a sign.
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }
    ((exponent as u32) << 24) | mantissa
}

/// Interface of a proof of work algorithm.
///
/// Phase 3 will provide a memory-hard implementation with a growing table. The
/// `height` parameter is already present because the table size will depend on
/// it.
pub trait PowEngine {
    fn hash(&self, header: &BlockHeader) -> Hash256;

    fn check(&self, header: &BlockHeader) -> Result<(), PowError> {
        let target = target_from_compact(header.bits)?;
        // Difficulty floor, applied INSIDE the work function: a target easier
        // than the floor is refused here, and not only by the bits equality
        // that `chain.rs` imposes. See `TargetTooEasy`.
        if target > floor_target() {
            return Err(PowError::TargetTooEasy);
        }
        let value = U256::from_be_bytes(self.hash(header).as_bytes());
        if value > target {
            return Err(PowError::InsufficientWork);
        }
        Ok(())
    }
}

/// Provisional SHA-256 proof of work. No anti-ASIC property.
///
/// Kept for tests that have nothing to do with memory, and to document by
/// contrast what [`Q21Pow`] brings.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256Pow;

impl PowEngine for Sha256Pow {
    fn hash(&self, header: &BlockHeader) -> Hash256 {
        tagged_hash(TAG_POW, &header.encode())
    }
}

/// Q21 proof of work: two-level memory-hard, growing table.
///
/// The path taken here is the **verification** one: it recomputes the `POW_K`
/// needed elements from the cache, without ever materializing the table. A
/// full node therefore holds the cache (64 MiB on mainnet) and not the 2 GiB a
/// miner requires. See [`crate::memhard`] for the details, for the measurement
/// that forced this two-level structure, and for the warning about the lack of
/// external cryptanalysis.
#[derive(Clone, Copy, Debug)]
pub struct Q21Pow {
    params: crate::memhard::TableParams,
}

impl Q21Pow {
    pub const fn new(network: crate::address::Network) -> Q21Pow {
        Q21Pow {
            params: crate::memhard::TableParams::for_network(network),
        }
    }

    pub const fn params(&self) -> crate::memhard::TableParams {
        self.params
    }
}

impl PowEngine for Q21Pow {
    fn hash(&self, header: &BlockHeader) -> Hash256 {
        crate::memhard::hash_verify(header, self.params)
    }
}

/// Verification using an **already built** epoch cache.
///
/// # Why this engine exists
///
/// [`Q21Pow`] goes through the global cache registry for each header: a lock,
/// then a lookup. That is of no consequence for a single block, but a snapshot
/// adoption verifies a whole chain (hundreds of thousands of headers) and does
/// so in parallel. That registry would then become the bottleneck: a lock
/// taken millions of times, fought over by every thread.
///
/// This engine borrows the cache by reference. It redefines **only** the hash:
/// the comparison to the target remains the trait's, so there is still only
/// one work validity rule, impossible to make diverge.
pub struct Q21PowWithCache<'a> {
    params: crate::memhard::TableParams,
    cache: &'a crate::memhard::PowCache,
}

impl<'a> Q21PowWithCache<'a> {
    pub fn new(
        params: crate::memhard::TableParams,
        cache: &'a crate::memhard::PowCache,
    ) -> Q21PowWithCache<'a> {
        Q21PowWithCache { params, cache }
    }
}

impl PowEngine for Q21PowWithCache<'_> {
    fn hash(&self, header: &BlockHeader) -> Hash256 {
        crate::memhard::hash_verify_with_cache(header, self.params, self.cache)
    }
}

/// Maximum number of work verdicts retained, before the oldest ones make room.
/// A verdict fits in about forty bytes: the bounded memory is on the order of
/// one hundred sixty kibibytes.
pub const WORK_MEMO_MAX: usize = 4096;

/// Proof of work verdicts already returned, by header id.
///
/// # Why this registry exists
///
/// The network layer held the global lock during the whole verification of a
/// received block, proof of work included: a memory-hard hash, and at each
/// epoch change the construction of a whole cache. Meanwhile, no other peer was
/// served, no mined block was announced, and the wallet interface waited.
///
/// The verdict depends only on the bytes of the header and the network
/// parameters: it is a pure function. It can therefore be computed **before**
/// taking the lock, recorded here, and the chain can read it back under the
/// lock instead of recomputing it. The id of a header is the hash of **all**
/// its fields; two headers that differ by one bit do not have the same id, and
/// therefore never share a verdict.
///
/// Rejections are retained just like acceptances: a header with invalid work
/// sent in a loop costs only a lookup.
///
/// The registry has its own lock, held for the duration of a lookup or an
/// insertion, never during a computation.
#[derive(Debug, Default)]
pub struct WorkMemo {
    inner: std::sync::Mutex<MemoInner>,
    /// Verdicts read back without computation.
    pub hits: std::sync::atomic::AtomicU64,
    /// Verdicts the chain itself had to compute, hence under the caller's
    /// lock. This is the counter that verification outside the lock must keep
    /// at zero for blocks coming from the network.
    pub computed: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Default)]
struct MemoInner {
    verdicts: std::collections::HashMap<Hash256, Result<(), PowError>>,
    order: std::collections::VecDeque<Hash256>,
}

impl WorkMemo {
    pub fn new() -> WorkMemo {
        WorkMemo::default()
    }

    /// The verdict already returned for this id, if there is one.
    pub fn verdict(&self, id: &Hash256) -> Option<Result<(), PowError>> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.verdicts.get(id).copied()
    }

    /// Records a verdict. Beyond [`WORK_MEMO_MAX`], the oldest one leaves.
    pub fn record(&self, id: Hash256, verdict: Result<(), PowError>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.verdicts.insert(id, verdict).is_none() {
            g.order.push_back(id);
            while g.order.len() > WORK_MEMO_MAX {
                if let Some(oldest) = g.order.pop_front() {
                    g.verdicts.remove(&oldest);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .verdicts
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// [`Q21Pow`] that first reads back the verdicts already returned.
///
/// Redefines only `check`, and only to consult [`WorkMemo`]: a missing verdict
/// is computed by the common rule of the trait, then retained. There is
/// therefore still only one work validity rule.
#[derive(Clone, Debug)]
pub struct Q21PowMemoized {
    pow: Q21Pow,
    memo: std::sync::Arc<WorkMemo>,
}

impl Q21PowMemoized {
    pub fn new(network: crate::address::Network) -> Q21PowMemoized {
        Q21PowMemoized {
            pow: Q21Pow::new(network),
            memo: std::sync::Arc::new(WorkMemo::new()),
        }
    }

    pub const fn params(&self) -> crate::memhard::TableParams {
        self.pow.params()
    }

    /// The bare engine, without the registry: the one used outside the lock.
    pub const fn engine(&self) -> Q21Pow {
        self.pow
    }

    pub fn memo(&self) -> std::sync::Arc<WorkMemo> {
        self.memo.clone()
    }
}

impl PowEngine for Q21PowMemoized {
    fn hash(&self, header: &BlockHeader) -> Hash256 {
        self.pow.hash(header)
    }

    fn check(&self, header: &BlockHeader) -> Result<(), PowError> {
        use std::sync::atomic::Ordering;
        let id = header.block_id();
        if let Some(v) = self.memo.verdict(&id) {
            self.memo.hits.fetch_add(1, Ordering::Relaxed);
            return v;
        }
        self.memo.computed.fetch_add(1, Ordering::Relaxed);
        let v = self.pow.check(header);
        self.memo.record(id, v);
        v
    }
}

/// Mining with a precomputed table.
///
/// This is the miner's path. Recomputing the elements at every nonce, as
/// [`mine`] does, would be correct but absurdly slow: that is precisely what
/// the design seeks to make expensive.
pub fn mine_with_table(
    header: &mut BlockHeader,
    table: &crate::memhard::PowTable,
    max_tries: u64,
) -> Result<u64, u64> {
    let target = match target_from_compact(header.bits) {
        Ok(c) => c,
        Err(_) => return Err(0),
    };
    for attempt in 0..max_tries {
        let value = U256::from_be_bytes(crate::memhard::hash_mining(header, table).as_bytes());
        if value <= target {
            return Ok(attempt);
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
    Err(max_tries)
}

/// Number of attempts explored per thread before taking stock.
///
/// A trade-off: too short, and we pay for creating threads; too long, and we
/// explore uselessly beyond the winner. Five hundred attempts represent a few
/// milliseconds of work on the mainnet table.
const BATCH_PER_THREAD: u64 = 512;

/// Mining spread over several threads, **with a result identical to
/// sequential mining**.
///
/// # Why this is not a mere convenience
///
/// The reference miner was single-threaded. On an eight-core machine, that
/// means anyone who bothers to write a parallel miner gets eight times the
/// throughput of ordinary people, for an afternoon's work. A project whose
/// reason for being is that mining stays accessible cannot ship a miner that
/// leaves seven eighths of the machine unused.
///
/// # Why the result stays deterministic
///
/// A naive parallel miner returns the first nonce found, which depends on
/// scheduling: two runs produce two different blocks. Here, the search
/// advances in **waves**: the threads sweep a contiguous range of nonces
/// together, we wait for the end of the wave, and we keep the **smallest**
/// winning nonce. The result is exactly the one a sequential loop would have
/// found, whatever the number of threads. That is what allows tests to compare
/// two independently mined chains.
pub fn mine_with_table_parallel(
    header: &mut BlockHeader,
    table: &std::sync::Arc<crate::memhard::PowTable>,
    max_tries: u64,
    threads: usize,
) -> Result<u64, u64> {
    let threads = threads.max(1);
    if threads == 1 {
        return mine_with_table(header, table, max_tries);
    }
    let target = match target_from_compact(header.bits) {
        Ok(c) => c,
        Err(_) => return Err(0),
    };

    // Sequential probe: most testnet blocks are found within a few hundred
    // attempts, and creating threads for that would cost more than the
    // computation itself.
    let start = header.nonce;
    let probe = BATCH_PER_THREAD.min(max_tries);
    for attempt in 0..probe {
        let value = U256::from_be_bytes(crate::memhard::hash_mining(header, table).as_bytes());
        if value <= target {
            return Ok(attempt);
        }
        header.nonce = header.nonce.wrapping_add(1);
    }

    let mut done = probe;
    while done < max_tries {
        let per_thread = BATCH_PER_THREAD
            .min((max_tries - done).div_ceil(threads as u64))
            .max(1);
        let base = start.wrapping_add(done);

        let winner = std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(threads);
            for f in 0..threads as u64 {
                let table = std::sync::Arc::clone(table);
                let mut h = *header;
                handles.push(s.spawn(move || {
                    let first = base.wrapping_add(f * per_thread);
                    for k in 0..per_thread {
                        h.nonce = first.wrapping_add(k);
                        let v =
                            U256::from_be_bytes(crate::memhard::hash_mining(&h, &table).as_bytes());
                        if v <= target {
                            return Some(done + f * per_thread + k);
                        }
                    }
                    None
                }));
            }
            handles
                .into_iter()
                .filter_map(|p| p.join().ok().flatten())
                .min()
        });

        if let Some(attempt) = winner {
            header.nonce = start.wrapping_add(attempt);
            return Ok(attempt);
        }
        done += per_thread * threads as u64;
    }

    header.nonce = start.wrapping_add(max_tries);
    Err(max_tries)
}

// ---------------------------------------------------------------------------
// Work
// ---------------------------------------------------------------------------

/// Expected work to find a block at the given target.
///
/// Equals `2^256 / (target + 1)`, that is the expected number of attempts.
/// Since `2^256` does not fit in a U256, we compute
/// `(~target) / (target + 1) + 1`, which gives exactly the same value: this is
/// Bitcoin's trick, and it is exact, not approximate.
///
/// # Why this function decides everything
///
/// Comparing two chains by their **length** is a design bug: an attacker can
/// produce a longer chain at low difficulty. The only honest measure is
/// cumulative work, and it is the one [`crate::chain`] uses to choose between
/// two forks.
pub fn block_work(bits: u32) -> U256 {
    let target = match target_from_compact(bits) {
        Ok(c) => c,
        // An invalid target is worth no work.
        Err(_) => return U256::ZERO,
    };
    let denom = match target.checked_add(U256::ONE) {
        Some(d) => d,
        None => return U256::ONE,
    };
    match target.not().div_rem(denom) {
        Some((q, _)) => q.checked_add(U256::ONE).unwrap_or(q),
        None => U256::ZERO,
    }
}

/// Searches for a nonce satisfying the target, within the limit of `max_tries`.
///
/// Single-threaded and deliberately simple: the serious miner will come with
/// phase 3. Returns the number of attempts consumed on failure.
pub fn mine<E: PowEngine>(
    engine: &E,
    header: &mut BlockHeader,
    max_tries: u64,
) -> Result<u64, u64> {
    let target = match target_from_compact(header.bits) {
        Ok(c) => c,
        Err(_) => return Err(0),
    };
    for attempt in 0..max_tries {
        let value = U256::from_be_bytes(engine.hash(header).as_bytes());
        if value <= target {
            return Ok(attempt);
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
    Err(max_tries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: Hash256([9u8; 32]),
            time: 1_755_000_000,
            bits,
            height: 1,
            nonce: 0,
        }
    }

    /// The property that makes the parallel miner acceptable: it must find
    /// **exactly** the same nonce as a sequential loop, whatever the number of
    /// threads. Without it, two nodes starting from the same candidate would
    /// produce two different blocks, and no test could compare two
    /// independently mined chains anymore.
    #[test]
    fn parallel_mining_gives_same_nonce_as_sequential() {
        use crate::address::Network;
        use crate::memhard::{PowTable, TableParams};

        let params = TableParams::for_network(Network::Regtest);
        let table = std::sync::Arc::new(PowTable::build(params, 0));

        // A target more demanding than testnet's, so that the search goes past
        // the initial sequential probe and actually enters the parallel waves.
        let mut reference = None;
        for threads in [1usize, 2, 3, 5, 8] {
            let mut h = header(0x2000_00ff);
            let attempt = mine_with_table_parallel(&mut h, &table, 5_000_000, threads)
                .expect("a nonce must exist");
            match reference {
                None => reference = Some((attempt, h.nonce)),
                Some(r) => assert_eq!(
                    (attempt, h.nonce),
                    r,
                    "{threads} threads found a different nonce than the sequential computation"
                ),
            }
            assert!(Q21Pow::new(Network::Regtest).check(&h).is_ok());
        }
    }

    /// A failure must stay a failure, whatever the number of threads.
    #[test]
    fn exhausted_budget_fails_the_same_in_parallel() {
        use crate::address::Network;
        use crate::memhard::{PowTable, TableParams};

        let params = TableParams::for_network(Network::Regtest);
        let table = std::sync::Arc::new(PowTable::build(params, 0));
        // Target impossible to reach in so few attempts.
        for threads in [1usize, 4] {
            let mut h = header(0x1d00_0001);
            assert!(mine_with_table_parallel(&mut h, &table, 2_000, threads).is_err());
        }
    }

    /// Benchmark of the real gain. Excluded from ordinary runs.
    ///
    /// `cargo test --release -- --ignored --nocapture parallel_mining_bench`
    #[test]
    #[ignore = "benchmark, not an assertion"]
    fn parallel_mining_bench() {
        use crate::address::Network;
        use crate::memhard::{PowTable, TableParams};

        let params = TableParams::for_network(Network::Testnet);
        let table = std::sync::Arc::new(PowTable::build(params, 0));
        let cores = std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1);

        println!("available cores: {cores}");
        let mut reference = 0.0f64;
        for threads in 1..=cores {
            let mut h = header(0x2000_000f);
            let t0 = std::time::Instant::now();
            let attempts = mine_with_table_parallel(&mut h, &table, 50_000_000, threads)
                .expect("a nonce must exist");
            let d = t0.elapsed().as_secs_f64();
            let rate = attempts as f64 / d.max(1e-9);
            if threads == 1 {
                reference = rate;
            }
            println!(
                "{threads} thread(s): {rate:>10.0} attempts/s   speedup {:.2} x   nonce {}",
                rate / reference.max(1e-9),
                h.nonce
            );
        }
    }

    #[test]
    fn decoding_known_targets() {
        // Bitcoin's easiest target: mantissa 0xffff, exponent 0x1d.
        // Canonical value:
        // 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        let c = target_from_compact(0x1d00_ffff).unwrap();
        let b = c.to_be_bytes();
        assert_eq!(b[0..4], [0x00; 4]);
        assert_eq!(b[4..6], [0xff, 0xff]);
        assert_eq!(b[6..], [0u8; 26]);
    }

    #[test]
    fn negative_target_is_refused() {
        assert_eq!(
            target_from_compact(0x0180_0000),
            Err(PowError::NegativeTarget)
        );
    }

    #[test]
    fn zero_target_is_refused() {
        assert_eq!(target_from_compact(0x1d00_0000), Err(PowError::ZeroTarget));
    }

    #[test]
    fn compact_encoding_round_trip() {
        for bits in [0x1d00_ffff_u32, 0x1c00_ffff, 0x2000_ffff, 0x0300_ffff] {
            let c = target_from_compact(bits).unwrap();
            let redone = target_to_compact(c);
            let c2 = target_from_compact(redone).unwrap();
            assert_eq!(c, c2, "unstable round trip for {bits:#x}");
        }
    }

    #[test]
    fn smaller_target_is_harder() {
        let easy = target_from_compact(0x2000_ffff).unwrap();
        let hard = target_from_compact(0x1000_ffff).unwrap();
        assert!(hard < easy);
    }

    #[test]
    fn mining_finds_nonce_for_easy_target() {
        let engine = Sha256Pow;
        // The easiest ALLOWED target: the floor itself. One in ~256 attempts
        // passes, so a few hundred attempts are enough, and, unlike the old
        // `0x2100_ffff`, this target is within the consensus bounds (see
        // `floor_target` and `TargetTooEasy`).
        let mut h = header(crate::consensus::INITIAL_BITS);
        let attempts = mine(&engine, &mut h, 100_000).expect("no nonce found");
        assert!(
            engine.check(&h).is_ok(),
            "the mined block does not validate"
        );
        assert!(attempts < 100_000);
    }

    /// ATTACK (red team 8b): a header announcing a target easier than the floor
    /// passed `check` with a zero nonce and negligible work, as long as no
    /// caller checked the bound outside. `check` must now refuse it itself.
    #[test]
    fn target_easier_than_floor_is_refused_by_check() {
        let engine = Sha256Pow;
        // 0x2100_7fff: exponent 0x21, target ~2^255, far above the floor
        // ~2^248. Decoding succeeds (no overflow), so only the bound stops it.
        // Zero nonce: no work.
        let h = header(0x2100_7fff);
        assert!(
            target_from_compact(h.bits).is_ok(),
            "the target decodes: it is not an overflow that stops it"
        );
        assert_eq!(
            engine.check(&h),
            Err(PowError::TargetTooEasy),
            "a target below the floor must be refused INSIDE the work function"
        );
    }

    #[test]
    fn unmined_block_fails_verification() {
        let engine = Sha256Pow;
        // Very demanding target: the zero nonce cannot fit.
        let h = header(0x0300_0001);
        assert_eq!(engine.check(&h), Err(PowError::InsufficientWork));
    }

    #[test]
    fn changing_nonce_changes_hash() {
        let engine = Sha256Pow;
        let a = header(0x2000_ffff);
        let mut b = a;
        b.nonce = 1;
        assert_ne!(engine.hash(&a), engine.hash(&b));
    }

    #[test]
    fn work_hash_differs_from_block_id() {
        let h = header(0x2000_ffff);
        assert_ne!(
            Sha256Pow.hash(&h),
            h.block_id(),
            "confusing the two is a design error"
        );
    }

    #[test]
    fn mining_gives_up_cleanly() {
        let engine = Sha256Pow;
        let mut h = header(0x0300_0001);
        assert_eq!(mine(&engine, &mut h, 50), Err(50));
    }
}
