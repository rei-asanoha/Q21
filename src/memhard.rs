//! Two-level memory-hard proof of work, growing table.
//!
//! This is lever A of section 5 of the white paper, and the only part of the
//! protocol that decides whether Q21 will be mineable by people or by
//! foundries.
//!
//! # What phase 6 fixed
//!
//! The initial design derived each table element by an independent hash,
//! `element(i) = H(seed, i)`. On the real 2 GiB table, the benchmark gave its
//! verdict:
//!
//! ```text
//! fraction held      memory       relative cost of an attempt
//!        1/1         2048 MiB          1.00 x
//!        1/2         1024 MiB          1.98 x
//!        1/8          256 MiB          2.85 x
//!        0/1            0 MiB          2.86 x
//! ```
//!
//! Two readings, both bad. First, doing **entirely** without memory cost only
//! 2.86x: a dedicated circuit whose hash is three times faster than a processor
//! had an incentive to carry no DRAM at all, and a SHA-256 circuit beats a
//! processor by a factor of ~10^8. Second, the curve flattened from 256 MiB:
//! beyond that, buying memory bought nothing more. The anti-ASIC property was
//! false, and only the measurement at the real size showed it: on 32 MiB,
//! everything fit in cache and the ratio displayed a reassuring 6.46x.
//!
//! # The two-level structure
//!
//! The fix follows Ethash's.
//!
//! - **Level 1, the cache** ([`PowCache`]): `N / POW_CACHE_RATIO` elements,
//!   that is 64 MiB on mainnet. Generated **as a chain** (element `i` depends
//!   on `i-1`) then mixed [`POW_CACHE_ROUNDS`] times. A fragment of it cannot
//!   be rebuilt without rebuilding everything that precedes it.
//! - **Level 2, the table** ([`PowTable`]): `N` elements, 2 GiB. Each element
//!   is computed by [`POW_J`] **dependent** random accesses to the cache.
//!
//! Mining without the table therefore no longer saves memory: it multiplies
//! the number of accesses by [`POW_J`], hence the bandwidth, the only resource
//! a circuit cannot manufacture with silicon.
//!
//! # The price, stated plainly
//!
//! A verifying node previously needed **zero** bytes. It must now hold the
//! cache: 64 MiB. That is the exact cost of the fix, and it is the same
//! trade-off Ethereum made. Verifying a block goes from ~45 us to ~660 us;
//! catching up on ten years of chain costs half an hour of proof of work
//! computation, which is less than verifying the ML-DSA signatures of the same
//! period.
//!
//! A miner, for its part, still holds 2 GiB, and rebuilds its table once per
//! epoch, about every 71 days.
//!
//! # The table grows
//!
//! Its size grows by [`POW_TABLE_GROWTH_PCT`] at each epoch. A circuit designed
//! around a fixed amount of memory becomes mediocre as soon as the table
//! exceeds it, and dedicated hardware therefore becomes obsolete on its own.
//! Monero had to inflict four defensive hard forks on itself between 2018 and
//! 2019 to get the same effect by hand; we prefer to automate it.
//!
//! # What the September 2026 review fixed
//!
//! The mixing loop derived the index of the next read from the **32 least
//! significant bits** of the accumulator, and the accumulation was an
//! addition whose carry never propagates back into those bits. The whole walk
//! (the [`POW_K`] reads) therefore depended only on a 32-bit word, whatever
//! the rest of the state. A table of 2^32 entries (128 GiB), computed once per
//! epoch, replaced the 32 dependent reads with a single one: a 32x bandwidth
//! gain for a machine with HBM memory, and table growth rendered useless,
//! since the state stayed at 32 bits whatever its size. The weakness was
//! mathematical, not statistical: two states differing only in their upper 224
//! bits walked exactly the same addresses.
//!
//! The index is now derived from a mix of all **four** words of the state, and
//! each read is followed by a diffusion over the full width: four Feistel
//! rounds built on the SplitMix64 finalizer. After a single iteration, every
//! bit of the state depends on every bit of the read and of the previous
//! state; there is no longer a short substate the walk could depend on. The
//! cost is about ten nanoseconds, against a hundred for the DRAM access it
//! follows: memory remains the bottleneck, which is the whole point. The same
//! fix applies to generating elements from the cache.
//!
//! # A warning this file must carry
//!
//! Designing a proof of work function is an exercise where one easily goes
//! wrong, and stays wrong for a long time; this file has already proven it
//! twice. The current construction **has received no external cryptanalysis**.
//! The measurements it shows were made by its author, on a single machine,
//! against a reference implementation and not against an implementation
//! optimized by someone whose job is to beat it. Until that review exists, the
//! anti-ASIC property remains a supported hypothesis, not an established fact.

use crate::block::BlockHeader;
use crate::consensus::*;
use crate::hash::{tagged_hash_parts, Hash256};
use crate::uint::U256;

const TAG_EPOCH: &str = "Q21/pow/epoch";
const TAG_ELEM: &str = "Q21/pow/elem";
const TAG_SEED: &str = "Q21/pow/seed";
const TAG_FINAL: &str = "Q21/pow/final";
const TAG_CACHE_SEED: &str = "Q21/pow/cache/seed";
const TAG_CACHE: &str = "Q21/pow/cache";
const TAG_CACHE_MIX: &str = "Q21/pow/cache/mix";
const TAG_ELEM_FINAL: &str = "Q21/pow/elem/final";

/// Table parameters for a given network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableParams {
    pub n0: u32,
    pub nmax: u32,
}

impl TableParams {
    pub const fn for_network(network: crate::address::Network) -> TableParams {
        match network {
            crate::address::Network::Mainnet => TableParams {
                n0: POW_TABLE_N0_MAINNET,
                nmax: POW_TABLE_NMAX_MAINNET,
            },
            crate::address::Network::Testnet => TableParams {
                n0: POW_TABLE_N0_TESTNET,
                nmax: POW_TABLE_NMAX_TESTNET,
            },
            crate::address::Network::Regtest => TableParams {
                n0: POW_TABLE_N0_REGTEST,
                nmax: POW_TABLE_NMAX_REGTEST,
            },
        }
    }
}

/// Proof of work epoch corresponding to a height.
pub const fn epoch_of(height: u64) -> u64 {
    height / POW_EPOCH_BLOCKS
}

/// Number of table elements at a given epoch.
pub fn table_size(params: TableParams, epoch: u64) -> u32 {
    let mut n = params.n0 as u64;
    let max = params.nmax as u64;
    for _ in 0..epoch {
        n = n * (100 + POW_TABLE_GROWTH_PCT) / 100;
        if n >= max {
            return params.nmax;
        }
    }
    n as u32
}

/// Seed of an epoch. Changes every [`POW_EPOCH_BLOCKS`] blocks.
pub fn epoch_seed(epoch: u64) -> Hash256 {
    tagged_hash_parts(TAG_EPOCH, &[&epoch.to_le_bytes()])
}

/// Number of cache elements at a given epoch.
pub fn cache_size(params: TableParams, epoch: u64) -> u32 {
    (table_size(params, epoch) / POW_CACHE_RATIO).max(1)
}

// ---------------------------------------------------------------------------
// Level 1: the cache
// ---------------------------------------------------------------------------

/// Cache of an epoch: level 1 of the proof of work.
///
/// # What it fixes
///
/// The first design derived each table element by an independent hash:
/// `element(i) = H(seed, i)`. It was elegant, and wrong. The phase 6
/// benchmark, on the real 2 GiB table, measured that doing entirely without
/// memory cost only **2.86x**, and that beyond 256 MiB, memory bought nothing
/// more. A dedicated circuit therefore had no reason to carry DRAM.
///
/// Here, a table element can only be computed by walking this cache [`POW_J`]
/// times, in **sequentially dependent** random accesses. Refusing the table no
/// longer saves memory: it multiplies the number of accesses by [`POW_J`],
/// hence the bandwidth, the only resource a circuit cannot manufacture with
/// silicon.
///
/// # What it honestly costs
///
/// A verifying node must now hold this cache: 64 MiB on mainnet, instead of
/// zero. That is the exact price of the fix, and it is the same trade-off
/// Ethereum made with Ethash. A miner, for its part, still holds 2 GiB.
pub struct PowCache {
    epoch: u64,
    c: u32,
    seed: Hash256,
    data: Vec<u8>,
}

impl PowCache {
    /// Builds the cache of an epoch.
    ///
    /// Generation is **sequential**: element `i` derives from element `i-1`,
    /// then [`POW_CACHE_ROUNDS`] mixing passes bind each element to another
    /// one drawn at random. A fragment of the cache therefore cannot be
    /// rebuilt without rebuilding everything that precedes it.
    pub fn build(params: TableParams, epoch: u64) -> PowCache {
        let c = cache_size(params, epoch);
        let seed = epoch_seed(epoch);
        let mut data = vec![0u8; c as usize * POW_ELEMENT_SIZE];

        // Initial chain.
        let mut current = tagged_hash_parts(TAG_CACHE_SEED, &[seed.as_bytes()]);
        data[0..POW_ELEMENT_SIZE].copy_from_slice(current.as_bytes());
        for i in 1..c as usize {
            current = tagged_hash_parts(TAG_CACHE, &[current.as_bytes()]);
            data[i * POW_ELEMENT_SIZE..(i + 1) * POW_ELEMENT_SIZE]
                .copy_from_slice(current.as_bytes());
        }

        // Mixing passes: each element depends on the previous one and on
        // another element designated by its own content.
        let mut xor = [0u8; POW_ELEMENT_SIZE];
        for _ in 0..POW_CACHE_ROUNDS {
            for i in 0..c as usize {
                let prev = if i == 0 { c as usize - 1 } else { i - 1 };
                let mut j = {
                    let d = &data[i * POW_ELEMENT_SIZE..i * POW_ELEMENT_SIZE + 4];
                    (u32::from_le_bytes([d[0], d[1], d[2], d[3]]) % c) as usize
                };
                // If the element drawn is the previous one itself, the XOR below
                // would cancel out and the element would become a constant (H(0)
                // for this tag) instead of depending on the cache. A loss of
                // entropy in the very structure the verifiers hold (red team
                // 8b). So we shift by one: the two mixed terms stay two distinct
                // elements, hence the XOR is never zero. Only the degenerate
                // slots (about one in `c`) change; all the others keep exactly
                // their value.
                if j == prev && c > 1 {
                    j = (prev + 1) % c as usize;
                }
                for k in 0..POW_ELEMENT_SIZE {
                    xor[k] = data[prev * POW_ELEMENT_SIZE + k] ^ data[j * POW_ELEMENT_SIZE + k];
                }
                let h = tagged_hash_parts(TAG_CACHE_MIX, &[&xor]);
                data[i * POW_ELEMENT_SIZE..(i + 1) * POW_ELEMENT_SIZE]
                    .copy_from_slice(h.as_bytes());
            }
        }

        PowCache {
            epoch,
            c,
            seed,
            data,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> u32 {
        self.c
    }

    pub fn is_empty(&self) -> bool {
        self.c == 0
    }

    pub fn memory_bytes(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn read(&self, i: u32) -> U256 {
        let start = i as usize * POW_ELEMENT_SIZE;
        let mut b = [0u8; POW_ELEMENT_SIZE];
        b.copy_from_slice(&self.data[start..start + POW_ELEMENT_SIZE]);
        U256::from_be_bytes(&b)
    }
}

/// Cache shared by the whole process.
///
/// Building the cache costs a few seconds on mainnet; redoing it per thread
/// would be absurd, and keeping one per peer would be ruinous. We keep at most
/// two epochs: the current one and the previous one, while an epoch
/// transition completes.
type SharedCaches = std::sync::Mutex<Vec<(TableParams, u64, std::sync::Arc<PowCache>)>>;
static CACHES: std::sync::OnceLock<SharedCaches> = std::sync::OnceLock::new();

/// Returns the cache of an epoch, building it if needed.
pub fn cache_for(params: TableParams, epoch: u64) -> std::sync::Arc<PowCache> {
    let m = CACHES.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, c)) = g.iter().find(|(p, e, _)| *p == params && *e == epoch) {
        return c.clone();
    }
    let c = std::sync::Arc::new(PowCache::build(params, epoch));
    g.push((params, epoch, c.clone()));
    // Keep only the last two entries.
    while g.len() > 2 {
        g.remove(0);
    }
    c
}

// ---------------------------------------------------------------------------
// Level 2: the table elements
// ---------------------------------------------------------------------------

/// Computes the table element at index `i`, from the cache.
///
/// Cost: two hashes and [`POW_J`] **dependent** random accesses to the cache.
/// That cost is what makes refusing the table expensive.
#[inline]
pub fn element(cache: &PowCache, i: u32) -> Hash256 {
    let mut acc = U256::from_be_bytes(
        tagged_hash_parts(TAG_ELEM, &[cache.seed.as_bytes(), &i.to_le_bytes()]).as_bytes(),
    );
    for _ in 0..POW_J {
        let idx = index_from(&acc, cache.c);
        acc = absorb(acc, cache.read(idx));
    }
    tagged_hash_parts(TAG_ELEM_FINAL, &[&acc.to_be_bytes()])
}

/// Precomputed table of an epoch. Useful to the miner, useless to the validator.
pub struct PowTable {
    epoch: u64,
    n: u32,
    /// Concatenated elements, `POW_ELEMENT_SIZE` bytes each.
    data: Vec<u8>,
}

impl PowTable {
    /// Builds the table of an epoch, in parallel on all cores.
    ///
    /// The elements are independent of one another once the cache is built:
    /// construction therefore parallelizes effortlessly. It is the only step
    /// of the design where parallelism is intended.
    pub fn build(params: TableParams, epoch: u64) -> PowTable {
        let cache = cache_for(params, epoch);
        Self::build_with_cache(&cache, params, epoch)
    }

    pub fn build_with_cache(cache: &PowCache, params: TableParams, epoch: u64) -> PowTable {
        let n = table_size(params, epoch);
        let mut data = vec![0u8; n as usize * POW_ELEMENT_SIZE];

        let threads = std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1)
            .max(1);
        let per_thread = (n as usize).div_ceil(threads).max(1);

        std::thread::scope(|s| {
            for (chunk_index, chunk) in data.chunks_mut(per_thread * POW_ELEMENT_SIZE).enumerate() {
                let cache = &*cache;
                s.spawn(move || {
                    let base = chunk_index * per_thread;
                    for k in 0..chunk.len() / POW_ELEMENT_SIZE {
                        let e = element(cache, (base + k) as u32);
                        chunk[k * POW_ELEMENT_SIZE..(k + 1) * POW_ELEMENT_SIZE]
                            .copy_from_slice(e.as_bytes());
                    }
                });
            }
        });

        PowTable { epoch, n, data }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> u32 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Memory footprint, in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn get(&self, i: u32) -> &[u8] {
        let start = i as usize * POW_ELEMENT_SIZE;
        &self.data[start..start + POW_ELEMENT_SIZE]
    }
}

/// Starting point of an attempt: hash of the full header, nonce included.
#[inline]
fn seed_of_header(header: &BlockHeader) -> Hash256 {
    tagged_hash_parts(TAG_SEED, &[&header.encode()])
}

/// SplitMix64 finalizer: a 64-bit bijection where every output bit depends on
/// every input bit. Three shifts, two multiplications.
#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Derives the index of the next access from the current accumulator.
///
/// Creates the sequential dependency: impossible to know where to read next
/// before having integrated the previous read.
///
/// All **four** words of the state enter the index. The version that read only
/// the low word made the whole walk a function of 32 bits: see the module
/// header note. The most significant bits of the mix are kept: they are the
/// ones the multiplications stirred best.
#[inline]
fn index_from(acc: &U256, n: u32) -> u32 {
    let m = mix64(
        acc.0[0] ^ acc.0[1].rotate_left(17) ^ acc.0[2].rotate_left(34) ^ acc.0[3].rotate_left(51),
    );
    ((m >> 32) as u32) % n
}

/// Integrates a read into the state, then diffuses over the full width.
///
/// The addition modulo 2^256 keeps the carry chain. Four Feistel rounds over
/// the four words follow, two words modified per round from two words left
/// intact: each round is a bijection by construction, and the two operations
/// of a round are independent, so the processor executes them side by side.
/// After the fourth round, each output word depends on each of the four input
/// words: that is what was missing. The state stays uniformly distributed, and
/// two distinct states cannot merge other than through a collision of the read
/// itself. About fifteen nanoseconds of latency, for a DRAM read that costs a
/// hundred.
#[inline]
fn absorb(acc: U256, read_value: U256) -> U256 {
    let mut s = acc.wrapping_add(read_value).0;
    s[1] ^= mix64(s[0]);
    s[3] ^= mix64(s[2]);
    s[0] ^= mix64(s[3]);
    s[2] ^= mix64(s[1]);
    s[1] ^= mix64(s[0]);
    s[3] ^= mix64(s[2]);
    s[0] ^= mix64(s[1]);
    s[2] ^= mix64(s[3]);
    U256(s)
}

/// Mixing loop.
///
/// # Why it does not hash at every access
///
/// The first version of this file hashed at every iteration. The benchmark gave
/// its verdict: only a **1.63x** advantage for the miner holding the table.
/// The reason invalidates the design: a hash costs about as much as a random
/// DRAM access. Recomputing an element instead of reading it therefore cost
/// almost nothing, and memory was not the bottleneck: the anti-ASIC promise
/// was empty.
///
/// The loop does only one addition modulo 2^256 and a diffusion of a few
/// nanoseconds per access ([`absorb`]). The cost of an iteration stays that of
/// the memory read, and almost nothing else.
///
/// The hash now comes in only at the two ends, as in Autolykos v2: once to
/// unroll the seed, once to produce the value compared to the target.
#[inline]
fn mix(start: Hash256, mut read: impl FnMut(u32) -> U256, n: u32) -> Hash256 {
    let mut acc = U256::from_be_bytes(start.as_bytes());
    for _ in 0..POW_K {
        let idx = index_from(&acc, n);
        acc = absorb(acc, read(idx));
    }
    tagged_hash_parts(TAG_FINAL, &[&acc.to_be_bytes()])
}

/// Mining path: reads the precomputed table.
pub fn hash_mining(header: &BlockHeader, table: &PowTable) -> Hash256 {
    let start = seed_of_header(header);
    mix(
        start,
        |i| {
            let mut b = [0u8; 32];
            b.copy_from_slice(table.get(i));
            U256::from_be_bytes(&b)
        },
        table.n,
    )
}

/// Miner holding only a **fraction** of the table.
///
/// # Why this type exists
///
/// Comparing "full table" with "no table" says almost nothing. No circuit
/// designer picks either of those two extremes: they pick the amount of memory
/// that maximizes their throughput per euro spent. The relevant question is
/// therefore the **curve**: how much does an attempt cost when one holds only
/// a fraction `f` of the table, recomputing the rest?
///
/// Access indices are uniform over `[0, n)`. Keeping the first `f * n`
/// elements therefore gives a hit rate of `f`, whatever subset the attacker
/// actually chooses: no element is more useful than another.
///
/// This type is not part of consensus. It exists only for measurement.
pub struct PartialTable {
    epoch: u64,
    n: u32,
    /// Number of elements actually stored, out of the `n`.
    n_stored: u32,
    cache: std::sync::Arc<PowCache>,
    data: Vec<u8>,
}

impl PartialTable {
    /// Builds a partial table holding `num/den` of the elements.
    ///
    /// `num = 0` models the attacker without memory, `num = den` the fully
    /// equipped miner.
    pub fn build(params: TableParams, epoch: u64, num: u32, den: u32) -> PartialTable {
        assert!(den > 0 && num <= den, "invalid fraction: {num}/{den}");
        let n = table_size(params, epoch);
        let cache = cache_for(params, epoch);
        let n_stored = ((n as u64 * num as u64) / den as u64) as u32;

        let mut data = vec![0u8; n_stored as usize * POW_ELEMENT_SIZE];
        {
            let cache = &*cache;
            let threads = std::thread::available_parallelism()
                .map(|v| v.get())
                .unwrap_or(1)
                .max(1);
            let per_thread = (n_stored as usize).div_ceil(threads).max(1);
            std::thread::scope(|s| {
                for (chunk_index, chunk) in
                    data.chunks_mut(per_thread * POW_ELEMENT_SIZE).enumerate()
                {
                    s.spawn(move || {
                        let base = chunk_index * per_thread;
                        for k in 0..chunk.len() / POW_ELEMENT_SIZE {
                            let e = element(cache, (base + k) as u32);
                            chunk[k * POW_ELEMENT_SIZE..(k + 1) * POW_ELEMENT_SIZE]
                                .copy_from_slice(e.as_bytes());
                        }
                    });
                }
            });
        }
        PartialTable {
            epoch,
            n,
            n_stored,
            cache,
            data,
        }
    }

    /// Takes over an already built full table, without rebuilding it.
    ///
    /// The benchmark sweeps several fractions; rebuilding 2 GiB at each point
    /// would cost hours for nothing.
    pub fn from_table(table: PowTable, cache: std::sync::Arc<PowCache>) -> PartialTable {
        PartialTable {
            epoch: table.epoch,
            n: table.n,
            n_stored: table.n,
            cache,
            data: table.data,
        }
    }

    /// Reduces the share of the table held, without freeing or reallocating.
    ///
    /// The elements beyond the limit will be recomputed on the fly: that is
    /// exactly the behavior of a miner that chose less memory.
    pub fn restrict(&mut self, num: u32, den: u32) {
        assert!(den > 0 && num <= den, "invalid fraction: {num}/{den}");
        self.n_stored = ((self.n as u64 * num as u64) / den as u64) as u32;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> u32 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Elements actually kept in memory.
    pub fn stored(&self) -> u32 {
        self.n_stored
    }

    /// Memory actually required by the strategy, not memory allocated.
    pub fn memory_bytes(&self) -> usize {
        self.n_stored as usize * POW_ELEMENT_SIZE
    }

    #[inline]
    fn read(&self, i: u32) -> U256 {
        if i < self.n_stored {
            let start = i as usize * POW_ELEMENT_SIZE;
            let mut b = [0u8; 32];
            b.copy_from_slice(&self.data[start..start + POW_ELEMENT_SIZE]);
            U256::from_be_bytes(&b)
        } else {
            U256::from_be_bytes(element(&self.cache, i).as_bytes())
        }
    }
}

/// Mining attempt with a partial table.
///
/// Returns exactly the same value as [`hash_mining`] and [`hash_verify`]: the
/// attacker's strategy changes its cost, never its result. That is precisely
/// what makes the attack possible, and therefore what must be measured.
pub fn hash_mining_partial(header: &BlockHeader, table: &PartialTable) -> Hash256 {
    let start = seed_of_header(header);
    mix(start, |i| table.read(i), table.n)
}

/// Verification path: recomputes the [`POW_K`] needed elements.
///
/// No table, no significant allocation. This is what a full node does, and it
/// is what costs a lot to a miner that would like to do without the table.
pub fn hash_verify(header: &BlockHeader, params: TableParams) -> Hash256 {
    let epoch = epoch_of(header.height);
    let cache = cache_for(params, epoch);
    hash_verify_with_cache(header, params, &cache)
}

/// Variant for whoever already holds the cache: that is the case of a node
/// that is syncing, which verifies thousands of blocks of the same epoch.
pub fn hash_verify_with_cache(
    header: &BlockHeader,
    params: TableParams,
    cache: &PowCache,
) -> Hash256 {
    // A cache from another epoch gives a different hash **silently**. Two
    // nodes, one with the right cache and the other with a stale cache, would
    // return two opposite verdicts on the same block: a split whose cause
    // nobody would see. The phase 8b audit measured it:
    // "height 51200, cache e0 == cache e1 ? false".
    //
    // We do not guess: if the cache does not match, we build a correct one.
    let epoch = epoch_of(header.height);
    if cache.epoch() != epoch {
        return hash_verify(header, params);
    }
    let n = table_size(params, epoch);
    let start = seed_of_header(header);
    mix(
        start,
        |i| U256::from_be_bytes(element(cache, i).as_bytes()),
        n,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;

    fn params() -> TableParams {
        TableParams::for_network(Network::Regtest)
    }

    fn header(nonce: u64, height: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256([7u8; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([9u8; 32]),
            time: 1_755_000_000,
            bits: INITIAL_BITS,
            height,
            nonce,
        }
    }

    /// The property that makes the protocol usable by light nodes.
    #[test]
    fn both_paths_give_same_result() {
        let p = params();
        let table = PowTable::build(p, 0);
        for nonce in 0..50u64 {
            let h = header(nonce, 10);
            assert_eq!(
                hash_mining(&h, &table),
                hash_verify(&h, p),
                "mining/verification divergence at nonce {nonce}"
            );
        }
    }

    #[test]
    fn both_paths_agree_over_several_epochs() {
        let p = params();
        for epoch in 0..3u64 {
            let table = PowTable::build(p, epoch);
            let h = header(42, epoch * POW_EPOCH_BLOCKS + 5);
            assert_eq!(hash_mining(&h, &table), hash_verify(&h, p));
        }
    }

    #[test]
    fn table_grows_then_caps() {
        let p = params();
        let t0 = table_size(p, 0);
        let t1 = table_size(p, 1);
        let t10 = table_size(p, 10);

        assert_eq!(t0, p.n0);
        assert!(t1 > t0, "the table must grow");
        assert!(t10 > t1);
        assert_eq!(table_size(p, 10_000), p.nmax, "growth must eventually cap");
    }

    #[test]
    fn growth_is_five_percent() {
        let p = TableParams::for_network(Network::Mainnet);
        let expected = (p.n0 as u64) * 105 / 100;
        assert_eq!(table_size(p, 1) as u64, expected);
    }

    /// This test turns the anti-ASIC promise into a checkable property.
    #[test]
    fn changing_epoch_changes_whole_table() {
        let p = params();
        let a = PowTable::build(p, 0);
        let b = PowTable::build(p, 1);
        // Even elements with the same index differ: the seed changed.
        assert_ne!(a.get(0), b.get(0));
        assert_ne!(a.get(5), b.get(5));
        assert!(b.len() > a.len(), "and the table grew");
    }

    #[test]
    fn different_nonce_gives_different_hash() {
        let p = params();
        let table = PowTable::build(p, 0);
        let a = hash_mining(&header(0, 1), &table);
        let b = hash_mining(&header(1, 1), &table);
        assert_ne!(a, b);
    }

    #[test]
    fn height_takes_part_in_hash() {
        let p = params();
        // Two heights of the same epoch: only the header changes.
        assert_ne!(hash_verify(&header(0, 1), p), hash_verify(&header(0, 2), p));
    }

    #[test]
    fn networks_do_not_share_memory_difficulty() {
        let r = TableParams::for_network(Network::Regtest);
        let t = TableParams::for_network(Network::Testnet);
        let m = TableParams::for_network(Network::Mainnet);
        assert!(r.n0 < t.n0);
        assert!(t.n0 < m.n0);
    }

    #[test]
    fn mainnet_table_weighs_two_gib() {
        let p = TableParams::for_network(Network::Mainnet);
        let bytes = p.n0 as u64 * POW_ELEMENT_SIZE as u64;
        assert_eq!(bytes, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn memory_footprint_is_as_announced() {
        let p = params();
        let t = PowTable::build(p, 0);
        assert_eq!(t.memory_bytes(), t.len() as usize * POW_ELEMENT_SIZE);
        assert_eq!(t.memory_bytes(), 32 * 1024);
    }

    #[test]
    fn computation_is_deterministic() {
        let p = params();
        let h = header(123, 456);
        assert_eq!(hash_verify(&h, p), hash_verify(&h, p));
    }

    /// Locks in the property that justifies this whole module.
    ///
    /// This test would have caught the initial design error. The first version
    /// hashed at every access: the ratio fell to 1.63x, which means a miner
    /// could do without memory for almost nothing: the anti-ASIC promise was
    /// empty. With a cheap mix, the ratio goes back up beyond 6x.
    ///
    /// The threshold is deliberately low: the measurement varies by machine,
    /// and a flaky test would be worse than no test. What it locks in is the
    /// order of magnitude.
    #[test]
    fn doing_without_table_costs_significantly_more() {
        let p = params();
        let table = PowTable::build(p, 0);
        let n = 3_000u64;

        // Warm-up: without it, the first loop pays for the cache misses.
        for nonce in 0..200 {
            std::hint::black_box(hash_mining(&header(nonce, 1), &table));
            std::hint::black_box(hash_verify(&header(nonce, 1), p));
        }

        let t0 = std::time::Instant::now();
        for nonce in 0..n {
            std::hint::black_box(hash_mining(&header(nonce, 1), &table));
        }
        let with_table = t0.elapsed().as_secs_f64();

        let t1 = std::time::Instant::now();
        for nonce in 0..n {
            std::hint::black_box(hash_verify(&header(nonce, 1), p));
        }
        let without_table = t1.elapsed().as_secs_f64();

        let ratio = without_table / with_table.max(1e-9);
        assert!(
            ratio > 10.0,
            "mining without the table costs only {ratio:.2} x more: element \
             derivation has become too cheap again"
        );
    }

    /// The partial table must change nothing in the result, whatever the
    /// fraction held. Without this property, the measurement of the time-memory
    /// trade-off would not measure the same function.
    #[test]
    fn partial_table_gives_same_hash() {
        let p = params();
        let full = PowTable::build(p, 0);
        for (num, den) in [(0, 1), (1, 4), (1, 2), (3, 4), (1, 1)] {
            let partial = PartialTable::build(p, 0, num, den);
            for nonce in 0..25u64 {
                let h = header(nonce, 10);
                assert_eq!(
                    hash_mining_partial(&h, &partial),
                    hash_mining(&h, &full),
                    "divergence at {num}/{den}, nonce {nonce}"
                );
            }
        }
    }

    #[test]
    fn partial_table_memory_follows_fraction() {
        let p = params();
        let n = table_size(p, 0);
        assert_eq!(PartialTable::build(p, 0, 0, 4).stored(), 0);
        assert_eq!(PartialTable::build(p, 0, 1, 4).stored(), n / 4);
        assert_eq!(PartialTable::build(p, 0, 4, 4).stored(), n);
        assert_eq!(
            PartialTable::build(p, 0, 1, 2).memory_bytes(),
            (n / 2) as usize * POW_ELEMENT_SIZE
        );
    }

    /// The property phase 6 had to rebuild.
    ///
    /// Computing a table element must cost much more than reading it. In the
    /// first design, it was a single hash, and that is exactly why doing
    /// without memory cost only 2.86x on the real 2 GiB table.
    #[test]
    fn computing_element_costs_much_more_than_reading_it() {
        let p = params();
        let table = PowTable::build(p, 0);
        let cache = cache_for(p, 0);
        let n = 20_000u32;

        for i in 0..1_000 {
            std::hint::black_box(element(&cache, i % table.len()));
        }

        let t0 = std::time::Instant::now();
        for i in 0..n {
            std::hint::black_box(element(&cache, i % table.len()));
        }
        let compute_time = t0.elapsed().as_secs_f64() / f64::from(n);

        let t1 = std::time::Instant::now();
        for i in 0..n {
            std::hint::black_box(table.get(i % table.len()));
        }
        let read_time = t1.elapsed().as_secs_f64() / f64::from(n);

        let ratio = compute_time / read_time.max(1e-12);
        assert!(
            ratio > 10.0,
            "recomputing an element costs only {ratio:.1} x its read: \
             derivation is too cheap and the time-memory trade-off \
             becomes favorable to the attacker again"
        );
    }

    /// The walk through memory no longer depends on a short substate.
    ///
    /// # The defect this test pins down
    ///
    /// The read index came from the low 32 bits of the accumulator, and the
    /// addition never propagated a carry into them: two states differing only
    /// in their upper 224 bits read exactly the same addresses, in the same
    /// order, and the sum of the reads was the same. A table of 2^32 sums
    /// (128 GiB) per epoch then replaced the thirty-two dependent reads with a
    /// single one.
    ///
    /// We replay a thousand pairs of states with the same low bits; none must
    /// share its walk.
    #[test]
    fn states_with_same_low_bits_do_not_walk_same_addresses() {
        fn walk(start: U256, n: u32) -> Vec<u32> {
            let mut acc = start;
            let mut v = Vec::with_capacity(POW_K);
            for _ in 0..POW_K {
                let idx = index_from(&acc, n);
                v.push(idx);
                // A synthetic "table": the element depends only on its index,
                // like a real table.
                let read_value = U256::from_be_bytes(
                    tagged_hash_parts("Q21/test/elem", &[&idx.to_le_bytes()]).as_bytes(),
                );
                acc = absorb(acc, read_value);
            }
            v
        }
        let n = 1u32 << 26;
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed = mix64(seed.wrapping_add(0x1234_5678_9ABC_DEF1));
            seed
        };
        let mut identical = 0;
        for _ in 0..1000 {
            let low = next() & 0xFFFF_FFFF;
            let a = U256([next() << 32 | low, next(), next(), next()]);
            let b = U256([next() << 32 | low, next(), next(), next()]);
            assert_eq!(
                a.0[0] as u32, b.0[0] as u32,
                "same low word by construction"
            );
            if walk(a, n) == walk(b, n) {
                identical += 1;
            }
        }
        assert_eq!(
            identical, 0,
            "{identical} pairs out of 1000 share their walk: the walk depends on a \
             short substate"
        );
    }

    /// Every bit of the state and of the read diffuses over the full width.
    ///
    /// Flipping a single input bit of `absorb` must change about half of the
    /// 256 output bits: the avalanche criterion. We require between a quarter
    /// and three quarters for each of the 512 input bits, which rules out any
    /// independent lane: that is exactly what was missing.
    #[test]
    fn read_diffuses_over_whole_state() {
        fn weight(a: U256, b: U256) -> u32 {
            (0..4).map(|i| (a.0[i] ^ b.0[i]).count_ones()).sum()
        }
        let acc = U256([
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
            0x0F1E_2D3C_4B5A_6978,
            0x8796_A5B4_C3D2_E1F0,
        ]);
        let read_value = U256([
            0xDEAD_BEEF_CAFE_F00D,
            0x1357_9BDF_2468_ACE0,
            0x0000_0000_0000_0001,
            0xFFFF_FFFF_FFFF_FFFF,
        ]);
        let reference = absorb(acc, read_value);
        for bit in 0..512u32 {
            let (mut a, mut l) = (acc, read_value);
            if bit < 256 {
                a.0[(bit / 64) as usize] ^= 1u64 << (bit % 64);
            } else {
                let b = bit - 256;
                l.0[(b / 64) as usize] ^= 1u64 << (b % 64);
            }
            let p = weight(reference, absorb(a, l));
            assert!(
                (64..=192).contains(&p),
                "bit {bit} changes only {p} output bits out of 256"
            );
        }
    }
}
