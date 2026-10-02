//! Consensus constants.
//!
//! Everything below defines the currency. Change a single one of these numbers,
//! and two nodes are no longer on the same chain. They live here, in a single
//! file, so that an auditor can check the entirety of the economic rules
//! without reading the rest of the code.
//!
//! Absolute rule: no floating point. Anywhere. See `emission`.

// ---------------------------------------------------------------------------
// Units
// ---------------------------------------------------------------------------

/// Number of decimals of the currency.
pub const DECIMALS: u32 = 8;

/// Number of indivisible units in one whole Q21.
pub const UNITS_PER_COIN: u64 = 100_000_000;

/// Absolute cap, in whole Q21. This number is the project.
pub const MAX_SUPPLY_COINS: u64 = 21_000_001;

/// Absolute cap, in indivisible units.
///
/// 21_000_001 * 1e8 = 2.1e15, far below u64::MAX (1.8e19).
pub const MAX_SUPPLY: u64 = MAX_SUPPLY_COINS * UNITS_PER_COIN;

/// The genesis coin: the unit beyond the 21,000,000.
///
/// Minted only once in block 0, outside the ordinary coinbase. It does not take
/// part in the emission schedule.
pub const GENESIS_PREMINT: u64 = UNITS_PER_COIN;

/// What mining can issue in total, excluding the genesis coin.
pub const EMISSION_CAP: u64 = MAX_SUPPLY - GENESIS_PREMINT;

// ---------------------------------------------------------------------------
// Pace
// ---------------------------------------------------------------------------

/// Target block interval, in seconds.
///
/// PROVISIONAL. Two minutes divide the variance by five compared to Bitcoin,
/// but increase the orphan rate, all the more since ML-DSA signatures weigh 47
/// times an ECDSA signature. To be confirmed by measurement on testnet, not by
/// reasoning.
pub const TARGET_BLOCK_SECS: u64 = 120;

/// Blocks per year at the target pace (525,600 minutes / 2).
pub const BLOCKS_PER_YEAR: u64 = 262_800;

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Initial reward, in indivisible units: 13.82743055 Q21.
///
/// # How this value was obtained, and why the first one was wrong
///
/// The naive derivation starts from *continuous* decay:
/// `R0 = CAP * ln(2) / half_life`, which gives 13.847118 Q21. That is wrong
/// here.
///
/// Q21 does not decay continuously: the reward stays **constant for a whole
/// epoch** of 4,320 blocks, then drops at once. Over each epoch we therefore
/// pay the value at the start of the epoch, higher than the average of the
/// continuous curve. It is a left Riemann sum, and it overestimates. The gap
/// looks negligible (0.14%) but it puts the theoretical infinite sum at
/// 21,029,899 Q21, that is **above the cap**.
///
/// The actual emission would still have stayed under 21 million, because
/// rounding down erodes the curve at every epoch. Relying on that would mean
/// depending on an arithmetic accident rather than a guarantee.
///
/// The chosen value is therefore bounded by construction:
///
/// ```text
/// R0 = floor( CAP * (DEN - NUM) / (DEN * EPOCH) )
/// ```
///
/// which guarantees `R0 * EPOCH * DEN / (DEN - NUM) <= EMISSION_CAP`: the
/// infinite sum of the discrete geometric series, even before any rounding,
/// holds below the cap. Checked by
/// `emission::tests::initial_reward_respects_cap`.
pub const INITIAL_REWARD: u64 = 1_382_743_055;

/// Length of a decay epoch, in blocks (~6 days).
pub const DECAY_EPOCH_BLOCKS: u64 = 4_320;

/// Decay factor per epoch, expressed as an integer fraction.
///
/// 99_715_550 / 100_000_000 = 0.9971555 per epoch, that is a half-life of
/// 243.33 epochs ~ 4 years. We store a numerator and a denominator, never a
/// float: `reward * NUM / DEN` in u128 is bit-for-bit reproducible on every
/// platform, `reward * 0.9971555` is not.
pub const DECAY_NUM: u128 = 99_715_550;
pub const DECAY_DEN: u128 = 100_000_000;

/// Length of the slow start, in blocks (~28 days).
///
/// Over this interval the reward rises linearly from zero. Without it, the few
/// miners present in the first week would capture a disproportionate share of
/// the total supply.
pub const SLOW_START_BLOCKS: u64 = 20_000;

/// Block reward floor, in units: 0.01 Q21.
///
/// # The defect this floor repairs
///
/// Geometric decay truncated to the integer never reaches the cap. Computed on
/// the actual trajectory: the reward fell below the indivisible unit at year
/// 91, and **137,899 Q21 out of 21,000,001 would never be created**. The number
/// engraved in the project's name would have been an asymptote, not a promise.
///
/// # What the floor changes
///
/// The base reward of an epoch is now
/// `max(geometric decay, TAIL_REWARD)`, and the cumulative emission is clipped
/// **exactly** at [`EMISSION_CAP`]: the last issuing block receives the
/// remainder, then nothing more, forever. Every unit of the cap therefore ends
/// up existing: `emission::block_subsidy` applies the rule, and a test checks
/// the exact equality.
///
/// # Why 0.01 Q21
///
/// Small enough to change nothing in the first half-century: the geometric
/// reward only falls below this floor around year 42, when more than 99% of
/// the cap has already been issued. Large enough for the end to come on a
/// human rather than geological time scale: the remainder runs out in a few
/// decades of tail, whereas a floor of one indivisible unit would have spread
/// the same sum over tens of thousands of years. And throughout the tail, a
/// miner earns a predictable floor subsidy income, on top of fees.
pub const TAIL_REWARD: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Number of blocks before a block reward becomes spendable.
///
/// Protects against reorgs: a coinbase spent then orphaned would invalidate
/// the whole chain of transactions descending from it. Bitcoin uses 100
/// blocks, about 16 hours. Since Q21 mines five times faster, we use 200 blocks
/// to keep a delay of the same order (about 6 h 40) rather than copying the
/// number without thinking about what it protects.
pub const COINBASE_MATURITY: u64 = 200;

/// Tolerance on a timestamp in the future, in seconds.
///
/// Beyond it, the block is rejected.
///
/// # Why it is not two hours, unlike Bitcoin
///
/// Bitcoin can afford two hours because its difficulty only moves every 2,016
/// blocks: a single timestamp weighs almost nothing there. Q21 adjusts **at
/// every block** over a window of 90: the same tolerance becomes a lever.
///
/// The phase 8b audit measured that a miner holding 20% of the hashrate and
/// writing timestamps two hours in the future made the difficulty drop by 70%,
/// and by 97% with a variant. The threshold of total collapse was at 20.7% of
/// the hashrate.
///
/// Ten minutes are more than enough to absorb the clock drift of an ordinary
/// machine (common systems synchronize to the second) and shrink the surface
/// of this attack by a factor of twelve. The bound used to be twenty minutes;
/// half is enough, and every minute of tolerance is a minute of leverage. The
/// main defense, however, remains the **signed** and **asymmetric** solve time
/// of `next_bits`, not this bound.
pub const MAX_FUTURE_TIME: u64 = 10 * 60;

/// Upper bound of the solve time in LWMA: an interval never counts for more
/// than this multiple of the target, however long it looks.
///
/// # Why it is lower than the bound on lag
///
/// With a symmetric bound at 6T, a miner writing `parent + 6T` injected 6T;
/// the next honest block, constrained by the median, removed only part of it:
/// a positive balance remained, hence a difficulty drop, hence accelerated
/// emission: 33% more blocks for half of the hashrate. With 4T ahead and 6T
/// behind, the honest block removes more than the attacker injected: the
/// manipulation **raises** the difficulty, and a rational miner gains nothing
/// from it. Measured by the `a1` test: no strategy lowers the difficulty
/// anymore.
///
/// The price for the honest network: after a sudden drop in hashrate, a real
/// interval of ten minutes only counts for eight; the difficulty comes down a
/// little more slowly. Over a 90-block window, that is negligible.
pub const LWMA_MAX_AHEAD: u64 = 4;

/// Lower bound of the solve time in LWMA, in multiples of the target: a
/// timestamp moved backward never removes more than this.
pub const LWMA_MAX_BEHIND: u64 = 6;

/// Size of the median time past window.
///
/// A block's timestamp must be strictly greater than the median of the `N`
/// previous ones. A median resists manipulation by a single miner, whereas an
/// average can be pulled.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Maximum size of a serialized block, in bytes.
///
/// PROVISIONAL, and the figure is explained in section 7 of the white paper:
/// an ML-DSA-65 signature weighs 3,309 bytes against 71 for ECDSA. Using 1 MB
/// like Bitcoin would limit a block to about 300 transactions. The final value
/// will be set from the orphan rate measurements of phase 6.
pub const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Minimum serialized size of a transaction, excluding the witness, in bytes.
///
/// A transaction with one input and one output weighs:
/// version(4) + varint(1) + outpoint(36) + sequence(4) + varint(1)
/// + output(8 + 1 + 32) + lock_time(8) = 95 bytes.
///
/// We use 64, knowingly below the real minimum: this constant only serves to
/// **bound** allocations, and a bound that is too generous stays safe whereas
/// a bound that is too tight would refuse a legitimate block.
pub const MIN_TX_SIZE: usize = 64;

/// Maximum number of transactions a block can contain.
///
/// Derived from [`MAX_BLOCK_SIZE`] rather than chosen: a block cannot contain
/// more transactions than its size allows. The previous value (500,000, set by
/// hand) let a three-megabyte compact announcement trigger an allocation of
/// several tens of megabytes. The ratio between what an adversary sends and
/// what it makes us allocate must stay bounded, and small.
pub const MAX_TX_PER_BLOCK: usize = MAX_BLOCK_SIZE / MIN_TX_SIZE;

/// Weight targeted by the miner when assembling a block.
///
/// This is not a consensus rule but a policy: a lighter block propagates
/// faster and gets orphaned less. It is published here because the mempool
/// must align with it: accepting a transaction that no miner will select
/// amounts to offering space to someone who will never pay.
pub const TARGET_BLOCK_WEIGHT: u64 = 2_000_000;

/// Weighting of non-witness data in the weight computation.
///
/// This implements the *witness discount*: the body of a transaction counts
/// four times, the witness only once. Without it, the weight of a Q21
/// transaction would be almost entirely dictated by its post-quantum
/// signature.
pub const WITNESS_DISCOUNT: u64 = 4;

/// Weight added to a transaction for **each output it creates**.
///
/// # What this prices
///
/// An output does not only cost its 41 bytes on the wire: it enters the UTXO
/// set of every node, in RAM, and stays there as long as it is not spent,
/// potentially forever. A witness byte, by contrast, is forgotten as soon as
/// the block is buried. Pricing both the same amounted to offering the
/// scarcest resource of the network at the price of the most abundant one: a
/// block full of tiny outputs cost a few hundred units and imposed twenty
/// gigabytes per day on every node.
///
/// Four hundred weight units is the equivalent of about a hundred bytes of
/// skeleton: creating an output now costs more than carrying it. This is not a
/// consensus rule but a relay and assembly policy; the consensus rule that
/// protects miners from themselves is [`MIN_OUTPUT_VALUE`].
pub const WEIGHT_PER_OUTPUT: u64 = 400;

/// Minimum value of an output, in units: **dust** is refused.
///
/// # Why it is a consensus rule, and not only a relay rule
///
/// Bitcoin refuses dust at relay only. Here, the rule must also hold against a
/// miner that would fill its own blocks: the fees it pays come back to it, so
/// no pricing slows it down. What slows it down is locked-up capital: at
/// 10,000 units per output, sixty million outputs (one day of full blocks)
/// lock up six thousand Q21, at a time when the whole network issues ten
/// thousand per day. And those units are not lost to it: consolidating them
/// afterwards costs it fees and time, which is exactly the price we wanted to
/// charge.
///
/// 10,000 units = 0.0001 Q21. A smaller legitimate payment makes no sense: it
/// would not cover the fee of its own spend.
///
/// Genesis is exempt: its coinbase carries the unit that takes the cap from
/// 21,000,000 to 21,000,001, and that unit is unspendable.
pub const MIN_OUTPUT_VALUE: u64 = 10_000;

// ---------------------------------------------------------------------------
// Difficulty
// ---------------------------------------------------------------------------

/// Window of the LWMA difficulty adjustment, in blocks.
///
/// An adjustment at every block over a weighted moving average, and not every
/// 2,016 blocks like Bitcoin. A small chain whose hashrate doubles or vanishes
/// in a day cannot wait two weeks: it would be killed by the first farm that
/// comes and goes.
pub const LWMA_WINDOW: usize = 90;

/// Initial difficulty target, in compact form.
///
/// Deliberately permissive: at block 1, the network has one machine.
pub const INITIAL_BITS: u32 = 0x2000_ffff;

/// Maximum factor of target change between two blocks.
///
/// Bounds the oscillations a miner could cause by manipulating timestamps
/// within the allowed window.
pub const MAX_TARGET_CHANGE: u64 = 4;

// ---------------------------------------------------------------------------
// Memory-hard proof of work
// ---------------------------------------------------------------------------

/// Number of table accesses per mining attempt.
///
/// These accesses are **sequentially dependent**: the index of the next one is
/// derived from the result of the previous one. Within an attempt, nothing can
/// be prefetched or parallelized.
///
/// What this protects, stated exactly: a circuit does not parallelize *one*
/// attempt, but it interleaves thousands of them, like any miner. The quantity
/// that then bounds throughput is not the latency of an access but **memory
/// bandwidth** and the capacity to hold the table: the same as for Ethash, and
/// the only ones a circuit buys at the same price as everyone else. A first
/// draft spoke of latency "on which nobody has a decisive advantage"; that was
/// stronger than what the construction guarantees, and ASIC resistance remains
/// a hypothesis until the proof of work has received external cryptanalysis.
pub const POW_K: usize = 32;

/// Size of a table element, in bytes.
pub const POW_ELEMENT_SIZE: usize = 32;

/// Length of a proof of work epoch, in blocks (~71 days at 2 min).
///
/// At each epoch, the seed changes and the table grows.
pub const POW_EPOCH_BLOCKS: u64 = 51_200;

/// Table growth per epoch, in percent.
///
/// This is the central mechanism of lever A of the white paper. A circuit
/// designed around a fixed amount of memory becomes mediocre as soon as the
/// table exceeds it. Dedicated hardware therefore becomes obsolete on its own,
/// without having to call for a defensive hard fork every six months, which
/// Monero had to inflict on itself four times between 2018 and 2019.
pub const POW_TABLE_GROWTH_PCT: u64 = 5;

/// Initial number of table elements, per network.
///
/// Mainnet: 2^26 elements x 32 B = 2 GiB. Chosen to fit on a consumer machine
/// while forcing a dedicated circuit to carry DRAM.
pub const POW_TABLE_N0_MAINNET: u32 = 1 << 26;
pub const POW_TABLE_N0_TESTNET: u32 = 1 << 20; // 32 MiB
pub const POW_TABLE_N0_REGTEST: u32 = 1 << 10; // 32 KiB

/// Table growth cap, per network.
///
/// Mainnet: 2^27 elements x 32 B = **4 GiB**, reached at the fifteenth epoch,
/// around the third year. The cap used to be 8 GiB; the promise "mineable by
/// everyone" brought it down to 4. A Raspberry Pi 5 has 8 GB in total, a
/// common laptop 8 or 16: an 8 GiB table excluded them around the sixth year,
/// for a marginal gain against dedicated hardware, which buys memory at will.
/// The table must weigh on silicon, not on individuals. To be reassessed in
/// five years, when 16 GB will be the low end.
pub const POW_TABLE_NMAX_MAINNET: u32 = 1 << 27; // 4 GiB, reached around year 3
pub const POW_TABLE_NMAX_TESTNET: u32 = 1 << 22;
pub const POW_TABLE_NMAX_REGTEST: u32 = 1 << 12;

// ---------------------------------------------------------------------------
// The cache: level 1 of the proof of work
// ---------------------------------------------------------------------------
//
// The first design derived each table element by an independent hash. The
// phase 6 benchmark, on the real 2 GiB table, gave its verdict: doing without
// memory entirely cost only **2.86x**, and beyond 256 MiB memory bought
// nothing at all. A dedicated circuit whose hash is three times faster than a
// processor therefore had an incentive to carry no DRAM at all: the anti-ASIC
// promise was false.
//
// The fix takes Ethash's two-level structure: a sequentially generated cache,
// and table elements that can only be computed by walking that cache.
// Recomputing an element stops being cheap.

/// Ratio between the table (level 2) and the cache (level 1).
///
/// Mainnet: 2 GiB table, 64 MiB cache. The cache is what a verifying node must
/// hold, as well as a miner that refuses the table.
pub const POW_CACHE_RATIO: u32 = 32;

/// Cache accesses needed to compute **one** table element.
///
/// This is the penalty factor imposed on whoever refuses the table: an
/// equipped miner pays one read where a miner without the table pays
/// [`POW_J`]. It is also the factor that multiplies the required memory
/// bandwidth: the only quantity a dedicated circuit cannot get around with
/// silicon.
pub const POW_J: usize = 256;

/// Mixing passes during cache construction.
///
/// The cache is generated as a chain: element `i` depends on element `i-1`.
/// The extra passes (RandMemoHash, Lerner 2014, like Ethash) prevent rebuilding
/// a fragment of the cache without rebuilding everything that precedes it.
pub const POW_CACHE_ROUNDS: usize = 3;

// ---------------------------------------------------------------------------
// Defense against deep reorgs
// ---------------------------------------------------------------------------

/// Maximum depth of an accepted reorg.
///
/// # What this rule does, and what it costs
///
/// Beyond this depth, a node refuses to switch to a competing chain even if it
/// carries more work. A transaction buried under that many blocks therefore
/// becomes irreversible for that node: this is rolling finality.
///
/// It is **not** free, and claiming otherwise would be dishonest. This rule
/// does not remove the 51% attack, it changes its nature: a majority attacker
/// can no longer rewrite old history, but a network partition lasting more
/// than `MAX_REORG_DEPTH` blocks produces two chains that will never reconcile
/// on their own. We trade a rewrite risk for a split risk.
///
/// The trade-off is chosen because a split is visible, diagnosable and
/// repairable by human intervention, whereas a deep rewrite is silent and
/// robs people.
///
/// 720 blocks at 2 minutes = 24 hours.
pub const MAX_REORG_DEPTH: u64 = 720;

/// Depth beyond which a fork must show excess work.
///
/// Between this depth and [`MAX_REORG_DEPTH`], a competing chain is accepted
/// only if its cumulative work exceeds that of the current chain by a margin
/// that grows with the depth of the fork. Reorganizing becomes more and more
/// expensive the further back one goes, instead of being free as soon as one
/// is a tip ahead.
pub const REORG_PENALTY_FROM_DEPTH: u64 = 6;

/// Percentage of extra work required per block of depth, beyond
/// [`REORG_PENALTY_FROM_DEPTH`].
pub const REORG_PENALTY_PCT_PER_BLOCK: u64 = 1;

/// Cap of the surcharge, as a percentage of the work produced since the fork.
///
/// # Why a cap
///
/// Without it, the surcharge reached 100% at depth 106 and more than 700% at
/// the maximum depth. An ordinary network partition (two countries, two
/// providers) mining at equal hashrate on both sides then became **permanent
/// within two hours** (simulation: last possible reunification at 66 blocks
/// in the median for a 50% minority, 153 blocks for a 40% minority), whereas
/// the documentation announced twenty-four hours. Each side saw itself
/// surcharged, and neither ever rejoined the other.
///
/// With 25%, any majority above 56% of the hashrate reunifies the network
/// within the [`MAX_REORG_DEPTH`] window, and a deep reorg by an attacker stays
/// a quarter more expensive, which, combined with the maximum depth, is enough
/// for the original goal.
pub const REORG_PENALTY_MAX_PCT: u64 = 25;

// ---------------------------------------------------------------------------
// Uncles
// ---------------------------------------------------------------------------

/// Maximum number of uncles attached to a block: **zero**, the mechanism is
/// withdrawn.
///
/// # Why it is withdrawn
///
/// An uncle's share was taken from the subsidy of the block that included it,
/// never added, so that the emission stayed exactly that of the schedule. A
/// miner that included an uncle therefore gave up a quarter of its reward to a
/// competitor without receiving anything in return: no rational miner did it,
/// and the binary's miner never did. The mechanism served only one purpose:
/// offering an attacker an extra validation surface. Three defects have
/// already been found and fixed there, including one that made a node resumed
/// from a snapshot diverge from a full node.
///
/// Making it work would require paying uncles **on top of** the subsidy, like
/// Ethereum, and therefore giving up an exactly predictable emission; that is
/// not a trade this project wants to make. At two minutes per block and with
/// compact announcements, orphan blocks are rare; paying them is not worth
/// what it costs.
///
/// The block format keeps its uncle list and its root, empty: nothing changes
/// on the wire. A block that carries uncles is refused.
pub const MAX_UNCLES: usize = 0;

/// Maximum age of an uncle, in blocks.
///
/// Beyond it, the orphan block can no longer be attached: without this bound,
/// a miner could accumulate old uncles and get paid for them all at once.
pub const MAX_UNCLE_AGE: u64 = 7;

/// Block bodies kept in memory, in number of blocks.
///
/// A node needs the **body** of a block for only two reasons: undoing a reorg,
/// and checking claimed uncles. Both are bounded, by [`MAX_REORG_DEPTH`] and
/// [`MAX_UNCLE_AGE`]. Beyond that, the body only serves to answer a peer that
/// is syncing, and the disk is enough.
///
/// Without this bound, a node kept the whole chain in RAM: a few thousand
/// blocks in development, several tens of gigabytes after a few years. The
/// margin beyond the reorg depth absorbs uncles and side branches being
/// evaluated.
pub const BODY_WINDOW: usize = MAX_REORG_DEPTH as usize + 288;

/// Block bodies kept in memory, in bytes: the second bound.
///
/// [`BODY_WINDOW`] counts blocks; a block weighs between a few hundred bytes
/// and [`MAX_BLOCK_SIZE`]. A thousand 4 MiB bodies make 4 GiB: a miner
/// producing large blocks made this store swell far beyond what a Raspberry Pi
/// or a small VPS tolerates (phase 8b red team, 2nd campaign, item 6d). So we
/// also bound in bytes: as soon as the store exceeds this budget, the oldest
/// bodies leave memory, even if they are within the block window; the disk
/// keeps them, and [`Chain::block_by_id`] reads them back from it. With
/// ordinary blocks, the block window bites first; with full blocks, this one
/// does, at 256 blocks.
///
/// One gigabyte: half of a miner's proof of work table, and enough to keep
/// eight hours of full blocks in memory.
///
/// [`Chain::block_by_id`]: crate::chain::Chain::block_by_id
pub const BODY_BUDGET_BYTES: usize = 1024 * 1024 * 1024;

/// Share of the subsidy paid to the miner of an uncle, in percent.
///
/// Lever C of the white paper: paying for the orphaned work of a poorly
/// connected miner rather than throwing it away. Without it, the big miner
/// wins the propagation races and therefore earns **more** than its share of
/// hashrate: a superlinear return that concentrates mining without anyone
/// attacking anything.
///
/// # This share is **taken from** the subsidy, not added
///
/// The first design paid this share **on top of** the subsidy, plus an
/// inclusion bonus. With at most two uncles, a block could therefore issue
/// 210% of its subsidy, and the actual maximum emission of the protocol stood
/// at **44,099,999 Q21**, for an announced cap of 21,000,001. The adversarial
/// audit of phase 8 demonstrated it with a test.
///
/// Now: `miner = subsidy - sum of uncle shares + fees`. A block issues
/// **exactly** its subsidy, whatever it contains, and the cap holds by
/// construction. The price of this fix is explicit: including an uncle costs
/// the miner what it pays out. See `AUDIT.md`.
pub const UNCLE_REWARD_PCT: u64 = 25;

// ---------------------------------------------------------------------------
// Genesis
// ---------------------------------------------------------------------------

/// Beneficiary of the genesis coin.
///
/// # Why this value is zero, and why that is a choice
///
/// This field **must be a network constant**, not a local address. A genesis
/// that depends on the wallet of whoever launches the node produces a
/// different genesis per machine, hence as many incompatible chains as
/// participants. The defect was found by actually launching two nodes: they
/// exchanged tens of thousands of blocks without ever making progress, each
/// block arriving with an unknown parent.
///
/// The chosen value is the zero hash. Nobody knows its preimage: no public key
/// can produce this hash other than through a preimage attack on SHA-256. The
/// genesis coin is therefore **permanently unspendable**.
///
/// This is not a makeshift but a stance: the figure 21,000,001 says that the
/// account is not settled, and the extra unit belongs to nobody, least of all
/// to whoever launched the chain. A founder who pre-allocates the first coin to
/// himself starts a currency without authority off on the wrong foot.
pub const GENESIS_BENEFICIARY: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Chain identifiers
// ---------------------------------------------------------------------------

/// Bech32m prefix of mainnet addresses.
pub const HRP_MAINNET: &str = "q21";

/// Bech32m prefix of testnet addresses.
pub const HRP_TESTNET: &str = "tq21";

/// Bech32m prefix of regtest.
///
/// Disposable local network, with difficulty fixed at the minimum, to develop
/// and test without waiting. Bitcoin has the same, for the same reason.
pub const HRP_REGTEST: &str = "rq21";

/// Network magic, prefix of every message of the p2p protocol.
///
/// The last byte of testnet counts its generations: `0x74` was the first
/// testnet, `0x75` is the one that followed the September 2026 review (new
/// proof of work, new signed hash, new genesis). Two generations do not talk
/// to each other: an old node sees an unknown magic and disconnects, instead of
/// exchanging blocks it would refuse.
pub const NETWORK_MAGIC_MAINNET: [u8; 4] = [0x51, 0x32, 0x31, 0x01];
pub const NETWORK_MAGIC_TESTNET: [u8; 4] = [0x51, 0x32, 0x31, 0x75];

// ---------------------------------------------------------------------------
// Invariants checked at compile time
// ---------------------------------------------------------------------------
//
// These checks are not tests: they break the build. An inconsistent consensus
// parameter must not be able to produce a binary, even if nobody runs
// `cargo test` before deploying.

const _: () = {
    assert!(MAX_SUPPLY == 2_100_000_100_000_000);
    assert!(EMISSION_CAP + GENESIS_PREMINT == MAX_SUPPLY);
    assert!(EMISSION_CAP == 21_000_000 * UNITS_PER_COIN);

    // Wide margin before overflow: no sum of legitimate amounts can approach
    // u64::MAX.
    assert!(MAX_SUPPLY < u64::MAX / 1000);

    // The reward must decrease, and not too fast.
    assert!(DECAY_NUM < DECAY_DEN);
    assert!(DECAY_NUM > DECAY_DEN / 100 * 99);

    // Fundamental guarantee: the discrete geometric sum to infinity holds
    // below the cap, even before any rounding. This line is what makes it
    // impossible to exceed 21,000,000 by mining, at any height.
    assert!(
        (INITIAL_REWARD as u128 * DECAY_EPOCH_BLOCKS as u128 * DECAY_DEN) / (DECAY_DEN - DECAY_NUM)
            <= EMISSION_CAP as u128
    );

    assert!(SLOW_START_BLOCKS > 0);
    assert!(DECAY_EPOCH_BLOCKS > 0);

    // The tail floor: strictly positive (it is what guarantees that the
    // emission reaches the cap in finite time) and far below the initial
    // reward, so that it only bites the tail of the curve and never its body.
    assert!(TAIL_REWARD > 0);
    assert!(TAIL_REWARD < INITIAL_REWARD / 1000);
};
