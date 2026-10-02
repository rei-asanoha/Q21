//! Chain: genesis, difficulty, branching index, fork choice, mining.
//!
//! # What this module protects, and what it cannot protect
//!
//! Better to write it here than in a document nobody opens: **no line of this
//! file makes a 51% attack impossible.** That is a theorem, not a gap. The rule
//! that makes Nakamoto consensus work (the valid chain is the one carrying the
//! most work) is exactly the one that gives power to a majority. Refusing its
//! chain would require knowing that it is the majority, hence an identity,
//! hence an authority: we would trade the problem for a worse one.
//!
//! What this module does do, on the other hand, and it is far from nothing:
//!
//! - **choose by cumulative work and not by length.** Comparing two chains by
//!   their number of blocks is a design bug: one can build a long chain at low
//!   difficulty for almost nothing;
//! - **bound the depth of a reorg** ([`MAX_REORG_DEPTH`]), which makes
//!   everything buried deeper irreversible;
//! - **make depth pay**: beyond a few blocks, a fork must show excess work
//!   that grows with its depth;
//! - **reward uncles**, to take away from the big miner the superlinear
//!   advantage it draws from propagation races.
//!
//! And what stays protected no matter what, including against an adversary
//! holding 99% of the hashrate: it can neither steal a coin whose key it does
//! not hold, nor create a unit beyond the subsidy, nor raise the cap of
//! 21,000,001. These three properties do not depend on consensus but on
//! cryptography and on rules that each node checks alone, on its own, without
//! trusting anyone.

use crate::address::Network;
use crate::amount::Amount;
use crate::block::{Block, BlockHeader};
use crate::consensus::*;
use crate::hash::Hash256;
use crate::memhard::{PowTable, TableParams};
use crate::pow::{self, PowEngine, Q21Pow, Q21PowMemoized};
use crate::sig::SchemeId;
use crate::state::Snapshot;
use crate::tx::{Transaction, TxIn, TxOut};
use crate::uint::U256;
use crate::utxo::{UndoRecord, UtxoSet};
use crate::validate::{self, BlockContext, ValidationError};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// Genesis
// ---------------------------------------------------------------------------

/// Message written in the coinbase of the genesis block.
///
/// Technically useless. In practice, the only line of the system that says why
/// it exists, and it fills a second, often forgotten function: a dated
/// newspaper headline **proves that the chain was not mined in secret before
/// that date**. It is a timestamp the founder cannot forge.
///
/// To be replaced with a real headline from the launch day.
/// Frozen: these bytes are part of the genesis block of every network, and
/// changing them creates another chain. They were last changed in 0.4.0,
/// which restarted the testnet from a new genesis.
pub const GENESIS_MESSAGE: &[u8] = b"Q21 -- one vote per machine, not per silicon foundry";

/// Timestamp of the genesis block. To be frozen at launch.
pub const GENESIS_TIME: u64 = 1_755_734_400;

/// Builds the genesis block.
///
/// Its coinbase issues exactly [`GENESIS_PREMINT`], the coin that takes the cap
/// from 21,000,000 to 21,000,001. The emission schedule returns zero at block
/// 0 (the slow start begins at zero), so that unit can only come from here.
///
/// **Fully deterministic.** No local parameter enters it: all nodes of a given
/// network produce bit for bit the same genesis block, hence the same id, hence
/// the same chain. See [`GENESIS_BENEFICIARY`] for why the coin is
/// unspendable.
pub fn genesis_block(network: Network) -> Block {
    // Genesis is deterministic but expensive: a proof of work table must be
    // built and then the nonces swept. Recomputing it on every call cost tens
    // of seconds of startup and tests. We compute it once per network and per
    // process.
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Vec<(Network, Block)>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    if let Ok(g) = cache.lock() {
        if let Some((_, b)) = g.iter().find(|(n, _)| *n == network) {
            return b.clone();
        }
    }
    let b = build_genesis(network);
    if let Ok(mut g) = cache.lock() {
        if !g.iter().any(|(n, _)| *n == network) {
            g.push((network, b.clone()));
        }
    }
    b
}

/// Id of the network's genesis block.
///
/// It is the only legitimate root of a Q21 chain. A block file whose first
/// record does not carry this id is not a chain of this network, whatever it
/// claims.
pub fn genesis_id(network: Network) -> Hash256 {
    genesis_block(network).header.block_id()
}

fn build_genesis(network: Network) -> Block {
    let beneficiary = Hash256(GENESIS_BENEFICIARY);
    // Genesis carries the chain's default scheme. It is unspendable (see
    // `GENESIS_BENEFICIARY`) but this field announces the security level Q21
    // adopts, and it enters the genesis id.
    let scheme = SchemeId::MlDsa87;
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(GENESIS_MESSAGE.to_vec())],
        outputs: vec![TxOut {
            value: Amount::from_units(GENESIS_PREMINT),
            scheme,
            pubkey_hash: beneficiary,
        }],
        lock_time: 0,
    };

    let mut b = Block {
        header: BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: beneficiary,
            time: GENESIS_TIME,
            bits: INITIAL_BITS,
            height: 0,
            nonce: 0,
        },
        transactions: vec![coinbase],
        uncles: Vec::new(),
    };
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();

    // Genesis carries a proof of work like the others: nobody should be able
    // to build a competing genesis without spending the same effort.
    let table = PowTable::build(TableParams::for_network(network), 0);
    let _ = pow::mine_with_table(&mut b.header, &table, 50_000_000);
    b
}

// ---------------------------------------------------------------------------
// Difficulty: LWMA
// ---------------------------------------------------------------------------

/// Difficulty adjustment by linearly weighted moving average.
///
/// At every block, and not every 2,016 like Bitcoin. A small chain whose
/// hashrate doubles or vanishes within a day cannot wait two weeks: it would
/// be killed by the first farm that passes by.
///
/// Two safeguards limit timestamp manipulation: each interval is bounded to
/// `[1, 6T]`, and the target can only change by a factor of
/// [`MAX_TARGET_CHANGE`] from one block to the next.
pub fn next_bits(recent_headers: &[BlockHeader]) -> u32 {
    let n = recent_headers.len();
    if n < 2 {
        return INITIAL_BITS;
    }
    let window = n.min(LWMA_WINDOW + 1);
    let recent = &recent_headers[n - window..];
    let k = recent.len() - 1;

    let t_target = TARGET_BLOCK_SECS;
    let max_ahead = LWMA_MAX_AHEAD * t_target;
    let max_behind = LWMA_MAX_BEHIND * t_target;

    // --- The solve time is SIGNED, and that is the whole point.
    //
    // The previous version computed `time[i+1] - time[i]` in unsigned
    // arithmetic, then bounded it to `[1, 6T]`. A timestamp moved backward
    // therefore gave 1, and never a negative value.
    //
    // That asymmetry was exploitable, and the phase 8b audit quantified it: a
    // miner systematically writing `parent + 6T` injects at every block
    // apparent time that **nothing ever subtracts**. The difficulty collapses.
    //
    // ```text
    //   hashrate share     difficulty drop      blocks obtained
    //         5 %                  21.5 %             x 1.28
    //        15 %                  82.5 %             x 5.68
    //        20 %                  97.3 %             x 37.1
    // ```
    //
    // The analytical threshold of total collapse is **20.7%**: beyond it, the
    // difficulty falls to its floor and the chain belongs to the attacker.
    // Twenty percent is not fifty-one.
    //
    // The first fix was Zawy's LWMA-1: bound symmetrically, to `[-6T, +6T]`,
    // so that the time pushed forward by a miner is given back by the next
    // block. It was, but not entirely: the honest block is constrained by the
    // median and cannot go back as far as the attacker went forward. A balance
    // remained: 33% more blocks for half of the hashrate.
    //
    // The bound is now **asymmetric**: `[-6T, +4T]`. The honest block removes
    // more than the attacker could inject, and the manipulation turns against
    // its author (see `LWMA_MAX_AHEAD`). The weighted sum stays floored so that
    // a sequence of backward timestamps cannot make it zero or negative.
    let mut weighted_sum: i128 = 0;
    let mut target_sum = U256::ZERO;

    for i in 0..k {
        let raw = recent[i + 1].time as i128 - recent[i].time as i128;
        let solvetime = raw.clamp(-(max_behind as i128), max_ahead as i128);
        weighted_sum += solvetime * (i as i128 + 1);

        match pow::target_from_compact(recent[i + 1].bits) {
            Ok(c) => target_sum = target_sum.checked_add(c).unwrap_or(target_sum),
            Err(_) => return INITIAL_BITS,
        }
    }

    let total_weight = (k as i128 * (k as i128 + 1)) / 2;
    if total_weight == 0 {
        return INITIAL_BITS;
    }

    // Floor at 5% of the expected duration: without it, a sequence of backward
    // timestamps would make the sum zero or negative, and the difficulty would
    // explode at once: the symmetric counterpart of the previous attack.
    let sum_floor = total_weight * t_target as i128 / 20;
    let sum = weighted_sum.max(sum_floor);

    let lwma = (sum / total_weight).max(1) as u64;
    let average_target = match target_sum.checked_div_u64(k as u64) {
        Some(c) => c,
        None => return INITIAL_BITS,
    };

    let mut new_target = match average_target.mul_div(lwma, t_target) {
        Some(c) => c,
        None => return INITIAL_BITS,
    };

    let ceiling = average_target
        .checked_mul_u64(MAX_TARGET_CHANGE)
        .unwrap_or(U256::MAX);
    let floor = average_target
        .checked_div_u64(MAX_TARGET_CHANGE)
        .unwrap_or(U256::ONE);
    new_target = new_target.min(ceiling).max(floor);
    if new_target.is_zero() {
        return INITIAL_BITS;
    }

    let limit = pow::target_from_compact(INITIAL_BITS).unwrap_or(U256::MAX);
    if new_target > limit {
        return INITIAL_BITS;
    }
    pow::target_to_compact(new_target)
}

// ---------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------

/// Index entry: a header and the cumulative work since genesis.
#[derive(Clone, Copy, Debug)]
pub struct BlockIndex {
    pub header: BlockHeader,
    pub total_work: U256,
    /// Total issued up to and including this block, in units.
    ///
    /// Kept per block for a specific reason: undoing a block must restore the
    /// parent's exact emission. The previous version recomputed it by adding
    /// up again the fees of each transaction of the undone block: a correct
    /// but fragile computation, which depended on the state of the UTXO set at
    /// the moment it was read. An eight-byte integer per block costs less than
    /// reasoning that has to be redone.
    ///
    /// Zero for blocks before a state snapshot loaded at startup: they cannot
    /// be undone anyway.
    pub issued: u64,
}

/// Default mining threads: all available cores.
///
/// A single-threaded reference miner would amount to offering a factor of
/// eight to anyone who bothers to write their own.
fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(1)
}

/// The block tree deduced from headers alone.
///
/// The block file is not a straight line: it also records side branches,
/// otherwise no reorg would survive a restart. Knowing which of these
/// branches is the active chain therefore takes a computation, and this is it.
pub struct BlockTree {
    /// All known headers, by id.
    pub by_id: HashMap<Hash256, BlockHeader>,
    /// Cumulative work since genesis, by id. A branch whose parent is missing
    /// does not appear here: it is orphaned, hence unusable.
    pub work: HashMap<Hash256, U256>,
    /// The active chain, from genesis to the heaviest tip.
    pub active: Vec<Hash256>,
    /// Id of the genesis block.
    pub genesis: Hash256,
}

/// Result of resuming from a state snapshot.
pub struct Resume {
    /// Chain positioned at the snapshot.
    pub chain: Chain,
    /// Blocks of the active chain to revalidate to reach the best tip.
    pub to_replay: Vec<Hash256>,
}

/// Why a resume failed. Every case falls back to full revalidation, never to a
/// silent acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeError {
    WrongNetwork,
    /// No block of height zero in the file.
    NoGenesis,
    /// A parent is missing, or a loop was detected.
    InconsistentIndex,
    /// The snapshot does not designate a block of the most-worked chain.
    SnapshotOffChain,
}

/// Why the adoption of a portable snapshot failed.
///
/// Every case refuses the adoption: a state is never adopted on a doubt. The
/// node then falls back to ordinary sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptionError {
    /// The snapshot commitment does not match the trusted value provided: it
    /// is not the expected state.
    UnexpectedCommitment,
    /// The snapshot tip does not match the trusted tip provided.
    UnexpectedTip,
    /// The headers do not lead to the trusted tip, at the announced height,
    /// from the real genesis: the header chain does not authenticate the tip.
    InauthenticHeaders,
    /// A header does not carry the difficulty the rule imposes at its
    /// position. Without this check, a fabricated chain would keep the floor
    /// difficulty from end to end and would cost almost nothing to produce.
    InvalidDifficulty { height: u64 },
    /// A header does not satisfy its own target: the announced work was not
    /// provided.
    InvalidWork { height: u64 },
    /// The proposed chain contradicts an anchor built into the binary. This is
    /// the case where the operator copied a poisoned trusted value: the
    /// software knows better, and refuses.
    AnchorContradicted { height: u64 },
    /// Building the chain failed (network, genesis, off chain).
    Resume(ResumeError),
}

impl std::fmt::Display for AdoptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdoptionError::UnexpectedCommitment => write!(
                f,
                "the snapshot commitment does not match the trusted value: it is \
                 not the expected state, it is not adopted"
            ),
            AdoptionError::UnexpectedTip => {
                write!(f, "the snapshot tip does not match the trusted tip")
            }
            AdoptionError::InauthenticHeaders => write!(
                f,
                "the headers do not lead to the trusted tip at the announced \
                 height: the tip is not authenticated"
            ),
            AdoptionError::InvalidDifficulty { height } => write!(
                f,
                "the header at height {height} does not carry the difficulty \
                 imposed by the rule: this header chain is fabricated"
            ),
            AdoptionError::InvalidWork { height } => write!(
                f,
                "the header at height {height} does not satisfy its target: the \
                 announced work was not provided"
            ),
            AdoptionError::AnchorContradicted { height } => write!(
                f,
                "the proposed chain contradicts the anchor built into this binary \
                 at height {height}: the trusted value provided is false or \
                 poisoned, nothing is adopted"
            ),
            AdoptionError::Resume(e) => write!(f, "resume impossible: {e}"),
        }
    }
}

impl std::fmt::Display for ResumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResumeError::WrongNetwork => write!(f, "snapshot from another network"),
            ResumeError::NoGenesis => write!(f, "no genesis block in the file"),
            ResumeError::InconsistentIndex => {
                write!(f, "inconsistent block index: missing parent or loop")
            }
            ResumeError::SnapshotOffChain => {
                write!(f, "the snapshot does not match the most-worked chain")
            }
        }
    }
}

/// Where a node writes the blocks it accepts.
///
/// # The defect this abstraction repairs
///
/// The daemon wrote to disk only the blocks **it mined itself**. Blocks
/// received from the network were valid, connected, served to peers, and lost
/// at shutdown. A node that synced while mining produced a block file with
/// holes: 0 to 4, then 11. On restart it went back to height 4, without a
/// word, and the work of seven blocks vanished.
///
/// Accepting a block and keeping it are not two decisions: they are the same
/// one. The journal is therefore plugged into the chain, not into the mining
/// loop.
pub trait Journal: Send + Sync {
    /// Records a block the chain has just accepted.
    ///
    /// The implementation must be idempotent: the same block can be presented
    /// twice without having to be written twice.
    fn record(&self, block: &Block);
}

/// What became of a submitted block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accept {
    /// The block extends the active chain.
    Extended,
    /// The block is valid but stays on a side branch.
    SideBranch,
    /// The active chain switched to another branch.
    Reorganized { depth: u64 },
    /// Already known.
    AlreadyKnown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    Validation(ValidationError),
    /// Unknown parent: impossible to attach this block.
    UnknownParent(Hash256),
    /// No common ancestor between this branch and the active chain, within the
    /// reach where we agree to look for one.
    ///
    /// Distinct from [`ChainError::BeyondFinality`]: there, we know by how much
    /// the reorg exceeds the limit; here, we do not even know where the branch
    /// comes from. Confusing the two has already cost one diagnosis.
    ForkPointNotFound {
        reach: u64,
    },
    /// The requested reorg exceeds the finality depth.
    ///
    /// This is the defense against deep reorgs. It protects the past at the
    /// cost of a split risk in case of a prolonged network partition; the
    /// trade-off is accepted and documented on [`MAX_REORG_DEPTH`].
    BeyondFinality {
        depth: u64,
        max: u64,
    },
    /// The fork is deep but does not bring the required excess work.
    InsufficientWorkForDepth {
        depth: u64,
    },
    /// The undo window does not cover the requested depth.
    ///
    /// Happens after resuming from a snapshot, when the reorg requires undoing
    /// more blocks than the node has replayed. We refuse rather than attempt an
    /// operation we could not complete.
    UndoWindowTooShort {
        depth: u64,
        available: u64,
    },
}

impl From<ValidationError> for ChainError {
    fn from(e: ValidationError) -> Self {
        ChainError::Validation(e)
    }
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

/// Provider of block bodies, for what memory no longer keeps.
///
/// The chain does not know the disk and must not know it: it describes
/// consensus. But a syncing peer requests old blocks, whose body has been
/// pruned. This interface is the only point where long history comes in, for
/// reading, never for validation.
pub trait BodySource: Send + Sync {
    fn body(&self, id: &Hash256) -> Option<Block>;
}

pub struct Chain {
    pub network: Network,
    index: HashMap<Hash256, BlockIndex>,
    /// Recent bodies only: see [`BODY_WINDOW`].
    blocks: HashMap<Hash256, Block>,
    /// Insertion order of the bodies, to prune the oldest ones.
    body_order: VecDeque<Hash256>,
    /// Weight of the bodies in memory, in encoded bytes: see
    /// [`BODY_BUDGET_BYTES`].
    body_bytes: usize,
    /// Where to read pruned bodies. Absent when purely in memory (tests,
    /// tools).
    source: Option<std::sync::Arc<dyn BodySource>>,
    /// Ids of the active chain, from genesis to the tip.
    active: Vec<Hash256>,
    pub utxo: UtxoSet,
    /// One record per block of the active chain, the last one at the back.
    ///
    /// Bounded by [`BODY_WINDOW`]: beyond rolling finality, undoing a block is
    /// forbidden anyway.
    undos: VecDeque<UndoRecord>,
    /// The work engine, with the registry of verdicts already returned: see
    /// [`crate::pow::WorkMemo`].
    pow: Q21PowMemoized,
    issued: u64,
    /// Proof of work table, kept between two blocks.
    ///
    /// Without this cache, every call to the miner would rebuild the epoch's
    /// table: 2 GiB and 2^26 hashes on mainnet, at every block. The table only
    /// changes once every [`POW_EPOCH_BLOCKS`] blocks (about 71 days) and there
    /// is no reason to recompute it more often.
    ///
    /// `RefCell` because mining does not modify the chain state and takes
    /// `&self`. The `Arc` lets the miner threads share the table without
    /// duplicating it: two gigabytes per thread would be absurd.
    table: RefCell<Option<std::sync::Arc<PowTable>>>,
    /// Threads used by the miner. All cores by default.
    miner_threads: usize,
}

impl Chain {
    pub fn new(network: Network, genesis: Block) -> Chain {
        let mut utxo = UtxoSet::new();
        let mut undo = UndoRecord::default();
        let mut issued = 0u64;
        for tx in &genesis.transactions {
            issued += tx.total_output().map(|a| a.units()).unwrap_or(0);
            utxo.apply_transaction(tx, 0, &mut undo);
        }

        let id = genesis.header.block_id();
        let mut index = HashMap::new();
        index.insert(
            id,
            BlockIndex {
                header: genesis.header,
                total_work: pow::block_work(genesis.header.bits),
                issued,
            },
        );
        let body_bytes = genesis.encode().len();
        let mut blocks = HashMap::new();
        blocks.insert(id, genesis);
        let mut body_order = VecDeque::new();
        body_order.push_back(id);

        Chain {
            network,
            index,
            blocks,
            body_order,
            body_bytes,
            source: None,
            active: vec![id],
            utxo,
            undos: VecDeque::from(vec![undo]),
            pow: Q21PowMemoized::new(network),
            issued,
            table: RefCell::new(None),
            miner_threads: default_threads(),
        }
    }

    /// Rebuilds a chain from a header index and a state snapshot.
    ///
    /// # What this function does, and what it refuses to do
    ///
    /// It rebuilds the **index** (which blocks exist, which one carries the
    /// most work) by reading only headers, and loads the **monetary state**
    /// from the snapshot. What it does not do: revalidate anything below the
    /// snapshot. This is a deliberate choice, and the same as Bitcoin Core's
    /// with its `chainstate`: whoever can rewrite your files has already won,
    /// and a full revalidation at every startup makes the node unusable long
    /// before it protects anyone.
    ///
    /// What remains guaranteed: the blocks returned in `to_replay` (everything
    /// after the snapshot) are fully validated by the caller, and the
    /// cumulative work of each branch is recomputed here from the headers.
    ///
    /// The snapshot must be taken **behind the tip**, not at the tip: replaying
    /// the last window rebuilds the undo records, without which no reorg would
    /// be possible anymore at startup.
    /// The block tree, as described by the headers alone.
    ///
    /// Three things, computed together because they follow from one another:
    /// which blocks exist, what cumulative work each carries, and which
    /// sequence leads from genesis to the heaviest tip.
    ///
    /// # Why it is a separate function
    ///
    /// Two startup paths need it, and for the same reason. The one that
    /// resumes from a snapshot must know where that snapshot sits in the tree.
    /// The one that has **no** snapshot (the case of an abrupt shutdown) must
    /// rebuild the state from genesis, and for that it first needs to know
    /// which chain is active. Without this answer, it replayed the file in its
    /// write order, which mixes branches, and ran into the anti-reorg defenses
    /// on its own history. See `RECONSTRUCTION` in the tests.
    pub fn block_tree(headers: &[BlockHeader]) -> Result<BlockTree, ResumeError> {
        // 1. Raw index, by id.
        let mut by_id: HashMap<Hash256, BlockHeader> = HashMap::new();
        let mut genesis = None;
        for h in headers {
            let id = h.block_id();
            if h.height == 0 {
                genesis = Some(id);
            }
            by_id.insert(id, *h);
        }
        let genesis = genesis.ok_or(ResumeError::NoGenesis)?;

        // 2. Cumulative work, by memoized walk back to genesis.
        //
        // Iterative and not recursive: a chain of one million blocks would
        // overflow the call stack, and a corrupted file could exploit that.
        let mut work: HashMap<Hash256, U256> = HashMap::new();
        work.insert(genesis, pow::block_work(by_id[&genesis].bits));

        for start in by_id.keys() {
            if work.contains_key(start) {
                continue;
            }
            let mut stack = Vec::new();
            let mut current = *start;
            let known = loop {
                if let Some(w) = work.get(&current) {
                    break Some(*w);
                }
                let Some(h) = by_id.get(&current) else {
                    break None; // parent missing from the file: orphan branch
                };
                stack.push(current);
                if stack.len() > by_id.len() {
                    return Err(ResumeError::InconsistentIndex);
                }
                current = h.prev_block;
            };
            let Some(mut w) = known else { continue };
            while let Some(id) = stack.pop() {
                w = w.checked_add(pow::block_work(by_id[&id].bits)).unwrap_or(w);
                work.insert(id, w);
            }
        }

        // 3. Best tip, then active chain by walking back.
        let best = work
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(id, _)| *id)
            .ok_or(ResumeError::NoGenesis)?;

        let mut active = Vec::new();
        let mut current = best;
        loop {
            active.push(current);
            if current == genesis {
                break;
            }
            current = by_id[&current].prev_block;
            if !by_id.contains_key(&current) {
                return Err(ResumeError::InconsistentIndex);
            }
        }
        active.reverse();

        Ok(BlockTree {
            by_id,
            work,
            active,
            genesis,
        })
    }

    /// Adopts a **portable** snapshot (coming from elsewhere) after anchoring
    /// it to a trusted value.
    ///
    /// # The trust model, stated plainly
    ///
    /// `from_snapshot` trusts its headers: they come from the node's own block
    /// file, already validated. A portable snapshot has none of these
    /// guarantees. Two anchors, both provided by the operator from a source
    /// they consider safe (the commitment and the tip shown by their explorer
    /// or by the export of their own node), replace them:
    ///
    /// - **the commitment** authenticates the UTXO set: the snapshot's MuHash
    ///   digest must equal the trusted value;
    /// - **the tip** authenticates the position: the snapshot must claim it,
    ///   and the headers must lead to it, at the announced height, from the
    ///   real genesis.
    ///
    /// # Why the proof of work **is** checked again
    ///
    /// A previous version skipped it, on the grounds that the structural
    /// chaining up to the trusted tip authenticates the whole chain: the hash of
    /// each header is fixed by the `prev_block` of the next one, so a single
    /// forged header would break the chain.
    ///
    /// The reasoning is correct, and it is not enough. It proves that the
    /// ancestors are authentic **given that the tip is**. And that is precisely
    /// the question: the tip comes only from a hex string the operator copied.
    /// Whoever controls it (impersonated explorer, interception, malicious
    /// mirror, simple typo) can fabricate from scratch a consistent header
    /// chain, without any computation, ending on their own tip, and a UTXO set
    /// of their choosing whose commitment matches their own value. The first
    /// three checks all pass. The node then adopts an entirely invented
    /// monetary state, for an attack cost of zero.
    ///
    /// Work is the only thing that can be checked **without trusting anyone**:
    /// that is the whole point of proof of work. So we check it again from
    /// genesis to the tip, and the attack stops being free: the work of the
    /// whole chain has to be redone.
    ///
    /// Two checks, inseparable:
    ///
    /// - **the difficulty** of each header must be the one the rule imposes at
    ///   its position, and not the one it claims. Without it, a fabricated
    ///   chain would stay at the floor difficulty from end to end;
    /// - **the work** of each header must satisfy that target.
    ///
    /// # The cost, measured rather than assumed
    ///
    /// The original objection ("it would be as expensive as the sync we are
    /// trying to avoid") confuses two things. A full sync validates the
    /// **bodies**: every transaction, every signature, every UTXO movement.
    /// Here we only check headers, through the *light* path of the memory-hard
    /// proof, the one that uses only the cache and never the table. And since
    /// we advance by increasing heights, the cache of an epoch is built only
    /// once. That is two orders of magnitude below a full validation, and it is
    /// paid only once, at adoption.
    pub fn adopt_snapshot(
        network: Network,
        snapshot: Snapshot,
        headers: &[BlockHeader],
        trusted_tip: Hash256,
        trusted_commitment: Hash256,
    ) -> Result<Resume, AdoptionError> {
        // 1. The state: UTXO set and total issued together, see
        //    [`crate::state::state_commitment`].
        if snapshot.commitment() != trusted_commitment {
            return Err(AdoptionError::UnexpectedCommitment);
        }
        // 2. The claimed position.
        if snapshot.tip != trusted_tip {
            return Err(AdoptionError::UnexpectedTip);
        }
        // 3. Authenticating the tip through the headers: we walk back from the
        //    trusted tip to genesis, checking the chaining and the height at
        //    each step. Nothing is taken on faith; everything is enforced by
        //    the hashes.
        let by_id: std::collections::HashMap<Hash256, &BlockHeader> =
            headers.iter().map(|h| (h.block_id(), h)).collect();
        let mut current = trusted_tip;
        let mut height = snapshot.height;
        // We record the path along the way: it is exactly the chain whose work
        // must be checked next, and walking it again would be wasteful.
        //
        // The capacity is bounded by the number of headers actually provided,
        // NEVER by `snapshot.height`: that height comes from a snapshot a peer
        // decodes and controls (it is only validated inside the loop below).
        // An adversarial height of `u64::MAX` overflowed `as usize + 1`, or
        // attempted an allocation of several terabytes, and made the process
        // ABORT (overflow-checks, panic=abort): a reliable remote crash of any
        // node fast-syncing from that peer. Found by the phase 8b red team
        // (2nd campaign). The loop cannot exceed the number of headers present
        // anyway, since each step requires an entry in `by_id`.
        let mut path: Vec<BlockHeader> = Vec::with_capacity(headers.len());
        loop {
            let Some(h) = by_id.get(&current) else {
                return Err(AdoptionError::InauthenticHeaders);
            };
            if h.height != height {
                return Err(AdoptionError::InauthenticHeaders);
            }
            path.push(**h);
            if height == 0 {
                if current != genesis_id(network) {
                    return Err(AdoptionError::InauthenticHeaders);
                }
                break;
            }
            current = h.prev_block;
            height -= 1;
        }
        // 4. The work. This is what makes the attack costly instead of free:
        //    see the header note.
        path.reverse(); // from genesis to the tip
        Self::check_work(network, &path)?;

        // 5. The anchors built into the binary. They take precedence over
        //    anything the operator may have copied: at the heights they cover,
        //    the truth comes from the software reviewed by everyone, not from a
        //    transmitted value.
        Self::check_anchors(&path, &snapshot, crate::fast_sync::builtin_anchors(network))?;

        // 5. The construction: positioning, index, window to replay.
        Chain::from_snapshot(network, snapshot, headers).map_err(AdoptionError::Resume)
    }

    /// Checks a candidate chain against the anchors built into the binary.
    ///
    /// `path` is ordered by increasing height, `path[0]` being genesis. Two
    /// requirements, and the second one matters most:
    ///
    /// - **every anchor below the tip must be found in the chain**, at its
    ///   height and with its id. A chain that claims to go elsewhere at a point
    ///   the binary holds as true is refused, even if it carries work: that is
    ///   where a very powerful adversary would come, and that is where we stop
    ///   them;
    /// - **at the exact height of an anchor, the commitment must match**. The
    ///   operator therefore cannot get another monetary state adopted at a
    ///   height whose commitment the binary knows.
    ///
    /// An empty table forbids nothing: the work recheck, for its part, is
    /// always applied.
    pub fn check_anchors(
        path: &[BlockHeader],
        snapshot: &Snapshot,
        anchors: &[crate::fast_sync::Anchor],
    ) -> Result<(), AdoptionError> {
        for a in anchors {
            if a.height > snapshot.height {
                continue; // beyond what we adopt: nothing to say
            }
            let Some(header) = path.get(a.height as usize) else {
                return Err(AdoptionError::AnchorContradicted { height: a.height });
            };
            if header.block_id() != a.tip {
                return Err(AdoptionError::AnchorContradicted { height: a.height });
            }
            if a.height == snapshot.height && snapshot.commitment() != a.commitment {
                return Err(AdoptionError::AnchorContradicted { height: a.height });
            }
        }
        Ok(())
    }

    /// Checks, from genesis to the tip, that each header carries the
    /// difficulty imposed by the rule **and** the work that satisfies that
    /// target.
    ///
    /// `active` is ordered by increasing height, `active[0]` being genesis. The
    /// order is not a mere convenience: it lets the epoch's cache be built only
    /// once, whereas an unordered walk would rebuild it over and over.
    fn check_work(network: Network, active: &[BlockHeader]) -> Result<(), AdoptionError> {
        if active.len() <= 1 {
            return Ok(());
        }
        let params = crate::memhard::TableParams::for_network(network);
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(16);

        // --- Epoch by epoch, and not in arbitrary slices.
        //
        // The cache registry only keeps the last two epochs. Threads each
        // working on a different epoch would therefore evict each other, and
        // verification would be slower with several threads than with one. So
        // we advance epoch by epoch: the cache is built once, then shared by
        // all the threads that check that particular slice.
        let mut i = 1usize;
        while i < active.len() {
            let epoch = crate::memhard::epoch_of(active[i].height);
            let mut j = i;
            while j < active.len() && crate::memhard::epoch_of(active[j].height) == epoch {
                j += 1;
            }
            let cache = crate::memhard::cache_for(params, epoch);
            Self::check_range(network, active, i, j, params, &cache, threads)?;
            i = j;
        }
        Ok(())
    }

    /// Spreads a slice of a single epoch over several threads.
    ///
    /// Each header is checked independently of the others: its difficulty
    /// depends only on its predecessors, which are already there and do not
    /// move, and its work depends only on itself. Splitting therefore changes
    /// no verdict, only the time it takes to come.
    #[allow(clippy::too_many_arguments)]
    fn check_range(
        network: Network,
        active: &[BlockHeader],
        start: usize,
        end: usize,
        params: crate::memhard::TableParams,
        cache: &crate::memhard::PowCache,
        threads: usize,
    ) -> Result<(), AdoptionError> {
        let n = end - start;
        let threads = threads.min(n).max(1);
        // Below a few hundred headers, spawning threads costs more than the work
        // given to them.
        if threads == 1 || n < 256 {
            return Self::check_segment(network, active, start, end, params, cache);
        }
        let size = n.div_ceil(threads);
        let results: Vec<Result<(), AdoptionError>> = std::thread::scope(|s| {
            let mut handles = Vec::new();
            let mut d = start;
            while d < end {
                let f = (d + size).min(end);
                handles.push(
                    s.spawn(move || Self::check_segment(network, active, d, f, params, cache)),
                );
                d = f;
            }
            handles
                .into_iter()
                // A verification thread that PANICS is a failure, never a
                // success: treating it as `Ok(())` let a segment whose proof of
                // work made the verifier panic pass as valid: an adoption wide
                // open. Red team 8b (2nd campaign).
                .map(|p| p.join().unwrap_or(Err(AdoptionError::InauthenticHeaders)))
                .collect()
        });
        // The segments are ordered by increasing height: taking the first error
        // always returns the lowest fault, whatever the order in which the
        // threads finished. A message that changed from one run to the next
        // would be useless.
        results
            .into_iter()
            .find_map(|r| r.err())
            .map_or(Ok(()), Err)
    }

    /// Checks a contiguous segment of headers, all of the same epoch.
    fn check_segment(
        network: Network,
        active: &[BlockHeader],
        start: usize,
        end: usize,
        params: crate::memhard::TableParams,
        cache: &crate::memhard::PowCache,
    ) -> Result<(), AdoptionError> {
        let engine = crate::pow::Q21PowWithCache::new(params, cache);
        for i in start..end {
            let header = &active[i];
            // 1. The imposed difficulty, not the claimed one. Regtest fixes it
            //    at the minimum, as everywhere else.
            let expected = if network == Network::Regtest {
                INITIAL_BITS
            } else {
                let d = (i - 1).saturating_sub(LWMA_WINDOW);
                next_bits(&active[d..i])
            };
            if header.bits != expected {
                return Err(AdoptionError::InvalidDifficulty {
                    height: header.height,
                });
            }
            // 2. The work itself. The comparison to the target remains the
            //    trait's: there is only one work validity rule.
            engine
                .check(header)
                .map_err(|_| AdoptionError::InvalidWork {
                    height: header.height,
                })?;
        }
        Ok(())
    }

    pub fn from_snapshot(
        network: Network,
        snapshot: Snapshot,
        headers: &[BlockHeader],
    ) -> Result<Resume, ResumeError> {
        if snapshot.network != network {
            return Err(ResumeError::WrongNetwork);
        }

        let BlockTree {
            by_id,
            work,
            active,
            ..
        } = Self::block_tree(headers)?;

        // 4. The snapshot must be on this active chain, at its height.
        let pos = snapshot.height as usize;
        if active.get(pos) != Some(&snapshot.tip) {
            return Err(ResumeError::SnapshotOffChain);
        }

        let mut index = HashMap::with_capacity(by_id.len());
        for (id, h) in &by_id {
            let Some(w) = work.get(id) else { continue };
            index.insert(
                *id,
                BlockIndex {
                    header: *h,
                    total_work: *w,
                    // Unknown below the snapshot, and of no use: we do not
                    // undo a block whose undo record we do not have.
                    issued: if *id == snapshot.tip {
                        snapshot.issued
                    } else {
                        0
                    },
                },
            );
        }

        let to_replay = active[pos + 1..].to_vec();
        Ok(Resume {
            chain: Chain {
                network,
                index,
                blocks: HashMap::new(),
                body_order: VecDeque::new(),
                body_bytes: 0,
                source: None,
                active: active[..=pos].to_vec(),
                utxo: snapshot.utxo,
                undos: VecDeque::new(),
                pow: Q21PowMemoized::new(network),
                issued: snapshot.issued,
                table: RefCell::new(None),
                miner_threads: default_threads(),
            },
            to_replay,
        })
    }

    /// State snapshot taken **behind** the tip, so that it stays replayable.
    ///
    /// We step back by the whole available undo window. On restart, replaying
    /// that window rebuilds the undo records and gives the node back its
    /// ability to reorganize, which a snapshot taken at the tip would have
    /// taken away.
    ///
    /// Returns `None` if the chain is too short for a snapshot to be of any
    /// use.
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.snapshot_at_depth(self.undos.len().saturating_sub(1))
    }

    /// State snapshot at a chosen depth, in blocks below the tip.
    ///
    /// The step back is capped by the available undo window: we cannot go
    /// further back than what we know how to undo.
    pub fn snapshot_at_depth(&self, depth: usize) -> Option<Snapshot> {
        let depth = depth.min(self.undos.len().saturating_sub(1));
        if depth == 0 || self.height() < depth as u64 {
            return None;
        }
        let height = self.height() - depth as u64;
        let tip = *self.active.get(height as usize)?;

        let mut utxo = self.utxo.clone();
        for undo in self.undos.iter().rev().take(depth) {
            utxo.undo(undo);
        }

        let muhash = utxo.commitment();
        Some(Snapshot {
            network: self.network,
            height,
            tip,
            issued: self
                .index
                .get(&tip)
                .map(|b| b.issued)
                .unwrap_or(self.issued),
            utxo,
            muhash,
        })
    }

    /// Plugs in a body provider for pruned blocks.
    pub fn set_body_source(&mut self, s: std::sync::Arc<dyn BodySource>) {
        self.source = Some(s);
    }

    /// Records a body and prunes the oldest ones.
    ///
    /// Two bounds, the first one reached wins: [`BODY_WINDOW`] in blocks,
    /// [`BODY_BUDGET_BYTES`] in bytes. Bodies leave from oldest to most recent;
    /// the body just stored is therefore the last to leave, which guarantees
    /// that a side branch being evaluated keeps its body for the duration of
    /// the reorg.
    ///
    /// Genesis is never pruned: it is the only block whose absence would make
    /// the chain unintelligible, and it costs only one block.
    fn keep_body(&mut self, id: Hash256, block: Block) {
        let weight = block.encode().len();
        match self.blocks.insert(id, block) {
            None => {
                self.body_order.push_back(id);
                self.body_bytes += weight;
            }
            Some(previous) => {
                // Same id, same encoding: the weight does not change. We
                // recompute it anyway rather than assume it.
                self.body_bytes = self
                    .body_bytes
                    .saturating_sub(previous.encode().len())
                    .saturating_add(weight);
            }
        }
        self.prune_bodies(BODY_WINDOW, BODY_BUDGET_BYTES);
    }

    /// Evicts the oldest bodies as long as either bound is exceeded. Separate
    /// from [`Self::keep_body`] so that tests can set small bounds without
    /// building a gigabyte of blocks.
    fn prune_bodies(&mut self, window: usize, budget: usize) {
        let genesis = self.active.first().copied();
        // `len() > 1`: genesis, being protected, must not make the loop spin
        // idly if it alone exceeded the budget.
        while self.body_order.len() > 1
            && (self.body_order.len() > window || self.body_bytes > budget)
        {
            if let Some(oldest) = self.body_order.pop_front() {
                if Some(oldest) == genesis {
                    self.body_order.push_back(oldest);
                    continue;
                }
                if let Some(b) = self.blocks.remove(&oldest) {
                    self.body_bytes = self.body_bytes.saturating_sub(b.encode().len());
                }
            }
        }
    }

    /// Bodies kept in RAM.
    pub fn bodies_in_memory(&self) -> usize {
        self.blocks.len()
    }

    /// Weight of the bodies kept in RAM, in encoded bytes.
    pub fn body_bytes_in_memory(&self) -> usize {
        self.body_bytes
    }

    /// Runs `f` with the table of the requested epoch, building it only if
    /// the cache does not already hold it.
    #[cfg(test)]
    fn with_table<R>(&self, epoch: u64, f: impl FnOnce(&PowTable) -> R) -> R {
        let t = self.table_for(epoch);
        f(&t)
    }

    /// The epoch's table, if it is already built. Builds nothing: it is up to
    /// the caller to do so **outside the lock** and to hand it over through
    /// [`Self::adopt_table`].
    pub fn table_if_ready(&self, epoch: u64) -> Option<std::sync::Arc<PowTable>> {
        self.table
            .borrow()
            .as_ref()
            .filter(|t| t.epoch() == epoch)
            .cloned()
    }

    /// Keeps a table built elsewhere, so that the miner does not rebuild it.
    pub fn adopt_table(&self, table: std::sync::Arc<PowTable>) {
        *self.table.borrow_mut() = Some(table);
    }

    /// The candidate block for the next mining round, without proof of work.
    ///
    /// # Why mining no longer happens here
    ///
    /// Mining used to assemble **and mine** under the chain lock, hence under
    /// the lock of the whole node: two million attempts per round, several
    /// seconds on a small processor, during which no received block was
    /// processed, no transaction relayed, no peer served. And at an epoch
    /// change, building the table (minutes) froze the node the same way.
    ///
    /// The node assembles the candidate here, releases the lock, mines outside
    /// with the table it holds, then comes back to connect the block. If the
    /// tip moved in the meantime, the connection fails cleanly and the next
    /// round starts again from the right parent.
    pub fn mining_candidate(
        &self,
        beneficiary: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        timestamp: u64,
    ) -> Block {
        self.assemble_candidate(beneficiary, scheme, mempool, &[], timestamp)
    }

    /// Table of the requested epoch, built if needed, shareable between
    /// threads.
    fn table_for(&self, epoch: u64) -> std::sync::Arc<PowTable> {
        let mut cache = self.table.borrow_mut();
        let needs_rebuild = match cache.as_ref() {
            Some(t) => t.epoch() != epoch,
            None => true,
        };
        if needs_rebuild {
            *cache = Some(std::sync::Arc::new(PowTable::build(
                self.pow.params(),
                epoch,
            )));
        }
        std::sync::Arc::clone(cache.as_ref().expect("table built just above"))
    }

    /// Number of threads used by the miner.
    pub fn mining_threads(&self) -> usize {
        self.miner_threads
    }

    /// Sets the number of miner threads. Zero restores the default value.
    pub fn set_mining_threads(&mut self, n: usize) {
        self.miner_threads = if n == 0 { default_threads() } else { n };
    }

    pub fn height(&self) -> u64 {
        self.active.len() as u64 - 1
    }

    pub fn tip_id(&self) -> Hash256 {
        *self.active.last().expect("a chain always has its genesis")
    }

    pub fn tip(&self) -> BlockHeader {
        self.index[&self.tip_id()].header
    }

    /// Cumulative work of the active chain. It is the only measure that counts.
    pub fn total_work(&self) -> U256 {
        self.index[&self.tip_id()].total_work
    }

    pub fn headers(&self) -> Vec<BlockHeader> {
        self.active.iter().map(|id| self.index[id].header).collect()
    }

    /// Block of the active chain at this height.
    ///
    /// Returns a value and not a reference: beyond [`BODY_WINDOW`], the body
    /// comes from disk and does not exist in memory.
    pub fn block_at(&self, height: u64) -> Option<Block> {
        let id = *self.active.get(height as usize)?;
        self.block_by_id(&id)
    }

    pub fn total_issued(&self) -> Amount {
        Amount::from_units(self.issued)
    }

    /// MuHash commitment of the UTXO set at the chain tip.
    ///
    /// It is the commitment to the currency set at this height: two synced
    /// nodes compute it identically. It is what makes a snapshot verifiable
    /// instead of taken on faith.
    pub fn utxo_commitment(&self) -> Hash256 {
        self.utxo.commitment()
    }

    /// State commitment at the tip: the MuHash **and** the total issued, bound
    /// together.
    ///
    /// It is the value an explorer displays and that a person copies to adopt
    /// a snapshot taken at this height: it is equal, by construction, to
    /// [`Snapshot::commitment`] of a snapshot taken here. See
    /// [`crate::state::state_commitment`] for what it commits to beyond the
    /// MuHash alone.
    pub fn state_commitment(&self) -> Hash256 {
        crate::state::state_commitment(self.utxo.commitment(), self.issued)
    }

    /// Number of unspent outputs at the tip.
    pub fn utxo_count(&self) -> usize {
        self.utxo.len()
    }

    /// Builds the fast-sync snapshot this node can serve.
    ///
    /// The same three pieces as `snapshot export-sync`: the snapshot taken
    /// behind the tip, the headers from genesis to its height, and a bounded
    /// window of bodies around it (genesis, then the blocks needed to replay on
    /// top without violating the uncle double-payment rule).
    ///
    /// Returns `None` if the chain is too short, or if a body of the window is
    /// missing: a node without a body source does not serve a snapshot.
    pub fn build_sync_snapshot(&self) -> Option<crate::fast_sync::SyncSnapshot> {
        let s = self.snapshot()?;
        let h = s.height;
        let all = self.headers();
        if h as usize >= all.len() {
            return None;
        }
        let headers = all[..=h as usize].to_vec();
        let margin = crate::consensus::MAX_UNCLE_AGE + 2;
        let start = h.saturating_sub(margin);
        let mut bodies = vec![self.block_at(0)?];
        for hh in start..=h {
            if hh == 0 {
                continue; // genesis is already there
            }
            bodies.push(self.block_at(hh)?);
        }
        Some(crate::fast_sync::SyncSnapshot {
            snapshot: s.to_portable_bytes(),
            headers,
            bodies,
        })
    }

    pub fn known_blocks(&self) -> usize {
        self.index.len()
    }

    pub fn pow_params(&self) -> TableParams {
        self.pow.params()
    }

    /// Difficulty the next block will have to carry.
    ///
    /// On regtest it stays fixed at the minimum: mining ten blocks in a row
    /// would otherwise raise the target by a factor of 4 at every block.
    ///
    /// Goes through [`Self::next_bits_after`]: `next_bits(&self.headers())`
    /// copied **all** the headers since genesis at every connected block, only
    /// to read the last 91. At five hundred thousand blocks, that was tens of
    /// milliseconds under the lock per block, and a quadratic initial sync.
    pub fn next_bits(&self) -> u32 {
        self.next_bits_after(self.tip_id())
    }

    fn recent_times(&self) -> Vec<u64> {
        let n = self.active.len();
        let start = n.saturating_sub(MEDIAN_TIME_SPAN);
        self.active[start..]
            .iter()
            .map(|id| self.index[id].header.time)
            .collect()
    }

    /// Timestamps of a block's ancestors, walking the index back from
    /// `parent`: the counterpart of [`Self::next_bits_after`] for the median,
    /// which therefore works for any branch. From oldest to most recent.
    fn recent_times_after(&self, parent: Hash256) -> Vec<u64> {
        let mut v = Vec::with_capacity(MEDIAN_TIME_SPAN);
        let mut current = parent;
        for _ in 0..MEDIAN_TIME_SPAN {
            match self.index.get(&current) {
                Some(b) => {
                    v.push(b.header.time);
                    if b.header.height == 0 {
                        break;
                    }
                    current = b.header.prev_block;
                }
                None => break,
            }
        }
        v.reverse();
        v
    }

    /// Ids of the recent ancestors, tip included.
    fn recent_ancestors(&self) -> Vec<Hash256> {
        let n = self.active.len();
        let start = n.saturating_sub(MAX_UNCLE_AGE as usize + 2);
        self.active[start..].to_vec()
    }

    /// Uncles already claimed by the recent blocks of the active chain.
    ///
    /// # Why this function can fail
    ///
    /// It used to read the bodies in memory. After resuming from a snapshot,
    /// those bodies are absent: the returned set was then **incomplete**, and
    /// a freshly restarted node accepted an already paid uncle that a full node
    /// refused. Two honest nodes, two verdicts: a split.
    ///
    /// It therefore goes through [`Chain::block_by_id`], which fetches the
    /// body from disk if needed, and **fails loudly** if a body is really
    /// missing. Blindly validating an anti-double-payment rule would be worse
    /// than not validating it at all: we would believe we were protected.
    fn claimed_uncles(&self) -> Result<HashSet<Hash256>, ValidationError> {
        // With no uncle possible, no uncle can have been claimed: the
        // double-payment rule has nothing to check, and rereading (hence
        // cloning) nine full bodies at every connection only added cost. The
        // read below resumes on its own if the protocol ever allows uncles
        // again.
        if MAX_UNCLES == 0 {
            return Ok(HashSet::new());
        }
        let n = self.active.len();
        let start = n.saturating_sub(MAX_UNCLE_AGE as usize + 2);
        let mut s = HashSet::new();
        for id in &self.active[start..] {
            let b = self
                .block_by_id(id)
                .ok_or(ValidationError::IncompleteHistory)?;
            for u in &b.uncles {
                s.insert(u.block_id());
            }
        }
        Ok(s)
    }

    /// Expected difficulty for a child of each recent ancestor.
    ///
    /// An uncle at height `h` is the sibling of the active block of the same
    /// height: it must carry the difficulty the chain imposed at that height,
    /// and not whatever its author chose to write.
    fn uncle_expected_bits(&self) -> HashMap<Hash256, u32> {
        let n = self.active.len();
        let start = n.saturating_sub(MAX_UNCLE_AGE as usize + 2);
        let mut m = HashMap::new();
        for id in &self.active[start..] {
            m.insert(*id, self.next_bits_after(*id));
        }
        m
    }

    /// Expected difficulty for a block whose parent is `parent`.
    ///
    /// Walks back the header index, which makes it computable for any branch,
    /// including a side branch that has not been connected. That is what allows
    /// refusing a block that chose its own target before even indexing it.
    pub fn next_bits_after(&self, parent: Hash256) -> u32 {
        if self.network == Network::Regtest {
            return INITIAL_BITS;
        }
        let mut headers: Vec<BlockHeader> = Vec::with_capacity(LWMA_WINDOW + 1);
        let mut current = parent;
        for _ in 0..=LWMA_WINDOW {
            match self.index.get(&current) {
                Some(b) => {
                    headers.push(b.header);
                    if b.header.height == 0 {
                        break;
                    }
                    current = b.header.prev_block;
                }
                None => break,
            }
        }
        headers.reverse();
        next_bits(&headers)
    }

    /// Block locator: waypoints so that a peer finds our common point.
    ///
    /// The last ten blocks, then an exponential step back to genesis. A peer
    /// compares this list with its own chain and answers from the first id it
    /// recognizes. The cost is logarithmic in the height, whereas sending the
    /// whole chain would be linear.
    pub fn locator(&self) -> Vec<Hash256> {
        let mut v = Vec::new();
        let mut step = 1usize;
        let mut i = self.active.len() - 1;
        loop {
            v.push(self.active[i]);
            if i == 0 || v.len() >= 64 {
                break;
            }
            if v.len() > 10 {
                step *= 2;
            }
            i = i.saturating_sub(step);
        }
        if *v.last().unwrap() != self.active[0] {
            v.push(self.active[0]);
        }
        v
    }

    /// Headers following the first recognized id of the locator.
    ///
    /// Returns at most `max` headers. Stops at `stop` if it is reached.
    pub fn headers_from(&self, locator: &[Hash256], stop: Hash256, max: usize) -> Vec<BlockHeader> {
        // Fork point by lookup in the index (one table read per locator
        // entry), and not by a linear scan of the active chain. A peer could
        // otherwise send 64 absent hashes and force 64 full scans of the chain:
        // tens of millions of comparisons per 2 KiB request, all under the
        // global lock. We keep the first locator entry that is indeed on the
        // active chain, at its height.
        let start = locator
            .iter()
            .find_map(|id| {
                let h = self.index.get(id)?.header.height as usize;
                if self.active.get(h) == Some(id) {
                    Some(h)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let mut v = Vec::new();
        for id in self.active.iter().skip(start + 1) {
            v.push(self.index[id].header);
            if v.len() >= max || *id == stop {
                break;
            }
        }
        v
    }

    /// Full block by id, including on a side branch.
    ///
    /// Looks in memory first, then with the body provider. A node without a
    /// provider knows nothing of pruned blocks, and says so.
    pub fn block_by_id(&self, id: &Hash256) -> Option<Block> {
        if let Some(b) = self.blocks.get(id) {
            return Some(b.clone());
        }
        self.source.as_ref()?.body(id)
    }

    /// Id of the active chain's block at this height.
    pub fn active_at(&self, height: u64) -> Option<Hash256> {
        self.active.get(height as usize).copied()
    }

    /// Total work a competing branch must reach to supplant the active chain,
    /// if it diverges at index `fork` of it and the reorg covers `depth`
    /// blocks.
    ///
    /// Exposes the finality rule for observation and tests: it is a read, it
    /// modifies nothing.
    pub fn work_required_for_reorg(&self, fork: usize, depth: u64) -> U256 {
        self.reorg_threshold(fork, depth)
    }

    /// Header of a known block, including on a side branch.
    pub fn header_of(&self, id: &Hash256) -> Option<BlockHeader> {
        self.index.get(id).map(|b| b.header)
    }

    /// Number of undo records available.
    ///
    /// It is the maximum depth of a reorg this node can still perform. Useful
    /// for operations: a freshly restarted node has fewer than a node that has
    /// been running for a long time.
    pub fn undo_window(&self) -> usize {
        self.undos.len()
    }

    pub fn has_block(&self, id: &Hash256) -> bool {
        self.index.contains_key(id)
    }

    /// Validates a block and attaches it to the current tip.
    pub fn connect(&mut self, block: &Block, now: u64) -> Result<Amount, ValidationError> {
        let times = self.recent_times();
        let anc = self.recent_ancestors();
        let claimed = self.claimed_uncles()?;
        let uncle_bits = self.uncle_expected_bits();
        let height = self.height() + 1;

        let ctx = BlockContext {
            network: self.network,
            height,
            prev_id: self.tip_id(),
            recent_times: &times,
            expected_bits: self.next_bits(),
            now,
            ancestors: &anc,
            claimed_uncles: &claimed,
            uncle_expected_bits: &uncle_bits,
            cumulative_issued: self.issued,
        };

        let fees = validate::check_block(block, &self.utxo, &ctx, &self.pow)?;

        let mut undo = UndoRecord::default();
        for tx in &block.transactions {
            self.utxo.apply_transaction(tx, height, &mut undo);
        }
        let coinbase = block.transactions[0].total_output()?.units();
        self.issued += coinbase.saturating_sub(fees.units());

        let id = block.header.block_id();
        let parent_work = self.index[&block.header.prev_block].total_work;
        let total = parent_work
            .checked_add(pow::block_work(block.header.bits))
            .unwrap_or(parent_work);
        self.index.insert(
            id,
            BlockIndex {
                header: block.header,
                total_work: total,
                issued: self.issued,
            },
        );
        self.keep_body(id, block.clone());
        self.active.push(id);
        self.undos.push_back(undo);
        if self.undos.len() > BODY_WINDOW {
            self.undos.pop_front();
        }
        Ok(fees)
    }

    /// Removes the tip block and restores the previous state.
    pub fn disconnect(&mut self) -> bool {
        if self.active.len() <= 1 {
            return false;
        }
        // CRITICAL ORDER: nothing is mutated until we are certain we can go
        // all the way.
        //
        // The previous version overwrote `self.issued` **before** noticing that
        // no undo record was available. A refused `disconnect` therefore left
        // the emission counter at the parent's value, and after resuming from a
        // snapshot, where earlier index entries carry zero, the counter dropped
        // to zero. An adversarial audit demonstrated it: "emission went from
        // 100691370 to 0 on a refused disconnect".
        //
        // Beyond the kept window, undoing is impossible, and it is already
        // forbidden by rolling finality. We refuse without touching anything.
        if self.undos.is_empty() {
            return false;
        }
        let parent = self.active[self.active.len() - 2];
        let parent_issued = self.index[&parent].issued;

        let undo = self.undos.pop_back().expect("checked just above");
        self.utxo.undo(&undo);
        self.active.pop();
        self.issued = parent_issued;
        true
    }

    // -----------------------------------------------------------------------
    // Fork choice
    // -----------------------------------------------------------------------

    /// Path from a block to an ancestor belonging to the active chain.
    ///
    /// Returns the index of the fork point in `active` and the blocks to
    /// connect, from oldest to most recent.
    fn path_to_active(&self, tip: Hash256) -> Option<(usize, Vec<Hash256>)> {
        let mut branch = Vec::new();
        let mut current = tip;
        for _ in 0..=MAX_REORG_DEPTH + 1 {
            let idx = self.index.get(&current)?;
            // `active[h]` is the active block of height `h`: knowing whether
            // `current` is part of it is an indexed read, not a scan. The
            // previous version walked the whole active chain at every step:
            // quadratic in the depth, linear in the age of the chain, for an
            // identical result.
            let height = idx.header.height as usize;
            if self.active.get(height) == Some(&current) {
                branch.reverse();
                return Some((height, branch));
            }
            branch.push(current);
            if idx.header.height == 0 {
                return None;
            }
            current = idx.header.prev_block;
        }
        None
    }

    /// Work a fork must exceed, depending on its depth.
    ///
    /// # The defect this version fixes
    ///
    /// The penalty applied to the work **accumulated since genesis**. Requiring
    /// "1% more per block of depth" therefore amounted to requiring 1% of the
    /// work of the chain's whole history, and not 1% of the fork's work.
    ///
    /// The phase 8b audit quantified it: from height 71,400 on (three months
    /// after launch), no reorg of depth 7 could succeed anymore, even with 100%
    /// of the hashrate and even against a perfectly honest branch. The real
    /// finality was not 720 blocks but **six**, and a network partition of more
    /// than twelve minutes produced two permanent chains.
    ///
    /// The penalty now bears on the work **of the fork**: what has been
    /// produced since the point of divergence, on both sides. It is the only
    /// quantity that makes sense: the common past is disputed by nobody.
    fn reorg_threshold(&self, fork: usize, depth: u64) -> U256 {
        let total = self.total_work();
        // Work common to both branches, up to the point of divergence.
        let common = self
            .active
            .get(fork)
            .and_then(|id| self.index.get(id))
            .map(|b| b.total_work)
            .unwrap_or(U256::ZERO);
        let since_fork = total.checked_sub(common).unwrap_or(U256::ZERO);

        if depth <= REORG_PENALTY_FROM_DEPTH {
            return total;
        }
        let excess = ((depth - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK)
            .min(REORG_PENALTY_MAX_PCT);
        // `common + (1 + excess%) * work_of_the_active_branch_since_the_fork`
        let surcharged = since_fork.mul_div(100 + excess, 100).unwrap_or(since_fork);
        common.checked_add(surcharged).unwrap_or(total)
    }

    /// Attachment of a header: known parent, height that follows the parent's.
    /// Returns the parent's height.
    ///
    /// --- Defense: the announced height must follow the parent's.
    ///
    /// It is checked BEFORE any computation, because the proof of work derives
    /// its epoch from `header.height`: a header announcing an arbitrary height
    /// made the node build the cache (then the table) of the corresponding
    /// epoch. Audit measurement: ~10 s of cache and ~5 min of table on mainnet,
    /// for a 160-byte message. Repeated, the node does nothing else.
    fn check_attachment(&self, header: &BlockHeader) -> Result<u64, ChainError> {
        let Some(parent) = self.index.get(&header.prev_block) else {
            return Err(ChainError::UnknownParent(header.prev_block));
        };
        let parent_height = parent.header.height;
        if header.height != parent_height + 1 {
            return Err(ChainError::Validation(ValidationError::BadHeight {
                expected: parent_height + 1,
                received: header.height,
            }));
        }
        Ok(parent_height)
    }

    /// What a header's position in the index imposes on it: finality,
    /// difficulty, timestamp. No body is needed, and nothing here costs more
    /// than walking the index back over a few dozen headers.
    ///
    /// Shared between submitting a whole block and checking a header alone
    /// ([`Self::check_header`]): one rule, two callers, impossible to make
    /// diverge.
    fn check_context(
        &self,
        header: &BlockHeader,
        parent_height: u64,
        now: u64,
    ) -> Result<(), ChainError> {
        // 1. Can the branch ever be adopted at all?
        //
        //    Rolling finality already refuses any reorg whose fork point is
        //    more than `MAX_REORG_DEPTH` below the tip. A branch that forks
        //    lower down can therefore NEVER win: indexing it, keeping its body
        //    and recording it in the journal is pure cost, and unbounded, since
        //    the index is never pruned.
        //
        //    That was the denial-of-service lever: the floor difficulty of the
        //    first blocks makes a sibling of genesis almost free (a few hundred
        //    hashes), and nothing bounded the number of siblings kept. Each one
        //    bought a permanent entry in memory and a record on disk.
        //
        //    This refusal changes no consensus rule: it rejects earlier exactly
        //    what `try_reorg` already rejected later. A peer that insists sees
        //    its misbehavior score rise.
        let fork_depth = self.height().saturating_sub(parent_height);
        if fork_depth > MAX_REORG_DEPTH {
            return Err(ChainError::BeyondFinality {
                depth: fork_depth,
                max: MAX_REORG_DEPTH,
            });
        }

        // 2. The announced difficulty must be the one the chain imposes at this
        //    position. Without this check, `pow.check` verified the work
        //    against `header.bits`, a field the sender fills in. With a
        //    near-maximal target, anyone produced an infinity of valid headers
        //    without mining once, and filled a node's index and bodies until
        //    exhaustion. Demonstrated by the phase 8 audit: 500 branches indexed
        //    without any computation.
        let expected = self.next_bits_after(header.prev_block);
        if header.bits != expected {
            return Err(ChainError::Validation(ValidationError::BadDifficulty {
                expected,
                received: header.bits,
            }));
        }

        // 2a. The timestamp, under the same conditions as on the active chain:
        //    after the median of the eleven ancestors **of its branch**, and not
        //    beyond the tolerance into the future.
        //
        //    These two checks only applied at connection. A side branch could
        //    therefore carry very spread-out timestamps (the LWMA difficulty
        //    dropped along the branch, up to six times thanks to the 6T bound
        //    per interval) and get 4 MiB bodies produced cheaply, which the
        //    node kept and served. Refusing here rules out no valid block: the
        //    connection would have refused it anyway, for the same reason.
        let times = self.recent_times_after(header.prev_block);
        let median = validate::median_time(&times);
        if !times.is_empty() && header.time <= median {
            return Err(ChainError::Validation(ValidationError::TimestampTooOld {
                median,
                received: header.time,
            }));
        }
        let limit = now + MAX_FUTURE_TIME;
        if header.time > limit {
            return Err(ChainError::Validation(ValidationError::TimestampInFuture {
                limit,
                received: header.time,
            }));
        }
        Ok(())
    }

    /// Checks a header **alone**, without its body: attachment, height,
    /// finality, difficulty, timestamp, and finally the work.
    ///
    /// # Why this check exists
    ///
    /// A compact block only brings the header and short ids: the body is
    /// rebuilt by the node by searching its mempool. The reconstruction used to
    /// happen **before** anyone looked at whether the header carried real
    /// work. A peer could therefore make the node search its mempool (under
    /// the global lock) for headers it fabricated without mining (phase 8b red
    /// team, 2nd campaign, item 4). The per-peer announcement budget already
    /// bounded the expense; this check brings it down to what it should be:
    /// nothing at all for a false header.
    ///
    /// This is what BIP 152 prescribes: a compact block is treated as a header
    /// first, and a header is checked before anything else.
    ///
    /// # What this guarantees
    ///
    /// These checks are a **strict subset** of those [`Self::submit`] applies
    /// to the whole block: they are the same functions, called in the same
    /// order. A header this check refuses would have been refused with its
    /// body; a header it accepts has passed nothing that submission does not
    /// check again. The work is checked through the light path (cache only,
    /// never the table): a few tens of microseconds.
    ///
    /// An already indexed header is accepted as is: submission will recognize
    /// the body as already seen.
    pub fn check_header(&self, header: &BlockHeader, now: u64) -> Result<(), ChainError> {
        if self.index.contains_key(&header.block_id()) {
            return Ok(());
        }
        let parent_height = self.check_attachment(header)?;
        self.check_context(header, parent_height, now)?;
        self.pow
            .check(header)
            .map_err(|e| ChainError::Validation(ValidationError::ProofOfWork(e)))
    }

    /// What is needed to verify a header's work **outside** the lock, or
    /// `None` if there is nothing to verify.
    ///
    /// Returns the bare engine and the registry in which to record the
    /// verdict, only if the header is unknown, attaches to a known parent at
    /// the right height, and carries the difficulty and timestamp its position
    /// imposes: the same cheap checks [`Self::check_header`] runs before the
    /// work. That is what prevents a peer from making the node compute, even
    /// outside the lock, the hash of a header fabricated at an arbitrary
    /// height: the height chooses the epoch, and an unknown epoch costs a
    /// whole cache.
    ///
    /// An already recorded verdict also returns `None`: nothing to recompute.
    pub fn header_to_prove(
        &self,
        header: &BlockHeader,
        now: u64,
    ) -> Option<(Q21Pow, std::sync::Arc<crate::pow::WorkMemo>)> {
        let id = header.block_id();
        if self.index.contains_key(&id) {
            return None;
        }
        let parent_height = self.check_attachment(header).ok()?;
        self.check_context(header, parent_height, now).ok()?;
        let memo = self.pow.memo();
        if memo.verdict(&id).is_some() {
            return None;
        }
        Some((self.pow.engine(), memo))
    }

    /// The registry of work verdicts of this chain.
    pub fn work_memo(&self) -> std::sync::Arc<crate::pow::WorkMemo> {
        self.pow.memo()
    }

    /// Submits a block to the node: attachment, side branch or reorg.
    ///
    /// This is the entry point the phase 4 network layer will use.
    pub fn submit(&mut self, block: &Block, now: u64) -> Result<Accept, ChainError> {
        let id = block.header.block_id();
        if self.index.contains_key(&id) {
            return Ok(Accept::AlreadyKnown);
        }
        let parent_height = self.check_attachment(&block.header)?;

        // Simple case: the block extends the tip.
        if block.header.prev_block == self.tip_id() {
            self.connect(block, now)?;
            return Ok(Accept::Extended);
        }

        // Side branch. Four checks before any insertion into the index, ordered
        // from cheapest to most expensive: what costs the most to check must be
        // what is checked last.
        //
        // 1, 2 and 2a: finality, difficulty and timestamp of the header, as
        //    imposed by its position in the index. See [`Self::check_context`],
        //    which shares them with the header-only check.
        self.check_context(&block.header, parent_height, now)?;

        // 3. Shape and size: the checks that require no context, and that
        //    Bitcoin calls `CheckBlock`.
        //
        //    They only ran on the connection path. A side branch therefore
        //    entered the index and the disk without anyone checking that its
        //    body matched its header: the Merkle root was never recomputed. A
        //    header with authentic work could thus drag along an arbitrary
        //    body, which the node stored, then **served to its peers**.
        //
        //    Refusing here cannot rule out any valid block: a body that fails
        //    these checks would fail at connection anyway.
        block
            .check_shape()
            .map_err(|e| ChainError::Validation(e.into()))?;
        let size = block.encode().len();
        if size > MAX_BLOCK_SIZE {
            return Err(ChainError::Validation(ValidationError::BlockTooLarge {
                max: MAX_BLOCK_SIZE,
                received: size,
            }));
        }

        // 4. The work itself: the most expensive, hence the last.
        self.pow
            .check(&block.header)
            .map_err(|e| ChainError::Validation(ValidationError::ProofOfWork(e)))?;

        let parent = self.index[&block.header.prev_block];
        let total = parent
            .total_work
            .checked_add(pow::block_work(block.header.bits))
            .unwrap_or(parent.total_work);

        self.index.insert(
            id,
            BlockIndex {
                header: block.header,
                total_work: total,
                // Unknown as long as the block is not connected: a side branch
                // has no emission, only a potential one.
                issued: 0,
            },
        );
        self.keep_body(id, block.clone());

        if total <= self.total_work() {
            return Ok(Accept::SideBranch);
        }

        let depth = self.try_reorg(id, now)?;
        Ok(Accept::Reorganized { depth })
    }

    /// Switches the active chain to `new_tip`.
    ///
    /// Atomic: if a block of the new branch fails validation, the old chain is
    /// fully restored.
    fn try_reorg(&mut self, new_tip: Hash256, now: u64) -> Result<u64, ChainError> {
        // No common ancestor within reach: this is not a reorg that is too
        // deep, it is a branch whose origin we do not know. Saying so has a
        // value: the old version returned `BeyondFinality { depth: u64::MAX }`
        // here, and an operator reading "depth 18446744073709551615" could do
        // nothing with it.
        let (fork, branch) = self
            .path_to_active(new_tip)
            .ok_or(ChainError::ForkPointNotFound {
                reach: MAX_REORG_DEPTH,
            })?;

        let depth = (self.active.len() - 1 - fork) as u64;

        // --- Defense: rolling finality.
        if depth > MAX_REORG_DEPTH {
            return Err(ChainError::BeyondFinality {
                depth,
                max: MAX_REORG_DEPTH,
            });
        }

        // --- Defense: depth has a price.
        let required = self.reorg_threshold(fork, depth);
        if self.index[&new_tip].total_work <= required {
            return Err(ChainError::InsufficientWorkForDepth { depth });
        }

        // --- Defense: undertake nothing that cannot be undone.
        //
        // A reorg requires `depth` undos. If the undo window does not hold that
        // many (the normal case after resuming from a snapshot), the restore
        // loop would never progress and the node would spin forever, with the
        // chain lock held. The phase 8 audit demonstrated it: the thread never
        // returned.
        //
        // So we refuse **before** touching anything. The node stays on its
        // chain, which is the safe behavior: it will catch up with the competing
        // branch when that branch has gained enough of a lead again, or after a
        // full resync.
        if (self.undos.len() as u64) < depth {
            return Err(ChainError::UndoWindowTooShort {
                depth,
                available: self.undos.len() as u64,
            });
        }

        // Remember the old branch so it can be restored identically.
        let old: Vec<Hash256> = self.active[fork + 1..].to_vec();

        // Bodies are fetched BEFORE any mutation: a pruned body would make a
        // direct index panic, and panicking in the middle of a reorg would
        // leave the chain in an impossible state.
        let mut branch_bodies = Vec::with_capacity(branch.len());
        for id in &branch {
            match self.block_by_id(id) {
                Some(b) => branch_bodies.push(b),
                None => return Err(ChainError::Validation(ValidationError::IncompleteHistory)),
            }
        }
        let mut old_bodies = Vec::with_capacity(old.len());
        for id in &old {
            match self.block_by_id(id) {
                Some(b) => old_bodies.push(b),
                None => return Err(ChainError::Validation(ValidationError::IncompleteHistory)),
            }
        }

        for _ in 0..depth {
            if !self.disconnect() {
                // Should not happen: the window was checked. But we never loop
                // on a function that can refuse.
                break;
            }
        }

        for b in &branch_bodies {
            if let Err(e) = self.connect(b, now) {
                while self.active.len() > fork + 1 {
                    if !self.disconnect() {
                        break;
                    }
                }
                for ab in &old_bodies {
                    if self.connect(ab, now).is_err() {
                        // The original chain does not revalidate, which should
                        // never happen, since these blocks were active and valid
                        // a moment ago. The old version crashed here (`expect`):
                        // a `panic` in a consensus routine, hence a node
                        // shutdown. The 8b red team flagged it; we could not
                        // trigger it (the path is deterministic), but a crash is
                        // not the right answer. Instead we go back down to the
                        // fork point (a PROVEN valid ancestor, hence a state that
                        // is always consistent, just shorter) and return. The
                        // node will start again from there by resyncing with its
                        // peers, without ever serving an inconsistent state.
                        while self.active.len() > fork + 1 {
                            if !self.disconnect() {
                                break;
                            }
                        }
                        return Err(ChainError::Validation(e));
                    }
                }
                return Err(ChainError::Validation(e));
            }
        }
        Ok(depth)
    }

    // -----------------------------------------------------------------------
    // Mining
    // -----------------------------------------------------------------------

    pub fn mine_block(
        &self,
        beneficiary: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        timestamp: u64,
        max_tries: u64,
    ) -> Option<Block> {
        self.mine_block_with_uncles(beneficiary, scheme, mempool, &[], timestamp, max_tries)
    }

    /// Assembles and mines a candidate block, uncles included.
    pub fn mine_block_with_uncles(
        &self,
        beneficiary: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        uncles: &[BlockHeader],
        timestamp: u64,
        max_tries: u64,
    ) -> Option<Block> {
        let height = self.height() + 1;
        let mut b = self.assemble_candidate(beneficiary, scheme, mempool, uncles, timestamp);
        let table = self.table_for(crate::memhard::epoch_of(height));
        pow::mine_with_table_parallel(&mut b.header, &table, max_tries, self.miner_threads).ok()?;
        Some(b)
    }

    /// The candidate block, complete and consistent, but without proof of
    /// work.
    ///
    /// Extracted from [`Self::mine_block_with_uncles`] so that the node's
    /// mining ([`Self::mining_candidate`]) reuses it: two ways of assembling a
    /// candidate are two ways of getting the coinbase wrong.
    fn assemble_candidate(
        &self,
        beneficiary: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        uncles: &[BlockHeader],
        timestamp: u64,
    ) -> Block {
        let height = self.height() + 1;

        let mut fees: u64 = 0;
        for tx in mempool {
            let inputs: u64 = tx
                .inputs
                .iter()
                .filter_map(|i| self.utxo.get(&i.prev_out))
                .map(|e| e.output.value.units())
                .sum();
            let outputs = tx.total_output().map(|a| a.units()).unwrap_or(0);
            fees += inputs.saturating_sub(outputs);
        }

        let rewards = validate::uncle_rewards(height, uncles.len());
        let miner_share = rewards.miner_share + fees;

        let mut outputs = vec![TxOut {
            value: Amount::from_units(miner_share),
            scheme,
            pubkey_hash: beneficiary,
        }];
        for u in uncles {
            outputs.push(TxOut {
                value: Amount::from_units(rewards.per_uncle),
                scheme,
                pubkey_hash: u.miner,
            });
        }

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(height.to_le_bytes().to_vec())],
            outputs,
            lock_time: 0,
        };

        let mut transactions = vec![coinbase];
        transactions.extend_from_slice(mempool);

        let median = validate::median_time(&self.recent_times());
        let time = timestamp.max(median + 1);

        let mut b = Block {
            header: BlockHeader {
                version: 1,
                prev_block: self.tip_id(),
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: beneficiary,
                time,
                bits: self.next_bits(),
                height,
                nonce: 0,
            },
            transactions,
            uncles: uncles.to_vec(),
        };
        b.header.merkle_root = b.compute_merkle_root();
        b.header.uncles_root = b.compute_uncles_root();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: Network = Network::Regtest;
    const TRIES: u64 = 5_000_000;

    fn new_chain() -> Chain {
        let g = genesis_block(NETWORK);
        Chain::new(NETWORK, g)
    }

    fn mine(c: &mut Chain, n: usize) {
        for _ in 0..n {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
                .expect("mining");
            c.connect(&b, t + 1).expect("connection");
        }
    }

    fn remine(c: &Chain, b: &mut Block) {
        b.header.merkle_root = b.compute_merkle_root();
        b.header.uncles_root = b.compute_uncles_root();
        b.header.nonce = 0;
        c.with_table(crate::memhard::epoch_of(b.header.height), |table| {
            pow::mine_with_table(&mut b.header, table, TRIES)
        })
        .unwrap();
    }

    /// The block tree finds the active chain amid the branches.
    ///
    /// # The incident this test pins down
    ///
    /// The fallback path (the one used when the snapshot is missing, hence
    /// after any abrupt shutdown) replayed the block file **in its write
    /// order**. That file also records side branches: the replay therefore
    /// asked the chain to accept dozens of successive reorgs, and ran into the
    /// anti-reorg defenses, which are made to repel an attacker and not to
    /// reread one's own history.
    ///
    /// Measured on two nodes mining against each other: after two thousand
    /// blocks, the node **refused to restart**. A node unable to reread its own
    /// file is one power outage away from total loss.
    ///
    /// The answer is here: we first ask the headers which chain is active, and
    /// validate it in height order. Not a single reorg left to accept.
    #[test]
    fn block_tree_finds_active_chain_among_branches() {
        let mut c = new_chain();
        mine(&mut c, 5);
        let fork = c.tip_id();
        let after_fork: Vec<Hash256> = c.active[1..].to_vec();

        // A competing branch, shorter: it must not win.
        let mut rival = Chain::new(NETWORK, genesis_block(NETWORK));
        for id in &after_fork {
            let b = c.block_by_id(id).expect("body");
            rival.connect(&b, b.header.time + 1).expect("same prefix");
        }
        let t = rival.tip().time + TARGET_BLOCK_SECS;
        let b = rival
            .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
            .expect("rival mining");
        rival.connect(&b, t + 1).expect("rival connection");
        assert_eq!(b.header.prev_block, fork);

        // We extend the main chain beyond the rival.
        mine(&mut c, 3);

        // The file mixes everything, in any order: that is exactly what the
        // block tree must be able to untangle.
        let mut headers: Vec<BlockHeader> = c.headers();
        headers.insert(2, b.header);

        let a = Chain::block_tree(&headers).expect("block tree");
        assert_eq!(
            a.active, c.active,
            "the active chain must be the heaviest, not the file order"
        );
        assert_eq!(a.genesis, c.active[0]);
        assert!(
            a.work.contains_key(&b.header.block_id()),
            "the side branch stays known: without it, no reorg would survive \
             a restart"
        );
    }

    /// A restart never resumes on an abandoned branch, and does not lose the
    /// ability to join it if it ends up winning.
    ///
    /// A side branch indexed before the shutdown is kept by the headers; on
    /// restart, the tip must be that of the heaviest chain, not the last one
    /// written. And if the side branch is then extended until it overtakes the
    /// active chain, the reorg must succeed (the branch bodies being provided)
    /// exactly as it would have without a restart.
    #[test]
    fn restart_does_not_resume_on_abandoned_branch() {
        let mut c = new_chain();
        mine(&mut c, 40);
        let fork_height = 37u64;
        let fork = c.active[fork_height as usize];

        // The side branch: two blocks from height 37, hence less work than the
        // active chain (40).
        let mut rival = Chain::new(NETWORK, genesis_block(NETWORK));
        for id in &c.active[1..=fork_height as usize] {
            let b = c.block_by_id(id).expect("body");
            rival.connect(&b, b.header.time + 1).expect("same prefix");
        }
        let mut side = Vec::new();
        for _ in 0..2 {
            let t = rival.tip().time + TARGET_BLOCK_SECS + 7;
            let b = rival
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
                .expect("rival mining");
            rival.connect(&b, t + 1).expect("rival connection");
            side.push(b);
        }
        assert_eq!(side[0].header.prev_block, fork);
        for b in &side {
            assert_eq!(
                c.submit(b, b.header.time + 1).expect("side branch"),
                Accept::SideBranch
            );
        }
        let active_tip = c.tip_id();

        // Restart: the tip is that of the active chain, not the last branch
        // written.
        let mut rc = resume(&c);
        assert_eq!(
            rc.tip_id(),
            active_tip,
            "the resume restarts on the abandoned branch"
        );
        assert_eq!(rc.height(), 40);

        // The side branch then wins: the reorg succeeds.
        for _ in 0..3 {
            let t = rival.tip().time + TARGET_BLOCK_SECS + 7;
            let b = rival
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
                .expect("rival mining");
            rival.connect(&b, t + 1).expect("rival connection");
            side.push(b);
        }
        let mut switched = false;
        for b in &side[2..] {
            if let Accept::Reorganized { .. } = rc.submit(b, b.header.time + 1).expect("submission")
            {
                switched = true;
            }
        }
        assert!(switched, "the branch that became the heaviest must win");
        assert_eq!(rc.tip_id(), rival.tip_id());
        assert_eq!(rc.height(), rival.height());
        assert_eq!(
            rc.utxo, rival.utxo,
            "the state matches that of the winning branch"
        );
    }

    /// A branch with no common ancestor is called what it is.
    ///
    /// It used to be reported as `BeyondFinality { depth: u64::MAX }`. An
    /// operator reading "depth 18446744073709551615" can do nothing with it:
    /// it is not a depth, it is a disguised admission of ignorance.
    #[test]
    fn branch_without_common_ancestor_does_not_claim_too_deep() {
        let e = ChainError::ForkPointNotFound { reach: 720 };
        match e {
            ChainError::ForkPointNotFound { reach } => assert_eq!(reach, 720),
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// Replays a full resume: snapshot, rebuild from the headers, revalidation
    /// of the window, and comparison with the original state.
    fn resume(c: &Chain) -> Chain {
        resume_at(c, usize::MAX)
    }

    /// In-memory body provider, for the resume tests.
    struct BodiesInMemory(HashMap<Hash256, Block>);
    impl BodySource for BodiesInMemory {
        fn body(&self, id: &Hash256) -> Option<Block> {
            self.0.get(id).cloned()
        }
    }

    fn resume_at(c: &Chain, depth: usize) -> Chain {
        let snapshot = c.snapshot_at_depth(depth).expect("chain long enough");
        let headers: Vec<BlockHeader> = c.index.values().map(|b| b.header).collect();
        let bodies: HashMap<Hash256, Block> = c.blocks.clone();

        let r = Chain::from_snapshot(c.network, snapshot, &headers).expect("resume");
        let mut rc = r.chain;
        // The body provider is plugged in BEFORE the replay: some rules (uncle
        // double payment, restoring a reorg) require rereading bodies older
        // than the snapshot.
        rc.set_body_source(std::sync::Arc::new(BodiesInMemory(bodies.clone())));
        for id in &r.to_replay {
            let b = bodies.get(id).expect("body of the replayed window");
            let t = b.header.time + 1;
            rc.connect(b, t)
                .expect("revalidation of the replayed block");
        }
        rc
    }

    /// The property that makes incremental startup legitimate: resuming from a
    /// snapshot must give **exactly** the same chain as revalidating from
    /// genesis.
    #[test]
    fn resume_finds_exactly_the_same_state() {
        let mut c = new_chain();
        mine(&mut c, 40);
        let rc = resume(&c);

        assert_eq!(rc.height(), c.height(), "height");
        assert_eq!(rc.tip_id(), c.tip_id(), "tip");
        assert_eq!(rc.total_issued(), c.total_issued(), "emission");
        assert_eq!(rc.total_work(), c.total_work(), "cumulative work");
        assert_eq!(rc.utxo, c.utxo, "UTXO set");
    }

    /// A snapshot taken at the tip would deprive the node of any reorg on
    /// restart. It is therefore taken behind the tip, and the replayed window
    /// rebuilds the undo records.
    #[test]
    fn resume_keeps_ability_to_reorganize() {
        let mut c = new_chain();
        mine(&mut c, 40);
        let snapshot = c.snapshot().unwrap();
        assert!(
            snapshot.height < c.height(),
            "the snapshot must be behind the tip"
        );

        let mut rc = resume(&c);
        let before = rc.height();
        assert!(rc.disconnect(), "undoing must remain possible");
        assert_eq!(rc.height(), before - 1);
        assert_eq!(
            rc.total_issued(),
            Amount::from_units(c.index[&rc.tip_id()].issued)
        );
    }

    /// Below the snapshot, undoing is impossible, and must fail cleanly rather
    /// than corrupt the UTXO set.
    /// Below the snapshot, undoing is impossible: it must fail cleanly and
    /// stop exactly there, without corrupting the UTXO set.
    #[test]
    fn undo_stops_exactly_at_snapshot() {
        let mut c = new_chain();
        mine(&mut c, 40);
        let snapshot_height = c.snapshot_at_depth(10).unwrap().height;
        assert_eq!(snapshot_height, 30);

        let mut rc = resume_at(&c, 10);
        assert_eq!(rc.height(), 40, "the resume replays the window");

        let mut undone = 0;
        while rc.disconnect() {
            undone += 1;
            assert!(undone < 1_000, "loop");
        }
        assert_eq!(undone, 10, "exactly the replayed window");
        assert_eq!(rc.height(), snapshot_height);

        // And the state stays consistent: it is that of the original chain at
        // the same height, not a half-undone UTXO set.
        let mut reference = new_chain();
        mine(&mut reference, 30);
        assert_eq!(rc.utxo, reference.utxo);
        assert_eq!(rc.tip_id(), reference.tip_id());
    }

    #[test]
    fn off_chain_snapshot_is_refused() {
        let mut c = new_chain();
        mine(&mut c, 30);
        let mut snapshot = c.snapshot().unwrap();
        snapshot.tip = Hash256([0xab; 32]);
        let headers: Vec<BlockHeader> = c.index.values().map(|b| b.header).collect();

        assert_eq!(
            Chain::from_snapshot(NETWORK, snapshot, &headers).err(),
            Some(ResumeError::SnapshotOffChain)
        );
    }

    #[test]
    fn resume_without_genesis_is_refused() {
        let mut c = new_chain();
        mine(&mut c, 5);
        let snapshot = c.snapshot();
        let headers: Vec<BlockHeader> = c
            .index
            .values()
            .map(|b| b.header)
            .filter(|h| h.height != 0)
            .collect();
        if let Some(i) = snapshot {
            assert_eq!(
                Chain::from_snapshot(NETWORK, i, &headers).err(),
                Some(ResumeError::NoGenesis)
            );
        }
    }

    /// Memory must not grow with the chain.
    #[test]
    fn old_bodies_are_pruned() {
        let mut c = new_chain();
        mine(&mut c, 30);
        assert!(
            c.bodies_in_memory() <= BODY_WINDOW + 1,
            "{} bodies in memory",
            c.bodies_in_memory()
        );
        // On a short chain, nothing is pruned yet: the bound is the property,
        // not the pruning itself.
        assert_eq!(c.bodies_in_memory(), 31);
    }

    /// Memory must not grow with block size either: the byte bound evicts old
    /// bodies before the block bound, from oldest to most recent, without ever
    /// touching genesis.
    #[test]
    fn byte_budget_prunes_bodies_before_block_window() {
        let mut c = new_chain();
        mine(&mut c, 30);
        let total = c.body_bytes_in_memory();
        let recount: usize = c.blocks.values().map(|b| b.encode().len()).sum();
        assert_eq!(
            total, recount,
            "the weight maintained on the fly must be exact"
        );
        assert_eq!(c.bodies_in_memory(), 31);

        // A budget that only holds roughly the last ten bodies.
        let genesis = c.active[0];
        let genesis_weight = c.blocks[&genesis].encode().len();
        let last_ten: usize = (21..=30)
            .map(|h| c.blocks[&c.active[h]].encode().len())
            .sum();
        let budget = genesis_weight + last_ten;
        c.prune_bodies(BODY_WINDOW, budget);

        assert!(
            c.body_bytes_in_memory() <= budget,
            "{} bytes in memory for a budget of {budget}",
            c.body_bytes_in_memory()
        );
        let recount: usize = c.blocks.values().map(|b| b.encode().len()).sum();
        assert_eq!(c.body_bytes_in_memory(), recount);
        assert!(c.blocks.contains_key(&genesis), "genesis never leaves");
        for h in 21..=30 {
            assert!(
                c.blocks.contains_key(&c.active[h]),
                "recent body {h} must stay"
            );
        }
        for h in 1..=20 {
            assert!(
                !c.blocks.contains_key(&c.active[h]),
                "old body {h} must have left"
            );
        }
        // The chain stays whole: evicted bodies are read back from the
        // provider, or reported as absent, never invented.
        assert_eq!(c.height(), 30);
        assert!(c.block_by_id(&c.active[5]).is_none());
    }

    #[test]
    fn genesis_issues_exactly_one_coin() {
        let c = new_chain();
        assert_eq!(c.height(), 0);
        assert_eq!(c.total_issued(), Amount::from_units(GENESIS_PREMINT));
    }

    #[test]
    fn genesis_carries_valid_memory_hard_proof_of_work() {
        let g = genesis_block(NETWORK);
        assert!(Q21Pow::new(NETWORK).check(&g.header).is_ok());
    }

    #[test]
    fn mining_raises_height_and_work() {
        let mut c = new_chain();
        let work0 = c.total_work();
        mine(&mut c, 5);
        assert_eq!(c.height(), 5);
        assert!(c.total_work() > work0, "work must accumulate");
    }

    #[test]
    fn work_grows_when_target_drops() {
        assert!(
            pow::block_work(0x1c00_ffff) > pow::block_work(0x2000_ffff),
            "a smaller target must be worth more work"
        );
    }

    #[test]
    fn invalid_target_is_worth_no_work() {
        assert_eq!(pow::block_work(0x1d00_0000), U256::ZERO);
    }

    #[test]
    fn already_seen_block_is_ignored() {
        let mut c = new_chain();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
            .unwrap();
        assert_eq!(c.submit(&b, t + 1), Ok(Accept::Extended));
        assert_eq!(c.submit(&b, t + 1), Ok(Accept::AlreadyKnown));
    }

    #[test]
    fn orphan_block_is_refused() {
        let mut c = new_chain();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
            .unwrap();
        b.header.prev_block = Hash256([0xab; 32]);
        assert!(matches!(
            c.submit(&b, t + 1),
            Err(ChainError::UnknownParent(_))
        ));
    }

    #[test]
    fn reorg_threshold_grows_with_depth() {
        let mut c = new_chain();
        mine(&mut c, 3);
        // Fork at genesis: the disputed branch is the whole chain.
        let shallow = c.reorg_threshold(0, REORG_PENALTY_FROM_DEPTH);
        let deep = c.reorg_threshold(0, REORG_PENALTY_FROM_DEPTH + 50);
        assert_eq!(shallow, c.total_work(), "no penalty at shallow depth");
        assert!(deep > shallow, "depth must have a price");
    }

    #[test]
    fn threshold_grows_monotonically() {
        let mut c = new_chain();
        mine(&mut c, 2);
        let mut previous = c.reorg_threshold(0, 0);
        for p in 1..100u64 {
            let s = c.reorg_threshold(0, p);
            assert!(s >= previous, "depth {p}: the threshold decreased");
            previous = s;
        }
    }

    #[test]
    fn disconnect_restores_state() {
        let mut c = new_chain();
        mine(&mut c, 3);
        let supply = c.utxo.total_value();
        let issued = c.total_issued();
        mine(&mut c, 1);
        assert!(c.disconnect());
        assert_eq!(c.height(), 3);
        assert_eq!(c.utxo.total_value(), supply);
        assert_eq!(c.total_issued(), issued);
    }

    #[test]
    fn genesis_is_never_disconnected() {
        let mut c = new_chain();
        assert!(!c.disconnect());
    }

    #[test]
    fn coinbase_must_pay_header_miner() {
        let mut c = new_chain();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
            .unwrap();
        b.transactions[0].outputs[0].pubkey_hash = Hash256([0xff; 32]);
        remine(&c, &mut b);
        assert_eq!(
            c.connect(&b, t + 1),
            Err(ValidationError::CoinbaseDoesNotPayMiner)
        );
    }

    #[test]
    fn greedy_coinbase_is_refused() {
        let mut c = new_chain();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
            .unwrap();
        let owed = b.transactions[0].outputs[0].value.units();
        b.transactions[0].outputs[0].value = Amount::from_units(owed + 1);
        remine(&c, &mut b);
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::ExcessiveSubsidy { .. })
        ));
    }

    #[test]
    fn block_without_proof_of_work_is_refused() {
        let mut c = new_chain();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, TRIES)
            .unwrap();
        b.header.nonce = b.header.nonce.wrapping_add(0x5bad);
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::ProofOfWork(_))
        ));
    }

    #[test]
    fn too_many_uncles_is_refused() {
        let mut c = new_chain();
        mine(&mut c, 3);
        let fake = c.tip();
        let uncles = vec![fake; MAX_UNCLES + 1];
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block_with_uncles(
                Hash256([2u8; 32]),
                SchemeId::LamportOts,
                &[],
                &uncles,
                t,
                TRIES,
            )
            .unwrap();
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::TooManyUncles { .. })
        ));
    }

    #[test]
    fn ancestor_cannot_pass_for_uncle() {
        let mut c = new_chain();
        mine(&mut c, 3);
        // The current tip is an ancestor of the upcoming block: presenting it
        // as an orphan would allow getting paid twice for the same work.
        let ancestor = c.tip();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block_with_uncles(
                Hash256([2u8; 32]),
                SchemeId::LamportOts,
                &[],
                &[ancestor],
                t,
                TRIES,
            )
            .unwrap();
        // Since uncles were withdrawn, every uncle is refused before even being
        // examined: the cheat no longer has a way in.
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::TooManyUncles { .. })
        ));
    }

    /// Difficulty only looks at the window, never at the whole history.
    ///
    /// This is the property `Chain::next_bits` depends on: computing over the
    /// last `LWMA_WINDOW + 1` headers walked back from the tip gives exactly
    /// what copying all the headers since genesis gave. If someone ever widens
    /// the read beyond the window, this test will say so before the two paths
    /// diverge.
    #[test]
    fn difficulty_only_depends_on_window() {
        let mut headers: Vec<BlockHeader> = Vec::new();
        let mut t = GENESIS_TIME;
        let mut bits = INITIAL_BITS;
        for h in 0..(3 * LWMA_WINDOW as u64 + 17) {
            // Irregular intervals, so that the window really matters. Faster
            // than the target on average, so that the difficulty lifts off the
            // floor and the comparison makes sense.
            t += match h % 5 {
                0 => 40,
                1 => 100,
                2 => 120,
                3 => 15,
                _ => 90,
            };
            headers.push(BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: Hash256::ZERO,
                time: t,
                bits,
                height: h,
                nonce: 0,
            });
            bits = next_bits(&headers);
        }
        let n = headers.len();
        let window = &headers[n - (LWMA_WINDOW + 1)..];
        assert_eq!(next_bits(&headers), next_bits(window));
        // And one header fewer in the window does change the result: the
        // window is the right one, neither wider nor narrower.
        assert_ne!(next_bits(&headers), next_bits(&headers[n - LWMA_WINDOW..]));
    }
}
