//! Consensus rules.
//!
//! This file decides what is valid. It is the only place in the project where
//! a mistake does not produce a bug but a chain split: two nodes that do not
//! give the same answer to "is this block valid?" are no longer on the same
//! network.
//!
//! The rules are therefore written one by one, named, and each has its test.
//! None is implicit.
//!
//! # What this module does not do
//!
//! It does not choose between two competing chains: that is the role of
//! [`crate::chain`]. It answers a local question: is this block, in that
//! state, acceptable?

use crate::address::Network;
use crate::amount::Amount;
use crate::block::{Block, BlockError};
use crate::consensus::*;
use crate::emission::block_subsidy;
use crate::pow::{PowEngine, PowError};
use crate::sig::{self, SchemeId, VerifyError};
use crate::tx::{OutPoint, Transaction, TxError};
use crate::utxo::{UtxoSet, UtxoView};
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValidationError {
    Structure(BlockError),
    Transaction(TxError),
    ProofOfWork(PowError),

    // --- Chaining ---
    BadHeight {
        expected: u64,
        received: u64,
    },
    BadParent,
    BadDifficulty {
        expected: u32,
        received: u32,
    },

    // --- Timestamp ---
    TimestampTooOld {
        median: u64,
        received: u64,
    },
    TimestampInFuture {
        limit: u64,
        received: u64,
    },

    // --- Size ---
    BlockTooLarge {
        max: usize,
        received: usize,
    },

    // --- Value ---
    MissingInput(OutPoint),
    DoubleSpend(OutPoint),
    CoinbaseImmature {
        available_at: u64,
        height: u64,
    },
    ValueNotConserved {
        inputs: u64,
        outputs: u64,
    },
    ExcessiveSubsidy {
        allowed: u64,
        claimed: u64,
    },
    FeeOverflow,

    // --- Uncles ---
    TooManyUncles {
        max: usize,
        received: usize,
    },
    DuplicateUncle(crate::hash::Hash256),
    UncleTooOld {
        age: u64,
        max: u64,
    },
    UncleInFuture,
    OrphanUncle,
    UncleAlreadyClaimed(crate::hash::Hash256),
    UncleIsAncestor,
    UncleProofOfWork(PowError),
    /// The coinbase does not pay the miner announced in the header.
    CoinbaseDoesNotPayMiner,
    /// The coinbase does not pay its share to an included uncle.
    UncleNotRewarded {
        index: usize,
    },

    /// An uncle carries a difficulty different from the one expected at its
    /// height.
    BadUncleDifficulty {
        expected: u32,
        received: u32,
    },
    /// This block would take the cumulative emission beyond the absolute cap.
    CapExceeded {
        cumulative: u64,
        emission: u64,
        cap: u64,
    },
    /// The coinbase does not commit to its height: two blocks could share the
    /// same transaction id.
    CoinbaseWithoutHeight,
    /// A recent block body is missing: impossible to check a rule that depends
    /// on it. We refuse rather than validate blindly.
    IncompleteHistory,

    // --- Signatures ---
    KeyDoesNotMatchLock,
    SchemeForbiddenOnNetwork(SchemeId),
    Signature(VerifyError),

    // --- Dust ---
    /// An output below [`MIN_OUTPUT_VALUE`]: it would occupy the UTXO set of
    /// every node without ever being worth the price of its own spend.
    DustOutput {
        minimum: u64,
        received: u64,
    },
}

impl ValidationError {
    /// Does the refusal come from **this binary**, which cannot verify the
    /// scheme, rather than from the block?
    ///
    /// `SchemeUnavailable` only covers a scheme **known** to the protocol but
    /// absent from this build (`--no-default-features`). An unknown id does
    /// not pass decoding and remains the sender's fault. When this function
    /// answers, nobody lied and nothing must be penalized or disconnected: it
    /// is the software that is not equipped to judge. The binary refuses to
    /// start in that state outside regtest anyway; this is belt and
    /// suspenders.
    pub fn locally_unverifiable_scheme(&self) -> Option<SchemeId> {
        match self {
            ValidationError::Signature(VerifyError::SchemeUnavailable(s)) => Some(*s),
            _ => None,
        }
    }
}

impl From<BlockError> for ValidationError {
    fn from(e: BlockError) -> Self {
        ValidationError::Structure(e)
    }
}
impl From<TxError> for ValidationError {
    fn from(e: TxError) -> Self {
        ValidationError::Transaction(e)
    }
}
impl From<PowError> for ValidationError {
    fn from(e: PowError) -> Self {
        ValidationError::ProofOfWork(e)
    }
}

/// Context needed to validate a block: what the chain already knows.
pub struct BlockContext<'a> {
    pub network: Network,
    pub height: u64,
    pub prev_id: crate::hash::Hash256,
    /// Timestamps of the last `MEDIAN_TIME_SPAN` blocks, in any order.
    pub recent_times: &'a [u64],
    pub expected_bits: u32,
    /// Current time, injected rather than read: a consensus that calls the
    /// system clock cannot be tested deterministically.
    pub now: u64,
    /// Ids of the recent ancestors, from the parent backward.
    ///
    /// Used to check that an uncle does attach to the current branch and that
    /// it is not already part of it.
    pub ancestors: &'a [crate::hash::Hash256],
    /// Uncles already claimed by recent blocks.
    ///
    /// Without this check, two successive blocks could collect the reward for
    /// the same orphaned work twice.
    pub claimed_uncles: &'a HashSet<crate::hash::Hash256>,
    /// Expected difficulty for a child of each recent ancestor.
    ///
    /// An uncle is the sibling of a block of the active chain: it must carry
    /// the same difficulty as that block. Without this check, an uncle's proof
    /// of work was checked against `header.bits`, a field its author fills
    /// in, hence against a target of its choosing. Crafting an uncle then cost
    /// no computation at all.
    pub uncle_expected_bits: &'a HashMap<crate::hash::Hash256, u32>,
    /// Total already issued before this block, in units.
    ///
    /// Used for the last line of defense: no block can take the cumulative
    /// emission beyond [`MAX_SUPPLY`]. This rule depends on no schedule, no
    /// subsidy and no uncle: it holds even if everything else is wrong.
    pub cumulative_issued: u64,
}

/// Uncle-related rewards, in indivisible units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UncleRewards {
    /// Share paid to each uncle miner, **taken from the subsidy**.
    pub per_uncle: u64,
    /// What remains for the block's miner, excluding fees.
    pub miner_share: u64,
}

/// Computes the split of the subsidy between the miner and the uncles.
///
/// # The invariant this function carries
///
/// `miner_share + n_uncles * per_uncle == subsidy(height)`, always.
///
/// The previous version **added** the uncle shares to the subsidy, plus an
/// inclusion bonus. A block could therefore issue 210% of its subsidy, and the
/// maximum emission of the protocol reached 44,099,999 Q21 for an announced
/// cap of 21,000,001. A cap that a consensus rule can exceed is not a cap.
pub fn uncle_rewards(height: u64, n_uncles: usize) -> UncleRewards {
    let base = block_subsidy(height).units();
    let per_uncle = base / 100 * UNCLE_REWARD_PCT;
    // `saturating` out of caution: `n_uncles` is already bounded by MAX_UNCLES
    // upstream, but this function is public and must not depend on the order
    // of its caller's checks.
    let paid_out = per_uncle.saturating_mul(n_uncles as u64);
    UncleRewards {
        per_uncle,
        miner_share: base.saturating_sub(paid_out),
    }
}

/// Checks the uncles attached to a block.
///
/// Each rule answers a specific cheat, named in a comment. An uncle is real
/// work that lost a propagation race: we pay for it, but we check that it is
/// what it claims to be.
pub fn check_uncles<E: PowEngine>(
    block: &Block,
    ctx: &BlockContext<'_>,
    pow: &E,
) -> Result<(), ValidationError> {
    if block.uncles.len() > MAX_UNCLES {
        return Err(ValidationError::TooManyUncles {
            max: MAX_UNCLES,
            received: block.uncles.len(),
        });
    }

    let mut seen: HashSet<crate::hash::Hash256> = HashSet::new();
    let ancestors: HashSet<crate::hash::Hash256> = ctx.ancestors.iter().copied().collect();

    for uncle in &block.uncles {
        let id = uncle.block_id();

        // Cheat: including the same uncle twice in a block.
        if !seen.insert(id) {
            return Err(ValidationError::DuplicateUncle(id));
        }

        // Cheat: collecting work already paid to a previous block.
        if ctx.claimed_uncles.contains(&id) {
            return Err(ValidationError::UncleAlreadyClaimed(id));
        }

        // Cheat: presenting an ancestor of the main chain as an orphan, and
        // getting paid a second time for the same block.
        if ancestors.contains(&id) {
            return Err(ValidationError::UncleIsAncestor);
        }

        // Cheat: accumulating old orphans and collecting them all at once.
        if uncle.height >= ctx.height {
            return Err(ValidationError::UncleInFuture);
        }
        let age = ctx.height - uncle.height;
        if age > MAX_UNCLE_AGE {
            return Err(ValidationError::UncleTooOld {
                age,
                max: MAX_UNCLE_AGE,
            });
        }

        // Cheat: inventing an uncle out of nowhere. Its parent must belong to
        // the current branch.
        if !ancestors.contains(&uncle.prev_block) {
            return Err(ValidationError::OrphanUncle);
        }

        // Cheat: choosing one's own difficulty.
        //
        // `pow.check` decodes the target from `uncle.bits`, which its author
        // fills in. Without the comparison that follows, a header carrying a
        // near-maximal target passed without any computation having been done,
        // and the block that included it got paid for that nonexistent work.
        let expected = ctx
            .uncle_expected_bits
            .get(&uncle.prev_block)
            .copied()
            .ok_or(ValidationError::OrphanUncle)?;
        if uncle.bits != expected {
            return Err(ValidationError::BadUncleDifficulty {
                expected,
                received: uncle.bits,
            });
        }

        // Cheat: crafting a header without spending any work.
        pow.check(uncle)
            .map_err(ValidationError::UncleProofOfWork)?;
    }
    Ok(())
}

/// Median of recent timestamps.
pub fn median_time(times: &[u64]) -> u64 {
    if times.is_empty() {
        return 0;
    }
    let mut v: Vec<u64> = times.iter().rev().take(MEDIAN_TIME_SPAN).copied().collect();
    v.sort_unstable();
    v[v.len() / 2]
}

/// Checks a single transaction against the UTXO set.
///
/// Returns the fee it yields. The coinbase is not handled here.
pub fn check_transaction<V: UtxoView + ?Sized>(
    tx: &Transaction,
    utxo: &V,
    network: Network,
    height: u64,
    already_seen: &mut HashSet<OutPoint>,
) -> Result<Amount, ValidationError> {
    tx.check_shape()?;

    // --- Rule: outputs must use an allowed scheme, and must not be dust.
    //
    // Before the inputs: these checks cost nothing, signature verification
    // costs a lot. We refuse the cheap things first.
    for output in &tx.outputs {
        if !output.scheme.allowed_on(network) {
            return Err(ValidationError::SchemeForbiddenOnNetwork(output.scheme));
        }
        if output.value.units() < MIN_OUTPUT_VALUE {
            return Err(ValidationError::DustOutput {
                minimum: MIN_OUTPUT_VALUE,
                received: output.value.units(),
            });
        }
    }

    let mut total_inputs: u64 = 0;

    for (i, input) in tx.inputs.iter().enumerate() {
        // --- Rule: never the same output twice, neither in this block nor
        //     elsewhere.
        if !already_seen.insert(input.prev_out) {
            return Err(ValidationError::DoubleSpend(input.prev_out));
        }

        let e = utxo
            .lookup(&input.prev_out)
            .ok_or(ValidationError::MissingInput(input.prev_out))?;

        // --- Rule: coinbase maturity.
        if e.is_coinbase && height < e.height + COINBASE_MATURITY {
            return Err(ValidationError::CoinbaseImmature {
                available_at: e.height + COINBASE_MATURITY,
                height,
            });
        }

        // --- Rule: the scheme must be allowed on this network.
        if !e.output.scheme.allowed_on(network) {
            return Err(ValidationError::SchemeForbiddenOnNetwork(e.output.scheme));
        }

        // --- Rule: the key presented must match the lock.
        let key_hash = sig::pubkey_hash(e.output.scheme, &input.witness.pubkey);
        if key_hash != e.output.pubkey_hash {
            return Err(ValidationError::KeyDoesNotMatchLock);
        }

        // --- Rule: the signature must verify against this input's hash.
        let message = tx.sighash(i as u32, network, &e.output);
        sig::verify(
            e.output.scheme,
            &input.witness.pubkey,
            &message,
            &input.witness.signature,
        )
        .map_err(ValidationError::Signature)?;

        total_inputs = total_inputs
            .checked_add(e.output.value.units())
            .ok_or(ValidationError::FeeOverflow)?;
    }

    // --- Rule: conservation of value. No money is created.
    let total_outputs = tx.total_output()?.units();
    if total_outputs > total_inputs {
        return Err(ValidationError::ValueNotConserved {
            inputs: total_inputs,
            outputs: total_outputs,
        });
    }

    Ok(Amount::from_units(total_inputs - total_outputs))
}

/// The UTXO set as seen by the `n`-th transaction of a block: the confirmed
/// set, plus the outputs created by the previous transactions of the block,
/// minus those they consumed.
struct BlockView<'a> {
    confirmed: &'a UtxoSet,
    created: HashMap<OutPoint, crate::utxo::UtxoEntry>,
    spent: HashSet<OutPoint>,
}

impl BlockView<'_> {
    /// Applies a validated transaction: its inputs disappear, its outputs
    /// appear for the following transactions of the block.
    fn apply(&mut self, tx: &Transaction, height: u64) {
        for e in &tx.inputs {
            self.spent.insert(e.prev_out);
        }
        let id = tx.txid();
        for (i, o) in tx.outputs.iter().enumerate() {
            self.created.insert(
                OutPoint {
                    txid: id,
                    index: i as u32,
                },
                crate::utxo::UtxoEntry {
                    output: *o,
                    height,
                    is_coinbase: false,
                },
            );
        }
    }
}

impl UtxoView for BlockView<'_> {
    fn lookup(&self, o: &OutPoint) -> Option<crate::utxo::UtxoEntry> {
        if self.spent.contains(o) {
            return None;
        }
        self.created
            .get(o)
            .copied()
            .or_else(|| self.confirmed.lookup(o))
    }
}

/// Validates a full block.
pub fn check_block<E: PowEngine>(
    block: &Block,
    utxo: &UtxoSet,
    ctx: &BlockContext<'_>,
    pow: &E,
) -> Result<Amount, ValidationError> {
    // --- Rule: size.
    //
    // From cheapest to most expensive: size, chaining, difficulty, timestamps
    // and proof of work are checked in microseconds; shape (which rehashes the
    // whole body for the Merkle roots) comes next, and signatures last. A
    // block without proof of work therefore no longer makes us hash four
    // mebibytes.
    let size = block.encode().len();
    if size > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge {
            max: MAX_BLOCK_SIZE,
            received: size,
        });
    }

    // --- Rule: chaining.
    if block.header.height != ctx.height {
        return Err(ValidationError::BadHeight {
            expected: ctx.height,
            received: block.header.height,
        });
    }
    if block.header.prev_block != ctx.prev_id {
        return Err(ValidationError::BadParent);
    }

    // --- Rule: difficulty imposed by the chain, not chosen by the miner.
    if block.header.bits != ctx.expected_bits {
        return Err(ValidationError::BadDifficulty {
            expected: ctx.expected_bits,
            received: block.header.bits,
        });
    }

    // --- Rule: timestamp after the recent median.
    let median = median_time(ctx.recent_times);
    if !ctx.recent_times.is_empty() && block.header.time <= median {
        return Err(ValidationError::TimestampTooOld {
            median,
            received: block.header.time,
        });
    }

    // --- Rule: timestamp not too far in the future.
    let limit = ctx.now + MAX_FUTURE_TIME;
    if block.header.time > limit {
        return Err(ValidationError::TimestampInFuture {
            limit,
            received: block.header.time,
        });
    }

    // --- Rule: proof of work.
    pow.check(&block.header)?;

    // --- Rule: structure, single coinbase, Merkle roots.
    block.check_shape()?;

    // --- Rule: every transaction valid, no double spend.
    //
    // Transactions are validated **in order**, against a view that overlays
    // on the confirmed set the outputs created earlier in this block. Without
    // that view, a transaction spending the output of a previous transaction
    // of the same block (a payment then the spend of its change, which the
    // mempool accepts and block selection packs in parent-before-child order)
    // was refused (`MissingInput`): the miner built an invalid block, lost its
    // work, and built it again on the next round. Order is still enforced: an
    // output created further down the block does not exist yet, and an output
    // already consumed by a previous transaction no longer exists.
    let mut already_seen: HashSet<OutPoint> = HashSet::new();
    let mut total_fees: u64 = 0;
    let mut view = BlockView {
        confirmed: utxo,
        created: HashMap::new(),
        spent: HashSet::new(),
    };
    for tx in &block.transactions[1..] {
        let f = check_transaction(tx, &view, ctx.network, ctx.height, &mut already_seen)?;
        total_fees = total_fees
            .checked_add(f.units())
            .ok_or(ValidationError::FeeOverflow)?;
        view.apply(tx, ctx.height);
    }

    // --- Rule: the uncles are valid.
    check_uncles(block, ctx, pow)?;

    // --- Rule: the coinbase does not take more than it is owed.
    //
    // This is the anti-inflation rule. It and the conservation of value are
    // the only two things that prevent money from being created, including
    // for an attacker holding 51% of the hashrate, who can reorganize blocks
    // but never create more money.
    let coinbase = &block.transactions[0];
    let rewards = uncle_rewards(ctx.height, block.uncles.len());

    // --- Rule: no dust in the coinbase either.
    //
    // A miner that pays fees pays them to itself: only the locking up of
    // capital slows it down, and that goes through this floor. Genesis is
    // exempt: it carries the unspendable unit of the cap.
    if ctx.height > 0 {
        for output in &coinbase.outputs {
            if output.value.units() < MIN_OUTPUT_VALUE {
                return Err(ValidationError::DustOutput {
                    minimum: MIN_OUTPUT_VALUE,
                    received: output.value.units(),
                });
            }
        }
    }

    // --- Rule: the coinbase commits to its height.
    //
    // Without it, two coinbases by the same miner for the same amount have the
    // same transaction id: the second overwrites the first in the UTXO set,
    // and undoing the second destroys the output of the first. Two honest
    // nodes then end up with the same tip and different UTXO sets: a silent
    // split. This is the lesson of BIP 30 and BIP 34 in Bitcoin, learned here
    // through an adversarial audit.
    let marker = ctx.height.to_le_bytes();
    if !coinbase.inputs[0].witness.signature.starts_with(&marker) {
        return Err(ValidationError::CoinbaseWithoutHeight);
    }

    // Required structure: the miner first, then one payment per uncle.
    if coinbase.outputs.len() != 1 + block.uncles.len() {
        return Err(ValidationError::UncleNotRewarded { index: 0 });
    }
    if coinbase.outputs[0].pubkey_hash != block.header.miner {
        return Err(ValidationError::CoinbaseDoesNotPayMiner);
    }
    for (i, uncle) in block.uncles.iter().enumerate() {
        let output = &coinbase.outputs[i + 1];
        if output.pubkey_hash != uncle.miner || output.value.units() != rewards.per_uncle {
            return Err(ValidationError::UncleNotRewarded { index: i });
        }
    }

    // The miner's share is what remains of the subsidy, plus fees. Uncle
    // shares are taken from it, never added.
    let miner_allowed = rewards
        .miner_share
        .checked_add(total_fees)
        .ok_or(ValidationError::FeeOverflow)?;
    let claimed = coinbase.outputs[0].value.units();
    if claimed > miner_allowed {
        return Err(ValidationError::ExcessiveSubsidy {
            allowed: miner_allowed,
            claimed,
        });
    }

    // --- Rule: the absolute cap. The last line of defense.
    //
    // Everything above is a schedule; this is a bound. It depends neither on
    // the subsidy, nor on uncles, nor on fees: it compares the cumulative
    // emission to the cap and refuses anything that would exceed it. Even if
    // an economic rule turned out to be wrong (it happened, twice), no block
    // can take the emission beyond 21,000,001 Q21.
    let total_coinbase = coinbase
        .total_output()
        .map_err(|_| ValidationError::FeeOverflow)?
        .units();
    let emission = total_coinbase.saturating_sub(total_fees);
    let cumulative = ctx
        .cumulative_issued
        .checked_add(emission)
        .ok_or(ValidationError::FeeOverflow)?;
    if cumulative > MAX_SUPPLY {
        return Err(ValidationError::CapExceeded {
            cumulative: ctx.cumulative_issued,
            emission,
            cap: MAX_SUPPLY,
        });
    }

    // --- Rule: the coinbase outputs respect the network.
    for output in &block.transactions[0].outputs {
        if !output.scheme.allowed_on(ctx.network) {
            return Err(ValidationError::SchemeForbiddenOnNetwork(output.scheme));
        }
    }

    Ok(Amount::from_units(total_fees))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash256;

    #[test]
    fn median_ignores_an_outlier() {
        let t = [100u64, 101, 102, 103, 999_999];
        assert_eq!(median_time(&t), 102);
    }

    #[test]
    fn median_handles_edge_cases() {
        assert_eq!(median_time(&[]), 0);
        assert_eq!(median_time(&[42]), 42);
        assert_eq!(median_time(&[2, 1]), 2);
    }

    #[test]
    fn median_only_looks_at_the_window() {
        // Twenty old blocks at 0, eleven recent ones at 1000: the median must
        // follow the recent ones.
        let mut t = vec![0u64; 20];
        t.extend(vec![1000u64; MEDIAN_TIME_SPAN]);
        assert_eq!(median_time(&t), 1000);
    }

    #[test]
    fn lamport_is_refused_on_mainnet() {
        assert!(!SchemeId::LamportOts.allowed_on(Network::Mainnet));
        assert!(SchemeId::LamportOts.allowed_on(Network::Testnet));
        assert!(SchemeId::LamportOts.allowed_on(Network::Regtest));
    }

    #[test]
    fn ml_dsa_is_accepted_everywhere() {
        for r in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(SchemeId::MlDsa65.allowed_on(r));
            assert!(SchemeId::MlDsa87.allowed_on(r));
        }
    }

    /// SPHINCS+ has no verification implementation: allowing it when creating
    /// an output burned unspendable funds (red team 8b). It must be refused
    /// everywhere, at creation as at spending, as long as it is not
    /// implemented.
    #[test]
    fn unimplemented_sphincs_plus_is_refused_everywhere() {
        for r in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(
                !SchemeId::SphincsPlus.allowed_on(r),
                "an unverifiable scheme must not be able to lock an output"
            );
            assert!(!SchemeId::SphincsPlus.is_available());
        }
    }

    #[test]
    fn missing_input_is_rejected() {
        let utxo = UtxoSet::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![crate::tx::TxIn {
                prev_out: OutPoint {
                    txid: Hash256([1u8; 32]),
                    index: 0,
                },
                witness: crate::tx::Witness::default(),
                sequence: 0,
            }],
            outputs: vec![crate::tx::TxOut {
                value: Amount::from_units(MIN_OUTPUT_VALUE),
                scheme: SchemeId::LamportOts,
                pubkey_hash: Hash256::ZERO,
            }],
            lock_time: 0,
        };
        let mut seen = HashSet::new();
        assert!(matches!(
            check_transaction(&tx, &utxo, Network::Testnet, 1, &mut seen),
            Err(ValidationError::MissingInput(_))
        ));
    }
}
