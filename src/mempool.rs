//! Pool of pending transactions.
//!
//! The mempool is not consensus: two nodes can have different contents in it
//! without the chain splitting. It is, however, a **front-line attack
//! surface**, because it accepts unsolicited data coming from anyone. Each rule
//! in this file answers a specific abuse, named in a comment.
//!
//! # The particular problem of Q21
//!
//! A Q21 transaction is heavy: the witness makes up 99% of its size. Charging
//! fees per raw byte would amount to charging post-quantum cryptography at full
//! price and making the chain unusable. The mempool therefore orders by **fee
//! rate per weighted weight**, the weighting being the `witness discount` of
//! section 7 of the white paper.
//!
//! # Chains of unconfirmed transactions
//!
//! A transaction can spend an output created by another transaction still in
//! the mempool. Without this, one cannot send twice in a row without waiting
//! for a block — ten minutes on Bitcoin, two here. The phase 4 limitation is
//! lifted.
//!
//! Three consequences, all handled:
//!
//! - **validation is done against a view** ([`MempoolView`]) that overlays the
//!   mempool outputs on the confirmed outputs, without cloning the latter;
//! - **eviction is by package.** Removing a transaction removes all its
//!   descendants: leaving them would mean keeping transactions whose inputs no
//!   longer exist, hence invalid ones;
//! - **selection for a block is topological.** A child placed before its parent
//!   would produce an invalid block, and the miner would discover the problem
//!   after having spent its electricity.

use crate::address::Network;
use crate::amount::Amount;
use crate::consensus::{COINBASE_MATURITY, MAX_BLOCK_SIZE, TARGET_BLOCK_WEIGHT, WITNESS_DISCOUNT};
use crate::hash::Hash256;
use crate::tx::{OutPoint, Transaction};
use crate::utxo::{UtxoEntry, UtxoSet, UtxoView};
use crate::validate::{self, ValidationError};
use std::collections::{HashMap, HashSet};

/// Maximum size of the mempool, in serialized bytes.
///
/// Hard bound: without it, an adversary fills the node's memory with valid but
/// never mined transactions.
pub const MEMPOOL_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Minimum accepted fee rate, in units per thousand weight units.
///
/// Filters out free noise. The goal is to keep out zero-cost flooding, not to
/// set a fee market: at ten units per thousand, an ordinary ML-DSA-87
/// transaction pays about 80 units, one millionth of a Q21. The first value, 1,
/// let the pool be saturated for a few thousand units; the weight per output
/// ([`crate::consensus::WEIGHT_PER_OUTPUT`]) does the rest against output
/// flooding.
pub const MIN_FEE_RATE: u64 = 10;

#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub fee: Amount,
    /// Weighted weight, witness discounted.
    pub weight: u64,
    /// Full serialized size, for memory accounting.
    pub size: usize,
    /// Arrival order, to break ties at equal fee rate.
    pub arrival: u64,
}

impl MempoolEntry {
    /// Fee per thousand weight units.
    pub fn fee_rate(&self) -> u64 {
        self.fee.units().saturating_mul(1000) / self.weight.max(1)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MempoolError {
    AlreadyPresent,
    /// An input consumes an output already committed by another mempool
    /// transaction. We do not relay a double spend.
    SpendConflict(OutPoint),
    /// An input comes from a transaction that is still unconfirmed.
    UnconfirmedDependency(OutPoint),
    FeeRateTooLow {
        received: u64,
        minimum: u64,
    },
    /// Too heavy to fit in a block: it would never be mined, and would only
    /// occupy the pool at the expense of the others.
    Unmineable {
        weight: u64,
        size: usize,
    },
    /// The mempool is full and this transaction pays less than the lowest
    /// bidder.
    FullAndUnderpaid,
    Validation(ValidationError),
}

impl From<ValidationError> for MempoolError {
    fn from(e: ValidationError) -> Self {
        MempoolError::Validation(e)
    }
}

/// View overlaying the mempool outputs on the confirmed outputs.
///
/// Copies nothing: both sets are consulted on demand. The mempool takes
/// precedence, since its outputs are more recent than the chain.
/// Space actually usable by transactions in a block.
///
/// A block must also hold its coinbase and any uncles. We keep a generous
/// margin: a transaction that would fit in a block only on condition of being
/// alone in it has no business in the pool.
pub const MAX_USABLE_BLOCK_SIZE: usize = MAX_BLOCK_SIZE - 64 * 1024;

/// Maximum weight of a transaction accepted into the pool.
///
/// Set to the budget the miner actually uses to assemble a block
/// ([`crate::consensus::TARGET_BLOCK_WEIGHT`]). A heavier transaction would
/// never be selected: accepting it would amount to offering free pool space to
/// someone with no intention of paying.
pub const MAX_USABLE_WEIGHT: u64 = TARGET_BLOCK_WEIGHT;

/// Apparent fees of a transaction, without verifying a single signature.
///
/// The input amounts are read from the UTXO set; knowing that a transaction
/// does not pay enough requires no cryptography. This is what makes it
/// possible to reject a flood before spending the slightest post-quantum
/// computation.
fn apparent_fees(tx: &Transaction, view: &MempoolView<'_>) -> Result<u64, MempoolError> {
    let mut inputs: u64 = 0;
    for e in &tx.inputs {
        let u = view
            .lookup(&e.prev_out)
            .ok_or(MempoolError::UnconfirmedDependency(e.prev_out))?;
        inputs = inputs
            .checked_add(u.output.value.units())
            .ok_or(MempoolError::UnconfirmedDependency(e.prev_out))?;
    }
    let outputs =
        tx.total_output()
            .map(|a| a.units())
            .map_err(|_| MempoolError::FeeRateTooLow {
                received: 0,
                minimum: MIN_FEE_RATE,
            })?;
    Ok(inputs.saturating_sub(outputs))
}

pub struct MempoolView<'a> {
    confirmed: &'a UtxoSet,
    overlay: &'a HashMap<OutPoint, UtxoEntry>,
    /// Outputs already consumed by the mempool: invisible, even if they still
    /// exist in the confirmed set.
    spent: &'a HashMap<OutPoint, Hash256>,
}

impl UtxoView for MempoolView<'_> {
    fn lookup(&self, o: &OutPoint) -> Option<UtxoEntry> {
        if let Some(e) = self.overlay.get(o) {
            return Some(*e);
        }
        if self.spent.contains_key(o) {
            return None;
        }
        self.confirmed.lookup(o)
    }
}

#[derive(Default)]
pub struct Mempool {
    entries: HashMap<Hash256, MempoolEntry>,
    /// Outputs committed by the mempool: detects double spends.
    committed: HashMap<OutPoint, Hash256>,
    /// Outputs created by the mempool transactions, spendable by their
    /// descendants before confirmation.
    created: HashMap<OutPoint, UtxoEntry>,
    /// Direct children of each transaction, for package eviction.
    children: HashMap<Hash256, Vec<Hash256>>,
    /// Still unconfirmed parents of each transaction.
    parents: HashMap<Hash256, Vec<Hash256>>,
    bytes: usize,
    counter: u64,
}

impl Mempool {
    pub fn new() -> Mempool {
        Mempool::default()
    }

    /// Median fee rate of the pending transactions, in units per thousand
    /// weight units.
    ///
    /// Used to suggest fees that reflect the actual state of the network rather
    /// than a constant chosen once and for all. Returns `None` when the pool is
    /// empty: there is then nothing to measure, and making up a figure would be
    /// worse than saying nothing.
    pub fn median_fee_rate(&self) -> Option<u64> {
        if self.entries.is_empty() {
            return None;
        }
        let mut rates: Vec<u64> = self.entries.values().map(|e| e.fee_rate()).collect();
        rates.sort_unstable();
        Some(rates[rates.len() / 2])
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn contains(&self, txid: &Hash256) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn get(&self, txid: &Hash256) -> Option<&Transaction> {
        self.entries.get(txid).map(|e| &e.tx)
    }

    /// Transactions of the pool, parents before children.
    ///
    /// # What this order is for
    ///
    /// The pool is rebuilt by replaying `accept` on each transaction. Now
    /// `accept` refuses a transaction one of whose unconfirmed parents is
    /// missing — rightly so: it would spend an output that exists nowhere.
    /// Returning them out of order would therefore lose every child on each
    /// reload.
    ///
    /// The order is also deterministic for a given state: two nodes in the same
    /// state write the same file, which makes the pools comparable.
    pub fn ordered_transactions(&self) -> Vec<Transaction> {
        let mut remaining: Vec<Hash256> = self.txids();
        let mut emitted: HashSet<Hash256> = HashSet::new();
        let mut out: Vec<Transaction> = Vec::with_capacity(remaining.len());

        // At most as many passes as transactions: a chain of N transactions
        // needs N of them in the worst case, and the loop stops as soon as a
        // pass emits nothing.
        while !remaining.is_empty() {
            let before = remaining.len();
            let mut deferred = Vec::new();
            for id in remaining {
                let ready = self
                    .parents
                    .get(&id)
                    .map(|ps| {
                        ps.iter()
                            .all(|p| emitted.contains(p) || !self.entries.contains_key(p))
                    })
                    .unwrap_or(true);
                if ready {
                    if let Some(e) = self.entries.get(&id) {
                        out.push(e.tx.clone());
                    }
                    emitted.insert(id);
                } else {
                    deferred.push(id);
                }
            }
            remaining = deferred;
            if remaining.len() == before {
                // No progress: a cycle would remain, which validation forbids.
                // We stop rather than loop.
                break;
            }
        }
        out
    }

    pub fn txids(&self) -> Vec<Hash256> {
        let mut v: Vec<Hash256> = self.entries.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Adds a transaction after full validation.
    pub fn accept(
        &mut self,
        tx: &Transaction,
        utxo: &UtxoSet,
        network: Network,
        height: u64,
    ) -> Result<Hash256, MempoolError> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyPresent);
        }

        // --- Abuse: relaying two competing versions of the same spend.
        let mut parents: Vec<Hash256> = Vec::new();
        for e in &tx.inputs {
            if let Some(other) = self.committed.get(&e.prev_out) {
                if *other != txid {
                    return Err(MempoolError::SpendConflict(e.prev_out));
                }
            }
            // An input coming from the mempool is now legitimate: we only
            // record the dependency, so as to be able to evict by package.
            if self.created.contains_key(&e.prev_out) {
                parents.push(e.prev_out.txid);
            } else if !utxo.contains(&e.prev_out) {
                return Err(MempoolError::UnconfirmedDependency(e.prev_out));
            }
        }

        // --- Abuse: occupying the pool with what can never be mined.
        //
        // A transaction heavier than a whole block used to be accepted, then
        // never selected. The phase 8b audit measured it: thirty transactions
        // of this kind occupied **99.8%** of the pool, for an actual cost of
        // zero — nothing being mined, no fee was ever paid. Honest transactions
        // were left with only 107 KiB out of 64 MiB.
        //
        // So we refuse upfront what a block will not be able to hold.
        let weight = tx.weight(WITNESS_DISCOUNT);
        let size = tx.encode().len();
        if size > MAX_USABLE_BLOCK_SIZE || weight > MAX_USABLE_WEIGHT {
            return Err(MempoolError::Unmineable { weight, size });
        }

        // --- Abuse: getting post-quantum signatures verified for nothing.
        //
        // Signature verification came before the fee check. A zero-fee
        // rejection cost 15.9 ms of computation, against 91 us for a shape
        // rejection: a ratio of 175. An adversary could thus burn processor
        // time for the price of a send.
        //
        // We compute the fees **before** any cryptography. The input amount is
        // read from the UTXO set; no signature is needed to know that a
        // transaction does not pay enough.
        let view = MempoolView {
            confirmed: utxo,
            overlay: &self.created,
            spent: &self.committed,
        };
        let announced_fees = apparent_fees(tx, &view)?;
        let announced_rate = announced_fees.saturating_mul(1000) / weight.max(1);
        if announced_rate < MIN_FEE_RATE {
            return Err(MempoolError::FeeRateTooLow {
                received: announced_rate,
                minimum: MIN_FEE_RATE,
            });
        }

        // Full validation: signatures, value conservation, maturity. The height
        // used is that of the next block, since that is where this transaction
        // could get in.
        let mut seen: HashSet<OutPoint> = HashSet::new();
        let fee = validate::check_transaction(tx, &view, network, height + 1, &mut seen)?;
        let entry = MempoolEntry {
            tx: tx.clone(),
            fee,
            weight,
            size,
            arrival: self.counter,
        };

        // --- Abuse: flooding for free.
        let rate = entry.fee_rate();
        if rate < MIN_FEE_RATE {
            return Err(MempoolError::FeeRateTooLow {
                received: rate,
                minimum: MIN_FEE_RATE,
            });
        }

        // --- Abuse: saturating the node's memory.
        if self.bytes + size > MEMPOOL_MAX_BYTES && !self.make_room(rate, size) {
            return Err(MempoolError::FullAndUnderpaid);
        }

        self.counter += 1;
        self.bytes += size;
        for e in &tx.inputs {
            self.committed.insert(e.prev_out, txid);
        }
        // The outputs of this transaction become spendable by its descendants.
        // They are never coinbases: a coinbase does not enter the mempool.
        for (i, output) in tx.outputs.iter().enumerate() {
            self.created.insert(
                OutPoint {
                    txid,
                    index: i as u32,
                },
                UtxoEntry {
                    output: *output,
                    height: height + 1,
                    is_coinbase: false,
                },
            );
        }
        parents.sort_unstable();
        parents.dedup();
        for p in &parents {
            self.children.entry(*p).or_default().push(txid);
        }
        self.parents.insert(txid, parents);
        self.entries.insert(txid, entry);
        Ok(txid)
    }

    /// Evicts the lowest-paying transactions to make room for `size` bytes.
    ///
    /// Returns `false` if the newcomer pays less than everything that would
    /// have to be sacrificed: in that case it is refused rather than making the
    /// mempool poorer.
    fn make_room(&mut self, incoming_rate: u64, size: usize) -> bool {
        let mut candidates: Vec<(Hash256, u64)> = self
            .entries
            .iter()
            .map(|(id, e)| (*id, e.fee_rate()))
            .collect();
        candidates.sort_by_key(|(id, rate)| (*rate, *id));

        let mut freed = 0usize;
        let mut to_evict = Vec::new();
        for (id, rate) in candidates {
            if self.bytes + size - freed <= MEMPOOL_MAX_BYTES {
                break;
            }
            if rate >= incoming_rate {
                return false; // nothing lower-paying to sacrifice
            }
            freed += self.entries[&id].size;
            to_evict.push(id);
        }
        for id in to_evict {
            self.remove(&id);
        }
        self.bytes + size <= MEMPOOL_MAX_BYTES
    }

    /// Removes a transaction **and all its descendants**.
    ///
    /// Keeping a child whose parent has disappeared would amount to keeping a
    /// transaction whose inputs no longer exist: invalid, and relayed to the
    /// whole network.
    pub fn remove(&mut self, txid: &Hash256) -> Option<MempoolEntry> {
        // Breadth-first walk of the descendants, to avoid recursion on a deep
        // chain.
        //
        // Membership is tested in a set, not by scanning the vector:
        // `Vec::contains` on each child made removing a chain of n links
        // quadratic — the audit had measured it at n^1.35, and the 64 MiB cap
        // allows chains of several thousand links. With the set, removal is
        // linear again.
        let mut to_remove = vec![*txid];
        let mut seen: HashSet<Hash256> = HashSet::new();
        seen.insert(*txid);
        let mut i = 0;
        while i < to_remove.len() {
            if let Some(children) = self.children.get(&to_remove[i]) {
                for c in children.clone() {
                    if seen.insert(c) {
                        to_remove.push(c);
                    }
                }
            }
            i += 1;
        }

        let mut first = None;
        // The descendants are removed first, the target last, so as to return
        // the requested entry to the caller.
        for id in to_remove.into_iter().rev() {
            if let Some(e) = self.remove_one(&id) {
                if id == *txid {
                    first = Some(e);
                }
            }
        }
        first
    }

    /// Removes a single transaction, without touching its descendants.
    fn remove_one(&mut self, txid: &Hash256) -> Option<MempoolEntry> {
        let e = self.entries.remove(txid)?;
        self.bytes = self.bytes.saturating_sub(e.size);
        for input in &e.tx.inputs {
            if self.committed.get(&input.prev_out) == Some(txid) {
                self.committed.remove(&input.prev_out);
            }
        }
        for i in 0..e.tx.outputs.len() {
            self.created.remove(&OutPoint {
                txid: *txid,
                index: i as u32,
            });
        }
        if let Some(parents) = self.parents.remove(txid) {
            for p in parents {
                if let Some(v) = self.children.get_mut(&p) {
                    v.retain(|c| c != txid);
                }
            }
        }
        self.children.remove(txid);
        Some(e)
    }

    /// Number of direct descendants of a transaction.
    pub fn child_count(&self, txid: &Hash256) -> usize {
        self.children.get(txid).map(|v| v.len()).unwrap_or(0)
    }

    /// Removes what a block has just confirmed, or made invalid.
    ///
    /// Two distinct cases: a transaction of the block is now confirmed, and a
    /// mempool transaction that spent the same output is now a double spend.
    /// Both must go.
    pub fn on_block_connected(&mut self, block: &crate::block::Block) {
        for tx in &block.transactions {
            self.remove(&tx.txid());
            for input in &tx.inputs {
                if let Some(conflict) = self.committed.get(&input.prev_out).copied() {
                    self.remove(&conflict);
                }
            }
        }
    }

    /// Candidate transactions for a block, highest-paying first.
    ///
    /// Deterministic order at equal rate: without this, two miners starting
    /// from the same mempool would build different blocks for no reason.
    pub fn select_for_block(&self, max_weight: u64) -> Vec<Transaction> {
        // The identifiers are computed **once**, not on each comparison of the
        // sort.
        //
        // The previous version called `txid()` — a hash over the whole
        // serialized transaction — inside the comparator, hence O(n log n)
        // times. On a pool full of large transactions, the phase 8b audit
        // measured **3.96 seconds to pick a single transaction**, and that
        // under the node's global lock: everything stopped during that time,
        // on every block template.
        let mut v: Vec<(&MempoolEntry, Hash256, u64)> = self
            .entries
            .iter()
            .map(|(id, e)| (e, *id, e.fee_rate()))
            .collect();
        v.sort_by(|(a, ida, rate_a), (b, idb, rate_b)| {
            rate_b
                .cmp(rate_a)
                .then(a.arrival.cmp(&b.arrival))
                .then(ida.cmp(idb))
        });

        let mut chosen: Vec<Transaction> = Vec::new();
        let mut selected: HashSet<Hash256> = HashSet::new();
        let mut weight = 0u64;

        for (e, id, _) in v {
            if weight + e.weight > max_weight {
                continue;
            }
            // --- Topological order: a child never goes before its parent.
            //
            // Without this check, the miner would produce a block where a
            // transaction spends an output that does not exist yet — invalid,
            // and it would only notice after having spent its electricity.
            let parents_ready = self
                .parents
                .get(&id)
                .map(|ps| {
                    ps.iter()
                        .all(|p| selected.contains(p) || !self.entries.contains_key(p))
                })
                .unwrap_or(true);
            if !parents_ready {
                continue;
            }
            weight += e.weight;
            selected.insert(id);
            chosen.push(e.tx.clone());
        }
        chosen
    }

    /// Revalidates the whole mempool against a UTXO set.
    ///
    /// Needed after a reorg: confirmed transactions can become valid again,
    /// and others become impossible.
    pub fn revalidate(&mut self, utxo: &UtxoSet, _network: Network, height: u64) {
        // The previous version revalidated each transaction with
        // `check_transaction` against a view where the spent set contained
        // **its own inputs**. Each transaction therefore saw itself as a double
        // spend of itself, and removed itself. Called on every connected block,
        // this function **emptied the pool entirely**: three perfectly valid
        // transactions became zero. Measurement from the phase 8b audit:
        // "before 50, after 0".
        //
        // The pool was therefore permanently empty on a real network, and no
        // transaction ever reached a block other than by being mined within
        // the second following its arrival.
        //
        // What actually changes when a block is connected is not the validity
        // of a signature — the signed hash does not depend on the chain — but
        // the **availability of the inputs** and the **maturity of
        // coinbases**. So we only check that, and cascade to the descendants.
        // It is also much faster: no post-quantum signature is rechecked.
        loop {
            let mut orphans: Vec<Hash256> = Vec::new();

            for (id, e) in &self.entries {
                for input in &e.tx.inputs {
                    let available = match utxo.get(&input.prev_out) {
                        Some(u) => {
                            // A reorg can make the height *go down*: a mature
                            // coinbase can become immature again.
                            !u.is_coinbase || height + 1 >= u.height + COINBASE_MATURITY
                        }
                        // Otherwise, the output must come from another
                        // transaction of the pool, still present.
                        None => self.created.contains_key(&input.prev_out),
                    };
                    if !available {
                        orphans.push(*id);
                        break;
                    }
                }
            }

            if orphans.is_empty() {
                return;
            }
            for id in orphans {
                // `remove` already takes the descendants along.
                self.remove(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
    use crate::sig::SchemeId;
    use crate::wallet::Wallet;

    const NETWORK: Network = Network::Regtest;
    const ATTEMPTS: u64 = 5_000_000;

    pub fn funded_chain(w: &mut Wallet, n: u64) -> Chain {
        chain_with_funds(w, n)
    }

    fn chain_with_funds(w: &mut Wallet, n: u64) -> Chain {
        let _ = w.new_address();
        let g = genesis_block(NETWORK);
        let mut c = Chain::new(NETWORK, g);
        for i in 1..=n {
            let a = w.new_address();
            let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }
        c
    }

    fn transfer(w: &mut Wallet, c: &Chain, fee: u64) -> Transaction {
        let mut dest = Wallet::from_seed([0xbb; 32], NETWORK);
        let a = dest.new_address();
        w.create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(10_000),
            Amount::from_units(fee),
        )
        .expect("build")
    }

    #[test]
    fn a_valid_transaction_is_accepted() {
        let mut w = Wallet::from_seed([0x01; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        let id = m
            .accept(&tx, &c.utxo, NETWORK, c.height())
            .expect("acceptance");
        assert_eq!(id, tx.txid());
        assert_eq!(m.len(), 1);
        assert!(m.contains(&id));
        assert!(m.bytes() > 0);
    }

    #[test]
    fn an_already_present_transaction_is_refused() {
        let mut w = Wallet::from_seed([0x02; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();
        assert_eq!(
            m.accept(&tx, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::AlreadyPresent)
        );
    }

    #[test]
    fn a_double_spend_is_refused() {
        let mut w = Wallet::from_seed([0x03; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx1 = transfer(&mut w, &c, 5_000);

        // Build a second transaction consuming the same input.
        let mut tx2 = tx1.clone();
        tx2.lock_time = 42; // changes the txid without changing the inputs

        let mut m = Mempool::new();
        m.accept(&tx1, &c.utxo, NETWORK, c.height()).unwrap();
        assert!(matches!(
            m.accept(&tx2, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::SpendConflict(_))
        ));
    }

    #[test]
    fn an_invalid_signature_is_refused() {
        let mut w = Wallet::from_seed([0x04; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let mut tx = transfer(&mut w, &c, 5_000);
        tx.inputs[0].witness.signature[0] ^= 0x01;

        let mut m = Mempool::new();
        assert!(matches!(
            m.accept(&tx, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::Validation(_))
        ));
        assert!(m.is_empty(), "nothing must remain after a refusal");
    }

    #[test]
    fn a_nonexistent_input_is_refused() {
        let mut w = Wallet::from_seed([0x05; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let mut tx = transfer(&mut w, &c, 5_000);
        tx.inputs[0].prev_out.txid = Hash256([0xee; 32]);

        let mut m = Mempool::new();
        assert!(matches!(
            m.accept(&tx, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::UnconfirmedDependency(_))
        ));
    }

    #[test]
    fn the_fee_rate_is_computed_on_the_weighted_weight() {
        let mut w = Wallet::from_seed([0x06; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 50_000);

        let mut m = Mempool::new();
        let id = m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();
        let e = &m.entries[&id];
        assert!(e.weight > 0);
        assert!(e.fee_rate() > 0);
        // The weighted weight must differ from the raw size: that is the whole
        // point of the witness discount.
        assert_ne!(e.weight, e.size as u64);
    }

    #[test]
    fn selection_orders_by_decreasing_rate() {
        let mut w = Wallet::from_seed([0x07; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 20);
        let mut dest = Wallet::from_seed([0xcc; 32], NETWORK);

        let mut m = Mempool::new();
        let mut expected_rates = Vec::new();
        for fee in [1_000u64, 90_000, 20_000] {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(10_000),
                    Amount::from_units(fee),
                )
                .expect("build");
            let id = m
                .accept(&tx, &c.utxo, NETWORK, c.height())
                .expect("acceptance");
            expected_rates.push(m.entries[&id].fee_rate());
        }

        let chosen = m.select_for_block(u64::MAX);
        assert_eq!(chosen.len(), 3);
        let rates: Vec<u64> = chosen
            .iter()
            .map(|t| m.entries[&t.txid()].fee_rate())
            .collect();
        let mut sorted = rates.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(rates, sorted, "the highest-paying must go first");
    }

    #[test]
    fn selection_respects_the_maximum_weight() {
        let mut w = Wallet::from_seed([0x08; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();
        assert!(m.select_for_block(10).is_empty(), "weight too low");
        assert_eq!(m.select_for_block(u64::MAX).len(), 1);
    }

    #[test]
    fn selection_is_deterministic() {
        let mut w = Wallet::from_seed([0x09; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 20);
        let mut dest = Wallet::from_seed([0xdd; 32], NETWORK);

        let mut m = Mempool::new();
        for _ in 0..4 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(10_000),
                    Amount::from_units(5_000),
                )
                .expect("build");
            m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();
        }
        let a: Vec<Hash256> = m
            .select_for_block(u64::MAX)
            .iter()
            .map(|t| t.txid())
            .collect();
        let b: Vec<Hash256> = m
            .select_for_block(u64::MAX)
            .iter()
            .map(|t| t.txid())
            .collect();
        assert_eq!(a, b, "two miners must build the same block");
    }

    #[test]
    fn a_confirmed_block_clears_what_it_contains_from_the_mempool() {
        let mut w = Wallet::from_seed([0x0a; 32], NETWORK);
        let mut c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();
        assert_eq!(m.len(), 1);

        let t = c.tip().time + TARGET_BLOCK_SECS;
        let a = w.new_address();
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        m.on_block_connected(&b);

        assert!(m.is_empty(), "the confirmed transaction had to leave");
        assert_eq!(m.bytes(), 0);
    }

    #[test]
    fn a_block_also_evicts_competing_double_spends() {
        let mut w = Wallet::from_seed([0x0b; 32], NETWORK);
        let mut c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 5_000);

        // A competing variant enters the mempool.
        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();

        // A block confirms a transaction that consumes the same output under
        // another identifier.
        let mut competitor = tx.clone();
        competitor.lock_time = 7;
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let a = w.new_address();
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();

        // Simulates the confirmation of the competitor.
        let fake_block = crate::block::Block {
            header: b.header,
            transactions: vec![b.transactions[0].clone(), competitor],
            uncles: vec![],
        };
        m.on_block_connected(&fake_block);
        assert!(m.is_empty(), "the competitor, now invalid, had to leave");
    }

    #[test]
    fn removal_releases_the_committed_outputs() {
        let mut w = Wallet::from_seed([0x0c; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        let id = m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();
        assert!(!m.committed.is_empty());
        m.remove(&id);
        assert!(m.committed.is_empty(), "the commitments must be released");
        assert_eq!(m.bytes(), 0);
    }

    #[test]
    fn revalidation_purges_what_has_become_invalid() {
        let mut w = Wallet::from_seed([0x0d; 32], NETWORK);
        let c = chain_with_funds(&mut w, COINBASE_MATURITY + 5);
        let tx = transfer(&mut w, &c, 5_000);

        let mut m = Mempool::new();
        m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap();

        // Against an empty UTXO set, nothing holds up anymore.
        m.revalidate(&UtxoSet::new(), NETWORK, c.height());
        assert!(m.is_empty());
    }
}

#[cfg(test)]
mod tests_chains {
    use super::tests::*;
    use super::*;
    use crate::sig::SchemeId;
    use crate::wallet::Wallet;

    const NETWORK: Network = Network::Regtest;

    /// The phase 4 limit, lifted.
    #[test]
    fn a_transaction_can_spend_an_output_still_in_the_mempool() {
        let mut w = Wallet::from_seed([0x20; 32], NETWORK);
        let c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x21; 32], NETWORK);
        let mut m = Mempool::new();

        // First spend: the change comes back to the wallet.
        let a1 = dest.new_address();
        let tx1 = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a1,
                Amount::from_units(100_000),
                Amount::from_units(5_000),
            )
            .expect("first");
        let id1 = m
            .accept(&tx1, &c.utxo, NETWORK, c.height())
            .expect("acceptance 1");

        // Second spend: it consumes the change of the first one, which is not
        // confirmed anywhere yet.
        let change_output = tx1
            .outputs
            .iter()
            .position(|o| w.owns(&o.pubkey_hash))
            .expect("there must be change");
        assert!(
            m.created.contains_key(&OutPoint {
                txid: id1,
                index: change_output as u32
            }),
            "the output must be visible in the mempool view"
        );

        let a2 = dest.new_address();
        let tx2 = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a2,
                Amount::from_units(100_000),
                Amount::from_units(5_000),
            )
            .expect("second");
        m.accept(&tx2, &c.utxo, NETWORK, c.height())
            .expect("the second spend must go through");
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn removing_a_parent_removes_its_descendants() {
        let mut w = Wallet::from_seed([0x22; 32], NETWORK);
        let c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x23; 32], NETWORK);
        let mut m = Mempool::new();

        let mut ids = Vec::new();
        for _ in 0..3 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(100_000),
                    Amount::from_units(5_000),
                )
                .expect("build");
            ids.push(
                m.accept(&tx, &c.utxo, NETWORK, c.height())
                    .expect("acceptance"),
            );
        }
        assert_eq!(m.len(), 3);

        // Removing the first one must take along all the descendants that
        // depend on it.
        m.remove(&ids[0]);
        assert!(
            m.len() < 3,
            "the descendants of a removed transaction must go too"
        );
        assert!(!m.contains(&ids[0]));
    }

    #[test]
    fn selection_always_places_parents_before_children() {
        let mut w = Wallet::from_seed([0x24; 32], NETWORK);
        let c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x25; 32], NETWORK);
        let mut m = Mempool::new();

        let mut arrival_order = Vec::new();
        for _ in 0..4 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(100_000),
                    Amount::from_units(5_000),
                )
                .expect("build");
            arrival_order.push(
                m.accept(&tx, &c.utxo, NETWORK, c.height())
                    .expect("acceptance"),
            );
        }

        let chosen = m.select_for_block(u64::MAX);
        let positions: HashMap<Hash256, usize> = chosen
            .iter()
            .enumerate()
            .map(|(i, t)| (t.txid(), i))
            .collect();

        for tx in &chosen {
            let id = tx.txid();
            for e in &tx.inputs {
                if let Some(parent_pos) = positions.get(&e.prev_out.txid) {
                    assert!(
                        *parent_pos < positions[&id],
                        "a child was placed before its parent: the block would be invalid"
                    );
                }
            }
        }
    }

    #[test]
    fn the_view_hides_an_output_already_spent_by_the_mempool() {
        let mut w = Wallet::from_seed([0x26; 32], NETWORK);
        let c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x27; 32], NETWORK);
        let mut m = Mempool::new();

        let a = dest.new_address();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(100_000),
                Amount::from_units(5_000),
            )
            .expect("build");
        let consumed = tx.inputs[0].prev_out;
        m.accept(&tx, &c.utxo, NETWORK, c.height())
            .expect("acceptance");

        let view = MempoolView {
            confirmed: &c.utxo,
            overlay: &m.created,
            spent: &m.committed,
        };
        assert!(c.utxo.contains(&consumed), "the output is still confirmed");
        assert!(
            view.lookup(&consumed).is_none(),
            "but the view must hide it, otherwise a double spend would be validated"
        );
    }

    #[test]
    fn a_confirmed_block_cleans_up_the_whole_chain() {
        let mut w = Wallet::from_seed([0x28; 32], NETWORK);
        let mut c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 10);
        let mut dest = Wallet::from_seed([0x29; 32], NETWORK);
        let mut m = Mempool::new();

        let mut txs = Vec::new();
        for _ in 0..3 {
            let a = dest.new_address();
            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(100_000),
                    Amount::from_units(5_000),
                )
                .expect("build");
            m.accept(&tx, &c.utxo, NETWORK, c.height())
                .expect("acceptance");
            txs.push(tx);
        }

        let selection = m.select_for_block(u64::MAX);
        let t = c.tip().time + crate::consensus::TARGET_BLOCK_SECS;
        let a = w.new_address();
        let block = c
            .mine_block(a.hash, SchemeId::LamportOts, &selection, t, 5_000_000)
            .expect("mining");
        c.connect(&block, t + 1).expect("the block must be valid");
        m.on_block_connected(&block);

        assert!(m.is_empty(), "everything confirmed must leave");
        assert_eq!(m.bytes(), 0);
        assert!(m.created.is_empty(), "no ghost output must remain");
        assert!(m.committed.is_empty());
    }
}
