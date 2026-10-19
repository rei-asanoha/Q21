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
use crate::tx::{OutPoint, Transaction, TxOut};
use crate::utxo::{UtxoEntry, UtxoSet, UtxoView};
use crate::validate::{self, ValidationError};
use std::collections::{BTreeSet, HashMap, HashSet};

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

/// What a newcomer must pay, per thousand weight units, **above** the
/// transaction it pushes out of a full pool.
///
/// Without a margin, a fee rate one unit higher — a rounding difference
/// between two ordinary sends — was enough to evict. During the endurance
/// test, the pool stayed full for an hour and churned on such differences:
/// nearly a thousand accepted payments were pushed out without anyone paying
/// more for it. Bitcoin Core calls this the incremental relay fee.
pub const INCREMENTAL_FEE_RATE: u64 = MIN_FEE_RATE;

/// Packages a full pool examines at most for one newcomer, cheapest first.
/// See `Mempool::room_for`.
pub const PACKAGE_CANDIDATES: usize = 256;

/// Transactions in one package at most, for eviction. A longer chain is not
/// pushed out as a package: its leaves still are, one by one.
pub const PACKAGE_MAX: usize = 64;

/// The node's own confirmed transactions remembered, for a reorganization
/// that would bring them back. Far beyond what six blocks can hold.
pub const LOCAL_CONFIRMED_MAX: usize = 4096;

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
    /// Submitted by this node's own wallet. Never evicted here: see
    /// [`Mempool::accept_local`].
    pub local: bool,
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
    /// The transactions a full pool may push out, cheapest first: those no
    /// other pending transaction depends on, and that this node's wallet did
    /// not submit. Key: fee rate, then the most recent first, then the id.
    evictable: BTreeSet<(u64, u64, Hash256)>,
    /// The node's own transactions recently confirmed: if a reorganization
    /// brings one back, it comes back as the node's own. Bounded by
    /// [`LOCAL_CONFIRMED_MAX`].
    local_confirmed: HashSet<Hash256>,
    bytes: usize,
    counter: u64,
    /// Bound in bytes; zero means [`MEMPOOL_MAX_BYTES`]. Only tests lower it.
    max_bytes: usize,
}

impl Mempool {
    pub fn new() -> Mempool {
        Mempool::default()
    }

    /// A pool bounded at `max_bytes`, to exercise a full pool in tests
    /// without filling 64 MiB.
    #[cfg(test)]
    pub fn with_capacity(max_bytes: usize) -> Mempool {
        Mempool {
            max_bytes,
            ..Mempool::default()
        }
    }

    fn capacity(&self) -> usize {
        if self.max_bytes == 0 {
            MEMPOOL_MAX_BYTES
        } else {
            self.max_bytes
        }
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

    /// Is this output already spent by a transaction waiting here?
    ///
    /// The wallet asks before choosing its coins: a coin spent by a pending
    /// transaction is still in the confirmed set until the next block, and
    /// choosing it again only builds a double spend that this pool refuses.
    pub fn spends(&self, o: &OutPoint) -> bool {
        self.committed.contains_key(o)
    }

    /// Outputs created by pending transactions and not yet spent by another
    /// one, for which `mine` answers yes; sorted, so that two runs choose
    /// the same coins.
    ///
    /// The wallet spends its own change with them before the next block.
    /// Without this, a wallet whose confirmed coins were all committed had to
    /// wait two minutes for a block before it could pay again, although its
    /// change was right there.
    pub fn unspent_created(&self, mine: &dyn Fn(&TxOut) -> bool) -> Vec<(OutPoint, TxOut)> {
        let mut v: Vec<(OutPoint, TxOut)> = self
            .created
            .iter()
            .filter(|(o, e)| !self.committed.contains_key(o) && mine(&e.output))
            .map(|(o, e)| (*o, e.output))
            .collect();
        v.sort_by_key(|(o, _)| *o);
        v
    }

    /// Does every output that the pending transaction `txid` spends satisfy
    /// `mine`? Answers whether a pending transaction is one of the wallet's
    /// own sends, whose change it can trust before the block: a payment
    /// received from someone else can still be replaced by its sender, and
    /// whatever spends it would vanish with it.
    pub fn spends_only(
        &self,
        txid: &Hash256,
        confirmed: &UtxoSet,
        mine: &dyn Fn(&TxOut) -> bool,
    ) -> bool {
        let Some(e) = self.entries.get(txid) else {
            return false;
        };
        e.tx.inputs.iter().all(|i| {
            self.created
                .get(&i.prev_out)
                .or_else(|| confirmed.get(&i.prev_out))
                .is_some_and(|u| mine(&u.output))
        })
    }

    /// Number of pending ancestors of `txid`, counted up to `limit` (the
    /// walk stops there: a deep chain costs no more than the limit).
    pub fn ancestors_up_to(&self, txid: &Hash256, limit: usize) -> usize {
        let mut seen: HashSet<Hash256> = HashSet::new();
        let mut todo: Vec<Hash256> = vec![*txid];
        while let Some(id) = todo.pop() {
            for p in self.parents.get(&id).map(|v| v.as_slice()).unwrap_or(&[]) {
                if self.entries.contains_key(p) && seen.insert(*p) {
                    if seen.len() >= limit {
                        return limit;
                    }
                    todo.push(*p);
                }
            }
        }
        seen.len()
    }

    /// The confirmed outputs as this pool sees them: plus those its
    /// transactions create, minus those they already spend.
    pub fn view<'a>(&'a self, confirmed: &'a UtxoSet) -> MempoolView<'a> {
        MempoolView {
            confirmed,
            overlay: &self.created,
            spent: &self.committed,
        }
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
        self.accept_with(tx, utxo, network, height, false)
    }

    /// Accepts a transaction of this node's own wallet.
    ///
    /// It is never evicted from this pool, whatever pays more: the wallet
    /// counts on it, and an eviction here was silent — the payment simply
    /// vanished, and its coins stayed reserved until the reservation expired.
    /// Other nodes may still evict it; this one keeps it, and offers it again
    /// to its peers until a block includes it. The pool stays bounded: when
    /// it is full and nothing else can make room, the wallet gets an explicit
    /// refusal.
    pub fn accept_local(
        &mut self,
        tx: &Transaction,
        utxo: &UtxoSet,
        network: Network,
        height: u64,
    ) -> Result<Hash256, MempoolError> {
        self.accept_with(tx, utxo, network, height, true)
    }

    fn accept_with(
        &mut self,
        tx: &Transaction,
        utxo: &UtxoSet,
        network: Network,
        height: u64,
        local: bool,
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
        // A full pool that this rate cannot get into is said before any
        // signature is checked: while the pool was full, every refused
        // transaction cost a post-quantum verification for nothing.
        if self.bytes + size > self.capacity() && self.room_for(announced_rate, size).is_none() {
            return Err(MempoolError::FullAndUnderpaid);
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
            local,
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
        if self.bytes + size > self.capacity() && !self.make_room(rate, size) {
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
            // A parent is no longer a leaf.
            if let Some(e) = self.entries.get(p) {
                self.evictable.remove(&Self::eviction_key(p, e));
            }
        }
        self.parents.insert(txid, parents);
        // --- Children already waiting for it.
        //
        // A parent can arrive after its child: a reorganization undoes the
        // block that had confirmed it, and puts it back here while the child
        // never left. Not linked, the parent passed for a leaf — evictable
        // alone, leaving its child spending outputs that no longer exist.
        let mut adopted: Vec<Hash256> = (0..tx.outputs.len() as u32)
            .filter_map(|index| self.committed.get(&OutPoint { txid, index }).copied())
            .filter(|c| *c != txid && self.entries.contains_key(c))
            .collect();
        adopted.sort_unstable();
        adopted.dedup();
        for c in &adopted {
            let p = self.parents.entry(*c).or_default();
            if !p.contains(&txid) {
                p.push(txid);
            }
        }
        if !local && adopted.is_empty() {
            self.evictable.insert(Self::eviction_key(&txid, &entry));
        }
        if !adopted.is_empty() {
            self.children.entry(txid).or_default().extend(adopted);
        }
        self.entries.insert(txid, entry);
        Ok(txid)
    }

    fn eviction_key(txid: &Hash256, e: &MempoolEntry) -> (u64, u64, Hash256) {
        (e.fee_rate(), u64::MAX - e.arrival, *txid)
    }

    /// The transactions to push out so that `size` more bytes fit, for a
    /// newcomer paying `rate`; `None` if it cannot get in. Each one returned
    /// is removed with its descendants by [`Mempool::make_room`].
    ///
    /// Two passes, and in both, what goes out pays at least
    /// [`INCREMENTAL_FEE_RATE`] less than the newcomer:
    ///
    /// 1. **Leaves first**, cheapest first — transactions nothing else in the
    ///    pool depends on. An eviction then takes no chain along: up to
    ///    v0.4.8, evicting a parent removed every descendant with it, and one
    ///    newcomer paying a unit more wiped out whole chains of payments that
    ///    paid as much as it did.
    /// 2. **Then whole packages** — a transaction and all its descendants —
    ///    judged on the rate of the package as a whole, when the leaves are
    ///    not enough. Without this pass, large cheap parents each holding up
    ///    a tiny well-paying child would pin a full pool: the child is too
    ///    dear to push out, and the parent is never a leaf.
    ///
    /// The node's own wallet transactions are never in either pass. The work
    /// is bounded: [`PACKAGE_CANDIDATES`] packages of at most
    /// [`PACKAGE_MAX`] transactions are examined.
    fn room_for(&self, rate: u64, size: usize) -> Option<Vec<Hash256>> {
        let need = (self.bytes + size).saturating_sub(self.capacity());
        let mut freed = 0usize;
        let mut out = Vec::new();
        for (r, _, id) in &self.evictable {
            if freed >= need || r.saturating_add(INCREMENTAL_FEE_RATE) > rate {
                break;
            }
            freed += self.entries[id].size;
            out.push(*id);
        }
        if freed >= need {
            return Some(out);
        }

        // --- 2. Packages.
        let mut candidates: Vec<(u64, u64, Hash256)> = self
            .entries
            .iter()
            .filter(|(id, e)| {
                !e.local
                    && self.children.get(*id).is_some_and(|v| !v.is_empty())
                    && e.fee_rate().saturating_add(INCREMENTAL_FEE_RATE) <= rate
            })
            .map(|(id, e)| Self::eviction_key(id, e))
            .collect();
        candidates.sort_unstable();
        candidates.truncate(PACKAGE_CANDIDATES);
        let mut packages: Vec<(u64, Hash256, Vec<Hash256>)> = Vec::new();
        for (_, _, id) in candidates {
            let Some(members) = self.descendant_package(&id) else {
                continue;
            };
            let (fee, weight) = members.iter().fold((0u64, 0u64), |(f, w), m| {
                let e = &self.entries[m];
                (f.saturating_add(e.fee.units()), w.saturating_add(e.weight))
            });
            let package_rate = fee.saturating_mul(1000) / weight.max(1);
            if package_rate.saturating_add(INCREMENTAL_FEE_RATE) <= rate {
                packages.push((package_rate, id, members));
            }
        }
        packages.sort_unstable_by_key(|(r, id, _)| (*r, *id));
        let mut taken: HashSet<Hash256> = out.iter().copied().collect();
        for (_, root, members) in packages {
            if freed >= need {
                break;
            }
            let mut added = false;
            for m in members {
                if taken.insert(m) {
                    freed += self.entries[&m].size;
                    added = true;
                }
            }
            if added {
                out.push(root);
            }
        }
        (freed >= need).then_some(out)
    }

    /// A transaction and every descendant of it in the pool; `None` if one of
    /// them is the node's own, or if there are more than [`PACKAGE_MAX`].
    fn descendant_package(&self, root: &Hash256) -> Option<Vec<Hash256>> {
        let mut members = vec![*root];
        let mut seen: HashSet<Hash256> = HashSet::new();
        seen.insert(*root);
        let mut i = 0;
        while i < members.len() {
            if self.entries.get(&members[i]).is_some_and(|e| e.local) {
                return None;
            }
            if let Some(children) = self.children.get(&members[i]) {
                for c in children {
                    if seen.insert(*c) {
                        members.push(*c);
                        if members.len() > PACKAGE_MAX {
                            return None;
                        }
                    }
                }
            }
            i += 1;
        }
        Some(members)
    }

    /// Evicts the lowest-paying transactions to make room for `size` bytes.
    ///
    /// Returns `false` if the newcomer does not pay enough more than what
    /// would have to be sacrificed: it is then refused rather than making the
    /// mempool poorer. See [`Mempool::room_for`].
    fn make_room(&mut self, incoming_rate: u64, size: usize) -> bool {
        let Some(to_evict) = self.room_for(incoming_rate, size) else {
            return false;
        };
        for id in to_evict {
            // A leaf leaves alone; a package root takes its descendants.
            self.remove(&id);
        }
        self.bytes + size <= self.capacity()
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
        self.evictable.remove(&Self::eviction_key(txid, &e));
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
                    // A parent left without children becomes a leaf again.
                    if v.is_empty() {
                        if let Some(pe) = self.entries.get(&p) {
                            if !pe.local {
                                self.evictable.insert(Self::eviction_key(&p, pe));
                            }
                        }
                    }
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

    /// Puts back the transactions of the blocks a reorganization abandoned
    /// (oldest block first, in block order, so that a parent comes before
    /// its children). Those the winning branch already confirmed, or made
    /// impossible, are refused by `accept` and dropped. Returns how many came
    /// back.
    pub fn return_abandoned(
        &mut self,
        blocks: &[crate::block::Block],
        utxo: &UtxoSet,
        network: Network,
        height: u64,
    ) -> usize {
        let mut back = 0;
        for b in blocks {
            // The first transaction of a block is its coinbase: it has no
            // place in a pool.
            for tx in b.transactions.iter().skip(1) {
                let local = self.local_confirmed.remove(&tx.txid());
                if self.accept_with(tx, utxo, network, height, local).is_ok() {
                    back += 1;
                }
            }
        }
        back
    }

    /// Removes what a block has just confirmed, or made invalid.
    ///
    /// Two distinct cases: a transaction of the block is now confirmed, and a
    /// mempool transaction that spent the same output is now a double spend.
    /// Both must go.
    ///
    /// A confirmed transaction leaves **alone**: its descendants still waiting
    /// here stay, since what they spend is now a confirmed output. Removing
    /// them with it, as `remove` does, erased every payment chained on change
    /// that did not fit in the same block (load test of 14 October 2026).
    pub fn on_block_connected(&mut self, block: &crate::block::Block) {
        for tx in &block.transactions {
            let txid = tx.txid();
            if self.remove_one(&txid).is_some_and(|e| e.local) {
                if self.local_confirmed.len() >= LOCAL_CONFIRMED_MAX {
                    self.local_confirmed.clear();
                }
                self.local_confirmed.insert(txid);
            }
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
        self.block_order(max_weight)
            .into_iter()
            .map(|e| e.tx.clone())
            .collect()
    }

    /// Identifiers to announce to a peer: the start of the block order
    /// (parents before children, best rate first), up to `max_inputs` inputs
    /// in all.
    ///
    /// # Why it exists (0.4.5)
    ///
    /// A transaction was announced once, when it arrived. A peer connected
    /// later, or one that had refused a child because its parent had not
    /// reached it yet, never heard of it again: the load test of 11 October
    /// 2026 saw five transactions wait on the two seeds while the miners
    /// never had them. The node now announces its pool to each new peer, and
    /// again every ten minutes; a peer that already holds a transaction does
    /// not ask for it, so this costs a few identifiers when all is well.
    ///
    /// The bound in inputs, not in transactions, matches what the receiving
    /// peer counts: its budget is debited per input verified
    /// ([`crate::net::TX_BUCKET_MAX`]). Staying well under it means the
    /// answer to the announcement is never taken for a flood.
    ///
    /// A start of a topological order keeps every parent of what it keeps.
    pub fn announcement(&self, max_inputs: u64) -> Vec<Hash256> {
        let mut out = Vec::new();
        let mut inputs = 0u64;
        for e in self.block_order(u64::MAX) {
            inputs += e.tx.inputs.len() as u64;
            if inputs > max_inputs {
                break;
            }
            out.push(e.tx.txid());
        }
        out
    }

    /// Identifiers of the **whole** pool to re-offer a peer, in block order
    /// (parents before children), up to `max_txs`.
    ///
    /// # The defect this closes (0.4.9, lab of 19 October)
    ///
    /// [`Self::announcement`] offers only a prefix bounded by inputs — about a
    /// hundred and thirty transactions. The periodic re-offer kept sending
    /// that same prefix, which a peer already holds, so the rest of a large
    /// pool was never reconciled: a node that connected to a peer holding one
    /// thousand three hundred transactions received one hundred and
    /// forty-five, then nothing, for ever. A miner then mined near-empty
    /// blocks while its peers held thousands of accepted payments.
    ///
    /// The re-offer now covers the whole pool. The receiver bounds its own
    /// intake — it requests within its per-peer budget and queues the rest —
    /// so a full offer is never a flood; a peer that holds a transaction does
    /// not ask for it again.
    pub fn announcement_window(&self, max_txs: usize) -> Vec<Hash256> {
        self.block_order(u64::MAX)
            .into_iter()
            .take(max_txs)
            .map(|e| e.tx.txid())
            .collect()
    }

    /// The order of [`Self::select_for_block`], without copying anything.
    fn block_order(&self, max_weight: u64) -> Vec<&MempoolEntry> {
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

        let mut chosen: Vec<&MempoolEntry> = Vec::new();
        let mut selected: HashSet<Hash256> = HashSet::new();
        let mut weight = 0u64;
        // Children met before one of their parents, by the parent they wait
        // for.
        let mut waiting: HashMap<Hash256, Vec<usize>> = HashMap::new();

        for start in 0..v.len() {
            let mut stack = vec![start];
            while let Some(i) = stack.pop() {
                let (e, id, _) = v[i];
                if selected.contains(&id) || weight + e.weight > max_weight {
                    continue;
                }
                // --- Topological order: a child never goes before its parent.
                //
                // Without this check, the miner would produce a block where a
                // transaction spends an output that does not exist yet —
                // invalid, and it would only notice after having spent its
                // electricity.
                //
                // A child met first is no longer dropped from the block: it
                // waits for its parent and goes in right after it. Dropping it
                // cost a block per link once a wallet spent its own change: a
                // parent with more inputs pays a lower rate than its child, so
                // the child always came first, and a chain of ten payments
                // took ten blocks.
                let missing = self.parents.get(&id).and_then(|ps| {
                    ps.iter()
                        .find(|p| !selected.contains(*p) && self.entries.contains_key(*p))
                });
                if let Some(p) = missing {
                    waiting.entry(*p).or_default().push(i);
                    continue;
                }
                weight += e.weight;
                selected.insert(id);
                chosen.push(e);
                if let Some(children) = waiting.remove(&id) {
                    stack.extend(children.into_iter().rev());
                }
            }
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
        //
        // First, what is already confirmed leaves on its own, without its
        // descendants: a reorg connects several blocks while only the tip
        // goes through `on_block_connected`. Treated as an orphan below (its
        // inputs are spent: by itself), it took its still-valid children
        // with it. A confirmed transaction is recognized by an output of its
        // own present in the confirmed set.
        let confirmed: Vec<Hash256> = self
            .entries
            .iter()
            .filter(|(id, e)| {
                (0..e.tx.outputs.len() as u32)
                    .any(|index| utxo.get(&OutPoint { txid: **id, index }).is_some())
            })
            .map(|(id, _)| *id)
            .collect();
        for id in confirmed {
            if self.remove_one(&id).is_some_and(|e| e.local) {
                if self.local_confirmed.len() >= LOCAL_CONFIRMED_MAX {
                    self.local_confirmed.clear();
                }
                self.local_confirmed.insert(id);
            }
        }
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

// ---------------------------------------------------------------------------
// Transactions waiting for a parent
// ---------------------------------------------------------------------------

/// Orphans kept at most. See [`OrphanPool`].
pub const MAX_ORPHANS: usize = 256;

/// Bytes of orphans kept at most.
pub const MAX_ORPHAN_BYTES: usize = 4 * 1024 * 1024;

/// A larger transaction is not kept as an orphan: payments are a few
/// kilobytes, and the pool must not be filled by a handful of large ones.
pub const MAX_ORPHAN_SIZE: usize = 100 * 1024;

/// How long an orphan waits for its parent.
pub const ORPHAN_EXPIRY: std::time::Duration = std::time::Duration::from_secs(20 * 60);

/// Transactions that arrived before their parent, kept until it comes.
///
/// # The defect this closes
///
/// A payment built on the change of another travels behind it, but not
/// always by the same route: a node can hear of the child from one peer
/// before the parent from another. The child was then refused —
/// "unconfirmed dependency" — and forgotten; the node only heard of it again
/// at the next offer of a peer's pool. In the endurance test, about forty
/// payments waited ten minutes that way, while the blocks went out almost
/// empty; in the lab, the last ones took three minutes to drain.
///
/// Kept here instead, the child is tried again the moment its parent is
/// accepted, or confirmed by a block. Nothing is verified when it is kept —
/// the refusal comes before any signature — and the pool is bounded in count
/// and in bytes; the oldest goes first.
#[derive(Default)]
pub struct OrphanPool {
    by_id: HashMap<Hash256, (Transaction, u64, std::time::Instant, usize)>,
    /// Missing parent -> orphans that spend it.
    by_parent: HashMap<Hash256, Vec<Hash256>>,
    bytes: usize,
}

impl OrphanPool {
    pub fn new() -> OrphanPool {
        OrphanPool::default()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn contains(&self, txid: &Hash256) -> bool {
        self.by_id.contains_key(txid)
    }

    /// Keeps `tx`, received from `peer`. Returns `false` if it is not kept
    /// (too large, or already there).
    pub fn add(&mut self, tx: Transaction, peer: u64, now: std::time::Instant) -> bool {
        let txid = tx.txid();
        let size = tx.encode().len();
        if size > MAX_ORPHAN_SIZE || self.by_id.contains_key(&txid) {
            return false;
        }
        self.expire(now);
        while !self.by_id.is_empty()
            && (self.by_id.len() >= MAX_ORPHANS || self.bytes + size > MAX_ORPHAN_BYTES)
        {
            let oldest = self
                .by_id
                .iter()
                .min_by_key(|(id, (_, _, at, _))| (*at, **id))
                .map(|(id, _)| *id)
                .expect("not empty");
            self.remove(&oldest);
        }
        let mut parents: Vec<Hash256> = tx.inputs.iter().map(|i| i.prev_out.txid).collect();
        parents.sort_unstable();
        parents.dedup();
        for p in parents {
            self.by_parent.entry(p).or_default().push(txid);
        }
        self.bytes += size;
        self.by_id.insert(txid, (tx, peer, now, size));
        true
    }

    /// Takes out the orphans that spend an output of `parent`, oldest first,
    /// with the peer each came from.
    pub fn take_children(&mut self, parent: &Hash256) -> Vec<(Transaction, u64)> {
        let Some(ids) = self.by_parent.remove(parent) else {
            return Vec::new();
        };
        let mut out: Vec<(std::time::Instant, Hash256)> = ids
            .iter()
            .filter_map(|id| self.by_id.get(id).map(|(_, _, at, _)| (*at, *id)))
            .collect();
        out.sort_unstable();
        out.dedup();
        out.into_iter()
            .filter_map(|(_, id)| self.remove(&id))
            .collect()
    }

    /// Drops the orphans older than [`ORPHAN_EXPIRY`].
    pub fn expire(&mut self, now: std::time::Instant) {
        let old: Vec<Hash256> = self
            .by_id
            .iter()
            .filter(|(_, (_, _, at, _))| now.saturating_duration_since(*at) >= ORPHAN_EXPIRY)
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            self.remove(&id);
        }
    }

    /// Drops every orphan received from `peer`.
    pub fn forget_peer(&mut self, peer: u64) {
        let from: Vec<Hash256> = self
            .by_id
            .iter()
            .filter(|(_, (_, p, _, _))| *p == peer)
            .map(|(id, _)| *id)
            .collect();
        for id in from {
            self.remove(&id);
        }
    }

    fn remove(&mut self, txid: &Hash256) -> Option<(Transaction, u64)> {
        let (tx, peer, _, size) = self.by_id.remove(txid)?;
        self.bytes -= size;
        for i in &tx.inputs {
            if let Some(v) = self.by_parent.get_mut(&i.prev_out.txid) {
                v.retain(|c| c != txid);
                if v.is_empty() {
                    self.by_parent.remove(&i.prev_out.txid);
                }
            }
        }
        Some((tx, peer))
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
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::sig::SchemeId;
    use crate::wallet::Wallet;

    const NETWORK: Network = Network::Regtest;
    const ATTEMPTS: u64 = 5_000_000;

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

    /// A send from `w` that may spend the change of its pending sends.
    fn spend_with_pending(
        w: &mut Wallet,
        c: &crate::chain::Chain,
        m: &Mempool,
        fee: u64,
    ) -> Transaction {
        let mut dest = Wallet::from_seed([0x26; 32], NETWORK);
        let a = dest.new_address();
        let pending = m.unspent_created(&|o| w.owns_output(o));
        let p = w
            .prepare_spend_avoiding(
                &c.utxo,
                c.height(),
                &[(a, Amount::from_units(10_000))],
                Amount::from_units(fee),
                &|o| m.spends(o),
                &pending,
            )
            .expect("prepare");
        w.sign_spend(&m.view(&c.utxo), p).expect("sign")
    }

    /// One mature coin, three sends: each spends the change of the one
    /// before. The announcement keeps the parents before the children, and
    /// a bound in inputs keeps a start of the chain, never a child alone.
    #[test]
    fn the_announcement_keeps_parents_first_and_stays_bounded() {
        let mut w = Wallet::from_seed([0x27; 32], NETWORK);
        let c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 1);
        let mut m = Mempool::new();
        let mut ids = Vec::new();
        for k in 0..3u64 {
            // The child pays more than its parent: the best rate first must
            // not put it ahead.
            let tx = spend_with_pending(&mut w, &c, &m, 300 + 100 * k);
            if let Some(parent) = ids.last() {
                assert_eq!(
                    tx.inputs[0].prev_out.txid, *parent,
                    "send {k} spends the change"
                );
            }
            ids.push(
                m.accept(&tx, &c.utxo, NETWORK, c.height())
                    .expect("accepted"),
            );
        }
        assert_eq!(m.announcement(u64::MAX), ids, "parents first");
        assert_eq!(m.announcement(2), ids[..2].to_vec(), "a start of the chain");
        assert!(m.announcement(0).is_empty());
        assert_eq!(m.ancestors_up_to(&ids[2], 10), 2);
        assert_eq!(
            m.ancestors_up_to(&ids[2], 1),
            1,
            "the walk stops at its limit"
        );
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
    /// A block that confirms a parent but has no room for its children keeps
    /// the children waiting: their input is now a confirmed coin.
    ///
    /// Before 0.4.7, confirming a transaction removed it **with all its
    /// descendants**. As soon as the wallet chained payments on its pending
    /// change (0.4.5) and blocks were full, every block that took a parent
    /// without its children erased them: on the load test of 14 October 2026,
    /// 208 of the last 600 payments checked had vanished from every node.
    #[test]
    fn confirming_a_parent_keeps_its_children_waiting() {
        let mut w = Wallet::from_seed([0x2a; 32], NETWORK);
        let mut c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 1);
        let mut m = Mempool::new();
        let mut ids = Vec::new();
        let mut txs = Vec::new();
        for k in 0..3u64 {
            let tx = spend_with_pending(&mut w, &c, &m, 300 + 100 * k);
            ids.push(
                m.accept(&tx, &c.utxo, NETWORK, c.height())
                    .expect("accepted"),
            );
            txs.push(tx);
        }
        // A full block: only the parent fits.
        let t = c.tip().time + crate::consensus::TARGET_BLOCK_SECS;
        let a = w.new_address();
        let block = c
            .mine_block(a.hash, SchemeId::LamportOts, &txs[..1], t, 5_000_000)
            .expect("mining");
        c.connect(&block, t + 1).expect("connect");
        m.on_block_connected(&block);
        m.revalidate(&c.utxo, NETWORK, c.height());

        assert_eq!(m.len(), 2, "the children must still be waiting");
        assert!(!m.contains(&ids[0]));
        assert_eq!(m.announcement(u64::MAX), ids[1..].to_vec());
        assert_eq!(
            m.ancestors_up_to(&ids[2], 10),
            1,
            "only the child remains above"
        );

        // And the next block takes them, in order.
        let next = m.select_for_block(u64::MAX);
        let t = c.tip().time + crate::consensus::TARGET_BLOCK_SECS;
        let block = c
            .mine_block(a.hash, SchemeId::LamportOts, &next, t, 5_000_000)
            .expect("mining");
        c.connect(&block, t + 1).expect("the children are valid");
        m.on_block_connected(&block);
        assert!(m.is_empty());
        assert!(m.created.is_empty() && m.committed.is_empty());
    }
    /// The largest coins pay first; and an amount that would need more coins
    /// than a transaction can carry is refused with a clear reason, not
    /// built into a transaction no block can hold.
    #[test]
    fn selection_takes_the_largest_coins_and_knows_its_limit() {
        let mut w = Wallet::from_seed([0x2f; 32], NETWORK);
        let max = w.max_inputs() as u64;
        let c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + max + 2);
        let coins = w.spendable(&c.utxo, c.height());
        assert!(coins.len() as u64 > max);
        let largest = coins
            .iter()
            .map(|(_, o, _)| o.value.units())
            .max()
            .expect("coins");
        let all: u64 = coins.iter().map(|(_, o, _)| o.value.units()).sum();

        // One coin's worth: the largest one alone.
        let (chosen, _) = w
            .select_coins(&c.utxo, c.height(), largest)
            .expect("selection");
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].1.value.units(), largest);

        // Everything: more coins than one transaction can carry.
        assert_eq!(
            w.select_coins(&c.utxo, c.height(), all).err(),
            Some(crate::wallet::WalletError::TooManyCoins {
                max_inputs: max as usize
            })
        );
        // More than everything: really not enough money.
        assert!(matches!(
            w.select_coins(&c.utxo, c.height(), all + 1),
            Err(crate::wallet::WalletError::InsufficientFunds { .. })
        ));

        // Too many coins, but one pending coin of ours covers it alone: it
        // pays, instead of "too many coins".
        let addr = w.new_address();
        let pending_point = crate::tx::OutPoint {
            txid: crate::hash::Hash256([0x78; 32]),
            index: 0,
        };
        let pending_out = crate::tx::TxOut {
            value: crate::amount::Amount::from_units(all * 2),
            scheme: coins[0].1.scheme,
            pubkey_hash: addr.hash,
        };
        let (chosen, _) = w
            .select_coins_avoiding(
                &c.utxo,
                c.height(),
                all,
                &|_| false,
                &[(pending_point, pending_out)],
            )
            .expect("the pending coin pays");
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].0, pending_point);
    }

    /// When only crumbs are confirmed, one pending coin that covers the
    /// payment alone is preferred to a handful of them; when a confirmed
    /// coin covers it, nothing changes.
    #[test]
    fn one_pending_coin_is_preferred_to_many_confirmed_crumbs() {
        let mut w = Wallet::from_seed([0x31; 32], NETWORK);
        let c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 6);
        let coins = w.spendable(&c.utxo, c.height());
        assert!(coins.len() >= 4);
        let smallest = coins.iter().map(|e| e.1.value.units()).min().unwrap();
        let largest = coins.iter().map(|e| e.1.value.units()).max().unwrap();
        // A pending coin of ours (the change of a send waiting for a block),
        // larger than any confirmed one.
        let addr = w.new_address();
        let pending_out = crate::tx::TxOut {
            value: crate::amount::Amount::from_units(largest * 10),
            pubkey_hash: addr.hash,
            scheme: coins[0].1.scheme,
        };
        let pending_point = crate::tx::OutPoint {
            txid: crate::hash::Hash256([0x77; 32]),
            index: 1,
        };
        let pending = [(pending_point, pending_out)];
        // Three crumbs' worth: the pending coin alone.
        let need = smallest.saturating_mul(3).max(largest * 2 + 1);
        let (chosen, total) = w
            .select_coins_avoiding(&c.utxo, c.height(), need, &|_| false, &pending)
            .expect("selection");
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].0, pending_point);
        assert_eq!(total, largest * 10);
        // One confirmed coin's worth: the confirmed coin, as before.
        let (chosen, _) = w
            .select_coins_avoiding(&c.utxo, c.height(), largest, &|_| false, &pending)
            .expect("selection");
        assert_eq!(chosen.len(), 1);
        assert_ne!(chosen[0].0, pending_point);
    }

    /// A payment that only the abandoned block carried comes back to the pool
    /// after a reorganization, instead of vanishing.
    #[test]
    fn a_reorg_puts_the_abandoned_payments_back() {
        let n = crate::consensus::COINBASE_MATURITY + 1;
        let mut w = Wallet::from_seed([0x2c; 32], NETWORK);
        let mut x = funded_chain(&mut w, n);
        // The same chain, built a second time: the competing miner.
        let mut y = funded_chain(&mut Wallet::from_seed([0x2c; 32], NETWORK), n);
        assert_eq!(x.tip_id(), y.tip_id());

        let mut m = Mempool::new();
        let payment = spend_with_pending(&mut w, &x, &m, 300);
        let id = m
            .accept(&payment, &x.utxo, NETWORK, x.height())
            .expect("accepted");

        // This node's block carries the payment.
        let t = x.tip().time + crate::consensus::TARGET_BLOCK_SECS;
        let mut ours = Wallet::from_seed([0x2d; 32], NETWORK);
        let a = ours.new_address();
        let mine = x
            .mine_block(a.hash, SchemeId::LamportOts, &[payment], t, 5_000_000)
            .expect("mining");
        x.connect(&mine, t + 1).expect("connect");
        m.on_block_connected(&mine);
        assert!(!m.contains(&id));

        // The other miner finds two empty blocks: its branch wins.
        let mut theirs = Wallet::from_seed([0x2e; 32], NETWORK);
        let b = theirs.new_address();
        let b1 = y
            .mine_block(b.hash, SchemeId::LamportOts, &[], t, 5_000_000)
            .expect("mining");
        y.connect(&b1, t + 1).expect("connect");
        let t2 = t + crate::consensus::TARGET_BLOCK_SECS;
        let b2 = y
            .mine_block(b.hash, SchemeId::LamportOts, &[], t2, 5_000_000)
            .expect("mining");
        assert!(matches!(
            x.submit(&b1, t2),
            Ok(crate::chain::Accept::SideBranch)
        ));
        assert!(matches!(
            x.submit(&b2, t2 + 1),
            Ok(crate::chain::Accept::Reorganized { depth: 1 })
        ));

        let abandoned = x.take_disconnected();
        assert_eq!(abandoned.len(), 1);
        assert_eq!(
            m.return_abandoned(&abandoned, &x.utxo, NETWORK, x.height()),
            1
        );
        m.revalidate(&x.utxo, NETWORK, x.height());
        assert!(m.contains(&id), "the payment is waiting again");
        assert!(x.take_disconnected().is_empty(), "handed over once");
    }

    /// The same on the path of a reorg, where only `revalidate` runs for the
    /// blocks of the new branch: the confirmed parent leaves, its child stays.
    #[test]
    fn revalidation_keeps_the_children_of_a_confirmed_parent() {
        let mut w = Wallet::from_seed([0x2b; 32], NETWORK);
        let mut c = funded_chain(&mut w, crate::consensus::COINBASE_MATURITY + 1);
        let mut m = Mempool::new();
        let parent = spend_with_pending(&mut w, &c, &m, 300);
        let p = m
            .accept(&parent, &c.utxo, NETWORK, c.height())
            .expect("parent");
        let child = spend_with_pending(&mut w, &c, &m, 400);
        let k = m
            .accept(&child, &c.utxo, NETWORK, c.height())
            .expect("child");
        let t = c.tip().time + crate::consensus::TARGET_BLOCK_SECS;
        let a = w.new_address();
        let block = c
            .mine_block(a.hash, SchemeId::LamportOts, &[parent], t, 5_000_000)
            .expect("mining");
        c.connect(&block, t + 1).expect("connect");
        // No `on_block_connected`: the reorg path.
        m.revalidate(&c.utxo, NETWORK, c.height());
        assert!(!m.contains(&p), "the confirmed parent leaves");
        assert!(m.contains(&k), "its child stays");
        assert_eq!(m.len(), 1);
    }

    // --- A full pool (0.4.9) ---------------------------------------------

    /// The set of evictable transactions is exactly the non-local leaves.
    fn check_evictable(m: &Mempool) {
        let expected: BTreeSet<(u64, u64, Hash256)> = m
            .entries
            .iter()
            .filter(|(id, e)| !e.local && m.children.get(*id).map_or(true, |v| v.is_empty()))
            .map(|(id, e)| Mempool::eviction_key(id, e))
            .collect();
        assert_eq!(m.evictable, expected);
    }

    /// One mature coin for `single`, five for `many`, on the same chain.
    fn two_wallets() -> (Wallet, Wallet, Chain) {
        let mut single = Wallet::from_seed([0x51; 32], NETWORK);
        let mut many = Wallet::from_seed([0x52; 32], NETWORK);
        let _ = single.new_address();
        let _ = many.new_address();
        let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
        for i in 1..=COINBASE_MATURITY + 5 {
            let a = if i == 1 {
                single.new_address()
            } else {
                many.new_address()
            };
            let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }
        (single, many, c)
    }

    fn rate_of(tx: &Transaction, fee: u64) -> u64 {
        fee * 1000 / tx.weight(WITNESS_DISCOUNT)
    }

    /// A rounding difference no longer evicts: the newcomer must pay a clear
    /// margin more than what it pushes out.
    #[test]
    fn a_full_pool_needs_a_clear_margin_to_evict() {
        let (_, mut w, c) = two_wallets();
        let probe = Mempool::new();
        let a = spend_with_pending(&mut w, &c, &probe, 5_000);
        let size = a.encode().len();
        let mut m = Mempool::with_capacity(size * 2 + size / 2);
        let a = m.accept(&a, &c.utxo, NETWORK, c.height()).expect("a");
        let b = spend_with_pending(&mut w, &c, &m, 5_000);
        let b = m.accept(&b, &c.utxo, NETWORK, c.height()).expect("b");
        check_evictable(&m);

        let barely = spend_with_pending(&mut w, &c, &m, 5_001);
        assert_eq!(
            m.accept(&barely, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::FullAndUnderpaid)
        );
        let clearly = spend_with_pending(&mut w, &c, &m, 50_000);
        assert!(rate_of(&clearly, 50_000) >= rate_of(&barely, 5_000) + INCREMENTAL_FEE_RATE);
        let id = m
            .accept(&clearly, &c.utxo, NETWORK, c.height())
            .expect("clearly");
        assert_eq!(m.len(), 2);
        assert!(m.contains(&id));
        assert!(m.contains(&a), "the oldest of two equals stays");
        assert!(!m.contains(&b), "the most recent of two equals goes first");
        check_evictable(&m);
    }

    /// Eviction takes the tip of a chain, never the chain: up to v0.4.8,
    /// pushing out a parent removed every payment chained on its change.
    #[test]
    fn eviction_never_takes_descendants_along() {
        let (mut single, mut many, c) = two_wallets();
        let mut m = Mempool::new();
        let parent = spend_with_pending(&mut single, &c, &m, 1_000);
        let parent_size = parent.encode().len();
        let pid = m.accept(&parent, &c.utxo, NETWORK, c.height()).unwrap();
        let child = spend_with_pending(&mut single, &c, &m, 1_000);
        assert_eq!(
            child.inputs[0].prev_out.txid, pid,
            "the child spends the change"
        );
        let child_size = child.encode().len();
        let mut m2 = Mempool::with_capacity(parent_size + child_size + child_size / 2);
        m2.accept(&parent, &c.utxo, NETWORK, c.height()).unwrap();
        let cid = m2.accept(&child, &c.utxo, NETWORK, c.height()).unwrap();
        check_evictable(&m2);
        assert_eq!(m2.evictable.len(), 1, "only the child is a leaf");

        let rich = spend_with_pending(&mut many, &c, &m2, 200_000);
        let rid = m2.accept(&rich, &c.utxo, NETWORK, c.height()).unwrap();
        assert!(m2.contains(&pid), "the parent stays");
        assert!(!m2.contains(&cid), "the child, a leaf, goes");
        assert!(m2.contains(&rid));
        check_evictable(&m2);

        // The parent is now a leaf, and the next newcomer can push it out.
        let rich2 = spend_with_pending(&mut many, &c, &m2, 200_000);
        m2.accept(&rich2, &c.utxo, NETWORK, c.height()).unwrap();
        assert!(!m2.contains(&pid));
        assert!(m2.contains(&rid));
        check_evictable(&m2);
    }

    /// The node's own wallet sends are never pushed out of its own pool: the
    /// refusal goes to the newcomer, explicitly.
    #[test]
    fn the_wallet_s_own_sends_are_never_evicted_here() {
        let (mut single, mut many, c) = two_wallets();
        let probe = Mempool::new();
        let parent = spend_with_pending(&mut single, &c, &probe, 1_000);
        let size = parent.encode().len();
        let mut m = Mempool::with_capacity(size * 2 + size / 2);
        let pid = m
            .accept_local(&parent, &c.utxo, NETWORK, c.height())
            .unwrap();
        let child = spend_with_pending(&mut single, &c, &m, 1_000);
        let cid = m
            .accept_local(&child, &c.utxo, NETWORK, c.height())
            .unwrap();
        check_evictable(&m);
        assert!(m.evictable.is_empty());
        let rich = spend_with_pending(&mut many, &c, &m, 500_000);
        assert_eq!(
            m.accept(&rich, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::FullAndUnderpaid)
        );
        assert!(m.contains(&pid) && m.contains(&cid));
        // A confirmed parent leaves alone; the local child is still protected.
        let block = crate::block::Block {
            header: c.tip(),
            transactions: vec![parent.clone()],
            uncles: Vec::new(),
        };
        m.on_block_connected(&block);
        assert!(m.contains(&cid));
        check_evictable(&m);
        assert!(m.evictable.is_empty());
    }

    /// A newcomer that cannot get into a full pool is refused before its
    /// post-quantum signature is verified: a bad signature that pays too
    /// little is refused as underpaid, not as invalid.
    #[test]
    fn a_hopeless_newcomer_is_refused_before_its_signature_is_checked() {
        let (_, mut w, c) = two_wallets();
        let probe = Mempool::new();
        let a = spend_with_pending(&mut w, &c, &probe, 5_000);
        let size = a.encode().len();
        let mut m = Mempool::with_capacity(size + size / 2);
        m.accept(&a, &c.utxo, NETWORK, c.height()).unwrap();

        let mut cheap = spend_with_pending(&mut w, &c, &m, 5_000);
        cheap.inputs[0].witness.signature[0] ^= 1;
        assert_eq!(
            m.accept(&cheap, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::FullAndUnderpaid)
        );
        let mut rich = spend_with_pending(&mut w, &c, &m, 50_000);
        rich.inputs[0].witness.signature[0] ^= 1;
        let r = m.accept(&rich, &c.utxo, NETWORK, c.height());
        assert!(matches!(r, Err(MempoolError::Validation(_))), "{r:?}");
        assert_eq!(m.len(), 1, "nothing was evicted for an invalid newcomer");
    }

    /// The set of evictable transactions stays exact through accepts,
    /// removals, confirmations and package removals.
    #[test]
    fn the_evictable_set_stays_exact() {
        let (mut single, mut many, c) = two_wallets();
        let mut m = Mempool::new();
        let mut ids = Vec::new();
        for k in 0..4u64 {
            let tx = spend_with_pending(&mut single, &c, &m, 1_000 + k);
            ids.push(m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap());
            check_evictable(&m);
            let tx = spend_with_pending(&mut many, &c, &m, 2_000 + k);
            if k % 2 == 0 {
                ids.push(m.accept_local(&tx, &c.utxo, NETWORK, c.height()).unwrap());
            } else {
                ids.push(m.accept(&tx, &c.utxo, NETWORK, c.height()).unwrap());
            }
            check_evictable(&m);
        }
        m.remove(&ids[2]);
        check_evictable(&m);
        m.remove(&ids[0]);
        check_evictable(&m);
        assert!(m.evictable.len() <= m.len());
    }

    /// Large cheap parents each holding up a dearer child no longer pin a
    /// full pool: the package goes out as a whole when the newcomer pays
    /// clearly more than the package does.
    #[test]
    fn a_cheap_parent_cannot_pin_the_pool_behind_a_dear_child() {
        let (mut single, mut many, c) = two_wallets();
        let mut probe = Mempool::new();
        let parent = spend_with_pending(&mut single, &c, &probe, 1_000);
        let pid = probe.accept(&parent, &c.utxo, NETWORK, c.height()).unwrap();
        let child = spend_with_pending(&mut single, &c, &probe, 40_000);
        let cid = probe.accept(&child, &c.utxo, NETWORK, c.height()).unwrap();
        let newcomer = spend_with_pending(&mut many, &c, &probe, 30_000);
        // The rates as the pool computes them.
        let (p, ch) = (&probe.entries[&pid], &probe.entries[&cid]);
        let package_rate = (p.fee.units() + ch.fee.units()) * 1000 / (p.weight + ch.weight);
        let r_new = {
            let mut q = Mempool::new();
            let id = q.accept(&newcomer, &c.utxo, NETWORK, c.height()).unwrap();
            q.entries[&id].fee_rate()
        };
        assert!(
            ch.fee_rate() + INCREMENTAL_FEE_RATE > r_new,
            "the child alone is too dear"
        );
        assert!(
            package_rate + INCREMENTAL_FEE_RATE <= r_new,
            "the package is cheaper"
        );

        let (sp, sc) = (parent.encode().len(), child.encode().len());
        let mut m = Mempool::with_capacity(sp + sc + newcomer.encode().len() / 2);
        let pid = m.accept(&parent, &c.utxo, NETWORK, c.height()).unwrap();
        let cid = m.accept(&child, &c.utxo, NETWORK, c.height()).unwrap();
        let nid = m
            .accept(&newcomer, &c.utxo, NETWORK, c.height())
            .expect("the package makes room");
        assert!(!m.contains(&pid) && !m.contains(&cid));
        assert!(m.contains(&nid));
        check_evictable(&m);
    }

    /// A parent that comes back after a reorganization finds its child
    /// again: it is no leaf, and cannot be pushed out alone.
    #[test]
    fn a_returning_parent_finds_its_waiting_child() {
        let (mut single, _, mut c) = two_wallets();
        let mut m = Mempool::new();
        let parent = spend_with_pending(&mut single, &c, &m, 1_000);
        let pid = m.accept(&parent, &c.utxo, NETWORK, c.height()).unwrap();
        let child = spend_with_pending(&mut single, &c, &m, 1_000);
        let cid = m.accept(&child, &c.utxo, NETWORK, c.height()).unwrap();

        // A block confirms the parent alone; the child waits.
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block(
                Hash256([9; 32]),
                SchemeId::LamportOts,
                std::slice::from_ref(&parent),
                t,
                ATTEMPTS,
            )
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        m.on_block_connected(&b);
        assert!(!m.contains(&pid) && m.contains(&cid));
        check_evictable(&m);

        // The block is undone: the parent comes back.
        assert!(c.disconnect());
        assert_eq!(m.return_abandoned(&[b], &c.utxo, NETWORK, c.height()), 1);
        assert!(m.contains(&pid) && m.contains(&cid));
        assert_eq!(m.child_count(&pid), 1, "the child is linked again");
        check_evictable(&m);
        assert!(
            !m.evictable.iter().any(|(_, _, id)| *id == pid),
            "a parent with a child is no leaf"
        );
        // Removing the parent takes the child: nothing left spending outputs
        // that no longer exist.
        m.remove(&pid);
        assert!(!m.contains(&cid));
    }

    /// The wallet's own payment, confirmed then undone by a reorganization,
    /// comes back as the wallet's own.
    #[test]
    fn a_local_payment_stays_local_through_a_reorganization() {
        let (mut single, _, mut c) = two_wallets();
        let mut m = Mempool::new();
        let tx = spend_with_pending(&mut single, &c, &m, 1_000);
        let id = m.accept_local(&tx, &c.utxo, NETWORK, c.height()).unwrap();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block(
                Hash256([9; 32]),
                SchemeId::LamportOts,
                std::slice::from_ref(&tx),
                t,
                ATTEMPTS,
            )
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        m.on_block_connected(&b);
        assert!(!m.contains(&id));
        assert!(c.disconnect());
        m.return_abandoned(&[b], &c.utxo, NETWORK, c.height());
        assert!(m.entries[&id].local);
        check_evictable(&m);
    }

    /// A child that arrives before its parent waits for it, and goes in the
    /// moment the parent does.
    #[test]
    fn an_orphan_waits_for_its_parent() {
        let (mut single, _, c) = two_wallets();
        let mut probe = Mempool::new();
        let parent = spend_with_pending(&mut single, &c, &probe, 1_000);
        let pid = probe.accept(&parent, &c.utxo, NETWORK, c.height()).unwrap();
        let child = spend_with_pending(&mut single, &c, &probe, 1_000);

        let mut m = Mempool::new();
        let mut orphans = OrphanPool::new();
        assert!(matches!(
            m.accept(&child, &c.utxo, NETWORK, c.height()),
            Err(MempoolError::UnconfirmedDependency(_))
        ));
        let now = std::time::Instant::now();
        assert!(orphans.add(child.clone(), 7, now));
        assert!(!orphans.add(child.clone(), 7, now), "kept once");
        m.accept(&parent, &c.utxo, NETWORK, c.height()).unwrap();
        let waiting = orphans.take_children(&pid);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].1, 7, "the peer it came from");
        m.accept(&waiting[0].0, &c.utxo, NETWORK, c.height())
            .unwrap();
        assert!(orphans.is_empty());
        assert_eq!(orphans.bytes, 0);
        assert!(orphans.by_parent.is_empty());
    }

    /// Bounded in count, oldest first; expired after a while; forgotten with
    /// the peer that sent them.
    #[test]
    fn the_orphan_pool_stays_bounded() {
        let mut o = OrphanPool::new();
        let t0 = std::time::Instant::now();
        let tx = |n: u32| Transaction {
            version: 1,
            inputs: vec![crate::tx::TxIn {
                prev_out: OutPoint {
                    txid: Hash256([(n % 251) as u8; 32]),
                    index: n,
                },
                witness: crate::tx::Witness {
                    pubkey: Vec::new(),
                    signature: Vec::new(),
                },
                sequence: 0,
            }],
            outputs: Vec::new(),
            lock_time: 0,
        };
        for n in 0..(MAX_ORPHANS as u32 + 50) {
            assert!(o.add(
                tx(n),
                u64::from(n % 3),
                t0 + std::time::Duration::from_millis(n as u64)
            ));
        }
        assert_eq!(o.len(), MAX_ORPHANS);
        assert!(!o.contains(&tx(0).txid()), "the oldest went first");
        assert!(o.contains(&tx(MAX_ORPHANS as u32 + 49).txid()));
        o.forget_peer(1);
        assert!(o.by_id.values().all(|(_, p, _, _)| *p != 1));
        o.expire(t0 + ORPHAN_EXPIRY + std::time::Duration::from_secs(1));
        assert!(o.is_empty());
        assert_eq!(o.bytes, 0);
        assert!(o.by_parent.is_empty());
    }
}
