//! UTXO set: the set of unspent outputs.
//!
//! This is the state of the currency. Everything else (blocks, transactions,
//! proof of work) is only a mechanism for agreeing on the contents of this
//! set.
//!
//! Each entry keeps its height of origin and whether it is a coinbase, for two
//! distinct reasons: coinbase maturity, and the ability to cleanly undo a
//! block during a reorg.

use crate::amount::Amount;
use crate::tx::{OutPoint, Transaction, TxOut};
use std::collections::{HashMap, HashSet};

/// Read-only view of a set of unspent outputs.
///
/// Introduced so that validation no longer depends on a concrete set. A
/// mempool that accepts chains of unconfirmed transactions must validate
/// against "the confirmed outputs **plus** those the mempool will create",
/// without cloning the confirmed set for each transaction, which would be
/// linear in the size of the chain for every acceptance.
pub trait UtxoView {
    fn lookup(&self, o: &OutPoint) -> Option<UtxoEntry>;
}

impl UtxoView for UtxoSet {
    fn lookup(&self, o: &OutPoint) -> Option<UtxoEntry> {
        self.get(o).copied()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UtxoEntry {
    pub output: TxOut,
    pub height: u64,
    pub is_coinbase: bool,
}

#[derive(Clone, Default, Debug)]
pub struct UtxoSet {
    map: HashMap<OutPoint, UtxoEntry>,
    /// Derived index: public key hash -> matching outputs.
    ///
    /// # Why it exists
    ///
    /// `spendable_for` walked the whole UTXO set for **each** address queried.
    /// A wallet of sixty thousand addresses over a set of sixty thousand
    /// outputs therefore required several billion comparisons: twenty seconds
    /// to display a balance. The cost was quadratic and invisible as long as
    /// the test chains stayed short.
    ///
    /// This index is entirely derived from `map` and does not take part in the
    /// equality of two UTXO sets: two identical sets stay identical whatever
    /// the order in which they were built.
    by_pubkey_hash: HashMap<crate::hash::Hash256, HashSet<OutPoint>>,
    /// MuHash commitment maintained **on the fly**.
    ///
    /// # Why it is here
    ///
    /// `commitment()` rebuilt the commitment from scratch (one 3,072-bit
    /// modular multiplication **per output**) on every call. Yet it is called
    /// by the public explorer on every display of its page, and by the state
    /// snapshot every five minutes, under the chain lock. At one million
    /// outputs, each visit froze the node for several seconds: a refresh loop
    /// was enough to take it out of service.
    ///
    /// MuHash is made for incremental use: inserting multiplies the
    /// numerator, removing multiplies the denominator, and the final
    /// commitment costs only one division. Every `insert` and every `remove`
    /// keeps it up to date; it is the same choice as Bitcoin Core. Like the
    /// index by public key hash, it is entirely derived from `map` and does
    /// not take part in equality.
    muhash: crate::muhash::MuHash,
}

/// The derived index does not take part in equality: only the set of outputs
/// defines the state of the currency.
impl PartialEq for UtxoSet {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl Eq for UtxoSet {}

/// Record of what a block changed, so that it can be undone.
///
/// Without it, undoing a block would require replaying the chain from
/// genesis, which makes any reorg prohibitive.
#[derive(Clone, Debug, Default)]
pub struct UndoRecord {
    spent: Vec<(OutPoint, UtxoEntry)>,
    created: Vec<OutPoint>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, o: &OutPoint) -> Option<&UtxoEntry> {
        self.map.get(o)
    }

    pub fn contains(&self, o: &OutPoint) -> bool {
        self.map.contains_key(o)
    }

    pub fn insert(&mut self, o: OutPoint, e: UtxoEntry) {
        let key_hash = e.output.pubkey_hash;
        if let Some(previous) = self.map.insert(o, e) {
            // Replacement: the old element leaves the commitment, and the old
            // key no longer designates this output.
            self.muhash.remove(&serialized_element(&o, &previous));
            if previous.output.pubkey_hash != key_hash {
                self.unindex(&previous.output.pubkey_hash, &o);
            }
        }
        self.muhash.insert(&serialized_element(&o, &e));
        self.by_pubkey_hash.entry(key_hash).or_default().insert(o);
    }

    fn unindex(&mut self, key_hash: &crate::hash::Hash256, o: &OutPoint) {
        if let Some(s) = self.by_pubkey_hash.get_mut(key_hash) {
            s.remove(o);
            if s.is_empty() {
                self.by_pubkey_hash.remove(key_hash);
            }
        }
    }

    pub fn remove(&mut self, o: &OutPoint) -> Option<UtxoEntry> {
        let e = self.map.remove(o);
        if let Some(v) = &e {
            self.muhash.remove(&serialized_element(o, v));
            let key_hash = v.output.pubkey_hash;
            self.unindex(&key_hash, o);
        }
        e
    }

    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &UtxoEntry)> {
        self.map.iter()
    }

    /// Sum of all unspent outputs.
    ///
    /// This is the money supply actually in circulation. The test that
    /// compares it with the theoretical emission is the project's
    /// anti-inflation safeguard.
    pub fn total_value(&self) -> Amount {
        Amount::checked_sum(self.map.values().map(|e| e.output.value))
            .expect("the money supply cannot overflow below the cap")
    }

    /// Commitment of the set: the MuHash digest of all unspent outputs.
    ///
    /// # What it is worth
    ///
    /// It is the commitment to the state of the currency. Two nodes holding the
    /// same UTXO set derive the same commitment from it, whatever the order in
    /// which they received the blocks: MuHash multiplication is commutative,
    /// which is why this walk does not need to sort. A forgery that *moves*
    /// the ownership of an output without creating anything (the one the
    /// emission check of `state.rs` could not catch) changes the commitment:
    /// the serialized element includes the public key hash.
    ///
    /// # The element format
    ///
    /// Each output is serialized in the exact order of the state snapshot
    /// ([`crate::state`]): outpoint, value, scheme, public key hash, height,
    /// coinbase flag. This format is frozen: changing it would change every
    /// commitment.
    ///
    /// # What it costs
    ///
    /// One modular division, whatever the size of the set: the accumulator is
    /// kept up to date by `insert` and `remove`. The version that walks
    /// everything again is [`Self::recomputed_commitment`]; it only serves to
    /// prove that the two coincide.
    pub fn commitment(&self) -> crate::hash::Hash256 {
        self.muhash.digest()
    }

    /// The commitment under an explicit MuHash final label. Only the upgrade
    /// of a 0.3.x data directory needs it: see [`crate::legacy`].
    pub fn commitment_with_tag(&self, tag: &str) -> crate::hash::Hash256 {
        self.muhash.digest_with_tag(tag)
    }

    /// The commitment recomputed from scratch, output by output.
    ///
    /// This is the definition; [`Self::commitment`] is its incremental
    /// upkeep. Linear in the size of the set: reserved for tests and explicit
    /// checks, never for the hot path.
    pub fn recomputed_commitment(&self) -> crate::hash::Hash256 {
        let mut mu = crate::muhash::MuHash::new();
        for (o, e) in self.map.iter() {
            mu.insert(&serialized_element(o, e));
        }
        mu.digest()
    }

    /// Applies a transaction: consumes its inputs, creates its outputs.
    ///
    /// Validates nothing. Validation happens in [`crate::validate`], before.
    pub fn apply_transaction(&mut self, tx: &Transaction, height: u64, undo: &mut UndoRecord) {
        let coinbase = tx.is_coinbase();
        if !coinbase {
            for input in &tx.inputs {
                if let Some(e) = self.remove(&input.prev_out) {
                    undo.spent.push((input.prev_out, e));
                }
            }
        }
        let txid = tx.txid();
        for (i, output) in tx.outputs.iter().enumerate() {
            let o = OutPoint {
                txid,
                index: i as u32,
            };
            // Always through `insert` and `remove`, never directly on `map`:
            // the index by public key hash must follow every movement,
            // otherwise a balance becomes wrong without any consensus test
            // noticing.
            self.insert(
                o,
                UtxoEntry {
                    output: *output,
                    height,
                    is_coinbase: coinbase,
                },
            );
            undo.created.push(o);
        }
    }

    /// Undoes a block: removes what it created, restores what it consumed.
    ///
    /// # The deduplication this method must do
    ///
    /// A block can spend an output it created itself earlier: a transaction
    /// spends the change of a previous transaction of the same block, a
    /// parent-before-child chaining that `validate` allows. That output then
    /// appears in **both** lists: `created` (by the transaction that made it)
    /// and `spent` (by the one that spent it). Yet before the block, it did
    /// not exist: it was born and died inside. After the undo, it must
    /// therefore NOT exist.
    ///
    /// The naive version removed the `created` outputs then reinserted the
    /// `spent` ones without deduplicating: the intra-block output, removed as
    /// created, was reinserted as spent, and survived: a phantom UTXO,
    /// spendable, extending no transaction of the active chain. The phase 8b
    /// red team demonstrated it: total value went from 10,000 to 19,000 on a
    /// single undo, money created out of nothing, and the corrupted state
    /// commitment stayed consistent with itself (the incremental commitment
    /// equaled the recomputation), so it was undetectable by the internal
    /// check and divergent for any freshly synced node. A reorg is a normal
    /// event in proof of work, and spending one's change in the same block is
    /// just as normal: the defect triggered on ordinary activity, not only
    /// under attack.
    ///
    /// So a spent output is restored **only if the block did not also create
    /// it**. An output present in both lists is a wash: removed, never
    /// restored.
    pub fn undo(&mut self, record: &UndoRecord) {
        let created: std::collections::HashSet<&OutPoint> = record.created.iter().collect();
        for o in &record.created {
            self.remove(o);
        }
        for (o, e) in &record.spent {
            if created.contains(o) {
                // Output born and spent in this block: before it, it did not
                // exist. Do not resurrect it.
                continue;
            }
            self.insert(*o, *e);
        }
    }

    /// Outputs spendable by the holder of a given public key hash.
    ///
    /// Does this set contain at least one output paying this hash?
    ///
    /// Used for address discovery during a restore: we want neither the
    /// amounts, nor the maturity, nor even the count; only whether the index
    /// being tried has already received something. The question is resolved
    /// by a single lookup in the index, without building a vector.
    pub fn knows(&self, pubkey_hash: &crate::hash::Hash256) -> bool {
        self.by_pubkey_hash
            .get(pubkey_hash)
            .is_some_and(|s| !s.is_empty())
    }

    /// Balance and number of unspent outputs of a public key hash.
    ///
    /// # The defect this method closes
    ///
    /// The explorer computed this balance by walking the **whole** UTXO set,
    /// and it did so while holding the global lock: the very one used to
    /// validate blocks and serve the mempool. On a mature chain, every
    /// address lookup (public, unauthenticated, and the main use of an
    /// explorer) therefore stalled consensus for the duration of a full scan.
    /// A few requests per second were enough to slow down block acceptance,
    /// without any of them looking malicious.
    ///
    /// The index by public key hash already existed for `spendable_for`, where
    /// it had solved exactly the same quadratic cost. It only remained to use
    /// it here: the price goes from the size of the whole set to the number of
    /// outputs of the single address requested.
    ///
    /// The value returned is identical to that of the scan, saturation
    /// included: it is the same computation, on the same outputs, in a
    /// different order.
    pub fn balance_of(&self, pubkey_hash: &crate::hash::Hash256) -> (u64, u64) {
        let Some(points) = self.by_pubkey_hash.get(pubkey_hash) else {
            return (0, 0);
        };
        let mut sum = 0u64;
        let mut count = 0u64;
        for o in points {
            if let Some(e) = self.map.get(o) {
                sum = sum.saturating_add(e.output.value.units());
                count += 1;
            }
        }
        (sum, count)
    }

    /// All the unspent outputs of a public key hash, **regardless of
    /// maturity**.
    ///
    /// [`UtxoSet::spendable_for`] leaves out coinbases that are too young;
    /// sometimes those are exactly the ones needed: to tell a miner when its
    /// reward will be released. Going through the index avoids walking the
    /// whole set to find the few outputs of a single address.
    pub fn outputs_of(&self, pubkey_hash: &crate::hash::Hash256) -> Vec<(OutPoint, UtxoEntry)> {
        let Some(points) = self.by_pubkey_hash.get(pubkey_hash) else {
            return Vec::new();
        };
        let mut v: Vec<(OutPoint, UtxoEntry)> = points
            .iter()
            .filter_map(|o| self.map.get(o).map(|e| (*o, *e)))
            .collect();
        // Deterministic order: two runs must return the same answer.
        v.sort_by_key(|(o, _)| *o);
        v
    }

    /// Filters coinbase maturity: a fresh block reward is not spendable.
    pub fn spendable_for(
        &self,
        pubkey_hash: &crate::hash::Hash256,
        current_height: u64,
        maturity: u64,
    ) -> Vec<(OutPoint, UtxoEntry)> {
        let Some(points) = self.by_pubkey_hash.get(pubkey_hash) else {
            return Vec::new();
        };
        let mut v: Vec<(OutPoint, UtxoEntry)> = points
            .iter()
            .filter_map(|o| self.map.get(o).map(|e| (*o, *e)))
            .filter(|(_, e)| !e.is_coinbase || current_height >= e.height + maturity)
            .collect();
        // Deterministic order: without it, two runs would build different
        // transactions from the same wallet.
        v.sort_by_key(|(o, _)| *o);
        v
    }
}

/// Serializes an unspent output in the canonical element format.
///
/// 86 bytes, in the order of the state snapshot: txid (32), index (4), value
/// (8), scheme (1), public key hash (32), height (8), coinbase (1). This byte
/// sequence is what enters the MuHash; its order is local consensus and must
/// never change.
fn serialized_element(o: &OutPoint, e: &UtxoEntry) -> Vec<u8> {
    let mut w = crate::ser::Writer::with_capacity(86);
    w.bytes(o.txid.as_bytes());
    w.u32(o.index);
    w.u64(e.output.value.units());
    w.u8(e.output.scheme.as_u8());
    w.bytes(e.output.pubkey_hash.as_bytes());
    w.u64(e.height);
    w.u8(u8::from(e.is_coinbase));
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash256;
    use crate::sig::SchemeId;
    use crate::tx::{TxIn, Witness};

    fn output(v: u64, h: u8) -> TxOut {
        TxOut {
            value: Amount::from_units(v),
            scheme: SchemeId::LamportOts,
            pubkey_hash: Hash256([h; 32]),
        }
    }

    fn coinbase(v: u64, h: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(vec![1, 2, 3])],
            outputs: vec![output(v, h)],
            lock_time: 0,
        }
    }

    /// The balance returned by the index must match a full scan, in every
    /// circumstance, including after an undo, which puts spent outputs back
    /// into circulation and removes created outputs. That is precisely where
    /// a derived index can drift from the truth, and an explorer's balance is
    /// worth something only if it never drifts.
    #[test]
    fn balance_by_key_hash_always_matches_scan() {
        fn scan(u: &UtxoSet, key: &Hash256) -> (u64, u64) {
            let mut sum = 0u64;
            let mut n = 0u64;
            for (_, e) in u.iter() {
                if e.output.pubkey_hash == *key {
                    sum = sum.saturating_add(e.output.value.units());
                    n += 1;
                }
            }
            (sum, n)
        }
        fn check(u: &UtxoSet, stage: &str) {
            for h in 0..5u8 {
                let key = Hash256([h; 32]);
                assert_eq!(
                    u.balance_of(&key),
                    scan(u, &key),
                    "{stage}: the index diverges from the scan on key hash {h}"
                );
            }
        }

        let mut u = UtxoSet::new();

        // Two outputs on the same key hash, a third one elsewhere.
        let a1 = coinbase(5_000, 1);
        let a2 = coinbase(3_000, 1);
        let b1 = coinbase(7_000, 2);
        let mut undo1 = UndoRecord::default();
        u.apply_transaction(&a1, 1, &mut undo1);
        u.apply_transaction(&a2, 1, &mut undo1);
        u.apply_transaction(&b1, 1, &mut undo1);
        check(&u, "after creation");
        assert_eq!(u.balance_of(&Hash256([1; 32])), (8_000, 2));

        // A spend: key hash 1 loses an output, key hash 3 gains one.
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: a1.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![output(4_000, 3)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&spend, 2, &mut undo2);
        check(&u, "after spend");
        assert_eq!(u.balance_of(&Hash256([1; 32])), (3_000, 1));
        assert_eq!(u.balance_of(&Hash256([3; 32])), (4_000, 1));

        // Undo: the index must return exactly to the previous state.
        u.undo(&undo2);
        check(&u, "after undo");
        assert_eq!(u.balance_of(&Hash256([1; 32])), (8_000, 2));
        assert_eq!(
            u.balance_of(&Hash256([3; 32])),
            (0, 0),
            "an undone output must no longer count"
        );

        // An unknown key hash has neither balance nor output.
        assert_eq!(u.balance_of(&Hash256([42; 32])), (0, 0));
    }

    /// The commitment maintained on the fly matches the recomputed commitment,
    /// in every circumstance: creations, spends, undos, replacement of an
    /// output under the same outpoint, and removal of an unknown output.
    ///
    /// This is the contract that allows `commitment()` to no longer walk the
    /// set. The slightest drift between the two paths would make the whole
    /// network refuse a valid snapshot, or accept a false one.
    #[test]
    fn incremental_commitment_always_matches_recomputation() {
        fn check(u: &UtxoSet, stage: &str) {
            assert_eq!(
                u.commitment(),
                u.recomputed_commitment(),
                "{stage}: the incremental commitment diverges from the recomputation"
            );
        }

        let mut u = UtxoSet::new();
        check(&u, "empty");
        let empty = u.commitment();

        let a1 = coinbase(5_000, 1);
        let a2 = coinbase(3_000, 1);
        let b1 = coinbase(7_000, 2);
        let mut undo1 = UndoRecord::default();
        u.apply_transaction(&a1, 1, &mut undo1);
        check(&u, "one creation");
        u.apply_transaction(&a2, 1, &mut undo1);
        u.apply_transaction(&b1, 1, &mut undo1);
        check(&u, "three creations");
        let three = u.commitment();
        assert_ne!(three, empty);

        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: a1.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![output(4_000, 3), output(900, 4)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&spend, 2, &mut undo2);
        check(&u, "after spend");

        // The undo brings back exactly the previous commitment: it is not
        // merely "consistent with the recomputation", it is the same value.
        u.undo(&undo2);
        check(&u, "after undo");
        assert_eq!(u.commitment(), three);

        // Replacement under the same outpoint: the old element must leave the
        // commitment before the new one enters it.
        let point = OutPoint {
            txid: b1.txid(),
            index: 0,
        };
        u.insert(
            point,
            UtxoEntry {
                output: output(7_000, 9),
                height: 1,
                is_coinbase: true,
            },
        );
        check(&u, "after replacement");
        assert_ne!(u.commitment(), three);

        // Removing an unknown output touches nothing.
        let before = u.commitment();
        assert!(u
            .remove(&OutPoint {
                txid: Hash256([0xEE; 32]),
                index: 7,
            })
            .is_none());
        assert_eq!(u.commitment(), before);
        check(&u, "after unknown removal");

        // Undoing everything brings back the empty set, and its commitment.
        u.undo(&undo1);
        u.remove(&point);
        assert!(u.is_empty());
        check(&u, "empty again");
        assert_eq!(u.commitment(), empty);
    }

    #[test]
    fn applying_coinbase_creates_output() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        let cb = coinbase(5_000, 1);
        u.apply_transaction(&cb, 1, &mut undo);

        assert_eq!(u.len(), 1);
        assert_eq!(u.total_value(), Amount::from_units(5_000));
        let e = u
            .get(&OutPoint {
                txid: cb.txid(),
                index: 0,
            })
            .unwrap();
        assert!(e.is_coinbase);
        assert_eq!(e.height, 1);
    }

    #[test]
    fn spending_consumes_and_creates() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        let cb = coinbase(10_000, 1);
        u.apply_transaction(&cb, 1, &mut undo);

        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: cb.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![output(6_000, 2), output(3_000, 1)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&spend, 2, &mut undo2);

        assert_eq!(u.len(), 2);
        // 1,000 units are missing: they are the fee, collected by the coinbase.
        assert_eq!(u.total_value(), Amount::from_units(9_000));
        assert!(!u.contains(&OutPoint {
            txid: cb.txid(),
            index: 0
        }));
    }

    #[test]
    fn undo_restores_state_exactly() {
        let mut u = UtxoSet::new();
        let mut undo1 = UndoRecord::default();
        let cb = coinbase(10_000, 1);
        u.apply_transaction(&cb, 1, &mut undo1);
        let before = u.total_value();
        let len_before = u.len();

        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: cb.txid(),
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![output(9_000, 2)],
            lock_time: 0,
        };
        let mut undo2 = UndoRecord::default();
        u.apply_transaction(&spend, 2, &mut undo2);
        assert_ne!(u.total_value(), before);

        u.undo(&undo2);
        assert_eq!(
            u.total_value(),
            before,
            "the undo did not restore the state"
        );
        assert_eq!(u.len(), len_before);
        assert!(u.contains(&OutPoint {
            txid: cb.txid(),
            index: 0
        }));
    }

    #[test]
    fn immature_coinbase_is_not_spendable() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        u.apply_transaction(&coinbase(10_000, 7), 10, &mut undo);
        let h = Hash256([7u8; 32]);

        assert!(u.spendable_for(&h, 50, 200).is_empty(), "too early");
        assert_eq!(u.spendable_for(&h, 210, 200).len(), 1, "should be mature");
    }

    #[test]
    fn filtering_by_key_works() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        u.apply_transaction(&coinbase(1_000, 1), 0, &mut undo);
        u.apply_transaction(&coinbase(2_000, 2), 0, &mut undo);

        assert_eq!(u.spendable_for(&Hash256([1u8; 32]), 1000, 0).len(), 1);
        assert_eq!(u.spendable_for(&Hash256([9u8; 32]), 1000, 0).len(), 0);
    }

    #[test]
    fn utxo_order_is_deterministic() {
        let mut u = UtxoSet::new();
        let mut undo = UndoRecord::default();
        for i in 0..20u8 {
            let mut cb = coinbase(1_000, 1);
            cb.inputs[0].witness.signature = vec![i];
            u.apply_transaction(&cb, 0, &mut undo);
        }
        let h = Hash256([1u8; 32]);
        let a: Vec<_> = u
            .spendable_for(&h, 1000, 0)
            .iter()
            .map(|(o, _)| *o)
            .collect();
        let b: Vec<_> = u
            .spendable_for(&h, 1000, 0)
            .iter()
            .map(|(o, _)| *o)
            .collect();
        assert_eq!(a, b, "the order must be stable between two calls");
    }

    #[test]
    fn commitment_is_independent_of_insertion_order() {
        // Two identical sets, filled in two opposite orders, have the same
        // commitment: that is the whole promise of MuHash.
        let mut a = UtxoSet::new();
        let mut b = UtxoSet::new();
        let mut entries = Vec::new();
        for i in 0..25u8 {
            let o = OutPoint {
                txid: Hash256([i; 32]),
                index: u32::from(i),
            };
            let e = UtxoEntry {
                output: output(1_000 + u64::from(i), i),
                height: u64::from(i),
                is_coinbase: i % 4 == 0,
            };
            entries.push((o, e));
        }
        for (o, e) in &entries {
            a.insert(*o, *e);
        }
        for (o, e) in entries.iter().rev() {
            b.insert(*o, *e);
        }
        assert_eq!(a.commitment(), b.commitment());
    }

    #[test]
    fn empty_set_commitment_is_stable() {
        assert_eq!(UtxoSet::new().commitment(), UtxoSet::new().commitment());
    }

    #[test]
    fn spending_changes_commitment_and_undo_restores_it() {
        let mut u = UtxoSet::new();
        let mut undo0 = UndoRecord::default();
        u.apply_transaction(&coinbase(10_000, 1), 1, &mut undo0);
        let before = u.commitment();

        let cb_txid = coinbase(10_000, 1).txid();
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: cb_txid,
                    index: 0,
                },
                witness: Witness::default(),
                sequence: 0,
            }],
            outputs: vec![output(9_000, 2)],
            lock_time: 0,
        };
        let mut undo = UndoRecord::default();
        u.apply_transaction(&spend, 2, &mut undo);
        assert_ne!(
            u.commitment(),
            before,
            "spending must change the commitment"
        );

        u.undo(&undo);
        assert_eq!(u.commitment(), before, "undo must restore the commitment");
    }

    #[test]
    fn moving_ownership_changes_commitment() {
        // The forgery the emission check does not see: same amount, same
        // height, different beneficiary. The commitment does see it.
        let o = OutPoint {
            txid: Hash256([9; 32]),
            index: 0,
        };
        let mut honest = UtxoSet::new();
        honest.insert(
            o,
            UtxoEntry {
                output: output(5_000, 1),
                height: 3,
                is_coinbase: false,
            },
        );
        let mut forged = UtxoSet::new();
        forged.insert(
            o,
            UtxoEntry {
                output: output(5_000, 2), // same amount, different key hash
                height: 3,
                is_coinbase: false,
            },
        );
        assert_ne!(honest.commitment(), forged.commitment());
    }
}
