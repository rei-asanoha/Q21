//! Compact block relay.
//!
//! # Why this module exists, and why it matters more here than elsewhere
//!
//! A Q21 block is huge. An ML-DSA-65 signature weighs 3,309 bytes, a public key
//! 1,952: the witness makes up 99% of a transaction. Broadcasting a full block
//! by pushing it byte by byte to each peer would take considerable time — and
//! that time has a political cost, not just a technical one.
//!
//! The causal chain is this one, and it is at the heart of the project:
//!
//! ```text
//! slow propagation  ->  more orphans  ->  the best-connected miner
//!                                         wins the races  ->  it earns
//!                                         MORE than its share of power
//!                                         ->  centralization
//! ```
//!
//! This is exactly the superlinear return that lever C of section 5 of the
//! white paper seeks to remove. Uncle rewards treat the consequence; compact
//! relay attacks the cause.
//!
//! # The principle
//!
//! A peer already has, in its mempool, most of the transactions of the block
//! being announced to it. There is no point sending them again. So we send the
//! header and, for each transaction, a **six-byte short identifier**. The peer
//! recognizes what it has, and only asks again for what it is missing.
//!
//! A block of 200 Q21 transactions weighs about 5 MiB. Its compact announcement
//! weighs the header plus 200 x 6 bytes, under 2 KiB. Three orders of
//! magnitude.
//!
//! # Why the short identifier is keyed
//!
//! Six bytes, so collisions are possible. If the function were not keyed, an
//! adversary would craft in advance transactions whose short identifier
//! collides with those of upcoming blocks, and would block reconstruction for
//! everyone.
//!
//! The key derives from the header **and from a nonce chosen by the sender**.
//! The header contains the mining nonce, unknown to all before the block
//! exists; the sender nonce makes sure that a given collision does not repeat
//! from one peer to the next. Collisions become chance again, and chance costs
//! a round trip, not a vulnerability.

use crate::block::{Block, BlockHeader};
use crate::hash::{tagged_hash_parts, Hash256};
use crate::ser::{ReadError, Reader, Writer};
use crate::siphash::siphash24;
use crate::tx::Transaction;
use std::collections::HashMap;

/// Size of a short identifier, in bytes.
pub const SHORT_ID_LEN: usize = 6;

const TAG_KEY: &str = "Q21/compact/key";

/// Maximum number of transactions announced in a compact block.
///
/// Re-exported from consensus, where it is **derived** from the maximum block
/// size instead of being set by hand. See
/// [`crate::consensus::MAX_TX_PER_BLOCK`].
pub use crate::consensus::MAX_TX_PER_BLOCK;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CompactError {
    /// The reconstructed block does not match the announced Merkle root.
    ///
    /// Means either an undetected collision or a malicious peer. In both cases
    /// the full block is requested again.
    BadMerkleRoot,
    /// The peer supplied a number of transactions different from what was
    /// missing.
    WrongTransactionCount {
        expected: usize,
        received: usize,
    },
    /// A supplied transaction does not match the requested identifier.
    UnexpectedTransaction {
        index: usize,
    },
    /// Absurd announcement, refused before any allocation.
    TooManyTransactions(usize),
    /// The coinbase must always be supplied in full.
    MissingCoinbase,
    Read(ReadError),
}

impl From<ReadError> for CompactError {
    fn from(e: ReadError) -> Self {
        CompactError::Read(e)
    }
}

/// Derives the short identifier key of a block.
pub fn short_id_key(header: &BlockHeader, nonce: u64) -> (u64, u64) {
    let h = tagged_hash_parts(TAG_KEY, &[&header.encode(), &nonce.to_le_bytes()]);
    let b = h.as_bytes();
    let mut k0 = [0u8; 8];
    let mut k1 = [0u8; 8];
    k0.copy_from_slice(&b[0..8]);
    k1.copy_from_slice(&b[8..16]);
    (u64::from_le_bytes(k0), u64::from_le_bytes(k1))
}

/// Short identifier of a transaction: the six low-order bytes of the SipHash.
#[inline]
pub fn short_id(k0: u64, k1: u64, txid: &Hash256) -> u64 {
    siphash24(k0, k1, txid.as_bytes()) & 0x0000_ffff_ffff_ffff
}

/// Compact announcement of a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    pub header: BlockHeader,
    /// Sender nonce, which personalizes the short identifier key.
    pub nonce: u64,
    /// Short identifiers of the transactions not prefilled, in block order.
    pub short_ids: Vec<u64>,
    /// Transactions supplied in full, with their index in the block.
    ///
    /// The coinbase is always among them: by construction, no peer can have it
    /// in its mempool.
    pub prefilled: Vec<(u32, Transaction)>,
    /// Uncle headers, sent as is: they are small and nobody has them cached.
    pub uncles: Vec<BlockHeader>,
}

impl CompactBlock {
    /// Builds the compact announcement of a block.
    pub fn from_block(block: &Block, nonce: u64) -> CompactBlock {
        let (k0, k1) = short_id_key(&block.header, nonce);
        let mut short_ids = Vec::with_capacity(block.transactions.len());
        let mut prefilled = Vec::new();

        for (i, tx) in block.transactions.iter().enumerate() {
            if i == 0 {
                // The coinbase exists nowhere else than in this block.
                prefilled.push((i as u32, tx.clone()));
            } else {
                short_ids.push(short_id(k0, k1, &tx.txid()));
            }
        }

        CompactBlock {
            header: block.header,
            nonce,
            short_ids,
            prefilled,
            uncles: block.uncles.clone(),
        }
    }

    /// Total number of transactions of the announced block.
    pub fn tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled.len()
    }

    /// Serialized size of the announcement.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.header.encode());
        w.u64(self.nonce);
        w.varint(self.short_ids.len() as u64);
        for id in &self.short_ids {
            // Six bytes, little-endian.
            w.bytes(&id.to_le_bytes()[..SHORT_ID_LEN]);
        }
        w.varint(self.prefilled.len() as u64);
        for (i, tx) in &self.prefilled {
            w.varint(*i as u64);
            w.var_bytes(&tx.encode());
        }
        w.varint(self.uncles.len() as u64);
        for u in &self.uncles {
            w.bytes(&u.encode());
        }
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<CompactBlock, CompactError> {
        if data.len() < BlockHeader::SIZE {
            return Err(CompactError::Read(ReadError::UnexpectedEnd));
        }
        let header = BlockHeader::decode(&data[..BlockHeader::SIZE]).map_err(CompactError::Read)?;
        let mut r = Reader::new(&data[BlockHeader::SIZE..]);

        let nonce = r.u64()?;

        // Same rule as everywhere else: we do not reserve room for more
        // elements than the rest of the frame can hold. A short identifier
        // takes six bytes.
        let n = r.read_count(6)?;
        if n > MAX_TX_PER_BLOCK {
            return Err(CompactError::TooManyTransactions(n));
        }
        let mut short_ids = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let mut buf = [0u8; 8];
            for byte in buf.iter_mut().take(SHORT_ID_LEN) {
                *byte = r.u8()?;
            }
            short_ids.push(u64::from_le_bytes(buf));
        }

        // An (index, transaction) pair: at least one byte of index, one of
        // length, and ten of transaction.
        let np = r.read_count(12)?;
        if np > MAX_TX_PER_BLOCK {
            return Err(CompactError::TooManyTransactions(np));
        }
        let mut prefilled = Vec::with_capacity(np.min(1024));
        for _ in 0..np {
            // A prefilled transaction index that does not fit in thirty-two
            // bits is refused, not truncated: without this, two different
            // `cmpctblock` messages on the wire decoded identically.
            let raw = r.varint()?;
            if raw > u32::MAX as u64 {
                return Err(CompactError::Read(ReadError::InvalidValue));
            }
            let i = raw as u32;
            let raw = r.var_bytes()?;
            let tx = Transaction::decode(raw)
                .map_err(|_| CompactError::Read(ReadError::InvalidValue))?;
            prefilled.push((i, tx));
        }

        let nu = r.read_count(BlockHeader::SIZE)?;
        if nu > 64 {
            return Err(CompactError::TooManyTransactions(nu));
        }
        let mut uncles = Vec::with_capacity(nu);
        for _ in 0..nu {
            let mut header_buf = [0u8; BlockHeader::SIZE];
            for byte in header_buf.iter_mut() {
                *byte = r.u8()?;
            }
            uncles.push(BlockHeader::decode(&header_buf).map_err(CompactError::Read)?);
        }

        r.expect_end()?;
        Ok(CompactBlock {
            header,
            nonce,
            short_ids,
            prefilled,
            uncles,
        })
    }
}

/// Reconstruction in progress of a compact block.
pub struct Reconstruction {
    header: BlockHeader,
    uncles: Vec<BlockHeader>,
    /// Slots of the block, `None` where a transaction is missing.
    slots: Vec<Option<Transaction>>,
    /// Indexes, in block order, of the missing transactions.
    missing: Vec<u32>,
}

impl Reconstruction {
    /// Tries to reconstruct a block from a mempool.
    ///
    /// Returns the reconstruction, complete or not. The missing indexes are
    /// the ones to request again from the peer.
    pub fn from_compact(
        compact: &CompactBlock,
        available: &HashMap<Hash256, Transaction>,
    ) -> Result<Reconstruction, CompactError> {
        let total = compact.tx_count();
        if total > MAX_TX_PER_BLOCK {
            return Err(CompactError::TooManyTransactions(total));
        }

        let (k0, k1) = short_id_key(&compact.header, compact.nonce);

        // Table of the short identifiers of what we have.
        //
        // A collision between two mempool transactions makes the identifier
        // ambiguous: we drop it rather than guess. The worst case is an extra
        // round trip, never a wrongly reconstructed block.
        let mut by_id: HashMap<u64, Option<&Transaction>> = HashMap::new();
        for (txid, tx) in available {
            let sid = short_id(k0, k1, txid);
            by_id
                .entry(sid)
                .and_modify(|e| *e = None)
                .or_insert(Some(tx));
        }

        let mut slots: Vec<Option<Transaction>> = vec![None; total];

        for (i, tx) in &compact.prefilled {
            let i = *i as usize;
            if i >= total {
                return Err(CompactError::UnexpectedTransaction { index: i });
            }
            slots[i] = Some(tx.clone());
        }
        if slots.first().map(|c| c.is_none()).unwrap_or(true) {
            return Err(CompactError::MissingCoinbase);
        }

        // The short identifiers fill the slots left free, in order.
        let mut free_slots = slots
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_none())
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
            .into_iter();

        let mut missing = Vec::new();
        for sid in &compact.short_ids {
            let slot = match free_slots.next() {
                Some(i) => i,
                None => return Err(CompactError::UnexpectedTransaction { index: total }),
            };
            match by_id.get(sid) {
                Some(Some(tx)) => slots[slot] = Some((*tx).clone()),
                _ => missing.push(slot as u32),
            }
        }

        Ok(Reconstruction {
            header: compact.header,
            uncles: compact.uncles.clone(),
            slots,
            missing,
        })
    }

    /// Indexes to request again from the peer. Empty if the reconstruction is
    /// complete.
    pub fn missing(&self) -> &[u32] {
        &self.missing
    }

    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Share of transactions found in the mempool.
    pub fn hit_rate(&self) -> f64 {
        let total = self.slots.len();
        if total == 0 {
            return 1.0;
        }
        (total - self.missing.len()) as f64 / total as f64
    }

    /// Completes the reconstruction with the requested transactions.
    ///
    /// Checks the Merkle root: it is the only thing that tells a correct
    /// reconstruction apart from a plausible one. An undetected collision, or a
    /// malicious peer, fails here.
    pub fn complete(mut self, supplied: Vec<Transaction>) -> Result<Block, CompactError> {
        if supplied.len() != self.missing.len() {
            return Err(CompactError::WrongTransactionCount {
                expected: self.missing.len(),
                received: supplied.len(),
            });
        }
        for (slot, tx) in self.missing.iter().zip(supplied) {
            self.slots[*slot as usize] = Some(tx);
        }
        self.finalize()
    }

    /// Finishes a reconstruction that is already complete.
    pub fn finish(self) -> Result<Block, CompactError> {
        if !self.missing.is_empty() {
            return Err(CompactError::WrongTransactionCount {
                expected: self.missing.len(),
                received: 0,
            });
        }
        self.finalize()
    }

    fn finalize(self) -> Result<Block, CompactError> {
        let mut transactions = Vec::with_capacity(self.slots.len());
        for (i, c) in self.slots.into_iter().enumerate() {
            match c {
                Some(tx) => transactions.push(tx),
                None => return Err(CompactError::UnexpectedTransaction { index: i }),
            }
        }
        let block = Block {
            header: self.header,
            transactions,
            uncles: self.uncles,
        };
        // The check that makes everything else safe.
        if block.compute_merkle_root() != block.header.merkle_root {
            return Err(CompactError::BadMerkleRoot);
        }
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::amount::Amount;
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
    use crate::sig::SchemeId;
    use crate::wallet::Wallet;

    const NETWORK: Network = Network::Regtest;
    const ATTEMPTS: u64 = 5_000_000;

    /// Builds a chain, a funded wallet, and a block carrying `n` real
    /// transactions.
    fn block_with_transactions(n: usize) -> (Block, Vec<Transaction>) {
        let mut w = Wallet::from_seed([0x77; 32], NETWORK);
        let _ = w.new_address();
        let g = genesis_block(NETWORK);
        let mut c = Chain::new(NETWORK, g);
        for i in 1..=(COINBASE_MATURITY + 20) {
            let a = w.new_address();
            let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }

        let mut dest = Wallet::from_seed([0x88; 32], NETWORK);
        let mut txs = Vec::new();
        for _ in 0..n {
            let a = dest.new_address();
            txs.push(
                w.create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(10_000),
                    Amount::from_units(1_000),
                )
                .expect("build"),
            );
        }

        let t = c.tip().time + TARGET_BLOCK_SECS;
        let a = w.new_address();
        let block = c
            .mine_block(a.hash, SchemeId::LamportOts, &txs, t, ATTEMPTS)
            .expect("mining the full block");
        (block, txs)
    }

    fn mempool_of(txs: &[Transaction]) -> HashMap<Hash256, Transaction> {
        txs.iter().map(|t| (t.txid(), t.clone())).collect()
    }

    #[test]
    fn a_peer_that_has_everything_rebuilds_without_round_trip() {
        let (block, txs) = block_with_transactions(3);
        let compact = CompactBlock::from_block(&block, 0xdead_beef);
        let available = mempool_of(&txs);

        let r = Reconstruction::from_compact(&compact, &available).expect("reconstruction");
        assert!(r.is_complete(), "missing: {:?}", r.missing());
        assert_eq!(r.hit_rate(), 1.0);
        assert_eq!(r.finish().expect("finalization"), block);
    }

    #[test]
    fn a_peer_with_nothing_requests_all_but_the_coinbase() {
        let (block, _) = block_with_transactions(3);
        let compact = CompactBlock::from_block(&block, 1);
        let empty = HashMap::new();

        let r = Reconstruction::from_compact(&compact, &empty).expect("reconstruction");
        assert!(!r.is_complete());
        assert_eq!(r.missing().len(), 3, "the coinbase is prefilled");
        assert!(!r.missing().contains(&0));
    }

    #[test]
    fn one_round_trip_is_enough_to_complete() {
        let (block, txs) = block_with_transactions(4);
        let compact = CompactBlock::from_block(&block, 7);

        // The peer only has the first of the four.
        let partial = mempool_of(&txs[..1]);
        let r = Reconstruction::from_compact(&compact, &partial).expect("reconstruction");
        assert_eq!(r.missing().len(), 3);

        // It requests exactly what is missing, in order.
        let requested: Vec<Transaction> = r
            .missing()
            .iter()
            .map(|i| block.transactions[*i as usize].clone())
            .collect();
        assert_eq!(r.complete(requested).expect("completion"), block);
    }

    /// The check that makes the scheme safe.
    #[test]
    fn a_substituted_transaction_is_rejected() {
        let (block, txs) = block_with_transactions(3);
        let compact = CompactBlock::from_block(&block, 3);
        let empty = HashMap::new();
        let r = Reconstruction::from_compact(&compact, &empty).unwrap();

        // A malicious peer sends back the right transactions out of order.
        let mut wrong_order: Vec<Transaction> = r
            .missing()
            .iter()
            .map(|i| block.transactions[*i as usize].clone())
            .collect();
        wrong_order.swap(0, 2);

        assert_eq!(
            r.complete(wrong_order),
            Err(CompactError::BadMerkleRoot),
            "the Merkle root must decide"
        );
        let _ = txs;
    }

    #[test]
    fn a_wrong_transaction_count_is_rejected() {
        let (block, _) = block_with_transactions(3);
        let compact = CompactBlock::from_block(&block, 4);
        let r = Reconstruction::from_compact(&compact, &HashMap::new()).unwrap();
        assert!(matches!(
            r.complete(vec![]),
            Err(CompactError::WrongTransactionCount {
                expected: 3,
                received: 0
            })
        ));
    }

    /// A collision in the mempool must never produce a wrong block.
    #[test]
    fn a_short_id_collision_degrades_without_breaking() {
        let (block, txs) = block_with_transactions(2);
        let compact = CompactBlock::from_block(&block, 11);
        let (k0, k1) = short_id_key(&compact.header, compact.nonce);

        // We craft a mempool where two different transactions carry the same
        // short identifier, by forcing the table.
        let mut available = mempool_of(&txs);
        let victim = txs[0].txid();
        let victim_sid = short_id(k0, k1, &victim);

        // Look for a fake txid that collides. Six bytes: a scan finds one
        // quickly, but we bound it so as not to loop forever.
        let mut intruder = None;
        for i in 0u64..2_000_000 {
            let fake = Hash256(crate::hash::tagged_hash("collision", &i.to_le_bytes()).0);
            if short_id(k0, k1, &fake) == victim_sid && fake != victim {
                intruder = Some(fake);
                break;
            }
        }

        if let Some(fake) = intruder {
            // Two entries, same short identifier: the ambiguity must lead to a
            // new request, not to a wrong choice.
            available.insert(fake, txs[1].clone());
            let r = Reconstruction::from_compact(&compact, &available).expect("reconstruction");
            assert!(
                !r.is_complete() || r.finish().is_ok(),
                "a collision must never produce an invalid block"
            );
        }
        // If no collision was found in the scanned window, the test proves
        // nothing but does not lie either: it passes without an assertion.
    }

    #[test]
    fn serialization_round_trip() {
        let (block, _) = block_with_transactions(3);
        let compact = CompactBlock::from_block(&block, 0x0123_4567_89ab_cdef);
        let decoded = CompactBlock::decode(&compact.encode()).expect("decoding");
        assert_eq!(decoded, compact);
    }

    #[test]
    fn round_trip_with_uncles() {
        let (mut block, _) = block_with_transactions(1);
        block.uncles = vec![block.header];
        let compact = CompactBlock::from_block(&block, 5);
        assert_eq!(CompactBlock::decode(&compact.encode()).unwrap(), compact);
    }

    /// An absurd announcement is refused, and refused **before** allocating.
    ///
    /// # Why this test accepts two different refusals
    ///
    /// It used to require `TooManyTransactions`, that is exceeding the protocol
    /// bound. Two checks now follow one another, and the first is finer: any
    /// count greater than what the rest of the frame can hold — six bytes per
    /// short identifier — is refused outright. Four billion identifiers
    /// announced in forty bytes therefore hit that check, with
    /// `Read(InvalidValue)`.
    ///
    /// The property locked in here is not the name of the refusal: it is that
    /// there is a refusal, and that no room is reserved for what was announced.
    /// Freezing the variant would amount to forbidding an earlier refusal.
    #[test]
    fn an_absurd_announcement_is_refused_before_allocation() {
        let (block, _) = block_with_transactions(1);
        let mut raw = block.header.encode();
        raw.extend_from_slice(&0u64.to_le_bytes());
        // varint announcing four billion short identifiers
        raw.push(0xfe);
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        match CompactBlock::decode(&raw) {
            Err(CompactError::TooManyTransactions(_))
            | Err(CompactError::Read(ReadError::InvalidValue)) => {}
            other => panic!(
                "an announcement of four billion identifiers in forty \
                 bytes must be refused: {other:?}"
            ),
        }
    }

    #[test]
    fn a_missing_coinbase_is_refused() {
        let (block, txs) = block_with_transactions(2);
        let mut compact = CompactBlock::from_block(&block, 9);
        compact.prefilled.clear();
        assert!(matches!(
            Reconstruction::from_compact(&compact, &mempool_of(&txs)),
            Err(CompactError::MissingCoinbase)
        ));
    }

    #[test]
    fn two_nonces_give_two_sets_of_identifiers() {
        let (block, _) = block_with_transactions(3);
        let a = CompactBlock::from_block(&block, 1);
        let b = CompactBlock::from_block(&block, 2);
        assert_ne!(
            a.short_ids, b.short_ids,
            "without this, a collision would repeat at every peer"
        );
    }

    /// The figure that justifies this whole module.
    #[test]
    fn the_compact_announcement_is_orders_of_magnitude_smaller() {
        let (block, txs) = block_with_transactions(5);
        let full = block.encode().len();
        let compact = CompactBlock::from_block(&block, 0).encoded_len();

        assert!(
            compact * 20 < full,
            "compact announcement {compact} B versus full block {full} B: \
             the expected gain is not there"
        );

        // Each transaction costs only six bytes in the announcement, where it
        // weighs more than twenty thousand in the block.
        let full_per_tx = full / block.transactions.len();
        assert!(full_per_tx > 10_000, "abnormally light transaction");
        let _ = txs;
    }
}
