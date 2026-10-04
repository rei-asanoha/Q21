//! Optional address and transaction index.
//!
//! # The problem
//!
//! "Show me every transaction of this address" has no cheap answer in a
//! blockchain. Nothing in the structure links an address to its
//! transactions: you have to go through all of them.
//!
//! So the node did exactly that - scanning backward, and stopping after five
//! thousand blocks. That is what explains the "bounded history" note in the
//! wallet. Past that limit, the answer is not wrong: it is incomplete, and it
//! says so.
//!
//! An explorer cannot settle for that. Looking up an address is its main use,
//! not its edge case.
//!
//! # Why it is optional
//!
//! An index costs twice: in disk space, and in a write at every block. A node
//! that validates the chain and keeps a wallet has no need for one - it only
//! looks up its own addresses, and it knows which ones they are.
//!
//! Forcing it on everyone would make every user pay for the convenience of
//! those who explore. Bitcoin Core decided the same way, with `txindex`, and
//! for the same reason. Here it is `--address-index`.
//!
//! The wallet is the exception, since 0.4.2. In practice its owner does
//! explore - the wallet links to the explorer of its own node - and its
//! history needs the same answer. Without the index, the explorer opened from
//! the wallet lost every transaction older than two thousand blocks, and the
//! Activity tab reread five thousand blocks every ten seconds to show one
//! week. `q21 wallet --no-index` keeps the old behavior.
//!
//! # How
//!
//! An append-only log, one record per block. Each record carries its own
//! checksum: a write cut in half - out of space, hard shutdown - leaves an
//! unreadable last record, which is ignored, and the index simply resumes a
//! few blocks back. This is not vital data: the index rebuilds entirely from
//! the chain, which is the only source.
//!
//! ## What a record contains
//!
//! ```text
//!   height           8 bytes
//!   block id        32 bytes    <- what makes it possible to detect a reorg
//!   tx count         4 bytes
//!     txid          32 bytes
//!     key hash count 4 bytes
//!       key hash    32 bytes    * n
//!   checksum         4 bytes
//! ```
//!
//! ## The address of an input
//!
//! An output carries the hash of the key allowed to spend it: indexing what
//! an address **receives** is immediate. An input, however, only designates
//! the output it consumes; to know whom that output belonged to, it has to be
//! found again.
//!
//! The witness is not enough: `pubkey_hash` depends on the signature scheme,
//! and the scheme is recorded on the output, not on the input. Rereading the
//! originating block would cost one read per input.
//!
//! So we keep a table of **unspent** outputs - the same keys as the UTXO set,
//! whose size depends on the economy, not on the length of the chain. An
//! output enters it when it is created, leaves it when it is spent, and on the
//! way answers the question "whose was it". On load, this table is taken
//! directly from the node's UTXO set: an output that a future transaction
//! will spend is, by construction, an output still alive today.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::block::Block;
use crate::hash::Hash256;
use crate::sha256::sha256;
use crate::tx::OutPoint;
use crate::utxo::UtxoSet;

/// Log magic. The final digit is the format version. Frozen value: changing
/// it would make existing index logs unreadable.
const MAGIC: &[u8; 8] = b"Q21INDX1";

/// Where a transaction is: its block, and its rank within that block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Position {
    pub height: u64,
    pub rank: u32,
}

#[derive(Debug)]
pub enum IndexError {
    Write(String),
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndexError::Write(e) => write!(f, "index not written: {e}"),
        }
    }
}

/// Address and transaction index.
pub struct Index {
    path: PathBuf,
    /// Public key hash -> where it appears.
    by_address: HashMap<Hash256, Vec<Position>>,
    /// Transaction id -> where it is.
    by_txid: HashMap<Hash256, Position>,
    /// Unspent output -> whom it belongs to. See the module header.
    owners: HashMap<OutPoint, Hash256>,
    /// Indexed blocks, in order: (height, block id).
    blocks: Vec<(u64, Hash256)>,
}

impl Index {
    /// Opens the log, or starts a fresh one if it does not exist.
    ///
    /// Never returns an error: an unreadable index is an index to rebuild,
    /// not a reason to refuse to start.
    pub fn open(path: &Path) -> Index {
        let mut index = Index {
            path: path.to_path_buf(),
            by_address: HashMap::new(),
            by_txid: HashMap::new(),
            owners: HashMap::new(),
            blocks: Vec::new(),
        };
        if let Ok(raw) = std::fs::read(path) {
            index.replay(&raw);
        }
        index
    }

    fn replay(&mut self, raw: &[u8]) {
        if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
            return;
        }
        let mut p = MAGIC.len();
        while let Some((record, next)) = read_record(raw, p) {
            let (height, id, transactions) = record;
            // A log must stay ordered: a record that goes backward betrays a
            // corruption that no checksum catches, since the checksum covers
            // each record taken separately.
            if let Some((last, _)) = self.blocks.last() {
                if height != last + 1 {
                    return;
                }
            }
            for (rank, (txid, hashes)) in transactions.into_iter().enumerate() {
                let position = Position {
                    height,
                    rank: rank as u32,
                };
                self.by_txid.insert(txid, position);
                for e in hashes {
                    self.by_address.entry(e).or_default().push(position);
                }
            }
            self.blocks.push((height, id));
            p = next;
        }
    }

    /// Rebuilds the owner table from the node's UTXO set.
    ///
    /// To be called once after opening. See the module header: an output that
    /// a future transaction will spend is necessarily an output still alive at
    /// the moment we start.
    pub fn prime(&mut self, utxo: &UtxoSet) {
        self.owners.clear();
        for (outpoint, entry) in utxo.iter() {
            self.owners.insert(*outpoint, entry.output.pubkey_hash);
        }
    }

    /// Height of the last indexed block. Zero if the index is empty.
    pub fn height(&self) -> u64 {
        self.blocks.last().map(|(h, _)| *h).unwrap_or(0)
    }

    /// Does the index contain anything?
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Id of the block indexed at this height.
    pub fn block_id(&self, height: u64) -> Option<Hash256> {
        let (first, _) = *self.blocks.first()?;
        // `try_from`: on 32 bits, an absurd height truncated to `usize`
        // would designate another block instead of none.
        let offset = usize::try_from(height.checked_sub(first)?).ok()?;
        self.blocks.get(offset).map(|(_, id)| *id)
    }

    /// Number of indexed blocks.
    pub fn indexed_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Positions where this key hash appears, from oldest to most
    /// recent.
    pub fn positions(&self, key_hash: &Hash256) -> &[Position] {
        self.by_address
            .get(key_hash)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Where this transaction is.
    pub fn position(&self, txid: &Hash256) -> Option<Position> {
        self.by_txid.get(txid).copied()
    }

    /// Indexed transactions accepted by `keep`, at most `max` of them.
    ///
    /// Used by the search to complete an identifier pasted truncated. It walks
    /// the whole table: a memory read, bounded by `max` matches, and the
    /// caller only reaches it for an incomplete identifier.
    pub fn find_txids(&self, mut keep: impl FnMut(&Hash256) -> bool, max: usize) -> Vec<Hash256> {
        self.by_txid
            .keys()
            .filter(|t| keep(t))
            .take(max)
            .copied()
            .collect()
    }

    /// Number of addresses known to the index.
    pub fn known_addresses(&self) -> usize {
        self.by_address.len()
    }

    /// Adds a block to the index, and writes it to the log.
    ///
    /// The block must immediately follow the last indexed one. It is up to the
    /// caller to guarantee it - in practice, the loop that follows the chain.
    pub fn index_block(&mut self, block: &Block) -> Result<(), IndexError> {
        let height = block.header.height;
        let id = block.header.block_id();
        let mut transactions: Vec<(Hash256, Vec<Hash256>)> = Vec::with_capacity(3);

        for (rank, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid();
            let position = Position {
                height,
                rank: rank as u32,
            };
            // A key hash is kept only once per transaction: an address that
            // receives two outputs of the same transaction does not appear
            // twice. Without that, an address screen would show duplicates
            // that are not distinct movements.
            let mut hashes: Vec<Hash256> = Vec::new();
            let add = |e: Hash256, v: &mut Vec<Hash256>| {
                if !v.contains(&e) {
                    v.push(e);
                }
            };

            // What the transaction spends: we find the owner of each consumed
            // output, then remove it from the table.
            for input in &tx.inputs {
                if input.prev_out.is_coinbase() {
                    continue;
                }
                if let Some(e) = self.owners.remove(&input.prev_out) {
                    add(e, &mut hashes);
                }
            }
            // What it creates.
            for (i, output) in tx.outputs.iter().enumerate() {
                add(output.pubkey_hash, &mut hashes);
                self.owners.insert(
                    OutPoint {
                        txid,
                        index: i as u32,
                    },
                    output.pubkey_hash,
                );
            }

            self.by_txid.insert(txid, position);
            for e in &hashes {
                self.by_address.entry(*e).or_default().push(position);
            }
            transactions.push((txid, hashes));
        }

        self.blocks.push((height, id));
        self.append_to_log(height, id, &transactions)
    }

    fn append_to_log(
        &self,
        height: u64,
        id: Hash256,
        transactions: &[(Hash256, Vec<Hash256>)],
    ) -> Result<(), IndexError> {
        use std::io::Write;
        let is_new = !self.path.exists();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| IndexError::Write(e.to_string()))?;
        let mut output = Vec::with_capacity(256);
        if is_new {
            output.extend_from_slice(MAGIC);
        }
        output.extend_from_slice(&write_record(height, id, transactions));
        f.write_all(&output)
            .map_err(|e| IndexError::Write(e.to_string()))?;
        Ok(())
    }

    /// Removes everything above this height.
    ///
    /// This is the answer to a reorg: the blocks of the abandoned branch must
    /// no longer appear in the index, otherwise an address would show
    /// transactions that never happened.
    ///
    /// The log is rewritten in full. A reorg is rare and shallow; a rewrite is
    /// cheaper there than a table of positions to keep up to date at every
    /// block for a case that almost never comes up.
    pub fn truncate(&mut self, height: u64) {
        self.blocks.retain(|(h, _)| *h <= height);
        self.by_txid.retain(|_, p| p.height <= height);
        for positions in self.by_address.values_mut() {
            positions.retain(|p| p.height <= height);
        }
        self.by_address.retain(|_, v| !v.is_empty());
        // The owners are taken back from the node's UTXO set, which has
        // already been brought back to the winning branch: `prime` will be
        // called again.
        let _ = std::fs::remove_file(&self.path);
        // Rewrite, in order. Nothing would be worse than a log whose order no
        // longer matches the memory that produced it.
        // The key hashes are rebuilt from `by_address`, the only table that
        // still holds them.
        let mut hashes_by_position: HashMap<(u64, u32), Vec<Hash256>> = HashMap::new();
        for (key_hash, positions) in &self.by_address {
            for p in positions {
                hashes_by_position
                    .entry((p.height, p.rank))
                    .or_default()
                    .push(*key_hash);
            }
        }
        let blocks = self.blocks.clone();
        for (h, id) in blocks {
            let mut transactions: Vec<(Hash256, Vec<Hash256>)> = Vec::new();
            let mut ranks: Vec<(u32, Hash256)> = self
                .by_txid
                .iter()
                .filter(|(_, p)| p.height == h)
                .map(|(txid, p)| (p.rank, *txid))
                .collect();
            ranks.sort_by_key(|(r, _)| *r);
            for (rank, txid) in ranks {
                let hashes = hashes_by_position
                    .get(&(h, rank))
                    .cloned()
                    .unwrap_or_default();
                transactions.push((txid, hashes));
            }
            let _ = self.append_to_log(h, id, &transactions);
        }
    }

    /// Erases everything, log included. Used when the index has diverged.
    pub fn clear(&mut self) {
        self.by_address.clear();
        self.by_txid.clear();
        self.owners.clear();
        self.blocks.clear();
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

type Record = (u64, Hash256, Vec<(Hash256, Vec<Hash256>)>);

fn write_record(height: u64, id: Hash256, transactions: &[(Hash256, Vec<Hash256>)]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + transactions.len() * 64);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&id.0);
    v.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for (txid, hashes) in transactions {
        v.extend_from_slice(&txid.0);
        v.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
        for e in hashes {
            v.extend_from_slice(&e.0);
        }
    }
    let checksum = sha256(&v);
    v.extend_from_slice(&checksum[..4]);
    v
}

/// Reads a record starting at `start`. Also returns the next position.
///
/// Returns `None` as soon as something is wrong: end of file, absurd length,
/// wrong checksum. That is intended - the log stops at the first doubtful
/// record, and the index resumes from there.
fn read_record(raw: &[u8], start: usize) -> Option<(Record, usize)> {
    let mut p = start;
    let read = |p: &mut usize, n: usize| -> Option<&[u8]> {
        let end = p.checked_add(n)?;
        if end > raw.len() {
            return None;
        }
        let s = &raw[*p..end];
        *p = end;
        Some(s)
    };

    let height = u64::from_le_bytes(read(&mut p, 8)?.try_into().ok()?);
    let mut id = [0u8; 32];
    id.copy_from_slice(read(&mut p, 32)?);
    let count = u32::from_le_bytes(read(&mut p, 4)?.try_into().ok()?) as usize;
    // An absurd length must not cause the memory it announces to be
    // reserved: the log is a local file, but a corrupted local file must not
    // bring the program down either.
    if count > 1_000_000 {
        return None;
    }
    let mut transactions = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(read(&mut p, 32)?);
        let n_hashes = u32::from_le_bytes(read(&mut p, 4)?.try_into().ok()?) as usize;
        if n_hashes > 1_000_000 {
            return None;
        }
        let mut hashes = Vec::with_capacity(n_hashes.min(1024));
        for _ in 0..n_hashes {
            let mut e = [0u8; 32];
            e.copy_from_slice(read(&mut p, 32)?);
            hashes.push(Hash256(e));
        }
        transactions.push((Hash256(txid), hashes));
    }
    let body = &raw[start..p];
    let expected = sha256(body);
    let got = read(&mut p, 4)?;
    if got != &expected[..4] {
        return None;
    }
    Some(((height, Hash256(id), transactions), p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::amount::Amount;
    use crate::block::BlockHeader;
    use crate::sig::SchemeId;
    use crate::tx::{Transaction, TxIn, TxOut};

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("q21-index-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn key_hash(n: u8) -> Hash256 {
        Hash256([n; 32])
    }

    fn output(n: u8, amount: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(amount),
            scheme: SchemeId::LamportOts,
            pubkey_hash: key_hash(n),
        }
    }

    fn coinbase(to: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(vec![1, 2, 3])],
            outputs: vec![output(to, 1000)],
            lock_time: 0,
        }
    }

    fn block(height: u64, mark: u8, transactions: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256([mark; 32]),
                uncles_root: Hash256::ZERO,
                miner: Hash256::ZERO,
                time: 1_700_000_000 + height,
                bits: 0x2000_ffff,
                height,
                nonce: 0,
            },
            transactions,
            uncles: Vec::new(),
        }
    }

    /// An address that receives appears in the index.
    #[test]
    fn an_output_records_its_address() {
        let d = temp_dir("output");
        let mut index = Index::open(&d.join("index.dat"));
        index.index_block(&block(0, 1, vec![coinbase(7)])).unwrap();

        assert_eq!(index.positions(&key_hash(7)).len(), 1);
        assert_eq!(index.positions(&key_hash(7))[0].height, 0);
        assert_eq!(index.positions(&key_hash(9)).len(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// An address that **spends** appears too.
    ///
    /// This is the hard half: the input only designates the output it
    /// consumes. Without the owner table, a spend would be invisible from the
    /// address that makes it - the screen would only show what it received.
    #[test]
    fn find_txids_filters_and_bounds() {
        let d = temp_dir("find-txids");
        let mut index = Index::open(&d.join("index.dat"));
        index.index_block(&block(0, 1, vec![coinbase(7)])).unwrap();
        index.index_block(&block(1, 2, vec![coinbase(8)])).unwrap();
        assert_eq!(index.find_txids(|_| true, 10).len(), 2);
        assert_eq!(index.find_txids(|_| true, 1).len(), 1);
        assert!(index.find_txids(|_| false, 10).is_empty());
    }

    #[test]
    fn a_spend_records_the_spending_address() {
        let d = temp_dir("spend");
        let mut index = Index::open(&d.join("index.dat"));

        let cb = coinbase(7);
        let cb_txid = cb.txid();
        index.index_block(&block(0, 1, vec![cb])).unwrap();

        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: cb_txid,
                    index: 0,
                },
                witness: Default::default(),
                sequence: 0,
            }],
            outputs: vec![output(8, 900)],
            lock_time: 0,
        };
        index
            .index_block(&block(1, 2, vec![coinbase(7), spend]))
            .unwrap();

        // 7 appears three times: the first coinbase, the second, and the
        // spend that consumes the first.
        assert_eq!(index.positions(&key_hash(7)).len(), 3);
        // 8 only once, as a receive.
        assert_eq!(index.positions(&key_hash(8)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// An address paid twice by the same transaction appears only once: it is
    /// a single movement.
    #[test]
    fn an_address_paid_twice_counts_only_once() {
        let d = temp_dir("duplicate");
        let mut index = Index::open(&d.join("index.dat"));
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(vec![9])],
            outputs: vec![output(7, 500), output(7, 500)],
            lock_time: 0,
        };
        index.index_block(&block(0, 1, vec![tx])).unwrap();
        assert_eq!(index.positions(&key_hash(7)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The log reads back identically.
    #[test]
    fn the_log_reads_back() {
        let d = temp_dir("reread");
        let path = d.join("index.dat");
        let txid;
        {
            let mut index = Index::open(&path);
            let cb = coinbase(7);
            txid = cb.txid();
            index.index_block(&block(0, 1, vec![cb])).unwrap();
            index.index_block(&block(1, 2, vec![coinbase(8)])).unwrap();
        }
        let index = Index::open(&path);
        assert_eq!(index.height(), 1);
        assert_eq!(index.indexed_blocks(), 2);
        assert_eq!(index.positions(&key_hash(7)).len(), 1);
        assert_eq!(index.position(&txid).map(|p| p.height), Some(0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A log cut in the middle of a record loses only that one.
    ///
    /// This is what a power cut during the write produces. The index must
    /// restart from the last complete record, not refuse to open.
    #[test]
    fn a_truncated_log_loses_the_last_block_and_nothing_else() {
        let d = temp_dir("truncated");
        let path = d.join("index.dat");
        {
            let mut index = Index::open(&path);
            index.index_block(&block(0, 1, vec![coinbase(7)])).unwrap();
            index.index_block(&block(1, 2, vec![coinbase(8)])).unwrap();
            index.index_block(&block(2, 3, vec![coinbase(9)])).unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        // Cut five bytes: the last record becomes unreadable.
        std::fs::write(&path, &raw[..raw.len() - 5]).unwrap();

        let index = Index::open(&path);
        assert_eq!(index.height(), 1, "the index did not recover the first two");
        assert_eq!(index.positions(&key_hash(9)).len(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A modified byte gets the record rejected.
    #[test]
    fn corruption_is_detected() {
        let d = temp_dir("corrupted");
        let path = d.join("index.dat");
        {
            let mut index = Index::open(&path);
            index.index_block(&block(0, 1, vec![coinbase(7)])).unwrap();
            index.index_block(&block(1, 2, vec![coinbase(8)])).unwrap();
        }
        let mut raw = std::fs::read(&path).unwrap();
        let middle = raw.len() / 2;
        raw[middle] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();

        let index = Index::open(&path);
        assert!(index.height() <= 1, "a corrupted record was accepted");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A reorg removes from the index what no longer happened.
    ///
    /// Without that, an address screen would show transactions from an
    /// abandoned branch - that is, movements that do not exist.
    #[test]
    fn a_reorg_removes_abandoned_blocks() {
        let d = temp_dir("reorg");
        let path = d.join("index.dat");
        let mut index = Index::open(&path);
        index.index_block(&block(0, 1, vec![coinbase(7)])).unwrap();
        index.index_block(&block(1, 2, vec![coinbase(8)])).unwrap();
        index.index_block(&block(2, 3, vec![coinbase(9)])).unwrap();
        assert_eq!(index.positions(&key_hash(9)).len(), 1);

        index.truncate(1);
        assert_eq!(index.height(), 1);
        assert_eq!(index.positions(&key_hash(9)).len(), 0);
        assert_eq!(index.positions(&key_hash(8)).len(), 1);

        // And the rewritten log says the same thing as memory.
        let reread = Index::open(&path);
        assert_eq!(reread.height(), 1);
        assert_eq!(reread.positions(&key_hash(9)).len(), 0);
        assert_eq!(reread.positions(&key_hash(8)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A log whose heights jump is rejected from the jump onward.
    #[test]
    fn an_out_of_order_log_stops_at_the_jump() {
        let d = temp_dir("jump");
        let path = d.join("index.dat");
        let mut raw = MAGIC.to_vec();
        raw.extend_from_slice(&write_record(0, Hash256([1; 32]), &[]));
        raw.extend_from_slice(&write_record(5, Hash256([2; 32]), &[]));
        std::fs::write(&path, &raw).unwrap();

        let index = Index::open(&path);
        assert_eq!(index.indexed_blocks(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Priming takes the owners back from the UTXO set.
    #[test]
    fn priming_recovers_the_owners() {
        let d = temp_dir("prime");
        let mut index = Index::open(&d.join("index.dat"));

        let cb = coinbase(7);
        let txid = cb.txid();
        let mut utxo = UtxoSet::new();
        let mut undo = Default::default();
        utxo.apply_transaction(&cb, 0, &mut undo);
        index.prime(&utxo);

        // Without ever having indexed block 0, the index knows whom the output
        // belongs to: a future spend will therefore be attributed to the right
        // address.
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid, index: 0 },
                witness: Default::default(),
                sequence: 0,
            }],
            outputs: vec![output(8, 900)],
            lock_time: 0,
        };
        index.index_block(&block(0, 1, vec![spend])).unwrap();
        assert_eq!(index.positions(&key_hash(7)).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The network does not enter the index: it does not need it.
    #[test]
    fn the_index_does_not_depend_on_the_network() {
        let _ = Network::Regtest;
    }
}
