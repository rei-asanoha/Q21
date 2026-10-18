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
    /// Does `owners` match the last indexed block? Not after reopening a
    /// non-empty log, which does not keep it: [`Index::plan`] then rebuilds
    /// it from the chain before extending anything.
    owners_valid: bool,
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
            owners_valid: true,
        };
        if let Ok(raw) = std::fs::read(path) {
            // A log that stops short — a record cut in half by a power cut —
            // is rewritten at once, down to its last good record. Left as it
            // was, every block appended after the bad record would be lost
            // at the next start, and the index would go back to the same
            // point at every restart.
            if !index.replay(&raw) {
                let _ = index.rewrite_log();
            }
        }
        index.owners_valid = index.blocks.is_empty();
        index
    }

    /// Reads the log back. Returns `false` if it stopped before the end.
    fn replay(&mut self, raw: &[u8]) -> bool {
        if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
            return raw.is_empty();
        }
        let mut p = MAGIC.len();
        while let Some((record, next)) = read_record(raw, p) {
            let (height, id, transactions) = record;
            // A log must stay ordered: a record that goes backward betrays a
            // corruption that no checksum catches, since the checksum covers
            // each record taken separately.
            if let Some((last, _)) = self.blocks.last() {
                if height != last + 1 {
                    return false;
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
        p == raw.len()
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
        self.owners_valid = true;
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
    /// The log is rewritten in full, into a temporary file renamed over the
    /// old one: a shutdown in the middle leaves either the old log or the new
    /// one, never half of each. Up to v0.4.8 the rewrite searched the whole
    /// transaction table once **per block** and reopened the file each time:
    /// quadratic, minutes on a long chain. It is now one pass and one write.
    ///
    /// The owner table is left as it is: see [`Index::apply`], which sets it
    /// for the fork.
    pub fn truncate(&mut self, height: u64) {
        self.blocks.retain(|(h, _)| *h <= height);
        self.by_txid.retain(|_, p| p.height <= height);
        for positions in self.by_address.values_mut() {
            positions.retain(|p| p.height <= height);
        }
        self.by_address.retain(|_, v| !v.is_empty());
        let _ = self.rewrite_log();
    }

    /// Writes the whole log again from memory. The key hashes are rebuilt
    /// from `by_address`, the only table that still holds them.
    fn rewrite_log(&self) -> std::io::Result<()> {
        use std::io::Write;
        let mut hashes_by_position: HashMap<(u64, u32), Vec<Hash256>> = HashMap::new();
        for (key_hash, positions) in &self.by_address {
            for p in positions {
                hashes_by_position
                    .entry((p.height, p.rank))
                    .or_default()
                    .push(*key_hash);
            }
        }
        // The order of the hashes inside a transaction is not kept by
        // `by_address`; sorting makes the rewrite deterministic.
        for v in hashes_by_position.values_mut() {
            v.sort_by_key(|h| h.0);
        }
        let mut by_height: HashMap<u64, Vec<(u32, Hash256)>> = HashMap::new();
        for (txid, p) in &self.by_txid {
            by_height.entry(p.height).or_default().push((p.rank, *txid));
        }
        let mut out = Vec::with_capacity(MAGIC.len() + self.blocks.len() * 128);
        out.extend_from_slice(MAGIC);
        for (h, id) in &self.blocks {
            let mut ranks = by_height.remove(h).unwrap_or_default();
            ranks.sort_by_key(|(r, _)| *r);
            let transactions: Vec<(Hash256, Vec<Hash256>)> = ranks
                .into_iter()
                .map(|(rank, txid)| {
                    let hashes = hashes_by_position
                        .get(&(*h, rank))
                        .cloned()
                        .unwrap_or_default();
                    (txid, hashes)
                })
                .collect();
            out.extend_from_slice(&write_record(*h, *id, &transactions));
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }

    /// Erases everything, log included. Used when the index has diverged.
    pub fn clear(&mut self) {
        self.by_address.clear();
        self.by_txid.clear();
        self.owners.clear();
        self.blocks.clear();
        self.owners_valid = true;
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Following the chain
// ---------------------------------------------------------------------------

/// What the index needs to read from the chain. Implemented by
/// [`crate::chain::Chain`]; the tests implement it on a simulated chain.
pub trait ChainView {
    /// Height of the active tip.
    fn tip_height(&self) -> u64;
    /// Id of the active block at this height.
    fn active_id(&self, height: u64) -> Option<Hash256>;
    /// The active block at this height, if its body is available.
    fn active_block(&self, height: u64) -> Option<Block>;
    /// Every unspent output of the active tip, with the key hash it pays.
    fn unspent_owners(&self) -> Vec<(OutPoint, Hash256)>;
    /// The outputs consumed by the active blocks above `height`, with the key
    /// hash each paid. `None` beyond the undo window.
    fn spent_above(&self, height: u64) -> Option<Vec<(OutPoint, Hash256)>>;
}

impl ChainView for crate::chain::Chain {
    fn tip_height(&self) -> u64 {
        self.height()
    }
    fn active_id(&self, height: u64) -> Option<Hash256> {
        self.active_at(height)
    }
    fn active_block(&self, height: u64) -> Option<Block> {
        self.block_at(height)
    }
    fn unspent_owners(&self) -> Vec<(OutPoint, Hash256)> {
        self.utxo
            .iter()
            .map(|(o, e)| (*o, e.output.pubkey_hash))
            .collect()
    }
    fn spent_above(&self, height: u64) -> Option<Vec<(OutPoint, Hash256)>> {
        crate::chain::Chain::spent_above(self, height)
    }
}

/// Transactions copied under the chain's lock in one step at most — beyond
/// the first block, which is always taken. About seven mebibytes of ML-DSA-87
/// payments.
pub const STEP_MAX_TRANSACTIONS: usize = 1000;

/// One step of following the chain, decided under the chain's lock by
/// [`Index::plan`] and carried out after it is released by [`Index::apply`].
///
/// # The defect this closes
///
/// Up to v0.4.8, the index followed the chain **inside** the chain's lock —
/// which is the node's lock — and answered any reorg by erasing itself and
/// reindexing every block from genesis, still inside the lock. During the
/// endurance test, a one-block reorg on a two-thousand-five-hundred-block
/// chain froze the France and Singapore nodes for more than ten minutes: no
/// peer served, no block relayed, no wallet answered.
///
/// Now:
///
/// - a reorg rewinds the index to the **fork** only, and the owners of the
///   outputs that the new branch consumes come from the chain's undo records;
///   erasing everything is the last resort, when the undo window does not
///   reach the fork;
/// - the work is cut into steps of a few blocks: the chain's lock is held only
///   to copy those blocks, and the indexing itself happens outside it.
#[derive(Debug)]
pub enum Step {
    /// The index is on the active tip.
    UpToDate,
    /// Index these blocks, which follow the last indexed one.
    Extend(Vec<Block>),
    /// A reorg: go back to `fork`, take `owners` as the owner table — the
    /// unspent outputs of the tip plus those the new branch consumes — then
    /// index `blocks`, the first ones of the new branch.
    Rewind {
        fork: u64,
        owners: Vec<(OutPoint, Hash256)>,
        blocks: Vec<Block>,
    },
    /// No common point within reach: start again from genesis, in steps.
    Clear,
    /// The body at this height is not available: nothing is indexed, rather
    /// than an index with a hole. Retried at the next step.
    Missing(u64),
}

impl Index {
    /// Decides the next step. Reads only; meant to be called under the
    /// chain's lock, and to be quick: at most `max_blocks` bodies are copied.
    pub fn plan(&self, chain: &impl ChainView, max_blocks: usize) -> Step {
        let tip = chain.tip_height();
        let max_blocks = max_blocks.max(1) as u64;
        // Bounded in blocks and in transactions: sixteen full blocks are tens
        // of mebibytes to copy under the chain's lock.
        let fetch = |from: u64| -> Result<Vec<Block>, u64> {
            let to = tip.min(from.saturating_add(max_blocks - 1));
            let mut blocks = Vec::new();
            if from > tip {
                return Ok(blocks);
            }
            let mut transactions = 0usize;
            for h in from..=to {
                if transactions >= STEP_MAX_TRANSACTIONS {
                    break;
                }
                match chain.active_block(h) {
                    Some(b) => {
                        transactions += b.transactions.len();
                        blocks.push(b);
                    }
                    None => return Err(h),
                }
            }
            Ok(blocks)
        };
        if self.is_empty() {
            return match fetch(0) {
                Ok(b) => Step::Extend(b),
                Err(h) => Step::Missing(h),
            };
        }
        let top = self.height();
        if self.owners_valid && top <= tip && chain.active_id(top) == self.block_id(top) {
            if top == tip {
                return Step::UpToDate;
            }
            return match fetch(top + 1) {
                Ok(b) => Step::Extend(b),
                Err(h) => Step::Missing(h),
            };
        }
        // Divergence, an index ahead of the chain, or an owner table to
        // rebuild after reopening: look for the fork — the last indexed block
        // itself, in the last case — and rebuild the table there.
        let first = self.blocks.first().map(|(h, _)| *h).unwrap_or(0);
        let mut h = top.min(tip);
        let fork = loop {
            if chain.active_id(h).is_some() && chain.active_id(h) == self.block_id(h) {
                break Some(h);
            }
            if h == first {
                break None;
            }
            h -= 1;
        };
        let Some(fork) = fork else {
            return Step::Clear;
        };
        let Some(spent) = chain.spent_above(fork) else {
            return Step::Clear;
        };
        let blocks = match fetch(fork + 1) {
            Ok(b) => b,
            Err(h) => return Step::Missing(h),
        };
        let mut owners = chain.unspent_owners();
        owners.extend(spent);
        Step::Rewind {
            fork,
            owners,
            blocks,
        }
    }

    /// Carries out a step decided by [`Index::plan`]. Needs no lock on the
    /// chain. Returns the number of blocks indexed.
    pub fn apply(&mut self, step: Step) -> Result<usize, IndexError> {
        let blocks = match step {
            Step::UpToDate | Step::Missing(_) => return Ok(0),
            Step::Clear => {
                self.clear();
                return Ok(0);
            }
            Step::Extend(blocks) => blocks,
            Step::Rewind {
                fork,
                owners,
                blocks,
            } => {
                if fork < self.height() {
                    self.truncate(fork);
                }
                self.owners = owners.into_iter().collect();
                self.owners_valid = true;
                blocks
            }
        };
        let mut n = 0;
        for b in &blocks {
            // A step planned before another one was applied no longer
            // follows: dropped, the next plan starts from the right place.
            let expected = if self.is_empty() {
                0
            } else {
                self.height() + 1
            };
            if b.header.height != expected {
                break;
            }
            self.index_block(b)?;
            n += 1;
        }
        Ok(n)
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

        let mut index = Index::open(&path);
        assert_eq!(index.height(), 1, "the index did not recover the first two");
        assert_eq!(index.positions(&key_hash(9)).len(), 0);

        // The torn record is gone from the file too: what is appended now
        // reads back at the next start, instead of sitting behind garbage.
        index.index_block(&block(2, 4, vec![coinbase(10)])).unwrap();
        drop(index);
        let index = Index::open(&path);
        assert_eq!(
            index.height(),
            2,
            "the block appended after the cut was lost"
        );
        assert_eq!(index.positions(&key_hash(10)).len(), 1);
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

/// The follower against a simulated chain: hundreds of random extensions and
/// reorgs, with intra-block spends and transactions mined again on the new
/// branch. After each one, the index followed step by step must be **exactly**
/// the index rebuilt from genesis — memory, owners and log.
#[cfg(test)]
mod follow_tests {
    use super::*;
    use crate::amount::Amount;
    use crate::block::BlockHeader;
    use crate::sig::SchemeId;
    use crate::tx::{Transaction, TxIn, TxOut, Witness};
    use crate::utxo::{UndoRecord, UtxoSet};

    struct Fake {
        blocks: Vec<Block>,
        utxo: UtxoSet,
        undos: Vec<UndoRecord>,
        /// Undo records the chain still keeps.
        window: usize,
        /// A height whose body is unavailable.
        missing: Option<u64>,
    }

    impl ChainView for Fake {
        fn tip_height(&self) -> u64 {
            self.blocks.len() as u64 - 1
        }
        fn active_id(&self, h: u64) -> Option<Hash256> {
            self.blocks.get(h as usize).map(|b| b.header.block_id())
        }
        fn active_block(&self, h: u64) -> Option<Block> {
            if self.missing == Some(h) {
                return None;
            }
            self.blocks.get(h as usize).cloned()
        }
        fn unspent_owners(&self) -> Vec<(OutPoint, Hash256)> {
            self.utxo
                .iter()
                .map(|(o, e)| (*o, e.output.pubkey_hash))
                .collect()
        }
        fn spent_above(&self, h: u64) -> Option<Vec<(OutPoint, Hash256)>> {
            let depth = (self.tip_height().checked_sub(h)?) as usize;
            if depth > self.window.min(self.undos.len()) {
                return None;
            }
            Some(
                self.undos
                    .iter()
                    .rev()
                    .take(depth)
                    .flat_map(|u| u.spent().iter().map(|(o, e)| (*o, e.output.pubkey_hash)))
                    .collect(),
            )
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn out(key: u64, value: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(value),
            scheme: SchemeId::LamportOts,
            pubkey_hash: Hash256([(key % 7) as u8 + 1; 32]),
        }
    }

    fn input(o: OutPoint) -> TxIn {
        TxIn {
            prev_out: o,
            witness: Witness {
                pubkey: Vec::new(),
                signature: Vec::new(),
            },
            sequence: 0,
        }
    }

    impl Fake {
        fn new() -> Fake {
            let mut f = Fake {
                blocks: Vec::new(),
                utxo: UtxoSet::new(),
                undos: Vec::new(),
                window: usize::MAX,
                missing: None,
            };
            let mut rng = Rng(1);
            let mut counter = 0;
            let g = f.make(&mut rng, &mut counter, &[]);
            f.push(g);
            f
        }

        fn push(&mut self, b: Block) {
            let mut u = UndoRecord::default();
            for tx in &b.transactions {
                self.utxo.apply_transaction(tx, b.header.height, &mut u);
            }
            self.undos.push(u);
            self.blocks.push(b);
        }

        /// Takes the tip off, and returns its spending transactions so that
        /// the new branch can mine some of them again, as a real reorg does.
        fn pop(&mut self) -> Vec<Transaction> {
            let u = self.undos.pop().unwrap();
            self.utxo.undo(&u);
            let b = self.blocks.pop().unwrap();
            b.transactions.into_iter().skip(1).collect()
        }

        /// A random block on the tip: a coinbase, then spends of live outputs —
        /// including outputs created earlier in the same block — and some of
        /// the `again` transactions when they still apply.
        fn make(&self, rng: &mut Rng, counter: &mut u64, again: &[Transaction]) -> Block {
            *counter += 1;
            let height = self.blocks.len() as u64;
            let mut live: Vec<OutPoint> = self.utxo.iter().map(|(o, _)| *o).collect();
            live.sort_by_key(|o| (o.txid.0, o.index));
            let mut used: std::collections::HashSet<OutPoint> = Default::default();
            let mut txs = vec![Transaction {
                version: 1,
                inputs: vec![TxIn::coinbase(counter.to_le_bytes().to_vec())],
                outputs: vec![out(rng.next(), 1_000_000 + *counter)],
                lock_time: 0,
            }];
            for tx in again {
                if rng.below(2) == 0
                    && tx
                        .inputs
                        .iter()
                        .all(|i| live.contains(&i.prev_out) && !used.contains(&i.prev_out))
                {
                    for i in &tx.inputs {
                        used.insert(i.prev_out);
                    }
                    txs.push(tx.clone());
                }
            }
            for _ in 0..rng.below(5) {
                let mut inputs = Vec::new();
                for _ in 0..1 + rng.below(2) {
                    if live.is_empty() {
                        break;
                    }
                    let o = live[rng.below(live.len() as u64) as usize];
                    if used.insert(o) {
                        inputs.push(input(o));
                    }
                }
                if inputs.is_empty() {
                    continue;
                }
                let n = 1 + rng.below(3);
                let tx = Transaction {
                    version: 1,
                    inputs,
                    outputs: (0..n).map(|i| out(rng.next(), 10 + i)).collect(),
                    lock_time: 0,
                };
                let txid = tx.txid();
                // Its outputs can be spent by the next transactions of the
                // same block.
                for i in 0..n as u32 {
                    live.push(OutPoint { txid, index: i });
                }
                txs.push(tx);
            }
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_block: self
                        .blocks
                        .last()
                        .map(|b| b.header.block_id())
                        .unwrap_or(Hash256::ZERO),
                    merkle_root: Hash256::ZERO,
                    uncles_root: Hash256::ZERO,
                    miner: Hash256::ZERO,
                    time: 1_700_000_000 + height,
                    bits: 0x2000_ffff,
                    height,
                    nonce: *counter,
                },
                transactions: txs,
                uncles: Vec::new(),
            }
        }
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("q21-follow-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Follows to the tip, in steps of `max` blocks. Returns the steps taken.
    fn follow(index: &mut Index, chain: &Fake, max: usize) -> usize {
        for n in 0..10_000 {
            match index.plan(chain, max) {
                Step::UpToDate => return n,
                Step::Missing(h) => panic!("missing {h}"),
                step => {
                    index.apply(step).unwrap();
                }
            }
        }
        panic!("the follower does not converge");
    }

    /// The reference: everything indexed again from genesis.
    fn rebuilt(chain: &Fake, path: &Path) -> Index {
        let _ = std::fs::remove_file(path);
        let mut i = Index::open(path);
        for b in &chain.blocks {
            i.index_block(b).unwrap();
        }
        i
    }

    fn assert_same(a: &Index, b: &Index, chain: &Fake, context: &str) {
        assert_eq!(a.blocks, b.blocks, "{context}: blocks");
        assert_eq!(a.by_txid, b.by_txid, "{context}: transactions");
        assert_eq!(a.by_address, b.by_address, "{context}: addresses");
        // Every live output's owner is known, and right: the next block
        // spending it will be attributed correctly.
        for (o, e) in chain.utxo.iter() {
            assert_eq!(
                a.owners.get(o),
                Some(&e.output.pubkey_hash),
                "{context}: owner of a live output"
            );
        }
        // The log says the same as the memory.
        let reread = Index::open(&a.path);
        assert_eq!(reread.blocks, a.blocks, "{context}: log blocks");
        assert_eq!(reread.by_txid, a.by_txid, "{context}: log transactions");
        assert_eq!(reread.by_address, a.by_address, "{context}: log addresses");
    }

    fn scenario(seed: u64, window: usize, max: usize, rounds: usize) {
        let d = dir(&format!("s{seed}-{window}-{max}"));
        let mut chain = Fake::new();
        chain.window = window;
        let mut rng = Rng(seed);
        let mut counter = 1000 * seed;
        let mut index = Index::open(&d.join("index.dat"));
        let mut reorgs = 0;
        for round in 0..rounds {
            match rng.below(10) {
                0..=5 => {
                    for _ in 0..1 + rng.below(3) {
                        let b = chain.make(&mut rng, &mut counter, &[]);
                        chain.push(b);
                    }
                }
                6..=8 if chain.blocks.len() > 2 => {
                    let depth = 1 + rng.below(5.min(chain.blocks.len() as u64 - 1));
                    let mut again = Vec::new();
                    for _ in 0..depth {
                        again.extend(chain.pop());
                    }
                    for _ in 0..depth + rng.below(3) {
                        let b = chain.make(&mut rng, &mut counter, &again);
                        chain.push(b);
                    }
                    reorgs += 1;
                }
                _ => {
                    // A single step, then the chain moves again before the
                    // follower has finished: the step in flight is stale.
                    let step = index.plan(&chain, max);
                    if rng.below(2) == 0 && chain.blocks.len() > 2 {
                        chain.pop();
                    }
                    let b = chain.make(&mut rng, &mut counter, &[]);
                    chain.push(b);
                    index.apply(step).unwrap();
                }
            }
            if rng.below(3) == 0 {
                follow(&mut index, &chain, max);
                let reference = rebuilt(&chain, &d.join("reference.dat"));
                assert_same(
                    &index,
                    &reference,
                    &chain,
                    &format!("seed {seed} round {round}"),
                );
            }
            if rng.below(25) == 0 {
                // Restart: the log is reread, the owner table is not kept.
                drop(index);
                index = Index::open(&d.join("index.dat"));
            }
        }
        follow(&mut index, &chain, max);
        let reference = rebuilt(&chain, &d.join("reference.dat"));
        assert_same(&index, &reference, &chain, &format!("seed {seed} end"));
        assert!(reorgs > 10, "the scenario must contain reorgs");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn following_equals_rebuilding_through_random_reorgs() {
        for seed in 1..=8 {
            scenario(seed * 7919, usize::MAX, 3, 250);
        }
    }

    /// A short undo window: deep reorgs fall back to a rebuild — in steps —
    /// and the result is the same.
    #[test]
    fn following_equals_rebuilding_with_a_short_undo_window() {
        for seed in 1..=4 {
            scenario(seed * 104_729, 2, 2, 200);
        }
    }

    /// A one-block reorg on a long chain costs a handful of blocks, not the
    /// whole chain — the freeze of the endurance test.
    #[test]
    fn a_shallow_reorg_reindexes_only_the_new_branch() {
        let d = dir("shallow");
        let mut chain = Fake::new();
        let mut rng = Rng(42);
        let mut counter = 0;
        for _ in 0..300 {
            let b = chain.make(&mut rng, &mut counter, &[]);
            chain.push(b);
        }
        let mut index = Index::open(&d.join("index.dat"));
        follow(&mut index, &chain, 16);
        let again = chain.pop();
        let b = chain.make(&mut rng, &mut counter, &again);
        chain.push(b);
        match index.plan(&chain, 16) {
            Step::Rewind { fork, blocks, .. } => {
                assert_eq!(fork, 299);
                assert_eq!(blocks.len(), 1, "only the new block is copied");
                index
                    .apply(Step::Rewind {
                        fork,
                        owners: chain
                            .unspent_owners()
                            .into_iter()
                            .chain(chain.spent_above(fork).unwrap())
                            .collect(),
                        blocks,
                    })
                    .unwrap();
            }
            other => panic!("expected a rewind, got {other:?}"),
        }
        assert!(matches!(index.plan(&chain, 16), Step::UpToDate));
        let reference = rebuilt(&chain, &d.join("reference.dat"));
        assert_same(&index, &reference, &chain, "shallow");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// End to end on a real chain: signed spends, a reorg through
    /// `Chain::submit`, and the owners of the new branch's inputs taken from
    /// the chain's own undo records.
    #[test]
    fn a_real_reorg_is_followed_from_the_fork() {
        use crate::address::Network;
        use crate::chain::{genesis_block, Accept, Chain, GENESIS_TIME};
        use crate::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
        use crate::wallet::Wallet;
        const NET: Network = Network::Regtest;

        fn funded(w: &mut Wallet) -> Chain {
            let _ = w.new_address();
            let mut c = Chain::new(NET, genesis_block(NET));
            for i in 1..=COINBASE_MATURITY + 6 {
                let a = w.new_address();
                let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
                let b = c
                    .mine_block(a.hash, SchemeId::LamportOts, &[], t, 5_000_000)
                    .unwrap();
                c.connect(&b, t + 1).unwrap();
            }
            c
        }
        fn pay(w: &mut Wallet, c: &Chain, seed: u8) -> Transaction {
            let mut dest = Wallet::from_seed([seed; 32], NET);
            let a = dest.new_address();
            w.create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(10_000),
                Amount::from_units(5_000),
            )
            .unwrap()
        }
        fn mine_on(c: &mut Chain, txs: &[Transaction]) -> Block {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(Hash256([3u8; 32]), SchemeId::LamportOts, txs, t, 5_000_000)
                .unwrap();
            c.connect(&b, t + 1).unwrap();
            b
        }

        let d = dir("real");
        let mut w1 = Wallet::from_seed([0x31; 32], NET);
        let mut w2 = Wallet::from_seed([0x31; 32], NET);
        let mut a = funded(&mut w1);
        let mut b = funded(&mut w2);
        assert_eq!(a.tip_id(), b.tip_id(), "same history up to the fork");
        let base = a.height();

        // Branch A: one payment. Branch B: two payments, two blocks.
        let tx_a = pay(&mut w1, &a, 0xa1);
        mine_on(&mut a, &[tx_a]);
        let tx_b1 = pay(&mut w2, &b, 0xb1);
        let b1 = mine_on(&mut b, &[tx_b1]);
        let tx_b2 = pay(&mut w2, &b, 0xb2);
        let b2 = mine_on(&mut b, &[tx_b2]);

        let mut index = Index::open(&d.join("index.dat"));
        for _ in 0..100 {
            let step = index.plan(&a, 16);
            if matches!(step, Step::UpToDate) {
                break;
            }
            index.apply(step).unwrap();
        }
        assert_eq!(index.height(), base + 1);

        let now = b2.header.time + 10;
        a.submit(&b1, now).unwrap();
        assert!(matches!(
            a.submit(&b2, now).unwrap(),
            Accept::Reorganized { depth: 1 }
        ));
        match index.plan(&a, 16) {
            Step::Rewind {
                fork, ref blocks, ..
            } => {
                assert_eq!(fork, base);
                assert_eq!(blocks.len(), 2);
            }
            ref other => panic!("expected a rewind, got {other:?}"),
        }
        for _ in 0..100 {
            let step = index.plan(&a, 16);
            if matches!(step, Step::UpToDate) {
                break;
            }
            index.apply(step).unwrap();
        }
        let _ = std::fs::remove_file(d.join("reference.dat"));
        let mut reference = Index::open(&d.join("reference.dat"));
        for h in 0..=a.height() {
            reference.index_block(&a.block_at(h).unwrap()).unwrap();
        }
        assert_eq!(index.blocks, reference.blocks);
        assert_eq!(index.by_txid, reference.by_txid);
        assert_eq!(index.by_address, reference.by_address);
        // The spender of the new branch is attributed: its input's owner came
        // from the undo records, not from the UTXO set of the tip.
        let spender = a.block_at(base + 1).unwrap().transactions[1].clone();
        let position = index.position(&spender.txid()).unwrap();
        let attributed = index
            .by_address
            .values()
            .filter(|v| v.contains(&position))
            .count();
        assert!(attributed >= 3, "payee, change and spender: {attributed}");
        for (o, e) in a.utxo.iter() {
            assert_eq!(index.owners.get(o), Some(&e.output.pubkey_hash));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A missing body pauses the index instead of leaving a hole in it.
    #[test]
    fn a_missing_body_never_leaves_a_hole() {
        let d = dir("missing");
        let mut chain = Fake::new();
        let mut rng = Rng(5);
        let mut counter = 0;
        for _ in 0..10 {
            let b = chain.make(&mut rng, &mut counter, &[]);
            chain.push(b);
        }
        chain.missing = Some(6);
        let mut index = Index::open(&d.join("index.dat"));
        for _ in 0..10 {
            let step = index.plan(&chain, 4);
            index.apply(step).unwrap();
        }
        assert_eq!(index.height(), 3, "stops before the missing block's batch");
        assert!(matches!(index.plan(&chain, 4), Step::Missing(6)));
        chain.missing = None;
        follow(&mut index, &chain, 4);
        let reference = rebuilt(&chain, &d.join("reference.dat"));
        assert_same(&index, &reference, &chain, "missing");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Reopened behind the chain, the index catches up from where it was —
    /// with the owner table rebuilt first — and not from genesis.
    #[test]
    fn a_reopened_index_resumes_from_its_last_block() {
        let d = dir("resume");
        let mut chain = Fake::new();
        let mut rng = Rng(9);
        let mut counter = 0;
        for _ in 0..50 {
            let b = chain.make(&mut rng, &mut counter, &[]);
            chain.push(b);
        }
        let mut index = Index::open(&d.join("index.dat"));
        follow(&mut index, &chain, 8);
        drop(index);
        for _ in 0..5 {
            let b = chain.make(&mut rng, &mut counter, &[]);
            chain.push(b);
        }
        let mut index = Index::open(&d.join("index.dat"));
        match index.plan(&chain, 8) {
            Step::Rewind { fork, blocks, .. } => {
                assert_eq!(fork, 50);
                assert_eq!(blocks.len(), 5);
            }
            other => panic!("expected a resume, got {other:?}"),
        }
        follow(&mut index, &chain, 8);
        let reference = rebuilt(&chain, &d.join("reference.dat"));
        assert_same(&index, &reference, &chain, "resume");
        let _ = std::fs::remove_dir_all(&d);
    }
}
