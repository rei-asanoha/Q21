//! Blocks and headers.
//!
//! Two fields set this header apart from Bitcoin's, and each answers a
//! commitment of the white paper.
//!
//! **`height` is in the header.** Bitcoin does not put it there and has to
//! infer it from the chain. Q21 needs it explicitly: the size of the proof of
//! work table grows with height, and a verifier must be able to size that
//! table before even attaching the block to a chain.
//!
//! **`uncles_root` commits to the uncles.** Uncle rewards are lever C of
//! section 5: paying for the orphaned work of a poorly connected miner rather
//! than throwing it away. Without a commitment in the header, a miner could
//! rewrite the uncle list after the fact.

use crate::hash::{tagged_hash, tags, Hash256};
use crate::merkle::merkle_root;
use crate::ser::{ReadError, Reader, Writer};
use crate::tx::{Transaction, TxError};

/// Block header: 160 bytes, fixed size (see [`BlockHeader::SIZE`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block: Hash256,
    pub merkle_root: Hash256,
    /// Merkle root of the included uncle headers.
    pub uncles_root: Hash256,
    /// Public key hash of the miner of this block.
    ///
    /// Present in the header and not only in the coinbase, because an uncle is
    /// transmitted only through its header: without this field, we would know
    /// that orphaned work deserves a reward without knowing whom to pay it to.
    /// Ethereum made the same choice, for the same reason.
    ///
    /// A consensus rule requires the first coinbase output to actually pay
    /// this hash; otherwise the field would be merely declarative, and
    /// therefore false.
    pub miner: Hash256,
    /// Unix timestamp in seconds.
    pub time: u64,
    /// Difficulty target, encoded in compact form.
    pub bits: u32,
    pub height: u64,
    pub nonce: u64,
}

impl BlockHeader {
    /// Serialized size, constant by construction.
    pub const SIZE: usize = 4 + 32 + 32 + 32 + 32 + 8 + 4 + 8 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::SIZE);
        w.u32(self.version);
        w.bytes(self.prev_block.as_bytes());
        w.bytes(self.merkle_root.as_bytes());
        w.bytes(self.uncles_root.as_bytes());
        w.bytes(self.miner.as_bytes());
        w.u64(self.time);
        w.u32(self.bits);
        w.u64(self.height);
        w.u64(self.nonce);
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<BlockHeader, ReadError> {
        let mut r = Reader::new(data);
        let h = BlockHeader {
            version: r.u32()?,
            prev_block: Hash256(r.array32()?),
            merkle_root: Hash256(r.array32()?),
            uncles_root: Hash256(r.array32()?),
            miner: Hash256(r.array32()?),
            time: r.u64()?,
            bits: r.u32()?,
            height: r.u64()?,
            nonce: r.u64()?,
        };
        r.expect_end()?;
        Ok(h)
    }

    /// Block id.
    ///
    /// Note: this is not the value compared to the difficulty target. The
    /// proof of work uses a distinct *memory-hard* function, whose
    /// implementation belongs to phase 3 of the roadmap. Confusing the two
    /// would be a design error.
    pub fn block_id(&self) -> Hash256 {
        tagged_hash(tags::BLOCK_HEADER, &self.encode())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    /// Headers of the uncles attached to this block.
    pub uncles: Vec<BlockHeader>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BlockError {
    NoTransactions,
    FirstTransactionNotCoinbase,
    MultipleCoinbase,
    BadMerkleRoot,
    BadUnclesRoot,
    Transaction(TxError),
    Read(ReadError),
}

impl From<ReadError> for BlockError {
    fn from(e: ReadError) -> Self {
        BlockError::Read(e)
    }
}

impl From<TxError> for BlockError {
    fn from(e: TxError) -> Self {
        BlockError::Transaction(e)
    }
}

impl Block {
    /// Computes the Merkle root of the transactions present.
    pub fn compute_merkle_root(&self) -> Hash256 {
        let leaves: Vec<Hash256> = self.transactions.iter().map(|t| t.merkle_leaf()).collect();
        merkle_root(&leaves)
    }

    pub fn compute_uncles_root(&self) -> Hash256 {
        let leaves: Vec<Hash256> = self
            .uncles
            .iter()
            .map(|u| crate::merkle::leaf_hash(u.block_id().as_bytes()))
            .collect();
        merkle_root(&leaves)
    }

    /// Structural checks, without access to the UTXO set or the difficulty.
    pub fn check_shape(&self) -> Result<(), BlockError> {
        if self.transactions.is_empty() {
            return Err(BlockError::NoTransactions);
        }
        if !self.transactions[0].is_coinbase() {
            return Err(BlockError::FirstTransactionNotCoinbase);
        }
        if self.transactions[1..].iter().any(|t| t.is_coinbase()) {
            return Err(BlockError::MultipleCoinbase);
        }
        for t in &self.transactions {
            t.check_shape()?;
        }
        if self.compute_merkle_root() != self.header.merkle_root {
            return Err(BlockError::BadMerkleRoot);
        }
        if self.compute_uncles_root() != self.header.uncles_root {
            return Err(BlockError::BadUnclesRoot);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.header.encode());
        w.varint(self.transactions.len() as u64);
        for t in &self.transactions {
            w.var_bytes(&t.encode());
        }
        w.varint(self.uncles.len() as u64);
        for u in &self.uncles {
            w.bytes(&u.encode());
        }
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<Block, BlockError> {
        let (block, consumed) = Self::decode_prefix(data)?;
        if consumed != data.len() {
            return Err(BlockError::Read(ReadError::TrailingBytes(
                data.len() - consumed,
            )));
        }
        Ok(block)
    }

    /// Decodes the block that starts `data`, without requiring `data` to end
    /// with it, and returns the number of bytes it occupies.
    ///
    /// # Why this variant exists
    ///
    /// The block file precedes each record with its length. When that prefix
    /// is damaged (a bit flipped on a worn-out memory card), the only way to
    /// recover the real length is to decode the block itself: its encoding is
    /// self-delimiting (every count and every sequence carries its size), so
    /// there is only one length at which decoding succeeds. That is what the
    /// block file repair uses. Consensus, for its part, goes through
    /// [`Self::decode`], which additionally requires that nothing trails
    /// behind.
    pub fn decode_prefix(data: &[u8]) -> Result<(Block, usize), BlockError> {
        if data.len() < BlockHeader::SIZE {
            return Err(BlockError::Read(ReadError::UnexpectedEnd));
        }
        let header = BlockHeader::decode(&data[..BlockHeader::SIZE])?;
        let mut r = Reader::new(&data[BlockHeader::SIZE..]);

        // Each transaction is preceded by its length and cannot occupy fewer
        // than ten bytes. We deliberately underestimate: a minimum too large
        // would refuse valid data, a minimum too small only weakens the
        // check.
        let n = r.read_count(10)?;
        let mut transactions = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            transactions.push(Transaction::decode(r.var_bytes()?)?);
        }

        let n_uncles = r.read_count(BlockHeader::SIZE)?;
        let mut uncles = Vec::with_capacity(n_uncles.min(64));
        for _ in 0..n_uncles {
            let left = r.remaining();
            if left < BlockHeader::SIZE {
                return Err(BlockError::Read(ReadError::UnexpectedEnd));
            }
            let mut buf = [0u8; BlockHeader::SIZE];
            for byte in buf.iter_mut() {
                *byte = r.u8()?;
            }
            uncles.push(BlockHeader::decode(&buf)?);
        }

        let consumed = data.len() - r.remaining();
        Ok((
            Block {
                header,
                transactions,
                uncles,
            },
            consumed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crate::sig::SchemeId;
    use crate::tx::{TxIn, TxOut};

    fn coinbase(height: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(height.to_le_bytes().to_vec())],
            outputs: vec![TxOut {
                value: crate::emission::block_subsidy(height),
                scheme: SchemeId::MlDsa65,
                pubkey_hash: Hash256([1u8; 32]),
            }],
            lock_time: 0,
        }
    }

    fn block(height: u64) -> Block {
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256([2u8; 32]),
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: Hash256([1u8; 32]),
                time: 1_755_000_000,
                bits: 0x1d00_ffff,
                height,
                nonce: 0,
            },
            transactions: vec![coinbase(height)],
            uncles: Vec::new(),
        };
        b.header.merkle_root = b.compute_merkle_root();
        b.header.uncles_root = b.compute_uncles_root();
        b
    }

    #[test]
    fn header_has_fixed_size() {
        assert_eq!(BlockHeader::SIZE, 160);
        assert_eq!(block(1).header.encode().len(), BlockHeader::SIZE);
    }

    #[test]
    fn header_round_trip() {
        let h = block(42).header;
        assert_eq!(BlockHeader::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn block_round_trip() {
        let b = block(100);
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
    }

    #[test]
    fn round_trip_with_uncles() {
        let mut b = block(100);
        b.uncles = vec![block(99).header, block(98).header];
        b.header.uncles_root = b.compute_uncles_root();
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
        assert!(b.check_shape().is_ok());
    }

    #[test]
    fn nonce_changes_id() {
        let a = block(1).header;
        let mut b = a;
        b.nonce = 1;
        assert_ne!(a.block_id(), b.block_id());
    }

    #[test]
    fn height_changes_id() {
        let a = block(1).header;
        let mut b = a;
        b.height = 2;
        assert_ne!(a.block_id(), b.block_id());
    }

    #[test]
    fn wrong_merkle_root_is_detected() {
        let mut b = block(10);
        b.header.merkle_root = Hash256([0xff; 32]);
        assert_eq!(b.check_shape(), Err(BlockError::BadMerkleRoot));
    }

    #[test]
    fn wrong_uncles_root_is_detected() {
        let mut b = block(10);
        b.uncles = vec![block(9).header];
        // uncles_root left at zero although an uncle is present.
        assert_eq!(b.check_shape(), Err(BlockError::BadUnclesRoot));
    }

    #[test]
    fn block_without_coinbase_is_refused() {
        let mut b = block(10);
        b.transactions[0].inputs[0].prev_out = crate::tx::OutPoint {
            txid: Hash256([5u8; 32]),
            index: 0,
        };
        b.header.merkle_root = b.compute_merkle_root();
        assert_eq!(
            b.check_shape(),
            Err(BlockError::FirstTransactionNotCoinbase)
        );
    }

    #[test]
    fn two_coinbases_are_refused() {
        let mut b = block(10);
        b.transactions.push(coinbase(10));
        b.header.merkle_root = b.compute_merkle_root();
        assert_eq!(b.check_shape(), Err(BlockError::MultipleCoinbase));
    }

    #[test]
    fn empty_block_is_refused() {
        let mut b = block(10);
        b.transactions.clear();
        b.header.merkle_root = b.compute_merkle_root();
        assert_eq!(b.check_shape(), Err(BlockError::NoTransactions));
    }

    #[test]
    fn genesis_coinbase_issues_nothing() {
        let b = block(0);
        assert_eq!(b.transactions[0].outputs[0].value, Amount::ZERO);
    }
}
