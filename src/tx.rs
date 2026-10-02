//! Transactions.
//!
//! UTXO model, taken from Bitcoin without conceptual change: a transaction
//! consumes existing outputs and creates new ones.
//!
//! One structural difference matters, and it is inherited from the SegWit
//! lesson: **the witness does not take part in the transaction id.** The
//! `txid` is computed over the transaction stripped of its signatures. Without
//! that separation, a signature re-encoded differently would change the id of
//! an already broadcast transaction, and break any chain of unconfirmed
//! transactions that builds on it. Bitcoin took six years to fix that defect;
//! we start with the fix.
//!
//! With 3,309-byte ML-DSA signatures, that separation also becomes a sizing
//! necessity: the witness accounts for most of a transaction's weight, and
//! must be weighted separately.

use crate::address::Network;
use crate::amount::Amount;
use crate::hash::{tagged_hash, tags, Hash256};
use crate::merkle::leaf_hash;
use crate::ser::{ReadError, Reader, Writer};
use crate::sig::SchemeId;

/// Reference to an earlier transaction output.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash256,
    pub index: u32,
}

impl OutPoint {
    /// Coinbase outpoint: references no real output.
    pub const COINBASE: OutPoint = OutPoint {
        txid: Hash256::ZERO,
        index: u32::MAX,
    };

    pub fn is_coinbase(&self) -> bool {
        *self == OutPoint::COINBASE
    }
}

/// Witness: what proves the right to spend.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Witness {
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Transaction input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxIn {
    pub prev_out: OutPoint,
    pub witness: Witness,
    /// Sequence, reserved for relative time locks.
    pub sequence: u32,
}

impl TxIn {
    pub fn coinbase(data: Vec<u8>) -> TxIn {
        TxIn {
            prev_out: OutPoint::COINBASE,
            witness: Witness {
                pubkey: Vec::new(),
                signature: data,
            },
            sequence: u32::MAX,
        }
    }
}

/// Transaction output: an amount and the lock that protects it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxOut {
    pub value: Amount,
    pub scheme: SchemeId,
    /// Hash of the public key allowed to spend.
    pub pubkey_hash: Hash256,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TxError {
    NoInputs,
    NoOutputs,
    AmountAboveCap,
    OutputSumOverflow,
    UnknownScheme(u8),
    Read(ReadError),
}

impl From<ReadError> for TxError {
    fn from(e: ReadError) -> Self {
        TxError::Read(e)
    }
}

impl Transaction {
    /// Serialization without the witnesses, as it travels on the network.
    pub fn encode_without_witness(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.outputs.len() * 40);
        w.u32(self.version);
        w.varint(self.inputs.len() as u64);
        for i in &self.inputs {
            w.bytes(i.prev_out.txid.as_bytes());
            w.u32(i.prev_out.index);
            w.u32(i.sequence);
        }
        w.varint(self.outputs.len() as u64);
        for o in &self.outputs {
            w.u64(o.value.units());
            w.u8(o.scheme.as_u8());
            w.bytes(o.pubkey_hash.as_bytes());
        }
        w.u64(self.lock_time);
        w.finish()
    }

    /// Full serialization, witnesses included. Defines the `wtxid`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.encode_without_witness());
        for i in &self.inputs {
            w.var_bytes(&i.witness.pubkey);
            w.var_bytes(&i.witness.signature);
        }
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<Transaction, TxError> {
        let mut r = Reader::new(data);
        let version = r.u32()?;

        // An input occupies at least forty bytes before its witness:
        // thirty-two for the id, four for the index, four for the sequence.
        // Announcing more inputs than the rest can carry is refused before
        // any reservation.
        let n_in = r.read_count(40)?;
        let mut prev: Vec<(OutPoint, u32)> = Vec::with_capacity(n_in.min(1024));
        for _ in 0..n_in {
            let txid = Hash256(r.array32()?);
            let index = r.u32()?;
            let sequence = r.u32()?;
            prev.push((OutPoint { txid, index }, sequence));
        }

        // An output occupies exactly forty-one bytes: eight for the amount,
        // one for the scheme, thirty-two for the hash.
        let n_out = r.read_count(41)?;
        let mut outputs = Vec::with_capacity(n_out.min(1024));
        for _ in 0..n_out {
            let value = Amount::from_units(r.u64()?);
            let raw = r.u8()?;
            let scheme = SchemeId::from_u8(raw).ok_or(TxError::UnknownScheme(raw))?;
            outputs.push(TxOut {
                value,
                scheme,
                pubkey_hash: Hash256(r.array32()?),
            });
        }

        let lock_time = r.u64()?;

        let mut inputs = Vec::with_capacity(prev.len());
        for (prev_out, sequence) in prev {
            let pubkey = r.var_bytes()?.to_vec();
            let signature = r.var_bytes()?.to_vec();
            inputs.push(TxIn {
                prev_out,
                witness: Witness { pubkey, signature },
                sequence,
            });
        }

        r.expect_end()?;
        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    /// Transaction id, insensitive to witnesses.
    /// Transaction id.
    ///
    /// # The coinbase exception, and why it is necessary
    ///
    /// A coinbase has no signature: its "witness" carries only free-form
    /// data, including the block height. Excluding it from the `txid` left
    /// coinbases **without any element of uniqueness**: two blocks by the same
    /// miner paying the same amount produced the same `txid`, the second
    /// output overwrote the first in the UTXO set, and undoing the second
    /// destroyed the output of the first. Two honest nodes then ended up with
    /// the same tip and different balances: a silent split.
    ///
    /// That is the flaw Bitcoin had (BIP 30) and closed with BIP 34. This
    /// field is therefore committed in the `txid` **for the coinbase only**,
    /// where it is malleable by nobody but the miner itself.
    ///
    /// Ordinary transactions keep a `txid` insensitive to their witness: that
    /// is the property that makes chaining safe, since a third party cannot
    /// alter a signature to change the id.
    ///
    /// The wire encoding has not changed: only the preimage of the hash
    /// differs.
    pub fn txid(&self) -> Hash256 {
        let base = self.encode_without_witness();
        if self.is_coinbase() {
            let mut w = Writer::with_capacity(base.len() + 32);
            w.bytes(&base);
            w.var_bytes(&self.inputs[0].witness.signature);
            return tagged_hash(tags::TX, &w.finish());
        }
        tagged_hash(tags::TX, &base)
    }

    /// Full id, witnesses included.
    pub fn wtxid(&self) -> Hash256 {
        tagged_hash(tags::TX, &self.encode())
    }

    /// Hash signed by the spender.
    ///
    /// Covers the stripped transaction and the index of the signed input (so
    /// that a signature cannot be replayed on another input) and two more
    /// things, learned from BIP-143:
    ///
    /// - **the network**, through its address prefix: a transaction signed on
    ///   testnet is valid only there, and vice versa. Without it, the same
    ///   keys used on two networks (or on the two branches of a split) made
    ///   every signature replayable on the other;
    /// - **the spent output** (value, scheme, lock): a signer that does not
    ///   see the chain (hardware, offline) thus knows exactly what it is
    ///   spending, hence what fee it pays, and its signature is valid only
    ///   for that particular output.
    pub fn sighash(&self, input_index: u32, network: Network, spent: &TxOut) -> Hash256 {
        let mut w = Writer::new();
        w.var_bytes(network.hrp().as_bytes());
        w.bytes(&self.encode_without_witness());
        w.u32(input_index);
        w.u64(spent.value.units());
        w.u8(spent.scheme.as_u8());
        w.bytes(spent.pubkey_hash.as_bytes());
        tagged_hash(tags::SIGHASH, w.as_slice())
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_out.is_coinbase()
    }

    /// Sum of the outputs, reporting any overflow.
    pub fn total_output(&self) -> Result<Amount, TxError> {
        Amount::checked_sum(self.outputs.iter().map(|o| o.value)).ok_or(TxError::OutputSumOverflow)
    }

    /// Shape checks, independent of the chain state.
    ///
    /// Does not check the signatures or the existence of the consumed
    /// outputs: that is the role of the validator, which needs the UTXO set.
    pub fn check_shape(&self) -> Result<(), TxError> {
        if self.inputs.is_empty() {
            return Err(TxError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TxError::NoOutputs);
        }
        for o in &self.outputs {
            if !o.value.is_within_supply() {
                return Err(TxError::AmountAboveCap);
            }
        }
        let total = self.total_output()?;
        if !total.is_within_supply() {
            return Err(TxError::AmountAboveCap);
        }
        Ok(())
    }

    /// Leaf hash, for the Merkle tree of a block.
    /// Merkle leaf: commits to the id **and** the witness.
    ///
    /// The `txid` ignores the witness, and that is intended: a third party
    /// must not be able to change the id of a transaction by touching up its
    /// signature. But if the Merkle root committed only to the `txid`, that
    /// same third party could replace a signature with another valid one in a
    /// block in transit, without the header noticing. So the leaf commits to
    /// both, like SegWit's witness commitment.
    pub fn merkle_leaf(&self) -> Hash256 {
        let mut w = Writer::with_capacity(64);
        w.bytes(self.txid().as_bytes());
        w.bytes(self.wtxid().as_bytes());
        leaf_hash(w.as_slice())
    }

    /// Weight of the transaction, witness weighted separately.
    ///
    /// This implements the *witness discount* of section 7 of the white paper:
    /// without it, a 3,309-byte ML-DSA signature would make the rest of the
    /// transaction pay the price of the cryptography it carries.
    ///
    /// Each output created adds [`crate::consensus::WEIGHT_PER_OUTPUT`]: an
    /// output occupies the UTXO set of every node for as long as it lives,
    /// whereas a witness byte is forgotten as soon as the block is buried.
    /// The weight therefore prices the scarce resource, not only the bytes on
    /// the wire.
    pub fn weight(&self, witness_discount: u64) -> u64 {
        let base = self.encode_without_witness().len() as u64;
        let witness: u64 = self
            .inputs
            .iter()
            .map(|i| (i.witness.pubkey.len() + i.witness.signature.len()) as u64)
            .sum();
        let outputs_weight = self.outputs.len() as u64 * crate::consensus::WEIGHT_PER_OUTPUT;
        base * witness_discount + witness + outputs_weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(v: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(v),
            scheme: SchemeId::MlDsa65,
            pubkey_hash: Hash256([7u8; 32]),
        }
    }

    fn simple_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([1u8; 32]),
                    index: 0,
                },
                witness: Witness {
                    pubkey: vec![2u8; 1952],
                    signature: vec![3u8; 3309],
                },
                sequence: 0xffff_ffff,
            }],
            outputs: vec![output(50_000), output(25_000)],
            lock_time: 0,
        }
    }

    #[test]
    fn serialization_round_trip() {
        let tx = simple_tx();
        assert_eq!(Transaction::decode(&tx.encode()).unwrap(), tx);
    }

    #[test]
    fn round_trip_with_several_inputs() {
        let mut tx = simple_tx();
        tx.inputs.push(TxIn {
            prev_out: OutPoint {
                txid: Hash256([9u8; 32]),
                index: 3,
            },
            witness: Witness {
                pubkey: vec![4u8; 2592],
                signature: vec![5u8; 4627],
            },
            sequence: 7,
        });
        assert_eq!(Transaction::decode(&tx.encode()).unwrap(), tx);
    }

    /// The point that cost Bitcoin six years.
    #[test]
    fn txid_does_not_depend_on_witness() {
        let a = simple_tx();
        let mut b = a.clone();
        b.inputs[0].witness.signature = vec![0xaa; 3309];

        assert_eq!(a.txid(), b.txid(), "the witness must not move the txid");
        assert_ne!(a.wtxid(), b.wtxid(), "the wtxid, however, must move");
    }

    #[test]
    fn txid_depends_on_outputs() {
        let a = simple_tx();
        let mut b = a.clone();
        b.outputs[0].value = Amount::from_units(50_001);
        assert_ne!(a.txid(), b.txid());
    }

    fn spent() -> TxOut {
        TxOut {
            value: Amount::from_units(70_000),
            scheme: SchemeId::LamportOts,
            pubkey_hash: Hash256([7u8; 32]),
        }
    }

    #[test]
    fn sighash_binds_signature_to_its_input() {
        let tx = simple_tx();
        let d = spent();
        assert_ne!(
            tx.sighash(0, Network::Regtest, &d),
            tx.sighash(1, Network::Regtest, &d),
            "otherwise a signature replays from one input to the other"
        );
    }

    /// The signed hash commits to the network: a testnet signature is
    /// worthless on mainnet, or on the other branch of a split. It also
    /// commits to the spent output: its value, its scheme and its lock.
    #[test]
    fn sighash_commits_to_network_and_spent_output() {
        let tx = simple_tx();
        let d = spent();
        let reference = tx.sighash(0, Network::Testnet, &d);
        assert_ne!(reference, tx.sighash(0, Network::Mainnet, &d));
        assert_ne!(reference, tx.sighash(0, Network::Regtest, &d));

        let mut other_value = d;
        other_value.value = Amount::from_units(70_001);
        assert_ne!(reference, tx.sighash(0, Network::Testnet, &other_value));

        let mut other_lock = d;
        other_lock.pubkey_hash = Hash256([8u8; 32]);
        assert_ne!(reference, tx.sighash(0, Network::Testnet, &other_lock));

        let mut other_scheme = d;
        other_scheme.scheme = SchemeId::MlDsa87;
        assert_ne!(reference, tx.sighash(0, Network::Testnet, &other_scheme));

        // And it stays deterministic.
        assert_eq!(reference, tx.sighash(0, Network::Testnet, &d));
    }

    #[test]
    fn sighash_differs_from_txid() {
        let tx = simple_tx();
        assert_ne!(
            tx.sighash(0, Network::Regtest, &spent()).as_bytes(),
            tx.txid().as_bytes()
        );
    }

    /// The Merkle leaf commits to the witness: touching up a signature
    /// changes the root, so the header refuses the block. The txid, however,
    /// does not move.
    #[test]
    fn merkle_leaf_commits_to_witness() {
        let a = simple_tx();
        let mut b = a.clone();
        b.inputs[0].witness.signature = vec![0xaa; 3309];
        assert_eq!(a.txid(), b.txid());
        assert_ne!(a.merkle_leaf(), b.merkle_leaf());
    }

    #[test]
    fn coinbase_is_recognized() {
        let cb = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(b"block 1".to_vec())],
            outputs: vec![output(1_384_711_800)],
            lock_time: 0,
        };
        assert!(cb.is_coinbase());
        assert!(!simple_tx().is_coinbase());
        assert_eq!(Transaction::decode(&cb.encode()).unwrap(), cb);
    }

    #[test]
    fn malformed_transactions_are_rejected() {
        let mut empty = simple_tx();
        empty.inputs.clear();
        assert_eq!(empty.check_shape(), Err(TxError::NoInputs));

        let mut no_output = simple_tx();
        no_output.outputs.clear();
        assert_eq!(no_output.check_shape(), Err(TxError::NoOutputs));
    }

    #[test]
    fn money_cannot_be_created_by_overflow() {
        // Two outputs whose sum overflows u64: the check must bite.
        let mut tx = simple_tx();
        tx.outputs = vec![output(u64::MAX), output(u64::MAX)];
        assert!(matches!(
            tx.check_shape(),
            Err(TxError::AmountAboveCap) | Err(TxError::OutputSumOverflow)
        ));
    }

    #[test]
    fn output_above_cap_is_refused() {
        let mut tx = simple_tx();
        tx.outputs = vec![output(crate::consensus::MAX_SUPPLY + 1)];
        assert_eq!(tx.check_shape(), Err(TxError::AmountAboveCap));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut b = simple_tx().encode();
        b.push(0x00);
        assert!(matches!(
            Transaction::decode(&b),
            Err(TxError::Read(ReadError::TrailingBytes(1)))
        ));
    }

    #[test]
    fn unknown_scheme_in_output_is_refused() {
        let tx = simple_tx();
        let mut b = tx.encode_without_witness();
        // Locates the scheme byte of the first output and corrupts it.
        let pos = 4 + 1 + (32 + 4 + 4) + 1 + 8;
        b[pos] = 200;
        assert!(matches!(
            Transaction::decode(&b),
            Err(TxError::UnknownScheme(200))
        ));
    }

    #[test]
    fn witness_dominates_weight_without_discount() {
        let tx = simple_tx();
        let without = tx.weight(1);
        let with = tx.weight(4);
        assert!(with > without);
        // An ML-DSA signature weighs much more than the body of the transaction.
        let base = tx.encode_without_witness().len() as u64;
        let witness = (1952 + 3309) as u64;
        assert!(witness > base * 20, "base={base} witness={witness}");
    }
}
