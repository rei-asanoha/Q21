//! Pay-to-policy outputs: the locks a payment channel needs.
//!
//! An ordinary output is locked to one key. A channel needs more: a 2-of-2
//! funding output, a "to_local" output the owner can take only after a delay
//! but the counterparty can take at once with a revocation secret, and HTLCs
//! that pay against a preimage or refund after a timeout. Q21 has no script
//! language, and this module does not add one. It adds a small, bounded tree:
//!
//! - `Key(scheme, pubkey_hash)`: a key matching the hash signs;
//! - `Preimage(hash)`: a 32-byte secret whose SHA-256 is `hash` is revealed;
//! - `Older(n)`: the spent output is at least `n` blocks old;
//! - `All[..]`: every child is satisfied;
//! - `Any[..]`: the witness names one child, and that child is satisfied.
//!
//! No loop, no arithmetic, no stack: the cost of evaluating a policy is
//! bounded by its size, and its size is bounded by consensus.
//!
//! # Where it lives in a transaction
//!
//! The output carries [`SchemeId::Policy`] and, in place of a key hash, the
//! policy hash ([`Policy::lock_hash`]). The spender puts the serialized policy
//! in the `pubkey` field of the witness and the serialized satisfaction in its
//! `signature` field. The wire format, the UTXO set and the weight formula are
//! untouched: both fields were already counted as witness bytes, so the
//! revealed policy and every key and signature it needs pay the witness rate,
//! as a plain spend does.
//!
//! # One encoding, and nothing more
//!
//! A policy decodes only from its canonical form: a single-child combinator,
//! a zero time lock, an unknown node or a trailing byte are refused, so two
//! byte strings never mean the same policy. The satisfaction is read *against*
//! the policy, which dictates every field; anything left over is refused. The
//! only freedom left to a third party is the one a plain spend already has —
//! the bytes of a signature — and the witness is outside the `txid`.

use crate::address::Network;
use crate::consensus::{
    MAX_POLICY_DEPTH, MAX_POLICY_LEAVES, MAX_POLICY_SIZE, POLICY_ACTIVATION_MAINNET,
    POLICY_ACTIVATION_REGTEST, POLICY_ACTIVATION_TESTNET,
};
use crate::hash::{tagged_hash, tags, Hash256};
use crate::ser::{ReadError, Reader, Writer};
use crate::sha256::sha256;
use crate::sig::{self, SchemeId, VerifyError};
use crate::tx::{Transaction, TxOut, Witness};
use crate::utxo::UtxoEntry;
use crate::validate::ValidationError;

/// Node tags of the serialized policy. Part of consensus once activated.
const NODE_KEY: u8 = 0x01;
const NODE_PREIMAGE: u8 = 0x02;
const NODE_OLDER: u8 = 0x03;
const NODE_ALL: u8 = 0x04;
const NODE_ANY: u8 = 0x05;

/// A spending policy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Policy {
    Key {
        scheme: SchemeId,
        pubkey_hash: Hash256,
    },
    /// SHA-256 of the 32-byte secret, as Lightning's `payment_hash`.
    Preimage(Hash256),
    /// Relative time lock, in blocks, from 1 to [`crate::consensus::MAX_POLICY_OLDER`].
    Older(u16),
    All(Vec<Policy>),
    Any(Vec<Policy>),
}

/// How a policy is satisfied: mirrors the tree, along the chosen branches.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Satisfaction {
    Key {
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    Preimage([u8; 32]),
    /// Nothing to reveal: the age of the spent output is read from the chain.
    Older,
    All(Vec<Satisfaction>),
    Any {
        index: u8,
        branch: Box<Satisfaction>,
    },
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PolicyError {
    /// The revealed policy is larger than [`MAX_POLICY_SIZE`].
    TooLarge {
        size: usize,
    },
    /// The revealed policy does not hash to the lock of the spent output.
    DoesNotMatchLock,
    /// Truncated input, non-canonical integer, or the like.
    Malformed(ReadError),
    UnknownNode(u8),
    /// A key leaf names something that is not a key scheme.
    NotAKeyScheme(u8),
    TooDeep,
    TooManyLeaves,
    /// A combinator with fewer than two children, or more than the leaf bound.
    BadArity(usize),
    /// `Older(0)`: a lock that locks nothing has a second, shorter spelling
    /// (no lock at all), so it is refused.
    OlderOutOfRange,
    /// Trailing bytes after the policy.
    TrailingPolicyBytes(usize),
    /// An `Any` branch index beyond the children.
    BadBranch {
        index: u8,
        arity: usize,
    },
    /// A key or signature whose length is not its scheme's.
    WitnessSize(VerifyError),
    WrongPreimage,
    /// The relative time lock of the chosen path has not expired.
    TooEarly {
        available_at: u64,
        height: u64,
    },
    /// Bytes left in the satisfaction once the chosen path is read.
    ExtraWitnessData(usize),
}

impl From<ReadError> for PolicyError {
    fn from(e: ReadError) -> Self {
        PolicyError::Malformed(e)
    }
}

/// Is the policy rule in force at `height` on `network`?
///
/// `height` is the height of the block that would contain the transaction:
/// the block's own height in block validation, the tip plus one in the
/// mempool.
pub fn is_active(network: Network, height: u64) -> bool {
    let activation = match network {
        Network::Mainnet => POLICY_ACTIVATION_MAINNET,
        Network::Testnet => POLICY_ACTIVATION_TESTNET,
        Network::Regtest => POLICY_ACTIVATION_REGTEST,
    };
    height >= activation
}

/// May an output locked under `scheme` be created or spent at `height`?
///
/// Key schemes keep their network rule unchanged; the policy value adds the
/// height, which [`SchemeId::allowed_on`] cannot see.
pub fn scheme_allowed(scheme: SchemeId, network: Network, height: u64) -> bool {
    match scheme {
        SchemeId::Policy => is_active(network, height),
        s => s.allowed_on(network),
    }
}

impl Policy {
    /// Canonical serialization. Only meaningful for a policy within the
    /// bounds; [`Policy::decode`] is the gate that enforces them.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        self.write(&mut w);
        w.finish()
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Policy::Key {
                scheme,
                pubkey_hash,
            } => {
                w.u8(NODE_KEY)
                    .u8(scheme.as_u8())
                    .bytes(pubkey_hash.as_bytes());
            }
            Policy::Preimage(h) => {
                w.u8(NODE_PREIMAGE).bytes(h.as_bytes());
            }
            Policy::Older(n) => {
                w.u8(NODE_OLDER).bytes(&n.to_le_bytes());
            }
            Policy::All(children) | Policy::Any(children) => {
                let tag = if matches!(self, Policy::All(_)) {
                    NODE_ALL
                } else {
                    NODE_ANY
                };
                // Saturating: an out-of-bounds policy must encode to
                // something `decode` refuses, never wrap into a valid count.
                w.u8(tag)
                    .u8(u8::try_from(children.len()).unwrap_or(u8::MAX));
                for c in children {
                    c.write(w);
                }
            }
        }
    }

    /// Decodes a policy, refusing every non-canonical or out-of-bounds form.
    pub fn decode(data: &[u8]) -> Result<Policy, PolicyError> {
        if data.len() > MAX_POLICY_SIZE {
            return Err(PolicyError::TooLarge { size: data.len() });
        }
        let mut r = Reader::new(data);
        let mut leaves = 0usize;
        let p = Self::read(&mut r, 1, &mut leaves)?;
        if r.remaining() != 0 {
            return Err(PolicyError::TrailingPolicyBytes(r.remaining()));
        }
        Ok(p)
    }

    fn read(r: &mut Reader<'_>, depth: usize, leaves: &mut usize) -> Result<Policy, PolicyError> {
        // Checked before reading the node: the recursion never goes one level
        // past the bound, whatever the input.
        if depth > MAX_POLICY_DEPTH {
            return Err(PolicyError::TooDeep);
        }
        let mut leaf = || {
            *leaves += 1;
            if *leaves > MAX_POLICY_LEAVES {
                Err(PolicyError::TooManyLeaves)
            } else {
                Ok(())
            }
        };
        match r.u8()? {
            NODE_KEY => {
                let raw = r.u8()?;
                // Only key schemes: a policy nested in a key leaf would be a
                // way around the depth bound.
                let scheme = SchemeId::from_u8(raw)
                    .filter(|s| SchemeId::ALL.contains(s))
                    .ok_or(PolicyError::NotAKeyScheme(raw))?;
                let pubkey_hash = Hash256(r.array32()?);
                leaf()?;
                Ok(Policy::Key {
                    scheme,
                    pubkey_hash,
                })
            }
            NODE_PREIMAGE => {
                let h = Hash256(r.array32()?);
                leaf()?;
                Ok(Policy::Preimage(h))
            }
            NODE_OLDER => {
                let n = u16::from_le_bytes([r.u8()?, r.u8()?]);
                if n == 0 {
                    return Err(PolicyError::OlderOutOfRange);
                }
                leaf()?;
                Ok(Policy::Older(n))
            }
            tag @ (NODE_ALL | NODE_ANY) => {
                let n = r.u8()? as usize;
                // A single child is the child itself, spelled differently.
                if !(2..=MAX_POLICY_LEAVES).contains(&n) {
                    return Err(PolicyError::BadArity(n));
                }
                let mut children = Vec::with_capacity(n);
                for _ in 0..n {
                    children.push(Self::read(r, depth + 1, leaves)?);
                }
                Ok(if tag == NODE_ALL {
                    Policy::All(children)
                } else {
                    Policy::Any(children)
                })
            }
            other => Err(PolicyError::UnknownNode(other)),
        }
    }

    /// The hash an output commits to: tagged, so that it can never equal the
    /// hash of a key (`Q21/address`) or of anything else in the protocol.
    pub fn lock_hash(&self) -> Hash256 {
        lock_hash_of(&self.encode())
    }

    /// An output locked to this policy.
    pub fn output(&self, value: crate::amount::Amount) -> TxOut {
        TxOut {
            value,
            scheme: SchemeId::Policy,
            pubkey_hash: self.lock_hash(),
        }
    }

    /// Number of leaves, in pre-order.
    pub fn leaf_count(&self) -> usize {
        match self {
            Policy::All(c) | Policy::Any(c) => c.iter().map(Policy::leaf_count).sum(),
            _ => 1,
        }
    }

    /// The key leaves with their pre-order leaf position, the number a signer
    /// passes to [`sighash`].
    pub fn key_leaves(&self) -> Vec<(u8, SchemeId, Hash256)> {
        fn go(p: &Policy, pos: &mut u8, out: &mut Vec<(u8, SchemeId, Hash256)>) {
            match p {
                Policy::Key {
                    scheme,
                    pubkey_hash,
                } => {
                    out.push((*pos, *scheme, *pubkey_hash));
                    *pos += 1;
                }
                Policy::All(c) | Policy::Any(c) => c.iter().for_each(|c| go(c, pos, out)),
                _ => *pos += 1,
            }
        }
        let mut out = Vec::new();
        go(self, &mut 0, &mut out);
        out
    }
}

fn lock_hash_of(policy_bytes: &[u8]) -> Hash256 {
    tagged_hash(tags::POLICY, policy_bytes)
}

impl Satisfaction {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.finish()
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Satisfaction::Key { pubkey, signature } => {
                w.var_bytes(pubkey).var_bytes(signature);
            }
            Satisfaction::Preimage(p) => {
                w.bytes(p);
            }
            Satisfaction::Older => {}
            Satisfaction::All(c) => c.iter().for_each(|c| c.write(w)),
            Satisfaction::Any { index, branch } => {
                w.u8(*index);
                branch.write(w);
            }
        }
    }
}

/// The witness of a policy spend.
pub fn witness(policy: &Policy, satisfaction: &Satisfaction) -> Witness {
    Witness {
        pubkey: policy.encode(),
        signature: satisfaction.encode(),
    }
}

/// The message the key at leaf `leaf` signs. See
/// [`Transaction::policy_sighash`].
pub fn sighash(
    tx: &Transaction,
    input_index: u32,
    network: Network,
    spent: &TxOut,
    policy: &Policy,
    leaf: u8,
) -> Hash256 {
    tx.policy_sighash(input_index, network, spent, &policy.encode(), leaf)
}

/// A key the chosen path requires, as read from the satisfaction.
struct KeyUse<'a> {
    leaf: u8,
    scheme: SchemeId,
    hash: Hash256,
    pubkey: &'a [u8],
    signature: &'a [u8],
}

/// What reading a satisfaction against its policy yields, before anything
/// that depends on the chain or costs a signature verification.
struct Path<'a> {
    keys: Vec<KeyUse<'a>>,
    /// Largest `Older` on the chosen path; zero when there is none.
    min_age: u64,
}

/// Reads the satisfaction of `p` from `r`, following the branches it names.
///
/// Preimages are checked here: one SHA-256 is cheaper than carrying them
/// further. Keys are only collected.
fn walk<'a>(
    p: &Policy,
    r: &mut Reader<'a>,
    leaf: &mut u8,
    path: &mut Path<'a>,
) -> Result<(), PolicyError> {
    match p {
        Policy::Key {
            scheme,
            pubkey_hash,
        } => {
            let pubkey = r.var_bytes()?;
            let signature = r.var_bytes()?;
            // Sizes first: the length prefix is the only free field, and a
            // wrong one is refused here rather than at verification.
            sig::check_sizes(*scheme, pubkey, signature).map_err(PolicyError::WitnessSize)?;
            path.keys.push(KeyUse {
                leaf: *leaf,
                scheme: *scheme,
                hash: *pubkey_hash,
                pubkey,
                signature,
            });
            *leaf += 1;
        }
        Policy::Preimage(h) => {
            let secret = r.array32()?;
            if sha256(&secret) != h.0 {
                return Err(PolicyError::WrongPreimage);
            }
            *leaf += 1;
        }
        Policy::Older(n) => {
            path.min_age = path.min_age.max(u64::from(*n));
            *leaf += 1;
        }
        Policy::All(children) => {
            for c in children {
                walk(c, r, leaf, path)?;
            }
        }
        Policy::Any(children) => {
            let index = r.u8()?;
            if usize::from(index) >= children.len() {
                return Err(PolicyError::BadBranch {
                    index,
                    arity: children.len(),
                });
            }
            for (i, c) in children.iter().enumerate() {
                if i == usize::from(index) {
                    walk(c, r, leaf, path)?;
                } else {
                    // Leaf positions are those of the whole tree, so that a
                    // signature names one leaf whichever branch is taken.
                    *leaf += c.leaf_count() as u8;
                }
            }
        }
    }
    Ok(())
}

/// Decodes the revealed policy and reads the satisfaction along it, with no
/// reference to the chain.
fn read_spend<'a>(spent: &TxOut, witness: &'a Witness) -> Result<(Policy, Path<'a>), PolicyError> {
    if witness.pubkey.len() > MAX_POLICY_SIZE {
        return Err(PolicyError::TooLarge {
            size: witness.pubkey.len(),
        });
    }
    // The lock before the decoding: a policy that is not the committed one
    // is refused whatever it contains.
    if lock_hash_of(&witness.pubkey) != spent.pubkey_hash {
        return Err(PolicyError::DoesNotMatchLock);
    }
    let policy = Policy::decode(&witness.pubkey)?;
    let mut r = Reader::new(&witness.signature);
    let mut path = Path {
        keys: Vec::new(),
        min_age: 0,
    };
    walk(&policy, &mut r, &mut 0, &mut path)?;
    if r.remaining() != 0 {
        return Err(PolicyError::ExtraWitnessData(r.remaining()));
    }
    Ok((policy, path))
}

/// Checks the spend of a policy output by input `input_index` of `tx`, in a
/// block at `height`.
///
/// # Relative time lock
///
/// `Older(n)` holds when `height >= spent.height + n`: the spend can enter the
/// block `n` blocks after the one that created the output, never before. An
/// output created earlier in the same block has age zero, so any `Older`
/// refuses it. The mempool passes the height of the next block, as for
/// coinbase maturity, and rechecks after a reorganization
/// ([`required_age`]).
///
/// # Order
///
/// Everything cheap — size, lock, structure, preimages, age, key hashes,
/// schemes — is refused before the first signature is verified.
pub fn check_spend(
    tx: &Transaction,
    input_index: u32,
    network: Network,
    spent: &UtxoEntry,
    height: u64,
    witness: &Witness,
) -> Result<(), ValidationError> {
    let (_, path) = read_spend(&spent.output, witness).map_err(ValidationError::Policy)?;

    if path.min_age > 0 {
        let available_at = spent.height.saturating_add(path.min_age);
        if height < available_at {
            return Err(ValidationError::Policy(PolicyError::TooEarly {
                available_at,
                height,
            }));
        }
    }

    for k in &path.keys {
        if !k.scheme.allowed_on(network) {
            return Err(ValidationError::SchemeForbiddenOnNetwork(k.scheme));
        }
        if sig::pubkey_hash(k.scheme, k.pubkey) != k.hash {
            return Err(ValidationError::KeyDoesNotMatchLock);
        }
    }

    for k in &path.keys {
        let message =
            tx.policy_sighash(input_index, network, &spent.output, &witness.pubkey, k.leaf);
        sig::verify(k.scheme, k.pubkey, &message, k.signature)
            .map_err(ValidationError::Signature)?;
    }
    Ok(())
}

/// Age the chosen path of an already validated policy spend requires, in
/// blocks; zero for anything else.
///
/// The mempool needs it after a reorganization: the signatures still hold,
/// but a lower tip, or a parent moved to a later block, can put a time lock
/// back in the future.
pub fn required_age(spent: &TxOut, witness: &Witness) -> u64 {
    if spent.scheme != SchemeId::Policy {
        return 0;
    }
    read_spend(spent, witness).map_or(0, |(_, path)| path.min_age)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash256 {
        Hash256([b; 32])
    }

    fn key_leaf(b: u8) -> Policy {
        Policy::Key {
            scheme: SchemeId::MlDsa87,
            pubkey_hash: h(b),
        }
    }

    fn htlc() -> Policy {
        Policy::Any(vec![
            Policy::All(vec![key_leaf(2), Policy::Preimage(h(9))]),
            Policy::All(vec![key_leaf(1), Policy::Older(144)]),
        ])
    }

    #[test]
    fn channel_shapes_round_trip() {
        let funding = Policy::All(vec![key_leaf(1), key_leaf(2)]);
        let to_local = Policy::Any(vec![
            Policy::All(vec![key_leaf(2), Policy::Preimage(h(8))]),
            Policy::All(vec![key_leaf(1), Policy::Older(720)]),
        ]);
        for p in [funding, to_local, htlc()] {
            let b = p.encode();
            assert_eq!(Policy::decode(&b), Ok(p.clone()));
            // One encoding: decode then encode gives the same bytes back.
            assert_eq!(Policy::decode(&b).unwrap().encode(), b);
        }
    }

    #[test]
    fn leaf_positions_are_pre_order() {
        assert_eq!(
            htlc().key_leaves(),
            vec![(0, SchemeId::MlDsa87, h(2)), (2, SchemeId::MlDsa87, h(1))]
        );
        assert_eq!(htlc().leaf_count(), 4);
    }

    /// The lock of a policy is domain-separated from the lock of a key: the
    /// same bytes hashed as one or the other never collide.
    #[test]
    fn policy_hash_is_not_a_key_hash() {
        let b = htlc().encode();
        assert_ne!(
            lock_hash_of(&b),
            sig::pubkey_hash(SchemeId::MlDsa87, &b[1..])
        );
        assert_ne!(lock_hash_of(&b), tagged_hash(tags::ADDRESS, &b));
    }

    #[test]
    fn non_canonical_policies_are_refused() {
        // A single-child combinator: the child spelled differently.
        let single = [NODE_ALL, 1, NODE_OLDER, 1, 0];
        assert_eq!(Policy::decode(&single), Err(PolicyError::BadArity(1)));
        // An empty one.
        assert_eq!(
            Policy::decode(&[NODE_ANY, 0]),
            Err(PolicyError::BadArity(0))
        );
        // A time lock of zero.
        assert_eq!(
            Policy::decode(&[NODE_OLDER, 0, 0]),
            Err(PolicyError::OlderOutOfRange)
        );
        // A trailing byte.
        let mut b = htlc().encode();
        b.push(0);
        assert_eq!(Policy::decode(&b), Err(PolicyError::TrailingPolicyBytes(1)));
        // Truncated.
        let b = htlc().encode();
        assert_eq!(
            Policy::decode(&b[..b.len() - 1]),
            Err(PolicyError::Malformed(ReadError::UnexpectedEnd))
        );
        // Unknown node.
        assert_eq!(Policy::decode(&[0x06]), Err(PolicyError::UnknownNode(6)));
        assert_eq!(Policy::decode(&[0x00]), Err(PolicyError::UnknownNode(0)));
        // A key leaf whose "scheme" is the policy value, or nothing known.
        for raw in [0u8, 5, 6, 255] {
            let mut b = vec![NODE_KEY, raw];
            b.extend_from_slice(&[0u8; 32]);
            assert_eq!(Policy::decode(&b), Err(PolicyError::NotAKeyScheme(raw)));
        }
        // Empty input.
        assert_eq!(
            Policy::decode(&[]),
            Err(PolicyError::Malformed(ReadError::UnexpectedEnd))
        );
    }

    #[test]
    fn policies_over_the_bounds_are_refused() {
        // Nine leaves.
        let nine = Policy::All(vec![
            Policy::All((0..4).map(|_| Policy::Older(1)).collect()),
            Policy::All((0..5).map(|_| Policy::Older(1)).collect()),
        ]);
        assert_eq!(nine.leaf_count(), 9);
        assert_eq!(
            Policy::decode(&nine.encode()),
            Err(PolicyError::TooManyLeaves)
        );
        // Nine children of one combinator.
        let wide = Policy::Any((0..9).map(|_| Policy::Older(1)).collect());
        assert_eq!(
            Policy::decode(&wide.encode()),
            Err(PolicyError::BadArity(9))
        );
        // Eight leaves is fine.
        let eight = Policy::Any((0..8).map(|_| key_leaf(1)).collect());
        assert!(Policy::decode(&eight.encode()).is_ok());
        assert!(eight.encode().len() <= MAX_POLICY_SIZE);
        // Depth five, leaves counting as a level: All[All[All[All[Older]]]].
        let mut deep = Policy::All(vec![Policy::Older(1), Policy::Older(2)]);
        for _ in 0..3 {
            deep = Policy::All(vec![deep, Policy::Older(3)]);
        }
        assert_eq!(Policy::decode(&deep.encode()), Err(PolicyError::TooDeep));
        // Depth four is fine.
        let mut ok = Policy::All(vec![Policy::Older(1), Policy::Older(2)]);
        for _ in 0..2 {
            ok = Policy::All(vec![ok, Policy::Older(3)]);
        }
        assert!(Policy::decode(&ok.encode()).is_ok());
        // Oversized bytes, refused before any parsing.
        let big = vec![NODE_ALL; MAX_POLICY_SIZE + 1];
        assert_eq!(
            Policy::decode(&big),
            Err(PolicyError::TooLarge {
                size: MAX_POLICY_SIZE + 1
            })
        );
    }

    #[test]
    fn activation_is_regtest_only() {
        assert!(!is_active(Network::Mainnet, u64::MAX - 1));
        assert!(!is_active(Network::Testnet, u64::MAX - 1));
        assert!(!is_active(Network::Regtest, 0));
        assert!(is_active(Network::Regtest, 1));
        assert!(!scheme_allowed(SchemeId::Policy, Network::Testnet, 1_000));
        assert!(scheme_allowed(SchemeId::MlDsa87, Network::Mainnet, 0));
        assert!(!scheme_allowed(SchemeId::LamportOts, Network::Mainnet, 0));
    }
}

/// Spends checked end to end, with real ML-DSA-87 keys, through
/// [`crate::validate::check_transaction`].
#[cfg(all(test, feature = "mldsa"))]
mod spend_tests {
    use super::*;
    use crate::amount::Amount;
    use crate::consensus::WITNESS_DISCOUNT;
    use crate::tx::{OutPoint, TxIn};
    use crate::utxo::UtxoSet;
    use crate::validate::check_transaction;
    use ml_dsa::{signature::Keypair, MlDsa87, Signer, SigningKey, B32};
    use std::collections::HashSet;

    const NET: Network = Network::Regtest;
    /// Height of the block that created the spent output.
    const BORN: u64 = 10;
    const VALUE: u64 = 1_000_000;

    struct Key {
        sk: SigningKey<MlDsa87>,
        pk: Vec<u8>,
    }

    impl Key {
        fn new(n: u8) -> Key {
            let sk = SigningKey::<MlDsa87>::from_seed(&B32::from([n; 32]));
            let pk = sk.verifying_key().encode()[..].to_vec();
            Key { sk, pk }
        }
        fn hash(&self) -> Hash256 {
            sig::pubkey_hash(SchemeId::MlDsa87, &self.pk)
        }
        fn leaf(&self) -> Policy {
            Policy::Key {
                scheme: SchemeId::MlDsa87,
                pubkey_hash: self.hash(),
            }
        }
        fn sign(&self, m: &Hash256) -> Vec<u8> {
            self.sk.sign(m.as_bytes()).encode()[..].to_vec()
        }
        fn output(&self, v: u64) -> TxOut {
            TxOut {
                value: Amount::from_units(v),
                scheme: SchemeId::MlDsa87,
                pubkey_hash: self.hash(),
            }
        }
    }

    fn preimage(n: u8) -> ([u8; 32], Hash256) {
        let s = [n; 32];
        (s, Hash256(sha256(&s)))
    }

    /// A UTXO set holding one output locked to `policy`, born at `BORN`.
    fn fixture(policy: &Policy) -> (UtxoSet, OutPoint, UtxoEntry) {
        let op = OutPoint {
            txid: Hash256([0x42; 32]),
            index: 0,
        };
        let e = UtxoEntry {
            output: policy.output(Amount::from_units(VALUE)),
            height: BORN,
            is_coinbase: false,
        };
        let mut u = UtxoSet::new();
        u.insert(op, e);
        (u, op, e)
    }

    /// One input spending `op`, paying `outputs`; the witness is filled later.
    fn spend(op: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: op,
                witness: Witness::default(),
                sequence: u32::MAX,
            }],
            outputs,
            lock_time: 0,
        }
    }

    fn sign_leaf(tx: &Transaction, e: &UtxoEntry, p: &Policy, leaf: u8, k: &Key) -> Satisfaction {
        Satisfaction::Key {
            pubkey: k.pk.clone(),
            signature: k.sign(&sighash(tx, 0, NET, &e.output, p, leaf)),
        }
    }

    fn check(
        u: &UtxoSet,
        tx: &Transaction,
        net: Network,
        height: u64,
    ) -> Result<Amount, ValidationError> {
        check_transaction(tx, u, net, height, &mut HashSet::new())
    }

    fn any(index: u8, s: Satisfaction) -> Satisfaction {
        Satisfaction::Any {
            index,
            branch: Box::new(s),
        }
    }

    fn pol(e: PolicyError) -> Result<Amount, ValidationError> {
        Err(ValidationError::Policy(e))
    }

    // --- Leaves --------------------------------------------------------

    #[test]
    fn key_leaf() {
        let (a, b) = (Key::new(1), Key::new(2));
        let p = a.leaf();
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![b.output(VALUE - 20_000)]);

        let good = sign_leaf(&tx, &e, &p, 0, &a);
        tx.inputs[0].witness = witness(&p, &good);
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            Ok(Amount::from_units(20_000))
        );

        // Wrong key: B's key and B's signature in A's leaf.
        let wrong = sign_leaf(&tx, &e, &p, 0, &b);
        tx.inputs[0].witness = witness(&p, &wrong);
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            Err(ValidationError::KeyDoesNotMatchLock)
        );

        // Missing signature.
        tx.inputs[0].witness = witness(
            &p,
            &Satisfaction::Key {
                pubkey: a.pk.clone(),
                signature: Vec::new(),
            },
        );
        assert!(matches!(
            check(&u, &tx, NET, BORN + 1),
            Err(ValidationError::Policy(PolicyError::WitnessSize(_)))
        ));

        // A's signature over something else: the plain sighash of the same
        // input, which a policy spend never signs.
        let plain = tx.sighash(0, NET, &e.output);
        tx.inputs[0].witness = witness(
            &p,
            &Satisfaction::Key {
                pubkey: a.pk.clone(),
                signature: a.sign(&plain),
            },
        );
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        );
    }

    #[test]
    fn preimage_leaf() {
        let b = Key::new(2);
        let (secret, hash) = preimage(7);
        let p = Policy::All(vec![b.leaf(), Policy::Preimage(hash)]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![b.output(VALUE - 20_000)]);
        let sig = sign_leaf(&tx, &e, &p, 0, &b);

        tx.inputs[0].witness = witness(
            &p,
            &Satisfaction::All(vec![sig.clone(), Satisfaction::Preimage(secret)]),
        );
        assert!(check(&u, &tx, NET, BORN + 1).is_ok());

        let mut wrong = secret;
        wrong[0] ^= 1;
        tx.inputs[0].witness = witness(
            &p,
            &Satisfaction::All(vec![sig, Satisfaction::Preimage(wrong)]),
        );
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::WrongPreimage)
        );
    }

    /// `Older(n)`: valid from the block `n` after the output's, not before.
    /// An output born in the spending block itself has age zero.
    #[test]
    fn older_leaf() {
        let a = Key::new(1);
        let p = Policy::All(vec![a.leaf(), Policy::Older(5)]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let s = Satisfaction::All(vec![sign_leaf(&tx, &e, &p, 0, &a), Satisfaction::Older]);
        tx.inputs[0].witness = witness(&p, &s);

        for height in [BORN, BORN + 1, BORN + 4] {
            assert_eq!(
                check(&u, &tx, NET, height),
                pol(PolicyError::TooEarly {
                    available_at: BORN + 5,
                    height
                })
            );
        }
        assert!(check(&u, &tx, NET, BORN + 5).is_ok());
        assert!(check(&u, &tx, NET, BORN + 500).is_ok());
        assert_eq!(required_age(&e.output, &tx.inputs[0].witness), 5);
    }

    // --- Channel shapes ------------------------------------------------

    #[test]
    fn funding_two_of_two() {
        let (a, b) = (Key::new(1), Key::new(2));
        let p = Policy::All(vec![a.leaf(), b.leaf()]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(500_000), b.output(VALUE - 520_000)]);
        let sa = sign_leaf(&tx, &e, &p, 0, &a);
        let sb = sign_leaf(&tx, &e, &p, 1, &b);

        tx.inputs[0].witness = witness(&p, &Satisfaction::All(vec![sa.clone(), sb.clone()]));
        assert!(check(&u, &tx, NET, BORN + 1).is_ok());

        // A alone, signing both slots.
        let sa1 = sign_leaf(&tx, &e, &p, 1, &a);
        tx.inputs[0].witness = witness(&p, &Satisfaction::All(vec![sa.clone(), sa1]));
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            Err(ValidationError::KeyDoesNotMatchLock)
        );

        // A alone, B's slot carrying B's key but no signature.
        let no_sig = Satisfaction::Key {
            pubkey: b.pk.clone(),
            signature: vec![0u8; SchemeId::MlDsa87.sig_len()],
        };
        tx.inputs[0].witness = witness(&p, &Satisfaction::All(vec![sa.clone(), no_sig]));
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        );

        // A alone, B's slot dropped.
        tx.inputs[0].witness = witness(&p, &Satisfaction::All(vec![sa]));
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::Malformed(ReadError::UnexpectedEnd))
        );

        // Signatures swapped between the slots: each names its leaf.
        tx.inputs[0].witness = witness(
            &p,
            &Satisfaction::All(vec![sb, sign_leaf(&tx, &e, &p, 0, &a)]),
        );
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            Err(ValidationError::KeyDoesNotMatchLock)
        );
    }

    fn to_local(local: &Key, remote: &Key, revocation: Hash256, delay: u16) -> Policy {
        Policy::Any(vec![
            Policy::All(vec![remote.leaf(), Policy::Preimage(revocation)]),
            Policy::All(vec![local.leaf(), Policy::Older(delay)]),
        ])
    }

    #[test]
    fn to_local_penalty_and_delay() {
        let (local, remote) = (Key::new(1), Key::new(2));
        let (secret, rev) = preimage(3);
        let p = to_local(&local, &remote, rev, 144);
        let (u, op, e) = fixture(&p);

        // Penalty: the remote, with the revocation secret, at once.
        let mut penalty = spend(op, vec![remote.output(VALUE - 20_000)]);
        let s = any(
            0,
            Satisfaction::All(vec![
                sign_leaf(&penalty, &e, &p, 0, &remote),
                Satisfaction::Preimage(secret),
            ]),
        );
        penalty.inputs[0].witness = witness(&p, &s);
        assert!(check(&u, &penalty, NET, BORN + 1).is_ok());
        // Not the local key on the penalty branch.
        let s = any(
            0,
            Satisfaction::All(vec![
                sign_leaf(&penalty, &e, &p, 0, &local),
                Satisfaction::Preimage(secret),
            ]),
        );
        penalty.inputs[0].witness = witness(&p, &s);
        assert_eq!(
            check(&u, &penalty, NET, BORN + 1),
            Err(ValidationError::KeyDoesNotMatchLock)
        );

        // Delayed branch: the local key, after the delay only.
        let mut delayed = spend(op, vec![local.output(VALUE - 20_000)]);
        let s = any(
            1,
            Satisfaction::All(vec![
                sign_leaf(&delayed, &e, &p, 2, &local),
                Satisfaction::Older,
            ]),
        );
        delayed.inputs[0].witness = witness(&p, &s);
        assert_eq!(
            check(&u, &delayed, NET, BORN + 143),
            pol(PolicyError::TooEarly {
                available_at: BORN + 144,
                height: BORN + 143
            })
        );
        assert!(check(&u, &delayed, NET, BORN + 144).is_ok());
    }

    #[test]
    fn htlc_success_and_timeout() {
        let (a, b) = (Key::new(1), Key::new(2));
        let (secret, payment_hash) = preimage(4);
        let p = Policy::Any(vec![
            Policy::All(vec![b.leaf(), Policy::Preimage(payment_hash)]),
            Policy::All(vec![a.leaf(), Policy::Older(40)]),
        ]);
        let (u, op, e) = fixture(&p);

        let mut success = spend(op, vec![b.output(VALUE - 20_000)]);
        let s = any(
            0,
            Satisfaction::All(vec![
                sign_leaf(&success, &e, &p, 0, &b),
                Satisfaction::Preimage(secret),
            ]),
        );
        success.inputs[0].witness = witness(&p, &s);
        assert!(check(&u, &success, NET, BORN + 1).is_ok());
        // B cannot take the timeout branch.
        let s = any(
            1,
            Satisfaction::All(vec![
                sign_leaf(&success, &e, &p, 2, &b),
                Satisfaction::Older,
            ]),
        );
        success.inputs[0].witness = witness(&p, &s);
        assert_eq!(
            check(&u, &success, NET, BORN + 100),
            Err(ValidationError::KeyDoesNotMatchLock)
        );

        let mut timeout = spend(op, vec![a.output(VALUE - 20_000)]);
        let s = any(
            1,
            Satisfaction::All(vec![
                sign_leaf(&timeout, &e, &p, 2, &a),
                Satisfaction::Older,
            ]),
        );
        timeout.inputs[0].witness = witness(&p, &s);
        assert!(matches!(
            check(&u, &timeout, NET, BORN + 39),
            Err(ValidationError::Policy(PolicyError::TooEarly { .. }))
        ));
        assert!(check(&u, &timeout, NET, BORN + 40).is_ok());
    }

    // --- Attacks -------------------------------------------------------

    /// The same key on two branches: its signature for one branch does not
    /// open the other, because each signature names its leaf.
    #[test]
    fn signature_does_not_replay_across_branches() {
        let a = Key::new(1);
        let (secret, hash) = preimage(5);
        let p = Policy::Any(vec![
            Policy::All(vec![a.leaf(), Policy::Preimage(hash)]),
            Policy::All(vec![a.leaf(), Policy::Older(10)]),
        ]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let branch_a = sign_leaf(&tx, &e, &p, 0, &a);

        tx.inputs[0].witness = witness(
            &p,
            &any(
                0,
                Satisfaction::All(vec![branch_a.clone(), Satisfaction::Preimage(secret)]),
            ),
        );
        assert!(check(&u, &tx, NET, BORN + 20).is_ok());

        tx.inputs[0].witness = witness(
            &p,
            &any(1, Satisfaction::All(vec![branch_a, Satisfaction::Older])),
        );
        assert_eq!(
            check(&u, &tx, NET, BORN + 20),
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        );
    }

    /// Nor across policies: the same key, the same transaction, another
    /// policy committing to it.
    #[test]
    fn signature_does_not_replay_across_policies() {
        let (a, b) = (Key::new(1), Key::new(2));
        let p1 = Policy::All(vec![a.leaf(), b.leaf()]);
        let p2 = Policy::Any(vec![a.leaf(), b.leaf()]);
        let (_, op, e1) = fixture(&p1);
        let (u2, _, e2) = fixture(&p2);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        // Same value, same outpoint, same leaf position: only the policy
        // differs.
        let s1 = sign_leaf(&tx, &e1, &p1, 0, &a);
        tx.inputs[0].witness = witness(&p2, &any(0, s1));
        assert_eq!(
            check(&u2, &tx, NET, BORN + 1),
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        );
        tx.inputs[0].witness = witness(&p2, &any(0, sign_leaf(&tx, &e2, &p2, 0, &a)));
        assert!(check(&u2, &tx, NET, BORN + 1).is_ok());
    }

    #[test]
    fn extra_or_malformed_witness_data_is_refused() {
        let a = Key::new(1);
        let (secret, hash) = preimage(6);
        let p = Policy::Any(vec![a.leaf(), Policy::Preimage(hash)]);
        let (u, op, _) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);

        let good = witness(&p, &any(1, Satisfaction::Preimage(secret)));
        tx.inputs[0].witness = good.clone();
        assert!(check(&u, &tx, NET, BORN + 1).is_ok());

        // One byte too many.
        let mut w = good.clone();
        w.signature.push(0);
        tx.inputs[0].witness = w;
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::ExtraWitnessData(1))
        );

        // Unused data for the other branch: a key and signature appended.
        let mut w = good.clone();
        w.signature.extend_from_slice(
            &Satisfaction::Key {
                pubkey: a.pk.clone(),
                signature: vec![0; SchemeId::MlDsa87.sig_len()],
            }
            .encode(),
        );
        let extra = w.signature.len() - good.signature.len();
        tx.inputs[0].witness = w;
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::ExtraWitnessData(extra))
        );

        // A branch that does not exist.
        tx.inputs[0].witness = witness(&p, &any(2, Satisfaction::Preimage(secret)));
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::BadBranch { index: 2, arity: 2 })
        );

        // A policy byte touched: no longer the committed policy.
        let mut w = good.clone();
        w.pubkey.push(0);
        tx.inputs[0].witness = w;
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::DoesNotMatchLock)
        );

        // An oversized policy is refused on its size alone.
        let mut w = good;
        w.pubkey = vec![0; MAX_POLICY_SIZE + 1];
        tx.inputs[0].witness = w;
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::TooLarge {
                size: MAX_POLICY_SIZE + 1
            })
        );
    }

    /// A key length written in a longer varint form than needed: same
    /// meaning, different bytes. Refused.
    #[test]
    fn non_canonical_satisfaction_is_refused() {
        let a = Key::new(1);
        let p = Policy::All(vec![a.leaf(), Policy::Older(1)]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let s = Satisfaction::All(vec![sign_leaf(&tx, &e, &p, 0, &a), Satisfaction::Older]);
        let canonical = s.encode();
        tx.inputs[0].witness = witness(&p, &s);
        assert!(check(&u, &tx, NET, BORN + 1).is_ok());

        // 2592 = 0xfd 0x20 0x0a; the same length on five bytes.
        assert_eq!(&canonical[..3], &[0xfd, 0x20, 0x0a]);
        let mut long = vec![0xfe, 0x20, 0x0a, 0x00, 0x00];
        long.extend_from_slice(&canonical[3..]);
        tx.inputs[0].witness.signature = long;
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::Malformed(ReadError::NonCanonicalVarint))
        );
    }

    #[test]
    fn activation_gates_creation_and_spending() {
        let a = Key::new(1);
        let (secret, hash) = preimage(6);
        let p = Policy::Any(vec![a.leaf(), Policy::Preimage(hash)]);

        // Creating a policy output: refused on the live networks at any
        // height, and on regtest below the activation height.
        let funding_src = OutPoint {
            txid: Hash256([0x43; 32]),
            index: 0,
        };
        for (net, height) in [
            (Network::Testnet, 1_000),
            (Network::Mainnet, 1_000),
            (Network::Regtest, 0),
        ] {
            let mut u = UtxoSet::new();
            u.insert(
                funding_src,
                UtxoEntry {
                    output: a.output(VALUE),
                    height: 0,
                    is_coinbase: false,
                },
            );
            let mut tx = spend(
                funding_src,
                vec![p.output(Amount::from_units(VALUE - 20_000))],
            );
            let m = tx.sighash(0, net, &a.output(VALUE));
            tx.inputs[0].witness = Witness {
                pubkey: a.pk.clone(),
                signature: a.sign(&m),
            };
            assert_eq!(
                check(&u, &tx, net, height),
                Err(ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy)),
                "{net:?} at {height}"
            );
            if net == Network::Regtest {
                assert!(check(&u, &tx, net, POLICY_ACTIVATION_REGTEST).is_ok());
            }
        }

        // Spending one that somehow exists: refused as well.
        let (u, op, _) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        tx.inputs[0].witness = witness(&p, &any(1, Satisfaction::Preimage(secret)));
        assert!(check(&u, &tx, NET, BORN + 1).is_ok());
        for net in [Network::Testnet, Network::Mainnet] {
            assert_eq!(
                check(&u, &tx, net, BORN + 1),
                Err(ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy))
            );
        }
        assert_eq!(
            check(&u, &tx, NET, 0),
            Err(ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy))
        );
    }

    // --- Weights -------------------------------------------------------

    /// Weight of each channel transaction, with real keys and signatures.
    ///
    /// `cargo test --features mldsa --lib policy::spend_tests::channel_weights -- --nocapture`
    #[test]
    fn channel_weights() {
        let (a, b) = (Key::new(1), Key::new(2));
        let (rev_secret, rev) = preimage(3);
        let (pay_secret, pay) = preimage(4);
        let fund = Policy::All(vec![a.leaf(), b.leaf()]);
        let (_, op, fe) = fixture(&fund);
        let w = |tx: &Transaction| tx.weight(WITNESS_DISCOUNT);

        // Funding: one plain ML-DSA-87 input, the 2-of-2 output and change.
        let src = OutPoint {
            txid: Hash256([0x44; 32]),
            index: 0,
        };
        let mut funding = spend(
            src,
            vec![fund.output(Amount::from_units(VALUE)), a.output(50_000)],
        );
        funding.inputs[0].witness = Witness {
            pubkey: a.pk.clone(),
            signature: a.sign(&funding.sighash(0, NET, &a.output(2 * VALUE))),
        };

        // Commitment: spends the funding output, pays to_local and to_remote.
        let local = to_local(&a, &b, rev, 144);
        let mut commitment = spend(
            op,
            vec![local.output(Amount::from_units(600_000)), b.output(380_000)],
        );
        let s = Satisfaction::All(vec![
            sign_leaf(&commitment, &fe, &fund, 0, &a),
            sign_leaf(&commitment, &fe, &fund, 1, &b),
        ]);
        commitment.inputs[0].witness = witness(&fund, &s);

        // Commitment with one HTLC as well.
        let htlc = Policy::Any(vec![
            Policy::All(vec![b.leaf(), Policy::Preimage(pay)]),
            Policy::All(vec![a.leaf(), Policy::Older(40)]),
        ]);
        let mut commitment_htlc = commitment.clone();
        commitment_htlc
            .outputs
            .push(htlc.output(Amount::from_units(100_000)));
        commitment_htlc.outputs[0].value = Amount::from_units(500_000);
        let s = Satisfaction::All(vec![
            sign_leaf(&commitment_htlc, &fe, &fund, 0, &a),
            sign_leaf(&commitment_htlc, &fe, &fund, 1, &b),
        ]);
        commitment_htlc.inputs[0].witness = witness(&fund, &s);

        // Spends of the commitment outputs.
        let (_, lop, le) = fixture(&local);
        let mut penalty = spend(lop, vec![b.output(580_000)]);
        let s = any(
            0,
            Satisfaction::All(vec![
                sign_leaf(&penalty, &le, &local, 0, &b),
                Satisfaction::Preimage(rev_secret),
            ]),
        );
        penalty.inputs[0].witness = witness(&local, &s);

        let mut delayed = spend(lop, vec![a.output(580_000)]);
        let s = any(
            1,
            Satisfaction::All(vec![
                sign_leaf(&delayed, &le, &local, 2, &a),
                Satisfaction::Older,
            ]),
        );
        delayed.inputs[0].witness = witness(&local, &s);

        let (_, hop, he) = fixture(&htlc);
        let mut success = spend(hop, vec![b.output(80_000)]);
        let s = any(
            0,
            Satisfaction::All(vec![
                sign_leaf(&success, &he, &htlc, 0, &b),
                Satisfaction::Preimage(pay_secret),
            ]),
        );
        success.inputs[0].witness = witness(&htlc, &s);

        let mut timeout = spend(hop, vec![a.output(80_000)]);
        let s = any(
            1,
            Satisfaction::All(vec![
                sign_leaf(&timeout, &he, &htlc, 2, &a),
                Satisfaction::Older,
            ]),
        );
        timeout.inputs[0].witness = witness(&htlc, &s);

        // Cooperative close: the funding output straight to two keys.
        let mut close = spend(op, vec![a.output(600_000), b.output(380_000)]);
        let s = Satisfaction::All(vec![
            sign_leaf(&close, &fe, &fund, 0, &a),
            sign_leaf(&close, &fe, &fund, 1, &b),
        ]);
        close.inputs[0].witness = witness(&fund, &s);

        // A plain one-input, two-output ML-DSA-87 payment, for scale.
        let mut plain = spend(src, vec![a.output(500_000), b.output(400_000)]);
        plain.inputs[0].witness = Witness {
            pubkey: a.pk.clone(),
            signature: a.sign(&Hash256::ZERO),
        };

        let rows = [
            ("plain payment (reference)", &plain),
            ("funding", &funding),
            ("commitment, 2 outputs", &commitment),
            ("commitment, 2 outputs + 1 HTLC", &commitment_htlc),
            ("penalty (to_local revoked)", &penalty),
            ("to_local delayed sweep", &delayed),
            ("HTLC success", &success),
            ("HTLC timeout", &timeout),
            ("cooperative close", &close),
        ];
        for (name, tx) in rows {
            let base = tx.encode_without_witness().len();
            let wit: usize = tx
                .inputs
                .iter()
                .map(|i| i.witness.pubkey.len() + i.witness.signature.len())
                .sum();
            println!(
                "{name:34} base {base:4} B  witness {wit:6} B  weight {:6}",
                w(tx)
            );
        }

        // The witness of a 2-of-2 spend is two key spends plus the policy and
        // framing: no hidden cost.
        let plain_wit = (SchemeId::MlDsa87.pubkey_len() + SchemeId::MlDsa87.sig_len()) as u64;
        assert_eq!(fund.encode().len(), 2 + 2 * 34);
        let two_of_two = commitment.inputs[0].witness.pubkey.len()
            + commitment.inputs[0].witness.signature.len();
        assert_eq!(two_of_two as u64, 2 * plain_wit + 70 + 2 * 6);
        assert!(w(&close) < 2 * w(&plain) + 200);
    }
}
