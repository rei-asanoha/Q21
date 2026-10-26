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
//! - `After(h)`: the spending block is at height `h` or above;
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
const NODE_AFTER: u8 = 0x06;

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
    /// Absolute time lock: the height of the spending block, from 1 to
    /// `u32::MAX`. Four bytes reach eight thousand years at the target
    /// spacing; eight would only leave room for an encoding nobody can use.
    After(u32),
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
    /// Nothing to reveal: the height is that of the block.
    After,
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
    /// `After(0)`: every block is at height zero or above, so the lock is
    /// another spelling of no lock at all.
    AfterOutOfRange,
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
    /// A time lock of the chosen path, relative or absolute, has not
    /// expired: `available_at` is the first height at which all of them have.
    TooEarly {
        available_at: u64,
        height: u64,
    },
    /// Bytes left in the satisfaction once the chosen path is read.
    ExtraWitnessData(usize),
    /// The leaf named by a lone signature check is not a key leaf.
    NotAKeyLeaf(u8),
    /// A key leaf of a one-time scheme (Lamport): a policy output can be
    /// spent along several paths and its keys signed more than once, which a
    /// one-time key cannot survive.
    OneTimeKey(u8),
    /// A path that some satisfaction can take without any key: once its
    /// preimage is public, or its time lock past, anyone could spend it, and
    /// anyone relaying the spend could redirect it.
    Unsigned,
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
/// mempool. A block at `activation_height - 1` refuses a policy output or
/// spend; a block at `activation_height` accepts it.
pub fn is_active(network: Network, height: u64) -> bool {
    height >= activation_height(network)
}

/// Can a policy output ever be valid on `network`? False on mainnet, where
/// the rule is dormant: there, anything carrying one is treated as 0.4.9
/// treated it, as unreadable.
pub fn may_appear_on(network: Network) -> bool {
    activation_height(network) != u64::MAX
}

/// Height from which the rule is in force; `u64::MAX` means never.
///
/// The compiled-in [`scheduled_activation`], except in an audit build whose
/// tests moved it with [`audit_set_activation_height`]. A release build has
/// no such switch.
pub fn activation_height(network: Network) -> u64 {
    #[cfg(feature = "audit")]
    if let Some(h) = audit_activation::get(network) {
        return h;
    }
    scheduled_activation(network)
}

/// The activation height compiled into this binary for `network`.
pub const fn scheduled_activation(network: Network) -> u64 {
    match network {
        Network::Mainnet => POLICY_ACTIVATION_MAINNET,
        Network::Testnet => POLICY_ACTIVATION_TESTNET,
        Network::Regtest => POLICY_ACTIVATION_REGTEST,
    }
}

/// Does `network` go through a transition, a height before which the rule is
/// closed and after which it is open?
///
/// True on testnet. False on mainnet, where it never opens, and on regtest,
/// where it opens at block 1, the first block that can carry a transaction
/// at all: a regtest chain has the rule from its start, and 0.4.10 already
/// had it there. Only where there is a transition must the peers be told
/// apart: a node that predates it cannot follow the chain past it.
pub fn has_transition(network: Network) -> bool {
    let h = activation_height(network);
    h > 1 && h != u64::MAX
}

/// Has the chain whose tip is at `tip` reached the activation?
///
/// True once the tip is at the activation height or above, and always on a
/// network without a transition where the rule may appear. This is what
/// opens payment channels: a funding broadcast from then on confirms at the
/// activation height or above.
pub fn reached(network: Network, tip: u64) -> bool {
    may_appear_on(network) && (!has_transition(network) || tip >= activation_height(network))
}

/// Where a network stands with respect to the activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationStatus {
    /// `None` on a network where the rule never opens.
    pub activation_height: Option<u64>,
    pub tip: u64,
    /// See [`reached`].
    pub active: bool,
    /// Blocks still to be mined before the tip reaches the activation height;
    /// zero once it has. `None` where the rule never opens.
    pub blocks_remaining: Option<u64>,
}

impl ActivationStatus {
    /// `blocks_remaining` at the target spacing.
    pub fn eta_seconds(&self) -> Option<u64> {
        self.blocks_remaining
            .map(|b| b.saturating_mul(crate::consensus::TARGET_BLOCK_SECS))
    }
}

/// The activation status of `network` at tip `tip`.
pub fn status(network: Network, tip: u64) -> ActivationStatus {
    if !may_appear_on(network) {
        return ActivationStatus {
            activation_height: None,
            tip,
            active: false,
            blocks_remaining: None,
        };
    }
    let h = activation_height(network);
    let active = reached(network, tip);
    ActivationStatus {
        activation_height: Some(h),
        tip,
        active,
        blocks_remaining: Some(if active { 0 } else { h - tip }),
    }
}

/// Moves the activation height of `network` for this process.
///
/// Audit builds only, for the tests and the lab that must cross a real
/// activation height on a network with a transition; never mainnet. Set once per process
/// and network, before anything reads it: setting it again to the same
/// height does nothing, to another height panics, so that two tests of one
/// process can never see two different rules.
#[cfg(feature = "audit")]
pub fn audit_set_activation_height(network: Network, height: u64) {
    audit_activation::set(network, height);
}

#[cfg(feature = "audit")]
mod audit_activation {
    use crate::address::Network;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Zero means not moved: the rule never opens at the genesis, which
    /// holds no transaction.
    static MAINNET: AtomicU64 = AtomicU64::new(0);
    static TESTNET: AtomicU64 = AtomicU64::new(0);
    static REGTEST: AtomicU64 = AtomicU64::new(0);

    fn slot(network: Network) -> &'static AtomicU64 {
        match network {
            Network::Mainnet => &MAINNET,
            Network::Testnet => &TESTNET,
            Network::Regtest => &REGTEST,
        }
    }

    pub fn get(network: Network) -> Option<u64> {
        match slot(network).load(Ordering::SeqCst) {
            0 => None,
            h => Some(h),
        }
    }

    pub fn set(network: Network, height: u64) {
        assert!(height >= 1, "the genesis cannot carry a policy");
        assert!(network != Network::Mainnet, "mainnet never opens the rule");
        match slot(network).compare_exchange(0, height, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {}
            Err(h) if h == height => {}
            Err(h) => panic!("{network:?} activation already moved to {h}, not {height}"),
        }
    }
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
            Policy::After(h) => {
                w.u8(NODE_AFTER).u32(*h);
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
        if !p.always_signed() {
            return Err(PolicyError::Unsigned);
        }
        Ok(p)
    }

    /// Does every way of satisfying this policy require a signature? An
    /// `All` needs one of its children to; an `Any`, every child.
    pub fn always_signed(&self) -> bool {
        match self {
            Policy::Key { .. } => true,
            Policy::Preimage(_) | Policy::Older(_) | Policy::After(_) => false,
            Policy::All(c) => c.iter().any(Policy::always_signed),
            Policy::Any(c) => c.iter().all(Policy::always_signed),
        }
    }

    /// The `Any` choices leading to leaf `leaf`, in the order a satisfaction
    /// states them: what a signer passes to [`sighash`] when every `Any` of
    /// the policy lies on the path to its leaf, as in all the channel shapes.
    /// Otherwise the signer takes them from the satisfaction it will use
    /// ([`Satisfaction::choices`]).
    pub fn choices_to(&self, leaf: u8) -> Vec<u8> {
        fn go(p: &Policy, leaf: u8, pos: &mut u8, out: &mut Vec<u8>) -> bool {
            match p {
                Policy::All(c) => c.iter().any(|c| go(c, leaf, pos, out)),
                Policy::Any(c) => {
                    for (i, child) in c.iter().enumerate() {
                        out.push(i as u8);
                        if go(child, leaf, pos, out) {
                            return true;
                        }
                        out.pop();
                    }
                    false
                }
                _ => {
                    *pos += 1;
                    *pos - 1 == leaf
                }
            }
        }
        let mut out = Vec::new();
        go(self, leaf, &mut 0, &mut out);
        out
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
                if scheme.is_one_time() {
                    return Err(PolicyError::OneTimeKey(raw));
                }
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
            NODE_AFTER => {
                let h = r.u32()?;
                if h == 0 {
                    return Err(PolicyError::AfterOutOfRange);
                }
                leaf()?;
                Ok(Policy::After(h))
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
    /// Every `Any` choice of this satisfaction, in the order it states them:
    /// what each key signs along with its leaf ([`sighash`]).
    pub fn choices(&self) -> Vec<u8> {
        fn go(s: &Satisfaction, out: &mut Vec<u8>) {
            match s {
                Satisfaction::All(c) => c.iter().for_each(|c| go(c, out)),
                Satisfaction::Any { index, branch } => {
                    out.push(*index);
                    go(branch, out);
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        go(self, &mut out);
        out
    }

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
            Satisfaction::Older | Satisfaction::After => {}
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

/// The message the key at leaf `leaf` signs, for a satisfaction making the
/// `Any` choices `choices`. See [`Transaction::policy_sighash`].
pub fn sighash(
    tx: &Transaction,
    input_index: u32,
    network: Network,
    spent: &TxOut,
    policy: &Policy,
    leaf: u8,
    choices: &[u8],
) -> Hash256 {
    tx.policy_sighash(input_index, network, spent, &policy.encode(), leaf, choices)
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
    /// Largest `After` on the chosen path; zero when there is none.
    min_height: u64,
    /// Every `Any` choice, in the order the satisfaction states them.
    choices: Vec<u8>,
}

impl Path<'_> {
    /// First block height at which every time lock of the path is met, for
    /// an output created at `born`. Zero when the path has none.
    fn available_at(&self, born: u64) -> u64 {
        let relative = if self.min_age > 0 {
            born.saturating_add(self.min_age)
        } else {
            0
        };
        relative.max(self.min_height)
    }
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
        Policy::After(h) => {
            path.min_height = path.min_height.max(u64::from(*h));
            *leaf += 1;
        }
        Policy::All(children) => {
            for c in children {
                walk(c, r, leaf, path)?;
            }
        }
        Policy::Any(children) => {
            let index = r.u8()?;
            path.choices.push(index);
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
        min_height: 0,
        choices: Vec::new(),
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
/// refuses it.
///
/// # Absolute time lock
///
/// `After(h)` holds when `height >= h`, `height` being that of the block that
/// includes the spend. The transaction's own `lock_time` plays no part: it
/// stays unenforced, as it always was.
///
/// The mempool passes the height of the next block for both, as for
/// coinbase maturity, and rechecks them after a reorganization
/// ([`available_at`]).
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
    let path = precheck(network, spent, height, witness)?;

    // The stripped transaction is the bulk of every message: encoded once
    // for all the keys of this input, not once per key.
    let stripped = tx.encode_without_witness();
    for k in &path.keys {
        let message = crate::tx::policy_sighash_of_stripped(
            &stripped,
            input_index,
            network,
            &spent.output,
            &witness.pubkey,
            k.leaf,
            &path.choices,
        );
        sig::verify(k.scheme, k.pubkey, &message, k.signature)
            .map_err(ValidationError::Signature)?;
    }
    Ok(())
}

/// Everything [`check_spend`] checks short of the signatures: lock,
/// decoding, branches, preimages, time locks, schemes, key hashes. A
/// validator runs it on every policy input before verifying any signature,
/// so that a transaction whose last input is malformed costs nothing.
pub fn precheck_spend(
    network: Network,
    spent: &UtxoEntry,
    height: u64,
    witness: &Witness,
) -> Result<(), ValidationError> {
    precheck(network, spent, height, witness).map(|_| ())
}

fn precheck<'a>(
    network: Network,
    spent: &UtxoEntry,
    height: u64,
    witness: &'a Witness,
) -> Result<Path<'a>, ValidationError> {
    let (_, path) = read_spend(&spent.output, witness).map_err(ValidationError::Policy)?;

    let available_at = path.available_at(spent.height);
    if height < available_at {
        return Err(ValidationError::Policy(PolicyError::TooEarly {
            available_at,
            height,
        }));
    }

    for k in &path.keys {
        if !k.scheme.allowed_on(network) {
            return Err(ValidationError::SchemeForbiddenOnNetwork(k.scheme));
        }
        if sig::pubkey_hash(k.scheme, k.pubkey) != k.hash {
            return Err(ValidationError::KeyDoesNotMatchLock);
        }
    }
    Ok(path)
}

/// Checks ONE key's signature, for leaf `leaf` of `policy`, on input
/// `input_index` of `tx` spending `spent`.
///
/// This is what a channel party needs when the counterparty sends its half of
/// a 2-of-2 spend: the same lock, decoding, key, size and message checks as
/// [`check_spend`], applied to one key, so that it need not sign its own half
/// just to run the full validation. It says nothing about the other keys, the
/// preimages or the time locks of the spend.
#[allow(clippy::too_many_arguments)]
pub fn check_signature(
    tx: &Transaction,
    input_index: u32,
    network: Network,
    spent: &TxOut,
    policy: &[u8],
    leaf: u8,
    choices: &[u8],
    pubkey: &[u8],
    signature: &[u8],
) -> Result<(), ValidationError> {
    // No height here: refused on any network where the rule never opens.
    if spent.scheme != SchemeId::Policy || activation_height(network) == u64::MAX {
        return Err(ValidationError::SchemeForbiddenOnNetwork(spent.scheme));
    }
    let p = ValidationError::Policy;
    if policy.len() > MAX_POLICY_SIZE {
        return Err(p(PolicyError::TooLarge { size: policy.len() }));
    }
    if lock_hash_of(policy) != spent.pubkey_hash {
        return Err(p(PolicyError::DoesNotMatchLock));
    }
    let decoded = Policy::decode(policy).map_err(p)?;
    let (_, scheme, hash) = decoded
        .key_leaves()
        .into_iter()
        .find(|(pos, _, _)| *pos == leaf)
        .ok_or(p(PolicyError::NotAKeyLeaf(leaf)))?;
    if !scheme.allowed_on(network) {
        return Err(ValidationError::SchemeForbiddenOnNetwork(scheme));
    }
    sig::check_sizes(scheme, pubkey, signature).map_err(|e| p(PolicyError::WitnessSize(e)))?;
    if sig::pubkey_hash(scheme, pubkey) != hash {
        return Err(ValidationError::KeyDoesNotMatchLock);
    }
    if choices.len() > MAX_POLICY_LEAVES {
        return Err(p(PolicyError::TooManyLeaves));
    }
    let message = tx.policy_sighash(input_index, network, spent, policy, leaf, choices);
    sig::verify(scheme, pubkey, &message, signature).map_err(ValidationError::Signature)
}

/// The relative time lock (`Older`) the chosen path of a policy spend
/// requires, in blocks; zero for anything else.
///
/// The mempool refuses a spend that needs one while the spent output is
/// itself unconfirmed: its age is zero until the parent is in a block, and
/// the block that would carry both would be invalid.
pub fn relative_lock(spent: &TxOut, witness: &Witness) -> u64 {
    if spent.scheme != SchemeId::Policy {
        return 0;
    }
    read_spend(spent, witness).map_or(0, |(_, path)| path.min_age)
}

/// How many signature verifications this witness can make a validator do:
/// the keys on the path a policy satisfaction names, one for anything else.
///
/// Read from the witness alone, without the spent output, for the relay
/// budget, which is charged before any lookup. A witness that is not a
/// readable policy spend costs one, as a plain spend does: if it does lock a
/// policy output, it fails before any verification.
pub fn verifications_claimed(witness: &Witness) -> u64 {
    if witness.pubkey.len() > MAX_POLICY_SIZE {
        return 1;
    }
    let Ok(policy) = Policy::decode(&witness.pubkey) else {
        return 1;
    };
    let mut r = Reader::new(&witness.signature);
    let mut path = Path {
        keys: Vec::new(),
        min_age: 0,
        min_height: 0,
        choices: Vec::new(),
    };
    if walk(&policy, &mut r, &mut 0, &mut path).is_err() {
        return 1;
    }
    (path.keys.len() as u64).max(1)
}

/// First block height at which the time locks of an already validated
/// policy spend are all met; zero for anything else.
///
/// The mempool needs it after a reorganization: the signatures still hold,
/// but a lower tip, or a parent moved to a later block or back into the
/// pool, can put a time lock back in the future.
pub fn available_at(spent: &UtxoEntry, witness: &Witness) -> u64 {
    if spent.output.scheme != SchemeId::Policy {
        return 0;
    }
    read_spend(&spent.output, witness).map_or(0, |(_, path)| path.available_at(spent.height))
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
    fn absolute_time_lock_encoding() {
        let p = Policy::Any(vec![
            Policy::All(vec![key_leaf(2), Policy::Preimage(h(9))]),
            Policy::All(vec![key_leaf(1), Policy::After(u32::MAX)]),
        ]);
        let b = p.encode();
        assert_eq!(Policy::decode(&b), Ok(p.clone()));
        assert_eq!(
            Policy::After(0x0102_0304).encode(),
            [NODE_AFTER, 4, 3, 2, 1]
        );
        // Zero locks nothing: refused, like Older(0).
        assert_eq!(
            Policy::decode(&[NODE_AFTER, 0, 0, 0, 0]),
            Err(PolicyError::AfterOutOfRange)
        );
        assert_eq!(
            Policy::decode(&[NODE_AFTER, 1, 0, 0]),
            Err(PolicyError::Malformed(ReadError::UnexpectedEnd))
        );
        // It counts as a leaf, and takes no witness byte.
        assert_eq!(p.leaf_count(), 4);
        assert!(Satisfaction::After.encode().is_empty());
    }

    /// Lamport keys are one-time: never in a policy, whose keys can sign
    /// along several paths.
    #[test]
    fn one_time_keys_are_refused_in_policies() {
        let lamport = Policy::All(vec![
            Policy::Key {
                scheme: SchemeId::LamportOts,
                pubkey_hash: h(1),
            },
            key_leaf(2),
        ]);
        assert_eq!(
            Policy::decode(&lamport.encode()),
            Err(PolicyError::OneTimeKey(SchemeId::LamportOts.as_u8()))
        );
    }

    /// Every way through a policy needs a key: a path of preimages and time
    /// locks alone is anyone's once the secret is out or the lock past.
    #[test]
    fn keyless_paths_are_refused() {
        for p in [
            Policy::Preimage(h(9)),
            Policy::Any(vec![key_leaf(1), Policy::Preimage(h(9))]),
            Policy::All(vec![Policy::Preimage(h(9)), Policy::Older(5)]),
            Policy::Any(vec![
                Policy::All(vec![key_leaf(2), Policy::Preimage(h(9))]),
                Policy::After(100),
            ]),
        ] {
            assert_eq!(
                Policy::decode(&p.encode()),
                Err(PolicyError::Unsigned),
                "{p:?}"
            );
        }
        assert!(htlc().always_signed());
        assert!(Policy::All(vec![key_leaf(1), Policy::Older(5)]).always_signed());
    }

    /// The `Any` choices a signer of each leaf commits to.
    #[test]
    fn choices_to_a_leaf() {
        assert_eq!(htlc().choices_to(0), vec![0]);
        assert_eq!(htlc().choices_to(2), vec![1]);
        assert!(Policy::All(vec![key_leaf(1), key_leaf(2)])
            .choices_to(1)
            .is_empty());
        let s = Satisfaction::All(vec![
            Satisfaction::Older,
            Satisfaction::Any {
                index: 1,
                branch: Box::new(Satisfaction::Any {
                    index: 0,
                    branch: Box::new(Satisfaction::After),
                }),
            },
        ]);
        assert_eq!(s.choices(), vec![1, 0]);
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
        assert_eq!(Policy::decode(&[0x07]), Err(PolicyError::UnknownNode(7)));
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
        let mut ok = Policy::All(vec![key_leaf(1), Policy::Older(2)]);
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
    fn activation_is_never_on_mainnet_and_at_its_height_elsewhere() {
        assert!(!is_active(Network::Mainnet, u64::MAX - 1));
        assert!(!is_active(Network::Testnet, POLICY_ACTIVATION_TESTNET - 1));
        assert!(is_active(Network::Testnet, POLICY_ACTIVATION_TESTNET));
        assert!(!is_active(Network::Regtest, 0));
        assert!(is_active(Network::Regtest, 1));
        assert!(!scheme_allowed(SchemeId::Policy, Network::Testnet, 1_000));
        assert!(scheme_allowed(
            SchemeId::Policy,
            Network::Testnet,
            POLICY_ACTIVATION_TESTNET
        ));
        assert!(!scheme_allowed(
            SchemeId::Policy,
            Network::Mainnet,
            u64::MAX - 1
        ));
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
            signature: k.sign(&sighash(
                tx,
                0,
                NET,
                &e.output,
                p,
                leaf,
                &p.choices_to(leaf),
            )),
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
        assert_eq!(available_at(&e, &tx.inputs[0].witness), BORN + 5);
    }

    /// `After(h)`: valid in the block at height `h`, not before, whatever the
    /// age of the output. With `Older` on the same path, the later of the two
    /// decides.
    #[test]
    fn after_leaf() {
        let a = Key::new(1);
        let p = Policy::All(vec![a.leaf(), Policy::After(BORN as u32 + 20)]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let s = Satisfaction::All(vec![sign_leaf(&tx, &e, &p, 0, &a), Satisfaction::After]);
        tx.inputs[0].witness = witness(&p, &s);
        assert_eq!(
            check(&u, &tx, NET, BORN + 19),
            pol(PolicyError::TooEarly {
                available_at: BORN + 20,
                height: BORN + 19
            })
        );
        assert!(check(&u, &tx, NET, BORN + 20).is_ok());
        // The transaction's own lock_time is not what is checked.
        let mut late = tx.clone();
        late.lock_time = u64::MAX;
        let s = Satisfaction::All(vec![sign_leaf(&late, &e, &p, 0, &a), Satisfaction::After]);
        late.inputs[0].witness = witness(&p, &s);
        assert!(check(&u, &late, NET, BORN + 20).is_ok());

        let both = Policy::All(vec![
            a.leaf(),
            Policy::Older(5),
            Policy::After(BORN as u32 + 3),
        ]);
        let (u, op, e) = fixture(&both);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let s = Satisfaction::All(vec![
            sign_leaf(&tx, &e, &both, 0, &a),
            Satisfaction::Older,
            Satisfaction::After,
        ]);
        tx.inputs[0].witness = witness(&both, &s);
        assert_eq!(available_at(&e, &tx.inputs[0].witness), BORN + 5);
        assert!(check(&u, &tx, NET, BORN + 4).is_err());
        assert!(check(&u, &tx, NET, BORN + 5).is_ok());
    }

    /// One counterparty signature, checked alone: accepted for its leaf,
    /// refused for another leaf, another policy, another transaction.
    #[test]
    fn lone_signature_check() {
        let (a, b) = (Key::new(1), Key::new(2));
        let p = Policy::All(vec![a.leaf(), b.leaf()]);
        let (_, op, e) = fixture(&p);
        let tx = spend(op, vec![b.output(VALUE - 20_000)]);
        let pb = p.encode();
        let sig_b = b.sign(&sighash(&tx, 0, NET, &e.output, &p, 1, &[]));
        let lone = |tx: &Transaction, out: &TxOut, pol: &[u8], leaf: u8, sig: &[u8]| {
            check_signature(tx, 0, NET, out, pol, leaf, &[], &b.pk, sig)
        };
        assert_eq!(lone(&tx, &e.output, &pb, 1, &sig_b), Ok(()));
        // Another leaf: A's slot (key mismatch), or a leaf that is no key.
        assert_eq!(
            lone(&tx, &e.output, &pb, 0, &sig_b),
            Err(ValidationError::KeyDoesNotMatchLock)
        );
        assert_eq!(
            lone(&tx, &e.output, &pb, 5, &sig_b),
            Err(ValidationError::Policy(PolicyError::NotAKeyLeaf(5)))
        );
        // Another transaction.
        let other = spend(op, vec![b.output(VALUE - 30_000)]);
        assert_eq!(
            lone(&other, &e.output, &pb, 1, &sig_b),
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        );
        // Another policy with B at the same leaf: the signature does not
        // carry over, and a policy that is not the lock is refused.
        let p2 = Policy::Any(vec![a.leaf(), b.leaf()]);
        let out2 = p2.output(Amount::from_units(VALUE));
        assert_eq!(
            lone(&tx, &out2, &p2.encode(), 1, &sig_b),
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        );
        assert_eq!(
            lone(&tx, &e.output, &p2.encode(), 1, &sig_b),
            Err(ValidationError::Policy(PolicyError::DoesNotMatchLock))
        );
        // Not a policy output at all, or on a network where the rule never
        // opens.
        assert!(lone(&tx, &b.output(VALUE), &pb, 1, &sig_b).is_err());
        assert_eq!(
            check_signature(
                &tx,
                0,
                Network::Mainnet,
                &e.output,
                &pb,
                1,
                &[],
                &b.pk,
                &sig_b
            ),
            Err(ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy))
        );
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
        let p = Policy::Any(vec![
            a.leaf(),
            Policy::All(vec![a.leaf(), Policy::Preimage(hash)]),
        ]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let branch = Satisfaction::All(vec![
            sign_leaf(&tx, &e, &p, 1, &a),
            Satisfaction::Preimage(secret),
        ]);

        let good = witness(&p, &any(1, branch.clone()));
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
        tx.inputs[0].witness = witness(&p, &any(2, branch));
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
        let p = Policy::All(vec![a.leaf(), Policy::Preimage(hash)]);

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
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let s = Satisfaction::All(vec![
            sign_leaf(&tx, &e, &p, 0, &a),
            Satisfaction::Preimage(secret),
        ]);
        tx.inputs[0].witness = witness(&p, &s);
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

    // --- Through blocks ------------------------------------------------

    /// A policy output funded and spent on a real regtest chain: the time
    /// lock counts blocks from the one that created the output, so a spend in
    /// that same block, or too soon after it, makes the block invalid.
    #[test]
    fn time_lock_through_blocks() {
        use crate::chain::{genesis_block, Chain};
        use crate::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
        use crate::utxo::UtxoView;

        let a = Key::new(1);
        let mut c = Chain::new(NET, genesis_block(NET));
        let candidate = |c: &Chain, txs: &[Transaction]| {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash(), SchemeId::MlDsa87, txs, t, 5_000_000)
                .expect("mining");
            (b, t + 1)
        };
        let (first, now) = candidate(&c, &[]);
        c.connect(&first, now).expect("block 1");
        for _ in 0..COINBASE_MATURITY {
            let (b, now) = candidate(&c, &[]);
            c.connect(&b, now).expect("maturing");
        }

        let coin = OutPoint {
            txid: first.transactions[0].txid(),
            index: 0,
        };
        let coin_entry = c.utxo.lookup(&coin).expect("mature coinbase");
        let p = Policy::All(vec![a.leaf(), Policy::Older(2)]);
        let funded = coin_entry.output.value.units() - 20_000;
        let mut funding = spend(coin, vec![p.output(Amount::from_units(funded))]);
        let m = funding.sighash(0, NET, &coin_entry.output);
        funding.inputs[0].witness = Witness {
            pubkey: a.pk.clone(),
            signature: a.sign(&m),
        };
        let locked = OutPoint {
            txid: funding.txid(),
            index: 0,
        };
        let spend_tx = |born: u64| {
            let e = UtxoEntry {
                output: p.output(Amount::from_units(funded)),
                height: born,
                is_coinbase: false,
            };
            let mut tx = spend(locked, vec![a.output(funded - 20_000)]);
            let s = Satisfaction::All(vec![sign_leaf(&tx, &e, &p, 0, &a), Satisfaction::Older]);
            tx.inputs[0].witness = witness(&p, &s);
            tx
        };
        let child = spend_tx(0);

        // Funding and spend in the same block: age zero.
        let (b, now) = candidate(&c, &[funding.clone(), child.clone()]);
        assert!(matches!(
            c.connect(&b, now),
            Err(ValidationError::Policy(PolicyError::TooEarly { .. }))
        ));

        // Funding alone, then the spend one block later: age one, still early.
        let (b, now) = candidate(&c, &[funding]);
        c.connect(&b, now).expect("funding");
        let born = c.height();
        let (b, now) = candidate(&c, std::slice::from_ref(&child));
        assert_eq!(
            c.connect(&b, now),
            Err(ValidationError::Policy(PolicyError::TooEarly {
                available_at: born + 2,
                height: born + 1
            }))
        );

        // Two blocks after the funding: accepted.
        let (b, now) = candidate(&c, &[]);
        c.connect(&b, now).expect("empty block");
        let (b, now) = candidate(&c, &[child]);
        c.connect(&b, now).expect("spend after the delay");
        assert!(c.utxo.lookup(&locked).is_none());
    }

    // --- A channel's life, through blocks -------------------------------

    use crate::block::Block;
    use crate::chain::{genesis_block, Chain};
    use crate::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
    use crate::mempool::{Mempool, MempoolError};
    use crate::utxo::UtxoView;
    use std::slice::from_ref;

    /// Fee of every channel transaction: far above the relay floor.
    const FEE: u64 = 2_000;
    /// The to_self delay of the commitments, in blocks.
    const D: u16 = 5;

    /// A regtest chain whose blocks all pay one miner, mined far enough that
    /// sizeable coinbases are mature: the slow start makes the first rewards
    /// too small to split between channel outputs.
    struct Regtest {
        c: Chain,
        miner: Hash256,
        /// Every connected block, from height 1.
        blocks: Vec<Block>,
    }

    impl Regtest {
        fn new(miner: &Key) -> Regtest {
            let mut r = Regtest {
                c: Chain::new(NET, genesis_block(NET)),
                miner: miner.hash(),
                blocks: Vec::new(),
            };
            r.mine_to(COINBASE_MATURITY + 210);
            r
        }

        fn height(&self) -> u64 {
            self.c.height()
        }

        fn candidate(&self, txs: &[Transaction]) -> (Block, u64) {
            let t = self.c.tip().time + TARGET_BLOCK_SECS;
            let b = self
                .c
                .mine_block(self.miner, SchemeId::MlDsa87, txs, t, 5_000_000)
                .expect("mining");
            (b, t + 1)
        }

        /// Mines `txs` into the next block; the chain refuses it or extends.
        fn mine(&mut self, txs: &[Transaction]) -> Result<(), ValidationError> {
            let (b, now) = self.candidate(txs);
            self.c.connect(&b, now)?;
            self.blocks.push(b);
            Ok(())
        }

        fn mine_to(&mut self, height: u64) {
            while self.height() < height {
                self.mine(&[]).expect("empty block");
            }
        }

        /// The miner's coinbase output of block `h`.
        fn coin(&self, h: u64) -> (OutPoint, TxOut) {
            let cb = &self.blocks[h as usize - 1].transactions[0];
            let op = OutPoint {
                txid: cb.txid(),
                index: 0,
            };
            (op, cb.outputs[0])
        }

        fn unspent(&self, op: &OutPoint) -> bool {
            self.c.utxo.lookup(op).is_some()
        }
    }

    fn out(tx: &Transaction, index: u32) -> (OutPoint, TxOut) {
        let op = OutPoint {
            txid: tx.txid(),
            index,
        };
        (op, tx.outputs[index as usize])
    }

    fn units(v: u64) -> Amount {
        Amount::from_units(v)
    }

    fn sign_out(tx: &Transaction, spent: &TxOut, p: &Policy, leaf: u8, k: &Key) -> Satisfaction {
        Satisfaction::Key {
            pubkey: k.pk.clone(),
            signature: k.sign(&sighash(tx, 0, NET, spent, p, leaf, &p.choices_to(leaf))),
        }
    }

    /// Spends a key output of `k`'s.
    fn plain_spend(op: OutPoint, spent: &TxOut, k: &Key, outputs: Vec<TxOut>) -> Transaction {
        let mut tx = spend(op, outputs);
        let m = tx.sighash(0, NET, spent);
        tx.inputs[0].witness = Witness {
            pubkey: k.pk.clone(),
            signature: k.sign(&m),
        };
        tx
    }

    /// Spends a 2-of-2 output with both signatures.
    fn both_sign(
        op: OutPoint,
        spent: &TxOut,
        p: &Policy,
        (a, b): (&Key, &Key),
        outputs: Vec<TxOut>,
    ) -> Transaction {
        let mut tx = spend(op, outputs);
        let s = Satisfaction::All(vec![
            sign_out(&tx, spent, p, 0, a),
            sign_out(&tx, spent, p, 1, b),
        ]);
        tx.inputs[0].witness = witness(p, &s);
        tx
    }

    /// `Any[ All[Key first, Preimage(hash)], All[Key second, lock] ]`: the
    /// shape of to_local (lock `Older`) and of an offered HTLC (lock `After`).
    fn secret_or_lock(first: &Key, hash: Hash256, second: &Key, lock: Policy) -> Policy {
        Policy::Any(vec![
            Policy::All(vec![first.leaf(), Policy::Preimage(hash)]),
            Policy::All(vec![second.leaf(), lock]),
        ])
    }

    /// The first branch: `k` signs at leaf 0 and reveals the secret.
    fn by_secret(
        op: OutPoint,
        spent: &TxOut,
        p: &Policy,
        k: &Key,
        secret: [u8; 32],
        to: &Key,
    ) -> Transaction {
        let mut tx = spend(op, vec![to.output(spent.value.units() - FEE)]);
        let s = any(
            0,
            Satisfaction::All(vec![
                sign_out(&tx, spent, p, 0, k),
                Satisfaction::Preimage(secret),
            ]),
        );
        tx.inputs[0].witness = witness(p, &s);
        tx
    }

    /// The second branch: `k` signs at leaf 2, once the lock allows.
    fn by_lock(
        op: OutPoint,
        spent: &TxOut,
        p: &Policy,
        k: &Key,
        lock: Satisfaction,
    ) -> Transaction {
        let mut tx = spend(op, vec![k.output(spent.value.units() - FEE)]);
        let s = any(
            1,
            Satisfaction::All(vec![sign_out(&tx, spent, p, 2, k), lock]),
        );
        tx.inputs[0].witness = witness(p, &s);
        tx
    }

    /// Pays the coinbase of block `h` to `outputs`, in a block of its own.
    fn fund(r: &mut Regtest, a: &Key, h: u64, outputs: impl Fn(u64) -> Vec<TxOut>) -> Transaction {
        let (coin, coin_out) = r.coin(h);
        let tx = plain_spend(coin, &coin_out, a, outputs(coin_out.value.units() - FEE));
        r.mine(from_ref(&tx)).expect("funding");
        tx
    }

    fn too_early(r: Result<(), ValidationError>) -> bool {
        matches!(
            r,
            Err(ValidationError::Policy(PolicyError::TooEarly { .. }))
        )
    }

    /// A opens a channel with B, moves to state 2 and revokes state 1 by
    /// handing its secret to B — then broadcasts state 1 anyway. B takes the
    /// whole to_local output at once; A's delayed sweep is refused before
    /// the delay, would have been valid at it, and finds nothing left.
    #[test]
    fn lifecycle_revoked_commitment_is_punished() {
        let (a, b) = (Key::new(1), Key::new(2));
        let mut r = Regtest::new(&a);
        let fund_p = Policy::All(vec![a.leaf(), b.leaf()]);
        let funding = fund(&mut r, &a, 200, |v| vec![fund_p.output(units(v))]);
        let (fop, fout) = out(&funding, 0);
        let v = fout.value.units();

        // A's commitments for states 1 and 2, signed by both, kept off-chain.
        let (r1, rh1) = preimage(11);
        let (_, rh2) = preimage(12);
        let local1 = secret_or_lock(&b, rh1, &a, Policy::Older(D));
        let state1 = both_sign(
            fop,
            &fout,
            &fund_p,
            (&a, &b),
            vec![local1.output(units(v / 2)), b.output(v - v / 2 - FEE)],
        );
        let local2 = secret_or_lock(&b, rh2, &a, Policy::Older(D));
        let state2 = both_sign(
            fop,
            &fout,
            &fund_p,
            (&a, &b),
            vec![local2.output(units(v / 4)), b.output(v - v / 4 - FEE)],
        );
        // Moving to state 2, A revokes state 1: B now holds r1.
        let revoked_secret_held_by_b = r1;

        // A cheats: the revoked commitment is still a valid transaction.
        r.mine(from_ref(&state1)).expect("revoked commitment");
        let hc = r.height();
        let (lop, lout) = out(&state1, 0);

        // A's delayed sweep: too early in the next block...
        let sweep = by_lock(lop, &lout, &local1, &a, Satisfaction::Older);
        assert_eq!(
            r.mine(from_ref(&sweep)),
            Err(ValidationError::Policy(PolicyError::TooEarly {
                available_at: hc + u64::from(D),
                height: hc + 1
            }))
        );
        // ...valid at the delay, had B not acted.
        assert!(check(&r.c.utxo, &sweep, NET, hc + u64::from(D)).is_ok());

        // B's penalty with the revocation secret: accepted at once.
        let penalty = by_secret(lop, &lout, &local1, &b, revoked_secret_held_by_b, &b);
        r.mine(from_ref(&penalty)).expect("penalty");
        assert_eq!(r.height(), hc + 1);
        assert!(!r.unspent(&lop));
        // B's to_remote output of state 1 is B's as well, at once.
        let (rop, rout) = out(&state1, 1);
        r.mine(from_ref(&plain_spend(
            rop,
            &rout,
            &b,
            vec![b.output(rout.value.units() - FEE)],
        )))
        .expect("to_remote");

        // At the delay, A's sweep spends nothing any more, and state 2 has
        // lost its funding output.
        r.mine_to(hc + u64::from(D) - 1);
        assert!(matches!(
            r.mine(from_ref(&sweep)),
            Err(ValidationError::MissingInput(_))
        ));
        assert!(matches!(
            r.mine(from_ref(&state2)),
            Err(ValidationError::MissingInput(_))
        ));
    }

    /// The honest unilateral close: A broadcasts the latest state and sweeps
    /// to_local in the block exactly `D` after the commitment's.
    #[test]
    fn lifecycle_unilateral_close_waits_exactly_the_delay() {
        let (a, b) = (Key::new(1), Key::new(2));
        let mut r = Regtest::new(&a);
        let fund_p = Policy::All(vec![a.leaf(), b.leaf()]);
        let funding = fund(&mut r, &a, 201, |v| vec![fund_p.output(units(v))]);
        let (fop, fout) = out(&funding, 0);
        let v = fout.value.units();
        let (_, rh2) = preimage(12);
        let local2 = secret_or_lock(&b, rh2, &a, Policy::Older(D));
        let state2 = both_sign(
            fop,
            &fout,
            &fund_p,
            (&a, &b),
            vec![local2.output(units(v / 4)), b.output(v - v / 4 - FEE)],
        );

        r.mine(from_ref(&state2)).expect("latest commitment");
        let hc = r.height();
        let (lop, lout) = out(&state2, 0);
        let sweep = by_lock(lop, &lout, &local2, &a, Satisfaction::Older);

        r.mine_to(hc + u64::from(D) - 2);
        assert!(
            too_early(r.mine(from_ref(&sweep))),
            "one block before the delay"
        );
        r.mine_to(hc + u64::from(D) - 1);
        r.mine(from_ref(&sweep)).expect("at the delay");
        assert_eq!(r.height(), hc + u64::from(D));
        assert!(!r.unspent(&lop));
    }

    /// An HTLC offered by A to B, with an absolute timeout: B claims one with
    /// the payment preimage; A takes another back at the deadline, not one
    /// block before.
    #[test]
    fn lifecycle_htlc_success_and_absolute_timeout() {
        let (a, b) = (Key::new(1), Key::new(2));
        let mut r = Regtest::new(&a);
        let fund_p = Policy::All(vec![a.leaf(), b.leaf()]);
        let funding = fund(&mut r, &a, 202, |v| vec![fund_p.output(units(v))]);
        let (fop, fout) = out(&funding, 0);
        let v = fout.value.units();

        let deadline = r.height() + 10;
        let after = Policy::After(deadline as u32);
        let (_, rh) = preimage(13);
        let (pay1, ph1) = preimage(21);
        let (_, ph2) = preimage(22);
        let local = secret_or_lock(&b, rh, &a, Policy::Older(D));
        let htlc1 = secret_or_lock(&b, ph1, &a, after.clone());
        let htlc2 = secret_or_lock(&b, ph2, &a, after);
        let htlc_value = 100_000;
        let commitment = both_sign(
            fop,
            &fout,
            &fund_p,
            (&a, &b),
            vec![
                local.output(units(v / 2)),
                b.output(v - v / 2 - 2 * htlc_value - FEE),
                htlc1.output(units(htlc_value)),
                htlc2.output(units(htlc_value)),
            ],
        );
        r.mine(from_ref(&commitment))
            .expect("commitment with two HTLCs");

        // Success: B, with the preimage, long before the deadline.
        let (h1op, h1out) = out(&commitment, 2);
        let success = by_secret(h1op, &h1out, &htlc1, &b, pay1, &b);
        r.mine(from_ref(&success)).expect("HTLC success");
        assert!(!r.unspent(&h1op));

        // Timeout: A, at the deadline and not one block before.
        let (h2op, h2out) = out(&commitment, 3);
        let timeout = by_lock(h2op, &h2out, &htlc2, &a, Satisfaction::After);
        r.mine_to(deadline - 2);
        assert_eq!(
            r.mine(from_ref(&timeout)),
            Err(ValidationError::Policy(PolicyError::TooEarly {
                available_at: deadline,
                height: deadline - 1
            }))
        );
        r.mine_to(deadline - 1);
        r.mine(from_ref(&timeout))
            .expect("HTLC timeout at the deadline");
        assert!(!r.unspent(&h2op));
    }

    /// The cooperative close: one transaction from the funding output to two
    /// plain outputs, both signatures, no delay. One party alone cannot.
    #[test]
    fn lifecycle_cooperative_close() {
        let (a, b) = (Key::new(1), Key::new(2));
        let mut r = Regtest::new(&a);
        let fund_p = Policy::All(vec![a.leaf(), b.leaf()]);
        let funding = fund(&mut r, &a, 203, |v| vec![fund_p.output(units(v))]);
        let (fop, fout) = out(&funding, 0);
        let v = fout.value.units();
        let outputs = vec![a.output(v / 3), b.output(v - v / 3 - FEE)];

        // A alone, signing both slots.
        let mut alone = spend(fop, outputs.clone());
        let s = Satisfaction::All(vec![
            sign_out(&alone, &fout, &fund_p, 0, &a),
            sign_out(&alone, &fout, &fund_p, 1, &a),
        ]);
        alone.inputs[0].witness = witness(&fund_p, &s);
        assert_eq!(
            r.mine(from_ref(&alone)),
            Err(ValidationError::KeyDoesNotMatchLock)
        );

        let close = both_sign(fop, &fout, &fund_p, (&a, &b), outputs);
        r.mine(from_ref(&close)).expect("cooperative close");
        assert!(!r.unspent(&fop));
    }

    // --- The mempool ---------------------------------------------------

    /// A pool takes a time-locked spend only once the next block can hold it.
    #[test]
    fn mempool_waits_for_time_locks() {
        let a = Key::new(1);
        let mut r = Regtest::new(&a);
        let hf = r.height() + 1;
        let relative = Policy::All(vec![a.leaf(), Policy::Older(2)]);
        let absolute = Policy::All(vec![a.leaf(), Policy::After(hf as u32 + 3)]);
        let funding = fund(&mut r, &a, 204, |v| {
            vec![
                relative.output(units(v / 2)),
                absolute.output(units(v - v / 2)),
            ]
        });
        assert_eq!(r.height(), hf);

        let lock_spend = |index: u32, p: &Policy, lock: Satisfaction| {
            let (op, o) = out(&funding, index);
            let mut tx = spend(op, vec![a.output(o.value.units() - FEE)]);
            let s = Satisfaction::All(vec![sign_out(&tx, &o, p, 0, &a), lock]);
            tx.inputs[0].witness = witness(p, &s);
            tx
        };
        let s_rel = lock_spend(0, &relative, Satisfaction::Older);
        let s_abs = lock_spend(1, &absolute, Satisfaction::After);
        let refused = |r: Result<Hash256, MempoolError>| {
            matches!(
                r,
                Err(MempoolError::Validation(ValidationError::Policy(
                    PolicyError::TooEarly { .. }
                )))
            )
        };

        let mut m = Mempool::new();
        // Tip hf: the next block, hf + 1, is too early for both.
        assert!(refused(m.accept(&s_rel, &r.c.utxo, NET, r.height())));
        assert!(refused(m.accept(&s_abs, &r.c.utxo, NET, r.height())));
        // Tip hf + 1: Older(2) is met in hf + 2; After(hf + 3) is not.
        r.mine(&[]).unwrap();
        assert_eq!(
            m.accept(&s_rel, &r.c.utxo, NET, r.height()),
            Ok(s_rel.txid())
        );
        assert!(refused(m.accept(&s_abs, &r.c.utxo, NET, r.height())));
        // Tip hf + 2: the next block is hf + 3.
        r.mine(&[]).unwrap();
        assert_eq!(
            m.accept(&s_abs, &r.c.utxo, NET, r.height()),
            Ok(s_abs.txid())
        );
    }

    /// A one-block reorganization drops the block that confirmed a funding
    /// transaction: it returns to the pool, so its output is unconfirmed
    /// again, and the pending `Older` spend of it must leave the pool.
    #[test]
    fn reorg_evicts_a_pending_older_spend() {
        let (a, b) = (Key::new(1), Key::new(2));
        let mut x = Regtest::new(&a);
        // The competing miner shares every block so far.
        let mut y = Regtest {
            c: Chain::new(NET, genesis_block(NET)),
            miner: b.hash(),
            blocks: x.blocks.clone(),
        };
        for blk in &x.blocks {
            y.c.connect(blk, blk.header.time + 1)
                .expect("shared prefix");
        }

        let p = Policy::All(vec![a.leaf(), Policy::Older(1)]);
        let funding = fund(&mut x, &a, 205, |v| vec![p.output(units(v))]);
        let (op, o) = out(&funding, 0);
        let mut pending = spend(op, vec![a.output(o.value.units() - FEE)]);
        let s = Satisfaction::All(vec![sign_out(&pending, &o, &p, 0, &a), Satisfaction::Older]);
        pending.inputs[0].witness = witness(&p, &s);

        let mut m = Mempool::new();
        let id = m
            .accept(&pending, &x.c.utxo, NET, x.height())
            .expect("Older(1) is met in the next block");

        // The other branch: two empty blocks, it wins by one.
        y.mine(&[]).unwrap();
        y.mine(&[]).unwrap();
        let (y1, y2) = (&y.blocks[y.blocks.len() - 2], &y.blocks[y.blocks.len() - 1]);
        assert!(matches!(
            x.c.submit(y1, y1.header.time + 1),
            Ok(crate::chain::Accept::SideBranch)
        ));
        assert!(matches!(
            x.c.submit(y2, y2.header.time + 1),
            Ok(crate::chain::Accept::Reorganized { depth: 1 })
        ));

        // What the node does after a reorganization: the abandoned
        // transactions come back, then the pool is revalidated.
        let abandoned = x.c.take_disconnected();
        assert_eq!(
            m.return_abandoned(&abandoned, &x.c.utxo, NET, x.c.height()),
            1
        );
        assert!(m.contains(&funding.txid()));
        assert!(m.contains(&id), "still there before revalidation");
        m.revalidate(&x.c.utxo, NET, x.c.height());
        assert!(m.contains(&funding.txid()), "the funding waits again");
        assert!(
            !m.contains(&id),
            "its Older spend cannot enter the next block"
        );
    }

    // --- Review fixes ---------------------------------------------------

    /// A co-signer cannot swap the branch of an `Any` inside a sibling of an
    /// `All`: every key signs all the choices of the satisfaction.
    #[test]
    fn a_co_signer_cannot_swap_a_sibling_branch() {
        let (a, b) = (Key::new(1), Key::new(2));
        let (secret, hash) = preimage(7);
        // Leaves: A 0, B 1, B 2, preimage 3.
        let p = Policy::All(vec![
            a.leaf(),
            Policy::Any(vec![
                b.leaf(),
                Policy::All(vec![b.leaf(), Policy::Preimage(hash)]),
            ]),
        ]);
        let (u, op, e) = fixture(&p);
        let mut tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let sig = |k: &Key, leaf: u8, choices: &[u8]| Satisfaction::Key {
            pubkey: k.pk.clone(),
            signature: k.sign(&sighash(&tx, 0, NET, &e.output, &p, leaf, choices)),
        };
        // A signs the spend through B's plain branch; B could later sign the
        // other branch alone.
        let a_for_0 = sig(&a, 0, &[0]);
        let b_plain = sig(&b, 1, &[0]);
        let b_other = sig(&b, 2, &[1]);
        let first = Satisfaction::All(vec![a_for_0.clone(), any(0, b_plain)]);
        // B re-signs the other branch alone: same txid, another witness.
        let swapped = Satisfaction::All(vec![
            a_for_0,
            any(
                1,
                Satisfaction::All(vec![b_other, Satisfaction::Preimage(secret)]),
            ),
        ]);
        tx.inputs[0].witness = witness(&p, &first);
        assert!(check(&u, &tx, NET, BORN + 1).is_ok());
        tx.inputs[0].witness = witness(&p, &swapped);
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        );
    }

    /// Cheap policy checks of every input come before any signature: a
    /// malformed policy input after a plain one with a bad signature is
    /// reported as the policy failure, without the verification.
    #[test]
    fn policy_inputs_are_prechecked_before_any_signature() {
        let a = Key::new(1);
        let (_, hash) = preimage(8);
        let p = Policy::All(vec![a.leaf(), Policy::Preimage(hash)]);
        let (mut u, op, e) = fixture(&p);
        let plain = OutPoint {
            txid: Hash256([0x77; 32]),
            index: 0,
        };
        u.insert(
            plain,
            UtxoEntry {
                output: a.output(VALUE),
                height: BORN,
                is_coinbase: false,
            },
        );
        let mut tx = spend(plain, vec![a.output(2 * VALUE - 40_000)]);
        tx.inputs.push(TxIn {
            prev_out: op,
            witness: Witness::default(),
            sequence: u32::MAX,
        });
        tx.inputs[0].witness = Witness {
            pubkey: a.pk.clone(),
            signature: vec![0; SchemeId::MlDsa87.sig_len()],
        };
        let wrong = Satisfaction::All(vec![
            Satisfaction::Key {
                pubkey: a.pk.clone(),
                signature: a.sign(&sighash(&tx, 1, NET, &e.output, &p, 0, &[])),
            },
            Satisfaction::Preimage([0xee; 32]),
        ]);
        tx.inputs[1].witness = witness(&p, &wrong);
        assert_eq!(
            check(&u, &tx, NET, BORN + 1),
            pol(PolicyError::WrongPreimage)
        );
    }

    /// The relay budget charges a policy input the keys on its path.
    #[test]
    fn relay_cost_counts_the_keys_of_the_path() {
        let (a, b) = (Key::new(1), Key::new(2));
        let p = Policy::All(vec![a.leaf(), b.leaf()]);
        let (_, op, e) = fixture(&p);
        let tx = spend(op, vec![a.output(VALUE - 20_000)]);
        let s = Satisfaction::All(vec![
            sign_leaf(&tx, &e, &p, 0, &a),
            sign_leaf(&tx, &e, &p, 1, &b),
        ]);
        assert_eq!(verifications_claimed(&witness(&p, &s)), 2);
        let plain = Witness {
            pubkey: a.pk.clone(),
            signature: vec![0; SchemeId::MlDsa87.sig_len()],
        };
        assert_eq!(verifications_claimed(&plain), 1);
        assert_eq!(verifications_claimed(&Witness::default()), 1);
    }

    /// The defect of the review: a parent paying little creates an `Older(1)`
    /// output and waits in the pool; one block later its child was accepted
    /// (the age was counted from the parent's acceptance), and the template
    /// put both in one block, invalid. The child now waits for its parent's
    /// confirmation, and a block carrying both is named as invalid at the
    /// child, which the miner drops.
    #[test]
    fn an_older_spend_of_an_unconfirmed_output_waits() {
        let a = Key::new(1);
        let mut r = Regtest::new(&a);
        let p = Policy::All(vec![a.leaf(), Policy::Older(1)]);
        let parent = {
            let (coin, coin_out) = r.coin(206);
            plain_spend(
                coin,
                &coin_out,
                &a,
                vec![p.output(units(coin_out.value.units() - FEE))],
            )
        };
        let (op, o) = out(&parent, 0);
        let mut child = spend(op, vec![a.output(o.value.units() - FEE)]);
        let s = Satisfaction::All(vec![sign_out(&child, &o, &p, 0, &a), Satisfaction::Older]);
        child.inputs[0].witness = witness(&p, &s);

        let mut m = Mempool::new();
        m.accept(&parent, &r.c.utxo, NET, r.height())
            .expect("parent");
        let early = |m: &mut Mempool, r: &Regtest| {
            matches!(
                m.accept(&child, &r.c.utxo, NET, r.height()),
                Err(MempoolError::Validation(ValidationError::Policy(
                    PolicyError::TooEarly { .. }
                )))
            )
        };
        assert!(early(&mut m, &r), "parent unconfirmed");
        // One block without the parent: still unconfirmed, still refused.
        r.mine(&[]).unwrap();
        m.revalidate(&r.c.utxo, NET, r.height());
        assert!(
            early(&mut m, &r),
            "one block later, parent still unconfirmed"
        );
        assert!(!m
            .select_for_block(u64::MAX)
            .iter()
            .any(|t| t.txid() == child.txid()));

        // A block that carries both is invalid at the child.
        let (b, _) = r.candidate(&[parent.clone(), child.clone()]);
        let (i, why) =
            crate::validate::first_invalid_transaction(&b, &r.c.utxo, NET, r.height() + 1)
                .expect("the child is invalid where it stands");
        assert_eq!(b.transactions[i].txid(), child.txid());
        assert!(matches!(
            why,
            ValidationError::Policy(PolicyError::TooEarly { .. })
        ));

        // Once the parent is in a block, the child enters the pool.
        r.mine(from_ref(&parent)).unwrap();
        m.on_block_connected(r.blocks.last().unwrap());
        assert_eq!(
            m.accept(&child, &r.c.utxo, NET, r.height()),
            Ok(child.txid())
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

/// The rule is dormant on mainnet, and on testnet below its activation
/// height: nothing carrying a policy output is treated more leniently there
/// than 0.4.9 treated it.
#[cfg(test)]
mod dormant_tests {
    use super::*;
    use crate::address::Address;
    use crate::amount::Amount;
    use crate::block::{Block, BlockHeader};
    use crate::consensus::NETWORK_MAGIC_TESTNET;
    use crate::mempool::{Mempool, MempoolError};
    use crate::net::{policy_output_is_malformed, Asked};
    use crate::tx::{OutPoint, TxIn};
    use crate::utxo::UtxoSet;
    use crate::wire::{Message, WireError};

    const S: SchemeId = SchemeId::MlDsa87;

    fn policy() -> Policy {
        Policy::All(vec![
            Policy::Key {
                scheme: S,
                pubkey_hash: Hash256([1; 32]),
            },
            Policy::Older(1),
        ])
    }

    fn key_out(v: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(v),
            scheme: S,
            pubkey_hash: Hash256([2; 32]),
        }
    }

    /// Placeholder witness of the right sizes: if anything verified it, the
    /// answer would be a signature error, not the one these tests expect.
    fn tx(prev: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: prev,
                witness: Witness {
                    pubkey: vec![0; S.pubkey_len()],
                    signature: vec![0; S.sig_len()],
                },
                sequence: u32::MAX,
            }],
            outputs,
            lock_time: 0,
        }
    }

    fn creating() -> (Transaction, UtxoSet) {
        let prev = OutPoint {
            txid: Hash256([3; 32]),
            index: 0,
        };
        let mut u = UtxoSet::new();
        u.insert(
            prev,
            UtxoEntry {
                output: key_out(1_000_000),
                height: 1,
                is_coinbase: false,
            },
        );
        (
            tx(prev, vec![policy().output(Amount::from_units(900_000))]),
            u,
        )
    }

    fn frame_and_parse(m: &Message) -> Result<Message, WireError> {
        Message::parse(&m.frame(NETWORK_MAGIC_TESTNET), NETWORK_MAGIC_TESTNET).map(|(m, _)| m)
    }

    /// A transaction or a block with a policy output, received on mainnet,
    /// or on testnet far below the activation: unreadable, as in 0.4.9 — the
    /// node penalizes the sender with `MISCONDUCT_MALFORMED` and drops it
    /// (see `Node::read_loop`).
    #[test]
    fn a_live_node_treats_a_policy_output_as_unreadable() {
        let (t, _) = creating();
        let header = BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: Hash256::ZERO,
            time: 0,
            bits: 0,
            height: 1,
            nonce: 0,
        };
        let block = Block {
            header,
            transactions: vec![
                Transaction {
                    version: 1,
                    inputs: vec![TxIn::coinbase(1u64.to_le_bytes().to_vec())],
                    outputs: vec![key_out(50_000)],
                    lock_time: 0,
                },
                t.clone(),
            ],
            uncles: Vec::new(),
        };
        for msg in [
            Message::Tx(Box::new(t.clone())),
            Message::Block(Box::new(block.clone())),
            Message::BlockTxn {
                block: Hash256::ZERO,
                txs: vec![t.clone()],
            },
        ] {
            let read = frame_and_parse(&msg).expect("the frame itself is well formed");
            for version in [4, crate::wire::PROTOCOL_VERSION] {
                assert!(policy_output_is_malformed(
                    Network::Testnet,
                    0,
                    version,
                    Asked::No,
                    &read
                ));
                assert!(policy_output_is_malformed(
                    Network::Mainnet,
                    u64::MAX - 1,
                    version,
                    Asked::Tx,
                    &read
                ));
                // Regtest, where the rule is active, reads it normally.
                assert!(!policy_output_is_malformed(
                    Network::Regtest,
                    0,
                    version,
                    Asked::No,
                    &read
                ));
            }
        }
        // Without a policy output, nothing changes anywhere.
        let mut plain = t.clone();
        plain.outputs = vec![key_out(900_000)];
        let read = frame_and_parse(&Message::Tx(Box::new(plain))).unwrap();
        assert!(!policy_output_is_malformed(
            Network::Testnet,
            0,
            4,
            Asked::No,
            &read
        ));
        assert!(!policy_output_is_malformed(
            Network::Mainnet,
            0,
            4,
            Asked::No,
            &read
        ));

        // The 0.4.9 path is unchanged: an unknown scheme byte still fails to
        // decode at all.
        let mut raw = t.encode();
        // Version, one input (40 bytes and its count), output count, value.
        let pos = 4 + 1 + 40 + 1 + 8;
        assert_eq!(raw[pos], SchemeId::Policy.as_u8());
        raw[pos] = 200;
        assert!(Transaction::decode(&raw).is_err());
    }

    /// The testnet activation is the one compiled in: a real height, with a
    /// transition, between today's tip and anything that would leave too
    /// little notice.
    #[test]
    fn testnet_schedules_the_activation_at_a_real_height() {
        assert_eq!(
            scheduled_activation(Network::Testnet),
            crate::consensus::POLICY_ACTIVATION_TESTNET
        );
        assert_eq!(activation_height(Network::Testnet), 17_000);
        assert!(has_transition(Network::Testnet));
        assert!(!is_active(Network::Testnet, 16_999));
        assert!(is_active(Network::Testnet, 17_000));
        let st = status(Network::Testnet, 4_440);
        assert_eq!(st.activation_height, Some(17_000));
        assert!(!st.active);
        assert_eq!(st.blocks_remaining, Some(12_560));
        assert_eq!(st.eta_seconds(), Some(12_560 * 120));
        assert!(!reached(Network::Testnet, 16_999));
        assert!(reached(Network::Testnet, 17_000));
        assert!(!may_appear_on(Network::Mainnet));
        assert!(!reached(Network::Mainnet, u64::MAX - 1));
    }

    /// Around the testnet activation: a block is judged by its own height; a
    /// transaction from a peer that predates the activation by our next
    /// block; one from a peer that follows it never when we asked for it,
    /// and, pushed unasked, from the notice before the activation on, counted
    /// from our tip alone — never from a height the peer claims.
    #[test]
    fn testnet_wire_reading_around_the_activation() {
        let (t, _) = creating();
        let new = crate::wire::POLICY_ACTIVATION_VERSION;
        let tx = Message::Tx(Box::new(t.clone()));
        let notice = crate::consensus::POLICY_ACTIVATION_NOTICE;
        let h = 17_000;
        let net = Network::Testnet;
        assert!(policy_output_is_malformed(net, h - 2, 4, Asked::No, &tx));
        assert!(policy_output_is_malformed(net, h - 2, 4, Asked::Tx, &tx));
        assert!(!policy_output_is_malformed(net, h - 1, 4, Asked::No, &tx));
        let edge = h - 1 - notice;
        assert!(!policy_output_is_malformed(net, edge, new, Asked::No, &tx));
        assert!(policy_output_is_malformed(
            net,
            edge - 1,
            new,
            Asked::No,
            &tx
        ));
        // The reviewer's probe: our tip at H - 1500, syncing, and the peer
        // already at H - 1 answering our request. Not malformed.
        assert!(!policy_output_is_malformed(
            net,
            h - 1500,
            new,
            Asked::Tx,
            &tx
        ));
        assert!(!policy_output_is_malformed(net, 0, new, Asked::Tx, &tx));
        // The transactions of a compact block are judged by its height.
        let txn = Message::BlockTxn {
            block: Hash256::ZERO,
            txs: vec![t.clone()],
        };
        for v in [4, new] {
            assert!(policy_output_is_malformed(
                net,
                h + 5,
                v,
                Asked::BlockAt(h - 1),
                &txn
            ));
            assert!(!policy_output_is_malformed(
                net,
                0,
                v,
                Asked::BlockAt(h),
                &txn
            ));
        }
        let block = |height: u64| {
            let mut header = BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: Hash256::ZERO,
                time: 0,
                bits: 0,
                height,
                nonce: 0,
            };
            header.height = height;
            Message::Block(Box::new(Block {
                header,
                transactions: vec![t.clone()],
                uncles: Vec::new(),
            }))
        };
        for v in [4, new] {
            assert!(policy_output_is_malformed(
                Network::Testnet,
                h + 5,
                v,
                Asked::Tx,
                &block(h - 1)
            ));
            assert!(!policy_output_is_malformed(
                Network::Testnet,
                0,
                v,
                Asked::No,
                &block(h)
            ));
        }
        // The mempool's own gate: the next block at the activation height.
        let (t, u) = creating();
        assert_eq!(
            Mempool::new().accept(&t, &u, Network::Testnet, h - 2),
            Err(MempoolError::Validation(
                ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy)
            ))
        );
        assert!(!matches!(
            Mempool::new().accept(&t, &u, Network::Testnet, h - 1),
            Err(MempoolError::Validation(
                ValidationError::SchemeForbiddenOnNetwork(_)
            ))
        ));
    }

    /// The mempool of a live network refuses a policy output, created or
    /// spent, before any signature is verified.
    #[test]
    fn a_live_mempool_refuses_policies_before_any_signature() {
        let (t, u) = creating();
        for net in [Network::Testnet, Network::Mainnet] {
            assert_eq!(
                Mempool::new().accept(&t, &u, net, 10),
                Err(MempoolError::Validation(
                    ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy)
                ))
            );
        }
        // A spend of one that would somehow exist.
        let locked = OutPoint {
            txid: Hash256([4; 32]),
            index: 0,
        };
        let mut u = UtxoSet::new();
        u.insert(
            locked,
            UtxoEntry {
                output: policy().output(Amount::from_units(1_000_000)),
                height: 1,
                is_coinbase: false,
            },
        );
        let spend = tx(locked, vec![key_out(900_000)]);
        assert_eq!(
            Mempool::new().accept(&spend, &u, Network::Testnet, 10),
            Err(MempoolError::Validation(
                ValidationError::SchemeForbiddenOnNetwork(SchemeId::Policy)
            ))
        );
    }

    /// No address designates a policy: the wallet, the RPC calls that take a
    /// destination (`sendtoaddress`, `sendmany`) and the screens all parse
    /// through `Address::parse`, so none can create a policy output.
    #[test]
    fn no_address_designates_a_policy() {
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let text = Address {
                network,
                scheme: SchemeId::Policy,
                hash: policy().lock_hash(),
            }
            .to_string();
            assert_eq!(
                Address::parse(&text),
                Err(crate::address::AddressError::UnknownScheme(5))
            );
            assert!(Address::parse_on(&text, network).is_err());
        }
    }
}
