//! Names: `@delbu` bound to an identity key, for life.
//!
//! A name is registered once, by a transaction carrying two outputs side by
//! side:
//!
//! | output | scheme | thirty-two bytes | value |
//! |---|---|---|---|
//! | the tag | [`SchemeId::NameTag`] | the name, in clear, zero-padded | [`NAME_PRICE`] |
//! | the owner | [`SchemeId::NameKey`] | hash of the identity key | 0 |
//!
//! Neither can ever be spent ([`SchemeId::is_spendable`]): the price is
//! destroyed, and the record stays in the UTXO set for good. The set is
//! therefore the registry: it follows every block, every reorganization,
//! every snapshot and every fast sync with no state of its own, and the
//! index of names ([`NameIndex`]) is derived from it like the index by key
//! hash.
//!
//! # The rules
//!
//! From the activation height of the network ([`is_active`]):
//!
//! 1. a transaction holds at most one tag and one owner output, the owner
//!    right after the tag;
//! 2. the name is canonical ([`decode`]): `a-z`, `0-9` and `-`, neither
//!    first nor last, [`NAME_MIN_LEN`] to [`NAME_MAX_LEN`] characters;
//! 3. the tag carries exactly [`NAME_PRICE`], the owner output exactly zero;
//! 4. one input of the transaction spends an ML-DSA-87 output locked to the
//!    owner hash: only the holder of the identity key registers in its name;
//! 5. no registered name shares its skeleton ([`skeleton`]): neither the same
//!    name, nor a look-alike of it;
//! 6. an owner holds at most [`MAX_NAMES_PER_OWNER`] names.
//!
//! Rules 1 to 3 hold for a transaction alone ([`registration`]); 4 needs the
//! spent outputs, 5 and 6 the registry, and are checked by
//! [`crate::validate::check_transaction`] against its view.
//!
//! # Why the skeleton is consensus
//!
//! A registry that refuses only the exact same name lets `de1bu` stand next
//! to `delbu`: the look-alike is the whole attack, and a wallet warning can
//! be clicked through. A rule of the chain cannot. The skeleton is frozen
//! here for good: changing it would change which names are valid.

use crate::address::Network;
use crate::consensus::{
    MAX_NAMES_PER_OWNER, NAME_ACTIVATION_MAINNET, NAME_ACTIVATION_REGTEST, NAME_ACTIVATION_TESTNET,
    NAME_MAX_LEN, NAME_MIN_LEN, NAME_PRICE,
};
use crate::hash::Hash256;
use crate::sig::SchemeId;
use crate::tx::{OutPoint, Transaction};
use std::collections::HashMap;

/// A name as it is stored: its bytes, padded with zeros to thirty-two.
pub type NameBytes = [u8; 32];

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

/// Are names in force at `height` on `network`? `height` is that of the block
/// that would carry the registration: its own in block validation, the tip
/// plus one in the mempool.
pub fn is_active(network: Network, height: u64) -> bool {
    height >= activation_height(network)
}

/// Can a name ever be registered on `network`? False on mainnet for now.
pub fn may_appear_on(network: Network) -> bool {
    activation_height(network) != u64::MAX
}

/// Height from which names are in force; `u64::MAX` means never. The
/// compiled-in [`scheduled_activation`], except in an audit build whose tests
/// moved it with [`audit_set_activation_height`].
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
        Network::Mainnet => NAME_ACTIVATION_MAINNET,
        Network::Testnet => NAME_ACTIVATION_TESTNET,
        Network::Regtest => NAME_ACTIVATION_REGTEST,
    }
}

/// Does `network` have a height before which names are refused and after
/// which they are accepted? True on testnet; false on mainnet (never) and on
/// regtest (from block 1).
pub fn has_transition(network: Network) -> bool {
    let h = activation_height(network);
    h > 1 && h != u64::MAX
}

/// Has a chain whose tip is at `tip` reached the activation, so that a
/// registration broadcast now confirms at the activation height or above?
pub fn reached(network: Network, tip: u64) -> bool {
    may_appear_on(network) && (!has_transition(network) || tip + 1 >= activation_height(network))
}

/// Moves the name activation height of `network` for this process. Audit
/// builds only, never mainnet; set once per process and network, exactly as
/// [`crate::policy::audit_set_activation_height`].
#[cfg(feature = "audit")]
pub fn audit_set_activation_height(network: Network, height: u64) {
    audit_activation::set(network, height);
}

#[cfg(feature = "audit")]
mod audit_activation {
    use crate::address::Network;
    use std::sync::atomic::{AtomicU64, Ordering};

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
        assert!(height >= 1, "the genesis cannot carry a name");
        assert!(network != Network::Mainnet, "mainnet never opens names");
        match slot(network).compare_exchange(0, height, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {}
            Err(h) if h == height => {}
            Err(h) => panic!("{network:?} name activation already moved to {h}, not {height}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The name itself
// ---------------------------------------------------------------------------

fn allowed(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'
}

/// Is `name` a canonical name: `a-z`, `0-9` and `-`, the hyphen neither
/// first nor last, between [`NAME_MIN_LEN`] and [`NAME_MAX_LEN`] characters?
pub fn is_canonical(name: &str) -> bool {
    let b = name.as_bytes();
    (NAME_MIN_LEN..=NAME_MAX_LEN).contains(&b.len())
        && b.iter().all(|&c| allowed(c))
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
}

/// What a person types, as the canonical name it designates: spaces around
/// it and a leading `@` dropped, ASCII capitals lowered. `None` if what is
/// left is not canonical: an accent, a Cyrillic letter or a space inside is
/// refused, never transliterated.
pub fn normalize(input: &str) -> Option<String> {
    let t = input.trim();
    let t = t.strip_prefix('@').unwrap_or(t);
    let lowered = t.to_ascii_lowercase();
    is_canonical(&lowered).then_some(lowered)
}

/// A canonical name as stored in an output.
pub fn encode(name: &str) -> Option<NameBytes> {
    if !is_canonical(name) {
        return None;
    }
    let mut out = [0u8; 32];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Some(out)
}

/// The name stored in an output, if the bytes are canonical: a canonical
/// name, then zeros only. Any other byte string is no name at all, so that
/// one name has exactly one encoding.
pub fn decode(bytes: &NameBytes) -> Option<String> {
    let len = bytes.iter().position(|&c| c == 0).unwrap_or(32);
    if bytes[len..].iter().any(|&c| c != 0) {
        return None;
    }
    let s = std::str::from_utf8(&bytes[..len]).ok()?;
    is_canonical(s).then(|| s.to_string())
}

/// The skeleton of a canonical name: what two look-alike names share.
///
/// Hyphens are dropped; `0` reads as `o`; `1` and `i` as `l`; `5` as `s`;
/// then `rn` reads as `m` and `vv` as `w`. Two names with the same skeleton
/// cannot both be registered. Frozen: consensus depends on every byte of it.
pub fn skeleton(name: &str) -> Vec<u8> {
    let mapped: Vec<u8> = name
        .bytes()
        .filter(|&c| c != b'-')
        .map(|c| match c {
            b'0' => b'o',
            b'1' | b'i' => b'l',
            b'5' => b's',
            other => other,
        })
        .collect();
    let mut out = Vec::with_capacity(mapped.len());
    let mut i = 0;
    while i < mapped.len() {
        let pair = (mapped[i], mapped.get(i + 1).copied());
        match pair {
            (b'r', Some(b'n')) => {
                out.push(b'm');
                i += 2;
            }
            (b'v', Some(b'v')) => {
                out.push(b'w');
                i += 2;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Reaching a name's owner
// ---------------------------------------------------------------------------

/// Tag of the hash a [`crate::wire::Reach`] signs.
const TAG_REACH: &str = "Q21/name/reach";

/// The hash a reach announcement signs: the network, the identity key, where
/// it listens and when, so that none of them can be changed or replayed on
/// another network.
pub fn reach_message(
    network: Network,
    pubkey: &[u8],
    target: &crate::wire::ReachTarget,
    time: u64,
) -> Hash256 {
    let mut t = Vec::with_capacity(64);
    match target {
        crate::wire::ReachTarget::Onion { name, port } => {
            t.push(1);
            t.extend_from_slice(name.as_bytes());
            t.extend_from_slice(&port.to_le_bytes());
        }
        crate::wire::ReachTarget::Ipv4 { ip, port } => {
            t.push(2);
            t.extend_from_slice(ip);
            t.extend_from_slice(&port.to_le_bytes());
        }
    }
    crate::hash::tagged_hash_parts(
        TAG_REACH,
        &[network.hrp().as_bytes(), pubkey, &t, &time.to_le_bytes()],
    )
}

// ---------------------------------------------------------------------------
// The registration
// ---------------------------------------------------------------------------

/// A registration, as a transaction carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The canonical name.
    pub name: String,
    /// Hash of the identity key that owns it, as an ML-DSA-87 address.
    pub owner: Hash256,
    /// Index of the tag output; the owner output is the next one.
    pub tag_index: u32,
}

/// Why a name registration is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    /// More than one tag, or more than one owner output, in a transaction.
    MoreThanOne,
    /// A tag without the owner output right after it, or the reverse.
    Unpaired,
    /// The tag does not hold a canonical name.
    NotCanonical,
    /// The tag does not carry exactly the price, or the owner output is not
    /// zero.
    WrongAmount { expected: u64, received: u64 },
    /// No input spends an ML-DSA-87 output locked to the owner hash: only the
    /// holder of the identity key may register in its name.
    NoOwnerInput,
    /// The name, or a look-alike with the same skeleton, is already taken.
    Taken,
    /// The owner already holds [`MAX_NAMES_PER_OWNER`] names.
    OwnerFull,
    /// A name output in a coinbase.
    InCoinbase,
    /// An input spends a name output, which can never be spent.
    Unspendable(OutPoint),
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameError::MoreThanOne => write!(f, "more than one name in a transaction"),
            NameError::Unpaired => write!(f, "a name output without its pair"),
            NameError::NotCanonical => write!(f, "not a canonical name"),
            NameError::WrongAmount { expected, received } => {
                write!(f, "name output of {received} units, expected {expected}")
            }
            NameError::NoOwnerInput => write!(f, "the owner key does not sign the registration"),
            NameError::Taken => write!(f, "name already taken, or too close to a taken name"),
            NameError::OwnerFull => {
                write!(f, "the owner already holds {MAX_NAMES_PER_OWNER} names")
            }
            NameError::InCoinbase => write!(f, "a name output in a coinbase"),
            NameError::Unspendable(o) => write!(f, "spends name output {o:?}"),
        }
    }
}

/// The registration `tx` carries, if any, checked for everything that
/// depends on the transaction alone (rules 1 to 3 of the module).
pub fn registration(tx: &Transaction) -> Result<Option<Registration>, NameError> {
    let tags: Vec<usize> = (0..tx.outputs.len())
        .filter(|&i| tx.outputs[i].scheme == SchemeId::NameTag)
        .collect();
    let keys: Vec<usize> = (0..tx.outputs.len())
        .filter(|&i| tx.outputs[i].scheme == SchemeId::NameKey)
        .collect();
    match (tags.as_slice(), keys.as_slice()) {
        ([], []) => Ok(None),
        ([t], [k]) if *k == *t + 1 => {
            let tag = &tx.outputs[*t];
            let key = &tx.outputs[*k];
            if tag.value.units() != NAME_PRICE {
                return Err(NameError::WrongAmount {
                    expected: NAME_PRICE,
                    received: tag.value.units(),
                });
            }
            if key.value.units() != 0 {
                return Err(NameError::WrongAmount {
                    expected: 0,
                    received: key.value.units(),
                });
            }
            let name = decode(&tag.pubkey_hash.0).ok_or(NameError::NotCanonical)?;
            Ok(Some(Registration {
                name,
                owner: key.pubkey_hash,
                tag_index: *t as u32,
            }))
        }
        ([_], [_]) | ([_], []) | ([], [_]) => Err(NameError::Unpaired),
        _ => Err(NameError::MoreThanOne),
    }
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// A registered name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameRecord {
    /// Hash of the identity key that owns it.
    pub owner: Hash256,
    /// The tag output, which says in which transaction it was registered.
    pub tag: OutPoint,
    /// Height of the block that registered it.
    pub height: u64,
}

/// The registry, derived from the name outputs of a UTXO set. Kept by
/// [`crate::utxo::UtxoSet`] through its `insert` and `remove`, like its index
/// by key hash: it never takes part in the equality of two sets.
#[derive(Clone, Debug, Default)]
pub struct NameIndex {
    by_name: HashMap<NameBytes, NameRecord>,
    by_skeleton: HashMap<Vec<u8>, NameBytes>,
    per_owner: HashMap<Hash256, usize>,
    /// Tag outpoint -> name, for the pairs currently indexed.
    by_tag: HashMap<OutPoint, NameBytes>,
}

impl NameIndex {
    /// Records a pair, once both of its outputs are in the set.
    pub(crate) fn add(&mut self, tag: OutPoint, name: NameBytes, owner: Hash256, height: u64) {
        let Some(text) = decode(&name) else {
            return;
        };
        if self.by_tag.contains_key(&tag) {
            return;
        }
        self.by_tag.insert(tag, name);
        self.by_skeleton.insert(skeleton(&text), name);
        self.by_name.insert(name, NameRecord { owner, tag, height });
        *self.per_owner.entry(owner).or_default() += 1;
    }

    /// Forgets the pair whose tag is `tag`, if it is indexed.
    pub(crate) fn remove_tag(&mut self, tag: &OutPoint) {
        let Some(name) = self.by_tag.remove(tag) else {
            return;
        };
        if let Some(r) = self.by_name.get(&name).copied() {
            if r.tag == *tag {
                self.by_name.remove(&name);
                if let Some(text) = decode(&name) {
                    let sk = skeleton(&text);
                    if self.by_skeleton.get(&sk) == Some(&name) {
                        self.by_skeleton.remove(&sk);
                    }
                }
                if let Some(n) = self.per_owner.get_mut(&r.owner) {
                    *n -= 1;
                    if *n == 0 {
                        self.per_owner.remove(&r.owner);
                    }
                }
            }
        }
    }

    /// The record of a canonical name.
    pub fn get(&self, name: &str) -> Option<NameRecord> {
        encode(name).and_then(|b| self.by_name.get(&b).copied())
    }

    /// The registered name that shares `skeleton`, if any.
    pub fn by_skeleton(&self, skeleton: &[u8]) -> Option<String> {
        self.by_skeleton.get(skeleton).and_then(decode)
    }

    /// How many names `owner` holds.
    pub fn owned(&self, owner: &Hash256) -> usize {
        self.per_owner.get(owner).copied().unwrap_or(0)
    }

    /// The names `owner` holds, sorted.
    pub fn names_of(&self, owner: &Hash256) -> Vec<String> {
        let mut v: Vec<String> = self
            .by_name
            .iter()
            .filter(|(_, r)| r.owner == *owner)
            .filter_map(|(n, _)| decode(n))
            .collect();
        v.sort();
        v
    }

    /// Number of registered names.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Total destroyed by registrations, in units.
    pub fn burned(&self) -> u64 {
        (self.by_name.len() as u64).saturating_mul(NAME_PRICE)
    }

    /// Every registered name, sorted: for the explorer and the look-alike
    /// search of a wallet.
    pub fn all(&self) -> Vec<String> {
        let mut v: Vec<String> = self.by_name.keys().filter_map(decode).collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crate::tx::{TxIn, TxOut, Witness};

    fn tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([7; 32]),
                    index: 0,
                },
                witness: Witness {
                    pubkey: vec![],
                    signature: vec![],
                },
                sequence: 0,
            }],
            outputs,
            lock_time: 0,
        }
    }

    fn tag(name: &str, units: u64) -> TxOut {
        let mut b = [0u8; 32];
        b[..name.len()].copy_from_slice(name.as_bytes());
        TxOut {
            value: Amount::from_units(units),
            scheme: SchemeId::NameTag,
            pubkey_hash: Hash256(b),
        }
    }

    fn key(owner: u8, units: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(units),
            scheme: SchemeId::NameKey,
            pubkey_hash: Hash256([owner; 32]),
        }
    }

    fn pay(units: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(units),
            scheme: SchemeId::MlDsa87,
            pubkey_hash: Hash256([9; 32]),
        }
    }

    #[test]
    fn canonical_names() {
        for ok in ["abc", "delbu", "q21", "a-b", "x1-y2-z3", &"a".repeat(30)] {
            assert!(is_canonical(ok), "{ok}");
        }
        for bad in [
            "ab",
            &"a".repeat(31),
            "-ab",
            "ab-",
            "Delbu",
            "del bu",
            "d\u{e9}lbu",
            "d\u{435}lbu", // a Cyrillic e
            "del_bu",
            "del.bu",
            "",
        ] {
            assert!(!is_canonical(bad), "{bad}");
        }
    }

    #[test]
    fn what_a_person_types_is_normalized() {
        assert_eq!(normalize("  @Delbu "), Some("delbu".into()));
        assert_eq!(normalize("DELBU"), Some("delbu".into()));
        assert_eq!(normalize("@d\u{e9}1bu"), None);
        assert_eq!(normalize("@"), None);
    }

    #[test]
    fn a_name_has_exactly_one_encoding() {
        let b = encode("delbu").unwrap();
        assert_eq!(decode(&b).as_deref(), Some("delbu"));
        let mut gap = b;
        gap[7] = b'x';
        assert_eq!(decode(&gap), None, "a byte after the padding");
        let mut upper = b;
        upper[0] = b'D';
        assert_eq!(decode(&upper), None);
        assert_eq!(decode(&[0u8; 32]), None);
        let full = encode(&"z".repeat(30)).unwrap();
        assert_eq!(decode(&full).unwrap().len(), 30);
        assert_eq!(decode(&[b'a'; 32]), None, "32 characters is too long");
    }

    #[test]
    fn look_alikes_share_a_skeleton() {
        let s = skeleton("delbu");
        for twin in ["de1bu", "del-bu", "deibu", "d-e-l-b-u"] {
            assert_eq!(skeleton(twin), s, "{twin}");
        }
        assert_eq!(skeleton("modern"), skeleton("rnodern"));
        assert_eq!(skeleton("wave"), skeleton("vvave"));
        assert_eq!(skeleton("b0b"), skeleton("bob"));
        assert_eq!(skeleton("5am"), skeleton("sam"));
        assert_ne!(skeleton("delbu"), skeleton("delbo"));
        assert_ne!(skeleton("alice"), skeleton("alise"));
    }

    #[test]
    fn a_registration_is_a_tag_then_its_owner() {
        let ok = tx(vec![pay(1_000_000), tag("delbu", NAME_PRICE), key(3, 0)]);
        assert_eq!(
            registration(&ok),
            Ok(Some(Registration {
                name: "delbu".into(),
                owner: Hash256([3; 32]),
                tag_index: 1
            }))
        );
        assert_eq!(registration(&tx(vec![pay(5)])), Ok(None));
    }

    #[test]
    fn malformed_registrations_are_refused() {
        let cases = [
            (
                vec![key(3, 0), tag("delbu", NAME_PRICE)],
                NameError::Unpaired,
            ),
            (
                vec![tag("delbu", NAME_PRICE), pay(1), key(3, 0)],
                NameError::Unpaired,
            ),
            (vec![tag("delbu", NAME_PRICE)], NameError::Unpaired),
            (vec![key(3, 0)], NameError::Unpaired),
            (
                vec![
                    tag("delbu", NAME_PRICE),
                    key(3, 0),
                    tag("other", NAME_PRICE),
                    key(3, 0),
                ],
                NameError::MoreThanOne,
            ),
            (
                vec![tag("delbu", NAME_PRICE - 1), key(3, 0)],
                NameError::WrongAmount {
                    expected: NAME_PRICE,
                    received: NAME_PRICE - 1,
                },
            ),
            (
                vec![tag("delbu", NAME_PRICE + 1), key(3, 0)],
                NameError::WrongAmount {
                    expected: NAME_PRICE,
                    received: NAME_PRICE + 1,
                },
            ),
            (
                vec![tag("delbu", NAME_PRICE), key(3, 1)],
                NameError::WrongAmount {
                    expected: 0,
                    received: 1,
                },
            ),
            (
                vec![tag("Delbu", NAME_PRICE), key(3, 0)],
                NameError::NotCanonical,
            ),
            (
                vec![tag("ab", NAME_PRICE), key(3, 0)],
                NameError::NotCanonical,
            ),
        ];
        for (outputs, err) in cases {
            assert_eq!(registration(&tx(outputs.clone())), Err(err), "{outputs:?}");
        }
    }

    #[test]
    fn the_index_follows_additions_and_removals() {
        let mut ix = NameIndex::default();
        let t1 = OutPoint {
            txid: Hash256([1; 32]),
            index: 0,
        };
        let t2 = OutPoint {
            txid: Hash256([2; 32]),
            index: 4,
        };
        let owner = Hash256([5; 32]);
        ix.add(t1, encode("delbu").unwrap(), owner, 5_300);
        ix.add(t2, encode("other").unwrap(), owner, 5_301);
        assert_eq!(ix.len(), 2);
        assert_eq!(ix.owned(&owner), 2);
        assert_eq!(ix.get("delbu").unwrap().height, 5_300);
        assert_eq!(ix.by_skeleton(&skeleton("de1bu")).as_deref(), Some("delbu"));
        assert_eq!(
            ix.names_of(&owner),
            vec!["delbu".to_string(), "other".into()]
        );
        assert_eq!(ix.burned(), 2 * NAME_PRICE);
        // Adding the same pair again changes nothing.
        ix.add(t1, encode("delbu").unwrap(), owner, 5_300);
        assert_eq!(ix.owned(&owner), 2);
        ix.remove_tag(&t1);
        assert_eq!(ix.get("delbu"), None);
        assert_eq!(ix.by_skeleton(&skeleton("delbu")), None);
        assert_eq!(ix.owned(&owner), 1);
        ix.remove_tag(&t1);
        ix.remove_tag(&t2);
        assert!(ix.is_empty());
        assert_eq!(ix.owned(&owner), 0);
    }
}

/// The rules of the chain, end to end: real ML-DSA-87 keys, real signatures,
/// [`crate::validate::check_transaction`] against a real UTXO set, its undo,
/// a block, and the mempool.
#[cfg(all(test, feature = "mldsa"))]
mod consensus_tests {
    use super::*;
    use crate::amount::Amount;
    use crate::block::{Block, BlockHeader};
    use crate::mempool::{Mempool, MempoolError};
    use crate::tx::{TxIn, TxOut, Witness};
    use crate::utxo::{UndoRecord, UtxoEntry, UtxoSet, UtxoView};
    use crate::validate::{check_transaction, first_invalid_transaction, ValidationError};
    use ml_dsa::{signature::Keypair, MlDsa87, Signer, SigningKey, B32};
    use std::collections::HashSet;

    const NET: Network = Network::Regtest;
    const H: u64 = 100;
    const COIN: u64 = 2 * NAME_PRICE;
    const FEE: u64 = 1_000_000;

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
            crate::sig::pubkey_hash(SchemeId::MlDsa87, &self.pk)
        }
        fn output(&self, v: u64) -> TxOut {
            TxOut {
                value: Amount::from_units(v),
                scheme: SchemeId::MlDsa87,
                pubkey_hash: self.hash(),
            }
        }
    }

    /// A set holding one coin of `COIN` for each key, at outpoint `n`.
    fn set_with(keys: &[(&Key, u8)]) -> UtxoSet {
        let mut u = UtxoSet::new();
        for (k, n) in keys {
            u.insert(
                coin(*n),
                UtxoEntry {
                    output: k.output(COIN),
                    height: 1,
                    is_coinbase: false,
                },
            );
        }
        u
    }

    fn coin(n: u8) -> OutPoint {
        OutPoint {
            txid: Hash256([n; 32]),
            index: 0,
        }
    }

    fn name_outputs(name: &str, owner: Hash256) -> Vec<TxOut> {
        vec![
            TxOut {
                value: Amount::from_units(NAME_PRICE),
                scheme: SchemeId::NameTag,
                pubkey_hash: Hash256(encode(name).unwrap()),
            },
            TxOut {
                value: Amount::ZERO,
                scheme: SchemeId::NameKey,
                pubkey_hash: owner,
            },
        ]
    }

    /// `signer` spends `prev` (worth `COIN`) to register `name` for `owner`,
    /// with the change back to itself.
    fn register(signer: &Key, prev: OutPoint, name: &str, owner: Hash256) -> Transaction {
        let mut outputs = name_outputs(name, owner);
        outputs.push(signer.output(COIN - NAME_PRICE - FEE));
        signed(signer, prev, outputs)
    }

    fn signed(signer: &Key, prev: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: prev,
                witness: Witness {
                    pubkey: signer.pk.clone(),
                    signature: vec![],
                },
                sequence: 0,
            }],
            outputs,
            lock_time: 0,
        };
        let m = tx.sighash(0, NET, &signer.output(COIN));
        tx.inputs[0].witness.signature = signer.sk.sign(m.as_bytes()).encode()[..].to_vec();
        tx
    }

    fn check(tx: &Transaction, u: &UtxoSet, height: u64) -> Result<Amount, ValidationError> {
        check_transaction(tx, u, NET, height, &mut HashSet::new())
    }

    fn apply(u: &mut UtxoSet, tx: &Transaction) -> UndoRecord {
        let mut undo = UndoRecord::default();
        u.apply_transaction(tx, H, &mut undo);
        undo
    }

    #[test]
    fn the_owner_registers_its_name_and_the_price_is_destroyed() {
        let k = Key::new(1);
        let mut u = set_with(&[(&k, 1)]);
        let tx = register(&k, coin(1), "delbu", k.hash());
        // The fee is what the miner gets: the price is not part of it.
        assert_eq!(check(&tx, &u, H), Ok(Amount::from_units(FEE)));
        apply(&mut u, &tx);
        let r = u.names().get("delbu").expect("registered");
        assert_eq!(r.owner, k.hash());
        assert_eq!(r.height, H);
        assert_eq!(u.names_owned(&k.hash()), 1);
        assert_eq!(u.names().burned(), NAME_PRICE);
        // The owner output is a record, not a coin: no wallet sees it.
        let mine = u.spendable_for(&k.hash(), H, 0);
        assert_eq!(mine.len(), 1, "the change only");
        assert_eq!(mine[0].1.output.value.units(), COIN - NAME_PRICE - FEE);
    }

    #[test]
    fn only_the_key_holder_registers_in_its_name() {
        let me = Key::new(1);
        let victim = Key::new(2);
        let u = set_with(&[(&me, 1)]);
        let tx = register(&me, coin(1), "delbu", victim.hash());
        assert_eq!(
            check(&tx, &u, H),
            Err(ValidationError::Name(NameError::NoOwnerInput))
        );
    }

    #[test]
    fn a_name_and_its_look_alikes_are_taken_for_good() {
        let a = Key::new(1);
        let b = Key::new(2);
        let mut u = set_with(&[(&a, 1), (&b, 2), (&b, 3), (&b, 4), (&b, 5)]);
        apply(&mut u, &register(&a, coin(1), "delbu", a.hash()));
        for (n, twin) in [(2, "delbu"), (3, "de1bu"), (4, "del-bu"), (5, "deibu")] {
            assert_eq!(
                check(&register(&b, coin(n), twin, b.hash()), &u, H),
                Err(ValidationError::Name(NameError::Taken)),
                "{twin}"
            );
        }
        // A genuinely different name is free.
        assert!(check(&register(&b, coin(2), "delbo", b.hash()), &u, H).is_ok());
    }

    #[test]
    fn three_names_per_owner_and_no_more() {
        let k = Key::new(1);
        let mut u = set_with(&[(&k, 1), (&k, 2), (&k, 3), (&k, 4)]);
        for (n, name) in [(1, "first"), (2, "second"), (3, "third")] {
            let tx = register(&k, coin(n), name, k.hash());
            assert!(check(&tx, &u, H).is_ok(), "{name}");
            apply(&mut u, &tx);
        }
        assert_eq!(u.names_owned(&k.hash()), MAX_NAMES_PER_OWNER);
        assert_eq!(
            check(&register(&k, coin(4), "fourth", k.hash()), &u, H),
            Err(ValidationError::Name(NameError::OwnerFull))
        );
    }

    #[test]
    fn a_name_output_can_never_be_spent() {
        let k = Key::new(1);
        let mut u = set_with(&[(&k, 1)]);
        let reg = register(&k, coin(1), "delbu", k.hash());
        apply(&mut u, &reg);
        for index in [0u32, 1] {
            let tag = OutPoint {
                txid: reg.txid(),
                index,
            };
            let mut tx = signed(&k, coin(1), vec![k.output(NAME_PRICE / 2)]);
            tx.inputs[0].prev_out = tag;
            assert_eq!(
                check(&tx, &u, H),
                Err(ValidationError::Name(NameError::Unspendable(tag)))
            );
        }
    }

    #[test]
    fn undoing_the_block_frees_the_name() {
        let a = Key::new(1);
        let b = Key::new(2);
        let mut u = set_with(&[(&a, 1), (&b, 2)]);
        let undo = apply(&mut u, &register(&a, coin(1), "delbu", a.hash()));
        assert!(u.names().get("delbu").is_some());
        u.undo(&undo);
        assert!(u.names().get("delbu").is_none());
        assert_eq!(u.names_owned(&a.hash()), 0);
        assert!(check(&register(&b, coin(2), "delbu", b.hash()), &u, H).is_ok());
    }

    #[test]
    fn the_registry_is_rebuilt_whatever_the_order_of_the_outputs() {
        let k = Key::new(1);
        let mut built = set_with(&[(&k, 1)]);
        let reg = register(&k, coin(1), "delbu", k.hash());
        apply(&mut built, &reg);
        // A snapshot restores outputs in any order: owner first here.
        let mut restored = UtxoSet::new();
        let mut entries: Vec<(OutPoint, UtxoEntry)> = built.iter().map(|(o, e)| (*o, *e)).collect();
        entries.sort_by_key(|(o, _)| std::cmp::Reverse(o.index));
        for (o, e) in entries {
            restored.insert(o, e);
        }
        assert_eq!(restored, built);
        assert_eq!(restored.names().get("delbu"), built.names().get("delbu"));
        assert_eq!(restored.commitment(), built.commitment());
    }

    #[test]
    fn testnet_refuses_names_before_their_activation() {
        let k = Key::new(1);
        let u = set_with(&[(&k, 1)]);
        let mut tx = register(&k, coin(1), "delbu", k.hash());
        let m = tx.sighash(0, Network::Testnet, &k.output(COIN));
        tx.inputs[0].witness.signature = k.sk.sign(m.as_bytes()).encode()[..].to_vec();
        let h = activation_height(Network::Testnet);
        assert_eq!(h, NAME_ACTIVATION_TESTNET);
        assert_eq!(
            check_transaction(&tx, &u, Network::Testnet, h - 1, &mut HashSet::new()),
            Err(ValidationError::SchemeForbiddenOnNetwork(SchemeId::NameTag))
        );
        assert!(check_transaction(&tx, &u, Network::Testnet, h, &mut HashSet::new()).is_ok());
        assert!(!is_active(Network::Mainnet, u64::MAX - 1));
    }

    #[test]
    fn a_block_cannot_register_the_same_name_twice() {
        let a = Key::new(1);
        let b = Key::new(2);
        let u = set_with(&[(&a, 1), (&b, 2)]);
        let first = register(&a, coin(1), "delbu", a.hash());
        let twin = register(&b, coin(2), "de1bu", b.hash());
        let header = BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: Hash256::ZERO,
            time: 0,
            bits: 0,
            height: H,
            nonce: 0,
        };
        let block = Block {
            header,
            transactions: vec![first.clone(), first, twin],
            uncles: vec![],
        };
        // The first transaction stands for the coinbase and is skipped.
        assert_eq!(
            first_invalid_transaction(&block, &u, NET, H),
            Some((2, ValidationError::Name(NameError::Taken)))
        );
    }

    #[test]
    fn the_mempool_holds_one_registration_per_name() {
        let a = Key::new(1);
        let b = Key::new(2);
        let c = Key::new(3);
        let mut u = set_with(&[(&a, 1), (&b, 2), (&c, 3)]);
        let mut pool = Mempool::new();
        let first = register(&a, coin(1), "delbu", a.hash());
        pool.accept(&first, &u, NET, H).expect("first");
        assert!(pool.touches_names(&first.txid()));
        let twin = register(&b, coin(2), "de1bu", b.hash());
        assert_eq!(
            pool.accept(&twin, &u, NET, H),
            Err(MempoolError::Validation(ValidationError::Name(
                NameError::Taken
            )))
        );
        // Another pool's registration of a look-alike gets mined first: ours
        // can no longer enter a block, and leaves.
        let other = register(&c, coin(3), "del-bu", c.hash());
        apply(&mut u, &other);
        pool.revalidate(&u, NET, H);
        assert!(!pool.contains(&first.txid()));
        // And the freed slot accepts a different name.
        let fine = register(&b, coin(2), "another", b.hash());
        assert!(pool.accept(&fine, &u, NET, H).is_ok());
    }
}
