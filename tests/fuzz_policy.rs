//! FUZZ (red-team campaign 6, round 2): pay-to-policy decoding and the
//! reading of a satisfaction against it.
//!
//! A policy and its satisfaction travel in the witness of any transaction
//! that spends a policy output: every relaying peer and every miner feeds
//! them to `Policy::decode` and `walk` (through `check_spend`,
//! `precheck_spend`, `relative_lock`, `available_at`), and the relay budget
//! reads them through `verifications_claimed` before anything else is looked
//! up. A panic there is a remote crash of every node.
//!
//! Asserted, beyond "never panics":
//!
//! - decoding is canonical: a policy that decodes re-encodes to exactly the
//!   same bytes, is within every consensus bound (size, depth, leaves) and is
//!   always signed;
//! - a randomly generated tree that decodes is the tree that was encoded;
//! - `verifications_claimed` is between 1 and `MAX_POLICY_LEAVES`;
//! - a witness `precheck_spend` accepts at height `h` has `available_at <= h`;
//! - `check_spend` accepts no witness other than the one honestly built
//!   (no third-party malleability of a policy witness);
//! - `check_signature` accepts only a signature that was really made for
//!   that policy, leaf and choices.
//!
//! Rounds: `Q21_POLICY_FUZZ_ROUNDS` (defaults below).

#![cfg(feature = "mldsa")]

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::channel::{ChannelKey, Signer};
use q21_core::consensus::{MAX_POLICY_DEPTH, MAX_POLICY_LEAVES, MAX_POLICY_SIZE};
use q21_core::hash::Hash256;
use q21_core::policy::{self, Policy, Satisfaction};
use q21_core::sha256::sha256;
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::utxo::UtxoEntry;

const NET: Network = Network::Regtest;

fn rounds(default: u64) -> u64 {
    std::env::var("Q21_POLICY_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    fn one_in(&mut self, n: u64) -> bool {
        n != 0 && self.next() % n == 0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 29) as u8
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for x in b.iter_mut() {
            *x = self.byte();
        }
        b
    }
}

fn hex(v: &[u8]) -> String {
    let mut s: String = v.iter().take(200).map(|b| format!("{b:02x}")).collect();
    if v.len() > 200 {
        s.push_str(&format!("... ({} bytes)", v.len()));
    }
    s
}

/// Byte mutations aimed at a tree encoding: node tags, arities, lengths.
fn mutate(rng: &mut Rng, v: &mut Vec<u8>) {
    if v.is_empty() {
        v.push(rng.byte());
        return;
    }
    let i = rng.below(v.len() as u64) as usize;
    match rng.below(9) {
        0 => v[i] ^= 1u8 << rng.below(8),
        1 => v[i] = rng.byte(),
        // A node tag or a small count.
        2 => v[i] = rng.below(10) as u8,
        3 => v[i] = if rng.one_in(2) { 0 } else { 0xff },
        4 => v.truncate(i),
        5 => {
            for _ in 0..(1 + rng.below(40)) {
                v.push(rng.byte());
            }
        }
        6 => {
            let n = 1 + rng.below(6) as usize;
            let piece: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            v.splice(i..i, piece);
        }
        7 => {
            // Duplicate a slice: nested repeats make deep or wide trees.
            let j = (i + 1 + rng.below(40) as usize).min(v.len());
            let piece: Vec<u8> = v[i..j].to_vec();
            v.splice(i..i, piece);
        }
        _ => {
            // A varint length prefix of the satisfaction set huge.
            v[i] = 0xfd + rng.below(3) as u8;
        }
    }
}

fn depth(p: &Policy) -> usize {
    match p {
        Policy::All(c) | Policy::Any(c) => 1 + c.iter().map(depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// The checks every decoded policy must pass.
fn check_decoded(p: &Policy, bytes: &[u8], ctx: &str) {
    assert_eq!(
        p.encode(),
        bytes,
        "{ctx}: a policy decoded from non-canonical bytes: {}",
        hex(bytes)
    );
    assert!(
        bytes.len() <= MAX_POLICY_SIZE,
        "{ctx}: oversized policy decoded"
    );
    assert!(
        depth(p) <= MAX_POLICY_DEPTH,
        "{ctx}: too deep: {}",
        hex(bytes)
    );
    assert!(
        p.leaf_count() >= 1 && p.leaf_count() <= MAX_POLICY_LEAVES,
        "{ctx}: leaves {}",
        p.leaf_count()
    );
    assert!(p.always_signed(), "{ctx}: an unsigned path decoded");
    let leaves = p.key_leaves();
    for (pos, scheme, _) in &leaves {
        assert!((*pos as usize) < p.leaf_count());
        assert!(!scheme.is_one_time(), "{ctx}: a one-time key leaf decoded");
    }
    for leaf in 0..=u8::MAX {
        let c = p.choices_to(leaf);
        assert!(c.len() <= MAX_POLICY_DEPTH);
    }
    let _ = p.lock_hash();
}

// ---------------------------------------------------------------------------
// Random trees
// ---------------------------------------------------------------------------

fn random_scheme(rng: &mut Rng) -> SchemeId {
    match rng.below(4) {
        0 | 1 => SchemeId::MlDsa87,
        2 => SchemeId::MlDsa65,
        _ => SchemeId::from_u8(rng.below(9) as u8).unwrap_or(SchemeId::LamportOts),
    }
}

fn random_policy(rng: &mut Rng, level: usize, keys: &[Hash256], h: Hash256) -> Policy {
    if level >= 6 || rng.one_in(3) {
        return match rng.below(7) {
            0..=2 => Policy::Key {
                scheme: random_scheme(rng),
                pubkey_hash: if rng.one_in(4) {
                    Hash256(rng.bytes32())
                } else {
                    keys[rng.below(keys.len() as u64) as usize]
                },
            },
            3 => Policy::Preimage(if rng.one_in(4) {
                Hash256(rng.bytes32())
            } else {
                h
            }),
            4 => Policy::Older(match rng.below(4) {
                0 => 0,
                1 => u16::MAX,
                _ => 1 + rng.below(20) as u16,
            }),
            _ => Policy::After(match rng.below(4) {
                0 => 0,
                1 => u32::MAX,
                _ => 1 + rng.below(1000) as u32,
            }),
        };
    }
    let n = match rng.below(12) {
        0 => 0,
        1 => 1,
        2 if level <= 2 => 9,
        3 if level == 1 => 256,
        _ => 2 + rng.below(3) as usize,
    };
    let children: Vec<Policy> = if n == 256 {
        (0..n)
            .map(|_| Policy::Key {
                scheme: SchemeId::MlDsa87,
                pubkey_hash: keys[0],
            })
            .collect()
    } else {
        (0..n)
            .map(|_| random_policy(rng, level + 1, keys, h))
            .collect()
    };
    if rng.one_in(2) {
        Policy::All(children)
    } else {
        Policy::Any(children)
    }
}

// ---------------------------------------------------------------------------
// Honest spends
// ---------------------------------------------------------------------------

struct Keys {
    keys: Vec<ChannelKey>,
    hashes: Vec<Hash256>,
    secret: [u8; 32],
    hash: Hash256,
}

impl Keys {
    fn new() -> Keys {
        let keys: Vec<ChannelKey> = (0..3u8)
            .map(|i| ChannelKey::from_seed(&[0x70 + i; 32]))
            .collect();
        let hashes: Vec<Hash256> = keys
            .iter()
            .map(|k| sig::pubkey_hash(SchemeId::MlDsa87, k.pubkey()))
            .collect();
        let secret = [0x42u8; 32];
        Keys {
            keys,
            hashes,
            secret,
            hash: Hash256(sha256(&secret)),
        }
    }
    fn key(&self, i: usize) -> Policy {
        Policy::Key {
            scheme: SchemeId::MlDsa87,
            pubkey_hash: self.hashes[i],
        }
    }
}

/// Valid policies of every shape the bounds allow.
fn corpus(k: &Keys) -> Vec<Policy> {
    let pre = || Policy::Preimage(k.hash);
    vec![
        // The channel funding output.
        Policy::All(vec![k.key(0), k.key(1)]),
        // A channel to_local.
        Policy::Any(vec![
            Policy::All(vec![k.key(1), pre()]),
            Policy::All(vec![k.key(0), Policy::Older(12)]),
        ]),
        Policy::Any(vec![k.key(0), k.key(1), k.key(2)]),
        Policy::All(vec![k.key(2), Policy::After(9)]),
        Policy::Any(vec![
            Policy::All(vec![k.key(0), Policy::Any(vec![pre(), Policy::Older(3)])]),
            k.key(1),
        ]),
        // Four levels.
        Policy::All(vec![
            k.key(0),
            Policy::Any(vec![
                Policy::All(vec![k.key(1), pre()]),
                Policy::All(vec![k.key(2), Policy::After(7)]),
            ]),
        ]),
        // Eight leaves.
        Policy::All(vec![
            k.key(0),
            k.key(1),
            k.key(2),
            k.key(0),
            pre(),
            Policy::Older(1),
            Policy::After(1),
            k.key(1),
        ]),
    ]
}

/// The key leaves of a satisfaction, in order: (leaf position, key index).
fn satisfy(
    p: &Policy,
    k: &Keys,
    rng: &mut Rng,
    leaf: &mut u8,
    uses: &mut Vec<(u8, usize)>,
) -> Satisfaction {
    match p {
        Policy::Key { pubkey_hash, .. } => {
            let i = k
                .hashes
                .iter()
                .position(|h| h == pubkey_hash)
                .expect("our key");
            uses.push((*leaf, i));
            *leaf += 1;
            Satisfaction::Key {
                pubkey: k.keys[i].pubkey().to_vec(),
                signature: Vec::new(),
            }
        }
        Policy::Preimage(_) => {
            *leaf += 1;
            Satisfaction::Preimage(k.secret)
        }
        Policy::Older(_) => {
            *leaf += 1;
            Satisfaction::Older
        }
        Policy::After(_) => {
            *leaf += 1;
            Satisfaction::After
        }
        Policy::All(c) => {
            Satisfaction::All(c.iter().map(|x| satisfy(x, k, rng, leaf, uses)).collect())
        }
        Policy::Any(c) => {
            let pick = rng.below(c.len() as u64) as usize;
            let mut chosen = None;
            for (j, child) in c.iter().enumerate() {
                if j == pick {
                    chosen = Some(satisfy(child, k, rng, leaf, uses));
                } else {
                    *leaf += child.leaf_count() as u8;
                }
            }
            Satisfaction::Any {
                index: pick as u8,
                branch: Box::new(chosen.expect("picked")),
            }
        }
    }
}

/// Puts the signatures in, in the order [`satisfy`] recorded the keys.
fn fill(s: &mut Satisfaction, sigs: &mut std::vec::IntoIter<Vec<u8>>) {
    match s {
        Satisfaction::Key { signature, .. } => *signature = sigs.next().expect("a signature"),
        Satisfaction::All(c) => c.iter_mut().for_each(|x| fill(x, sigs)),
        Satisfaction::Any { branch, .. } => fill(branch, sigs),
        _ => {}
    }
}

struct Spend {
    tx: Transaction,
    entry: UtxoEntry,
    witness: Witness,
    choices: Vec<u8>,
    /// (leaf, key index, signature).
    sigs: Vec<(u8, usize, Vec<u8>)>,
}

const BORN: u64 = 100;
const HEIGHT: u64 = 2_000;

fn honest_spend(p: &Policy, k: &Keys, rng: &mut Rng) -> Spend {
    let spent = p.output(Amount::from_units(1_000_000));
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: Hash256(rng.bytes32()),
                index: 0,
            },
            witness: Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(900_000),
            scheme: SchemeId::MlDsa87,
            pubkey_hash: Hash256([0x11; 32]),
        }],
        lock_time: 0,
    };
    let mut uses = Vec::new();
    let mut sat = satisfy(p, k, rng, &mut 0, &mut uses);
    let choices = sat.choices();
    let mut sigs = Vec::new();
    for (leaf, i) in &uses {
        let m = policy::sighash(&tx, 0, NET, &spent, p, *leaf, &choices);
        sigs.push((*leaf, *i, k.keys[*i].sign(&m)));
    }
    let mut it = sigs
        .iter()
        .map(|(_, _, s)| s.clone())
        .collect::<Vec<_>>()
        .into_iter();
    fill(&mut sat, &mut it);
    let witness = policy::witness(p, &sat);
    Spend {
        tx,
        entry: UtxoEntry {
            output: spent,
            height: BORN,
            is_coinbase: false,
        },
        witness,
        choices,
        sigs,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn policy_decoding_is_total_and_canonical() {
    let k = Keys::new();
    let mut rng = Rng(0x5150_2131_9011_0001);
    let seeds: Vec<Vec<u8>> = corpus(&k).iter().map(Policy::encode).collect();
    for s in &seeds {
        let p = Policy::decode(s).expect("corpus policy decodes");
        check_decoded(&p, s, "corpus");
    }
    let total = rounds(200_000);
    let mut decoded = 0u64;
    for round in 0..total {
        // Mutated valid encodings.
        let mut v = seeds[rng.below(seeds.len() as u64) as usize].clone();
        for _ in 0..=rng.below(3) {
            mutate(&mut rng, &mut v);
        }
        let r = std::panic::catch_unwind(|| Policy::decode(&v));
        match r {
            Err(_) => panic!("PANIC in Policy::decode at round {round}: {}", hex(&v)),
            Ok(Ok(p)) => {
                decoded += 1;
                check_decoded(&p, &v, &format!("mutated round {round}"));
            }
            Ok(Err(_)) => {}
        }
        // Random trees, valid or not, encoded as a careless or hostile
        // encoder would.
        if round % 4 == 0 {
            let t = random_policy(&mut rng, 1, &k.hashes, k.hash);
            let bytes = t.encode();
            match Policy::decode(&bytes) {
                Ok(p) => {
                    check_decoded(&p, &bytes, &format!("random round {round}"));
                    assert_eq!(p, t, "a random tree decoded as another tree");
                }
                Err(_) => {}
            }
        }
        // Raw noise, short.
        if round % 16 == 0 {
            let n = rng.below(80) as usize;
            let raw: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            if let Ok(p) = Policy::decode(&raw) {
                check_decoded(&p, &raw, "noise");
            }
        }
    }
    eprintln!("policy decoding: {total} rounds, {decoded} mutated encodings decoded");
}

#[test]
fn satisfaction_reading_never_panics_and_is_not_malleable() {
    let k = Keys::new();
    let mut rng = Rng(0x5150_2131_9011_0002);
    let spends: Vec<(Policy, Spend)> = corpus(&k)
        .into_iter()
        .flat_map(|p| {
            // Several honest spends per policy: every branch of its Anys.
            (0..4)
                .map(|_| {
                    let s = honest_spend(&p, &k, &mut rng);
                    (p.clone(), s)
                })
                .collect::<Vec<_>>()
        })
        .collect();
    for (p, s) in &spends {
        let r = policy::check_spend(&s.tx, 0, NET, &s.entry, HEIGHT, &s.witness);
        assert!(r.is_ok(), "honest spend of {p:?} refused: {r:?}");
        assert!(policy::precheck_spend(NET, &s.entry, HEIGHT, &s.witness).is_ok());
        assert_eq!(
            policy::verifications_claimed(&s.witness),
            s.sigs.len().max(1) as u64
        );
    }

    let total = rounds(40_000);
    let mut prechecked = 0u64;
    let mut checked = 0u64;
    for round in 0..total {
        let (p, s) = &spends[rng.below(spends.len() as u64) as usize];
        let mut w = s.witness.clone();
        match rng.below(4) {
            0 => {
                for _ in 0..=rng.below(2) {
                    mutate(&mut rng, &mut w.pubkey);
                }
            }
            1 => {
                // Swap in another policy's satisfaction, or another spend's.
                let (_, o) = &spends[rng.below(spends.len() as u64) as usize];
                if rng.one_in(2) {
                    w.signature = o.witness.signature.clone();
                } else {
                    w.pubkey = o.witness.pubkey.clone();
                }
            }
            _ => {
                for _ in 0..=rng.below(3) {
                    mutate(&mut rng, &mut w.signature);
                }
            }
        }
        let height = match rng.below(4) {
            0 => 0,
            1 => BORN,
            2 => u64::MAX,
            _ => HEIGHT,
        };
        let entry = UtxoEntry {
            output: s.entry.output,
            height: if rng.one_in(8) {
                u64::MAX - rng.below(100)
            } else {
                s.entry.height
            },
            is_coinbase: false,
        };
        let outcome = std::panic::catch_unwind(|| {
            let claimed = policy::verifications_claimed(&w);
            let lock = policy::relative_lock(&entry.output, &w);
            let avail = policy::available_at(&entry, &w);
            let pre = policy::precheck_spend(NET, &entry, height, &w).is_ok();
            (claimed, lock, avail, pre)
        });
        let (claimed, lock, avail, pre) = match outcome {
            Err(_) => panic!(
                "PANIC reading a satisfaction at round {round} (height {height}, born {}):\npolicy {}\nsatisfaction {}",
                entry.height,
                hex(&w.pubkey),
                hex(&w.signature)
            ),
            Ok(x) => x,
        };
        assert!(
            claimed >= 1 && claimed <= MAX_POLICY_LEAVES as u64,
            "verifications_claimed out of range: {claimed}"
        );
        assert!(lock <= u64::from(u16::MAX));
        if pre {
            assert!(
                avail <= height,
                "precheck passed at {height} but the spend is available at {avail}"
            );
            assert!(Policy::decode(&w.pubkey).is_ok());
        }
        match pre {
            true => {
                prechecked += 1;
                // The full check, signatures included: only the honest
                // witness may pass.
                if rng.one_in(2) {
                    checked += 1;
                    let r = policy::check_spend(&s.tx, 0, NET, &entry, height, &w);
                    if r.is_ok() {
                        assert_eq!(
                            w, s.witness,
                            "a policy witness other than the one signed was accepted (malleable) for {p:?}"
                        );
                    }
                }
            }
            false => {}
        }

        // One key's signature, as a channel peer's is checked.
        if round % 8 == 0 {
            let (leaf, ki, real) = &s.sigs[rng.below(s.sigs.len() as u64) as usize];
            let mut leaf_try = *leaf;
            let mut choices = s.choices.clone();
            let mut sig_try = real.clone();
            let mut pk = k.keys[*ki].pubkey().to_vec();
            let mut policy_bytes = s.witness.pubkey.clone();
            match rng.below(6) {
                0 => leaf_try = rng.byte(),
                1 => {
                    for _ in 0..rng.below(12) {
                        choices.push(rng.byte());
                    }
                }
                2 => {
                    let j = rng.below(sig_try.len() as u64) as usize;
                    sig_try[j] ^= 1;
                }
                3 => pk = k.keys[(*ki + 1) % 3].pubkey().to_vec(),
                4 => mutate(&mut rng, &mut policy_bytes),
                _ => {}
            }
            let r = std::panic::catch_unwind(|| {
                policy::check_signature(
                    &s.tx,
                    rng_index(round),
                    NET,
                    &s.entry.output,
                    &policy_bytes,
                    leaf_try,
                    &choices,
                    &pk,
                    &sig_try,
                )
            });
            match r {
                Err(_) => panic!(
                    "PANIC in check_signature at round {round}: leaf {leaf_try}, choices {choices:?}, policy {}",
                    hex(&policy_bytes)
                ),
                Ok(Ok(())) => {
                    assert!(
                        rng_index(round) == 0
                            && policy_bytes == s.witness.pubkey
                            && leaf_try == *leaf
                            && choices == s.choices
                            && sig_try == *real
                            && pk == k.keys[*ki].pubkey(),
                        "check_signature accepted a signature not made for these parameters (round {round})"
                    );
                }
                Ok(Err(_)) => {}
            }
        }
    }
    eprintln!(
        "satisfactions: {total} rounds, {prechecked} passed the precheck, {checked} fully checked"
    );
}

/// The input index a single-signature check names: 0 mostly, an index
/// beyond the transaction now and then.
fn rng_index(round: u64) -> u32 {
    match round % 64 {
        8 => 1,
        16 => u32::MAX,
        _ => 0,
    }
}
