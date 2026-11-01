//! FUZZ (red-team campaign 6, round 2): the payment-channel engine past the
//! handshake, driven by a peer that holds its own key and signs whatever it
//! likes.
//!
//! The decoders were fuzzed already (`tests/fuzz_decoders.rs`); what lies
//! behind them was not. A channel peer is not a stranger on the wire: it owns
//! one of the two funding keys, so every signature check that guards a handler
//! is one it can pass for any content of its choosing. This file plays that
//! peer as a "puppet": no state machine of its own, only its key, its
//! revocation shachain and the points the victim announced. It signs the
//! victim's commitments at any state and balances, any control message, any
//! reestablish counters, any splice transaction, and delivers them to a real
//! [`Machine`] (the victim) in random order, mixed with honest payments,
//! honest splices, crossed proposals, restarts from the journal, replays,
//! reflections of the victim's own messages, and byte-level mutations of every
//! frame exchanged so far.
//!
//! What is asserted:
//!
//! - nothing panics (the release build aborts on a panic: a remote crash);
//! - the balances always sum to the capacity, and the local commitment number
//!   never goes backwards;
//! - a message the puppet could not honestly send (wrong direction, wrong
//!   sum, wrong state, bad signature, replay, mutation) changes NOTHING:
//!   phase, counters, balances, capacity, splice and funding are as before;
//! - an accepted splice satisfies every rule a splice must (re-derived here
//!   independently), and the victim's own balance is untouched by it;
//! - a close accepted from the puppet has a fee within the bounds and charged
//!   to the puppet, and once the victim has signed it no update is accepted;
//! - the transactions the victim completes (splice input, cooperative close)
//!   pass the consensus check of the policy spend;
//! - a reopened journal rebuilds exactly the same channel;
//! - `check_behind_proof` never accepts anything the puppet can build, and
//!   `behind_proof` only ever reveals the puppet's own secret.
//!
//! Rounds: `Q21_CHANNEL_FUZZ_ROUNDS` (default per test below).
//!
//! Run: `cargo test --features mldsa,audit --test fuzz_channel_engine`

#![cfg(feature = "mldsa")]

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::channel::journal::Balances;
use q21_core::channel::keys::CHANNEL_SCHEME;
use q21_core::channel::machine::{splice_sequence, SyncVerdict};
use q21_core::channel::messages::{control_message, CONTROL_CLOSE, CONTROL_READY};
use q21_core::channel::txbuild::{self, key_output, ChannelParams, FeeTier, ACCEPTOR, FUNDER};
use q21_core::channel::{ChannelError, ChannelKey, Machine, Message, Phase, Revocation, Signer};
use q21_core::channel::{MAX_CAPACITY, MIN_CAPACITY};
use q21_core::consensus::{MIN_OUTPUT_VALUE, UNITS_PER_COIN};
use q21_core::hash::{tagged_hash_parts, Hash256};
use q21_core::sha256::sha256;
use q21_core::shachain;
use q21_core::tx::{OutPoint, Transaction, TxIn, Witness};
use q21_core::utxo::UtxoEntry;

const NET: Network = Network::Regtest;
const CAP: u64 = 50 * UNITS_PER_COIN;
const DELAY: u16 = 12;
const DEPTH: u16 = 2;
const RATE: u64 = 10;
const VICTIM_PAYOUT: Hash256 = Hash256([0xa0; 32]);
const PUPPET_PAYOUT: Hash256 = Hash256([0xf0; 32]);

fn rounds(default: usize) -> usize {
    std::env::var("Q21_CHANNEL_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Deterministic generator and scratch directories
// ---------------------------------------------------------------------------

/// splitmix64: reproducible, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// In `[0, n)`; 0 when `n` is 0.
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
    fn pick_u64(&mut self, v: &[u64]) -> u64 {
        v[self.below(v.len() as u64) as usize]
    }
    /// An integer a careless bound would mishandle: a fixed edge value, a
    /// value next to one of `near`, or noise.
    fn edge(&mut self, near: &[u64]) -> u64 {
        const FIXED: [u64; 13] = [
            0,
            1,
            2,
            3,
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            1 << 32,
            u32::MAX as u64,
            (1 << 48) - 1,
            1 << 48,
            i64::MAX as u64,
            MAX_CAPACITY,
        ];
        if !near.is_empty() && self.one_in(2) {
            let base = self.pick_u64(near);
            match self.below(5) {
                0 => base,
                1 => base.wrapping_add(1),
                2 => base.wrapping_sub(1),
                3 => base.wrapping_add(self.below(1000)),
                _ => base.wrapping_sub(self.below(1000)),
            }
        } else if self.one_in(5) {
            self.next()
        } else {
            self.pick_u64(&FIXED)
        }
    }
}

static DIRS: AtomicU64 = AtomicU64::new(0);

/// A scratch directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let n = DIRS.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("q21-fuzz-chan-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch directory");
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sig_len() -> usize {
    CHANNEL_SCHEME.sig_len()
}

fn garbage_sigs(rng: &mut Rng) -> [Vec<u8>; 3] {
    let b = rng.byte();
    [
        vec![b; sig_len()],
        vec![b ^ 1; sig_len()],
        vec![b ^ 2; sig_len()],
    ]
}

/// A short, printable view of a message (signatures are kilobytes).
fn summary(m: &Message) -> String {
    let s = format!("{m:?}");
    let n = s.chars().count();
    if n > 400 {
        format!("{}... ({n} chars)", s.chars().take(400).collect::<String>())
    } else {
        s
    }
}

fn hex(v: &[u8]) -> String {
    let mut s: String = v.iter().take(160).map(|b| format!("{b:02x}")).collect();
    if v.len() > 160 {
        s.push_str(&format!("... ({} bytes)", v.len()));
    }
    s
}

// ---------------------------------------------------------------------------
// The puppet: the peer's key, its shachain, and nothing else
// ---------------------------------------------------------------------------

struct Puppet {
    key: ChannelKey,
    root: [u8; 32],
    /// FUNDER or ACCEPTOR.
    idx: usize,
    /// The victim's announced revocation points, by state.
    victim_points: BTreeMap<u64, Hash256>,
    /// The highest control sequence number the victim accepted from us.
    seq: u64,
}

impl Puppet {
    fn new(seed: [u8; 32], root: [u8; 32], idx: usize) -> Puppet {
        Puppet {
            key: ChannelKey::from_seed(&seed),
            root,
            idx,
            victim_points: BTreeMap::new(),
            seq: 0,
        }
    }
    fn pubkey(&self) -> Vec<u8> {
        self.key.pubkey().to_vec()
    }
    fn sign(&self, m: &Hash256) -> Vec<u8> {
        self.key.sign(m)
    }
    /// Our secret of state `n`, derived as the engine derives its own.
    fn secret(&self, n: u64) -> [u8; 32] {
        shachain::derive(&self.root, shachain::MAX_INDEX - n)
    }
    fn point(&self, n: u64) -> Hash256 {
        Hash256(sha256(&self.secret(n)))
    }
    /// The revocation of our state `m`, announcing the point of `m + 2`.
    fn revocation(&self, m: u64) -> Revocation {
        Revocation {
            secret: self.secret(m),
            next_hash: self.point(m + 2),
        }
    }
    fn victim_point(&self, n: u64) -> Option<Hash256> {
        self.victim_points.get(&n).copied()
    }

    /// Our signatures, at each tier, over the victim's commitment `n` at
    /// `bal`, built on `params`, spending `outpoint`, with the victim's point
    /// `point` and the fee the victim computes from `fee_params`.
    #[allow(clippy::too_many_arguments)]
    fn sign_commitment(
        &self,
        victim_index: usize,
        params: &ChannelParams,
        fee_params: &ChannelParams,
        outpoint: OutPoint,
        n: u64,
        bal: Balances,
        point: Hash256,
    ) -> [Vec<u8>; 3] {
        let mut sigs: [Vec<u8>; 3] = Default::default();
        for tier in FeeTier::ALL {
            let fee = txbuild::commitment_fee(fee_params, txbuild::tier_rate(RATE, tier));
            let mut c = params.commitment(victim_index, n, bal, fee, point);
            c.tx.inputs[0].prev_out = outpoint;
            let m = params.funding_sighash(&c.tx, NET, self.idx);
            sigs[tier as usize] = self.sign(&m);
        }
        sigs
    }

    /// Signatures over the victim's commitment `n` at `bal` on its current
    /// funding, if we know its point for `n`.
    fn update_sigs(&self, v: &Machine, n: u64, bal: Balances) -> Option<[Vec<u8>; 3]> {
        let point = self.victim_point(n)?;
        let outpoint = v.funding_outpoint()?;
        let p = v.params().clone();
        Some(self.sign_commitment(v.our_index(), &p, &p, outpoint, n, bal, point))
    }

    fn control(&self, cid: Hash256, seq: u64, kind: u8, fields: &[u8]) -> Vec<u8> {
        self.sign(&control_message(cid, self.idx as u8, seq, kind, fields))
    }
    fn close(&self, cid: Hash256, fee: u64, seq: u64) -> Message {
        Message::Close {
            fee,
            seq,
            signature: self.control(cid, seq, CONTROL_CLOSE, &fee.to_le_bytes()),
        }
    }
    fn ready(&self, cid: Hash256, seq: u64) -> Message {
        Message::Ready {
            seq,
            signature: self.control(cid, seq, CONTROL_READY, &[]),
        }
    }
    /// A reestablish with any counters, proven by our key as the engine
    /// proves its own (`reestablish_message` in machine.rs).
    fn reestablish(
        &self,
        cid: Hash256,
        counters: [u64; 4],
        nonce: [u8; 32],
        direction: u8,
    ) -> Message {
        let mut c = [0u8; 32];
        for (i, v) in counters.iter().enumerate() {
            c[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        let m = tagged_hash_parts(
            "Q21/channel/reestablish-proof",
            &[cid.as_bytes(), &nonce, &[direction], &c],
        );
        Message::Reestablish {
            channel_id: cid,
            local_commit_number: counters[0],
            remote_commit_number: counters[1],
            next_revocation_sent: counters[2],
            next_revocation_recv: counters[3],
            nonce,
            direction,
            proof: self.sign(&m),
        }
    }
}

/// The counters an honest peer in step with `c` reports: its local is our
/// remote, its revocations sent are ours received, and so on.
fn mirror(c: [u64; 4]) -> [u64; 4] {
    [c[1], c[0], c[3], c[2]]
}

// ---------------------------------------------------------------------------
// What must not move
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snap {
    phase: Phase,
    counters: [u64; 4],
    balances: Balances,
    capacity: u64,
    splicing: bool,
    funding: Option<OutPoint>,
}

impl Snap {
    fn of(v: &Machine) -> Snap {
        Snap {
            phase: v.phase(),
            counters: v.sync_counters(),
            balances: v.balances(),
            capacity: v.params().capacity.units(),
            splicing: v.splicing(),
            funding: v.funding_outpoint(),
        }
    }
}

// ---------------------------------------------------------------------------
// Delivery: every handler a peer's frame can reach
// ---------------------------------------------------------------------------

/// Delivers `msg` to the handler the node would call for it (sometimes a
/// sibling handler the same frame type can also reach). Returns the
/// victim's answers.
fn deliver(
    v: &mut Machine,
    msg: &Message,
    rng: &mut Rng,
    scratch: &Path,
) -> Result<Vec<Message>, ChannelError> {
    match msg {
        Message::Open { .. } => {
            // An Open always reaches a fresh acceptor.
            let path = scratch.join(format!("open-{}.jrnl", rng.next()));
            let r = Machine::accept(
                &path,
                NET,
                Box::new(ChannelKey::from_seed(&[0x33; 32])),
                RATE,
                msg,
                VICTIM_PAYOUT,
                PUPPET_PAYOUT,
            );
            let _ = std::fs::remove_file(&path);
            r.map(|(_, a)| vec![a])
        }
        Message::Accept { .. } => v.on_accept(msg).map(|()| Vec::new()),
        Message::Funding { .. } => v.on_funding(msg).map(|m| vec![m]),
        Message::FundingSigned { .. } => v.on_funding_signed(msg).map(|()| Vec::new()),
        Message::Ready { .. } => v.on_ready(msg).map(|()| Vec::new()),
        Message::Update { .. } => {
            if rng.one_in(3) {
                v.on_update(msg).map(|m| vec![m])
            } else {
                v.on_peer_update(msg)
            }
        }
        Message::Ack { .. } => v.on_ack(msg).map(|m| vec![m]),
        Message::Revoke { .. } => v.on_revoke(msg).map(|()| Vec::new()),
        Message::Reestablish { .. } => v.on_reestablish(msg),
        Message::Close { .. } => {
            if rng.one_in(4) {
                v.on_close_crossing(msg).map(|()| Vec::new())
            } else {
                v.on_close(msg).map(|m| vec![m])
            }
        }
        Message::CloseSigned { .. } => v.on_close_signed(msg).map(|_| Vec::new()),
        Message::Error { .. } => Ok(Vec::new()),
        Message::Splice { .. } => v.on_splice(msg),
        Message::SpliceAck { .. } => v.on_splice_ack(msg).map(|_| Vec::new()),
        Message::SpliceSig { .. } => v.on_splice_sig(msg).map(|_| Vec::new()),
        Message::SpliceLocked { .. } => v.on_splice_locked(msg).map(|()| Vec::new()),
        Message::SpliceBusy { .. } => v.on_splice_busy(msg).map(|_| Vec::new()),
        Message::BehindProof { .. } => {
            assert!(
                !v.check_behind_proof(msg),
                "check_behind_proof accepted a proof the peer could build: {}",
                summary(msg)
            );
            Ok(Vec::new())
        }
    }
}

/// Byte-level mutation of an encoded frame (same operators as
/// `tests/fuzz_decoders.rs`, plus 64-bit fields set to edge values).
fn mutate_bytes(rng: &mut Rng, v: &mut Vec<u8>) {
    if v.is_empty() {
        v.push(rng.byte());
        return;
    }
    match rng.below(8) {
        0 => {
            let i = rng.below(v.len() as u64) as usize;
            v[i] ^= 1u8 << rng.below(8);
        }
        1 => {
            let i = rng.below(v.len() as u64) as usize;
            v[i] = rng.byte();
        }
        2 => {
            let n = rng.below(v.len() as u64) as usize;
            v.truncate(n);
        }
        3 => {
            for _ in 0..(1 + rng.below(16)) {
                v.push(rng.byte());
            }
        }
        4 | 5 => {
            // A u64 field right after the version and type bytes (state,
            // fee, seq, capacity...) or anywhere, set to an edge value.
            if v.len() >= 10 {
                let i = if rng.one_in(2) {
                    2
                } else {
                    rng.below((v.len() - 7) as u64) as usize
                };
                let x = rng.edge(&[]);
                v[i..i + 8].copy_from_slice(&x.to_le_bytes());
            }
        }
        6 => {
            // The type byte.
            if v.len() >= 2 {
                v[1] = rng.below(21) as u8;
            }
        }
        _ => {
            let i = rng.below(v.len() as u64) as usize;
            let n = 1 + rng.below(8) as usize;
            let piece: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            v.splice(i..i, piece);
        }
    }
}

/// Field-level mutation, keeping the signatures: the shape a peer that
/// replays or edits a captured frame produces.
fn mutate_fields(rng: &mut Rng, m: &Message) -> Message {
    let mut m = m.clone();
    match &mut m {
        Message::Update {
            state,
            balances,
            tier_sigs,
        } => match rng.below(4) {
            0 => *state = rng.edge(&[*state]),
            1 => {
                let i = rng.below(2) as usize;
                let x = rng.edge(&[balances[0], balances[1]]);
                balances[i] = x;
            }
            2 => tier_sigs.swap(0, 2),
            _ => {
                let b = *balances;
                *balances = [b[1], b[0]];
            }
        },
        Message::Ack {
            state,
            tier_sigs,
            revocation,
        } => match rng.below(3) {
            0 => *state = rng.edge(&[*state]),
            1 => tier_sigs.swap(0, 1),
            _ => revocation.secret[rng.below(32) as usize] ^= 1,
        },
        Message::Revoke { state, revocation } => match rng.below(3) {
            0 => *state = rng.edge(&[*state]),
            1 => revocation.secret = rng.bytes32(),
            _ => revocation.next_hash = Hash256(rng.bytes32()),
        },
        Message::Reestablish {
            local_commit_number,
            remote_commit_number,
            next_revocation_sent,
            next_revocation_recv,
            direction,
            ..
        } => match rng.below(5) {
            0 => *local_commit_number = rng.edge(&[*local_commit_number]),
            1 => *remote_commit_number = rng.edge(&[*remote_commit_number]),
            2 => *next_revocation_sent = rng.edge(&[*next_revocation_sent]),
            3 => *next_revocation_recv = rng.edge(&[*next_revocation_recv]),
            _ => *direction ^= 1,
        },
        Message::Close { fee, seq, .. } => {
            if rng.one_in(2) {
                *fee = rng.edge(&[*fee]);
            } else {
                *seq = rng.edge(&[*seq]);
            }
        }
        Message::Ready { seq, .. } => *seq = rng.edge(&[*seq]),
        Message::CloseSigned { fee, .. } => *fee = rng.edge(&[*fee]),
        Message::Splice {
            state,
            add,
            funding_input,
            tx,
            ..
        } => match rng.below(4) {
            0 => *state = rng.edge(&[*state]),
            1 => *add = rng.edge(&[*add]),
            2 => *funding_input = rng.edge(&[u64::from(*funding_input)]) as u32,
            _ => mutate_bytes(rng, tx),
        },
        Message::SpliceAck { state, tier_sigs } => {
            if rng.one_in(2) {
                *state = rng.edge(&[*state]);
            } else {
                tier_sigs.swap(1, 2);
            }
        }
        Message::SpliceSig { state, .. } => *state = rng.edge(&[*state]),
        Message::SpliceLocked { state, revocation } => {
            if rng.one_in(2) {
                *state = rng.edge(&[*state]);
            } else {
                revocation.secret = rng.bytes32();
            }
        }
        Message::SpliceBusy { state } => *state = rng.edge(&[*state]),
        Message::BehindProof { state, secret } => {
            if rng.one_in(2) {
                *state = rng.edge(&[*state]);
            } else {
                secret[0] ^= 0x80;
            }
        }
        Message::Funding { funding_index, .. } => *funding_index ^= 1,
        Message::Open { capacity, .. } => *capacity = rng.edge(&[*capacity, MIN_CAPACITY]),
        Message::Accept { .. } | Message::FundingSigned { .. } | Message::Error { .. } => {}
    }
    m
}

/// Whether `tx` is a splice the rules allow (re-derived from the protocol
/// description, independently of `check_splice_tx`).
fn splice_is_well_formed(
    tx: &Transaction,
    state: u64,
    next_state: u64,
    funding_input: u32,
    add: u64,
    old_funding: OutPoint,
    old_params: &ChannelParams,
) -> bool {
    let k = funding_input as usize;
    if state != next_state || state == 0 || tx.inputs.len() < 2 || k + 1 != tx.inputs.len() {
        return false;
    }
    if tx.inputs[k].prev_out != old_funding || tx.inputs[k].sequence != splice_sequence(state) {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    for i in &tx.inputs {
        if !seen.insert(i.prev_out)
            || !i.witness.pubkey.is_empty()
            || !i.witness.signature.is_empty()
        {
            return false;
        }
    }
    if tx.inputs[..k].iter().any(|i| i.prev_out == old_funding) || tx.lock_time != 0 {
        return false;
    }
    if add < MIN_OUTPUT_VALUE {
        return false;
    }
    let Some(cap) = old_params
        .capacity
        .units()
        .checked_add(add)
        .filter(|c| *c <= MAX_CAPACITY)
    else {
        return false;
    };
    let new = ChannelParams {
        capacity: Amount::from_units(cap),
        ..old_params.clone()
    };
    tx.outputs.first() == Some(&new.funding_output())
}

// ---------------------------------------------------------------------------
// An episode: one victim, one puppet
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    ok: BTreeMap<&'static str, u64>,
    err: BTreeMap<&'static str, u64>,
}

impl Stats {
    fn note<T, E>(&mut self, what: &'static str, r: &Result<T, E>) {
        let m = if r.is_ok() {
            &mut self.ok
        } else {
            &mut self.err
        };
        *m.entry(what).or_insert(0) += 1;
    }
    fn print(&self, test: &str) {
        let mut keys: Vec<&&str> = self.ok.keys().chain(self.err.keys()).collect();
        keys.sort();
        keys.dedup();
        eprintln!("--- {test}: outcomes (ok / err) ---");
        for k in keys {
            eprintln!(
                "  {k:<28} {:>6} / {:>6}",
                self.ok.get(*k).copied().unwrap_or(0),
                self.err.get(*k).copied().unwrap_or(0)
            );
        }
    }
}

struct Episode {
    dir: TempDir,
    v: Machine,
    vseed: [u8; 32],
    p: Puppet,
    /// The victim's index, and the puppet's.
    us: usize,
    them: usize,
    corpus: Vec<Message>,
    max_local: Option<u64>,
    /// A close the victim signed: no update may follow.
    close_signed: bool,
}

const CORPUS_KEEP: usize = 8;
const CORPUS_MAX: usize = 160;

impl Episode {
    fn open(rng: &mut Rng, victim_is_funder: bool) -> Episode {
        let dir = TempDir::new("eng");
        let vseed = rng.bytes32();
        let pseed = rng.bytes32();
        let proot = rng.bytes32();
        let outpoint = OutPoint {
            txid: Hash256(rng.bytes32()),
            index: rng.below(4) as u32,
        };
        let jpath = dir.path().join("victim.jrnl");
        let mut corpus = Vec::new();
        let (v, p, us) = if victim_is_funder {
            let mut p = Puppet::new(pseed, proot, ACCEPTOR);
            let (mut v, open) = Machine::new_funder(
                &jpath,
                NET,
                Box::new(ChannelKey::from_seed(&vseed)),
                p.pubkey(),
                CAP,
                DELAY,
                DEPTH,
                RATE,
                VICTIM_PAYOUT,
                PUPPET_PAYOUT,
            )
            .expect("new_funder");
            if let Message::Open { first_hashes, .. } = &open {
                for (i, h) in first_hashes.iter().enumerate() {
                    p.victim_points.insert(i as u64, *h);
                }
            }
            corpus.push(open);
            let accept = Message::Accept {
                acceptor_pubkey: p.pubkey(),
                first_hashes: vec![p.point(0), p.point(1)],
            };
            v.on_accept(&accept).expect("on_accept");
            corpus.push(accept);
            let funding = v.funding_created(outpoint).expect("funding_created");
            corpus.push(funding);
            let sigs = p.update_sigs(&v, 0, [CAP, 0]).expect("victim point 0");
            let fs = Message::FundingSigned { tier_sigs: sigs };
            v.on_funding_signed(&fs).expect("on_funding_signed");
            corpus.push(fs);
            (v, p, FUNDER)
        } else {
            let mut p = Puppet::new(pseed, proot, FUNDER);
            let open = Message::Open {
                capacity: CAP,
                delay: DELAY,
                funding_depth: DEPTH,
                funder_pubkey: p.pubkey(),
                first_hashes: vec![p.point(0), p.point(1)],
            };
            let (mut v, accept) = Machine::accept(
                &jpath,
                NET,
                Box::new(ChannelKey::from_seed(&vseed)),
                RATE,
                &open,
                VICTIM_PAYOUT,
                PUPPET_PAYOUT,
            )
            .expect("accept");
            if let Message::Accept { first_hashes, .. } = &accept {
                for (i, h) in first_hashes.iter().enumerate() {
                    p.victim_points.insert(i as u64, *h);
                }
            }
            corpus.push(open);
            corpus.push(accept);
            let point0 = p.victim_point(0).expect("victim point 0");
            let params = v.params().clone();
            let sigs = p.sign_commitment(ACCEPTOR, &params, &params, outpoint, 0, [CAP, 0], point0);
            let funding = Message::Funding {
                funding_txid: outpoint.txid,
                funding_index: outpoint.index,
                tier_sigs: sigs,
            };
            let fs = v.on_funding(&funding).expect("on_funding");
            corpus.push(funding);
            corpus.push(fs);
            (v, p, ACCEPTOR)
        };
        let mut e = Episode {
            dir,
            v,
            vseed,
            p,
            us,
            them: 1 - us,
            corpus,
            max_local: None,
            close_signed: false,
        };
        let ready = e.v.funding_confirmed().expect("funding_confirmed");
        e.remember(ready);
        let pr = e.p.ready(e.cid(), 1);
        e.v.on_ready(&pr).expect("on_ready");
        e.p.seq = 1;
        e.remember(pr);
        assert_eq!(e.v.phase(), Phase::Open);
        e.invariants("open");
        e
    }

    fn cid(&self) -> Hash256 {
        self.v.channel_id()
    }

    fn remember(&mut self, m: Message) {
        if self.corpus.len() >= CORPUS_MAX {
            self.corpus.remove(CORPUS_KEEP);
        }
        self.corpus.push(m);
    }

    fn invariants(&mut self, ctx: &str) {
        let v = &self.v;
        let b = v.balances();
        let cap = v.params().capacity.units();
        assert_eq!(
            b[0].checked_add(b[1]),
            Some(cap),
            "{ctx}: balances {b:?} do not sum to the capacity {cap}"
        );
        if !v.splicing() {
            let l = v.latest_balances();
            assert_eq!(
                l[0].checked_add(l[1]),
                Some(cap),
                "{ctx}: latest balances {l:?} do not sum to the capacity {cap}"
            );
        }
        assert!(
            v.irrevocable_balance() <= b[self.us],
            "{ctx}: irrevocable balance above the balance"
        );
        let lc = v.local_commit_number();
        assert!(
            lc >= self.max_local,
            "{ctx}: local commitment number went backwards: {:?} -> {lc:?}",
            self.max_local
        );
        self.max_local = lc;
        let r = v.retained();
        assert!(
            r[0] <= 2 && r[1] <= 2 && r[2] <= 3 && r[3] <= 16 && r[4] <= 64 && r[5] <= 49,
            "{ctx}: per-state memory unbounded: {r:?}"
        );
    }

    fn unchanged(&self, before: &Snap, ctx: &str) {
        let now = Snap::of(&self.v);
        assert_eq!(
            *before, now,
            "{ctx}: a message the peer could not honestly send changed the channel"
        );
    }

    /// Delivers, catching a panic to name the input that caused it.
    fn guarded_deliver(
        &mut self,
        msg: &Message,
        rng: &mut Rng,
        ctx: &str,
    ) -> Result<Vec<Message>, ChannelError> {
        let scratch = self.dir.path().to_path_buf();
        let v = &mut self.v;
        match catch_unwind(AssertUnwindSafe(|| deliver(v, msg, rng, &scratch))) {
            Ok(r) => r,
            Err(_) => panic!(
                "PANIC in the channel engine ({ctx}) on a peer message: {}\nencoded: {}",
                summary(msg),
                hex(&msg.encode())
            ),
        }
    }

    // --- Honest moves -------------------------------------------------------

    /// The puppet pays `amount` to the victim, by the book.
    fn puppet_pays(&mut self, amount: u64) -> Result<(), String> {
        let n = self.v.next_state_number();
        let mut bal = self.v.balances();
        bal[self.them] = bal[self.them].checked_sub(amount).ok_or("amount")?;
        bal[self.us] += amount;
        let sigs = self
            .p
            .update_sigs(&self.v, n, bal)
            .ok_or_else(|| format!("no victim point for {n}"))?;
        let upd = Message::Update {
            state: n,
            balances: bal,
            tier_sigs: sigs,
        };
        let out = self
            .v
            .on_peer_update(&upd)
            .map_err(|e| format!("on_peer_update({n}): {e:?}"))?;
        self.remember(upd);
        let (st, secret, next) = out
            .iter()
            .find_map(|m| match m {
                Message::Ack {
                    state, revocation, ..
                } => Some((*state, revocation.secret, revocation.next_hash)),
                _ => None,
            })
            .ok_or("no Ack")?;
        assert_eq!(st, n, "the Ack names another state");
        if let Some(pt) = self.p.victim_point(n - 1) {
            assert_eq!(
                Hash256(sha256(&secret)),
                pt,
                "the victim revealed a secret that does not match its own point"
            );
        }
        self.p.victim_points.insert(n + 1, next);
        for m in out {
            self.remember(m);
        }
        let rev = Message::Revoke {
            state: n,
            revocation: self.p.revocation(n - 1),
        };
        self.v
            .on_revoke(&rev)
            .map_err(|e| format!("on_revoke({n}): {e:?}"))?;
        self.remember(rev);
        assert_eq!(self.v.balances(), bal, "an honest payment did not settle");
        Ok(())
    }

    /// The victim pays `amount` to the puppet, by the book.
    fn victim_pays(&mut self, amount: u64) -> Result<(), String> {
        let mut bal = self.v.balances();
        bal[self.us] = bal[self.us].checked_sub(amount).ok_or("amount")?;
        bal[self.them] += amount;
        let upd = self.v.propose(bal).map_err(|e| format!("propose: {e:?}"))?;
        let n = match &upd {
            Message::Update { state, .. } => *state,
            other => return Err(format!("propose returned {}", summary(other))),
        };
        self.remember(upd);
        let sigs = self
            .p
            .update_sigs(&self.v, n, bal)
            .ok_or_else(|| format!("no victim point for {n}"))?;
        let ack = Message::Ack {
            state: n,
            tier_sigs: sigs,
            revocation: self.p.revocation(n - 1),
        };
        let rev = self
            .v
            .on_ack(&ack)
            .map_err(|e| format!("on_ack({n}): {e:?}"))?;
        self.remember(ack);
        self.take_victim_revoke(&rev, n)?;
        self.remember(rev);
        assert_eq!(self.v.balances(), bal, "an honest payment did not settle");
        Ok(())
    }

    /// Checks the victim's `Revoke` of state `n` and records the point it
    /// announces.
    fn take_victim_revoke(&mut self, rev: &Message, n: u64) -> Result<(), String> {
        match rev {
            Message::Revoke { state, revocation } if *state == n => {
                if let Some(pt) = self.p.victim_point(n - 1) {
                    assert_eq!(
                        Hash256(sha256(&revocation.secret)),
                        pt,
                        "the victim revealed a secret that does not match its own point"
                    );
                }
                self.p.victim_points.insert(n + 1, revocation.next_hash);
                Ok(())
            }
            other => Err(format!("expected Revoke({n}), got {}", summary(other))),
        }
    }

    /// An honest reestablish: the victim must find both sides in step.
    fn resync(&mut self, rng: &mut Rng) {
        let c = mirror(self.v.sync_counters());
        let m = self
            .p
            .reestablish(self.cid(), c, rng.bytes32(), self.p.idx as u8);
        let r = self.v.on_reestablish(&m);
        assert!(r.is_ok(), "honest reestablish refused: {r:?}");
        assert_eq!(
            self.v.sync(),
            SyncVerdict::InStep,
            "honest reestablish not in step: victim {:?}, puppet {c:?}",
            self.v.sync_counters()
        );
        self.remember(m);
    }

    /// Both sides propose the same state at once, and their merge settles.
    fn crossed(&mut self, rng: &mut Rng, stats: &mut Stats) -> Result<(), String> {
        let (sv, sp) = (self.v.sendable(), self.v.remote_sendable());
        if sv == 0 || sp == 0 {
            return Ok(());
        }
        let base = self.v.balances();
        let n = self.v.next_state_number();
        let xv = 1 + rng.below(sv);
        let xp = 1 + rng.below(sp);
        let mut bv = base;
        bv[self.us] -= xv;
        bv[self.them] += xv;
        let mut bp = base;
        bp[self.them] -= xp;
        bp[self.us] += xp;
        let upd_v = self.v.propose(bv).map_err(|e| format!("propose: {e:?}"))?;
        self.remember(upd_v);

        // A crossing update that lowers the victim below the settled state,
        // properly signed: refused, and nothing moves.
        if base[self.us] > 0 && rng.one_in(2) {
            let mut bad = base;
            let take = 1 + rng.below(base[self.us]);
            bad[self.us] -= take;
            bad[self.them] += take;
            if let Some(sigs) = self.p.update_sigs(&self.v, n, bad) {
                let before = Snap::of(&self.v);
                let m = Message::Update {
                    state: n,
                    balances: bad,
                    tier_sigs: sigs,
                };
                let r = self.guarded_deliver(&m, rng, "crossing update draining the victim");
                stats.note("crossed/draining", &r);
                assert!(r.is_err(), "a crossing update lowering our side was taken");
                self.unchanged(&before, "crossing update draining the victim");
            }
        }

        let sigs = self.p.update_sigs(&self.v, n, bp).ok_or("no point")?;
        let upd_p = Message::Update {
            state: n,
            balances: bp,
            tier_sigs: sigs,
        };
        let out = self
            .v
            .on_peer_update(&upd_p)
            .map_err(|e| format!("crossed on_peer_update: {e:?}"))?;
        self.remember(upd_p);
        let rev = out
            .iter()
            .find(|m| matches!(m, Message::Revoke { .. }))
            .cloned()
            .ok_or("no Revoke for the crossed state")?;
        self.take_victim_revoke(&rev, n)?;
        for m in out {
            self.remember(m);
        }
        let prev = Message::Revoke {
            state: n,
            revocation: self.p.revocation(n - 1),
        };
        self.v
            .on_revoke(&prev)
            .map_err(|e| format!("crossed on_revoke: {e:?}"))?;
        self.remember(prev);
        let merged = [bv[0] + bp[0] - base[0], bv[1] + bp[1] - base[1]];
        if self.v.has_initiative() {
            let m = self
                .v
                .merge_if_ready()
                .map_err(|e| format!("merge_if_ready: {e:?}"))?
                .ok_or("the side with the initiative did not propose the merge")?;
            match &m {
                Message::Update {
                    state, balances, ..
                } => {
                    assert_eq!(*state, n + 1);
                    assert_eq!(*balances, merged, "the merge is not both payments");
                }
                other => return Err(format!("merge is {}", summary(other))),
            }
            self.remember(m);
            let sigs = self
                .p
                .update_sigs(&self.v, n + 1, merged)
                .ok_or("no point")?;
            let ack = Message::Ack {
                state: n + 1,
                tier_sigs: sigs,
                revocation: self.p.revocation(n),
            };
            let rev = self
                .v
                .on_ack(&ack)
                .map_err(|e| format!("merge on_ack: {e:?}"))?;
            self.remember(ack);
            self.take_victim_revoke(&rev, n + 1)?;
            self.remember(rev);
        } else {
            let none = self
                .v
                .merge_if_ready()
                .map_err(|e| format!("merge_if_ready: {e:?}"))?;
            assert!(none.is_none(), "the side without the initiative proposed");
            // A "merge" that pays the victim more than both payments,
            // validly signed: still refused, it is not the merge.
            if merged[self.them] > 0 && rng.one_in(2) {
                let mut more = merged;
                more[self.them] -= 1;
                more[self.us] += 1;
                if let Some(sigs) = self.p.update_sigs(&self.v, n + 1, more) {
                    let before = Snap::of(&self.v);
                    let m = Message::Update {
                        state: n + 1,
                        balances: more,
                        tier_sigs: sigs,
                    };
                    let r = self.guarded_deliver(&m, rng, "not the merge");
                    stats.note("crossed/not-the-merge", &r);
                    assert!(r.is_err(), "an update other than the merge was taken");
                    self.unchanged(&before, "not the merge");
                }
            }
            let sigs = self
                .p
                .update_sigs(&self.v, n + 1, merged)
                .ok_or("no point")?;
            let m = Message::Update {
                state: n + 1,
                balances: merged,
                tier_sigs: sigs,
            };
            let out = self
                .v
                .on_peer_update(&m)
                .map_err(|e| format!("merge on_peer_update: {e:?}"))?;
            self.remember(m);
            let (st, next) = out
                .iter()
                .find_map(|m| match m {
                    Message::Ack {
                        state, revocation, ..
                    } => Some((*state, revocation.next_hash)),
                    _ => None,
                })
                .ok_or("no Ack of the merge")?;
            assert_eq!(st, n + 1);
            self.p.victim_points.insert(n + 2, next);
            for m in out {
                self.remember(m);
            }
            let r = Message::Revoke {
                state: n + 1,
                revocation: self.p.revocation(n),
            };
            self.v
                .on_revoke(&r)
                .map_err(|e| format!("merge on_revoke: {e:?}"))?;
            self.remember(r);
        }
        assert_eq!(self.v.balances(), merged, "the merge did not settle");
        Ok(())
    }

    // --- Splices ------------------------------------------------------------

    /// The puppet adds coins, with a splice transaction that is valid or
    /// broken in one of many ways, always signed consistently with what it
    /// claims. Whatever the victim accepts must be a valid splice.
    fn puppet_splice(&mut self, rng: &mut Rng, stats: &mut Stats) -> Result<(), String> {
        self.resync(rng);
        let n = self.v.next_state_number();
        let old = self.v.params().clone();
        let old_cap = old.capacity.units();
        let funding = self.v.funding_outpoint().ok_or("no funding")?;
        let mut add = match rng.below(4) {
            0 => MIN_OUTPUT_VALUE,
            1 => UNITS_PER_COIN,
            2 => MIN_OUTPUT_VALUE + rng.below(20 * UNITS_PER_COIN),
            _ => MAX_CAPACITY - old_cap,
        };
        let mut state = n;
        let mut funding_input = 1u32;
        let new_cap = old_cap.saturating_add(add);
        let mut new_params = ChannelParams {
            capacity: Amount::from_units(new_cap),
            ..old.clone()
        };
        let coin = OutPoint {
            txid: Hash256(rng.bytes32()),
            index: rng.below(3) as u32,
        };
        let mut tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: coin,
                    witness: Witness::default(),
                    sequence: u32::MAX,
                },
                TxIn {
                    prev_out: funding,
                    witness: Witness::default(),
                    sequence: splice_sequence(n),
                },
            ],
            outputs: vec![
                new_params.funding_output(),
                key_output(Hash256([0x5c; 32]), 2 * MIN_OUTPUT_VALUE),
            ],
            lock_time: 0,
        };
        let mut raw: Option<Vec<u8>> = None;
        let mut sign_bal_delta: u64 = 0;
        let variant = if rng.one_in(3) { 0 } else { 1 + rng.below(16) };
        match variant {
            0 => {}
            1 => tx.lock_time = rng.edge(&[1]).max(1),
            2 => tx.inputs[1].sequence ^= 1 + rng.below(u64::from(u32::MAX)) as u32,
            3 => {
                tx.inputs.swap(0, 1);
                funding_input = if rng.one_in(2) { 1 } else { 0 };
            }
            4 => {
                let dup = tx.inputs[1].clone();
                tx.inputs.push(dup);
            }
            5 => {
                let dup = tx.inputs[0].clone();
                tx.inputs.insert(1, dup);
            }
            6 => {
                tx.outputs[0] = ChannelParams {
                    capacity: Amount::from_units(new_cap.wrapping_add(rng.edge(&[1]))),
                    ..old.clone()
                }
                .funding_output();
            }
            7 => {
                add = rng.edge(&[
                    0,
                    MIN_OUTPUT_VALUE - 1,
                    MAX_CAPACITY - old_cap + 1,
                    u64::MAX - old_cap + 1,
                    u64::MAX,
                ]);
                // The output follows the claim where it can.
                new_params = ChannelParams {
                    capacity: Amount::from_units(old_cap.wrapping_add(add)),
                    ..old.clone()
                };
                tx.outputs[0] = new_params.funding_output();
            }
            8 => funding_input = rng.edge(&[1, 2]) as u32,
            9 => {
                tx.inputs.remove(0);
                funding_input = 0;
            }
            10 => {
                tx.inputs[0].witness = Witness {
                    pubkey: vec![1; 3],
                    signature: vec![2; 5],
                };
            }
            11 => state = rng.edge(&[n, n + 1, n - 1, 0]),
            12 => {
                // Many coins: still a valid splice, a large transaction.
                let extra = 1 + rng.below(44);
                for i in 0..extra {
                    tx.inputs.insert(
                        0,
                        TxIn {
                            prev_out: OutPoint {
                                txid: Hash256(rng.bytes32()),
                                index: i as u32,
                            },
                            witness: Witness::default(),
                            sequence: rng.next() as u32,
                        },
                    );
                }
                funding_input = (tx.inputs.len() - 1) as u32;
            }
            13 => {
                let mut b = tx.encode();
                mutate_bytes(rng, &mut b);
                raw = Some(b);
            }
            14 => sign_bal_delta = 1,
            15 => tx.outputs.clear(),
            _ => tx.version = rng.next() as u32,
        }
        if variant != 13 && variant != 15 {
            // Keep output 0 consistent with the (possibly changed) params.
            if variant != 6 && variant != 7 {
                tx.outputs[0] = new_params.funding_output();
            }
        }
        let tx_bytes = raw.clone().unwrap_or_else(|| tx.encode());
        let new_out = OutPoint {
            txid: tx.txid(),
            index: 0,
        };
        let cur = self.v.balances();
        let mut bal = cur;
        bal[self.them] = bal[self.them].wrapping_add(add);
        bal[self.us] = bal[self.us].wrapping_add(sign_bal_delta);
        let sigs = match self.p.victim_point(state) {
            Some(pt) if variant != 13 => {
                self.p
                    .sign_commitment(self.us, &new_params, &new_params, new_out, state, bal, pt)
            }
            _ => garbage_sigs(rng),
        };
        let msg = Message::Splice {
            state,
            add,
            funding_input,
            tx: tx_bytes,
            tier_sigs: sigs,
        };
        let before = Snap::of(&self.v);
        let r = self.guarded_deliver(&msg, rng, "puppet splice");
        stats.note("splice/puppet", &r);
        self.remember(msg);
        let accepted =
            matches!(&r, Ok(out) if out.iter().any(|m| matches!(m, Message::SpliceAck { .. })));
        if !accepted {
            // Refused, or SpliceBusy: nothing kept.
            self.unchanged(
                &before,
                &format!("refused puppet splice (variant {variant}): {r:?}"),
            );
            return Ok(());
        }
        // Accepted: it must be a splice the rules allow, and leave our own
        // balance as it was.
        assert!(
            raw.is_none()
                && splice_is_well_formed(&tx, state, n, funding_input, add, funding, &old),
            "the victim accepted a malformed splice (variant {variant}): state {state}, add {add}, funding_input {funding_input}, tx {tx:?}"
        );
        assert!(self.v.splicing());
        assert_eq!(
            self.v.balances()[self.us],
            cur[self.us],
            "a splice moved our side"
        );
        assert_eq!(self.v.params().capacity.units(), old_cap + add);
        if let Ok(out) = r {
            for m in out {
                self.remember(m);
            }
        }
        self.during_splice(rng, stats, n);
        self.lock_splice(rng, n)?;
        assert!(!self.v.splicing(), "the splice did not finish");
        assert_eq!(self.v.balances()[self.us], cur[self.us]);
        assert_eq!(self.v.params().capacity.units(), old_cap + add);
        Ok(())
    }

    /// Hostile traffic while a splice at `n` waits for the chain: nothing
    /// of it may move the channel.
    fn during_splice(&mut self, rng: &mut Rng, stats: &mut Stats, n: u64) {
        for _ in 0..(1 + rng.below(5)) {
            let before = Snap::of(&self.v);
            let cur = self.v.balances();
            let m = match rng.below(7) {
                0 => {
                    // A payment to us during the splice: no update now.
                    let mut b = cur;
                    if b[self.them] > 0 {
                        b[self.them] -= 1;
                        b[self.us] += 1;
                    }
                    let st = rng.pick_u64(&[n, n + 1]);
                    // Signed for `n` only: the splice state settles, and a
                    // signed update for `n + 1` would be a real payment.
                    let sigs = if st == n {
                        self.p
                            .update_sigs(&self.v, st, b)
                            .unwrap_or_else(|| garbage_sigs(rng))
                    } else {
                        garbage_sigs(rng)
                    };
                    Message::Update {
                        state: st,
                        balances: b,
                        tier_sigs: sigs,
                    }
                }
                // A stale sequence number: a fresh valid Close may be
                // agreed during a splice (on_close_crossing), by design.
                1 => self.p.close(self.cid(), rng.edge(&[20_000]), self.p.seq),
                2 => Message::SpliceLocked {
                    state: rng.edge(&[n]),
                    revocation: Revocation {
                        secret: rng.bytes32(),
                        next_hash: Hash256(rng.bytes32()),
                    },
                },
                3 => Message::SpliceBusy {
                    state: rng.edge(&[n]),
                },
                4 => Message::SpliceSig {
                    state: rng.edge(&[n]),
                    signature: vec![rng.byte(); sig_len()],
                },
                5 => Message::SpliceAck {
                    state: rng.edge(&[n]),
                    tier_sigs: garbage_sigs(rng),
                },
                _ => {
                    // Replay of the splice itself, or an edit of it.
                    match self
                        .corpus
                        .iter()
                        .rev()
                        .find(|m| matches!(m, Message::Splice { .. }))
                        .cloned()
                    {
                        Some(s) if rng.one_in(2) => s,
                        Some(s) => mutate_fields(rng, &s),
                        None => Message::SpliceBusy { state: n },
                    }
                }
            };
            let r = self.guarded_deliver(&m, rng, "during a splice");
            stats.note("splice/during", &r);
            if let Ok(out) = &r {
                // The replay of the splice is answered again, the same way.
                if !out.is_empty() {
                    assert!(
                        out.iter().all(|a| matches!(
                            a,
                            Message::SpliceAck { .. } | Message::SpliceSig { .. }
                        )),
                        "unexpected answer during a splice: {out:?}"
                    );
                }
            }
            self.unchanged(&before, &format!("during a splice: {}", summary(&m)));
            assert!(self.v.splicing(), "the splice vanished");
        }
    }

    /// Both sides see the splice at `n` buried and trade the revocations of
    /// the last old state, in a random order.
    fn lock_splice(&mut self, rng: &mut Rng, n: u64) -> Result<(), String> {
        self.v.note_splice_height(Some(100 + rng.below(50)));
        let theirs = Message::SpliceLocked {
            state: n,
            revocation: self.p.revocation(n - 1),
        };
        let puppet_first = rng.one_in(2);
        if puppet_first {
            self.v
                .on_splice_locked(&theirs)
                .map_err(|e| format!("on_splice_locked: {e:?}"))?;
        }
        let ours = self
            .v
            .splice_locked()
            .map_err(|e| format!("splice_locked: {e:?}"))?;
        match &ours {
            Message::SpliceLocked { state, revocation } if *state == n => {
                if let Some(pt) = self.p.victim_point(n - 1) {
                    assert_eq!(Hash256(sha256(&revocation.secret)), pt);
                }
                self.p.victim_points.insert(n + 1, revocation.next_hash);
            }
            other => return Err(format!("splice_locked returned {}", summary(other))),
        }
        self.remember(ours);
        if !puppet_first {
            self.v
                .on_splice_locked(&theirs)
                .map_err(|e| format!("on_splice_locked: {e:?}"))?;
        }
        self.remember(theirs);
        Ok(())
    }

    /// The victim adds coins; the puppet answers honestly, refuses, crosses
    /// it with a payment, or sends forgeries first.
    fn victim_splice(&mut self, rng: &mut Rng, stats: &mut Stats) -> Result<(), String> {
        self.resync(rng);
        let n = self.v.next_state_number();
        let old = self.v.params().clone();
        let old_cap = old.capacity.units();
        let funding = self.v.funding_outpoint().ok_or("no funding")?;
        let add = MIN_OUTPUT_VALUE + rng.below(5 * UNITS_PER_COIN);
        if old_cap + add > MAX_CAPACITY {
            return Ok(());
        }
        let new_params = ChannelParams {
            capacity: Amount::from_units(old_cap + add),
            ..old.clone()
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: OutPoint {
                        txid: Hash256(rng.bytes32()),
                        index: 0,
                    },
                    witness: Witness::default(),
                    sequence: u32::MAX,
                },
                TxIn {
                    prev_out: funding,
                    witness: Witness::default(),
                    sequence: splice_sequence(n),
                },
            ],
            outputs: vec![
                new_params.funding_output(),
                key_output(Hash256([0x6d; 32]), 3 * MIN_OUTPUT_VALUE),
            ],
            lock_time: 0,
        };
        let cur = self.v.balances();
        let counters0 = self.v.sync_counters();
        let msg = match self.v.propose_splice(add, tx.clone()) {
            Ok(m) => m,
            Err(e) => return Err(format!("propose_splice: {e:?}")),
        };
        self.remember(msg.clone());
        let stripped = match &msg {
            Message::Splice { tx, .. } => Transaction::decode(tx).map_err(|e| format!("{e:?}"))?,
            other => return Err(format!("propose_splice returned {}", summary(other))),
        };
        let new_out = OutPoint {
            txid: stripped.txid(),
            index: 0,
        };
        let mut bal = cur;
        bal[self.us] += add;

        // Forgeries first: none may complete, cancel or move the splice.
        for _ in 0..rng.below(4) {
            let before = Snap::of(&self.v);
            let m = match rng.below(5) {
                0 => Message::SpliceAck {
                    state: n,
                    tier_sigs: if rng.one_in(2) {
                        garbage_sigs(rng)
                    } else {
                        // Signed, but over other balances.
                        let mut b = bal;
                        b[self.us] -= 1;
                        b[self.them] += 1;
                        let pt = self.p.victim_point(n).ok_or("no point")?;
                        self.p
                            .sign_commitment(self.us, &new_params, &new_params, new_out, n, b, pt)
                    },
                },
                1 => Message::SpliceSig {
                    state: n,
                    signature: if rng.one_in(2) {
                        vec![rng.byte(); sig_len()]
                    } else {
                        // Signed over the wrong input.
                        self.p
                            .sign(&old.funding_sighash_at(&stripped, 0, NET, self.p.idx))
                    },
                },
                2 => Message::SpliceBusy {
                    state: rng.edge(&[n]).max(n + 1),
                },
                3 => {
                    // A forged crossing payment: must not drop our splice.
                    let mut b = cur;
                    if b[self.them] > 0 {
                        b[self.them] -= 1;
                        b[self.us] += 1;
                    }
                    Message::Update {
                        state: n,
                        balances: b,
                        tier_sigs: garbage_sigs(rng),
                    }
                }
                _ => {
                    // A crossing "payment" that drains us, validly signed
                    // over the old funding.
                    let mut b = cur;
                    let take = cur[self.us].min(1 + rng.below(UNITS_PER_COIN));
                    b[self.us] -= take;
                    b[self.them] += take;
                    let pt = self.p.victim_point(n).ok_or("no point")?;
                    let sigs = self
                        .p
                        .sign_commitment(self.us, &old, &old, funding, n, b, pt);
                    Message::Update {
                        state: n,
                        balances: b,
                        tier_sigs: if take == 0 { garbage_sigs(rng) } else { sigs },
                    }
                }
            };
            let r = self.guarded_deliver(&m, rng, "forged answer to our splice");
            stats.note("splice/victim-forged", &r);
            if let Message::SpliceBusy { .. } = m {
                // Another state: not ours, ignored.
                assert!(matches!(r, Ok(ref o) if o.is_empty()), "{r:?}");
            } else {
                assert!(r.is_err(), "forged answer taken: {} -> {r:?}", summary(&m));
            }
            self.unchanged(
                &before,
                &format!("forged answer to our splice: {}", summary(&m)),
            );
            assert!(self.v.splicing(), "a forgery dropped our splice");
        }

        match rng.below(4) {
            0 => {
                // Refused.
                let busy = Message::SpliceBusy { state: n };
                let r = self
                    .v
                    .on_splice_busy(&busy)
                    .map_err(|e| format!("on_splice_busy: {e:?}"))?;
                assert!(r.is_some(), "a refused splice did not give its coins back");
                self.remember(busy);
                assert!(!self.v.splicing());
                assert_eq!(self.v.balances(), cur);
                assert_eq!(self.v.params().capacity.units(), old_cap);
                assert_eq!(self.v.funding_outpoint(), Some(funding));
                assert_eq!(
                    self.v.sync_counters(),
                    counters0,
                    "a dropped splice left its state behind"
                );
                Ok(())
            }
            1 if self.v.remote_sendable() > 0 => {
                // A payment of the peer crosses it: the payment wins.
                let amt = 1 + rng.below(self.v.remote_sendable());
                let mut b = cur;
                b[self.them] -= amt;
                b[self.us] += amt;
                let pt = self.p.victim_point(n).ok_or("no point")?;
                let sigs = self
                    .p
                    .sign_commitment(self.us, &old, &old, funding, n, b, pt);
                let upd = Message::Update {
                    state: n,
                    balances: b,
                    tier_sigs: sigs,
                };
                let out = self
                    .v
                    .on_peer_update(&upd)
                    .map_err(|e| format!("crossing payment: {e:?}"))?;
                self.remember(upd);
                assert!(
                    !self.v.splicing(),
                    "the crossing payment did not drop the splice"
                );
                assert_eq!(self.v.params().capacity.units(), old_cap);
                let next = out
                    .iter()
                    .find_map(|m| match m {
                        Message::Ack {
                            state, revocation, ..
                        } if *state == n => Some(revocation.next_hash),
                        _ => None,
                    })
                    .ok_or("no Ack of the crossing payment")?;
                self.p.victim_points.insert(n + 1, next);
                for m in out {
                    self.remember(m);
                }
                let rev = Message::Revoke {
                    state: n,
                    revocation: self.p.revocation(n - 1),
                };
                self.v
                    .on_revoke(&rev)
                    .map_err(|e| format!("crossing on_revoke: {e:?}"))?;
                self.remember(rev);
                assert_eq!(self.v.balances(), b);
                // The late refusal of the dropped splice changes nothing.
                let before = Snap::of(&self.v);
                let r = self.v.on_splice_busy(&Message::SpliceBusy { state: n });
                assert!(matches!(r, Ok(None)), "{r:?}");
                self.unchanged(&before, "late SpliceBusy");
                Ok(())
            }
            _ => {
                // Honest: both signatures, in either order.
                let pt = self.p.victim_point(n).ok_or("no point")?;
                let ack = Message::SpliceAck {
                    state: n,
                    tier_sigs: self.p.sign_commitment(
                        self.us,
                        &new_params,
                        &new_params,
                        new_out,
                        n,
                        bal,
                        pt,
                    ),
                };
                let sig = Message::SpliceSig {
                    state: n,
                    signature: self
                        .p
                        .sign(&old.funding_sighash_at(&stripped, 1, NET, self.p.idx)),
                };
                let (first, second) = if rng.one_in(2) {
                    (ack, sig)
                } else {
                    (sig, ack)
                };
                let r1 = self.guarded_deliver(&first, rng, "splice answer 1");
                let r2 = self.guarded_deliver(&second, rng, "splice answer 2");
                stats.note("splice/victim-answer", &r1);
                stats.note("splice/victim-answer", &r2);
                r1.map_err(|e| format!("first answer: {e:?}"))?;
                r2.map_err(|e| format!("second answer: {e:?}"))?;
                // The completed transaction: its funding input is a valid
                // spend of the old funding output, as the chain checks it.
                let done = self.v.splice_tx().cloned().ok_or("splice not complete")?;
                let entry = UtxoEntry {
                    output: old.funding_output(),
                    height: 5,
                    is_coinbase: false,
                };
                let check = q21_core::policy::check_spend(
                    &done,
                    1,
                    NET,
                    &entry,
                    10,
                    &done.inputs[1].witness,
                );
                assert!(
                    check.is_ok(),
                    "the completed splice input is invalid: {check:?}"
                );
                self.remember(first);
                self.remember(second);
                self.during_splice(rng, stats, n);
                self.lock_splice(rng, n)?;
                assert!(!self.v.splicing());
                assert_eq!(self.v.balances(), bal);
                assert_eq!(self.v.params().capacity.units(), old_cap + add);
                Ok(())
            }
        }
    }

    // --- Hostile moves ------------------------------------------------------

    /// An update the puppet signs but must not get accepted.
    fn bad_update(&mut self, rng: &mut Rng, stats: &mut Stats) {
        let n = self.v.next_state_number();
        let cur = self.v.balances();
        let cap = self.v.params().capacity.units();
        let fee = self.v.commit_fee(FeeTier::High);
        let (us, them) = (self.us, self.them);
        let kind = rng.below(7);
        let (state, mut bal, sign) = match kind {
            0 if cur[us] > 0 => {
                // Drains the victim.
                let take = 1 + rng.below(cur[us]);
                let mut b = cur;
                b[us] -= take;
                b[them] += take;
                (n, b, true)
            }
            1 => {
                let b = [rng.edge(&[cur[0], cap, fee]), rng.edge(&[cur[1], cap, fee])];
                (n, b, rng.one_in(2))
            }
            2 => {
                // The funder below the highest-tier fee.
                let f = rng.below(fee);
                let mut b = [0u64; 2];
                b[FUNDER] = f;
                b[ACCEPTOR] = cap - f;
                (n, b, true)
            }
            3 => {
                let mut s = rng.edge(&[n, n + 1, n + 2, n - 1, shachain::MAX_INDEX]);
                if s == n {
                    s = n + 1;
                }
                let mut b = cur;
                if b[them] > 0 {
                    b[them] -= 1;
                    b[us] += 1;
                }
                // Validly signed only for a state already settled: a signed
                // update for a future state is a real payment, which a
                // later replay could rightly complete.
                (s, b, s < n)
            }
            _ => {
                // A valid payment, with signatures that do not match it.
                let mut b = cur;
                if b[them] > 0 {
                    b[them] -= 1;
                    b[us] += 1;
                }
                (n, b, true)
            }
        };
        // Never an honest update by accident.
        let honest_shape = state == n
            && bal[0].checked_add(bal[1]) == Some(cap)
            && bal[us] >= cur[us]
            && bal[FUNDER] >= fee;
        let mut sigs = if sign {
            self.p
                .update_sigs(&self.v, state, bal)
                .unwrap_or_else(|| garbage_sigs(rng))
        } else {
            garbage_sigs(rng)
        };
        let mut mutation = "not honest-shaped";
        // The victim's own output trimmed as dust: its commitment then has no
        // output a revocation point enters, and some "wrong" signatures sign
        // the very same transaction — valid, not a defect. Such balances are
        // left to the honest moves.
        let vi = self.v.our_index();
        let victim_keeps = if vi == FUNDER {
            bal[vi].saturating_sub(fee)
        } else {
            bal[vi]
        };
        if honest_shape && victim_keeps < txbuild::TO_LOCAL_DUST {
            return;
        }
        if honest_shape {
            match rng.below(4) {
                0 => {
                    mutation = "tiers swapped";
                    sigs.swap(0, 2)
                }
                1 => {
                    mutation = "bit flipped";
                    let i = rng.below(3) as usize;
                    let j = rng.below(sig_len() as u64) as usize;
                    sigs[i][j] ^= 1 << rng.below(8);
                }
                2 => {
                    mutation = "other balances";
                    // Signed over other balances.
                    let mut other = bal;
                    if other[us] > 0 {
                        other[us] -= 1;
                        other[them] += 1;
                    } else {
                        other[them] -= 1;
                        other[us] += 1;
                    }
                    sigs = self
                        .p
                        .update_sigs(&self.v, state, other)
                        .unwrap_or_else(|| garbage_sigs(rng));
                }
                _ => {
                    mutation = "other point";
                    // Signed with another state's point.
                    let pt = self
                        .p
                        .victim_point(n + 1)
                        .or_else(|| self.p.victim_point(n - 1))
                        .unwrap_or(Hash256([7; 32]));
                    let p = self.v.params().clone();
                    let op = self.v.funding_outpoint().unwrap_or(OutPoint {
                        txid: Hash256::ZERO,
                        index: 0,
                    });
                    sigs = self.p.sign_commitment(us, &p, &p, op, state, bal, pt);
                }
            }
            // A zero-amount honest update stays honest whatever its sigs:
            // nudge the balance off the capacity so it cannot pass anyway.
            if bal == cur {
                bal[us] = bal[us].wrapping_add(1);
            }
        }
        let m = Message::Update {
            state,
            balances: bal,
            tier_sigs: sigs,
        };
        let before = Snap::of(&self.v);
        let r = self.guarded_deliver(&m, rng, "bad update");
        stats.note("update/bad", &r);
        if let Ok(out) = &r {
            // Only an idempotent answer to a state already settled.
            let _ = out;
            assert!(
                state < n,
                "the victim accepted an invalid update for a new state ({mutation}, honest shape {honest_shape}, n {n}): {}",
                summary(&m)
            );
        }
        self.remember(m);
        self.unchanged(&before, "bad update");
    }

    fn bad_revoke_or_ack(&mut self, rng: &mut Rng, stats: &mut Stats) {
        let n = self.v.next_state_number();
        let last = n.saturating_sub(1);
        let state = rng.edge(&[last, n, n + 1, 1, shachain::MAX_INDEX]);
        let revocation = match rng.below(3) {
            0 => Revocation {
                secret: rng.bytes32(),
                next_hash: Hash256(rng.bytes32()),
            },
            1 => {
                // Our real secret, of a state other than the one named.
                let s = rng.below(n + 2);
                Revocation {
                    secret: self.p.secret(s),
                    next_hash: self.p.point(s + 2),
                }
            }
            _ => Revocation {
                secret: self.p.secret(last),
                next_hash: Hash256(rng.bytes32()),
            },
        };
        // The peer's real secret for `state - 1` would be a (premature but
        // genuine) revocation, which the victim may take: never send that.
        let mut revocation = revocation;
        if state >= 1
            && state - 1 <= shachain::MAX_INDEX
            && revocation.secret == self.p.secret(state - 1)
        {
            revocation.secret[0] ^= 1;
        }
        let m = if rng.one_in(2) {
            Message::Revoke { state, revocation }
        } else {
            Message::Ack {
                state,
                tier_sigs: garbage_sigs(rng),
                revocation,
            }
        };
        let before = Snap::of(&self.v);
        let r = self.guarded_deliver(&m, rng, "bad revoke/ack");
        stats.note("revoke-ack/bad", &r);
        self.remember(m);
        self.unchanged(&before, "bad revoke/ack");
    }

    /// A reestablish with counters of the puppet's choosing, signed.
    fn hostile_reestablish(&mut self, rng: &mut Rng, stats: &mut Stats) {
        let c = self.v.sync_counters();
        let honest = mirror(c);
        let mut counters = honest;
        for x in counters.iter_mut() {
            if rng.one_in(2) {
                *x = rng.edge(&[*x, c[0], c[1], c[2], c[3]]);
            }
        }
        let mut direction = self.p.idx as u8;
        if rng.one_in(10) {
            direction = rng.byte();
        }
        let nonce = match self.corpus.iter().rev().find_map(|m| match m {
            Message::Reestablish { nonce, .. } => Some(*nonce),
            _ => None,
        }) {
            Some(old) if rng.one_in(8) => old,
            _ => rng.bytes32(),
        };
        let mut m = self.p.reestablish(self.cid(), counters, nonce, direction);
        if rng.one_in(10) {
            if let Message::Reestablish { channel_id, .. } = &mut m {
                *channel_id = Hash256(rng.bytes32());
            }
        }
        let before = Snap::of(&self.v);
        let r = self.guarded_deliver(&m, rng, "hostile reestablish");
        stats.note("reestablish/hostile", &r);
        self.unchanged(&before, "hostile reestablish");
        // A proof of the peer's older copy only ever reveals the peer's own
        // secret.
        if let Some(Message::BehindProof { state, secret }) = self.v.behind_proof() {
            assert!(state <= shachain::MAX_INDEX);
            assert_eq!(
                secret,
                self.p.secret(state),
                "behind_proof revealed something other than the peer's own secret"
            );
            stats.note::<(), ()>("reestablish/behind-proof", &Ok(()));
        }
        self.remember(m);
        if rng.one_in(2) {
            self.resync(rng);
        }
    }

    fn hostile_ready(&mut self, rng: &mut Rng, stats: &mut Stats) {
        let seq = if rng.one_in(3) {
            rng.edge(&[self.p.seq])
        } else {
            self.p.seq.wrapping_add(1)
        };
        // u64::MAX would end every later control message: keep it rare.
        let seq = if seq == u64::MAX && !rng.one_in(8) {
            self.p.seq.wrapping_add(1)
        } else {
            seq
        };
        let mut m = self.p.ready(self.cid(), seq);
        let forged = rng.one_in(4);
        if forged {
            if let Message::Ready { signature, .. } = &mut m {
                signature[rng.below(sig_len() as u64) as usize] ^= 1;
            }
        }
        let before = Snap::of(&self.v);
        let r = self.guarded_deliver(&m, rng, "ready");
        stats.note("ready", &r);
        if r.is_ok() {
            assert!(!forged, "a forged Ready was taken");
            assert!(seq > self.p.seq, "a stale Ready was taken");
            self.p.seq = seq;
        }
        self.remember(m);
        self.unchanged(&before, "ready");
    }

    /// The puppet proposes a close. Returns true if the channel is now
    /// closing (the episode ends).
    fn hostile_close(&mut self, rng: &mut Rng, stats: &mut Stats) -> bool {
        // In step first, so that a refusal is about the Close itself.
        self.resync(rng);
        let (min, max) = txbuild::close_fee_bounds(self.v.params());
        let them_bal = self.v.balances()[self.them];
        let fee = rng.edge(&[min, max, them_bal, 20_000]);
        let seq = if rng.one_in(4) {
            rng.edge(&[self.p.seq])
        } else {
            self.p.seq.wrapping_add(1)
        };
        let m = self.p.close(self.cid(), fee, seq);
        let crossing = rng.one_in(5);
        let before = Snap::of(&self.v);
        let scratch = self.dir.path().to_path_buf();
        let v = &mut self.v;
        let r = match catch_unwind(AssertUnwindSafe(|| {
            if crossing {
                v.on_close_crossing(&m).map(|()| None)
            } else {
                v.on_close(&m).map(Some)
            }
        })) {
            Ok(r) => r,
            Err(_) => panic!("PANIC in on_close: {} (scratch {scratch:?})", summary(&m)),
        };
        stats.note(if crossing { "close/crossing" } else { "close" }, &r);
        self.remember(m);
        match r {
            Err(_) => {
                self.unchanged(&before, "refused close");
                false
            }
            Ok(signed) => {
                assert!(
                    fee >= min && fee <= max && fee <= them_bal,
                    "a close fee outside the bounds was accepted: {fee} not in [{min}, {max}] or above the payer's {them_bal}"
                );
                assert!(seq > self.p.seq, "a stale Close was accepted");
                self.p.seq = seq;
                assert_eq!(
                    self.v.balances(),
                    before.balances,
                    "a close moved the balances"
                );
                assert_eq!(self.v.phase(), Phase::Closing);
                if let Some(s) = signed {
                    match &s {
                        Message::CloseSigned { fee: f, .. } => assert_eq!(*f, fee),
                        other => panic!("on_close answered {}", summary(other)),
                    }
                    self.close_signed = true;
                    self.remember(s);
                }
                true
            }
        }
    }

    /// Once the victim signed a close, no update is taken, however signed.
    fn after_close(&mut self, rng: &mut Rng, stats: &mut Stats) {
        if !self.close_signed {
            return;
        }
        for _ in 0..3 {
            let n = self.v.next_state_number();
            let mut b = self.v.balances();
            if b[self.them] > 0 && rng.one_in(2) {
                b[self.them] -= 1;
                b[self.us] += 1;
            }
            let Some(sigs) = self.p.update_sigs(&self.v, n, b) else {
                return;
            };
            let m = Message::Update {
                state: n,
                balances: b,
                tier_sigs: sigs,
            };
            let before = Snap::of(&self.v);
            let r = self.guarded_deliver(&m, rng, "update after a signed close");
            stats.note("update/after-close", &r);
            assert!(
                r.is_err(),
                "an update was taken after we signed a close: {r:?}"
            );
            self.unchanged(&before, "update after a signed close");
        }
    }

    /// The victim proposes the close; the puppet answers with forgeries,
    /// then honestly. The fully signed close must be a valid spend paying
    /// each side its balance (the victim less the fee).
    fn victim_closes(&mut self, rng: &mut Rng, stats: &mut Stats) -> Result<(), String> {
        self.resync(rng);
        let (min, max) = txbuild::close_fee_bounds(self.v.params());
        let bal = self.v.balances();
        if bal[self.us] < min {
            return Ok(());
        }
        let fee = min + rng.below(max.min(bal[self.us]) - min + 1);
        let m = self
            .v
            .propose_close(fee)
            .map_err(|e| format!("propose_close: {e:?}"))?;
        self.remember(m);
        let funding = self.v.funding_outpoint().ok_or("no funding")?;
        let payout = if self.us == FUNDER {
            [VICTIM_PAYOUT, PUPPET_PAYOUT]
        } else {
            [PUPPET_PAYOUT, VICTIM_PAYOUT]
        };
        let params = self.v.params().clone();
        let sign_close = |p: &Puppet, f: u64| {
            let c = params.cooperative_close(funding, bal, f, payout, 1 - p.idx);
            p.sign(&params.funding_sighash(&c.tx, NET, p.idx))
        };
        for _ in 0..rng.below(3) {
            let (f, s) = match rng.below(3) {
                0 => (fee, vec![rng.byte(); sig_len()]),
                1 => (rng.edge(&[fee]), sign_close(&self.p, fee)),
                _ => {
                    let f2 = fee.wrapping_add(1 + rng.below(100));
                    (f2, sign_close(&self.p, f2))
                }
            };
            let cs = Message::CloseSigned {
                fee: f,
                signature: s,
            };
            let before = Snap::of(&self.v);
            let r = self.guarded_deliver(&cs, rng, "forged CloseSigned");
            stats.note("close/forged-signed", &r);
            assert!(
                r.is_err() || f == fee,
                "a forged CloseSigned was taken: {r:?}"
            );
            self.unchanged(&before, "forged CloseSigned");
            self.remember(cs);
        }
        let cs = Message::CloseSigned {
            fee,
            signature: sign_close(&self.p, fee),
        };
        let tx = self
            .v
            .on_close_signed(&cs)
            .map_err(|e| format!("on_close_signed: {e:?}"))?;
        self.remember(cs);
        let entry = UtxoEntry {
            output: self.v.funding_output(),
            height: 5,
            is_coinbase: false,
        };
        let check = q21_core::policy::check_spend(&tx, 0, NET, &entry, 10, &tx.inputs[0].witness);
        assert!(
            check.is_ok(),
            "the cooperative close is not a valid spend: {check:?}"
        );
        for o in &tx.outputs {
            if o.pubkey_hash == payout[self.us] {
                assert_eq!(o.value.units(), bal[self.us] - fee, "the close shorts us");
            } else {
                assert_eq!(
                    o.pubkey_hash, payout[self.them],
                    "the close pays a stranger"
                );
                assert_eq!(o.value.units(), bal[self.them]);
            }
        }
        Ok(())
    }

    /// Stray splice messages while no splice runs.
    fn stray_splice(&mut self, rng: &mut Rng, stats: &mut Stats) {
        let n = self.v.next_state_number();
        let st = rng.edge(&[n, n - 1, n + 1, 0]);
        let m = match rng.below(4) {
            0 => Message::SpliceAck {
                state: st,
                tier_sigs: garbage_sigs(rng),
            },
            1 => Message::SpliceSig {
                state: st,
                signature: vec![rng.byte(); sig_len()],
            },
            2 => Message::SpliceBusy { state: st },
            _ => Message::SpliceLocked {
                state: st,
                revocation: Revocation {
                    secret: if rng.one_in(2) {
                        self.p.secret(st.min(shachain::MAX_INDEX).saturating_sub(1))
                    } else {
                        rng.bytes32()
                    },
                    next_hash: Hash256(rng.bytes32()),
                },
            },
        };
        let before = Snap::of(&self.v);
        let r = self.guarded_deliver(&m, rng, "stray splice message");
        stats.note("splice/stray", &r);
        self.remember(m);
        self.unchanged(&before, "stray splice message");
    }

    fn behind_proofs(&mut self, rng: &mut Rng, stats: &mut Stats) {
        let latest = self.v.local_commit_number().unwrap_or(0);
        let state = rng.edge(&[latest, latest.saturating_sub(1), shachain::MAX_INDEX]);
        // Every secret the victim ever revealed is in the corpus.
        let revealed: Vec<[u8; 32]> = self
            .corpus
            .iter()
            .filter_map(|m| match m {
                Message::Ack { revocation, .. }
                | Message::Revoke { revocation, .. }
                | Message::SpliceLocked { revocation, .. } => Some(revocation.secret),
                _ => None,
            })
            .collect();
        let secret = if !revealed.is_empty() && rng.one_in(2) {
            revealed[rng.below(revealed.len() as u64) as usize]
        } else {
            rng.bytes32()
        };
        let m = Message::BehindProof { state, secret };
        let r = self.guarded_deliver(&m, rng, "behind proof");
        stats.note("behind-proof", &r);
        self.remember(m);
    }

    /// Replays, reflections and mutations of everything exchanged so far.
    fn mutation(&mut self, rng: &mut Rng, stats: &mut Stats) {
        if self.corpus.is_empty() {
            return;
        }
        let base = self.corpus[rng.below(self.corpus.len() as u64) as usize].clone();
        let m = match rng.below(3) {
            // A plain replay (or the reflection of the victim's own frame).
            0 => Some(base),
            1 => Some(mutate_fields(rng, &base)),
            _ => {
                let mut b = base.encode();
                for _ in 0..=rng.below(3) {
                    mutate_bytes(rng, &mut b);
                }
                match Message::decode(&b) {
                    Ok(m) => Some(m),
                    Err(_) => {
                        stats.note::<(), ()>("mutation/undecodable", &Err(()));
                        None
                    }
                }
            }
        };
        let Some(m) = m else { return };
        // An Update the peer signed for a state not settled yet is a real
        // payment of the peer, which the victim may rightly accept later —
        // a crossing refused it at the time. Its replay is not an attack.
        if let Message::Update { state, .. } = &m {
            if *state >= self.v.next_state_number() {
                return;
            }
        }
        let before = Snap::of(&self.v);
        let r = self.guarded_deliver(&m, rng, "replay/mutation");
        stats.note("mutation", &r);
        if r.is_ok() && matches!(m, Message::Close { .. }) && self.v.phase() == Phase::Closing {
            // A Close the peer signed earlier, refused then (its fee above
            // the peer's balance at the time), valid now: a genuine close.
            stats.note::<(), ()>("mutation/late-close", &Ok(()));
            assert_eq!(self.v.balances(), before.balances);
            assert_eq!(self.v.sync_counters(), before.counters);
            return;
        }
        self.unchanged(&before, &format!("replay/mutation {}", summary(&m)));
    }

    /// Restart: the journal alone must rebuild the same channel.
    fn restart(&mut self) {
        let before = Snap::of(&self.v);
        let path = self.dir.path().join("victim.jrnl");
        let m = Machine::reopen(
            &path,
            NET,
            Box::new(ChannelKey::from_seed(&self.vseed)),
            RATE,
        )
        .expect("reopen");
        self.v = m;
        self.unchanged(&before, "reopen from the journal");
    }
}

/// One episode of `steps` random moves. Returns at the first close.
fn run_episode(rng: &mut Rng, victim_is_funder: bool, steps: usize, stats: &mut Stats) {
    let mut e = Episode::open(rng, victim_is_funder);
    for step in 0..steps {
        if e.v.phase() != Phase::Open {
            break;
        }
        let ctx = format!("step {step}");
        let roll = rng.below(100);
        match roll {
            0..=17 => {
                let s = e.v.remote_sendable();
                if s > 0 {
                    let amount = match rng.below(4) {
                        0 => s,
                        1 => 1,
                        2 => MIN_OUTPUT_VALUE.min(s),
                        _ => 1 + rng.below(s),
                    };
                    let r = e.puppet_pays(amount);
                    stats.note("honest/puppet-pays", &r);
                    if let Err(err) = r {
                        panic!("{ctx}: an honest payment to the victim failed: {err}");
                    }
                }
            }
            18..=27 => {
                let s = e.v.sendable();
                if s > 0 {
                    let amount = if rng.one_in(4) { s } else { 1 + rng.below(s) };
                    let r = e.victim_pays(amount);
                    stats.note("honest/victim-pays", &r);
                    if let Err(err) = r {
                        panic!("{ctx}: an honest payment from the victim failed: {err}");
                    }
                }
            }
            28..=31 => {
                let r = e.crossed(rng, stats);
                stats.note("honest/crossed", &r);
                if let Err(err) = r {
                    panic!("{ctx}: crossed proposals failed: {err}");
                }
            }
            32..=45 => e.bad_update(rng, stats),
            46..=52 => e.bad_revoke_or_ack(rng, stats),
            53..=59 => e.hostile_reestablish(rng, stats),
            60..=63 => e.hostile_ready(rng, stats),
            64..=65 => {
                if e.hostile_close(rng, stats) {
                    e.after_close(rng, stats);
                    break;
                }
            }
            66..=67 => e.behind_proofs(rng, stats),
            68..=70 => e.stray_splice(rng, stats),
            71..=75 => {
                let r = e.puppet_splice(rng, stats);
                if let Err(err) = r {
                    panic!("{ctx}: a puppet splice the victim accepted did not complete: {err}");
                }
            }
            76..=80 => {
                let r = e.victim_splice(rng, stats);
                stats.note("honest/victim-splice", &r);
                if let Err(err) = r {
                    panic!("{ctx}: a victim splice failed: {err}");
                }
            }
            81..=82 => e.restart(),
            83 => {
                let r = e.victim_closes(rng, stats);
                stats.note("honest/victim-closes", &r);
                if let Err(err) = r {
                    panic!("{ctx}: a cooperative close of ours failed: {err}");
                }
                break;
            }
            _ => e.mutation(rng, stats),
        }
        e.invariants(&ctx);
    }
}

#[test]
fn engine_survives_a_hostile_funder() {
    // The victim accepted the channel: it starts with nothing, and every
    // coin it holds came from the hostile side.
    let mut rng = Rng(0x5150_2131_C4A7_0001);
    let mut stats = Stats::default();
    let total = rounds(500);
    let mut done = 0;
    while done < total {
        let steps = 40 + rng.below(40) as usize;
        run_episode(&mut rng, false, steps.min(total - done), &mut stats);
        done += steps;
    }
    stats.print("hostile funder");
}

#[test]
fn engine_survives_a_hostile_acceptor() {
    // The victim opened the channel and holds its whole capacity at first.
    let mut rng = Rng(0x5150_2131_C4A7_0002);
    let mut stats = Stats::default();
    let total = rounds(500);
    let mut done = 0;
    while done < total {
        let steps = 40 + rng.below(40) as usize;
        run_episode(&mut rng, true, steps.min(total - done), &mut stats);
        done += steps;
    }
    stats.print("hostile acceptor");
}

/// Thousands of replays, reflections and mutations of a rich corpus, each
/// delivered to every handler that can take it.
#[test]
fn mutated_frames_never_move_the_channel() {
    let mut rng = Rng(0x5150_2131_C4A7_0003);
    let mut stats = Stats::default();
    let total = rounds(4000);
    for victim_is_funder in [false, true] {
        let mut e = Episode::open(&mut rng, victim_is_funder);
        // Warm-up: a history with every kind of frame in it.
        if !victim_is_funder {
            e.puppet_pays(10 * UNITS_PER_COIN).expect("payment");
        }
        e.victim_pays(UNITS_PER_COIN).expect("payment");
        e.puppet_splice(&mut rng, &mut stats).expect("splice");
        e.victim_splice(&mut rng, &mut stats).expect("splice");
        e.crossed(&mut rng, &mut stats).expect("crossed");
        if e.v.remote_sendable() >= 12_345 {
            e.puppet_pays(12_345).expect("payment");
        }
        e.resync(&mut rng);
        for round in 0..total / 2 {
            if e.v.phase() != Phase::Open {
                break;
            }
            e.mutation(&mut rng, &mut stats);
            e.invariants(&format!("mutation round {round}"));
            // Move on now and then, so replays become old.
            if round % 250 == 249 {
                let rs = e.v.remote_sendable();
                if rs > 0 {
                    let amount = 1 + rng.below(rs);
                    e.puppet_pays(amount).expect("payment");
                }
                let s = e.v.sendable();
                if s > 0 {
                    let amount = 1 + rng.below(s);
                    e.victim_pays(amount).expect("payment");
                }
                e.resync(&mut rng);
            }
        }
    }
    stats.print("mutations");
}
