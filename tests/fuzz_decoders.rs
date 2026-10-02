//! Decoder fuzzing — everything that reads bytes coming from a stranger.
//!
//! # Why this file exists
//!
//! A node reads bytes that anyone can fabricate: protocol frames, snapshot
//! package, portable state snapshot, blocks, transactions, addresses. Each of
//! these decoders is an entry point. A human audit reads the code and
//! reasons; a machine, on the other hand, tries millions of twisted cases that
//! nobody would have imagined. The two complement each other, and the second
//! finds what the first does not see.
//!
//! # What this fuzzer does beyond the existing tests
//!
//! The random-input tests already present send bytes drawn at random. That is
//! useful, but shallow: the frame carries a **checksum**, and random bytes
//! never satisfy it. Decoding therefore stops at the gate, and everything
//! behind it — the loops that read lists, the bounded allocations, the length
//! arithmetic — is never reached.
//!
//! This one works differently, like a real fuzzer:
//!
//! 1. it starts from **valid encodings** (a seed corpus);
//! 2. it **mutates** them — flipped bits, overwritten bytes, truncations,
//!    splices between two seeds, and above all **falsified length fields**,
//!    which is where overflows and oversized allocations hide;
//! 3. for a frame, it **recomputes the checksum** after mutation, so that the
//!    mutated payload gets past the gate and really reaches the decoder we
//!    want to test.
//!
//! # What it checks
//!
//! A single thing, but it is absolute: **no input must make the process
//! panic**. A decoder that panics is a node that a stranger stops remotely
//! with a well-chosen message. Refusing cleanly is always acceptable;
//! stopping never is.
//!
//! The test profile keeps `overflow-checks`: an arithmetic overflow therefore
//! panics, and will be caught here rather than in production.
//!
//! # Reproducibility
//!
//! The seed is fixed: two runs test exactly the same cases. On failure, the
//! test prints the faulty input in hexadecimal and the round number, enough to
//! replay the case by hand.

use q21_core::address::Network;
use q21_core::block::{Block, BlockHeader};
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::fast_sync::SyncSnapshot;
use q21_core::hash::Hash256;
use q21_core::sha256::sha256;
use q21_core::sig::SchemeId;
use q21_core::tx::Transaction;
use q21_core::wire::{InvItem, InvKind, Message, NetAddr};

const NETWORK: Network = Network::Regtest;
const MAGIC: [u8; 4] = [0x51, 0x32, 0x31, 0x72];
const MAX_TRIES: u64 = 50_000_000;
const HEADER_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Deterministic generator
// ---------------------------------------------------------------------------

/// splitmix64: short, dependency-free, and of sufficient quality to seed
/// mutations. We are not after cryptographic randomness, we are after
/// reproducible variety.
struct Prng(u64);

impl Prng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// An integer in `[0, n)`. Returns 0 if `n` is zero, so that the caller
    /// never has to worry about it.
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
    /// True once in `n`.
    fn one_in(&mut self, n: u64) -> bool {
        n != 0 && self.next_u64() % n == 0
    }
}

// ---------------------------------------------------------------------------
// Corpus of valid seeds
// ---------------------------------------------------------------------------

fn chain(n: u64) -> Chain {
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=n {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, MAX_TRIES)
            .expect("mining");
        c.connect(&b, t + 1).expect("connection");
    }
    c
}

/// The valid frames of each protocol message. This is the starting point of
/// the mutations: a mutated valid seed reaches the decoder, where pure noise
/// stops at the gate.
fn frame_corpus(c: &Chain) -> Vec<Vec<u8>> {
    let headers = c.headers();
    let block = c.block_at(1).expect("block 1");
    let tx = block.transactions[0].clone();
    let inv = vec![
        InvItem {
            kind: InvKind::Block,
            hash: c.tip_id(),
        },
        InvItem {
            kind: InvKind::Tx,
            hash: Hash256([7u8; 32]),
        },
    ];

    let messages = vec![
        Message::Version {
            version: 1,
            timestamp: 1_755_000_000,
            nonce: 42,
            user_agent: "q21:test".into(),
            start_height: 7,
        },
        Message::VerAck,
        Message::Ping(0xdead_beef),
        Message::Pong(1),
        Message::GetHeaders {
            locator: vec![c.tip_id(), Hash256::ZERO],
            stop: Hash256::ZERO,
        },
        Message::Headers(headers.clone()),
        Message::Inv(inv.clone()),
        Message::GetData(inv),
        Message::Block(Box::new(block)),
        Message::Tx(Box::new(tx)),
        Message::GetAddr,
        Message::Addr(vec![NetAddr {
            ip: [192, 168, 1, 1],
            port: 21121,
            last_seen: 1_755_000_000,
        }]),
        Message::GetSnapshot,
        Message::SnapshotInfo {
            height: 12,
            tip: c.tip_id(),
            commitment: Hash256([9u8; 32]),
            size: 4096,
            chunks: 1,
        },
        Message::GetSnapshotChunk { index: 0 },
        Message::SnapshotChunk {
            index: 0,
            data: vec![0xab; 512],
        },
    ];
    messages.iter().map(|m| m.frame(MAGIC)).collect()
}

/// The other formats: they do not go through a frame, but come just as much
/// from a stranger — a snapshot file, a downloaded state snapshot.
fn format_corpus(c: &Chain) -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();
    if let Some(a) = c.build_sync_snapshot() {
        v.push(("snapshot", a.encode()));
    }
    if let Some(s) = c.snapshot_at_depth(1) {
        v.push(("state_snapshot", s.to_portable_bytes()));
    }
    if let Some(b) = c.block_at(1) {
        v.push(("transaction", b.transactions[0].encode()));
        v.push(("header", b.header.encode()));
        v.push(("block", b.encode()));
    }
    v
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// Applies a random mutation. This is where the fuzzer's effectiveness is
/// decided: the operators are chosen to target what really breaks a decoder —
/// lengths, counts, bounds.
fn mutate(a: &mut Prng, v: &mut Vec<u8>) {
    if v.is_empty() {
        v.push(a.byte());
        return;
    }
    match a.below(7) {
        // Flip a bit: the finest mutation.
        0 => {
            let i = a.below(v.len());
            v[i] ^= 1u8 << a.below(8);
        }
        // Overwrite a byte.
        1 => {
            let i = a.below(v.len());
            v[i] = a.byte();
        }
        // Extreme values find badly written bounds.
        2 => {
            let i = a.below(v.len());
            v[i] = if a.one_in(2) { 0x00 } else { 0xFF };
        }
        // Truncate: tests the "what if some is missing?" of every read.
        3 => {
            let n = a.below(v.len());
            v.truncate(n);
        }
        // Extend: tests the "what if some is left over?".
        4 => {
            let n = 1 + a.below(64);
            for _ in 0..n {
                v.push(a.byte());
            }
        }
        // Falsify a length or count field. THE mutation that matters: this is
        // how a decoder gets asked to reserve four gibibytes for a twenty-byte
        // frame.
        5 => {
            if v.len() >= 4 {
                let i = a.below(v.len() - 3);
                let absurd: u32 = match a.below(4) {
                    0 => u32::MAX,
                    1 => 0x7FFF_FFFF,
                    2 => 0x00FF_FFFF,
                    _ => 0xFFFF_0000,
                };
                v[i..i + 4].copy_from_slice(&absurd.to_le_bytes());
            }
        }
        // Splice a piece in the middle: produces hybrid structures that no
        // honest encoder would make.
        _ => {
            let i = a.below(v.len());
            let n = 1 + a.below(16);
            let piece: Vec<u8> = (0..n).map(|_| a.byte()).collect();
            v.splice(i..i, piece);
        }
    }
}

/// Recomputes the length and checksum of a mutated frame.
///
/// Without this, the mutated payload would be rejected at the gate and the
/// message decoder would **never** be reached — exactly the limit of the
/// existing random tests. So we repair the envelope so that the mutation
/// lands where we want to test it: inside.
fn repair_frame(v: &mut [u8]) {
    if v.len() < HEADER_LEN {
        return;
    }
    let payload_len = v.len() - HEADER_LEN;
    let checksum = sha256(&v[HEADER_LEN..]);
    v[..4].copy_from_slice(&MAGIC);
    v[16..20].copy_from_slice(&(payload_len as u32).to_le_bytes());
    v[20..24].copy_from_slice(&checksum[..4]);
}

fn hex(v: &[u8]) -> String {
    let short: Vec<u8> = v.iter().take(96).copied().collect();
    let mut s: String = short.iter().map(|o| format!("{o:02x}")).collect();
    if v.len() > 96 {
        s.push_str(&format!("... ({} bytes)", v.len()));
    }
    s
}

/// Runs a decoder while catching a possible panic, so as to be able to say
/// **which** input caused it. A fuzzer that fails without showing its case
/// only serves to worry people.
fn no_panic(name: &str, round: u32, input: &[u8], f: impl FnOnce() + std::panic::UnwindSafe) {
    if std::panic::catch_unwind(f).is_err() {
        panic!(
            "PANIC in decoder \"{name}\" at round {round}.\n\
             Faulty input: {}\n\
             A decoder that panics is a node that a stranger stops remotely.",
            hex(input)
        );
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// No input, however twisted, must make a decoder panic.
#[test]
fn no_decoder_panics_on_mutated_input() {
    // Silences the panic traces: we catch some on purpose, and the output
    // would be unreadable. The final message says everything.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let c = chain(12);
    let frames = frame_corpus(&c);
    let formats = format_corpus(&c);
    assert!(!frames.is_empty(), "empty frame corpus");
    assert!(
        formats.len() >= 4,
        "format corpus too thin: {}",
        formats.len()
    );

    let mut a = Prng(0x5150_2131_4A21_0001);
    // The number of rounds is set from the outside, so that a long campaign
    // uses exactly the same code as the short test in continuous integration
    // — two intensities, a single implementation, hence no possible drift
    // between what we test every day and what we test in depth:
    //
    //   Q21_FUZZ_ROUNDS=2000000 cargo test --release --test fuzz_decoders
    let rounds: u32 = std::env::var("Q21_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150_000);

    for round in 0..rounds {
        // --- The protocol frames.
        let base = &frames[a.below(frames.len())];
        let mut v = base.clone();
        for _ in 0..=a.below(3) {
            mutate(&mut a, &mut v);
        }
        // Two thirds of the time we repair the envelope, to reach the decoder;
        // the rest tests the gate itself.
        if !a.one_in(3) {
            repair_frame(&mut v);
        }
        no_panic("Message::parse", round, &v, || {
            let _ = Message::parse(&v, MAGIC);
        });

        // --- The other formats.
        let (name, base) = &formats[a.below(formats.len())];
        let mut w = base.clone();
        for _ in 0..=a.below(3) {
            mutate(&mut a, &mut w);
        }
        no_panic(name, round, &w, || match *name {
            "snapshot" => {
                let _ = SyncSnapshot::decode(&w);
            }
            "state_snapshot" => {
                let _ = q21_core::state::Snapshot::from_portable_bytes(&w, NETWORK);
            }
            "transaction" => {
                let _ = Transaction::decode(&w);
            }
            "header" => {
                let _ = BlockHeader::decode(&w);
            }
            _ => {
                let _ = Block::decode(&w);
            }
        });
    }

    std::panic::set_hook(previous);
}

/// Addresses come from a human who copies them, hence from anywhere: an
/// email, a message, a misread barcode. The decoder must refuse without ever
/// stopping.
#[test]
fn no_twisted_address_causes_a_panic() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut w = q21_core::wallet::Wallet::from_seed([3u8; 32], NETWORK);
    let valid = w.new_address().to_string_bech32();

    let mut a = Prng(0x5150_2131_4A21_0002);
    let rounds: u32 = std::env::var("Q21_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80_000);
    for round in 0..rounds {
        let mut v = valid.clone().into_bytes();
        for _ in 0..=a.below(3) {
            mutate(&mut a, &mut v);
        }
        // An address is text: we only test what can be text.
        let s = String::from_utf8_lossy(&v).to_string();
        no_panic("Address::parse", round, s.as_bytes(), || {
            let _ = q21_core::address::Address::parse(&s);
        });
        no_panic("bech32::decode", round, s.as_bytes(), || {
            let _ = q21_core::bech32::decode(&s);
        });
    }

    std::panic::set_hook(previous);
}
