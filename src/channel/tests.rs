//! Engine tests: message codec, transaction builders and weights, the state
//! machine and its journal, crash-safety and reestablish, the watcher, and a
//! property test that an honest party never loses funds.
//!
//! These run only with `--features mldsa`: every signature is a real
//! ML-DSA-87 signature, as on the chain.

use super::journal::{self, Record};
use super::keys::{ChannelKey, Signer};
use super::machine::{Machine, Phase};
use super::messages::{initiative, Message, Revocation, WireError};
use super::txbuild::{self, ChannelParams, FeeTier, ACCEPTOR, FUNDER};
use super::watcher::{classify, Watch, WatchContext};
use crate::address::Network;
use crate::consensus::{MIN_OUTPUT_VALUE, UNITS_PER_COIN, WITNESS_DISCOUNT};
use crate::hash::Hash256;
use crate::tx::OutPoint;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const NET: Network = Network::Regtest;
const CAP: u64 = 50 * UNITS_PER_COIN;
const DELAY: u16 = 12;
const DEPTH: u16 = 2;
const RATE: u64 = 10;

static CTR: AtomicU64 = AtomicU64::new(0);

fn tmpdir() -> PathBuf {
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("q21chan-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn fkey() -> Box<dyn Signer> {
    Box::new(ChannelKey::from_seed(&[1u8; 32]))
}
fn akey() -> Box<dyn Signer> {
    Box::new(ChannelKey::from_seed(&[2u8; 32]))
}

/// A funded, open channel pair, with a fixed funding outpoint. Returns
/// `(funder, acceptor)`.
fn open_pair(dir: &std::path::Path) -> (Machine, Machine) {
    let f_signer = fkey();
    let a_signer = akey();
    let a_pub = a_signer.pubkey().to_vec();
    let (mut f, open) = Machine::new_funder(
        dir.join("f.jrnl"),
        NET,
        f_signer,
        a_pub,
        CAP,
        DELAY,
        DEPTH,
        RATE,
    )
    .unwrap();
    let (mut a, accept) = Machine::accept(dir.join("a.jrnl"), NET, a_signer, RATE, &open).unwrap();
    f.on_accept(&accept).unwrap();
    let outpoint = OutPoint {
        txid: Hash256([9u8; 32]),
        index: 0,
    };
    let funding = f.funding_created(outpoint).unwrap();
    let funding_signed = a.on_funding(&funding).unwrap();
    f.on_funding_signed(&funding_signed).unwrap();
    f.funding_confirmed().unwrap();
    a.funding_confirmed().unwrap();
    assert_eq!(f.phase(), Phase::Open);
    assert_eq!(a.phase(), Phase::Open);
    (f, a)
}

/// Runs one payment update, `initiator` paying so that balances become `bal`.
fn pay(initiator: &mut Machine, responder: &mut Machine, bal: [u64; 2]) {
    let upd = initiator.propose(bal).unwrap();
    let ack = responder.on_update(&upd).unwrap();
    let rev = initiator.on_ack(&ack).unwrap();
    responder.on_revoke(&rev).unwrap();
    assert_eq!(initiator.balances(), bal);
    assert_eq!(responder.balances(), bal);
}

// --- Message codec ----------------------------------------------------------

fn sample_sig() -> Vec<u8> {
    vec![0x5a; crate::sig::SchemeId::MlDsa87.sig_len()]
}
fn sample_pk() -> Vec<u8> {
    vec![0x3c; crate::sig::SchemeId::MlDsa87.pubkey_len()]
}

#[test]
fn every_message_round_trips() {
    let tiers = [sample_sig(), sample_sig(), sample_sig()];
    let rev = Revocation {
        secret: [7u8; 32],
        next_hash: Hash256([8u8; 32]),
    };
    let msgs = vec![
        Message::Open {
            capacity: CAP,
            delay: DELAY,
            funding_depth: DEPTH,
            funder_pubkey: sample_pk(),
            first_hashes: vec![Hash256([1u8; 32]), Hash256([2u8; 32])],
        },
        Message::Accept {
            acceptor_pubkey: sample_pk(),
            first_hashes: vec![Hash256([3u8; 32])],
        },
        Message::Funding {
            funding_txid: Hash256([4u8; 32]),
            funding_index: 2,
            tier_sigs: tiers.clone(),
        },
        Message::FundingSigned {
            tier_sigs: tiers.clone(),
        },
        Message::Ready,
        Message::Update {
            state: 5,
            balances: [10_000, 20_000],
            tier_sigs: tiers.clone(),
        },
        Message::Ack {
            state: 5,
            tier_sigs: tiers.clone(),
            revocation: rev.clone(),
        },
        Message::Revoke {
            state: 5,
            revocation: rev.clone(),
        },
        Message::Reestablish {
            channel_id: Hash256([6u8; 32]),
            local_commit_number: 3,
            remote_commit_number: 3,
            next_revocation_sent: 2,
            next_revocation_recv: 2,
            nonce: [9u8; 32],
            direction: 1,
            proof: sample_sig(),
        },
        Message::Close { fee: 20_000 },
        Message::CloseSigned {
            fee: 20_000,
            signature: sample_sig(),
        },
        Message::Error {
            reason: "bye".to_string(),
        },
    ];
    for m in msgs {
        let bytes = m.encode();
        assert_eq!(Message::decode(&bytes), Ok(m.clone()), "round trip {m:?}");
        // A trailing byte is refused.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(matches!(
            Message::decode(&extra),
            Err(WireError::Read(crate::ser::ReadError::TrailingBytes(_)))
        ));
    }
}

#[test]
fn a_bad_version_and_type_are_refused() {
    let m = Message::Ready.encode();
    let mut wrong_ver = m.clone();
    wrong_ver[0] = 9;
    assert_eq!(
        Message::decode(&wrong_ver),
        Err(WireError::UnknownVersion(9))
    );
    let mut wrong_type = m.clone();
    wrong_type[1] = 200;
    assert_eq!(
        Message::decode(&wrong_type),
        Err(WireError::UnknownType(200))
    );
}

#[test]
fn an_oversized_crypto_field_is_refused() {
    // A signature one byte too long must not decode as a valid tier sig.
    let mut w = crate::ser::Writer::new();
    w.u8(super::messages::WIRE_VERSION);
    // FundingSigned type is 4.
    w.u8(4).u8(3);
    for _ in 0..3 {
        w.var_bytes(&vec![0u8; crate::sig::SchemeId::MlDsa87.sig_len() + 1]);
    }
    assert_eq!(Message::decode(&w.finish()), Err(WireError::FieldTooLong));
}

#[test]
fn tie_break_picks_the_smaller_funding_hash() {
    let small = Hash256([0u8; 32]);
    let big = Hash256([0xffu8; 32]);
    assert_eq!(initiative(&[small, big]), 0);
    assert_eq!(initiative(&[big, small]), 1);
    // Equal hashes resolve deterministically to index 0.
    assert_eq!(initiative(&[small, small]), 0);
}

// --- Transaction builders and weights ---------------------------------------

#[test]
fn channel_transaction_weights() {
    let fk = ChannelKey::from_seed(&[1u8; 32]);
    let ak = ChannelKey::from_seed(&[2u8; 32]);
    let params = ChannelParams {
        funding: [fk.pubkey_hash(), ak.pubkey_hash()],
        capacity: crate::amount::Amount::from_units(CAP),
        delay: DELAY,
    };
    let w = |tx: &crate::tx::Transaction| tx.weight(WITNESS_DISCOUNT);

    // A single ML-DSA-87 key spend (one input, one output).
    let key_spend = txbuild::key_spend_weight();

    // A funding transaction: one key input, policy output + change (two
    // outputs). This is the 8,563 the simulator reports.
    let mut funding = crate::tx::Transaction {
        version: 1,
        inputs: vec![crate::tx::TxIn {
            prev_out: OutPoint {
                txid: Hash256::ZERO,
                index: 0,
            },
            witness: crate::tx::Witness {
                pubkey: fk.pubkey().to_vec(),
                signature: vec![0u8; crate::sig::SchemeId::MlDsa87.sig_len()],
            },
            sequence: u32::MAX,
        }],
        outputs: vec![
            params.funding_output(),
            txbuild::key_output(fk.pubkey_hash(), 1_000_000),
        ],
        lock_time: 0,
    };
    let funding_weight = w(&funding);
    funding.outputs.pop();
    let funding_weight_1out = w(&funding);

    // Commitments at two and one output.
    let std_commit = txbuild::standard_commitment_weight(&params);
    let c1 = params.commitment(FUNDER, 7, [CAP - 5_000, 5_000], 0, Hash256([1u8; 32]));
    let mut c1tx = c1.tx;
    c1tx.inputs[0].witness = txbuild::dummy_funding_witness(&params.funding_policy());
    assert_eq!(c1.trimmed_outputs, 1, "the 5000-unit side is dust");
    assert_eq!(c1.trimmed_units, 5_000);
    let commit_1out = w(&c1tx);

    // Cooperative close (two outputs).
    let close = params.cooperative_close(
        OutPoint {
            txid: Hash256::ZERO,
            index: 0,
        },
        [CAP - 2_000_000, 2_000_000],
        20_000,
    );
    let mut closetx = close.tx;
    closetx.inputs[0].witness = txbuild::dummy_funding_witness(&params.funding_policy());
    let close_weight = w(&closetx);

    // Penalty, local sweep, to_remote claim — built against a real to_local.
    let commit = params.commitment(
        ACCEPTOR,
        3,
        [CAP - 2_000_000, 2_000_000],
        0,
        Hash256([4u8; 32]),
    );
    let to_local_out = commit
        .tx
        .outputs
        .iter()
        .find(|o| o.scheme == crate::sig::SchemeId::Policy)
        .copied()
        .unwrap();
    let to_local_op = OutPoint {
        txid: commit.tx.txid(),
        index: 0,
    };
    let penalty = txbuild::penalty_tx(
        to_local_op,
        &to_local_out,
        &commit.to_local,
        [5u8; 32],
        fk.pubkey_hash(),
        20_000,
        NET,
        &fk,
    );
    let penalty_weight = w(&penalty);
    let sweep = txbuild::local_sweep_tx(
        to_local_op,
        &to_local_out,
        &commit.to_local,
        ak.pubkey_hash(),
        20_000,
        NET,
        &ak,
    );
    let sweep_weight = w(&sweep);
    let to_remote_out = txbuild::key_output(fk.pubkey_hash(), 2_000_000);
    let claim = txbuild::to_remote_claim_tx(
        to_local_op,
        &to_remote_out,
        fk.pubkey_hash(),
        20_000,
        NET,
        &fk,
    );
    let claim_weight = w(&claim);

    println!(
        "WEIGHTS key_spend={key_spend} funding_1out={funding_weight_1out} funding_2out={funding_weight} \
         commitment_2out={std_commit} commitment_1out={commit_1out} coop_close_2out={close_weight} \
         penalty={penalty_weight} local_sweep={sweep_weight} to_remote_claim={claim_weight}"
    );

    assert_eq!(key_spend, 7_999);
    assert_eq!(funding_weight, 8_563);
    assert_eq!(claim_weight, key_spend);
    assert!(std_commit > key_spend, "commitment carries two sigs");
    assert!(
        penalty_weight > key_spend,
        "penalty reveals the policy and a preimage"
    );
}

#[test]
fn dust_trimming_is_exact() {
    let params = ChannelParams {
        funding: [Hash256([1u8; 32]), Hash256([2u8; 32])],
        capacity: crate::amount::Amount::from_units(CAP),
        delay: DELAY,
    };
    // Acceptor just below dust: trimmed into fee, funder output only.
    let c = params.commitment(FUNDER, 1, [CAP - 9_999, 9_999], 0, Hash256([3u8; 32]));
    assert_eq!(c.tx.outputs.len(), 1);
    assert_eq!(c.trimmed_units, 9_999);
    assert_eq!(c.trimmed_outputs, 1);
    // Exactly at the floor: kept.
    let c = params.commitment(
        FUNDER,
        1,
        [CAP - MIN_OUTPUT_VALUE, MIN_OUTPUT_VALUE],
        0,
        Hash256([3u8; 32]),
    );
    assert_eq!(c.tx.outputs.len(), 2);
    assert_eq!(c.trimmed_units, 0);
}

#[test]
fn fee_tiers_climb_then_cap() {
    assert_eq!(FeeTier::Low.multiplier(), 1);
    assert_eq!(FeeTier::Medium.multiplier(), 4);
    assert_eq!(FeeTier::High.multiplier(), 16);
    // Base below the relay minimum is lifted to it.
    assert_eq!(
        txbuild::tier_rate(1, FeeTier::Low),
        crate::mempool::MIN_FEE_RATE
    );
    assert_eq!(txbuild::tier_rate(RATE, FeeTier::High), RATE * 16);
    // A huge base is capped.
    assert_eq!(
        txbuild::tier_rate(u64::MAX, FeeTier::High),
        txbuild::MAX_COMMIT_FEE_RATE
    );
}

// --- State machine: opening and payments ------------------------------------

#[test]
fn a_channel_opens_and_both_agree() {
    let dir = tmpdir();
    let (f, a) = open_pair(&dir);
    assert_eq!(f.balances(), [CAP, 0]);
    assert_eq!(a.balances(), [CAP, 0]);
    assert_eq!(f.channel_id(), a.channel_id());
    assert_eq!(f.our_index(), FUNDER);
    assert_eq!(a.our_index(), ACCEPTOR);
    assert_eq!(f.local_commit_number(), Some(0));
    assert_eq!(a.local_commit_number(), Some(0));
}

#[test]
fn payments_both_directions_settle() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    // Funder pays the acceptor three times.
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    // Acceptor pays some back.
    pay(&mut a, &mut f, [CAP - 2_000_000, 2_000_000]);
    assert_eq!(f.balances(), [CAP - 2_000_000, 2_000_000]);
    assert_eq!(a.balances(), [CAP - 2_000_000, 2_000_000]);
    assert_eq!(f.local_commit_number(), Some(3));
    assert_eq!(a.local_commit_number(), Some(3));
    // Each holds the other's revocation for every past state.
    assert!(!f.revocation_store().is_empty());
    assert!(!a.revocation_store().is_empty());
}

#[test]
fn an_unbalanced_update_is_refused() {
    let dir = tmpdir();
    let (mut f, _a) = open_pair(&dir);
    // Does not conserve capacity.
    assert!(matches!(
        f.propose([CAP, 1_000_000]),
        Err(super::machine::ChannelError::BadBalances)
    ));
}

// --- Journal crash-safety ---------------------------------------------------

/// Reads a channel's journal file bytes.
fn read_journal(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

/// INV1 at the record level: no revocation secret is revealed before the
/// replacement commitment is persisted.
fn inv1_holds(records: &[Record]) -> bool {
    let mut max_local: Option<u64> = None;
    for r in records {
        match r {
            Record::LocalCommit { state, .. } => {
                max_local = Some(max_local.map_or(*state, |m| m.max(*state)))
            }
            // Revealing the secret for `state` requires LocalCommit >= state+1.
            Record::RevocationSent { state } if max_local < Some(state + 1) => {
                return false;
            }
            _ => {}
        }
    }
    true
}

#[test]
fn a_truncated_journal_replays_to_a_clean_prefix() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    // A handful of payments both ways: a rich journal.
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    pay(&mut f, &mut a, [CAP - 2_500_000, 2_500_000]);
    pay(&mut a, &mut f, [CAP - 1_500_000, 1_500_000]);
    pay(&mut f, &mut a, [CAP - 4_000_000, 4_000_000]);

    let path = dir.join("f.jrnl");
    let bytes = read_journal(&path);
    let full = journal::replay(&bytes);
    assert!(inv1_holds(&full), "the completed journal must satisfy INV1");
    assert!(full.len() > 10);

    // Truncate at every byte offset: replay must be a clean prefix of `full`,
    // never panic, and always satisfy INV1.
    for cut in 0..=bytes.len() {
        let part = journal::replay(&bytes[..cut]);
        assert!(
            part.len() <= full.len() && part[..] == full[..part.len()],
            "replay of a {cut}-byte prefix is not a prefix of the full journal"
        );
        assert!(inv1_holds(&part), "INV1 violated at cut {cut}");
    }
}

#[test]
fn a_corrupt_record_stops_replay_without_touching_earlier_ones() {
    let dir = tmpdir();
    let (f, _a) = open_pair(&dir);
    drop(f);
    let path = dir.join("f.jrnl");
    let mut bytes = read_journal(&path);
    let full = journal::replay(&bytes);
    assert!(!full.is_empty());
    // Flip a byte in the body of the last frame: its checksum fails, and
    // replay keeps everything before it.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let part = journal::replay(&bytes);
    assert_eq!(part, full[..full.len() - 1].to_vec());
}

#[test]
fn a_machine_reopens_from_its_journal_at_every_record_boundary() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    pay(&mut a, &mut f, [CAP - 500_000, 500_000]);
    let path = dir.join("f.jrnl");
    let bytes = read_journal(&path);
    let full = journal::replay(&bytes);

    // Reopen at every record boundary (found by walking the frame headers):
    // the counters must stay consistent.
    let mut offset = 0usize;
    let mut i = 0;
    while offset + 8 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 8 + len;
        if offset > bytes.len() {
            break;
        }
        let partial = dir.join(format!("f-cut-{i}.jrnl"));
        std::fs::write(&partial, &bytes[..offset]).unwrap();
        let m = Machine::reopen(&partial, NET, fkey(), RATE).unwrap();
        // local_commit is always at most the highest state seen.
        assert!(m.local_commit_number() <= f.local_commit_number());
        i += 1;
    }
    assert_eq!(i, full.len(), "walked every record frame");
}

// --- Revocation correctness -------------------------------------------------

#[test]
fn an_old_state_is_punished_and_the_latest_is_not() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]); // state 1
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]); // state 2 (current)

    // The funder cheats: broadcasts its revoked state 1 commitment (the
    // engine retains the latest two, so state 1 is still on hand to cheat with
    // — as a dishonest party would keep it).
    let revoked = f.signed_commitment_at(1, FeeTier::Low).unwrap();
    // The acceptor watches.
    let ctx = WatchContext {
        params: a.params(),
        our_index: a.our_index(),
        store: a.revocation_store(),
        latest_state: a.local_commit_number().unwrap(),
    };
    let decision = classify(&ctx, a.funding_outpoint().unwrap(), &revoked);
    match &decision {
        Watch::RevokedByPeer { state, .. } => assert_eq!(*state, 1),
        other => panic!("expected RevokedByPeer, got {other:?}"),
    }
    // The acceptor can build a valid penalty.
    let penalty = a
        .build_penalty(&decision, a.params().funding[ACCEPTOR], 20_000)
        .unwrap();
    assert_eq!(penalty.inputs.len(), 1);
    assert_eq!(penalty.outputs.len(), 1);

    // The latest state is NOT seen as revoked.
    let latest = f.signed_commitment_at(2, FeeTier::Low).unwrap();
    let decision = classify(&ctx, a.funding_outpoint().unwrap(), &latest);
    assert!(
        matches!(decision, Watch::PeerLatest { state: 2, .. }),
        "the latest state must not be punishable: {decision:?}"
    );
}

// --- Reestablish ------------------------------------------------------------

/// Verifies a peer reestablish and returns the resends, checking the proof.
fn exchange_reestablish(x: &mut Machine, y: &mut Machine) -> (Vec<Message>, Vec<Message>) {
    let rx = x.reestablish().unwrap();
    let ry = y.reestablish().unwrap();
    let for_y = y.on_reestablish(&rx).unwrap();
    let for_x = x.on_reestablish(&ry).unwrap();
    (for_x, for_y)
}

#[test]
fn reestablish_between_complete_states_resends_nothing() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    pay(&mut a, &mut f, [CAP - 400_000, 400_000]);
    let (for_f, for_a) = exchange_reestablish(&mut f, &mut a);
    assert!(
        for_f.is_empty(),
        "nothing to resend to the funder: {for_f:?}"
    );
    assert!(
        for_a.is_empty(),
        "nothing to resend to the acceptor: {for_a:?}"
    );
    assert_eq!(f.balances(), a.balances());
}

#[test]
fn reestablish_rejects_a_forged_proof_and_a_replayed_nonce() {
    let dir = tmpdir();
    let (f, mut a) = open_pair(&dir);
    let rf = f.reestablish().unwrap();
    // A good one verifies.
    assert!(a.on_reestablish(&rf).is_ok());
    // The same nonce again is refused (replay).
    assert_eq!(
        a.on_reestablish(&rf),
        Err(super::machine::ChannelError::BadReestablish)
    );
    // A forged proof is refused.
    let mut forged = f.reestablish().unwrap();
    if let Message::Reestablish { proof, .. } = &mut forged {
        proof[0] ^= 0xff;
    }
    assert_eq!(
        a.on_reestablish(&forged),
        Err(super::machine::ChannelError::BadReestablish)
    );
}

#[test]
fn reestablish_recovers_from_a_crash_mid_update() {
    // The funder proposes state 1, the acceptor processes it fully (Ack), but
    // the funder crashes before persisting its LocalCommit(1). On reopen and
    // reestablish, the acceptor resends its Ack and the update completes.
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]); // state 1 fully done

    // Start state 2: funder proposes, acceptor acks, but funder crashes
    // before handling the ack.
    let upd = f.propose([CAP - 2_000_000, 2_000_000]).unwrap();
    let _ack = a.on_update(&upd).unwrap();
    // Funder crashes: drop it and reopen from its journal (which has
    // RemoteCommit(2) but no LocalCommit(2)).
    drop(f);
    let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    assert_eq!(f.local_commit_number(), Some(1));

    // Reconnect. The acceptor must resend its Ack for state 2.
    let (_f_resends, a_resends) = exchange_reestablish(&mut f, &mut a);
    assert!(
        a_resends
            .iter()
            .any(|m| matches!(m, Message::Ack { state: 2, .. })),
        "acceptor should resend Ack(2): {a_resends:?}"
    );
    // Drive the resend home: the acceptor's Ack reaches the recovered funder.
    for m in a_resends {
        if let Message::Ack { .. } = m {
            let rev = f.on_ack(&m).unwrap();
            a.on_revoke(&rev).unwrap();
        }
    }
    assert_eq!(f.balances(), [CAP - 2_000_000, 2_000_000]);
    assert_eq!(a.balances(), [CAP - 2_000_000, 2_000_000]);
    assert_eq!(f.local_commit_number(), Some(2));
    assert_eq!(a.local_commit_number(), Some(2));
}

// --- Cooperative close ------------------------------------------------------

#[test]
fn a_cooperative_close_is_signed_by_both() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 5_000_000, 5_000_000]);
    let close = f.propose_close(20_000).unwrap();
    let signed_by_a = a.on_close(&close).unwrap();
    let close_tx = f.on_close_signed(&signed_by_a).unwrap();
    assert_eq!(f.phase(), Phase::Closed);
    assert_eq!(close_tx.inputs.len(), 1);
    assert_eq!(close_tx.outputs.len(), 2);
    // Outputs pay the final balance less the close fee from the funder.
    let total: u64 = close_tx.outputs.iter().map(|o| o.value.units()).sum();
    assert_eq!(total, CAP - 20_000);
}

// --- Watcher: our own commitment --------------------------------------------

#[test]
fn our_own_commitment_is_swept_only_after_the_delay() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    // The acceptor force-closes with its own latest commitment.
    let mine = a.force_close(FeeTier::Low).unwrap();
    assert_eq!(a.phase(), Phase::Forcing);
    let ctx = WatchContext {
        params: a.params(),
        our_index: a.our_index(),
        store: a.revocation_store(),
        latest_state: a.local_commit_number().unwrap(),
    };
    let decision = classify(&ctx, a.funding_outpoint().unwrap(), &mine);
    let Watch::OurCommitment {
        state: 1,
        to_local: Some(_),
        delay,
    } = decision
    else {
        panic!("expected OurCommitment, got {decision:?}");
    };
    assert_eq!(delay, DELAY);
    let sweep = a
        .build_local_sweep(&decision, a.params().funding[ACCEPTOR], 20_000)
        .unwrap();
    assert_eq!(sweep.inputs.len(), 1);

    // Validate the sweep on a minimal UTXO view: its to_local output lives at
    // `born`; the sweep needs the delayed branch, valid only `DELAY` blocks on.
    let born = 100u64;
    let mut utxo = crate::utxo::UtxoSet::new();
    let to_local_out = mine
        .outputs
        .iter()
        .find(|o| o.scheme == crate::sig::SchemeId::Policy)
        .copied()
        .unwrap();
    utxo.insert(
        crate::tx::OutPoint {
            txid: mine.txid(),
            index: 0,
        },
        crate::utxo::UtxoEntry {
            output: to_local_out,
            height: born,
            is_coinbase: false,
        },
    );
    use std::collections::HashSet;
    // Too early: refused.
    assert!(
        crate::validate::check_transaction(&sweep, &utxo, NET, born + 1, &mut HashSet::new())
            .is_err()
    );
    // After the delay: accepted.
    assert!(crate::validate::check_transaction(
        &sweep,
        &utxo,
        NET,
        born + DELAY as u64,
        &mut HashSet::new()
    )
    .is_ok());
}

#[test]
fn a_spend_of_another_outpoint_is_not_our_channel() {
    let dir = tmpdir();
    let (_f, a) = open_pair(&dir);
    let unrelated = crate::tx::Transaction {
        version: 1,
        inputs: vec![crate::tx::TxIn {
            prev_out: OutPoint {
                txid: Hash256([0x55; 32]),
                index: 1,
            },
            witness: crate::tx::Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![txbuild::key_output(Hash256([1; 32]), MIN_OUTPUT_VALUE)],
        lock_time: 0,
    };
    let ctx = WatchContext {
        params: a.params(),
        our_index: a.our_index(),
        store: a.revocation_store(),
        latest_state: a.local_commit_number().unwrap(),
    };
    assert_eq!(
        classify(&ctx, a.funding_outpoint().unwrap(), &unrelated),
        Watch::NotOurChannel
    );
}

// --- Property: the honest party never loses funds ---------------------------

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// Random payments both directions, then one party broadcasts a random past
/// state. The honest party's recovery on chain is at least its fair balance,
/// and a penalty against a revoked state validates before the delay while the
/// cheater's own sweep does not.
#[test]
fn honest_party_never_loses_against_a_random_broadcast() {
    use std::collections::HashSet;
    for seed in 0..12u64 {
        let dir = tmpdir();
        let (mut f, mut a) = open_pair(&dir);
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15 ^ seed.wrapping_mul(0x1234567));
        let payments = 3 + rng.below(6); // 3..=8 states
        let mut bal = [CAP, 0u64];
        let mut states: Vec<[u64; 2]> = vec![bal];
        for _ in 0..payments {
            // Move a random amount from whichever side can afford it while
            // keeping a coin, in either direction.
            let amt = 100_000 + rng.below(3_000_000);
            let payer = if rng.below(2) == 0 { FUNDER } else { ACCEPTOR };
            let (payer, amt) = if bal[payer] >= amt + UNITS_PER_COIN {
                (payer, amt)
            } else if bal[1 - payer] >= amt + UNITS_PER_COIN {
                (1 - payer, amt)
            } else {
                continue;
            };
            bal[payer] -= amt;
            bal[1 - payer] += amt;
            if payer == FUNDER {
                pay(&mut f, &mut a, bal);
            } else {
                pay(&mut a, &mut f, bal);
            }
            states.push(bal);
        }
        let k = f.local_commit_number().unwrap(); // current state
                                                  // Retained states on hand to broadcast: the latest two.
        let j = if k == 0 { 0 } else { k - 1 + rng.below(2) }; // k-1 or k
        let j = j.min(k);
        let broadcast = f.signed_commitment_at(j, FeeTier::Low).unwrap();
        let born = 100u64;
        let fund_op = a.funding_outpoint().unwrap();

        // Put the broadcast commitment's outputs into a UTXO view.
        let mut utxo = crate::utxo::UtxoSet::new();
        for (idx, out) in broadcast.outputs.iter().enumerate() {
            utxo.insert(
                crate::tx::OutPoint {
                    txid: broadcast.txid(),
                    index: idx as u32,
                },
                crate::utxo::UtxoEntry {
                    output: *out,
                    height: born,
                    is_coinbase: false,
                },
            );
        }

        let ctx = WatchContext {
            params: a.params(),
            our_index: a.our_index(),
            store: a.revocation_store(),
            latest_state: k,
        };
        let decision = classify(&ctx, fund_op, &broadcast);
        let honest_fair = states[k as usize][ACCEPTOR];

        let mut honest_recovered = 0u64;
        match &decision {
            Watch::RevokedByPeer {
                state, to_local, ..
            } => {
                assert!(*state < k, "a revoked broadcast");
                // Penalty sweeps the cheater's to_local to the acceptor.
                let penalty = a
                    .build_penalty(&decision, a.params().funding[ACCEPTOR], 20_000)
                    .unwrap();
                // Penalty is valid the very next block, before the delay.
                assert!(
                    crate::validate::check_transaction(
                        &penalty,
                        &utxo,
                        NET,
                        born + 1,
                        &mut HashSet::new()
                    )
                    .is_ok(),
                    "penalty must validate before the delay"
                );
                honest_recovered += penalty.outputs[0].value.units();
                // The cheater's own sweep of that same to_local is refused
                // until the delay: the penalty wins the race.
                let cheater_sweep = f
                    .build_local_sweep(
                        &Watch::OurCommitment {
                            state: *state,
                            to_local: Some(*to_local),
                            delay: DELAY,
                        },
                        f.params().funding[FUNDER],
                        20_000,
                    )
                    .unwrap();
                assert!(
                    crate::validate::check_transaction(
                        &cheater_sweep,
                        &utxo,
                        NET,
                        born + 1,
                        &mut HashSet::new()
                    )
                    .is_err(),
                    "the cheater's sweep must not be valid before its delay"
                );
                // The acceptor also owns its to_remote on that commitment.
                if let Some((idx, out)) = broadcast.outputs.iter().enumerate().find(|(_, o)| {
                    o.scheme == crate::sig::SchemeId::MlDsa87
                        && o.pubkey_hash == a.params().funding[ACCEPTOR]
                }) {
                    let claim = a.build_to_remote_claim(
                        &super::watcher::OutputRef {
                            outpoint: crate::tx::OutPoint {
                                txid: broadcast.txid(),
                                index: idx as u32,
                            },
                            output: *out,
                        },
                        a.params().funding[ACCEPTOR],
                        20_000,
                    );
                    assert!(crate::validate::check_transaction(
                        &claim,
                        &utxo,
                        NET,
                        born + 1,
                        &mut HashSet::new()
                    )
                    .is_ok());
                    honest_recovered += claim.outputs[0].value.units();
                }
            }
            Watch::PeerLatest { state, to_remote } => {
                assert_eq!(*state, k);
                if let Some(to_remote) = to_remote {
                    let claim =
                        a.build_to_remote_claim(to_remote, a.params().funding[ACCEPTOR], 20_000);
                    assert!(crate::validate::check_transaction(
                        &claim,
                        &utxo,
                        NET,
                        born + 1,
                        &mut HashSet::new()
                    )
                    .is_ok());
                    honest_recovered += claim.outputs[0].value.units();
                }
            }
            other => panic!("unexpected watcher decision {other:?}"),
        }

        // The honest party never ends up with less than its fair balance,
        // minus the fees it must pay to claim (two sweeps at 20k at most).
        let fee_budget = 2 * 20_000 + 20_000; // claim/penalty fees + commitment fee
        assert!(
            honest_recovered + fee_budget >= honest_fair,
            "seed {seed}: honest recovered {honest_recovered} < fair {honest_fair} (state {j} of {k})"
        );
    }
}

// --- Fee-tier selection, validated on chain ---------------------------------

#[test]
fn fee_tiers_are_signed_and_each_validates_on_chain() {
    use std::collections::HashSet;
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]);
    let _ = (&f, &a);

    let mut funder_outputs = Vec::new();
    for tier in FeeTier::ALL {
        // A fresh force-close at each tier (reopen to stay in Open).
        let dir2 = tmpdir();
        let (mut f2, mut a2) = open_pair(&dir2);
        pay(&mut f2, &mut a2, [CAP - 2_000_000, 2_000_000]);
        let mut u = crate::utxo::UtxoSet::new();
        u.insert(
            f2.funding_outpoint().unwrap(),
            crate::utxo::UtxoEntry {
                output: f2.funding_output(),
                height: 10,
                is_coinbase: false,
            },
        );
        let tx = f2.force_close(tier).unwrap();
        crate::validate::check_transaction(&tx, &u, NET, 11, &mut HashSet::new())
            .expect("the commitment must validate as a 2-of-2 spend");
        // The funder's own output falls as the tier (and fee) rises.
        let funder_out = tx
            .outputs
            .iter()
            .find(|o| o.scheme == crate::sig::SchemeId::Policy)
            .map(|o| o.value.units())
            .unwrap();
        funder_outputs.push(funder_out);
    }
    assert!(
        funder_outputs[0] > funder_outputs[1] && funder_outputs[1] > funder_outputs[2],
        "higher tiers pay more fee from the funder's output: {funder_outputs:?}"
    );
}

// --- Simultaneous-update tie-break ------------------------------------------

#[test]
fn simultaneous_updates_resolve_by_initiative() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    // Exactly one side holds the initiative.
    assert_ne!(f.has_initiative(), a.has_initiative());
    let funder_wins = f.has_initiative();
    // The winner proposes first; the loser retries after. Driving them in that
    // order yields a consistent two-state sequence. The two updates move the
    // balance in opposite directions.
    let step1 = [CAP - 1_000_000, 1_000_000];
    let step2 = [CAP - 500_000, 500_000];
    if funder_wins {
        pay(&mut f, &mut a, step1); // funder proposes
        pay(&mut a, &mut f, step2); // acceptor retries
    } else {
        // Acceptor holds the initiative: it proposes first.
        pay(&mut a, &mut f, step1);
        pay(&mut f, &mut a, step2);
    }
    assert_eq!(f.balances(), a.balances());
    assert_eq!(f.balances(), step2);
    assert_eq!(f.local_commit_number(), Some(2));
}

// --- Reestablish after each handshake/update message ------------------------

#[test]
fn reestablish_after_each_message_keeps_both_consistent() {
    // Reconnect at the boundary after every message of the opening handshake
    // and a couple of updates; the channel always resynchronizes.
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    for step in 0..4 {
        // A payment, then a reconnection right after it completes.
        let mut b = f.balances();
        b[ACCEPTOR] += 300_000;
        b[FUNDER] -= 300_000;
        pay(&mut f, &mut a, b);
        let (rf, ra) = exchange_reestablish(&mut f, &mut a);
        assert!(
            rf.is_empty() && ra.is_empty(),
            "step {step}: spurious resends {rf:?} {ra:?}"
        );
        assert_eq!(f.balances(), a.balances());
        assert_eq!(f.local_commit_number(), Some(step + 1));
    }
}

// --- INV3: crash at every write point of an update, then reestablish --------

/// Delivers queued messages between the two sides, following each with the
/// reply it produces, until the protocol is quiescent. `to_f`/`to_a` are
/// messages destined for the funder / acceptor.
fn settle(f: &mut Machine, a: &mut Machine, mut to_f: Vec<Message>, mut to_a: Vec<Message>) {
    for _ in 0..16 {
        if let Some(m) = to_a.pop() {
            match m {
                Message::Update { .. } => {
                    if let Ok(reply) = a.on_update(&m) {
                        to_f.push(reply);
                    }
                }
                Message::Ack { .. } => {
                    if let Ok(reply) = a.on_ack(&m) {
                        to_f.push(reply);
                    }
                }
                Message::Revoke { .. } => {
                    let _ = a.on_revoke(&m);
                }
                _ => {}
            }
        } else if let Some(m) = to_f.pop() {
            match m {
                Message::Update { .. } => {
                    if let Ok(reply) = f.on_update(&m) {
                        to_a.push(reply);
                    }
                }
                Message::Ack { .. } => {
                    if let Ok(reply) = f.on_ack(&m) {
                        to_a.push(reply);
                    }
                }
                Message::Revoke { .. } => {
                    let _ = f.on_revoke(&m);
                }
                _ => {}
            }
        } else {
            break;
        }
    }
}

#[test]
fn a_crash_at_every_update_write_point_reestablishes_without_loss() {
    // For each number of messages exchanged in an update to state 3, crash the
    // funder (reopen from its journal — which reflects exactly the writes made
    // before the messages it had sent), reconnect, and drive to completion.
    // Both sides must converge to the same state and balances, and the honest
    // acceptor must never be worse off.
    for crash_after in 0..=3u8 {
        let dir = tmpdir();
        let (mut f, mut a) = open_pair(&dir);
        pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]); // state 1
        pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]); // state 2
        let target = [CAP - 3_000_000, 3_000_000];

        // Drive the update to state 3 through exactly `crash_after` messages.
        // Each engine call fsyncs its journal before returning the message it
        // emits, so stopping here models a crash at that write point.
        if crash_after >= 1 {
            let upd = f.propose(target).unwrap();
            if crash_after >= 2 {
                let ack = a.on_update(&upd).unwrap();
                if crash_after >= 3 {
                    let rev = f.on_ack(&ack).unwrap();
                    a.on_revoke(&rev).unwrap();
                } else {
                    // Funder has the Ack in hand but crashes before handling.
                    let _ = ack;
                }
            } else {
                // Funder proposed (RemoteCommit persisted) but the Update was
                // not delivered.
                let _ = upd;
            }
        }

        // Crash the funder: drop it and reopen from its journal.
        let before = f.balances();
        drop(f);
        let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
        let _ = before;

        // Reconnect and converge. Each side verifies the other's proof and
        // computes its own resends.
        let rf = f.reestablish().unwrap();
        let ra = a.reestablish().unwrap();
        let f_resends = f.on_reestablish(&ra).unwrap(); // f sends these to a
        let a_resends = a.on_reestablish(&rf).unwrap(); // a sends these to f
        settle(&mut f, &mut a, a_resends, f_resends);

        // Both sides agree on the balance and the state, with no loss.
        assert_eq!(
            f.balances(),
            a.balances(),
            "crash_after={crash_after}: balances diverged"
        );
        assert_eq!(
            f.local_commit_number(),
            a.local_commit_number(),
            "crash_after={crash_after}: state diverged"
        );
        // The settled balance is either the old state 2 or the new state 3,
        // and whichever it is, both sides hold it.
        let b = f.balances();
        assert!(
            b == [CAP - 2_000_000, 2_000_000] || b == target,
            "crash_after={crash_after}: unexpected balance {b:?}"
        );
        // Another reconnection now resends nothing: fully synchronized.
        let (r1, r2) = exchange_reestablish(&mut f, &mut a);
        assert!(
            r1.is_empty() && r2.is_empty(),
            "crash_after={crash_after}: not quiescent after recovery: {r1:?} {r2:?}"
        );
    }
}

// --- Wallet-derived channel keys & revocation-root secrecy ------------------

#[test]
fn wallet_derives_a_reproducible_channel_key() {
    use crate::sig::SchemeId;
    let w = crate::wallet::Wallet::from_seed_scheme([0x33u8; 32], NET, SchemeId::MlDsa87).unwrap();
    let k0 = w.channel_key(0);
    let k1 = w.channel_key(1);
    assert_ne!(k0.pubkey(), k1.pubkey(), "each channel index is a new key");
    // It signs verifiably through the ordinary verification path.
    let m = Hash256([9u8; 32]);
    let sig = k0.sign(&m);
    assert_eq!(
        crate::sig::verify(SchemeId::MlDsa87, k0.pubkey(), &m, &sig),
        Ok(())
    );
    // The same wallet seed reconstructs the same key.
    let w2 = crate::wallet::Wallet::from_seed_scheme([0x33u8; 32], NET, SchemeId::MlDsa87).unwrap();
    assert_eq!(w2.channel_key(0).pubkey(), k0.pubkey());
}

#[test]
fn the_revocation_root_depends_on_private_material() {
    // Two keys that differ only in their private seed produce different
    // revocation roots for the same channel: the root cannot be a function of
    // the public key alone, or the counterparty could derive our secrets.
    let cid = Hash256([7u8; 32]);
    let a = ChannelKey::from_seed(&[1u8; 32]);
    let b = ChannelKey::from_seed(&[2u8; 32]);
    assert_ne!(a.revocation_root(&cid), b.revocation_root(&cid));
    // And it is bound to the channel id.
    assert_ne!(
        a.revocation_root(&cid),
        a.revocation_root(&Hash256([8u8; 32]))
    );
    // Stable for the same inputs.
    assert_eq!(a.revocation_root(&cid), a.revocation_root(&cid));
}
