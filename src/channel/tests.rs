//! Engine tests: message codec, transaction builders and weights, the state
//! machine and its journal, crash-safety and reestablish, the watcher, and a
//! property test that an honest party never loses funds.
//!
//! These run only with `--features mldsa`: every signature is a real
//! ML-DSA-87 signature, as on the chain.

use super::journal::{self, Record};
use super::keys::{ChannelKey, Signer};
use super::machine::{ChannelError, Machine, Phase};
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
    let f_payout = Hash256([0xf0u8; 32]);
    let a_payout = Hash256([0xa0u8; 32]);
    let (mut f, open) = Machine::new_funder(
        dir.join("f.jrnl"),
        NET,
        f_signer,
        a_pub,
        CAP,
        DELAY,
        DEPTH,
        RATE,
        f_payout,
        a_payout,
    )
    .unwrap();
    let (mut a, accept) = Machine::accept(
        dir.join("a.jrnl"),
        NET,
        a_signer,
        RATE,
        &open,
        a_payout,
        f_payout,
    )
    .unwrap();
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
        Message::Ready {
            seq: 7,
            signature: sample_sig(),
        },
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
        Message::Close {
            fee: 20_000,
            seq: 3,
            signature: sample_sig(),
        },
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
    let m = Message::Error { reason: "x".into() }.encode();
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
        [Hash256([0xf0u8; 32]), Hash256([0xa0u8; 32])],
        FUNDER,
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

/// D14: a proposal lost with the old link is resent on reestablish. Until it
/// lands, the side that never received it must not propose the same state:
/// the two proposals would cross, and the channel deadlock with both in
/// flight.
#[test]
fn reestablish_holds_our_proposal_until_the_peers_lost_one_lands() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    // The acceptor proposes state 2; the link drops before it arrives.
    let _lost = a.propose([CAP - 900_000, 900_000]).unwrap();

    // Reconnect. The acceptor's reestablish shows the funder a proposal on
    // its way: the funder holds its own.
    let (_f_resends, a_resends) = exchange_reestablish(&mut f, &mut a);
    assert!(
        f.update_in_flight(),
        "the funder may propose over the acceptor's resent update"
    );

    // The resent update lands and settles; the funder may propose again.
    let upd = a_resends
        .into_iter()
        .find(|m| matches!(m, Message::Update { state: 2, .. }))
        .expect("the acceptor resends its update");
    let ack = f.on_update(&upd).unwrap();
    let rev = a.on_ack(&ack).unwrap();
    f.on_revoke(&rev).unwrap();
    assert!(!f.update_in_flight());
    pay(&mut f, &mut a, [CAP - 1_500_000, 1_500_000]);
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
    // Closing until the close confirms; it can be rebuilt meanwhile.
    assert_eq!(f.phase(), Phase::Closing);
    assert_eq!(f.signed_cooperative_close(), Some(close_tx.clone()));
    assert!(f.is_cooperative_close(&close_tx));
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

// --- Security regression tests -----------------------------------------------

/// C1 (critical): a received update may only keep or raise our own balance. A
/// counterparty that proposes an update draining us is refused before we
/// persist anything or reveal a secret, and the channel keeps working.
#[test]
fn an_update_that_drains_us_is_rejected() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    // A legitimate payment from the funder to the acceptor completes normally.
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    assert_eq!(f.balances(), [CAP - 1_000_000, 1_000_000]);

    // Now the acceptor crafts an update that moves most of the funder's balance
    // to itself and signs the funder's commitment at that drained split — a
    // valid signature over our own commitment, the single-message theft C1
    // describes. The funder must refuse before persisting or revealing anything.
    let evil = a.propose([CAP / 4, CAP - CAP / 4]).unwrap();
    let before_state = f.local_commit_number();
    let before_bal = f.balances();
    assert_eq!(
        f.on_update(&evil),
        Err(ChannelError::WrongDirection),
        "an update lowering our balance must be refused"
    );
    assert_eq!(
        f.local_commit_number(),
        before_state,
        "no commitment was persisted"
    );
    assert_eq!(
        f.balances(),
        before_bal,
        "our balance is unchanged by the rejected drain"
    );
}

/// H2: the sweep fee is capped so a penalty (or sweep/claim) output never falls
/// below the dust floor, and a to_local below dust+fee is never created — so a
/// cheater cannot pick a revoked balance that makes the victim's penalty
/// dust-invalid and unconfirmable.
#[test]
fn a_small_to_local_still_yields_a_valid_penalty() {
    // The fee cap: the swept output stays at or above the dust floor.
    assert_eq!(txbuild::capped_fee(30_000, 20_000), 20_000); // output 10_000
    assert_eq!(txbuild::capped_fee(15_000, 20_000), 5_000); // output 10_000
    assert_eq!(txbuild::capped_fee(10_000, 20_000), 0); // output 10_000
    assert_eq!(txbuild::capped_fee(1_000_000, 20_000), 20_000); // unchanged

    // A penalty built on a small (revoked-shape) to_local produces a valid,
    // non-dust output instead of a zero/negative one.
    let dir = tmpdir();
    let (f, _a) = open_pair(&dir);
    let policy = f.params().to_local_policy(FUNDER, Hash256([3u8; 32]));
    let out = policy.output(crate::amount::Amount::from_units(15_000));
    let op = OutPoint {
        txid: Hash256([7u8; 32]),
        index: 0,
    };
    let penalty = txbuild::penalty_tx(
        op,
        &out,
        &policy,
        [0u8; 32],
        Hash256([0x5e; 32]),
        20_000,
        NET,
        f.signer(),
    );
    assert!(
        penalty.outputs[0].value.units() >= MIN_OUTPUT_VALUE,
        "the penalty output must clear the dust floor, got {}",
        penalty.outputs[0].value.units()
    );

    // And a to_local below dust+fee is dropped into the miner fee, never
    // created as an unsweepable output.
    let c = f
        .params()
        .commitment(FUNDER, 1, [20_000, CAP - 20_000], 0, Hash256([1u8; 32]));
    assert_eq!(c.trimmed_outputs, 1, "a 20000-unit to_local is trimmed");
    assert_eq!(c.trimmed_units, 20_000);
}

/// H3: an acceptor refuses an open whose parameters would leave its funds
/// unprotected or frozen — a too-short or too-long delay, too shallow a funding
/// depth, or a dust capacity.
#[test]
fn accept_rejects_dangerous_open_parameters() {
    let payout = Hash256([0xf0u8; 32]);
    let dangerous: &[(u64, u16, u16)] = &[
        (CAP, 0, DEPTH),        // delay 0: revoked holder's own sweep has no head-start
        (CAP, 3, DEPTH),        // delay below the minimum
        (CAP, 5_000, DEPTH),    // delay far above the maximum: funds frozen
        (CAP, DELAY, 0),        // depth 0: funding treated as final unconfirmed
        (CAP, DELAY, 1),        // depth below the minimum
        (10_000, DELAY, DEPTH), // capacity below the floor
    ];
    for &(capacity, delay, depth) in dangerous {
        let dir = tmpdir();
        let a_signer = akey();
        let a_pub = a_signer.pubkey().to_vec();
        let (_f, open) = Machine::new_funder(
            dir.join("f.jrnl"),
            NET,
            fkey(),
            a_pub,
            capacity,
            delay,
            depth,
            RATE,
            payout,
            payout,
        )
        .unwrap();
        let r = Machine::accept(
            dir.join("a.jrnl"),
            NET,
            a_signer,
            RATE,
            &open,
            payout,
            payout,
        );
        assert_eq!(
            r.err(),
            Some(ChannelError::BadParameters),
            "open must be refused: capacity={capacity} delay={delay} depth={depth}"
        );
    }
    // A sane open is still accepted.
    let dir = tmpdir();
    let a_signer = akey();
    let a_pub = a_signer.pubkey().to_vec();
    let (_f, open) = Machine::new_funder(
        dir.join("f.jrnl"),
        NET,
        fkey(),
        a_pub,
        CAP,
        DELAY,
        DEPTH,
        RATE,
        payout,
        payout,
    )
    .unwrap();
    assert!(Machine::accept(
        dir.join("a.jrnl"),
        NET,
        a_signer,
        RATE,
        &open,
        payout,
        payout
    )
    .is_ok());
}

/// H3 on testnet: the bounds are the network's. An open on regtest terms
/// (twelve blocks, two confirmations) leaves a testnet acceptor that goes
/// offline for an afternoon open to a revoked-state theft, and is refused;
/// one on testnet terms is accepted, from its minimum up to `MAX_DELAY`.
#[test]
fn a_testnet_acceptor_applies_the_testnet_bounds() {
    use crate::channel::{terms, MAX_DELAY, MIN_DELAY_TESTNET};
    let net = Network::Testnet;
    let t = terms(net);
    assert_eq!(
        (t.default_delay, t.min_delay, t.max_delay, t.funding_depth),
        (1_440, 720, 2_016, 6)
    );
    assert_eq!(
        terms(NET),
        crate::channel::Terms {
            default_delay: DELAY,
            min_delay: 6,
            max_delay: MAX_DELAY,
            funding_depth: DEPTH,
        },
        "regtest keeps its short terms"
    );
    let payout = Hash256([0xf0u8; 32]);
    let try_open = |delay: u16, depth: u16| {
        let dir = tmpdir();
        let a_signer = akey();
        let a_pub = a_signer.pubkey().to_vec();
        let (_f, open) = Machine::new_funder(
            dir.join("f.jrnl"),
            net,
            fkey(),
            a_pub,
            CAP,
            delay,
            depth,
            RATE,
            payout,
            payout,
        )
        .unwrap();
        Machine::accept(
            dir.join("a.jrnl"),
            net,
            a_signer,
            RATE,
            &open,
            payout,
            payout,
        )
        .map(|_| ())
    };
    for (delay, depth) in [
        (DELAY, DEPTH),
        (DELAY, t.funding_depth),
        (MIN_DELAY_TESTNET - 1, t.funding_depth),
        (t.default_delay, DEPTH),
        (t.default_delay, t.funding_depth - 1),
        (MAX_DELAY + 1, t.funding_depth),
    ] {
        assert_eq!(
            try_open(delay, depth),
            Err(ChannelError::BadParameters),
            "testnet must refuse delay={delay} depth={depth}"
        );
    }
    for (delay, depth) in [
        (MIN_DELAY_TESTNET, t.funding_depth),
        (t.default_delay, t.funding_depth),
        (MAX_DELAY, t.funding_depth + 4),
    ] {
        assert_eq!(
            try_open(delay, depth),
            Ok(()),
            "delay={delay} depth={depth}"
        );
    }
}

// --- D11: a crash at every journal write of an update, on either side --------

/// Keeps only the first `keep` record frames of a journal, as a crash right
/// after the `keep`-th `fsync` would leave it.
fn keep_records(path: &std::path::Path, keep: usize) {
    let bytes = read_journal(path);
    let mut offset = 0usize;
    for _ in 0..keep {
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 8 + len;
    }
    std::fs::write(path, &bytes[..offset]).unwrap();
}

fn record_count(path: &std::path::Path) -> usize {
    journal::replay(&read_journal(path)).len()
}

/// Which side a message is for, in [`deliver_all`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum To {
    F,
    A,
}

/// A message's kind and state, for a readable failure.
fn kind(m: &Message) -> String {
    match m {
        Message::Update { state, .. } => format!("Update({state})"),
        Message::Ack { state, .. } => format!("Ack({state})"),
        Message::Revoke { state, .. } => format!("Revoke({state})"),
        Message::Close { fee, .. } => format!("Close({fee})"),
        Message::CloseSigned { .. } => "CloseSigned".into(),
        Message::Reestablish { .. } => "Reestablish".into(),
        _ => "other".into(),
    }
}

/// Delivers messages in order, queueing every reply for the other side, until
/// nothing is left. Any handler error is a failure: after a reestablish an
/// honest peer never sends a message the other side must refuse.
fn deliver_all(
    f: &mut Machine,
    a: &mut Machine,
    mut queue: std::collections::VecDeque<(To, Message)>,
) -> Result<(), String> {
    let mut steps = 0;
    while let Some((to, m)) = queue.pop_front() {
        steps += 1;
        if steps > 64 {
            return Err("did not settle".into());
        }
        let (me, back) = match to {
            To::F => (&mut *f, To::A),
            To::A => (&mut *a, To::F),
        };
        match handle(me, &m) {
            Ok(replies) => queue.extend(replies.into_iter().map(|r| (back, r))),
            Err(e) => return Err(format!("{to:?} refused {}: {e}", kind(&m))),
        }
    }
    Ok(())
}

/// What a node does with one channel message, as the manager dispatches it:
/// the replies to send back.
fn handle(me: &mut Machine, m: &Message) -> Result<Vec<Message>, String> {
    let e = |e: ChannelError| format!("{e:?}");
    match m {
        Message::Update { .. } => me.on_peer_update(m).map_err(e),
        Message::Ack { .. } => me.on_ack(m).map(|r| vec![r]).map_err(e),
        Message::Revoke { .. } => {
            me.on_revoke(m).map_err(e)?;
            Ok(me.merge_if_ready().map_err(e)?.into_iter().collect())
        }
        Message::Close { .. } => me.on_close(m).map(|r| vec![r]).map_err(e),
        Message::CloseSigned { .. } => me.on_close_signed(m).map(|_| Vec::new()).map_err(e),
        other => Err(format!("unexpected message {}", kind(other))),
    }
}

/// Reconnects two machines: each verifies the other's reestablish, and what
/// each owes is delivered until both are quiescent.
fn reconnect(f: &mut Machine, a: &mut Machine) -> Result<(), String> {
    let rf = f.reestablish().unwrap();
    let ra = a.reestablish().unwrap();
    let mut q = std::collections::VecDeque::new();
    for m in a.on_reestablish(&rf).map_err(|e| format!("{e:?}"))? {
        q.push_back((To::F, m));
    }
    for m in f.on_reestablish(&ra).map_err(|e| format!("{e:?}"))? {
        q.push_back((To::A, m));
    }
    deliver_all(f, a, q)
}

/// One crash scenario: an update to state 3 paid by the funder or by the
/// acceptor, cut at write `keep` of protocol step `step` (1 propose, 2 Ack
/// built, 3 Revoke built, 4 Revoke taken) on the side running that step, its
/// outgoing message lost. The crashed side reopens from its truncated journal,
/// and so does the other side when `reopen_both` (a restart of both nodes).
fn crash_scenario(
    funder_pays: bool,
    step: usize,
    keep: Option<usize>,
    reopen_both: bool,
) -> Result<usize, String> {
    crash_scenario_after(0, funder_pays, step, keep, reopen_both)
}

/// [`crash_scenario`] after `history` round trips of payments, enough of them
/// for the journals to have been compacted before the update that is cut.
fn crash_scenario_after(
    history: u64,
    funder_pays: bool,
    step: usize,
    keep: Option<usize>,
    reopen_both: bool,
) -> Result<usize, String> {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    for i in 0..history {
        pay(&mut f, &mut a, [CAP - 1_000 - i, 1_000 + i]);
        pay(&mut a, &mut f, [CAP, 0]);
    }
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]);
    pay(&mut a, &mut f, [CAP - 1_500_000, 1_500_000]);
    let old = [CAP - 1_500_000, 1_500_000];
    let target = if funder_pays {
        [CAP - 2_500_000, 2_500_000]
    } else {
        [CAP - 1_000_000, 1_000_000]
    };
    let paths = [dir.join("f.jrnl"), dir.join("a.jrnl")];
    // Index 0 is the funder, 1 the acceptor; the payer runs steps 1 and 3.
    let payer = if funder_pays { 0 } else { 1 };
    let runner = if step % 2 == 1 { payer } else { 1 - payer };
    let mut before = 0;
    {
        let (p, r) = if funder_pays {
            (&mut f, &mut a)
        } else {
            (&mut a, &mut f)
        };
        // Each step runs only if the previous one delivered its message; the
        // runner's record count is taken just before its step.
        let mut count = |at: usize| {
            if at == step {
                before = record_count(&paths[runner]);
            }
        };
        count(1);
        let upd = p.propose(target).unwrap();
        if step >= 2 {
            count(2);
            let ack = r.on_update(&upd).unwrap();
            if step >= 3 {
                count(3);
                let rev = p.on_ack(&ack).unwrap();
                if step >= 4 {
                    count(4);
                    r.on_revoke(&rev).unwrap();
                }
            }
        }
    }
    let written = record_count(&paths[runner]) - before;
    let keep = keep.unwrap_or(written);
    if keep > written {
        return Ok(written);
    }
    keep_records(&paths[runner], before + keep);
    // The crashed side reopens from its truncated journal. The other keeps
    // running in memory, or restarts too and replays its complete journal.
    let reopen_f = runner == 0 || reopen_both;
    let reopen_a = runner == 1 || reopen_both;
    let mut f = if reopen_f {
        drop(f);
        Machine::reopen(&paths[0], NET, fkey(), RATE).unwrap()
    } else {
        f
    };
    let mut a = if reopen_a {
        drop(a);
        Machine::reopen(&paths[1], NET, akey(), RATE).unwrap()
    } else {
        a
    };

    let ctx = format!("funder_pays={funder_pays} step={step} keep={keep}");
    reconnect(&mut f, &mut a).map_err(|e| format!("{ctx}: {e}"))?;
    if f.balances() != a.balances() || f.local_commit_number() != a.local_commit_number() {
        return Err(format!(
            "{ctx}: diverged {:?}@{:?} vs {:?}@{:?}",
            f.balances(),
            f.local_commit_number(),
            a.balances(),
            a.local_commit_number()
        ));
    }
    let b = f.balances();
    if b != old && b != target {
        return Err(format!("{ctx}: unexpected balance {b:?}"));
    }
    if f.update_in_flight() || a.update_in_flight() {
        return Err(format!("{ctx}: an update is still in flight"));
    }
    // A second reconnection resends nothing.
    let rf = f.reestablish().unwrap();
    let ra = a.reestablish().unwrap();
    let r1 = a.on_reestablish(&rf).unwrap();
    let r2 = f.on_reestablish(&ra).unwrap();
    if !r1.is_empty() || !r2.is_empty() {
        let k: Vec<String> = r1.iter().chain(r2.iter()).map(kind).collect();
        return Err(format!("{ctx}: not quiescent: {k:?}"));
    }
    // Payments resume both ways, then a cooperative close is signed by both.
    let n = f.local_commit_number().unwrap();
    let mut next = b;
    next[FUNDER] -= 100_000;
    next[ACCEPTOR] += 100_000;
    let upd = f
        .propose(next)
        .map_err(|e| format!("{ctx}: propose {e:?}"))?;
    let mut q = std::collections::VecDeque::new();
    q.push_back((To::A, upd));
    deliver_all(&mut f, &mut a, q).map_err(|e| format!("{ctx}: {e}"))?;
    let mut back = next;
    back[FUNDER] += 50_000;
    back[ACCEPTOR] -= 50_000;
    let upd = a
        .propose(back)
        .map_err(|e| format!("{ctx}: propose {e:?}"))?;
    let mut q = std::collections::VecDeque::new();
    q.push_back((To::F, upd));
    deliver_all(&mut f, &mut a, q).map_err(|e| format!("{ctx}: {e}"))?;
    if f.balances() != back || a.balances() != back || f.local_commit_number() != Some(n + 2) {
        return Err(format!("{ctx}: payments after recovery did not settle"));
    }
    let close = f.propose_close(20_000).unwrap();
    let signed = a.on_close(&close).map_err(|e| format!("{ctx}: {e:?}"))?;
    f.on_close_signed(&signed)
        .map_err(|e| format!("{ctx}: close {e:?}"))?;
    Ok(written)
}

#[test]
fn a_crash_at_any_journal_write_of_an_update_recovers_on_either_side() {
    let mut failures = Vec::new();
    let mut scenarios = 0;
    for funder_pays in [true, false] {
        for step in 1..=4 {
            let written = crash_scenario(funder_pays, step, Some(usize::MAX), false).unwrap();
            for keep in 0..=written {
                for reopen_both in [false, true] {
                    scenarios += 1;
                    if let Err(e) = crash_scenario(funder_pays, step, Some(keep), reopen_both) {
                        failures.push(format!("reopen_both={reopen_both} {e}"));
                    }
                }
            }
        }
    }
    assert!(scenarios >= 40, "only {scenarios} scenarios ran");
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A reloaded proposal counts as in flight until the reestablish settles it,
/// so no second update can be stacked on an unacknowledged one.
#[test]
fn a_reloaded_proposal_is_in_flight_until_reestablish() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    assert!(!f.update_in_flight() && !a.update_in_flight());
    let _lost = f.propose([CAP - 2_000_000, 2_000_000]).unwrap();
    assert!(f.update_in_flight());
    drop(f);
    let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    assert!(
        f.update_in_flight(),
        "the journaled proposal is still in flight"
    );
    assert_eq!(f.propose_close(20_000), Err(ChannelError::Unexpected));
    reconnect(&mut f, &mut a).unwrap();
    assert!(!f.update_in_flight() && !a.update_in_flight());
    assert_eq!(f.balances(), [CAP - 2_000_000, 2_000_000]);
    assert_eq!(a.balances(), f.balances());
}

/// A cooperative close whose `Close` was lost to a crash is sent again on
/// reestablish and completes; the peer recognises the close on chain.
#[test]
fn a_lost_close_is_resent_on_reestablish() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let _lost = f.propose_close(20_000).unwrap();
    drop(f);
    let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    assert_eq!(f.phase(), Phase::Closing);
    // Asking again yields the same Close rather than an error.
    assert!(matches!(
        f.propose_close(99_999).unwrap(),
        Message::Close { fee: 20_000, .. }
    ));
    let rf = f.reestablish().unwrap();
    let ra = a.reestablish().unwrap();
    let to_a = f.on_reestablish(&ra).unwrap();
    assert!(a.on_reestablish(&rf).unwrap().is_empty());
    assert!(matches!(to_a[..], [Message::Close { fee: 20_000, .. }]));
    let signed = a.on_close(&to_a[0]).unwrap();
    let tx = f.on_close_signed(&signed).unwrap();
    assert_eq!(f.phase(), Phase::Closing);
    assert_eq!(a.phase(), Phase::Closing);
    assert!(a.is_cooperative_close(&tx), "the peer recognises the close");
    // A spend paying anyone but the two payout addresses is not a close.
    let mut other = tx.clone();
    other.outputs[0].pubkey_hash = Hash256([0x66u8; 32]);
    assert!(!a.is_cooperative_close(&other));
}

/// An update, an Ack or a Revoke naming state 0 is refused. An Ack or a
/// Revoke computed the state below it, `0 - 1`: with overflow checks on and
/// `panic = "abort"`, a single message from the peer stopped the node.
#[test]
fn an_update_message_for_state_zero_is_refused_not_a_crash() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    let Message::Update {
        balances,
        tier_sigs,
        ..
    } = f.propose([CAP - 2_000_000, 2_000_000]).unwrap()
    else {
        unreachable!()
    };
    let rev = Revocation {
        secret: [0u8; 32],
        next_hash: Hash256::ZERO,
    };
    let update = Message::Update {
        state: 0,
        balances,
        tier_sigs: tier_sigs.clone(),
    };
    let ack = Message::Ack {
        state: 0,
        tier_sigs,
        revocation: rev.clone(),
    };
    let revoke = Message::Revoke {
        state: 0,
        revocation: rev,
    };
    assert_eq!(a.on_update(&update), Err(ChannelError::Unexpected));
    assert_eq!(f.on_ack(&ack), Err(ChannelError::Unexpected));
    assert_eq!(a.on_revoke(&revoke), Err(ChannelError::Unexpected));
}

// --- L6: memory and journal bounds -------------------------------------------

/// A long-lived channel keeps bounded per-state maps and a bounded journal,
/// and the compacted journal replays to the exact same state — including the
/// counterparty's oldest revoked state, still punishable.
#[test]
fn a_long_channel_keeps_its_maps_and_journal_bounded() {
    use super::machine::COMPACT_AFTER;
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]);
    // The funder's state 1, revoked by now: kept aside to cheat with later.
    let old = f.signed_commitment_at(1, FeeTier::Low).unwrap();
    let mut bal = f.balances();
    let mut biggest = 0u64;
    for i in 0..150u64 {
        let step = 10_000 + i;
        if i % 3 == 2 {
            bal[FUNDER] += step;
            bal[ACCEPTOR] -= step;
            pay(&mut a, &mut f, bal);
        } else {
            bal[FUNDER] -= step;
            bal[ACCEPTOR] += step;
            pay(&mut f, &mut a, bal);
        }
        for m in [&f, &a] {
            assert!(
                m.journal_records() <= COMPACT_AFTER + 6,
                "journal unbounded"
            );
            let [lc, rb, ini, tp, _, st] = m.retained();
            assert!(
                lc <= 2 && rb <= 2 && ini <= 3 && tp <= 4,
                "{:?}",
                m.retained()
            );
            assert!(st <= crate::shachain::MAX_ENTRIES);
        }
        biggest = biggest.max(std::fs::metadata(dir.join("f.jrnl")).unwrap().len());
        if i % 25 == 24 {
            // The journal, compacted or not, replays to the same state.
            for (m, name, key) in [(&f, "f", fkey()), (&a, "a", akey())] {
                let copy = dir.join(format!("{name}-copy.jrnl"));
                std::fs::copy(dir.join(format!("{name}.jrnl")), &copy).unwrap();
                let back = Machine::reopen(&copy, NET, key, RATE).unwrap();
                assert_eq!(back.digest(), m.digest(), "{name} after {i} payments");
                std::fs::remove_file(&copy).unwrap();
            }
        }
    }
    // Without compaction the funder's journal would hold some 150 commitments
    // of three ML-DSA-87 signatures each, about 2 MB.
    assert!(biggest < 1_200_000, "journal reached {biggest} bytes");
    // The oldest revoked state is still recognised and punishable after the
    // journal was compacted many times and reopened.
    drop(a);
    let a = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
    match a.identify_spend(&old) {
        w @ Watch::RevokedByPeer { state: 1, .. } => {
            assert!(a.build_penalty(&w, Hash256([5u8; 32]), 20_000).is_ok());
        }
        other => panic!("the old state is not recognised as revoked: {other:?}"),
    }
}

/// Compaction in the middle of an update keeps every half-done write: the
/// update still completes after a reopen, and the channel closes.
#[test]
fn a_journal_compacted_mid_update_still_completes_it() {
    for step in 1..=3usize {
        let dir = tmpdir();
        let (mut f, mut a) = open_pair(&dir);
        pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
        pay(&mut a, &mut f, [CAP - 500_000, 500_000]);
        let upd = f.propose([CAP - 900_000, 900_000]).unwrap();
        if step >= 2 {
            let ack = a.on_update(&upd).unwrap();
            if step >= 3 {
                let _rev_lost = f.on_ack(&ack).unwrap();
            }
        }
        let (df, da) = (f.digest(), a.digest());
        f.compact().unwrap();
        a.compact().unwrap();
        drop(f);
        drop(a);
        let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
        let mut a = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
        assert_eq!(f.digest(), df, "step {step}");
        assert_eq!(a.digest(), da, "step {step}");
        reconnect(&mut f, &mut a).unwrap();
        assert_eq!(f.balances(), [CAP - 900_000, 900_000], "step {step}");
        assert_eq!(a.balances(), f.balances());
        let close = f.propose_close(20_000).unwrap();
        let signed = a.on_close(&close).unwrap();
        f.on_close_signed(&signed).unwrap();
    }
}

/// The reestablish nonces a channel remembers are a bounded window, and the
/// latest is still refused if replayed.
#[test]
fn reestablish_nonces_are_a_bounded_window() {
    use super::machine::MAX_SEEN_NONCES;
    let dir = tmpdir();
    let (f, mut a) = open_pair(&dir);
    let mut last = None;
    for _ in 0..(MAX_SEEN_NONCES + 40) {
        let r = f.reestablish().unwrap();
        a.on_reestablish(&r).unwrap();
        last = Some(r);
    }
    assert_eq!(a.retained()[4], MAX_SEEN_NONCES);
    assert_eq!(
        a.on_reestablish(&last.unwrap()),
        Err(ChannelError::BadReestablish)
    );
}

/// The same crash points once the journals have been compacted: the snapshot
/// a compaction writes resynchronizes exactly as the full history would.
#[test]
fn a_crash_after_compaction_recovers_at_every_journal_write() {
    use super::machine::COMPACT_AFTER;
    let history = (COMPACT_AFTER as u64) / 10 + 2;
    let mut failures = Vec::new();
    for funder_pays in [true, false] {
        for step in 1..=4 {
            let written =
                crash_scenario_after(history, funder_pays, step, Some(usize::MAX), true).unwrap();
            for keep in 0..=written {
                if let Err(e) = crash_scenario_after(history, funder_pays, step, Some(keep), true) {
                    failures.push(e);
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// --- L7: secrets do not outlive their holder ---------------------------------

/// Drops `value` in place and returns the 32 bytes at `at` (a field of it)
/// afterwards. The storage stays ours (it is a `ManuallyDrop`), so the bytes
/// are what the drop left behind.
fn bytes_after_drop<T>(value: T, at: impl Fn(&T) -> *const [u8; 32]) -> [u8; 32] {
    let mut slot = std::mem::ManuallyDrop::new(value);
    let p = at(&slot);
    // Safe: `slot` is dropped exactly once, here, and never used again; the
    // bytes read are plain integers in storage `slot` still owns.
    unsafe {
        std::mem::ManuallyDrop::drop(&mut slot);
        std::ptr::read_volatile(p)
    }
}

#[test]
fn a_channel_key_seed_is_wiped_on_drop() {
    let k = ChannelKey::from_seed(&[0x5au8; 32]);
    assert_eq!(unsafe { *k.seed_location() }, [0x5au8; 32]);
    assert_eq!(bytes_after_drop(k, |k| k.seed_location()), [0u8; 32]);
}

#[test]
fn a_machine_revocation_root_is_wiped_on_drop() {
    let dir = tmpdir();
    let (f, a) = open_pair(&dir);
    drop(a);
    assert_ne!(unsafe { *f.revocation_root_location() }, [0u8; 32]);
    assert_eq!(
        bytes_after_drop(f, |m| m.revocation_root_location()),
        [0u8; 32]
    );
}

/// The closer journals the peer's close signature before it broadcasts: a
/// close lost from the mempool by a crash is rebuilt, identical, from the
/// reopened journal.
#[test]
fn a_signed_close_survives_a_restart() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 4_000_000, 4_000_000]);
    let close = f.propose_close(20_000).unwrap();
    let signed = a.on_close(&close).unwrap();
    let tx = f.on_close_signed(&signed).unwrap();
    // Again: idempotent.
    assert_eq!(f.on_close_signed(&signed).unwrap(), tx);
    drop(f);
    let f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    assert_eq!(f.phase(), Phase::Closing);
    assert_eq!(f.signed_cooperative_close(), Some(tx));
}

// --- Crossed proposals: both sides pay at the same moment ---------------------

/// The settled state the crossing tests start from (state 2).
const X_BASE: [u64; 2] = [CAP - 1_500_000, 1_500_000];
const X_F_PAYS: u64 = 300_000;
const X_A_PAYS: u64 = 100_000;
/// Both payments, merged into state 4.
const X_MERGED: [u64; 2] = [
    CAP - 1_500_000 - X_F_PAYS + X_A_PAYS,
    1_500_000 + X_F_PAYS - X_A_PAYS,
];

type Queue = std::collections::VecDeque<Message>;

/// A channel at state 2 where both sides have just proposed state 3, each
/// proposal on its way to the other.
fn crossed_pair() -> (PathBuf, Machine, Machine, Queue, Queue) {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]);
    pay(&mut a, &mut f, X_BASE);
    let uf = f
        .propose([X_BASE[0] - X_F_PAYS, X_BASE[1] + X_F_PAYS])
        .unwrap();
    let ua = a
        .propose([X_BASE[0] + X_A_PAYS, X_BASE[1] - X_A_PAYS])
        .unwrap();
    (dir, f, a, Queue::from(vec![ua]), Queue::from(vec![uf]))
}

/// Delivers the next message queued for `who` and queues its replies for the
/// other side.
fn deliver_one(
    who: To,
    f: &mut Machine,
    a: &mut Machine,
    to_f: &mut Queue,
    to_a: &mut Queue,
) -> Result<(), String> {
    let (me, inbox, outbox) = match who {
        To::F => (f, to_f, to_a),
        To::A => (a, to_a, to_f),
    };
    let m = inbox.pop_front().expect("a queued message");
    let replies = handle(me, &m).map_err(|e| format!("{who:?} refused {}: {e}", kind(&m)))?;
    outbox.extend(replies);
    Ok(())
}

/// Runs one schedule of the crossing: at each step where both sides have a
/// message waiting, `choices` (then `false`) picks who receives first (`true`:
/// the acceptor). With `crash = Some((k, side))`, `side` is killed before step
/// `k`: it reopens from its journal, both links' messages in flight are lost,
/// and the two reconnect. Returns every choice made, then checks the outcome:
/// both payments merged, state 4 on both sides, every commitment either holds
/// at the crossed state 3 revoked, payments both ways and a cooperative close
/// still working.
fn run_crossing(choices: &[bool], crash: Option<(usize, To)>) -> Result<Vec<bool>, String> {
    let (dir, mut f, mut a, mut to_f, mut to_a) = crossed_pair();
    let mut decisions = Vec::new();
    let mut step = 0usize;
    loop {
        if let Some((k, side)) = crash {
            if k == step {
                to_f.clear();
                to_a.clear();
                match side {
                    To::F => {
                        drop(f);
                        f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
                    }
                    To::A => {
                        drop(a);
                        a = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
                    }
                }
                let rf = f.reestablish().unwrap();
                let ra = a.reestablish().unwrap();
                to_f.extend(a.on_reestablish(&rf).map_err(|e| format!("{e:?}"))?);
                to_a.extend(f.on_reestablish(&ra).map_err(|e| format!("{e:?}"))?);
            }
        }
        let who = match (to_f.is_empty(), to_a.is_empty()) {
            (true, true) => break,
            (false, true) => To::F,
            (true, false) => To::A,
            (false, false) => {
                let d = choices.get(decisions.len()).copied().unwrap_or(false);
                decisions.push(d);
                if d {
                    To::A
                } else {
                    To::F
                }
            }
        };
        deliver_one(who, &mut f, &mut a, &mut to_f, &mut to_a)?;
        step += 1;
        if step > 64 {
            return Err("did not settle".into());
        }
    }
    let ctx = format!("choices={decisions:?} crash={crash:?}");
    if crash.is_some_and(|(k, _)| k >= step) {
        // The crash point lies past the end: nothing more to check here.
        return Ok(decisions);
    }
    if f.balances() != X_MERGED || a.balances() != X_MERGED {
        return Err(format!(
            "{ctx}: {:?} / {:?}, not the merge",
            f.balances(),
            a.balances()
        ));
    }
    if f.local_commit_number() != Some(4) || a.local_commit_number() != Some(4) {
        return Err(format!("{ctx}: not at state 4"));
    }
    if f.update_in_flight() || a.update_in_flight() {
        return Err(format!("{ctx}: still in flight"));
    }
    // Every variant at index 3 is revoked: each side's own commitment there
    // (the peer's payment to it) is punishable by the other, and the
    // watcher's own balance in it is located, to be claimed with the penalty.
    for (holder, watcher) in [(&f, &a), (&a, &f)] {
        let variant = holder.signed_commitment_at(3, FeeTier::Low).unwrap();
        let ours = watcher.params().funding[watcher.our_index()];
        let own = variant
            .outputs
            .iter()
            .position(|o| o.scheme != crate::sig::SchemeId::Policy && o.pubkey_hash == ours);
        match watcher.identify_spend(&variant) {
            Watch::RevokedByPeer {
                state: 3,
                to_remote,
                ..
            } if to_remote.map(|r| r.outpoint.index as usize) == own => {}
            other => {
                return Err(format!(
                    "{ctx}: a state-3 variant is not revoked: {other:?}"
                ))
            }
        }
    }
    let rf = f.reestablish().unwrap();
    let ra = a.reestablish().unwrap();
    if !a.on_reestablish(&rf).unwrap().is_empty() || !f.on_reestablish(&ra).unwrap().is_empty() {
        return Err(format!("{ctx}: not quiescent"));
    }
    let mut b = X_MERGED;
    b[FUNDER] -= 50_000;
    b[ACCEPTOR] += 50_000;
    pay(&mut f, &mut a, b);
    b[FUNDER] += 20_000;
    b[ACCEPTOR] -= 20_000;
    pay(&mut a, &mut f, b);
    let close = f.propose_close(20_000).unwrap();
    let signed = a.on_close(&close).unwrap();
    f.on_close_signed(&signed)
        .map_err(|e| format!("{ctx}: {e:?}"))?;
    Ok(decisions)
}

/// Every order in which the crossed messages can arrive, each explored
/// once: the two proposals, the two revocations, and the merged update.
fn every_crossing_schedule(crash: Option<(usize, To)>) -> (usize, Vec<String>) {
    let mut stack: Vec<Vec<bool>> = vec![Vec::new()];
    let (mut runs, mut failures) = (0, Vec::new());
    while let Some(prefix) = stack.pop() {
        runs += 1;
        match run_crossing(&prefix, crash) {
            Ok(decisions) => {
                for i in prefix.len()..decisions.len() {
                    let mut p = decisions[..i].to_vec();
                    p.push(true);
                    stack.push(p);
                }
            }
            Err(e) => failures.push(e),
        }
    }
    (runs, failures)
}

/// Both sides propose the same state at once, at every interleaving of what
/// follows: the two proposals merge into the next state, no commitment either
/// side holds at the crossed index survives unrevoked, and the channel keeps
/// paying and closes.
#[test]
fn crossed_proposals_merge_at_every_interleaving() {
    let (runs, failures) = every_crossing_schedule(None);
    assert!(runs >= 4, "only {runs} interleavings");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The same with either side killed and restarted before any step of the
/// crossing, its messages in flight lost: the reestablish resumes the merge.
#[test]
fn crossed_proposals_merge_across_a_restart_at_any_step() {
    let mut failures = Vec::new();
    for side in [To::F, To::A] {
        for k in 0..8 {
            for schedule in [vec![], vec![true; 8], vec![true, false, true, false]] {
                if let Err(e) = run_crossing(&schedule, Some((k, side))) {
                    failures.push(e);
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A crash inside the crossing handler, the merge proposal or its update, at
/// every journal write of every message the crashed side handles: it reopens
/// from its truncated journal and the two still converge on the merge.
#[test]
fn crossed_proposals_survive_a_crash_at_every_journal_write() {
    let mut failures = Vec::new();
    let mut cuts = 0;
    for side in [To::F, To::A] {
        for a_first in [false, true] {
            // The `nth` message the crashed side handles is cut after `keep`
            // of its writes.
            for nth in 0..4usize {
                for keep in 0..4usize {
                    let (dir, mut f, mut a, mut to_f, mut to_a) = crossed_pair();
                    let path = match side {
                        To::F => dir.join("f.jrnl"),
                        To::A => dir.join("a.jrnl"),
                    };
                    let mut handled = 0;
                    let mut cut = false;
                    for _ in 0..32 {
                        let who = match (to_f.is_empty(), to_a.is_empty()) {
                            (true, true) => break,
                            (false, true) => To::F,
                            (true, false) => To::A,
                            (false, false) if a_first => To::A,
                            (false, false) => To::F,
                        };
                        let before = record_count(&path);
                        deliver_one(who, &mut f, &mut a, &mut to_f, &mut to_a).unwrap();
                        if who == side {
                            if handled == nth {
                                let written = record_count(&path) - before;
                                if keep < written {
                                    keep_records(&path, before + keep);
                                    cut = true;
                                }
                                break;
                            }
                            handled += 1;
                        }
                    }
                    if !cut {
                        continue;
                    }
                    cuts += 1;
                    to_f.clear();
                    to_a.clear();
                    match side {
                        To::F => {
                            drop(f);
                            f = Machine::reopen(&path, NET, fkey(), RATE).unwrap();
                        }
                        To::A => {
                            drop(a);
                            a = Machine::reopen(&path, NET, akey(), RATE).unwrap();
                        }
                    }
                    let ctx = format!("side={side:?} a_first={a_first} nth={nth} keep={keep}");
                    if let Err(e) = reconnect(&mut f, &mut a) {
                        failures.push(format!("{ctx}: {e}"));
                        continue;
                    }
                    if f.balances() != X_MERGED || a.balances() != X_MERGED {
                        failures.push(format!("{ctx}: {:?} / {:?}", f.balances(), a.balances()));
                        continue;
                    }
                    if f.update_in_flight() || a.update_in_flight() {
                        failures.push(format!("{ctx}: in flight"));
                    }
                }
            }
        }
    }
    assert!(cuts >= 20, "only {cuts} cut points");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A crossed proposal that would not merge into a valid state, or that pays
/// the wrong way, is refused before anything is journaled or revealed.
#[test]
fn a_crossed_proposal_draining_us_is_refused() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]);
    let _uf = f.propose([CAP - 2_100_000, 2_100_000]).unwrap();
    // The acceptor "pays" by lowering the funder's balance.
    let bad = a.propose([CAP - 2_500_000, 2_500_000]).unwrap();
    let records = f.journal_records();
    assert_eq!(f.on_peer_update(&bad), Err(ChannelError::WrongDirection));
    assert_eq!(f.journal_records(), records);
}

// --- Cooperative-close fees -------------------------------------------------

/// A peer proposing a close cannot make us pay for it: an unbounded fee, or
/// one larger than the proposer's own balance, is refused before anything is
/// journaled or signed, and a fee within bounds is charged to the proposer
/// alone, our side paid in full.
#[test]
fn a_peer_proposed_close_fee_is_bounded_and_charged_to_the_proposer() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    let (_, max) = txbuild::close_fee_bounds(f.params());
    // The acceptor asks the funder to burn its balance as fee.
    let records = f.journal_records();
    for fee in [CAP - 1_000_000, max + 1, 0] {
        let close = a.close_message(fee).unwrap();
        assert_eq!(
            f.on_close(&close),
            Err(ChannelError::BadParameters),
            "fee {fee}"
        );
    }
    assert_eq!(f.journal_records(), records, "nothing journaled");
    assert_eq!(f.phase(), Phase::Open);
    // Within bounds but above what the proposer holds.
    pay(&mut a, &mut f, [CAP - 5_000, 5_000]);
    let close = a.close_message(20_000).unwrap();
    assert_eq!(f.on_close(&close), Err(ChannelError::BadParameters));
    // A sane proposal by the acceptor: the acceptor pays.
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    let close = a.propose_close(20_000).unwrap();
    let signed = f.on_close(&close).unwrap();
    let tx = a.on_close_signed(&signed).unwrap();
    let paid = |h: Hash256| -> u64 {
        tx.outputs
            .iter()
            .filter(|o| o.pubkey_hash == h)
            .map(|o| o.value.units())
            .sum()
    };
    assert_eq!(
        paid(Hash256([0xf0u8; 32])),
        CAP - 1_000_000,
        "the funder is paid in full"
    );
    assert_eq!(
        paid(Hash256([0xa0u8; 32])),
        1_000_000 - 20_000,
        "the proposer pays"
    );
    assert!(f.is_cooperative_close(&tx));
}

/// We never propose a close fee out of bounds, nor one beyond our balance.
#[test]
fn our_own_close_fee_is_bounded_too() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 10_000, 10_000]);
    let (_, max) = txbuild::close_fee_bounds(f.params());
    assert_eq!(f.propose_close(max + 1), Err(ChannelError::BadParameters));
    assert_eq!(a.propose_close(20_000), Err(ChannelError::BadParameters));
    assert_eq!(f.phase(), Phase::Open);
    assert!(f.propose_close(20_000).is_ok());
}

/// One funding per channel: a second Funding naming another outpoint is
/// refused instead of overwriting the first; the same Funding again is
/// answered again.
#[test]
fn a_second_funding_is_refused() {
    let dir = tmpdir();
    let f_signer = fkey();
    let a_signer = akey();
    let a_pub = a_signer.pubkey().to_vec();
    let payout = Hash256([0xf0u8; 32]);
    let (mut f, open) = Machine::new_funder(
        dir.join("f.jrnl"),
        NET,
        f_signer,
        a_pub,
        CAP,
        DELAY,
        DEPTH,
        RATE,
        payout,
        payout,
    )
    .unwrap();
    let (mut a, accept) = Machine::accept(
        dir.join("a.jrnl"),
        NET,
        a_signer,
        RATE,
        &open,
        payout,
        payout,
    )
    .unwrap();
    f.on_accept(&accept).unwrap();
    // A replayed Accept is refused by the engine: it never funds twice.
    assert_eq!(f.on_accept(&accept), Err(ChannelError::Unexpected));
    let outpoint = OutPoint {
        txid: Hash256([9u8; 32]),
        index: 0,
    };
    let funding = f.funding_created(outpoint).unwrap();
    let signed = a.on_funding(&funding).unwrap();
    assert_eq!(
        a.on_funding(&funding).unwrap(),
        signed,
        "the same Funding again"
    );
    let mut other = funding.clone();
    if let Message::Funding { funding_txid, .. } = &mut other {
        *funding_txid = Hash256([7u8; 32]);
    }
    assert_eq!(a.on_funding(&other), Err(ChannelError::Unexpected));
    assert_eq!(a.funding_outpoint(), Some(outpoint), "not overwritten");
}

// --- Signed control messages ------------------------------------------------

/// N1: a Close moves a channel to closing, so it is signed by the sender's
/// funding key over the channel, its side, its fee and a sequence number. One
/// made up, signed by another key, for another fee, or sent back as if from
/// the other side, is refused before anything is journaled; the genuine one,
/// replayed — even after a restart — is stale and ignored.
#[test]
fn a_close_is_taken_only_signed_and_only_once() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    let records = f.journal_records();
    let close = a.propose_close(20_000).unwrap();
    let Message::Close {
        fee,
        seq,
        signature,
    } = close.clone()
    else {
        unreachable!()
    };
    let other = ChannelKey::from_seed(&[0x5a; 32]);
    let forged = [
        Message::Close {
            fee,
            seq,
            signature: vec![0; signature.len()],
        },
        Message::Close {
            fee,
            seq,
            signature: other.sign(&super::messages::control_message(
                f.channel_id(),
                ACCEPTOR as u8,
                seq,
                super::messages::CONTROL_CLOSE,
                &fee.to_le_bytes(),
            )),
        },
        Message::Close {
            fee: fee + 1,
            seq,
            signature: signature.clone(),
        },
        Message::Close {
            fee,
            seq: seq + 1,
            signature: signature.clone(),
        },
    ];
    for m in &forged {
        assert_eq!(f.on_close(m), Err(ChannelError::BadSignature), "{m:?}");
        assert_eq!(f.on_close_crossing(m), Err(ChannelError::BadSignature));
    }
    // Our own side's signature, sent back to us, is not the peer's.
    let mine = f.close_message(20_000).unwrap();
    assert_eq!(a.on_close(&close), Err(ChannelError::BadSignature));
    assert_eq!(f.on_close(&mine), Err(ChannelError::BadSignature));
    assert_eq!(f.phase(), Phase::Open);
    // One record: the sequence number our own Close above used.
    assert_eq!(f.journal_records(), records + 1);

    let signed = f.on_close(&close).unwrap();
    assert!(matches!(signed, Message::CloseSigned { .. }));
    assert_eq!(f.on_close(&close), Err(ChannelError::Stale));
    drop(f);
    let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    assert_eq!(
        f.on_close(&close),
        Err(ChannelError::Stale),
        "after a restart"
    );
}

/// N1: Ready is signed too; a forged one is refused and a replayed one is
/// stale.
#[test]
fn a_ready_is_taken_only_signed_and_only_once() {
    let dir = tmpdir();
    let (mut f, _a) = open_pair(&dir);
    let m = super::messages::control_message(
        f.channel_id(),
        ACCEPTOR as u8,
        99,
        super::messages::CONTROL_READY,
        &[],
    );
    let forged = Message::Ready {
        seq: 99,
        signature: ChannelKey::from_seed(&[0x5b; 32]).sign(&m),
    };
    assert_eq!(f.on_ready(&forged), Err(ChannelError::BadSignature));
    let genuine = Message::Ready {
        seq: 99,
        signature: akey().sign(&m),
    };
    assert_eq!(f.on_ready(&genuine), Ok(()));
    assert_eq!(f.on_ready(&genuine), Err(ChannelError::Stale));
}

/// N1: the reestablish proof covers every counter the sender reports: a
/// relay that alters where a side says it stands breaks the proof.
#[test]
fn a_tampered_reestablish_is_refused() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    let honest = a.reestablish_for([0x42; 32]);
    let Message::Reestablish {
        channel_id,
        local_commit_number,
        remote_commit_number,
        next_revocation_sent,
        next_revocation_recv,
        nonce,
        direction,
        proof,
    } = honest.clone()
    else {
        unreachable!()
    };
    let tampered = Message::Reestablish {
        channel_id,
        local_commit_number: local_commit_number + 1,
        remote_commit_number,
        next_revocation_sent,
        next_revocation_recv,
        nonce,
        direction,
        proof,
    };
    assert_eq!(
        f.on_reestablish(&tampered),
        Err(ChannelError::BadReestablish)
    );
    assert!(f.on_reestablish(&honest).is_ok());
}
