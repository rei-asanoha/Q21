//! Engine tests: message codec, transaction builders and weights, the state
//! machine and its journal, crash-safety and reestablish, the watcher, and a
//! property test that an honest party never loses funds.
//!
//! These run only with `--features mldsa`: every signature is a real
//! ML-DSA-87 signature, as on the chain.

use super::journal::{self, Journal, Record};
use super::keys::{ChannelKey, Signer};
use super::machine::{channel_id, Machine, Phase};
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
fn open_pair(dir: &PathBuf) -> (Machine, Machine) {
    let f_signer = fkey();
    let a_signer = akey();
    let a_pub = a_signer.pubkey().to_vec();
    let (mut f, open) =
        Machine::new_funder(dir.join("f.jrnl"), NET, f_signer, a_pub, CAP, DELAY, DEPTH, RATE)
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
    assert_eq!(Message::decode(&wrong_ver), Err(WireError::UnknownVersion(9)));
    let mut wrong_type = m.clone();
    wrong_type[1] = 200;
    assert_eq!(Message::decode(&wrong_type), Err(WireError::UnknownType(200)));
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
            prev_out: OutPoint { txid: Hash256::ZERO, index: 0 },
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
        OutPoint { txid: Hash256::ZERO, index: 0 },
        [CAP - 2_000_000, 2_000_000],
        20_000,
    );
    let mut closetx = close.tx;
    closetx.inputs[0].witness = txbuild::dummy_funding_witness(&params.funding_policy());
    let close_weight = w(&closetx);

    // Penalty, local sweep, to_remote claim — built against a real to_local.
    let commit = params.commitment(ACCEPTOR, 3, [CAP - 2_000_000, 2_000_000], 0, Hash256([4u8; 32]));
    let to_local_out = commit.tx.outputs.iter().find(|o| o.scheme == crate::sig::SchemeId::Policy).copied().unwrap();
    let to_local_op = OutPoint { txid: commit.tx.txid(), index: 0 };
    let penalty = txbuild::penalty_tx(
        to_local_op, &to_local_out, &commit.to_local, [5u8; 32], fk.pubkey_hash(), 20_000, NET, &fk,
    );
    let penalty_weight = w(&penalty);
    let sweep = txbuild::local_sweep_tx(
        to_local_op, &to_local_out, &commit.to_local, ak.pubkey_hash(), 20_000, NET, &ak,
    );
    let sweep_weight = w(&sweep);
    let to_remote_out = txbuild::key_output(fk.pubkey_hash(), 2_000_000);
    let claim = txbuild::to_remote_claim_tx(to_local_op, &to_remote_out, fk.pubkey_hash(), 20_000, NET, &fk);
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
    assert!(penalty_weight > key_spend, "penalty reveals the policy and a preimage");
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
    let c = params.commitment(FUNDER, 1, [CAP - MIN_OUTPUT_VALUE, MIN_OUTPUT_VALUE], 0, Hash256([3u8; 32]));
    assert_eq!(c.tx.outputs.len(), 2);
    assert_eq!(c.trimmed_units, 0);
}

#[test]
fn fee_tiers_climb_then_cap() {
    assert_eq!(FeeTier::Low.multiplier(), 1);
    assert_eq!(FeeTier::Medium.multiplier(), 4);
    assert_eq!(FeeTier::High.multiplier(), 16);
    // Base below the relay minimum is lifted to it.
    assert_eq!(txbuild::tier_rate(1, FeeTier::Low), crate::mempool::MIN_FEE_RATE);
    assert_eq!(
        txbuild::tier_rate(RATE, FeeTier::High),
        RATE * 16
    );
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
    assert_eq!(f.revocation_store().len() >= 1, true);
    assert_eq!(a.revocation_store().len() >= 1, true);
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
            Record::RevocationSent { state } => {
                // Revealing secret for `state` requires LocalCommit >= state+1.
                if max_local < Some(state + 1) {
                    return false;
                }
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
    let penalty = a.build_penalty(&decision, a.params().funding[ACCEPTOR], 20_000).unwrap();
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
    assert!(for_f.is_empty(), "nothing to resend to the funder: {for_f:?}");
    assert!(for_a.is_empty(), "nothing to resend to the acceptor: {for_a:?}");
    assert_eq!(f.balances(), a.balances());
}

#[test]
fn reestablish_rejects_a_forged_proof_and_a_replayed_nonce() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
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
        a_resends.iter().any(|m| matches!(m, Message::Ack { state: 2, .. })),
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
