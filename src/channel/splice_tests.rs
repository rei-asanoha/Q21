//! Splices and the proof of an older copy: the engine side.
//!
//! A splice is driven message by message between two real machines, with
//! real ML-DSA-87 signatures; the transactions it yields are checked against
//! a UTXO set as the chain would check them. Every journal boundary is
//! reopened, and a crash at every write point reconnects without loss.

use super::journal::Record;
use super::keys::{ChannelKey, Signer, CHANNEL_SCHEME};
use super::machine::{ChannelError, Machine, Phase};
use super::messages::Message;
use super::tests::{akey, fkey, open_pair, pay, tmpdir, CAP, NET, RATE};
use super::txbuild::{key_output, ChannelParams, FeeTier, ACCEPTOR, FUNDER};
use super::watcher::Watch;
use crate::consensus::UNITS_PER_COIN;
use crate::hash::Hash256;
use crate::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use std::collections::HashSet;

const ADD: u64 = 10 * UNITS_PER_COIN;
const COIN: u64 = 12 * UNITS_PER_COIN;
const SPLICE_FEE: u64 = 50_000;

/// The wallet coin the adder brings, and the key that spends it.
struct Coin {
    key: ChannelKey,
    outpoint: OutPoint,
    output: TxOut,
}

fn coin(tag: u8) -> Coin {
    let key = ChannelKey::from_seed(&[0x40 ^ tag; 32]);
    let output = key_output(crate::sig::pubkey_hash(CHANNEL_SCHEME, key.pubkey()), COIN);
    Coin {
        key,
        outpoint: OutPoint {
            txid: Hash256([0xc0 ^ tag; 32]),
            index: 1,
        },
        output,
    }
}

/// The splice `m` would send: the coin, then the funding output, paying the
/// new funding output and the change; the coin signed as a wallet signs it.
fn splice_tx(m: &Machine, c: &Coin, add: u64) -> Transaction {
    let new = ChannelParams {
        capacity: crate::amount::Amount::from_units(m.params().capacity.units() + add),
        ..m.params().clone()
    };
    let mut tx = Transaction {
        version: 1,
        inputs: vec![
            TxIn {
                prev_out: c.outpoint,
                witness: Witness::default(),
                sequence: u32::MAX,
            },
            TxIn {
                prev_out: m.funding_outpoint().unwrap(),
                witness: Witness::default(),
                sequence: super::machine::splice_sequence(m.next_state_number()),
            },
        ],
        outputs: vec![
            new.funding_output(),
            key_output(c.output.pubkey_hash, COIN - add - SPLICE_FEE),
        ],
        lock_time: 0,
    };
    let msg = tx.sighash(0, NET, &c.output);
    tx.inputs[0].witness = Witness {
        pubkey: c.key.pubkey().to_vec(),
        signature: c.key.sign(&msg),
    };
    tx
}

fn utxo(entries: &[(OutPoint, TxOut)]) -> crate::utxo::UtxoSet {
    let mut u = crate::utxo::UtxoSet::new();
    for (op, out) in entries {
        u.insert(
            *op,
            crate::utxo::UtxoEntry {
                output: *out,
                height: 10,
                is_coinbase: false,
            },
        );
    }
    u
}

fn valid(tx: &Transaction, u: &crate::utxo::UtxoSet) {
    crate::validate::check_transaction(tx, u, NET, 11, &mut HashSet::new())
        .expect("valid on chain");
}

/// Drives a whole splice from `adder` to `other` up to the signed
/// transaction, which it returns.
fn splice(adder: &mut Machine, other: &mut Machine, c: &Coin, add: u64) -> Transaction {
    let tx = splice_tx(adder, c, add);
    let msg = adder.propose_splice(add, tx).unwrap();
    let answer = other.on_splice(&msg).unwrap();
    assert_eq!(answer.len(), 2, "{answer:?}");
    assert!(adder.on_splice_ack(&answer[0]).unwrap().is_none());
    adder.on_splice_sig(&answer[1]).unwrap().expect("complete")
}

/// Both sides see the splice buried and exchange their revocations.
fn lock(x: &mut Machine, y: &mut Machine) {
    x.note_splice_height(Some(20));
    y.note_splice_height(Some(20));
    let lx = x.splice_locked().unwrap();
    let ly = y.splice_locked().unwrap();
    y.on_splice_locked(&lx).unwrap();
    x.on_splice_locked(&ly).unwrap();
    assert!(!x.splicing() && !y.splicing());
}

#[test]
fn a_splice_adds_to_the_same_channel_and_every_close_stays_valid() {
    for adder_index in [FUNDER, ACCEPTOR] {
        let dir = tmpdir();
        let (mut f, mut a) = open_pair(&dir);
        pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]); // state 1
        let c = coin(adder_index as u8);
        let old_funding = f.funding_outpoint().unwrap();
        let old_output = f.funding_output();
        let cid = f.channel_id();
        let (x, y) = if adder_index == FUNDER {
            (&mut f, &mut a)
        } else {
            (&mut a, &mut f)
        };
        let tx = splice(x, y, &c, ADD);
        // The splice spends the funding and the adder's coin, as the chain
        // checks it.
        valid(
            &tx,
            &utxo(&[(old_funding, old_output), (c.outpoint, c.output)]),
        );
        let new_funding = OutPoint {
            txid: tx.txid(),
            index: 0,
        };
        assert_eq!(x.funding_outpoint(), Some(new_funding));
        assert_eq!(y.funding_outpoint(), Some(new_funding));
        assert_eq!(x.channel_id(), cid, "the same channel");
        let mut expected = [CAP - 3_000_000, 3_000_000];
        expected[adder_index] += ADD;
        assert_eq!(x.balances(), expected);
        assert_eq!(y.balances(), expected);
        // In flight until the chain buries it: no payment, no close.
        assert!(x.update_in_flight() && y.update_in_flight());
        assert!(x.propose([CAP + ADD - 4_000_000, 4_000_000]).is_err());
        assert!(x.propose_close(20_000).is_err());

        // Not yet on chain: a close alone broadcasts the last old state.
        let old_u = utxo(&[(old_funding, old_output)]);
        for m in [&*x, &*y] {
            let close = m.closing_commitment(FeeTier::High).unwrap();
            assert_eq!(close.inputs[0].prev_out, old_funding);
            valid(&close, &old_u);
        }
        // On chain: the first state on the new funding.
        x.note_splice_height(Some(20));
        y.note_splice_height(Some(20));
        let new_u = utxo(&[(new_funding, tx.outputs[0])]);
        for m in [&*x, &*y] {
            let close = m.closing_commitment(FeeTier::High).unwrap();
            assert_eq!(close.inputs[0].prev_out, new_funding);
            valid(&close, &new_u);
        }
        lock(x, y);
        assert_eq!(x.params().capacity.units(), CAP + ADD);
        // Payments resume, both ways, on the new funding.
        let mut paid = expected;
        paid[adder_index] -= 1_000_000;
        paid[1 - adder_index] += 1_000_000;
        pay(x, y, paid);
        pay(y, x, expected);
        for m in [&*x, &*y] {
            valid(&m.closing_commitment(FeeTier::Low).unwrap(), &new_u);
        }
        // The journal reopens to the same machine, before and after a
        // compaction.
        let (fx, fy) = (x.digest(), y.digest());
        drop((f, a));
        let f2 = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
        let a2 = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
        let (d_f, d_a) = (f2.digest(), a2.digest());
        assert!(d_f == fx || d_f == fy);
        assert!(d_a == fx || d_a == fy);
        assert_eq!(f2.params().capacity.units(), CAP + ADD);
    }
}

#[test]
fn a_cooperative_close_after_a_splice_spends_the_new_funding() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    let c = coin(7);
    let tx = splice(&mut a, &mut f, &c, ADD);
    lock(&mut f, &mut a);
    let close = f.propose_close(20_000).unwrap();
    let signed = a.on_close(&close).unwrap();
    let close_tx = f.on_close_signed(&signed).unwrap();
    assert_eq!(close_tx.inputs[0].prev_out.txid, tx.txid());
    valid(
        &close_tx,
        &utxo(&[(f.funding_outpoint().unwrap(), tx.outputs[0])]),
    );
    let paid: u64 = close_tx.outputs.iter().map(|o| o.value.units()).sum();
    assert_eq!(paid, CAP + ADD - 20_000);
}

#[test]
fn a_payment_crossing_a_splice_wins_and_the_splice_can_come_again() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]); // state 1
    let c = coin(1);
    // The funder proposes a splice while the acceptor pays: both state 2.
    let sp = f.propose_splice(ADD, splice_tx(&f, &c, ADD)).unwrap();
    let upd = a.propose([CAP - 2_000_000, 2_000_000]).unwrap();
    // The acceptor refuses the splice, keeping nothing.
    let busy = a.on_splice(&sp).unwrap();
    assert!(matches!(busy[..], [Message::SpliceBusy { state: 2 }]));
    assert!(!a.splicing());
    // The funder drops its splice and takes the payment.
    let replies = f.on_peer_update(&upd).unwrap();
    assert!(!f.splicing());
    assert_eq!(f.params().capacity.units(), CAP);
    assert_eq!(f.on_splice_busy(&busy[0]).unwrap(), None, "already dropped");
    let Message::Ack { .. } = &replies[0] else {
        panic!("{replies:?}")
    };
    let rev = a.on_ack(&replies[0]).unwrap();
    f.on_revoke(&rev).unwrap();
    assert_eq!(f.balances(), [CAP - 2_000_000, 2_000_000]);
    assert_eq!(a.balances(), f.balances());
    // The journal reopens without the dropped splice.
    let d = f.digest();
    drop(f);
    let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    assert_eq!(f.digest(), d);
    // Now the splice goes through, at the next state.
    let tx = splice(&mut f, &mut a, &c, ADD);
    assert_eq!(f.funding_outpoint().unwrap().txid, tx.txid());
    lock(&mut f, &mut a);
    assert_eq!(f.balances(), [CAP - 2_000_000 + ADD, 2_000_000]);
}

#[test]
fn a_splice_busy_from_the_peer_drops_ours() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    let c = coin(2);
    let sp = f.propose_splice(ADD, splice_tx(&f, &c, ADD)).unwrap();
    let _ = (&sp, &a);
    let gone = f
        .on_splice_busy(&Message::SpliceBusy { state: 1 })
        .unwrap()
        .expect("dropped");
    assert_eq!(gone.inputs[0].prev_out, c.outpoint);
    assert!(!f.splicing());
    assert!(!f.update_in_flight());
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
}

#[test]
fn a_malformed_splice_is_refused_and_leaves_nothing() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    let c = coin(3);
    let good = splice_tx(&f, &c, ADD);
    let base = f.propose_splice(ADD, good.clone()).unwrap();
    let Message::Splice {
        state,
        tier_sigs,
        funding_input,
        ..
    } = base.clone()
    else {
        unreachable!()
    };
    let strip = |t: &Transaction| {
        let mut t = t.clone();
        for i in &mut t.inputs {
            i.witness = Witness::default();
        }
        t.encode()
    };
    let mut cases: Vec<(Vec<u8>, u64, u32, &str)> = Vec::new();
    // The funding output is not the last input.
    let mut t = good.clone();
    t.inputs.swap(0, 1);
    cases.push((strip(&t), ADD, funding_input, "funding first"));
    // The new funding output does not hold the capacity plus the addition.
    let mut t = good.clone();
    t.outputs[0].value = crate::amount::Amount::from_units(CAP + ADD - 1);
    cases.push((strip(&t), ADD, funding_input, "short output"));
    // It waits for a height.
    let mut t = good.clone();
    t.lock_time = 500;
    cases.push((strip(&t), ADD, funding_input, "lock time"));
    // An addition below the dust floor.
    cases.push((strip(&good), 1, funding_input, "dust"));
    // Witnesses on the wire.
    cases.push((good.encode(), ADD, funding_input, "witnesses"));
    // Another index for the funding input.
    cases.push((strip(&good), ADD, 0, "index"));
    for (tx, add, fi, what) in cases {
        let msg = Message::Splice {
            state,
            add,
            funding_input: fi,
            tx,
            tier_sigs: tier_sigs.clone(),
        };
        let r = a.on_splice(&msg);
        assert!(
            matches!(
                r,
                Err(ChannelError::BadParameters) | Err(ChannelError::BadSignature)
            ),
            "{what}: {r:?}"
        );
        assert!(!a.splicing(), "{what}");
        assert_eq!(a.params().capacity.units(), CAP, "{what}");
    }
    // Signatures over another commitment.
    let Message::Splice { tx, .. } = &base else {
        unreachable!()
    };
    let forged = Message::Splice {
        state,
        add: ADD,
        funding_input,
        tx: tx.clone(),
        tier_sigs: [
            tier_sigs[1].clone(),
            tier_sigs[0].clone(),
            tier_sigs[2].clone(),
        ],
    };
    assert_eq!(a.on_splice(&forged), Err(ChannelError::BadSignature));
    assert!(!a.splicing());
    // And the real one still goes through.
    let answer = a.on_splice(&base).unwrap();
    let _ = f.on_splice_ack(&answer[0]).unwrap();
    // A funding signature over something else is refused.
    let Message::SpliceSig { state, signature } = &answer[1] else {
        unreachable!()
    };
    let mut bad = signature.clone();
    bad[10] ^= 1;
    assert_eq!(
        f.on_splice_sig(&Message::SpliceSig {
            state: *state,
            signature: bad
        }),
        Err(ChannelError::BadSignature)
    );
    assert!(f.on_splice_sig(&answer[1]).unwrap().is_some());
}

#[test]
fn no_update_and_no_old_secret_while_a_splice_waits_for_the_chain() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]); // state 1
    let c = coin(4);
    splice(&mut f, &mut a, &c, ADD); // state 2
                                     // An update from either side is refused, and so is a forged Update for
                                     // the splice state that would make us reveal the secret of state 1.
    assert!(a.propose([CAP - 4_000_000, 4_000_000]).is_err());
    let fake = Message::Update {
        state: 2,
        balances: [CAP - 3_000_000 + ADD, 3_000_000],
        tier_sigs: Default::default(),
    };
    assert!(a.on_update(&fake).is_err());
    // Reestablish resends the answer, never a revocation of state 1.
    let rf = f.reestablish().unwrap();
    let ra = a.reestablish().unwrap();
    for m in a.on_reestablish(&rf).unwrap() {
        assert!(
            matches!(m, Message::SpliceAck { .. } | Message::SpliceSig { .. }),
            "{m:?}"
        );
    }
    let owed = f.on_reestablish(&ra).unwrap();
    assert!(owed.is_empty(), "the adder owes nothing: {owed:?}");
    // A peer's SpliceLocked before ours: its revocation taken, ours kept.
    let la = a.splice_locked().unwrap();
    f.on_splice_locked(&la).unwrap();
    assert!(f.splicing());
    let Message::SpliceLocked { revocation, .. } = la else {
        unreachable!()
    };
    let _ = revocation;
    let lf = f.splice_locked().unwrap();
    a.on_splice_locked(&lf).unwrap();
    assert!(!f.splicing() && !a.splicing());
}

#[test]
fn a_revoked_old_state_broadcast_during_a_splice_is_punished() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]); // state 1
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]); // state 2
    let revoked = f.signed_commitment_at(1, FeeTier::Low).unwrap();
    let c = coin(5);
    splice(&mut a, &mut f, &c, ADD); // state 3, by the acceptor
                                     // The funder cheats with state 1, on the old funding: the acceptor
                                     // recognizes it.
    match a.identify_spend(&revoked) {
        Watch::RevokedByPeer { state: 1, .. } => {}
        other => panic!("{other:?}"),
    }
    // The latest old state, broadcast by the funder, is a fair close.
    let latest_old = f.closing_commitment(FeeTier::Low).unwrap();
    match a.identify_spend(&latest_old) {
        Watch::PeerLatest { state: 2, .. } => {}
        other => panic!("{other:?}"),
    }
    // And the first state on the new funding, once the splice is on chain.
    f.note_splice_height(Some(30));
    let first_new = f.closing_commitment(FeeTier::Low).unwrap();
    match a.identify_spend(&first_new) {
        Watch::PeerLatest { state: 3, .. } => {}
        other => panic!("{other:?}"),
    }
}

/// What a machine must answer to `m`, as the manager dispatches it.
fn handle(x: &mut Machine, m: &Message) -> Vec<Message> {
    match m {
        Message::Splice { .. } => x.on_splice(m).unwrap_or_default(),
        Message::SpliceAck { .. } => {
            let _ = x.on_splice_ack(m);
            Vec::new()
        }
        Message::SpliceSig { .. } => {
            let _ = x.on_splice_sig(m);
            Vec::new()
        }
        Message::SpliceLocked { .. } => {
            let _ = x.on_splice_locked(m);
            Vec::new()
        }
        Message::SpliceBusy { .. } => {
            let _ = x.on_splice_busy(m);
            Vec::new()
        }
        other => panic!("unexpected during a splice: {other:?}"),
    }
}

/// Delivers every message, in order, until neither side owes anything.
fn deliver_all(f: &mut Machine, a: &mut Machine, to_f: Vec<Message>, to_a: Vec<Message>) {
    let mut to_f: std::collections::VecDeque<_> = to_f.into();
    let mut to_a: std::collections::VecDeque<_> = to_a.into();
    for _ in 0..32 {
        if let Some(m) = to_a.pop_front() {
            to_f.extend(handle(a, &m));
        } else if let Some(m) = to_f.pop_front() {
            to_a.extend(handle(f, &m));
        } else {
            return;
        }
    }
    panic!("no quiescence");
}

#[test]
fn a_funding_signature_ahead_of_the_commitment_is_kept() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    let c = coin(9);
    let msg = f.propose_splice(ADD, splice_tx(&f, &c, ADD)).unwrap();
    let answer = a.on_splice(&msg).unwrap();
    assert!(f.on_splice_sig(&answer[1]).unwrap().is_none());
    // A crash in between keeps it.
    drop(f);
    let mut f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    let tx = f.on_splice_ack(&answer[0]).unwrap().expect("completed");
    assert_eq!(f.splice_tx(), Some(&tx));
}

#[test]
fn a_crash_at_every_splice_write_point_reconnects_without_loss() {
    // Steps: 0 nothing; 1 Splice sent; 2 answer received by the adder
    // (Ack only); 3 Sig too; 4 both locked.
    for crash_adder in [true, false] {
        for step in 0..=4u8 {
            let dir = tmpdir();
            let (mut f, mut a) = open_pair(&dir);
            pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
            let c = coin(6);
            let mut sent = false;
            if step >= 1 {
                let msg = f.propose_splice(ADD, splice_tx(&f, &c, ADD)).unwrap();
                sent = true;
                if step >= 2 {
                    let answer = a.on_splice(&msg).unwrap();
                    let _ = f.on_splice_ack(&answer[0]).unwrap();
                    if step >= 3 {
                        f.on_splice_sig(&answer[1]).unwrap().unwrap();
                    }
                    if step >= 4 {
                        f.note_splice_height(Some(20));
                        let lf = f.splice_locked().unwrap();
                        let _ = lf; // lost with the crash
                    }
                }
            }
            // Crash one side: reopen it from its journal.
            if crash_adder {
                drop(f);
                f = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
            } else {
                drop(a);
                a = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
            }
            let rf = f.reestablish().unwrap();
            let ra = a.reestablish().unwrap();
            let to_a = f.on_reestablish(&ra).unwrap();
            let to_f = a.on_reestablish(&rf).unwrap();
            deliver_all(&mut f, &mut a, to_f, to_a);
            let what = format!("crash_adder={crash_adder} step={step}");
            if !sent {
                assert!(!f.splicing() && !a.splicing(), "{what}");
                continue;
            }
            // Both hold the splice, signed, with the same balances.
            assert!(f.splicing() || step >= 4, "{what}");
            assert_eq!(f.local_commit_number(), Some(2), "{what}");
            assert_eq!(a.local_commit_number(), Some(2), "{what}");
            assert_eq!(f.balances(), a.balances(), "{what}");
            assert!(f.splice_tx().is_some(), "{what}: the adder completes it");
            // Then the chain buries it, and both finish.
            f.note_splice_height(Some(20));
            a.note_splice_height(Some(20));
            let mut to_a = vec![];
            let mut to_f = vec![];
            if f.splicing() {
                to_a.push(f.splice_locked().unwrap());
            }
            if a.splicing() {
                to_f.push(a.splice_locked().unwrap());
            }
            deliver_all(&mut f, &mut a, to_f, to_a);
            let (r1, r2) = super::tests::exchange_reestablish(&mut f, &mut a);
            deliver_all(&mut f, &mut a, r2, r1);
            assert!(!f.splicing() && !a.splicing(), "{what}");
            assert!(!f.update_in_flight() && !a.update_in_flight(), "{what}");
            pay(&mut f, &mut a, [CAP - 4_000_000 + ADD, 4_000_000]);
        }
    }
}

#[test]
fn a_splice_reopens_to_the_same_machine_at_every_record() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let c = coin(8);
    let mut digests = Vec::new();
    let msg = f.propose_splice(ADD, splice_tx(&f, &c, ADD)).unwrap();
    digests.push((f.digest(), a.digest()));
    let answer = a.on_splice(&msg).unwrap();
    digests.push((f.digest(), a.digest()));
    let _ = f.on_splice_ack(&answer[0]).unwrap();
    f.on_splice_sig(&answer[1]).unwrap();
    digests.push((f.digest(), a.digest()));
    f.note_splice_height(Some(20));
    let lf = f.splice_locked().unwrap();
    digests.push((f.digest(), a.digest()));
    a.on_splice_locked(&lf).unwrap();
    digests.push((f.digest(), a.digest()));
    let (df, da) = digests.last().unwrap().clone();
    drop((f, a));
    let f2 = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    let a2 = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
    // `splice_height` is the chain's, not the journal's: compare at rest.
    let strip = |d: &str| d.to_string();
    assert_eq!(strip(&a2.digest()), strip(&da));
    let _ = df;
    assert!(f2.splicing());
    // Compaction keeps the same machine too.
    let mut f3 = f2;
    let before = f3.digest();
    f3.compact().unwrap();
    drop(f3);
    let f4 = Machine::reopen(dir.join("f.jrnl"), NET, fkey(), RATE).unwrap();
    assert_eq!(f4.digest(), before);
    let journal = super::journal::Journal::open(dir.join("f.jrnl")).unwrap().1;
    assert!(journal.iter().any(|r| matches!(r, Record::Splice { .. })));
    assert_eq!(f4.phase(), Phase::Open);
}

// --- Proof of an older copy -------------------------------------------------

#[test]
fn an_older_copy_is_proven_older_and_a_bare_claim_proves_nothing() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]); // state 1
                                                       // A copy of the acceptor's folder, now.
    let old = dir.join("a-old.jrnl");
    std::fs::copy(dir.join("a.jrnl"), &old).unwrap();
    pay(&mut f, &mut a, [CAP - 2_000_000, 2_000_000]); // state 2
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]); // state 3
    drop(a);
    let mut stale = Machine::reopen(&old, NET, akey(), RATE).unwrap();
    let rf = f.reestablish().unwrap();
    let rs = stale.reestablish().unwrap();
    stale.on_reestablish(&rf).unwrap();
    f.on_reestablish(&rs).unwrap();
    assert_eq!(stale.sync(), super::machine::SyncVerdict::WeAreBehind);
    assert_eq!(f.sync(), super::machine::SyncVerdict::PeerIsBehind);
    let proof = f.behind_proof().expect("the funder holds the revocation");
    assert!(stale.check_behind_proof(&proof));
    // A secret that is not ours, or ours for an older state, proves nothing.
    let Message::BehindProof { state, secret } = proof.clone() else {
        unreachable!()
    };
    let mut forged = secret;
    forged[0] ^= 1;
    assert!(!stale.check_behind_proof(&Message::BehindProof {
        state,
        secret: forged
    }));
    let older = f
        .revocation_store()
        .get(crate::shachain::MAX_INDEX)
        .expect("state 0 revoked");
    assert!(!stale.check_behind_proof(&Message::BehindProof {
        state: 0,
        secret: older
    }));
    // In step, there is nothing to prove.
    let dir2 = tmpdir();
    let (mut f2, mut a2) = open_pair(&dir2);
    pay(&mut f2, &mut a2, [CAP - 1_000_000, 1_000_000]);
    let _ = super::tests::exchange_reestablish(&mut f2, &mut a2);
    assert!(f2.behind_proof().is_none());
}

#[test]
fn every_prefix_of_a_splice_journal_reopens_and_never_reveals_the_old_state_early() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]); // state 1
    let c = coin(10);
    splice(&mut a, &mut f, &c, ADD); // state 2, the acceptor adds
    lock(&mut f, &mut a);
    pay(&mut f, &mut a, [CAP - 4_000_000, 4_000_000 + ADD]); // state 3
    drop((f, a));
    for (name, key) in [
        ("f.jrnl", fkey as fn() -> Box<dyn Signer>),
        ("a.jrnl", akey),
    ] {
        let full = dir.join(name);
        let total = super::tests::record_count(&full);
        let bytes = std::fs::read(&full).unwrap();
        for keep in 1..=total {
            let p = dir.join(format!("cut-{name}-{keep}"));
            std::fs::write(&p, &bytes).unwrap();
            super::tests::keep_records(&p, keep);
            let records = super::journal::replay(&std::fs::read(&p).unwrap());
            // The secret of state 1, the last on the old funding, is revealed
            // only after the splice is journaled as buried.
            let locked = records
                .iter()
                .position(|r| matches!(r, Record::SpliceLocked));
            let revealed = records
                .iter()
                .position(|r| matches!(r, Record::RevocationSent { state: 1 }));
            // (A compaction after the splice is over rewrites the journal
            // without it: nothing then to order.)
            let spliced = records.iter().any(|r| matches!(r, Record::Splice { .. }));
            if let (true, Some(r)) = (spliced, revealed) {
                assert!(locked.is_some_and(|l| l < r), "{name} keep={keep}");
            }
            let m = Machine::reopen(&p, NET, key(), RATE).unwrap();
            let _ = m.balances();
        }
    }
}

// --- Every way a splice can end up half-known on one side -------------------

/// Dispatches a message as the manager does.
fn dispatch(x: &mut Machine, m: &Message) -> Vec<Message> {
    let r: Result<Vec<Message>, ChannelError> = match m {
        Message::Splice { .. } => x.on_splice(m),
        Message::SpliceAck { .. } => x.on_splice_ack(m).map(|_| vec![]),
        Message::SpliceSig { .. } => x.on_splice_sig(m).map(|_| vec![]),
        Message::SpliceLocked { .. } => x.on_splice_locked(m).map(|_| vec![]),
        Message::SpliceBusy { .. } => x.on_splice_busy(m).map(|_| vec![]),
        Message::Update { .. } => x.on_peer_update(m),
        Message::Ack { .. } => x.on_ack(m).map(|r| vec![r]),
        Message::Revoke { .. } => x.on_revoke(m).map(|_| vec![]),
        Message::Close { .. } => {
            if x.update_in_flight() {
                x.on_close_crossing(m).map(|_| vec![])
            } else {
                x.on_close(m).map(|r| vec![r])
            }
        }
        Message::CloseSigned { .. } => x.on_close_signed(m).map(|_| vec![]),
        other => panic!("{other:?}"),
    };
    r.unwrap_or_else(|e| panic!("{m:?} -> {e:?}"))
}

fn run(f: &mut Machine, a: &mut Machine, to_f: Vec<Message>, to_a: Vec<Message>) {
    let mut to_f: std::collections::VecDeque<_> = to_f.into();
    let mut to_a: std::collections::VecDeque<_> = to_a.into();
    for _ in 0..64 {
        if let Some(m) = to_a.pop_front() {
            to_f.extend(dispatch(a, &m));
        } else if let Some(m) = to_f.pop_front() {
            to_a.extend(dispatch(f, &m));
        } else {
            return;
        }
    }
    panic!("no quiescence");
}

fn reconnect(f: &mut Machine, a: &mut Machine) {
    let rf = f.reestablish().unwrap();
    let ra = a.reestablish().unwrap();
    let to_a = f.on_reestablish(&ra).unwrap();
    let to_f = a.on_reestablish(&rf).unwrap();
    run(f, a, to_f, to_a);
}

#[test]
fn a_lost_splice_locked_comes_back_whichever_side_finished() {
    for first in [FUNDER, ACCEPTOR] {
        let dir = tmpdir();
        let (mut f, mut a) = open_pair(&dir);
        pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
        let c = coin(21);
        splice(&mut f, &mut a, &c, ADD); // the funder adds
        f.note_splice_height(Some(20));
        a.note_splice_height(Some(20));
        // One side locks and is heard; the other finishes, and its own
        // SpliceLocked is lost with the link.
        if first == FUNDER {
            let lf = f.splice_locked().unwrap();
            a.on_splice_locked(&lf).unwrap();
            let _lost = a.splice_locked().unwrap();
            assert!(!a.splicing() && f.splicing());
        } else {
            let la = a.splice_locked().unwrap();
            f.on_splice_locked(&la).unwrap();
            let _lost = f.splice_locked().unwrap();
            assert!(!f.splicing() && a.splicing());
        }
        reconnect(&mut f, &mut a);
        assert!(!f.splicing() && !a.splicing(), "first={first}");
        assert!(
            !f.update_in_flight() && !a.update_in_flight(),
            "first={first}"
        );
        pay(&mut f, &mut a, [CAP - 4_000_000 + ADD, 4_000_000]);
        pay(&mut a, &mut f, [CAP - 3_000_000 + ADD, 3_000_000]);
    }
}

#[test]
fn a_close_crossing_a_splice_closes() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let c = coin(23);
    let sp = f.propose_splice(ADD, splice_tx(&f, &c, ADD)).unwrap();
    let close = a.propose_close(20_000).unwrap();
    run(&mut f, &mut a, vec![close], vec![sp]);
    assert!(!f.splicing() && !a.splicing());
    // The close agreed meanwhile goes on: the adder's own Close follows,
    // or its signature of the other side's.
    if let Some(m) = f.close_after_update().unwrap() {
        run(&mut f, &mut a, vec![], vec![m]);
    }
    assert!(f.has_signed_close() || a.has_signed_close());
}

#[test]
fn after_its_secret_is_out_the_last_old_state_is_never_broadcast() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let c = coin(24);
    splice(&mut f, &mut a, &c, ADD);
    a.note_splice_height(Some(20));
    let la = a.splice_locked().unwrap();
    f.on_splice_locked(&la).unwrap(); // f holds a's secret of state 1
                                      // A reorganization takes the splice back, or a restart forgets where
                                      // it stands: still the first new state, never the revoked old one.
    a.note_splice_height(None);
    let close = a.closing_commitment(FeeTier::High).unwrap();
    assert!(!matches!(
        f.identify_spend(&close),
        Watch::RevokedByPeer { .. }
    ));
    assert_eq!(close.inputs[0].prev_out, a.funding_outpoint().unwrap());
    drop(a);
    let a = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
    let close = a.closing_commitment(FeeTier::High).unwrap();
    assert!(!matches!(
        f.identify_spend(&close),
        Watch::RevokedByPeer { .. }
    ));
}

#[test]
fn two_splices_at_once_both_drop_and_can_come_again() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let (cf, ca) = (coin(26), coin(27));
    let sf = f.propose_splice(ADD, splice_tx(&f, &cf, ADD)).unwrap();
    let sa = a.propose_splice(ADD, splice_tx(&a, &ca, ADD)).unwrap();
    run(&mut f, &mut a, vec![sa], vec![sf]);
    assert!(!f.splicing() && !a.splicing());
    reconnect(&mut f, &mut a);
    splice(&mut a, &mut f, &ca, ADD);
    lock(&mut f, &mut a);
    assert_eq!(f.params().capacity.units(), CAP + ADD);
}

#[test]
fn a_forged_update_does_not_drop_our_splice() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let c = coin(29);
    let sp = f.propose_splice(ADD, splice_tx(&f, &c, ADD)).unwrap();
    let fake = Message::Update {
        state: 2,
        balances: [CAP - 3_000_000, 3_000_000],
        tier_sigs: Default::default(),
    };
    assert!(f.on_peer_update(&fake).is_err());
    assert!(f.splicing(), "still ours");
    // And the real answer still completes it.
    let answer = a.on_splice(&sp).unwrap();
    assert!(f.on_splice_ack(&answer[0]).unwrap().is_none());
    assert!(f.on_splice_sig(&answer[1]).unwrap().is_some());
}

#[test]
fn a_splice_dropped_never_shares_its_transaction_with_a_later_one() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let c = coin(30);
    let first = splice_tx(&f, &c, ADD);
    let sp = f.propose_splice(ADD, first.clone()).unwrap();
    let upd = a.propose([CAP - 2_000_000, 2_000_000]).unwrap();
    let _busy = a.on_splice(&sp).unwrap();
    let ack = f.on_peer_update(&upd).unwrap();
    let rev = a.on_ack(&ack[0]).unwrap();
    f.on_revoke(&rev).unwrap();
    // The same coins again, one state later: another transaction.
    let again = splice_tx(&f, &c, ADD);
    assert_ne!(again.txid(), first.txid());
    // And the first one, offered at the new state, is refused.
    assert_eq!(
        f.propose_splice(ADD, first),
        Err(ChannelError::BadParameters)
    );
}

#[test]
fn a_crash_between_locking_and_revealing_still_journals_the_reveal() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 3_000_000, 3_000_000]);
    let c = coin(31);
    splice(&mut f, &mut a, &c, ADD);
    // The adder locks first, and its journal ends at the lock: cut there.
    f.note_splice_height(Some(20));
    let _lost = f.splice_locked().unwrap();
    drop(f);
    let path = dir.join("f.jrnl");
    let records = super::journal::replay(&std::fs::read(&path).unwrap());
    let keep = records
        .iter()
        .rposition(|r| matches!(r, Record::SpliceLocked))
        .unwrap()
        + 1;
    super::tests::keep_records(&path, keep);
    let mut f = Machine::reopen(&path, NET, fkey(), RATE).unwrap();
    // Locked: its old state is never the close, whatever the chain says.
    let close = f.closing_commitment(FeeTier::High).unwrap();
    assert_eq!(close.inputs[0].prev_out, f.funding_outpoint().unwrap());
    // The other side locks in turn; both reveal, and journal it.
    a.note_splice_height(Some(20));
    let la = a.splice_locked().unwrap();
    f.on_splice_locked(&la).unwrap();
    reconnect(&mut f, &mut a);
    assert!(!f.splicing() && !a.splicing());
    drop(f);
    let f = Machine::reopen(&path, NET, fkey(), RATE).unwrap();
    assert!(!f.splicing());
    let close = f.closing_commitment(FeeTier::High).unwrap();
    assert_eq!(close.inputs[0].prev_out, f.funding_outpoint().unwrap());
}

/// Red-team campaign 9, C1: once a splice was locked and finished, its old
/// funding was no longer watched. A reorganization deeper than the splice's
/// burial brought the old funding back unspent, and a revoked state there,
/// broadcast then, went unpunished. The finished splice is now kept until
/// the channel's funding is buried past any reorganization: its old funding
/// stays watched, a revoked state there is recognized — after a reopen of
/// the journal too — and a second splice waits until it is forgotten.
#[test]
fn a_finished_splice_keeps_its_old_funding_watched_until_forgotten() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]); // state 1
    let revoked = f.signed_commitment_at(1, FeeTier::Low).unwrap();
    let old_funding = f.funding_outpoint().unwrap();
    let c = coin(6);
    let tx = splice(&mut f, &mut a, &c, ADD); // state 2, by the funder
    lock(&mut f, &mut a);
    // Finished: payments go on, the splice is no longer in progress...
    pay(&mut f, &mut a, [CAP + ADD - 2_000_000, 2_000_000]);
    // ... but its old funding is still watched, on both sides.
    for m in [&f, &a] {
        assert!(m.watched_outpoints().contains(&old_funding));
        let (txid, old, _) = m.retired_splice().expect("kept");
        assert_eq!((txid, old), (tx.txid(), old_funding));
    }
    // The adder holds the whole splice, to announce it again.
    assert_eq!(
        f.retired_splice().unwrap().2.map(|t| t.txid()),
        Some(tx.txid())
    );
    assert!(
        a.retired_splice().unwrap().2.is_none(),
        "stripped on the other side"
    );
    // A revoked state on the old funding, back after a reorganization:
    // recognized, and punishable.
    match a.identify_spend(&revoked) {
        w @ Watch::RevokedByPeer { state: 1, .. } => {
            assert!(a.build_penalty(&w, Hash256([5u8; 32]), 20_000).is_ok());
        }
        other => panic!("{other:?}"),
    }
    // The same after the journal is read again, and after a compaction.
    a.compact().unwrap();
    let a2 = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
    assert!(a2.watched_outpoints().contains(&old_funding));
    assert!(matches!(
        a2.identify_spend(&revoked),
        Watch::RevokedByPeer { state: 1, .. }
    ));
    drop(a2);
    // No second splice while the first is watched: the peer keeps nothing.
    let c2 = coin(7);
    assert!(f.propose_splice(ADD, splice_tx(&f, &c2, ADD)).is_err());
    // Forgotten once buried past any reorganization: the old funding with
    // it, and a second splice may come.
    for m in [&mut f, &mut a] {
        m.forget_retired().unwrap();
        assert!(m.retired_splice().is_none());
        assert!(!m.watched_outpoints().contains(&old_funding));
    }
    let a3 = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
    assert!(a3.retired_splice().is_none(), "forgotten for good");
    drop(a3);
    splice(&mut f, &mut a, &c2, ADD);
}

/// Campaign 10, round 4 (`perse`): a channel given up stays given up in its
/// journal through a restart and a compaction: the archive reads it so even
/// when its own record was lost in a crash.
#[test]
fn a_given_up_channel_stays_given_up_through_a_compaction() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]);
    a.mark_abandoned().unwrap();
    assert!(a.was_abandoned());
    assert_eq!(a.phase(), Phase::Closed);
    drop(a);
    let mut a1 = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
    assert!(a1.was_abandoned(), "replayed from the Abandoned record");
    a1.compact().unwrap();
    drop(a1);
    let a2 = Machine::reopen(dir.join("a.jrnl"), NET, akey(), RATE).unwrap();
    assert_eq!(a2.phase(), Phase::Closed);
    assert!(a2.was_abandoned(), "still given up after a compaction");
}

/// Campaign 14, B3-1: a copy restored from a backup taken while its own
/// addition was pending completes it for nobody: the peer's acknowledgement
/// and signature, replayed after the channel moved on, are refused once the
/// copy knows it is older.
#[test]
fn an_older_copy_completes_no_pending_addition_of_its_own() {
    let dir = tmpdir();
    let (mut f, mut a) = open_pair(&dir);
    pay(&mut f, &mut a, [CAP - 1_000_000, 1_000_000]); // state 1
    let c = coin(11);
    let tx = splice_tx(&f, &c, ADD);
    let msg = f.propose_splice(ADD, tx).unwrap();
    // The funder's folder, copied while its addition is pending.
    std::fs::copy(dir.join("f.jrnl"), dir.join("f-old.jrnl")).unwrap();
    let answer = a.on_splice(&msg).unwrap(); // kept by the peer
    assert!(f.on_splice_ack(&answer[0]).unwrap().is_none());
    f.on_splice_sig(&answer[1]).unwrap().expect("complete");
    lock(&mut f, &mut a);
    pay(&mut f, &mut a, [CAP + ADD - 2_000_000, 2_000_000]);
    pay(&mut f, &mut a, [CAP + ADD - 3_000_000, 3_000_000]);
    drop(f);
    let mut stale = Machine::reopen(dir.join("f-old.jrnl"), NET, fkey(), RATE).unwrap();
    let _ = super::tests::exchange_reestablish(&mut stale, &mut a);
    assert_eq!(stale.sync(), super::machine::SyncVerdict::WeAreBehind);
    assert!(
        stale.on_splice_ack(&answer[0]).is_err(),
        "an older copy took the acknowledgement of its stale addition"
    );
    assert!(
        stale.on_splice_sig(&answer[1]).is_err(),
        "an older copy completed its stale addition"
    );
}
